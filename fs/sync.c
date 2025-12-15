// SPDX-License-Identifier: GPL-2.0
/*
 * High-level sync()-related operations
 */

#include <linux/blkdev.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/writeback.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/backing-dev.h>
#include "internal.h"

#define VALID_FLAGS (SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE| \
			SYNC_FILE_RANGE_WAIT_AFTER)

/*
 * Write out and wait upon all dirty data associated with this
 * superblock.  Filesystem data as well as the underlying block
 * device.  Takes the superblock lock.
 */
int sync_filesystem(struct super_block *sb)
{
	int ret = 0;

	/*
	 * We need to be protected against the filesystem going from
	 * r/o to r/w or vice versa.
	 */
	WARN_ON(!rwsem_is_locked(&sb->s_umount));

	/*
	 * No point in syncing out anything if the filesystem is read-only.
	 */
	if (sb_rdonly(sb))
		return 0;

	/*
	 * Do the filesystem syncing work.  For simple filesystems
	 * writeback_inodes_sb(sb) just dirties buffers with inodes so we have
	 * to submit I/O for these buffers via sync_blockdev().  This also
	 * speeds up the wait == 1 case since in that case write_inode()
	 * methods call sync_dirty_buffer() and thus effectively write one block
	 * at a time.
	 */
	writeback_inodes_sb(sb, WB_REASON_SYNC);
	if (sb->s_op->sync_fs) {
		ret = sb->s_op->sync_fs(sb, 0);
		if (ret)
			return ret;
	}
	ret = sync_blockdev_nowait(sb->s_bdev);
	if (ret)
		return ret;

	sync_inodes_sb(sb);
	if (sb->s_op->sync_fs) {
		ret = sb->s_op->sync_fs(sb, 1);
		if (ret)
			return ret;
	}
	return sync_blockdev(sb->s_bdev);
}
EXPORT_SYMBOL(sync_filesystem);

static void sync_inodes_one_sb(struct super_block *sb, void *arg)
{
	if (!sb_rdonly(sb))
		sync_inodes_sb(sb);
}

static void sync_fs_one_sb(struct super_block *sb, void *arg)
{
	if (!sb_rdonly(sb) && !(sb->s_iflags & SB_I_SKIP_SYNC) &&
	    sb->s_op->sync_fs)
		sb->s_op->sync_fs(sb, *(int *)arg);
}

/*
 * Sync everything. We start by waking flusher threads so that most of
 * writeback runs on all devices in parallel. Then we sync all inodes reliably
 * which effectively also waits for all flusher threads to finish doing
 * writeback. At this point all data is on disk so metadata should be stable
 * and we tell filesystems to sync their metadata via ->sync_fs() calls.
 * Finally, we writeout all block devices because some filesystems (e.g. ext2)
 * just write metadata (such as inodes or bitmaps) to block device page cache
 * and do not sync it on their own in ->sync_fs().
 */
void ksys_sync(void)
{
	int nowait = 0, wait = 1;

	wakeup_flusher_threads(WB_REASON_SYNC);
	iterate_supers(sync_inodes_one_sb, NULL);
	iterate_supers(sync_fs_one_sb, &nowait);
	iterate_supers(sync_fs_one_sb, &wait);
	sync_bdevs(false);
	sync_bdevs(true);
	if (unlikely(laptop_mode))
		laptop_sync_completion();
}

/**
 * sys_sync - Commit all filesystem buffers to persistent storage
 *
 * long-desc: Synchronizes all modified in-core data and metadata to all
 *   mounted filesystems and block devices. This syscall causes all dirty
 *   file data, filesystem metadata, and block device buffers to be written
 *   to their backing storage devices.
 *
 *   The synchronization proceeds in multiple phases for correctness:
 *   1. Wakes background writeback (flusher) threads to begin writing dirty
 *      pages across all backing devices in parallel.
 *   2. Iterates through all mounted superblocks and syncs inodes that have
 *      dirty data, using sync_inodes_sb() for each filesystem.
 *   3. Calls each filesystem's sync_fs() callback twice - first without
 *      waiting (to initiate I/O), then with waiting (for completion).
 *   4. Syncs all block devices: first initiates writes (sync_bdevs(false)),
 *      then waits for I/O completion (sync_bdevs(true)).
 *   5. In laptop mode, cancels pending writeback timers since data is now
 *      synchronized.
 *
 *   Unlike the POSIX specification which only requires scheduling writes,
 *   Linux waits for all I/O to complete before returning. This provides
 *   stronger guarantees equivalent to calling fsync() on every open file
 *   in the system.
 *
 *   IMPORTANT: This syscall silently ignores all errors from individual
 *   filesystems or block devices. Even if some filesystems fail to sync
 *   (e.g., due to I/O errors, disconnected devices, or full disks), the
 *   syscall still returns success. Applications requiring error detection
 *   should use syncfs() or fsync() on individual file descriptors instead.
 *
 *   The syscall uses TASK_UNINTERRUPTIBLE for all wait operations, meaning
 *   it cannot be interrupted by signals. In cases of very slow or hung
 *   storage devices, the calling process may appear to hang indefinitely.
 *   The kernel will log a warning after hung_task_timeout_secs (default 120
 *   seconds) if the sync has not completed.
 *
 *   Read-only filesystems are skipped during synchronization. Filesystems
 *   marked with SB_I_SKIP_SYNC (like some pseudo-filesystems) have their
 *   sync_fs callback skipped, but their inodes are still synced.
 *
 *   The syscall can be called by any user without special privileges.
 *   There are no security implications since it only writes data that the
 *   user has already caused to be modified through normal file operations.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Always returns 0 regardless of whether the synchronization actually
 *     succeeded. All errors from underlying filesystems and block devices are
 *     silently ignored. This behavior is intentional and matches the syscall's
 *     historical semantics. Applications needing error reporting should use
 *     syncfs(2) (per-filesystem) or fsync(2) (per-file) instead, which do
 *     report errors. The void return type in POSIX (sync() returns void in
 *     user space) is mapped to a 0 return value at the kernel interface.
 *
 * lock: sb_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Global spinlock protecting the super_blocks list. Acquired briefly
 *     during iteration over all mounted filesystems in iterate_supers(). The
 *     lock is dropped while processing each individual superblock to allow
 *     concurrent mount/unmount operations. Acquired and released multiple
 *     times during the sync operation (once for each iterate_supers call).
 *
 * lock: sb->s_umount
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Per-superblock read-write semaphore protecting against concurrent
 *     unmount operations. Acquired in read mode (down_read) for each mounted
 *     filesystem during iteration. This prevents the filesystem from being
 *     unmounted while sync operations are in progress. The lock is held
 *     while calling sync_inodes_one_sb() and sync_fs_one_sb() callbacks.
 *
 * lock: sb->s_sync_lock
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: Per-superblock mutex acquired during wait_sb_inodes() to serialize
 *     waiting for inode writeback completion. This prevents multiple sync
 *     operations from interfering with each other's tracking of in-flight
 *     inode writes.
 *
 * lock: sb->s_inode_wblist_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Per-superblock spinlock protecting the s_inodes_wb list that tracks
 *     inodes with pending writeback. Acquired with interrupts disabled
 *     (spin_lock_irq) during wait_sb_inodes() when iterating over and waiting
 *     for inodes under writeback.
 *
 * lock: bdi->wb_switch_rwsem
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Per-BDI (backing device info) read-write semaphore acquired in write
 *     mode during sync_inodes_sb() to protect against inode writeback context
 *     switching (cgroup writeback). Ensures stable wb (writeback) association
 *     while submitting and waiting for writeback work.
 *
 * lock: blockdev_superblock->s_inode_list_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Spinlock protecting the list of block device inodes. Acquired during
 *     sync_bdevs() when iterating over all block devices to sync their page
 *     caches. The lock is dropped temporarily while performing I/O on each
 *     block device to allow concurrent block device operations.
 *
 * lock: bdev->bd_disk->open_mutex
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: Per-block-device mutex acquired during sync_bdevs() before syncing
 *     each block device. Ensures the block device is not being closed or
 *     opened concurrently. Only devices with at least one opener are synced.
 *
 * signal: any
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DISCARD
 *   condition: During any wait operation
 *   desc: All wait operations in sync() use TASK_UNINTERRUPTIBLE state, making
 *     the syscall completely non-interruptible by signals. Signals delivered
 *     during the sync remain pending and will be handled after the syscall
 *     returns. This can cause the process to appear hung if storage is slow
 *     or unresponsive. There is no way to abort a sync() in progress.
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: All mounted filesystems
 *   desc: Writes all dirty file data and filesystem metadata (inodes, directory
 *     entries, superblocks, journals, allocation bitmaps, etc.) from kernel
 *     page cache to underlying block devices. The exact metadata written
 *     depends on each filesystem's implementation of writeback_inodes_sb(),
 *     sync_inodes_sb(), and sync_fs() operations.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_HARDWARE
 *   target: All block devices
 *   desc: Initiates and waits for I/O completion on all block devices that
 *     have dirty page cache data. This includes both filesystem block devices
 *     and any block devices with direct I/O buffered data. Uses
 *     filemap_fdatawrite() to initiate writes and filemap_fdatawait_keep_errors()
 *     to wait for completion.
 *   condition: Block devices must have at least one opener (bd_openers > 0)
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Writeback timer state (laptop mode only)
 *   desc: When laptop_mode is enabled (non-zero /proc/sys/vm/laptop_mode),
 *     cancels any pending writeback timers for all backing devices via
 *     laptop_sync_completion(). This prevents unnecessary disk spin-ups
 *     after an explicit sync since data is now on disk.
 *   condition: Only when laptop_mode sysctl is non-zero
 *   reversible: yes (timers will be rescheduled on next dirty data)
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: Flusher threads and calling process
 *   desc: Wakes all per-BDI flusher threads via wakeup_flusher_threads() to
 *     begin parallel writeback. The calling process then blocks waiting for
 *     writeback completion using wait_event() with TASK_UNINTERRUPTIBLE.
 *     The process may sleep for extended periods if there is significant
 *     dirty data or slow storage devices.
 *   reversible: no
 *
 * constraint: Hung task detection
 *   desc: If the sync operation takes longer than hung_task_timeout_secs
 *     (default 120 seconds), the kernel logs a warning message identifying
 *     the waiting task. This is informational only; the sync continues
 *     waiting. This can indicate storage problems or very large amounts of
 *     dirty data.
 *
 * constraint: Read-only filesystems skipped
 *   desc: Filesystems mounted read-only (sb_rdonly() returns true) are skipped
 *     during sync operations since they cannot have dirty data. This is a
 *     performance optimization that reduces unnecessary lock acquisition.
 *
 * constraint: SB_I_SKIP_SYNC filesystems
 *   desc: Filesystems with the SB_I_SKIP_SYNC internal flag set (such as
 *     overlayfs passthrough and certain pseudo-filesystems) have their
 *     sync_fs() callback skipped. Their inodes are still synced via
 *     sync_inodes_one_sb(). This prevents redundant syncs for stacked
 *     filesystems.
 *
 * examples: sync();
 *
 * notes: Historical behavior: Before Linux 1.3.20, sync() returned before I/O
 *   completed, matching POSIX minimum requirements. Modern Linux waits for
 *   completion, providing stronger guarantees.
 *
 *   The double-sync pattern (calling sync() twice) seen in some shutdown scripts
 *   is a historical artifact from when sync() only scheduled writes. With modern
 *   Linux semantics, a single sync() call is sufficient.
 *
 *   For data integrity, applications should prefer fsync() or fdatasync() on
 *   specific files, or syncfs() on specific filesystems. These syscalls report
 *   errors and provide targeted synchronization rather than system-wide sync.
 *
 *   Disk caches: sync() writes data to block devices but does not guarantee
 *   data has reached persistent media if devices have write caching enabled.
 *   Use hdparm -W0 or filesystem mount options like barrier/flush to ensure
 *   write-through behavior for data integrity.
 *
 *   Performance impact: sync() can cause significant I/O load and may take
 *   a long time to complete on systems with large amounts of dirty data or
 *   many mounted filesystems. Consider syncfs() for targeted synchronization.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE0(sync)
{
	ksys_sync();
	return 0;
}

static void do_sync_work(struct work_struct *work)
{
	int nowait = 0;
	int wait = 1;

	/*
	 * Sync twice to reduce the possibility we skipped some inodes / pages
	 * because they were temporarily locked
	 */
	iterate_supers(sync_inodes_one_sb, NULL);
	iterate_supers(sync_fs_one_sb, &nowait);
	sync_bdevs(false);
	iterate_supers(sync_inodes_one_sb, NULL);
	iterate_supers(sync_fs_one_sb, &wait);
	sync_bdevs(false);
	printk("Emergency Sync complete\n");
	kfree(work);
}

void emergency_sync(void)
{
	struct work_struct *work;

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (work) {
		INIT_WORK(work, do_sync_work);
		schedule_work(work);
	}
}

/*
 * sync a single super
 */
SYSCALL_DEFINE1(syncfs, int, fd)
{
	CLASS(fd, f)(fd);
	struct super_block *sb;
	int ret, ret2;

	if (fd_empty(f))
		return -EBADF;
	sb = fd_file(f)->f_path.dentry->d_sb;

	down_read(&sb->s_umount);
	ret = sync_filesystem(sb);
	up_read(&sb->s_umount);

	ret2 = errseq_check_and_advance(&sb->s_wb_err, &fd_file(f)->f_sb_err);

	return ret ? ret : ret2;
}

/**
 * vfs_fsync_range - helper to sync a range of data & metadata to disk
 * @file:		file to sync
 * @start:		offset in bytes of the beginning of data range to sync
 * @end:		offset in bytes of the end of data range (inclusive)
 * @datasync:		perform only datasync
 *
 * Write back data in range @start..@end and metadata for @file to disk.  If
 * @datasync is set only metadata needed to access modified file data is
 * written.
 */
int vfs_fsync_range(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;

	if (!file->f_op->fsync)
		return -EINVAL;
	if (!datasync && (inode_state_read_once(inode) & I_DIRTY_TIME))
		mark_inode_dirty_sync(inode);
	return file->f_op->fsync(file, start, end, datasync);
}
EXPORT_SYMBOL(vfs_fsync_range);

/**
 * vfs_fsync - perform a fsync or fdatasync on a file
 * @file:		file to sync
 * @datasync:		only perform a fdatasync operation
 *
 * Write back data and metadata for @file to disk.  If @datasync is
 * set only metadata needed to access modified file data is written.
 */
int vfs_fsync(struct file *file, int datasync)
{
	return vfs_fsync_range(file, 0, LLONG_MAX, datasync);
}
EXPORT_SYMBOL(vfs_fsync);

static int do_fsync(unsigned int fd, int datasync)
{
	CLASS(fd, f)(fd);

	if (fd_empty(f))
		return -EBADF;

	return vfs_fsync(fd_file(f), datasync);
}

/**
 * sys_fsync - Synchronize a file's data and metadata to persistent storage
 * @fd: File descriptor of the open file to synchronize
 *
 * long-desc: Transfers all modified in-core data and metadata for the file
 *   referred to by the file descriptor fd to the underlying storage device.
 *   This ensures that the file's contents, along with all metadata necessary
 *   to retrieve the file (size, timestamps, allocation information), are
 *   written to persistent storage and will survive a system crash or power
 *   failure.
 *
 *   The syscall performs the following operations in order:
 *   1. If I_DIRTY_TIME is set and this is not a datasync operation (always
 *      the case for fsync), marks the inode dirty to ensure timestamps are
 *      persisted.
 *   2. Calls the filesystem's fsync callback (file->f_op->fsync) with the
 *      range 0 to LLONG_MAX (entire file).
 *   3. The filesystem callback typically writes dirty pages via
 *      file_write_and_wait_range(), syncs metadata, and issues a storage
 *      flush/barrier to ensure data reaches persistent media.
 *
 *   Unlike fdatasync(2), fsync() always synchronizes all metadata, including
 *   access and modification timestamps, even if they are not strictly
 *   necessary for retrieving the file data. This provides the strongest
 *   durability guarantee.
 *
 *   The behavior varies by filesystem type:
 *   - Regular filesystems (ext4, xfs, btrfs): Full data and metadata sync
 *     with storage flush/barrier
 *   - Network filesystems (NFS, CIFS): Commits data to server, may return
 *     EINTR if interrupted
 *   - Block devices: Syncs the block device page cache and issues flush
 *   - Pipes, sockets, FIFOs: Returns EINVAL (no fsync operation)
 *   - In-memory filesystems (tmpfs, ramfs): Returns 0 immediately (noop)
 *
 *   Error Reporting Semantics (Important):
 *   The error returned by fsync() may reflect errors that occurred during
 *   earlier write operations on the file. Due to background writeback, write
 *   errors may not be reported until a subsequent fsync() call. The kernel
 *   tracks writeback errors per file descriptor using an error sequence
 *   counter (errseq_t). Each call to fsync() advances this counter and
 *   returns any errors that occurred since the last fsync() or since the
 *   file was opened.
 *
 *   CAUTION: If multiple file descriptors refer to the same file (via dup()
 *   or multiple open() calls), an error may be reported to only ONE of the
 *   descriptors. Applications should either use a single descriptor for sync
 *   operations or check errors on all descriptors.
 *
 *   Storage Cache Considerations:
 *   This syscall requests the filesystem to issue a cache flush command to
 *   the storage device. However, whether data actually reaches persistent
 *   media depends on the device and its configuration:
 *   - Devices with volatile write cache may not persist data if power is lost
 *     during the flush (use hdparm -W0 to disable)
 *   - Battery-backed caches are considered persistent
 *   - Some filesystems have mount options to control barrier behavior
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, INT_MAX
 *   constraint: Must be a valid file descriptor for an open file. The file
 *     must support fsync operations (regular files, block devices, and some
 *     special files). File must have been opened with at least one of O_RDONLY,
 *     O_WRONLY, or O_RDWR - the specific access mode does not matter for fsync.
 *     Using a closed or invalid file descriptor returns EBADF.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success, indicating that the file's data and metadata
 *     have been successfully transferred to persistent storage. Note that some
 *     filesystems (ramfs, tmpfs) return success immediately without actually
 *     persisting data, as they are purely in-memory.
 *
 * error: EBADF, Invalid file descriptor
 *   desc: The file descriptor fd is not a valid open file descriptor. This
 *     occurs if fd has never been opened, was already closed, or is outside
 *     the valid range of file descriptors for the process.
 *
 * error: EINVAL, File does not support synchronization
 *   desc: The file referred to by fd does not support synchronization. This
 *     happens when the file's underlying filesystem or device does not provide
 *     an fsync operation (file->f_op->fsync is NULL). Common cases include:
 *     pipes, FIFOs (named pipes), anonymous sockets, and certain pseudo-files.
 *     POSIX uses EROFS or EINVAL interchangeably for this condition.
 *
 * error: EIO, I/O error during synchronization
 *   desc: An I/O error occurred while syncing data or metadata. This may
 *     indicate hardware failure, disconnected storage, or filesystem corruption.
 *     The error may reflect a previous write() that failed during background
 *     writeback. After an EIO error, some or all of the file's data may not
 *     have been persisted. Applications should handle this by retrying or
 *     failing gracefully. Note that the specific affected data cannot be
 *     determined from the error.
 *
 * error: ENOSPC, No space left on device
 *   desc: The filesystem ran out of space while attempting to complete the
 *     sync operation. This typically occurs when metadata operations (such as
 *     allocating blocks for data that was written past EOF) require additional
 *     space that is not available. Can also be reported from delayed allocation
 *     filesystems when reserved space becomes unavailable.
 *
 * error: EDQUOT, Disk quota exceeded
 *   desc: The user's disk quota was exceeded during the sync operation. Most
 *     commonly returned by NFS and other networked filesystems when the server
 *     enforces quota limits. Can occur for delayed allocations that exceed
 *     quota at sync time even though the original write appeared to succeed.
 *
 * error: EINTR, Interrupted by signal
 *   desc: The syscall was interrupted by a signal before completion. This is
 *     primarily returned by network filesystems (NFS) where the sync involves
 *     a potentially long RPC operation. Most local filesystems use
 *     uninterruptible waits and do not return EINTR. When EINTR is returned,
 *     some data may or may not have been synced - the application should retry.
 *
 * error: EROFS, Read-only filesystem
 *   desc: The file resides on a read-only filesystem. While writes to such
 *     files would normally fail earlier, this can occur if the filesystem
 *     was remounted read-only after the file was opened for writing, or
 *     for certain special file types. Some implementations return EINVAL
 *     instead.
 *
 * lock: inode->i_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired briefly in vfs_fsync_range() when checking and clearing
 *     I_DIRTY_TIME flag before marking the inode dirty. This ensures atomic
 *     handling of the lazytime state. Also acquired by filesystem callbacks
 *     when updating inode state during writeback.
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Acquired by most filesystem fsync implementations (e.g.,
 *     __generic_file_fsync) to serialize metadata synchronization and
 *     prevent concurrent modifications during sync. Held for the duration
 *     of sync_mapping_buffers() and sync_inode_metadata() calls. Some
 *     filesystems (ext4 with journaling) do not acquire this lock.
 *
 * lock: file->f_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired during file_check_and_advance_wb_err() to atomically
 *     check and advance the file's writeback error sequence number. This
 *     ensures that concurrent fsync calls on the same file descriptor
 *     properly serialize error reporting.
 *
 * lock: mapping->i_pages (xa_lock)
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The xarray lock protecting the page cache is acquired during
 *     writeback operations when looking up dirty pages and clearing
 *     writeback state. Held briefly during page cache manipulation.
 *
 * signal: any
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: During network filesystem operations (NFS)
 *   desc: For network filesystems like NFS, signals can interrupt the RPC
 *     operations involved in committing data to the server. In this case,
 *     the syscall returns -EINTR. For local filesystems, the wait for I/O
 *     completion typically uses TASK_UNINTERRUPTIBLE, making the syscall
 *     non-interruptible. The process may appear hung if storage is slow
 *     or unresponsive.
 *   error: -EINTR
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: File data and metadata on storage device
 *   desc: Writes all dirty pages belonging to the file's address space to
 *     the backing storage device. For regular files, this includes file
 *     contents that have been modified since the last sync. Metadata changes
 *     (inode information: size, timestamps, permissions, ownership, extended
 *     attributes) are also written. For journaling filesystems, this may
 *     involve journal commits.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_HARDWARE
 *   target: Storage device write cache
 *   desc: Issues a cache flush command (FUA or explicit flush) to the
 *     underlying storage device to ensure data in the device's volatile
 *     write cache is committed to persistent media. This is critical for
 *     data durability guarantees. The exact mechanism depends on the
 *     filesystem and device (blkdev_issue_flush, REQ_FUA, etc.).
 *   condition: Only if filesystem enables barriers/flushes
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: File writeback error tracking (file->f_wb_err)
 *   desc: Advances the file descriptor's writeback error cursor
 *     (file->f_wb_err) to match the current mapping error sequence
 *     (mapping->wb_err). This marks any pending errors as "seen" so they
 *     are reported exactly once to userspace. Also clears the AS_EIO and
 *     AS_ENOSPC flags on the address space for legacy compatibility.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Inode dirty state (I_DIRTY_TIME, I_DIRTY_SYNC)
 *   desc: If the inode has I_DIRTY_TIME set (lazy timestamps), the fsync
 *     operation clears this flag and sets I_DIRTY_SYNC to ensure timestamps
 *     are written to disk. This transitions the inode from lazytime state
 *     to regular dirty state for proper synchronization.
 *   condition: Only if inode has I_DIRTY_TIME set
 *   reversible: yes (subsequent file operations will re-dirty timestamps)
 *
 * constraint: File type restrictions
 *   desc: Only files with an fsync file operation callback can be synced.
 *     Regular files, directories, block devices, and character devices with
 *     fsync support can be synchronized. Pipes, sockets, and FIFOs return
 *     EINVAL as they have no persistent storage backing.
 *
 * constraint: Per-file-descriptor error reporting
 *   desc: Writeback errors are tracked per file descriptor, not per file.
 *     Each file descriptor maintains its own error sequence cursor. An error
 *     will only be reported once, to the first file descriptor that calls
 *     fsync() after the error occurs. Applications that open the same file
 *     multiple times must check all file descriptors for errors.
 *
 * constraint: Write ordering
 *   desc: fsync() provides ordering guarantees only for the specific file
 *     being synced. Data written to other files or the same file through
 *     different descriptors may not be ordered with respect to this sync.
 *     For directory entry durability (making sure a newly created file
 *     survives a crash), an fsync on the parent directory is also required.
 *
 * examples: fsync(fd);  // Sync file data and metadata to disk
 *   ret = fsync(fd); if (ret) { perror("fsync"); }  // With error checking
 *
 * notes: fsync vs fdatasync: fsync() synchronizes all metadata including
 *   timestamps, while fdatasync() only synchronizes metadata necessary
 *   for data retrieval (size, allocation). fdatasync() may be faster for
 *   applications that don't need timestamp durability.
 *
 *   Directory fsync: To ensure a newly created file (via create/link/rename)
 *   survives a crash, applications must fsync both the file AND its parent
 *   directory. The file's fsync ensures the data is written; the directory
 *   fsync ensures the directory entry pointing to the file is written.
 *
 *   Historical note: Early Linux implementations (pre-2.6) had various bugs
 *   and inconsistencies in fsync behavior. The current implementation was
 *   significantly improved around the 2.6.17 timeframe and again in 4.18
 *   with better error reporting (errseq_t infrastructure).
 *
 *   PostgreSQL fsync surprise (LWN 2018): A notable issue was discovered
 *   where errors during background writeback could be lost if no file
 *   descriptor had called fsync() recently. Modern kernels (4.18+) track
 *   errors per-file-descriptor to improve error reporting reliability.
 *
 *   O_SYNC/O_DSYNC files: For files opened with O_SYNC or O_DSYNC, each
 *   write() already provides synchronization guarantees, so fsync() may
 *   not perform additional I/O beyond verifying any pending errors.
 *
 *   NFS considerations: NFS fsync() actually sends a COMMIT RPC to the
 *   server, which can take significantly longer than local fsync and
 *   may return EINTR if interrupted. Server-side errors (quota exceeded,
 *   no space) are reported through this mechanism.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE1(fsync, unsigned int, fd)
{
	return do_fsync(fd, 0);
}

/**
 * sys_fdatasync - Synchronize a file's data to persistent storage
 * @fd: File descriptor of the open file to synchronize
 *
 * long-desc: Transfers all modified in-core data for the file referred to
 *   by the file descriptor fd to the underlying storage device. Unlike
 *   fsync(2), this syscall does not flush modified metadata unless that
 *   metadata is needed for subsequent data retrieval to be correctly
 *   handled.
 *
 *   Specifically, fdatasync() only synchronizes metadata changes that are
 *   required for a subsequent read operation to return the correct data.
 *   This includes file size changes and data block allocation, but excludes
 *   modifications to access time (atime), modification time (mtime), and
 *   other non-essential metadata. This optimization can reduce disk I/O
 *   compared to fsync() when the application does not require timestamp
 *   durability.
 *
 *   The syscall performs the following operations in order:
 *   1. Unlike fsync(), the I_DIRTY_TIME check is skipped - timestamps are
 *      NOT explicitly marked for synchronization.
 *   2. Calls the filesystem's fsync callback (file->f_op->fsync) with the
 *      datasync parameter set to 1, indicating data-integrity sync mode.
 *   3. The filesystem callback typically writes dirty data pages via
 *      file_write_and_wait_range(), then only syncs metadata if
 *      I_DIRTY_DATASYNC is set (indicating size or allocation changes).
 *   4. Issues a storage flush/barrier to ensure data reaches persistent
 *      media.
 *
 *   Metadata synchronization behavior by filesystem:
 *   - ext4: Uses fast commit for regular files when journaling is enabled.
 *     For non-journaled mode, syncs only if I_DIRTY_DATASYNC is set.
 *   - XFS: Optimized datasync that skips inode updates when only timestamps
 *     have changed.
 *   - NFS: Commits data to server via COMMIT RPC. The datasync flag affects
 *     what metadata the server is asked to commit.
 *   - Btrfs: May skip some tree updates when only doing datasync.
 *   - tmpfs/ramfs: Returns 0 immediately (no persistent storage).
 *
 *   When to use fdatasync vs fsync:
 *   - Use fdatasync() when you only need to ensure data is durable and don't
 *     care about timestamps surviving a crash.
 *   - Use fsync() when timestamps or other metadata must be durable, such as
 *     for compliance with applications expecting mtime-based change detection.
 *   - For newly created files, both syscalls behave similarly since the file
 *     size change requires metadata sync.
 *
 *   Error Reporting Semantics:
 *   The error returned by fdatasync() may reflect errors that occurred during
 *   earlier write operations on the file due to background writeback. The
 *   kernel tracks writeback errors per file descriptor using an error sequence
 *   counter (errseq_t). Each call to fdatasync() advances this counter and
 *   returns any errors that occurred since the last sync or since the file
 *   was opened. After kernel 4.13, error reporting was significantly improved
 *   to ensure errors are reported to at least one file descriptor.
 *
 *   CAUTION: If multiple file descriptors refer to the same file (via dup()
 *   or multiple open() calls), an error may be reported to only ONE of the
 *   descriptors. Applications should either use a single descriptor for sync
 *   operations or check errors on all descriptors.
 *
 *   Storage Cache Considerations:
 *   This syscall requests the filesystem to issue a cache flush command to
 *   the storage device. However, whether data actually reaches persistent
 *   media depends on the device and its configuration. Devices with volatile
 *   write cache may not persist data if power is lost during the flush.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, INT_MAX
 *   constraint: Must be a valid file descriptor for an open file. The file
 *     must support fsync operations (regular files, block devices, directories,
 *     and some special files). The specific access mode (O_RDONLY, O_WRONLY,
 *     O_RDWR) does not matter for fdatasync - even read-only descriptors can
 *     trigger sync of pending writes from other descriptors to the same file.
 *     Using a closed or invalid file descriptor returns EBADF.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success, indicating that the file's data (and any
 *     essential metadata) has been successfully transferred to persistent
 *     storage. Note that some filesystems (ramfs, tmpfs) return success
 *     immediately without actually persisting data, as they are purely
 *     in-memory.
 *
 * error: EBADF, Invalid file descriptor
 *   desc: The file descriptor fd is not a valid open file descriptor. This
 *     occurs if fd has never been opened, was already closed, or is outside
 *     the valid range of file descriptors for the process.
 *
 * error: EINVAL, File does not support synchronization
 *   desc: The file referred to by fd does not support synchronization. This
 *     happens when the file's underlying filesystem or device does not provide
 *     an fsync operation (file->f_op->fsync is NULL). Common cases include:
 *     pipes, FIFOs (named pipes), anonymous sockets, and certain pseudo-files.
 *     POSIX specifies this error for files not supporting synchronization.
 *
 * error: EIO, I/O error during synchronization
 *   desc: An I/O error occurred while syncing data or metadata. This may
 *     indicate hardware failure, disconnected storage, or filesystem corruption.
 *     The error may reflect a previous write() that failed during background
 *     writeback. Since kernel 4.13, EIO errors are reported to all file
 *     descriptors that wrote data which triggered the error. After an EIO
 *     error, some or all of the file's data may not have been persisted.
 *     Applications should handle this by retrying or failing gracefully.
 *
 * error: ENOSPC, No space left on device
 *   desc: The filesystem ran out of space while attempting to complete the
 *     sync operation. This typically occurs when metadata operations (such as
 *     allocating blocks for data that was written past EOF) require additional
 *     space that is not available. Delayed allocation filesystems may report
 *     this at sync time when reserved space becomes unavailable, even though
 *     the original write appeared to succeed.
 *
 * error: EDQUOT, Disk quota exceeded
 *   desc: The user's disk quota was exceeded during the sync operation. Most
 *     commonly returned by NFS and other networked filesystems when the server
 *     enforces quota limits. Can occur for delayed allocations that exceed
 *     quota at sync time even though the original write appeared to succeed.
 *
 * error: EINTR, Interrupted by signal
 *   desc: The syscall was interrupted by a signal before completion. This is
 *     primarily returned by network filesystems (NFS) where the sync involves
 *     a potentially long RPC operation that can be interrupted. Most local
 *     filesystems use TASK_UNINTERRUPTIBLE waits and do not return EINTR.
 *     When EINTR is returned, some data may or may not have been synced - the
 *     application should retry the operation.
 *
 * error: EROFS, Read-only filesystem
 *   desc: The file resides on a read-only filesystem. While writes to such
 *     files would normally fail earlier, this can occur if the filesystem
 *     was remounted read-only after the file was opened for writing, or for
 *     certain special file types. Some filesystems return EINVAL instead.
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Acquired by most filesystem fsync implementations (e.g.,
 *     __generic_file_fsync) to serialize metadata synchronization and
 *     prevent concurrent modifications during sync. Held for the duration
 *     of sync_mapping_buffers() and sync_inode_metadata() calls. Some
 *     filesystems (ext4 with journaling) do not acquire this lock as they
 *     use journal transaction ordering instead.
 *
 * lock: inode->i_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired briefly during writeback when checking and updating inode
 *     dirty state flags (I_DIRTY_DATASYNC, I_DIRTY_PAGES). Also acquired by
 *     filesystem callbacks when updating inode state during writeback. This
 *     spinlock protects the inode's state flags from concurrent modification.
 *
 * lock: file->f_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired during file_check_and_advance_wb_err() to atomically
 *     check and advance the file's writeback error sequence number. This
 *     ensures that concurrent fdatasync calls on the same file descriptor
 *     properly serialize error reporting.
 *
 * lock: mapping->i_pages (xa_lock)
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The xarray lock protecting the page cache is acquired during
 *     writeback operations when looking up dirty pages, initiating writeback,
 *     and clearing writeback state. Held briefly during page cache operations.
 *
 * signal: any
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: During network filesystem operations (NFS)
 *   desc: For network filesystems like NFS, signals can interrupt the RPC
 *     operations involved in committing data to the server. In this case,
 *     the syscall returns -EINTR. For local filesystems, the wait for I/O
 *     completion typically uses TASK_UNINTERRUPTIBLE, making the syscall
 *     non-interruptible by signals. The process may appear hung if storage
 *     is slow or unresponsive, and the hung task detector will report after
 *     hung_task_timeout_secs (default 120 seconds).
 *   error: -EINTR
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: File data on storage device
 *   desc: Writes all dirty pages belonging to the file's address space to
 *     the backing storage device. For regular files, this includes file
 *     contents that have been modified since the last sync. Metadata changes
 *     are only written if I_DIRTY_DATASYNC is set, indicating that essential
 *     metadata (file size, block allocation) has changed. Timestamp updates
 *     are explicitly NOT forced to disk by fdatasync, unlike fsync.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_HARDWARE
 *   target: Storage device write cache
 *   desc: Issues a cache flush command (FUA or explicit flush) to the
 *     underlying storage device to ensure data in the device's volatile
 *     write cache is committed to persistent media. This is critical for
 *     data durability guarantees. The exact mechanism depends on the
 *     filesystem and device (blkdev_issue_flush, REQ_FUA, etc.). Some
 *     filesystems have mount options to control flush/barrier behavior.
 *   condition: Only if filesystem enables barriers/flushes
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: File writeback error tracking (file->f_wb_err)
 *   desc: Advances the file descriptor's writeback error cursor
 *     (file->f_wb_err) to match the current mapping error sequence
 *     (mapping->wb_err). This marks any pending errors as "seen" so they
 *     are reported exactly once to userspace. This mechanism was improved
 *     in kernel 4.13 and 4.18 to ensure more reliable error reporting.
 *   reversible: no
 *
 * constraint: File type restrictions
 *   desc: Only files with an fsync file operation callback can be synced.
 *     Regular files, directories, block devices, and character devices with
 *     fsync support can be synchronized. Pipes, sockets, and FIFOs return
 *     EINVAL as they have no persistent storage backing.
 *
 * constraint: Per-file-descriptor error reporting
 *   desc: Writeback errors are tracked per file descriptor, not per file.
 *     Each file descriptor maintains its own error sequence cursor. An error
 *     will only be reported once, to the first file descriptor that calls
 *     fdatasync() after the error occurs. Applications that open the same
 *     file multiple times must check all file descriptors for errors.
 *
 * constraint: Metadata not synced
 *   desc: Unlike fsync(), fdatasync() does not guarantee that metadata such
 *     as modification time (mtime), access time (atime), or other non-essential
 *     inode fields are persisted. Only metadata required for subsequent data
 *     retrieval (file size, data block pointers) is synchronized. This is
 *     specified by POSIX as "synchronized I/O data integrity completion"
 *     rather than "synchronized I/O file integrity completion".
 *
 * examples: fdatasync(fd);  // Sync file data to disk
 *   ret = fdatasync(fd); if (ret < 0) { perror("fdatasync"); }  // With error checking
 *
 * notes: fdatasync vs fsync performance: fdatasync() can be faster than
 *   fsync() for workloads that perform many small writes because it avoids
 *   writing timestamp updates to disk on each sync. For typical database
 *   transaction logs or append-only writes, the performance difference can
 *   be significant.
 *
 *   Directory fdatasync: Calling fdatasync() on a directory behaves similarly
 *   to fsync() on a directory - it ensures that directory entries (filenames
 *   and inode numbers) are persisted. For newly created files, you must
 *   fdatasync() both the file AND its parent directory for the file to be
 *   recoverable after a crash.
 *
 *   Pre-Linux 2.2 behavior: Before Linux 2.2, fdatasync() was implemented
 *   as equivalent to fsync(), providing no performance advantage. Modern
 *   implementations properly distinguish between the two operations.
 *
 *   PostgreSQL fsync issues (2018): A notable issue was discovered where
 *   errors during background writeback could be lost if no file descriptor
 *   had called fsync/fdatasync recently. Modern kernels (4.13+) track errors
 *   per-file-descriptor via errseq_t to improve reliability. Applications
 *   should now PANIC or abort transactions on fdatasync failure rather than
 *   retrying, as the data may have been discarded from the page cache.
 *
 *   O_DSYNC files: For files opened with O_DSYNC, each write() already
 *   provides data synchronization guarantees equivalent to following each
 *   write with fdatasync(), so calling fdatasync() may not perform additional
 *   I/O beyond verifying any pending errors.
 *
 * since-version: 2.0
 */
SYSCALL_DEFINE1(fdatasync, unsigned int, fd)
{
	return do_fsync(fd, 1);
}

int sync_file_range(struct file *file, loff_t offset, loff_t nbytes,
		    unsigned int flags)
{
	int ret;
	struct address_space *mapping;
	loff_t endbyte;			/* inclusive */
	umode_t i_mode;

	ret = -EINVAL;
	if (flags & ~VALID_FLAGS)
		goto out;

	endbyte = offset + nbytes;

	if ((s64)offset < 0)
		goto out;
	if ((s64)endbyte < 0)
		goto out;
	if (endbyte < offset)
		goto out;

	if (sizeof(pgoff_t) == 4) {
		if (offset >= (0x100000000ULL << PAGE_SHIFT)) {
			/*
			 * The range starts outside a 32 bit machine's
			 * pagecache addressing capabilities.  Let it "succeed"
			 */
			ret = 0;
			goto out;
		}
		if (endbyte >= (0x100000000ULL << PAGE_SHIFT)) {
			/*
			 * Out to EOF
			 */
			nbytes = 0;
		}
	}

	if (nbytes == 0)
		endbyte = LLONG_MAX;
	else
		endbyte--;		/* inclusive */

	i_mode = file_inode(file)->i_mode;
	ret = -ESPIPE;
	if (!S_ISREG(i_mode) && !S_ISBLK(i_mode) && !S_ISDIR(i_mode) &&
			!S_ISLNK(i_mode))
		goto out;

	mapping = file->f_mapping;
	ret = 0;
	if (flags & SYNC_FILE_RANGE_WAIT_BEFORE) {
		ret = file_fdatawait_range(file, offset, endbyte);
		if (ret < 0)
			goto out;
	}

	if (flags & SYNC_FILE_RANGE_WRITE) {
		if ((flags & SYNC_FILE_RANGE_WRITE_AND_WAIT) ==
			     SYNC_FILE_RANGE_WRITE_AND_WAIT)
			ret = filemap_fdatawrite_range(mapping, offset,
					endbyte);
		else
			ret = filemap_flush_range(mapping, offset, endbyte);
		if (ret < 0)
			goto out;
	}

	if (flags & SYNC_FILE_RANGE_WAIT_AFTER)
		ret = file_fdatawait_range(file, offset, endbyte);

out:
	return ret;
}

/**
 * sys_sync_file_range - Synchronize a file segment with disk
 * @fd: File descriptor for the file to synchronize
 * @offset: Starting byte offset for the range to sync
 * @nbytes: Number of bytes to sync (0 means sync to end of file)
 * @flags: Bitmask of SYNC_FILE_RANGE_* flags controlling the operation
 *
 * long-desc: Provides fine-grained control for synchronizing file data in
 *   a specific byte range to the underlying storage device. Unlike fsync(2)
 *   and fdatasync(2), this syscall allows applications to precisely control
 *   which data is written and whether to wait for completion.
 *
 *   The offset and nbytes parameters specify the range to synchronize. The
 *   offset is rounded down to the nearest page boundary, and the end of
 *   the range (offset + nbytes) is rounded up to the nearest page boundary.
 *   If nbytes is 0, the operation extends from offset to the end of the file.
 *
 *   The flags parameter is a bitmask that controls the synchronization
 *   behavior through three independent operations:
 *
 *   SYNC_FILE_RANGE_WAIT_BEFORE (1): Wait for writeout of all pages in the
 *     range that are already under writeback to complete before proceeding.
 *     This ensures any in-flight I/O completes before new writeout starts.
 *
 *   SYNC_FILE_RANGE_WRITE (2): Initiate writeout of all dirty pages in the
 *     range that are not presently under writeback. When used alone or with
 *     only WAIT_BEFORE, this uses WB_SYNC_NONE mode (asynchronous writeback).
 *     When combined with both WAIT_BEFORE and WAIT_AFTER, uses WB_SYNC_ALL
 *     mode for data integrity (waits for any in-flight I/O to complete before
 *     starting new I/O, ensuring pages dirty at entry are placed under I/O).
 *
 *   SYNC_FILE_RANGE_WAIT_AFTER (4): Wait for writeout of all pages in the
 *     range to complete after the WRITE operation. Returns any errors that
 *     occurred during writeback.
 *
 *   Common flag combinations:
 *   - 0: No operation (returns success immediately)
 *   - WRITE (2): Asynchronous flush, not suitable for data integrity
 *   - WAIT_BEFORE|WRITE (3): Start writeback for data integrity
 *   - WAIT_AFTER (4): Wait for completion of previous async writeback
 *   - WRITE_AND_WAIT (7): Full data sync equivalent to fdatasync on the range
 *
 *   CRITICAL LIMITATIONS (read carefully before use):
 *   1. NO METADATA SYNC: This syscall NEVER writes file metadata. Without
 *      metadata persistence, data written to newly-allocated blocks may be
 *      lost on crash because the block allocation is not recorded.
 *   2. NO DISK CACHE FLUSH: The syscall does not issue a disk cache flush
 *      command. Data may remain in volatile disk cache after return.
 *   3. OVERWRITES ONLY: Data integrity is only guaranteed when overwriting
 *      existing, already-allocated disk blocks. For new writes past EOF or
 *      writes to holes, use fsync(2) or fdatasync(2) instead.
 *   4. COW FILESYSTEMS: On copy-on-write filesystems (btrfs, etc.), even
 *      overwrites may allocate new blocks, breaking the overwrite guarantee.
 *
 *   The syscall is designed for applications like databases that can track
 *   which regions are already allocated and want fine-grained control over
 *   background writeback to reduce latency spikes.
 *
 *   On 32-bit architectures where 64-bit arguments must be aligned (ARM,
 *   PowerPC), an alternative syscall sync_file_range2() is provided with
 *   the flags parameter before the 64-bit arguments to avoid register
 *   padding overhead.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, INT_MAX
 *   constraint: Must be a valid file descriptor for an open file. The file
 *     must be a regular file, block device, directory, or symbolic link.
 *     Notably, the file descriptor does NOT need to be opened for writing;
 *     sync_file_range can sync data written through other file descriptors
 *     referring to the same file. This matches fsync() and fdatasync()
 *     behavior. Pipes, sockets, FIFOs, and other special file types return
 *     ESPIPE.
 *
 * param: offset
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, LLONG_MAX
 *   constraint: Starting byte offset for synchronization, must be non-negative.
 *     Rounded down to the nearest page boundary internally. The offset does
 *     not need to be within the current file size; if the offset exceeds the
 *     file size, the operation succeeds immediately with nothing to sync.
 *     On 32-bit systems with 32-bit pgoff_t, offsets at or beyond
 *     0x100000000ULL * PAGE_SIZE (typically 16TB on 4KB page systems) succeed
 *     immediately as they are beyond the addressable page cache range.
 *
 * param: nbytes
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, LLONG_MAX
 *   constraint: Length of the range to synchronize in bytes. When set to 0,
 *     the range extends from offset to the end of the file (LLONG_MAX is used
 *     internally as the end boundary). The end of the range is calculated as
 *     offset + nbytes - 1 (inclusive) and rounded up to page boundary. The
 *     sum offset + nbytes must not overflow a signed 64-bit value; overflow
 *     returns EINVAL. Negative values when cast to signed are rejected.
 *
 * param: flags
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER
 *   constraint: Bitmask of synchronization control flags. Only the three
 *     defined SYNC_FILE_RANGE_* flags are valid. Setting any other bits
 *     returns EINVAL. The value 0 is permitted and results in no operation
 *     (immediate success). The combination SYNC_FILE_RANGE_WRITE_AND_WAIT (7)
 *     represents all three flags and provides the strongest guarantee.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success, indicating the requested synchronization
 *     operations completed. For WAIT_BEFORE and WAIT_AFTER operations, this
 *     means all pages in the range have completed writeback. For WRITE alone,
 *     this only means writeback was successfully initiated. Success does NOT
 *     guarantee data has reached persistent media due to disk write caches.
 *
 * error: EBADF, Invalid file descriptor
 *   desc: The file descriptor fd is not a valid open file descriptor. This
 *     occurs if fd was never opened, has been closed, or is outside the
 *     valid range for the process's file descriptor table.
 *
 * error: EINVAL, Invalid flags specified
 *   desc: The flags argument contains bits other than the three valid
 *     SYNC_FILE_RANGE_* flags. Only bits 0, 1, and 2 may be set; any other
 *     bits being set causes this error.
 *
 * error: EINVAL, Invalid offset (negative)
 *   desc: The offset argument, when interpreted as a signed 64-bit value,
 *     is negative. File offsets must be non-negative.
 *
 * error: EINVAL, Invalid range (overflow or wraparound)
 *   desc: The sum of offset + nbytes, when interpreted as a signed 64-bit
 *     value, overflows or wraps around to a negative value. This also
 *     occurs if the calculated end byte (offset + nbytes) is less than
 *     offset, indicating arithmetic overflow.
 *
 * error: ESPIPE, Illegal seek (unsupported file type)
 *   desc: The file referred to by fd is not a regular file, block device,
 *     directory, or symbolic link. Pipes, FIFOs, sockets, and certain
 *     other special files do not support synchronization and return this
 *     error. This is the same error returned by lseek(2) on such files.
 *
 * error: EIO, I/O error during writeback
 *   desc: An I/O error occurred while writing data to the storage device.
 *     This error is detected during WAIT_BEFORE or WAIT_AFTER operations
 *     via the AS_EIO flag in the address_space. The error may reflect a
 *     previous write operation that failed during background writeback.
 *     After this error, some pages may have been written while others
 *     failed. The specific affected pages cannot be determined. The
 *     AS_EIO flag is cleared after being reported.
 *
 * error: ENOSPC, No space left on device
 *   desc: The filesystem ran out of space during writeback. This typically
 *     occurs when delayed allocation fails to find space for data that
 *     was successfully buffered in memory. Detected via the AS_ENOSPC
 *     flag in the address_space during WAIT_BEFORE or WAIT_AFTER. The
 *     AS_ENOSPC flag is cleared after being reported.
 *
 * error: ENOMEM, Out of memory
 *   desc: Memory allocation failed during the writeback operation. When
 *     using SYNC_FILE_RANGE_WRITE_AND_WAIT (all three flags), the kernel
 *     uses WB_SYNC_ALL mode which will retry writeback after reclaim
 *     throttling if ENOMEM occurs. With other flag combinations using
 *     WB_SYNC_NONE mode, ENOMEM is returned immediately without retry.
 *
 * lock: mapping->i_pages (xa_lock)
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The xarray lock protecting the page cache is acquired briefly
 *     during page lookup and writeback state changes. Acquired via
 *     xa_lock_irq() when iterating pages under writeback during the
 *     WAIT_BEFORE and WAIT_AFTER phases. Also acquired during writeback
 *     initiation when looking up dirty pages.
 *
 * lock: PG_writeback (page bit lock)
 *   type: KAPI_LOCK_CUSTOM
 *   acquired: true
 *   released: true
 *   desc: During WAIT_BEFORE and WAIT_AFTER operations, folio_wait_writeback()
 *     waits on the PG_writeback bit of each page in the range. The wait
 *     uses TASK_UNINTERRUPTIBLE state, making it non-interruptible by
 *     signals. The bit is set by writeback initiation and cleared by I/O
 *     completion handlers.
 *
 * lock: file->f_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired during file_check_and_advance_wb_err() when checking
 *     and advancing the file's writeback error sequence number. Ensures
 *     atomic error reporting across concurrent sync operations on the
 *     same file descriptor.
 *
 * signal: any
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DISCARD
 *   condition: During any wait operation
 *   desc: All wait operations in sync_file_range() use TASK_UNINTERRUPTIBLE
 *     state via folio_wait_writeback(). This makes the syscall completely
 *     non-interruptible by signals. Signals delivered during the sync
 *     remain pending and are handled after return. The process will appear
 *     to hang if storage is slow or unresponsive. The hung task detector
 *     will log a warning after hung_task_timeout_secs (default 120 seconds).
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: File data pages in specified range
 *   desc: When SYNC_FILE_RANGE_WRITE is set, initiates writeback of dirty
 *     pages in the specified byte range. Pages are submitted to the block
 *     layer for I/O. The writeback mode (WB_SYNC_NONE vs WB_SYNC_ALL)
 *     depends on the flag combination. Only file DATA is written; file
 *     metadata (inode, directory entries, allocation maps) is NOT synced.
 *   condition: Only when SYNC_FILE_RANGE_WRITE flag is set
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Address space error flags (AS_EIO, AS_ENOSPC)
 *   desc: When WAIT_BEFORE or WAIT_AFTER operations encounter errors,
 *     the AS_EIO and AS_ENOSPC flags in the file's address_space are
 *     checked and cleared via file_check_and_advance_wb_err(). This
 *     means each error is reported to at most one caller. The file's
 *     f_wb_err cursor is also advanced to track which errors have been
 *     reported to this file descriptor.
 *   condition: During WAIT_BEFORE or WAIT_AFTER operations
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: Calling process
 *   desc: The process may sleep for extended periods waiting for I/O
 *     completion during WAIT_BEFORE and WAIT_AFTER operations. With
 *     SYNC_FILE_RANGE_WRITE alone, the process may also block briefly
 *     if the block device request queue is congested, despite using
 *     WB_SYNC_NONE mode. cond_resched() is called between processing
 *     folio batches to allow preemption.
 *   reversible: no
 *
 * constraint: No metadata synchronization
 *   desc: This syscall NEVER writes file metadata. For files where data
 *     has been written past EOF or into holes (sparse regions), the
 *     block allocation metadata is not persisted. A crash after
 *     sync_file_range() but before an fsync()/fdatasync() may result
 *     in data loss or corruption even though sync_file_range() returned
 *     success.
 *
 * constraint: No disk cache flush
 *   desc: The syscall does not issue a disk cache flush command (e.g.,
 *     FLUSH CACHE or FUA). Data may remain in the disk's volatile write
 *     cache after this call returns. For true data durability, use
 *     fsync(2) or fdatasync(2) which issue cache flush commands. This
 *     syscall is designed for background writeback, not crash safety.
 *
 * constraint: 32-bit pgoff_t limitation
 *   desc: On 32-bit systems with 32-bit pgoff_t (sizeof(pgoff_t) == 4),
 *     offsets at or beyond 0x100000000ULL << PAGE_SHIFT are beyond the
 *     page cache's addressing capability. Operations starting at such
 *     offsets succeed immediately without doing anything. Operations
 *     ending at such offsets are truncated to the maximum addressable
 *     range.
 *
 * constraint: Per-file-descriptor error reporting
 *   desc: Writeback errors are tracked per file descriptor using the
 *     errseq_t mechanism. Errors are reported via the file's f_wb_err
 *     cursor and are only reported once. If multiple file descriptors
 *     reference the same file, an error may only be reported to one
 *     of them. Applications should use a single file descriptor for
 *     sync operations or check all descriptors.
 *
 * constraint: Page-aligned operation
 *   desc: The actual synchronization operates on page-aligned boundaries.
 *     The offset is rounded down to the nearest page boundary, and the
 *     end of the range is rounded up. This may result in syncing slightly
 *     more data than specified. For 4KB pages, offset 1000 and nbytes 100
 *     would sync the entire first page (bytes 0-4095).
 *
 * examples: sync_file_range(fd, 0, 0, SYNC_FILE_RANGE_WRITE);  // Async writeback of entire file
 *   sync_file_range(fd, 0, 4096, SYNC_FILE_RANGE_WRITE_AND_WAIT);  // Sync first 4KB
 *   sync_file_range(fd, off, len, SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE);  // Start integrity writeback
 *   sync_file_range(fd, off, len, SYNC_FILE_RANGE_WAIT_AFTER);  // Wait for previous async writeback
 *
 * notes: This syscall was introduced in Linux 2.6.17 specifically for
 *   applications like databases (PostgreSQL) that need fine-grained control
 *   over writeback without the overhead of full fsync operations.
 *
 *   The man page describes this syscall as "extremely dangerous" for portable
 *   programs due to the lack of metadata synchronization. Use fsync(2) or
 *   fdatasync(2) for applications requiring crash-safe data persistence.
 *
 *   Historical note: The writeback mode was changed to WB_SYNC_NONE in commit
 *   23d0127096cb (Linux 4.6) for performance, then partially reverted in commit
 *   c553ea4fdf27 (Linux 5.2) to use WB_SYNC_ALL when all three flags are set,
 *   matching user expectations for the SYNC_FILE_RANGE_WRITE_AND_WAIT case.
 *
 *   Architecture variants: sync_file_range2() is provided for architectures
 *   (ARM, PowerPC, some others) where 64-bit syscall arguments must be
 *   register-aligned. It takes flags before offset/nbytes to avoid padding.
 *   Functionally identical to sync_file_range().
 *
 *   NFS consideration: On NFS, this syscall initiates WRITE operations but
 *   does not issue a COMMIT. The COMMIT (which makes data persistent on the
 *   server) only happens with fsync()/fdatasync(). Therefore sync_file_range()
 *   provides even weaker guarantees on NFS than on local filesystems.
 *
 * since-version: 2.6.17
 */
int ksys_sync_file_range(int fd, loff_t offset, loff_t nbytes,
			 unsigned int flags)
{
	CLASS(fd, f)(fd);

	if (fd_empty(f))
		return -EBADF;

	return sync_file_range(fd_file(f), offset, nbytes, flags);
}

SYSCALL_DEFINE4(sync_file_range, int, fd, loff_t, offset, loff_t, nbytes,
				unsigned int, flags)
{
	return ksys_sync_file_range(fd, offset, nbytes, flags);
}

#if defined(CONFIG_COMPAT) && defined(__ARCH_WANT_COMPAT_SYNC_FILE_RANGE)
COMPAT_SYSCALL_DEFINE6(sync_file_range, int, fd, compat_arg_u64_dual(offset),
		       compat_arg_u64_dual(nbytes), unsigned int, flags)
{
	return ksys_sync_file_range(fd, compat_arg_u64_glue(offset),
				    compat_arg_u64_glue(nbytes), flags);
}
#endif

/* It would be nice if people remember that not all the world's an i386
   when they introduce new system calls */
SYSCALL_DEFINE4(sync_file_range2, int, fd, unsigned int, flags,
				 loff_t, offset, loff_t, nbytes)
{
	return ksys_sync_file_range(fd, offset, nbytes, flags);
}
