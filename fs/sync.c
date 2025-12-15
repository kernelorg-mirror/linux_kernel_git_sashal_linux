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

SYSCALL_DEFINE1(fsync, unsigned int, fd)
{
	return do_fsync(fd, 0);
}

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

/*
 * ksys_sync_file_range() permits finely controlled syncing over a segment of
 * a file in the range offset .. (offset+nbytes-1) inclusive.  If nbytes is
 * zero then ksys_sync_file_range() will operate from offset out to EOF.
 *
 * The flag bits are:
 *
 * SYNC_FILE_RANGE_WAIT_BEFORE: wait upon writeout of all pages in the range
 * before performing the write.
 *
 * SYNC_FILE_RANGE_WRITE: initiate writeout of all those dirty pages in the
 * range which are not presently under writeback. Note that this may block for
 * significant periods due to exhaustion of disk request structures.
 *
 * SYNC_FILE_RANGE_WAIT_AFTER: wait upon writeout of all pages in the range
 * after performing the write.
 *
 * Useful combinations of the flag bits are:
 *
 * SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE: ensures that all pages
 * in the range which were dirty on entry to ksys_sync_file_range() are placed
 * under writeout.  This is a start-write-for-data-integrity operation.
 *
 * SYNC_FILE_RANGE_WRITE: start writeout of all dirty pages in the range which
 * are not presently under writeout.  This is an asynchronous flush-to-disk
 * operation.  Not suitable for data integrity operations.
 *
 * SYNC_FILE_RANGE_WAIT_BEFORE (or SYNC_FILE_RANGE_WAIT_AFTER): wait for
 * completion of writeout of all pages in the range.  This will be used after an
 * earlier SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE operation to wait
 * for that operation to complete and to return the result.
 *
 * SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE|SYNC_FILE_RANGE_WAIT_AFTER
 * (a.k.a. SYNC_FILE_RANGE_WRITE_AND_WAIT):
 * a traditional sync() operation.  This is a write-for-data-integrity operation
 * which will ensure that all pages in the range which were dirty on entry to
 * ksys_sync_file_range() are written to disk.  It should be noted that disk
 * caches are not flushed by this call, so there are no guarantees here that the
 * data will be available on disk after a crash.
 *
 *
 * SYNC_FILE_RANGE_WAIT_BEFORE and SYNC_FILE_RANGE_WAIT_AFTER will detect any
 * I/O errors or ENOSPC conditions and will return those to the caller, after
 * clearing the EIO and ENOSPC flags in the address_space.
 *
 * It should be noted that none of these operations write out the file's
 * metadata.  So unless the application is strictly performing overwrites of
 * already-instantiated disk blocks, there are no guarantees here that the data
 * will be available after a crash.
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
