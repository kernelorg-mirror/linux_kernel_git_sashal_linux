// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/open.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/rcupdate.h>
#include <linux/audit.h>
#include <linux/falloc.h>
#include <linux/fs_struct.h>
#include <linux/dnotify.h>
#include <linux/compat.h>
#include <linux/mnt_idmapping.h>
#include <linux/filelock.h>

#include "internal.h"

int do_truncate(struct mnt_idmap *idmap, struct dentry *dentry,
		loff_t length, unsigned int time_attrs, struct file *filp)
{
	int ret;
	struct iattr newattrs;

	/* Not pretty: "inode->i_size" shouldn't really be signed. But it is. */
	if (length < 0)
		return -EINVAL;

	newattrs.ia_size = length;
	newattrs.ia_valid = ATTR_SIZE | time_attrs;
	if (filp) {
		newattrs.ia_file = filp;
		newattrs.ia_valid |= ATTR_FILE;
	}

	/* Remove suid, sgid, and file capabilities on truncate too */
	ret = dentry_needs_remove_privs(idmap, dentry);
	if (ret < 0)
		return ret;
	if (ret)
		newattrs.ia_valid |= ret | ATTR_FORCE;

	ret = inode_lock_killable(dentry->d_inode);
	if (ret)
		return ret;

	/* Note any delegations or leases have already been broken: */
	ret = notify_change(idmap, dentry, &newattrs, NULL);
	inode_unlock(dentry->d_inode);
	return ret;
}

int vfs_truncate(const struct path *path, loff_t length)
{
	struct mnt_idmap *idmap;
	struct inode *inode;
	int error;

	inode = path->dentry->d_inode;

	/* For directories it's -EISDIR, for other non-regulars - -EINVAL */
	if (S_ISDIR(inode->i_mode))
		return -EISDIR;
	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	idmap = mnt_idmap(path->mnt);
	error = inode_permission(idmap, inode, MAY_WRITE);
	if (error)
		return error;

	error = fsnotify_truncate_perm(path, length);
	if (error)
		return error;

	error = mnt_want_write(path->mnt);
	if (error)
		return error;

	error = -EPERM;
	if (IS_APPEND(inode))
		goto mnt_drop_write_and_out;

	error = get_write_access(inode);
	if (error)
		goto mnt_drop_write_and_out;

	/*
	 * Make sure that there are no leases.  get_write_access() protects
	 * against the truncate racing with a lease-granting setlease().
	 */
	error = break_lease(inode, O_WRONLY);
	if (error)
		goto put_write_and_out;

	error = security_path_truncate(path);
	if (!error)
		error = do_truncate(idmap, path->dentry, length, 0, NULL);

put_write_and_out:
	put_write_access(inode);
mnt_drop_write_and_out:
	mnt_drop_write(path->mnt);

	return error;
}
EXPORT_SYMBOL_GPL(vfs_truncate);

int do_sys_truncate(const char __user *pathname, loff_t length)
{
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	struct path path;
	int error;

	if (length < 0)	/* sorry, but loff_t says... */
		return -EINVAL;

retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (!error) {
		error = vfs_truncate(&path, length);
		path_put(&path);
	}
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE2(truncate, const char __user *, path, long, length)
{
	return do_sys_truncate(path, length);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(truncate, const char __user *, path, compat_off_t, length)
{
	return do_sys_truncate(path, length);
}
#endif

int do_ftruncate(struct file *file, loff_t length, int small)
{
	struct inode *inode;
	struct dentry *dentry;
	int error;

	/* explicitly opened as large or we are on 64-bit box */
	if (file->f_flags & O_LARGEFILE)
		small = 0;

	dentry = file->f_path.dentry;
	inode = dentry->d_inode;
	if (!S_ISREG(inode->i_mode) || !(file->f_mode & FMODE_WRITE))
		return -EINVAL;

	/* Cannot ftruncate over 2^31 bytes without large file support */
	if (small && length > MAX_NON_LFS)
		return -EINVAL;

	/* Check IS_APPEND on real upper inode */
	if (IS_APPEND(file_inode(file)))
		return -EPERM;

	error = security_file_truncate(file);
	if (error)
		return error;

	error = fsnotify_truncate_perm(&file->f_path, length);
	if (error)
		return error;

	scoped_guard(super_write, inode->i_sb)
		return do_truncate(file_mnt_idmap(file), dentry, length,
				   ATTR_MTIME | ATTR_CTIME, file);
}

int do_sys_ftruncate(unsigned int fd, loff_t length, int small)
{
	if (length < 0)
		return -EINVAL;
	CLASS(fd, f)(fd);
	if (fd_empty(f))
		return -EBADF;

	return do_ftruncate(fd_file(f), length, small);
}

SYSCALL_DEFINE2(ftruncate, unsigned int, fd, off_t, length)
{
	return do_sys_ftruncate(fd, length, 1);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(ftruncate, unsigned int, fd, compat_off_t, length)
{
	return do_sys_ftruncate(fd, length, 1);
}
#endif

/* LFS versions of truncate are only needed on 32 bit machines */
#if BITS_PER_LONG == 32
SYSCALL_DEFINE2(truncate64, const char __user *, path, loff_t, length)
{
	return do_sys_truncate(path, length);
}

SYSCALL_DEFINE2(ftruncate64, unsigned int, fd, loff_t, length)
{
	return do_sys_ftruncate(fd, length, 0);
}
#endif /* BITS_PER_LONG == 32 */

#if defined(CONFIG_COMPAT) && defined(__ARCH_WANT_COMPAT_TRUNCATE64)
COMPAT_SYSCALL_DEFINE3(truncate64, const char __user *, pathname,
		       compat_arg_u64_dual(length))
{
	return ksys_truncate(pathname, compat_arg_u64_glue(length));
}
#endif

#if defined(CONFIG_COMPAT) && defined(__ARCH_WANT_COMPAT_FTRUNCATE64)
COMPAT_SYSCALL_DEFINE3(ftruncate64, unsigned int, fd,
		       compat_arg_u64_dual(length))
{
	return ksys_ftruncate(fd, compat_arg_u64_glue(length));
}
#endif

int vfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	int ret;
	loff_t sum;

	if (offset < 0 || len <= 0)
		return -EINVAL;

	if (mode & ~(FALLOC_FL_MODE_MASK | FALLOC_FL_KEEP_SIZE))
		return -EOPNOTSUPP;

	/*
	 * Modes are exclusive, even if that is not obvious from the encoding
	 * as bit masks and the mix with the flag in the same namespace.
	 *
	 * To make things even more complicated, FALLOC_FL_ALLOCATE_RANGE is
	 * encoded as no bit set.
	 */
	switch (mode & FALLOC_FL_MODE_MASK) {
	case FALLOC_FL_ALLOCATE_RANGE:
	case FALLOC_FL_UNSHARE_RANGE:
	case FALLOC_FL_ZERO_RANGE:
		break;
	case FALLOC_FL_PUNCH_HOLE:
		if (!(mode & FALLOC_FL_KEEP_SIZE))
			return -EOPNOTSUPP;
		break;
	case FALLOC_FL_COLLAPSE_RANGE:
	case FALLOC_FL_INSERT_RANGE:
	case FALLOC_FL_WRITE_ZEROES:
		if (mode & FALLOC_FL_KEEP_SIZE)
			return -EOPNOTSUPP;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;

	/*
	 * On append-only files only space preallocation is supported.
	 */
	if ((mode & ~FALLOC_FL_KEEP_SIZE) && IS_APPEND(inode))
		return -EPERM;

	if (IS_IMMUTABLE(inode))
		return -EPERM;

	/*
	 * We cannot allow any fallocate operation on an active swapfile
	 */
	if (IS_SWAPFILE(inode))
		return -ETXTBSY;

	/*
	 * Revalidate the write permissions, in case security policy has
	 * changed since the files were opened.
	 */
	ret = security_file_permission(file, MAY_WRITE);
	if (ret)
		return ret;

	ret = fsnotify_file_area_perm(file, MAY_WRITE, &offset, len);
	if (ret)
		return ret;

	if (S_ISFIFO(inode->i_mode))
		return -ESPIPE;

	if (S_ISDIR(inode->i_mode))
		return -EISDIR;

	if (!S_ISREG(inode->i_mode) && !S_ISBLK(inode->i_mode))
		return -ENODEV;

	/* Check for wraparound */
	if (check_add_overflow(offset, len, &sum))
		return -EFBIG;

	if (sum > inode->i_sb->s_maxbytes)
		return -EFBIG;

	if (!file->f_op->fallocate)
		return -EOPNOTSUPP;

	file_start_write(file);
	ret = file->f_op->fallocate(file, mode, offset, len);

	/*
	 * Create inotify and fanotify events.
	 *
	 * To keep the logic simple always create events if fallocate succeeds.
	 * This implies that events are even created if the file size remains
	 * unchanged, e.g. when using flag FALLOC_FL_KEEP_SIZE.
	 */
	if (ret == 0)
		fsnotify_modify(file);

	file_end_write(file);
	return ret;
}
EXPORT_SYMBOL_GPL(vfs_fallocate);

int ksys_fallocate(int fd, int mode, loff_t offset, loff_t len)
{
	CLASS(fd, f)(fd);

	if (fd_empty(f))
		return -EBADF;

	return vfs_fallocate(fd_file(f), mode, offset, len);
}

/**
 * sys_fallocate - Manipulate file space allocation
 * @fd: File descriptor of the target file
 * @mode: Operation mode flags (FALLOC_FL_* bitmask)
 * @offset: Starting byte offset for the operation
 * @len: Length in bytes of the range to operate on
 *
 * long-desc: Manipulates the allocated disk space for a file within the
 *   specified range [offset, offset+len). The behavior depends on the mode
 *   flags provided. This is a Linux-specific syscall; the portable alternative
 *   is posix_fallocate(3), which provides a subset of functionality.
 *
 *   Mode 0 (FALLOC_FL_ALLOCATE_RANGE): Allocates disk space for the specified
 *   range, ensuring subsequent writes won't fail due to lack of space. If the
 *   range extends beyond EOF, the file size is increased. Uninitialized regions
 *   within the range read as zeros. Allocation may exceed the requested range
 *   due to filesystem block size rounding.
 *
 *   FALLOC_FL_KEEP_SIZE: Can be ORed with allocation modes. Prevents file size
 *   changes even if offset+len exceeds i_size. Useful for preallocating space
 *   for append workloads without changing visible file size.
 *
 *   FALLOC_FL_PUNCH_HOLE: Deallocates space in the range, creating a hole.
 *   Partial blocks are zeroed; whole blocks are removed. MUST be combined with
 *   FALLOC_FL_KEEP_SIZE. File size remains unchanged. Supported on ext4, XFS,
 *   Btrfs, tmpfs, gfs2, and others.
 *
 *   FALLOC_FL_COLLAPSE_RANGE: Removes the byte range without leaving a hole.
 *   Content after the range is shifted to offset, reducing file size by len
 *   bytes. Both offset and len must be multiples of filesystem block size.
 *   Cannot reach or pass EOF. Cannot be combined with other flags.
 *
 *   FALLOC_FL_ZERO_RANGE: Zeros the range efficiently using unwritten extents
 *   or metadata operations when possible. Blocks are preallocated for hole
 *   regions. Can be combined with FALLOC_FL_KEEP_SIZE.
 *
 *   FALLOC_FL_INSERT_RANGE: Inserts a hole at offset, shifting existing content
 *   upward by len bytes, increasing file size. Both offset and len must be
 *   multiples of filesystem block size. Offset must be less than EOF. Cannot
 *   be combined with other flags.
 *
 *   FALLOC_FL_UNSHARE_RANGE: Unshares copy-on-write blocks, making them private.
 *   Useful for ensuring subsequent writes don't fail due to CoW space issues.
 *   Cannot be combined with punch, zero, collapse, or insert modes.
 *
 *   FALLOC_FL_WRITE_ZEROES: Zeros a range in a way optimized for subsequent
 *   overwrites. May use hardware write-zeroes commands. Cannot be combined
 *   with FALLOC_FL_KEEP_SIZE.
 *
 *   Filesystem support varies. Not all filesystems support all modes. Block
 *   devices support basic allocation. Pipes, FIFOs, sockets, and directories
 *   are not supported.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid file descriptor open for writing (O_WRONLY or
 *     O_RDWR). Must refer to a regular file or block device. Pipes, FIFOs,
 *     directories, sockets, and most special files are not supported.
 *
 * param: mode
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
 *               FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE |
 *               FALLOC_FL_INSERT_RANGE | FALLOC_FL_UNSHARE_RANGE |
 *               FALLOC_FL_WRITE_ZEROES
 *   constraint: Mode flags are mutually exclusive (only one operation type),
 *     except FALLOC_FL_KEEP_SIZE which can be combined with allocation,
 *     unshare, and zero-range modes. FALLOC_FL_PUNCH_HOLE requires
 *     FALLOC_FL_KEEP_SIZE to be set. FALLOC_FL_COLLAPSE_RANGE,
 *     FALLOC_FL_INSERT_RANGE, and FALLOC_FL_WRITE_ZEROES cannot be combined
 *     with FALLOC_FL_KEEP_SIZE. Mode 0 (no flags) performs space preallocation.
 *
 * param: offset
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, LLONG_MAX
 *   constraint: Must be non-negative. For FALLOC_FL_COLLAPSE_RANGE and
 *     FALLOC_FL_INSERT_RANGE, must be aligned to filesystem block size.
 *     For FALLOC_FL_INSERT_RANGE, must be strictly less than current file
 *     size. For FALLOC_FL_COLLAPSE_RANGE, offset+len must not reach or
 *     exceed EOF. offset+len must not overflow loff_t or exceed s_maxbytes.
 *
 * param: len
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_NONZERO
 *   constraint: Must be strictly positive (len > 0). For FALLOC_FL_COLLAPSE_RANGE
 *     and FALLOC_FL_INSERT_RANGE, must be aligned to filesystem block size.
 *     offset+len must not overflow or exceed maximum file size limits.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. On error, returns a negative error code.
 *     The operation is generally not atomic; a failure may leave the file
 *     in a partially modified state depending on the filesystem.
 *
 * error: EBADF, Bad file descriptor
 *   desc: fd is not a valid open file descriptor, or fd is not opened for
 *     writing (missing O_WRONLY or O_RDWR access mode).
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned for multiple conditions: (1) offset is negative, (2) len
 *     is zero or negative, (3) for FALLOC_FL_COLLAPSE_RANGE or
 *     FALLOC_FL_INSERT_RANGE, offset or len is not a multiple of the
 *     filesystem logical block size, (4) for FALLOC_FL_COLLAPSE_RANGE,
 *     offset+len reaches or exceeds EOF, (5) for FALLOC_FL_INSERT_RANGE,
 *     offset is at or beyond EOF, (6) mode contains incompatible flag
 *     combinations.
 *
 * error: EOPNOTSUPP, Operation not supported
 *   desc: The filesystem does not implement fallocate, or does not support
 *     the requested mode. Also returned for unsupported flag combinations
 *     that pass initial validation, or when the filesystem-specific handler
 *     rejects the operation (e.g., collapse/insert on encrypted ext4 files).
 *
 * error: EPERM, Operation not permitted
 *   desc: The file has the immutable attribute set (chattr +i), or the file
 *     is append-only (chattr +a) and the operation is not pure preallocation.
 *     Also returned when file seals prevent the operation: F_SEAL_WRITE or
 *     F_SEAL_FUTURE_WRITE blocks punch-hole, F_SEAL_GROW blocks operations
 *     that would extend the file.
 *
 * error: ETXTBSY, Text file busy
 *   desc: The file is an active swap file, or for FALLOC_FL_COLLAPSE_RANGE
 *     or FALLOC_FL_INSERT_RANGE, the file is currently being executed.
 *
 * error: ESPIPE, Illegal seek
 *   desc: fd refers to a pipe or FIFO, which do not support fallocate.
 *
 * error: EISDIR, Is a directory
 *   desc: fd refers to a directory. Directories do not support fallocate.
 *
 * error: ENODEV, No such device
 *   desc: fd refers to a file type that is not a regular file or block
 *     device (e.g., socket, character device).
 *
 * error: EFBIG, File too large
 *   desc: offset+len exceeds the maximum file size supported by the
 *     filesystem (s_maxbytes), or would cause offset+len to overflow,
 *     or (when extending file size) would exceed RLIMIT_FSIZE. When
 *     RLIMIT_FSIZE is exceeded, SIGXFSZ is also sent to the process.
 *
 * error: ENOSPC, No space left on device
 *   desc: The device containing the file has insufficient free space to
 *     allocate the requested blocks. Also returned by tmpfs when the
 *     requested range exceeds configured maximum blocks.
 *
 * error: EIO, I/O error
 *   desc: An I/O error occurred during the filesystem operation, typically
 *     when reading or writing metadata or data blocks.
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory to complete the operation. This may
 *     occur during extent allocation, page cache operations, or internal
 *     structure allocation.
 *
 * error: EINTR, Interrupted system call
 *   desc: The operation was interrupted by a signal before completion.
 *     Some filesystems check for fatal signals during long-running
 *     allocation loops and may return early with partial completion.
 *
 * lock: sb_writers (SB_FREEZE_WRITE level)
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Acquired via file_start_write() to prevent filesystem freeze
 *     during the operation. This is a per-cpu read-write semaphore that
 *     blocks freeze_super() while held. Released via file_end_write()
 *     after the filesystem's fallocate handler returns.
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Acquired by filesystem-specific fallocate handlers (e.g., ext4,
 *     XFS, Btrfs) to serialize access to inode metadata and prevent
 *     concurrent modifications. Most filesystems acquire this lock
 *     exclusively. Released before return.
 *
 * lock: mapping->invalidate_lock
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: conditional
 *   released: true
 *   desc: Acquired by some filesystem handlers (e.g., ext4 for punch-hole,
 *     collapse, insert, zero-range) to prevent page cache invalidation
 *     races. Prevents page faults from reinstantiating pages being removed.
 *
 * signal: SIGXFSZ
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: When file size change would exceed RLIMIT_FSIZE
 *   desc: Sent to the calling process when the operation would extend the
 *     file size beyond the soft RLIMIT_FSIZE limit. The signal is sent
 *     via send_sig() from inode_newsize_ok() and the syscall returns
 *     -EFBIG. The default action for SIGXFSZ is to terminate the process.
 *   timing: KAPI_SIGNAL_TIME_BEFORE
 *
 * signal: pending_signals
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: During long-running filesystem operations
 *   desc: Some filesystems (e.g., tmpfs/shmem) check fatal_signal_pending()
 *     during allocation loops. If a fatal signal is pending, the operation
 *     aborts early, potentially leaving the file partially modified.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM | KAPI_EFFECT_MODIFY_STATE
 *   target: File data blocks and metadata
 *   desc: Allocates, deallocates, or modifies disk blocks associated with
 *     the file depending on mode. For preallocation (mode 0), blocks are
 *     reserved. For punch-hole, blocks are freed. For collapse/insert,
 *     block mappings are reorganized. For zero-range, blocks may be
 *     converted to unwritten extents or zeroed.
 *   condition: Always on success
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: File size (i_size)
 *   desc: Unless FALLOC_FL_KEEP_SIZE is specified, extending allocations
 *     increase i_size to offset+len. FALLOC_FL_COLLAPSE_RANGE decreases
 *     i_size by len bytes. FALLOC_FL_INSERT_RANGE increases i_size by
 *     len bytes. FALLOC_FL_PUNCH_HOLE never changes i_size (requires
 *     KEEP_SIZE flag).
 *   condition: When not using FALLOC_FL_KEEP_SIZE and range extends beyond EOF
 *   reversible: yes (via truncate)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Inode timestamps (ctime, mtime)
 *   desc: The inode's ctime and mtime are updated to the current time
 *     via file_modified() called by filesystem handlers. This reflects
 *     that the file's content or metadata has changed.
 *   condition: On successful modification
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: File mode bits (setuid, setgid)
 *   desc: The setuid and setgid bits may be cleared from the file mode
 *     via file_remove_privs() called by file_modified(). This security
 *     measure prevents privilege escalation after file modification.
 *   condition: When file has setuid/setgid bits and is modified
 *   reversible: yes (via chmod)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify events
 *   desc: On successful completion, fsnotify_modify() is called to generate
 *     inotify and fanotify FS_MODIFY events, notifying watchers of the
 *     file content change. Events are generated even for KEEP_SIZE
 *     operations that don't change visible file size.
 *   condition: Operation succeeds (returns 0)
 *   reversible: no
 *
 * constraint: File Seals
 *   desc: For files with seals (e.g., memfd, shmem), certain seals block
 *     specific operations. F_SEAL_WRITE and F_SEAL_FUTURE_WRITE prevent
 *     punch-hole operations. F_SEAL_GROW prevents operations that would
 *     extend the file size. F_SEAL_SHRINK prevents collapse operations
 *     (implicit in setattr checks). Sealed files return -EPERM.
 *
 * constraint: Filesystem Block Alignment
 *   desc: FALLOC_FL_COLLAPSE_RANGE and FALLOC_FL_INSERT_RANGE require both
 *     offset and len to be aligned to the filesystem's logical block size.
 *     The specific alignment requirement varies by filesystem. Misaligned
 *     requests return -EINVAL.
 *
 * constraint: Resource Limits
 *   desc: When extending file size, the new size is checked against
 *     RLIMIT_FSIZE. If the limit would be exceeded, SIGXFSZ is sent and
 *     -EFBIG is returned. The filesystem's s_maxbytes limit also applies.
 *     Some filesystems (tmpfs) have additional block count limits.
 *
 * examples: fallocate(fd, 0, 0, 1048576);  // Preallocate 1MB from start
 *   fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, 4096);  // Preallocate without size change
 *   fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 4096, 4096);  // Punch hole
 *   fallocate(fd, FALLOC_FL_ZERO_RANGE, 0, 4096);  // Zero first 4KB
 *   fallocate(fd, FALLOC_FL_COLLAPSE_RANGE, 4096, 4096);  // Remove second 4KB block
 *   fallocate(fd, FALLOC_FL_INSERT_RANGE, 4096, 4096);  // Insert 4KB hole
 *
 * notes: This is a Linux-specific syscall introduced in Linux 2.6.23. The
 *   portable POSIX equivalent is posix_fallocate(3), which only supports
 *   basic allocation (mode 0 behavior) and falls back to writing zeros
 *   if the filesystem lacks native support.
 *
 *   On 32-bit architectures, the compat syscall splits the 64-bit offset
 *   and len parameters into high/low 32-bit pairs.
 *
 *   Filesystem support for various modes: ext4 supports all modes except
 *   UNSHARE (extent-based files only for some modes). XFS supports all
 *   modes. Btrfs supports allocation, punch-hole, and zero-range. tmpfs
 *   supports allocation and punch-hole. NFS v4.2+ supports allocation,
 *   punch-hole, and zero-range. Block devices support basic allocation.
 *
 *   The operation is NOT guaranteed to be atomic. A crash or error during
 *   the operation may leave the file in a partially modified state. For
 *   data integrity, use fsync() after fallocate().
 *
 * since-version: 2.6.23
 */
SYSCALL_DEFINE4(fallocate, int, fd, int, mode, loff_t, offset, loff_t, len)
{
	return ksys_fallocate(fd, mode, offset, len);
}

#if defined(CONFIG_COMPAT) && defined(__ARCH_WANT_COMPAT_FALLOCATE)
COMPAT_SYSCALL_DEFINE6(fallocate, int, fd, int, mode, compat_arg_u64_dual(offset),
		       compat_arg_u64_dual(len))
{
	return ksys_fallocate(fd, mode, compat_arg_u64_glue(offset),
			      compat_arg_u64_glue(len));
}
#endif

/*
 * access() needs to use the real uid/gid, not the effective uid/gid.
 * We do this by temporarily clearing all FS-related capabilities and
 * switching the fsuid/fsgid around to the real ones.
 *
 * Creating new credentials is expensive, so we try to skip doing it,
 * which we can if the result would match what we already got.
 */
static bool access_need_override_creds(int flags)
{
	const struct cred *cred;

	if (flags & AT_EACCESS)
		return false;

	cred = current_cred();
	if (!uid_eq(cred->fsuid, cred->uid) ||
	    !gid_eq(cred->fsgid, cred->gid))
		return true;

	if (!issecure(SECURE_NO_SETUID_FIXUP)) {
		kuid_t root_uid = make_kuid(cred->user_ns, 0);
		if (!uid_eq(cred->uid, root_uid)) {
			if (!cap_isclear(cred->cap_effective))
				return true;
		} else {
			if (!cap_isidentical(cred->cap_effective,
			    cred->cap_permitted))
				return true;
		}
	}

	return false;
}

static const struct cred *access_override_creds(void)
{
	struct cred *override_cred;

	override_cred = prepare_creds();
	if (!override_cred)
		return NULL;

	/*
	 * XXX access_need_override_creds performs checks in hopes of skipping
	 * this work. Make sure it stays in sync if making any changes in this
	 * routine.
	 */

	override_cred->fsuid = override_cred->uid;
	override_cred->fsgid = override_cred->gid;

	if (!issecure(SECURE_NO_SETUID_FIXUP)) {
		/* Clear the capabilities if we switch to a non-root user */
		kuid_t root_uid = make_kuid(override_cred->user_ns, 0);
		if (!uid_eq(override_cred->uid, root_uid))
			cap_clear(override_cred->cap_effective);
		else
			override_cred->cap_effective =
				override_cred->cap_permitted;
	}

	/*
	 * The new set of credentials can *only* be used in
	 * task-synchronous circumstances, and does not need
	 * RCU freeing, unless somebody then takes a separate
	 * reference to it.
	 *
	 * NOTE! This is _only_ true because this credential
	 * is used purely for override_creds() that installs
	 * it as the subjective cred. Other threads will be
	 * accessing ->real_cred, not the subjective cred.
	 *
	 * If somebody _does_ make a copy of this (using the
	 * 'get_current_cred()' function), that will clear the
	 * non_rcu field, because now that other user may be
	 * expecting RCU freeing. But normal thread-synchronous
	 * cred accesses will keep things non-racy to avoid RCU
	 * freeing.
	 */
	override_cred->non_rcu = 1;
	return override_creds(override_cred);
}

static int do_faccessat(int dfd, const char __user *filename, int mode, int flags)
{
	struct path path;
	struct inode *inode;
	int res;
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	const struct cred *old_cred = NULL;

	if (mode & ~S_IRWXO)	/* where's F_OK, X_OK, W_OK, R_OK? */
		return -EINVAL;

	if (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
		return -EINVAL;

	if (flags & AT_SYMLINK_NOFOLLOW)
		lookup_flags &= ~LOOKUP_FOLLOW;
	if (flags & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;

	if (access_need_override_creds(flags)) {
		old_cred = access_override_creds();
		if (!old_cred)
			return -ENOMEM;
	}

retry:
	res = user_path_at(dfd, filename, lookup_flags, &path);
	if (res)
		goto out;

	inode = d_backing_inode(path.dentry);

	if ((mode & MAY_EXEC) && S_ISREG(inode->i_mode)) {
		/*
		 * MAY_EXEC on regular files is denied if the fs is mounted
		 * with the "noexec" flag.
		 */
		res = -EACCES;
		if (path_noexec(&path))
			goto out_path_release;
	}

	res = inode_permission(mnt_idmap(path.mnt), inode, mode | MAY_ACCESS);
	/* SuS v2 requires we report a read only fs too */
	if (res || !(mode & S_IWOTH) || special_file(inode->i_mode))
		goto out_path_release;
	/*
	 * This is a rare case where using __mnt_is_readonly()
	 * is OK without a mnt_want/drop_write() pair.  Since
	 * no actual write to the fs is performed here, we do
	 * not need to telegraph to that to anyone.
	 *
	 * By doing this, we accept that this access is
	 * inherently racy and know that the fs may change
	 * state before we even see this result.
	 */
	if (__mnt_is_readonly(path.mnt))
		res = -EROFS;

out_path_release:
	path_put(&path);
	if (retry_estale(res, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	if (old_cred)
		put_cred(revert_creds(old_cred));

	return res;
}

/**
 * sys_faccessat - check user's permissions for a file relative to a directory
 * @dfd: Directory file descriptor (or AT_FDCWD for current working directory)
 * @filename: Pathname of file to check, relative to @dfd or absolute
 * @mode: Accessibility check mask (F_OK, R_OK, W_OK, X_OK, or combinations)
 *
 * long-desc: Checks whether the calling process can access the file specified
 *   by @filename. When @dfd is AT_FDCWD, relative paths are resolved from the
 *   current working directory. When @dfd is a valid directory file descriptor,
 *   relative paths are resolved from that directory. Absolute paths ignore
 *   @dfd in both cases.
 *
 *   Unlike most syscalls which use effective user/group IDs, faccessat() uses
 *   the real uid/gid for permission checks. This is achieved by temporarily
 *   overriding credentials: fsuid is set to uid, fsgid is set to gid, and
 *   effective capabilities are cleared (for non-root) or set to permitted
 *   capabilities (for root), unless the SECURE_NO_SETUID_FIXUP securebits flag
 *   is set. This behavior matches the POSIX access() semantics designed for
 *   set-user-ID programs to check permissions of the real user.
 *
 *   The @mode argument specifies the accessibility checks: F_OK (0) tests for
 *   existence only, R_OK (4) tests read permission, W_OK (2) tests write
 *   permission, X_OK (1) tests execute permission. These can be combined via
 *   bitwise OR. The check succeeds only if ALL requested permissions are
 *   granted.
 *
 *   For regular files with X_OK, the syscall also checks if the filesystem is
 *   mounted with the "noexec" option and returns -EACCES if so. For write
 *   permission checks on non-special files, the syscall additionally verifies
 *   the filesystem is not read-only, returning -EROFS if it is.
 *
 *   WARNING: Using access/faccessat to check permissions before opening a file
 *   creates a time-of-check-time-of-use (TOCTOU) race condition. File
 *   permissions or existence may change between the check and subsequent
 *   operation. Do not use this syscall for security-critical access control.
 *
 *   This syscall was introduced in Linux 2.6.16. Note that faccessat() does
 *   not accept a flags argument; use faccessat2() for flag support including
 *   AT_EACCESS, AT_SYMLINK_NOFOLLOW, and AT_EMPTY_PATH.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: dfd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be AT_FDCWD (-100) to use current working directory, or
 *     a valid file descriptor referring to a directory when @filename is a
 *     relative path. Ignored when @filename is an absolute path. An invalid
 *     or non-directory file descriptor with a relative path returns -EBADF
 *     or -ENOTDIR respectively.
 *
 * param: filename
 *   type: KAPI_TYPE_PATH
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid null-terminated pathname in user-space memory.
 *     Maximum total path length is PATH_MAX (4096) bytes including null
 *     terminator. Individual path components are limited to NAME_MAX (255)
 *     bytes. An empty string returns -ENOENT. If the pointer is invalid or
 *     inaccessible, returns -EFAULT.
 *
 * param: mode
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: 0x7
 *   constraint: Must contain only bits from S_IRWXO (octal 0007), corresponding
 *     to R_OK (4), W_OK (2), X_OK (1), or F_OK (0). The value 0 (F_OK) tests
 *     only for existence. Any bits set outside this mask cause -EINVAL.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 if all requested permissions are granted (or if @mode is
 *     F_OK and the file exists). On failure, returns a negative error code.
 *
 * error: EINVAL, Invalid mode bits
 *   desc: The @mode argument contains bits outside the valid mask (S_IRWXO).
 *     Valid values are F_OK (0), or any combination of R_OK (4), W_OK (2),
 *     and X_OK (1).
 *
 * error: EFAULT, Bad address
 *   desc: The @filename pointer points outside the accessible address space.
 *     Detected when copying the pathname from user space via strncpy_from_user()
 *     in getname_flags().
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory to allocate the filename structure via
 *     __getname(), or to allocate credentials via prepare_creds() for the
 *     temporary credential override.
 *
 * error: ENOENT, No such file or directory
 *   desc: A component of @filename does not exist, or @filename is an empty
 *     string, or @filename is a dangling symbolic link pointing to a
 *     nonexistent target, or a directory component has been removed.
 *
 * error: EBADF, Bad file descriptor
 *   desc: @dfd is not AT_FDCWD and is not a valid open file descriptor,
 *     and @filename is a relative path. Not returned for absolute paths.
 *
 * error: ENOTDIR, Not a directory
 *   desc: A component of @filename used as a directory is not actually a
 *     directory, or @dfd refers to a non-directory file and @filename is
 *     a relative path.
 *
 * error: ELOOP, Too many symbolic links
 *   desc: Too many symbolic links were encountered while resolving @filename.
 *     The kernel limit is 40 symlinks per path resolution with a maximum
 *     recursion depth of 8 for nested symbolic links (MAXSYMLINKS).
 *
 * error: ENAMETOOLONG, File name too long
 *   desc: @filename or one of its path components exceeds system limits.
 *     Individual components are limited to NAME_MAX (255) bytes, and the
 *     total path is limited to PATH_MAX (4096) bytes including terminator.
 *
 * error: EACCES, Permission denied
 *   desc: The requested access would be denied. This can occur because:
 *     (1) read, write, or execute permission is denied for the file itself,
 *     (2) search permission is denied for a directory in the path prefix,
 *     (3) execute permission was requested on a regular file and the
 *     filesystem is mounted with MS_NOEXEC (noexec option), (4) the file
 *     has an unmapped uid/gid and write was requested. Permission checking
 *     uses real uid/gid, not effective, unless AT_EACCESS flag is used
 *     with faccessat2().
 *
 * error: EPERM, Operation not permitted
 *   desc: Write access was requested on a file that has the immutable
 *     attribute set (via chattr +i or FS_IMMUTABLE_FL ioctl flag).
 *
 * error: EROFS, Read-only file system
 *   desc: Write access was requested on a file that resides on a read-only
 *     filesystem. This includes filesystems mounted read-only and those
 *     that became read-only due to errors (remount-ro). Only checked for
 *     non-special files (not sockets, FIFOs, block/char devices).
 *
 * error: EIO, Input/output error
 *   desc: An I/O error occurred while reading from the filesystem during
 *     path resolution or inode lookup. This is filesystem-dependent and
 *     indicates a hardware or low-level filesystem error.
 *
 * error: ESTALE, Stale file handle
 *   desc: The file handle has become stale, typically on NFS when the file
 *     was deleted or replaced on the server. The kernel automatically
 *     retries with LOOKUP_REVAL to revalidate, but if it still fails,
 *     -ESTALE is returned to userspace.
 *
 * error: EOVERFLOW, Value too large
 *   desc: The file's uid or gid cannot be represented in the current
 *     user namespace. Returned when HAS_UNMAPPED_ID() is true for the
 *     inode during permission checking.
 *
 * lock: RCU read-side critical section
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: Path lookup uses RCU-walk mode (rcu_read_lock) for fast path
 *     resolution. If RCU-walk fails (e.g., due to blocking operation needed),
 *     the lookup falls back to reference-counted (ref-walk) mode.
 *
 * lock: inode->i_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: conditional
 *   released: true
 *   desc: May be briefly acquired when setting the IOP_FASTPERM flag on an
 *     inode during permission checking optimization. This is a one-time
 *     operation per inode lifetime.
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypasses read, write, and execute permission checks on files
 *     and directories. For execute permission on files, at least one execute
 *     bit (owner, group, or other) must still be set.
 *   without: Permission checks follow standard UNIX DAC rules based on file
 *     mode bits and real uid/gid of the calling process.
 *   condition: Checked via capable_wrt_inode_uidgid() in generic_permission()
 *     when initial permission check fails.
 *
 * capability: CAP_DAC_READ_SEARCH
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypasses read permission checks on files and read/execute (search)
 *     permission checks on directories.
 *   without: Permission checks follow standard UNIX DAC rules.
 *   condition: Checked via capable_wrt_inode_uidgid() in generic_permission()
 *     when initial permission check fails.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Task credentials (temporary)
 *   desc: Temporarily overrides the calling task's subjective credentials
 *     to use real uid/gid instead of effective uid/gid for permission
 *     checking. This modification is task-local and is reverted before
 *     the syscall returns via revert_creds().
 *   reversible: yes
 *   condition: Always, unless AT_EACCESS flag is used with faccessat2()
 *
 * constraint: TOCTOU Race Condition
 *   desc: Results of access/faccessat are inherently racy. The file's
 *     permissions, ownership, or existence may change between this check
 *     and any subsequent operation on the file. Do not rely on this syscall
 *     for security decisions. The kernel explicitly acknowledges this in
 *     the __mnt_is_readonly() check with a comment noting the race.
 *
 * constraint: Real vs Effective ID Semantics
 *   desc: Unlike most filesystem operations, faccessat() checks permissions
 *     using real uid/gid, not effective uid/gid. This is the POSIX-mandated
 *     behavior for access(). To check with effective credentials, use
 *     faccessat2() with the AT_EACCESS flag.
 *
 * examples: faccessat(AT_FDCWD, "/etc/passwd", R_OK);  // Check readable
 *   faccessat(AT_FDCWD, "/tmp", W_OK | X_OK);  // Check write+search on dir
 *   faccessat(dirfd, "file.txt", F_OK);  // Check existence relative to dirfd
 *
 * notes: This syscall follows symbolic links by default. To check the
 *   permissions of a symlink itself without following it, use faccessat2()
 *   with the AT_SYMLINK_NOFOLLOW flag. The original faccessat() deliberately
 *   omits the flags argument present in the POSIX specification; glibc's
 *   faccessat() wrapper emulates flags via faccessat2() when available.
 *
 *   ACLs (Access Control Lists) are considered if the filesystem supports
 *   POSIX ACLs. The check_acl() function is called during permission
 *   evaluation when the file has ACL entries.
 *
 *   On idmapped mounts, uid/gid mapping is applied before permission checking
 *   via mnt_idmap().
 *
 * since-version: 2.6.16
 */
SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
{
	return do_faccessat(dfd, filename, mode, 0);
}

SYSCALL_DEFINE4(faccessat2, int, dfd, const char __user *, filename, int, mode,
		int, flags)
{
	return do_faccessat(dfd, filename, mode, flags);
}

SYSCALL_DEFINE2(access, const char __user *, filename, int, mode)
{
	return do_faccessat(AT_FDCWD, filename, mode, 0);
}

/**
 * sys_chdir - Change current working directory
 * @filename: Pathname of new working directory
 *
 * long-desc: Changes the current working directory of the calling process to
 *   the directory specified by @filename. The current working directory is
 *   the starting point for interpreting relative pathnames (those not starting
 *   with '/').
 *
 *   The path resolution follows symbolic links (LOOKUP_FOLLOW). The final
 *   component must be a directory (LOOKUP_DIRECTORY). The calling process
 *   must have search (execute) permission on the target directory.
 *
 *   If the path lookup encounters a stale NFS file handle (-ESTALE), the
 *   syscall automatically retries with LOOKUP_REVAL to revalidate cached
 *   dentries before returning the error to userspace.
 *
 *   The change affects only the calling process. Child processes created via
 *   fork() inherit the parent's working directory at fork time. The working
 *   directory is preserved across execve() calls.
 *
 *   For changing directory using an open file descriptor, use fchdir(). For
 *   changing the root directory, use chroot() which requires CAP_SYS_CHROOT.
 *
 *   POSIX.1-2008 compliant. This syscall has existed since Linux 1.0.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: filename
 *   type: KAPI_TYPE_PATH
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid null-terminated pathname in user-space memory.
 *     Maximum total path length is PATH_MAX (4096) bytes including null
 *     terminator. Individual path components are limited to NAME_MAX (255)
 *     bytes. The path must resolve to a directory. An empty string returns
 *     -ENOENT. If the pointer is invalid or inaccessible, returns -EFAULT.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. On error, returns a negative error code and
 *     the current working directory remains unchanged.
 *
 * error: ENOENT, No such file or directory
 *   desc: A component of @filename does not exist, or @filename is an empty
 *     string, or @filename is a dangling symbolic link pointing to a
 *     nonexistent target.
 *
 * error: ENOTDIR, Not a directory
 *   desc: A component used as a directory in @filename is not actually a
 *     directory, or the final component of @filename is not a directory.
 *
 * error: EACCES, Permission denied
 *   desc: Search permission is denied on a component of the path prefix,
 *     or search (execute) permission is denied on the target directory.
 *     Permission checking uses effective uid/gid. The calling process needs
 *     execute permission on the target directory to change to it.
 *
 * error: EFAULT, Bad address
 *   desc: The @filename pointer points outside the accessible address space.
 *     Detected when copying the pathname from user space via strncpy_from_user()
 *     in getname_flags().
 *
 * error: ENAMETOOLONG, File name too long
 *   desc: @filename or one of its path components exceeds system limits.
 *     Individual components are limited to NAME_MAX (255) bytes, and the
 *     total path is limited to PATH_MAX (4096) bytes including terminator.
 *
 * error: ELOOP, Too many symbolic links
 *   desc: Too many symbolic links were encountered while resolving @filename.
 *     The kernel limit is 40 symlinks per path resolution with a maximum
 *     recursion depth of 8 for nested symbolic links (MAXSYMLINKS).
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory to allocate the filename structure via
 *     __getname() or other internal structures during path resolution.
 *
 * error: EIO, Input/output error
 *   desc: An I/O error occurred while reading from the filesystem during
 *     path resolution or inode lookup. This is filesystem-dependent and
 *     indicates a hardware or low-level filesystem error.
 *
 * error: ESTALE, Stale file handle
 *   desc: The file handle has become stale, typically on NFS when the
 *     directory was deleted or replaced on the server. The kernel
 *     automatically retries with LOOKUP_REVAL to revalidate, but if it
 *     still fails, -ESTALE is returned to userspace.
 *
 * lock: RCU read-side critical section
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: Path lookup uses RCU-walk mode (rcu_read_lock) for fast path
 *     resolution. If RCU-walk fails (e.g., due to blocking operation needed),
 *     the lookup falls back to reference-counted (ref-walk) mode.
 *
 * lock: fs->seq (seqlock)
 *   type: KAPI_LOCK_SEQLOCK
 *   acquired: true
 *   released: true
 *   desc: The process's fs_struct seqlock is acquired exclusively via
 *     write_seqlock() in set_fs_pwd() when updating the current working
 *     directory. This serializes concurrent accesses to fs->pwd and ensures
 *     atomic updates visible to other threads sharing the fs_struct.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process current working directory (current->fs->pwd)
 *   desc: Changes the calling process's current working directory to the
 *     specified path. The new directory's path structure (vfsmount and dentry)
 *     is stored in current->fs->pwd. The previous working directory's
 *     reference count is decremented via path_put().
 *   condition: On successful path resolution and permission check
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Reference counts on path structures
 *   desc: Increments reference count on the new working directory's vfsmount
 *     (via mntget) and dentry (via dget) through path_get(). Decrements
 *     reference count on the old working directory through path_put().
 *   condition: On success
 *   reversible: no
 *
 * capability: CAP_DAC_READ_SEARCH
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypasses execute permission check on directories
 *   without: Process must have execute permission on each directory component
 *     in the path and on the target directory itself
 *   condition: Checked via capable_wrt_inode_uidgid() in generic_permission()
 *     when standard permission check fails
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Overrides all DAC permission checks including execute on directories
 *   without: Process must have appropriate execute permissions for path traversal
 *   condition: Checked via capable_wrt_inode_uidgid() in generic_permission()
 *     when standard permission check fails
 *
 * examples: chdir("/tmp");  // Change to /tmp directory
 *   chdir("..");  // Move to parent directory
 *   chdir("subdir");  // Change to relative subdirectory
 *
 * notes: Unlike chroot(), chdir() does not require any capabilities - any
 *   process can change its working directory if it has search permission.
 *   The working directory is per-process state stored in the fs_struct.
 *   Threads sharing the same fs_struct (created with CLONE_FS) share the
 *   same working directory. A successful chdir() does not guarantee that
 *   the directory will remain accessible; it may be subsequently deleted
 *   or have permissions changed. Some filesystems (AFS, FUSE, NFS) perform
 *   additional permission checks via the MAY_CHDIR flag.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE1(chdir, const char __user *, filename)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
retry:
	error = user_path_at(AT_FDCWD, filename, lookup_flags, &path);
	if (error)
		goto out;

	error = path_permission(&path, MAY_EXEC | MAY_CHDIR);
	if (error)
		goto dput_and_out;

	set_fs_pwd(current->fs, &path);

dput_and_out:
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	return error;
}

/**
 * sys_fchdir - Change current working directory using a file descriptor
 * @fd: File descriptor referring to a directory
 *
 * long-desc: Changes the current working directory of the calling process to
 *   the directory referred to by the open file descriptor @fd. The current
 *   working directory is the starting point for interpreting relative pathnames
 *   (those not starting with '/').
 *
 *   Unlike chdir(), which takes a pathname, fchdir() operates on an already-open
 *   file descriptor. This provides several advantages: it avoids race conditions
 *   where the directory could be moved or renamed between path resolution and
 *   the directory change, and it allows changing to a directory that the process
 *   can no longer access by path (e.g., after directory permissions changed).
 *
 *   The file descriptor @fd must refer to a directory. Since Linux 3.5, O_PATH
 *   file descriptors are accepted, making fchdir() comparable to the O_SEARCH
 *   functionality in Solaris. An O_PATH descriptor can be obtained for a
 *   directory with only execute (search) permission, without read permission.
 *
 *   The calling process must have search (execute) permission on the directory.
 *   Some filesystems (AFS, FUSE, NFS) perform additional permission checks via
 *   the MAY_CHDIR flag to support access control beyond standard UNIX permissions.
 *
 *   The change affects only the calling process. Child processes created via
 *   fork() inherit the parent's working directory at fork time. The working
 *   directory is preserved across execve() calls.
 *
 *   POSIX.1-2001 and POSIX.1-2008 compliant. This syscall has existed since
 *   the original Linux kernel.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid open file descriptor referring to a directory.
 *     O_PATH file descriptors are accepted (since Linux 3.5), allowing the
 *     caller to change to a directory opened with only search permission.
 *     The file descriptor must not refer to a regular file, device, socket,
 *     FIFO, or symbolic link. Referral points (special objects in distributed
 *     filesystems like AFS) are rejected.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. On error, returns a negative error code and
 *     the current working directory remains unchanged.
 *
 * error: EBADF, Bad file descriptor
 *   desc: The file descriptor @fd is not a valid open file descriptor, or
 *     the file associated with @fd has been closed. Detected by fdget_raw()
 *     when looking up the file descriptor in the process's file descriptor
 *     table.
 *
 * error: ENOTDIR, Not a directory
 *   desc: The file descriptor @fd refers to a file that is not a directory.
 *     This includes regular files, symbolic links, block devices, character
 *     devices, FIFOs, sockets, and special filesystem objects like referral
 *     points in distributed filesystems (AFS, DFS). Checked via d_can_lookup()
 *     which verifies the dentry type is DCACHE_DIRECTORY_TYPE.
 *
 * error: EACCES, Permission denied
 *   desc: Search (execute) permission is denied on the directory. This is
 *     checked via inode_permission() using MAY_EXEC | MAY_CHDIR flags. The
 *     permission check respects POSIX ACLs if the filesystem supports them.
 *     LSM modules (SELinux, AppArmor) may also deny access based on security
 *     policy. On filesystems with custom permission handlers (FUSE, AFS, NFS),
 *     additional access control checks may be performed.
 *
 * lock: fs->seq (seqlock)
 *   type: KAPI_LOCK_SEQLOCK
 *   acquired: true
 *   released: true
 *   desc: The process's fs_struct seqlock is acquired exclusively via
 *     write_seqlock() in set_fs_pwd() when updating the current working
 *     directory. This serializes concurrent accesses to fs->pwd and ensures
 *     atomic updates visible to other threads sharing the fs_struct.
 *
 * lock: inode->i_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: conditional
 *   released: true
 *   desc: May be briefly acquired when setting the IOP_FASTPERM flag on an
 *     inode during permission checking optimization in do_inode_permission().
 *     This is a one-time operation per inode lifetime.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process current working directory (current->fs->pwd)
 *   desc: Changes the calling process's current working directory to the
 *     directory referred to by @fd. The new directory's path structure
 *     (vfsmount and dentry) is stored in current->fs->pwd. The previous
 *     working directory's reference count is decremented via path_put().
 *   condition: On successful permission check
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Reference counts on path structures
 *   desc: Increments reference count on the new working directory's vfsmount
 *     (via mntget) and dentry (via dget) through path_get(). Decrements
 *     reference count on the old working directory through path_put().
 *   condition: On success
 *   reversible: no
 *
 * capability: CAP_DAC_READ_SEARCH
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypasses execute (search) permission check on directories
 *   without: Process must have execute permission on the directory
 *   condition: Checked via capable_wrt_inode_uidgid() in generic_permission()
 *     when standard permission check fails
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Overrides all DAC permission checks including execute on directories
 *   without: Process must have appropriate execute permissions
 *   condition: Checked via capable_wrt_inode_uidgid() in generic_permission()
 *     when standard permission check fails
 *
 * examples: fchdir(dirfd);  // Change to directory opened by open()
 *   fchdir(fd);  // Change using O_PATH fd from openat(AT_FDCWD, ".", O_PATH)
 *
 * notes: Unlike chdir(), fchdir() does not involve any pathname resolution,
 *   so it cannot fail with ENOENT, ENAMETOOLONG, ELOOP, or ESTALE errors.
 *   The directory must already be open, which means the path was resolved
 *   and validated at open() time.
 *
 *   The working directory is per-process state stored in the fs_struct.
 *   Threads sharing the same fs_struct (created with CLONE_FS) share the
 *   same working directory. A successful fchdir() does not guarantee that
 *   the directory will remain accessible; it may be subsequently deleted,
 *   have permissions changed, or become unmounted.
 *
 *   fchdir() is particularly useful for implementing secure directory
 *   traversal patterns: open a directory, verify it's the expected one
 *   (e.g., by checking device and inode numbers), then fchdir() to it.
 *   This avoids TOCTOU races present in chdir() with pathnames.
 *
 *   Since Linux 3.5, O_PATH file descriptors are accepted. This allows
 *   changing to a directory that was opened with only execute permission
 *   (not read permission), similar to Solaris O_SEARCH.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE1(fchdir, unsigned int, fd)
{
	CLASS(fd_raw, f)(fd);
	int error;

	if (fd_empty(f))
		return -EBADF;

	if (!d_can_lookup(fd_file(f)->f_path.dentry))
		return -ENOTDIR;

	error = file_permission(fd_file(f), MAY_EXEC | MAY_CHDIR);
	if (!error)
		set_fs_pwd(current->fs, &fd_file(f)->f_path);
	return error;
}

/**
 * sys_chroot - Change the root directory of the calling process
 * @filename: Pathname to the new root directory
 *
 * long-desc: Changes the root directory of the calling process to the directory
 *   specified by @filename. This modifies pathname resolution such that any
 *   absolute path (beginning with '/') will be interpreted relative to the new
 *   root. This affects the calling process and its descendants created via
 *   fork() after the call. The root directory is preserved across execve().
 *
 *   chroot() only changes the apparent root directory for pathname resolution;
 *   it does NOT change the current working directory. After calling chroot(),
 *   processes should typically call chdir("/") to set the working directory
 *   inside the new root. Failing to do so allows the process to access files
 *   outside the new root via relative paths.
 *
 *   SECURITY WARNING: chroot() is NOT a security mechanism and does NOT provide
 *   a secure sandbox. A privileged process can escape a chroot jail trivially
 *   via: mkdir("foo"); chroot("foo"); chdir(".."); This works because chroot()
 *   doesn't change the current working directory, so relative paths can reach
 *   outside. Other escape vectors include: open file descriptors to outside
 *   directories, ptrace, /proc access, and creating device nodes. For secure
 *   isolation, use namespaces (unshare/clone with CLONE_NEWNS), pivot_root(),
 *   or container technologies. FreeBSD's jail() provides stronger isolation.
 *
 *   The @filename must resolve to a directory. Symbolic links are followed
 *   (LOOKUP_FOLLOW). The calling process must have search (execute) permission
 *   on the target directory and CAP_SYS_CHROOT capability in its user namespace.
 *
 *   If the path lookup encounters a stale NFS file handle (-ESTALE), the
 *   syscall automatically retries with LOOKUP_REVAL to revalidate cached
 *   dentries before returning the error to userspace.
 *
 *   The change affects only the calling process and its descendants. The root
 *   directory is shared between threads via fs_struct, so threads sharing
 *   fs_struct (created with CLONE_FS) share the same root. Child processes
 *   created via fork() inherit the parent's root at fork time.
 *
 *   Intended use cases include: installation programs (operating on a different
 *   root), debugging with specific library versions, running daemons with
 *   restricted filesystem views (though not for security), and legacy
 *   application isolation.
 *
 *   Not part of POSIX.1-2001 or POSIX.1-2008. Marked LEGACY in SUSv2. Available
 *   in SVr4, 4.4BSD. This syscall has existed since Linux 1.0.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: filename
 *   type: KAPI_TYPE_PATH
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid null-terminated pathname in user-space memory.
 *     Maximum total path length is PATH_MAX (4096) bytes including null
 *     terminator. Individual path components are limited to NAME_MAX (255)
 *     bytes. The path must resolve to a directory. An empty string returns
 *     -ENOENT. If the pointer is invalid or inaccessible, returns -EFAULT.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. On error, returns a negative error code and
 *     the root directory remains unchanged.
 *
 * error: EPERM, Operation not permitted
 *   desc: The caller does not have CAP_SYS_CHROOT capability in its user
 *     namespace. This is the most common error - chroot() is a privileged
 *     operation. The capability check is performed via ns_capable() against
 *     current_user_ns(). Also returned if the Linux Security Module (LSM)
 *     denies the operation through the security_path_chroot() hook.
 *
 * error: ENOENT, No such file or directory
 *   desc: A component of @filename does not exist, or @filename is an empty
 *     string, or @filename is a dangling symbolic link pointing to a
 *     nonexistent target.
 *
 * error: ENOTDIR, Not a directory
 *   desc: A component used as a directory in @filename is not actually a
 *     directory, or the final component of @filename is not a directory.
 *     The LOOKUP_DIRECTORY flag ensures the target must be a directory.
 *
 * error: EACCES, Permission denied
 *   desc: Search permission is denied on a component of the path prefix,
 *     or search (execute) permission is denied on the target directory.
 *     Permission checking uses effective uid/gid. The calling process needs
 *     execute permission on the target directory. LSM modules may also
 *     return EACCES if security policy denies directory traversal.
 *
 * error: EFAULT, Bad address
 *   desc: The @filename pointer points outside the accessible address space.
 *     Detected when copying the pathname from user space via strncpy_from_user()
 *     in getname_flags().
 *
 * error: ENAMETOOLONG, File name too long
 *   desc: @filename or one of its path components exceeds system limits.
 *     Individual components are limited to NAME_MAX (255) bytes, and the
 *     total path is limited to PATH_MAX (4096) bytes including terminator.
 *
 * error: ELOOP, Too many symbolic links
 *   desc: Too many symbolic links were encountered while resolving @filename.
 *     The kernel limit is 40 symlinks per path resolution with a maximum
 *     recursion depth of 8 for nested symbolic links (MAXSYMLINKS).
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory to allocate the filename structure via
 *     __getname() or other internal structures during path resolution.
 *
 * error: EIO, Input/output error
 *   desc: An I/O error occurred while reading from the filesystem during
 *     path resolution or inode lookup. This is filesystem-dependent and
 *     indicates a hardware or low-level filesystem error.
 *
 * error: ESTALE, Stale file handle
 *   desc: The file handle has become stale, typically on NFS when the
 *     directory was deleted or replaced on the server. The kernel
 *     automatically retries with LOOKUP_REVAL to revalidate, but if it
 *     still fails, -ESTALE is returned to userspace.
 *
 * lock: RCU read-side critical section
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: Path lookup uses RCU-walk mode (rcu_read_lock) for fast path
 *     resolution. If RCU-walk fails (e.g., due to blocking operation needed),
 *     the lookup falls back to reference-counted (ref-walk) mode.
 *
 * lock: fs->seq (seqlock)
 *   type: KAPI_LOCK_SEQLOCK
 *   acquired: true
 *   released: true
 *   desc: The process's fs_struct seqlock is acquired exclusively via
 *     write_seqlock() in set_fs_root() when updating the root directory.
 *     This serializes concurrent accesses to fs->root and ensures atomic
 *     updates visible to other threads sharing the fs_struct.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process root directory (current->fs->root)
 *   desc: Changes the calling process's root directory to the specified path.
 *     The new directory's path structure (vfsmount and dentry) is stored in
 *     current->fs->root. The previous root directory's reference count is
 *     decremented via path_put(). This affects all pathname resolution
 *     starting with '/' for the calling process.
 *   condition: On successful path resolution, permission check, capability
 *     check, and security module approval
 *   reversible: yes (via another chroot call with appropriate permissions)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Reference counts on path structures
 *   desc: Increments reference count on the new root directory's vfsmount
 *     (via mntget) and dentry (via dget) through path_get(). Decrements
 *     reference count on the old root directory through path_put().
 *   condition: On success
 *   reversible: no
 *
 * capability: CAP_SYS_CHROOT
 *   type: KAPI_CAP_PERFORM_OPERATION
 *   allows: Permits changing the root directory of the calling process
 *   without: The syscall fails with -EPERM. Unprivileged processes cannot
 *     change their root directory under any circumstances.
 *   condition: Checked via ns_capable(current_user_ns(), CAP_SYS_CHROOT)
 *     after path resolution succeeds but before setting the new root.
 *     The capability is checked in the caller's user namespace.
 *
 * capability: CAP_DAC_READ_SEARCH
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypasses execute permission check on directories during path
 *     traversal. Does not bypass the CAP_SYS_CHROOT requirement.
 *   without: Process must have execute permission on each directory component
 *     in the path and on the target directory itself
 *   condition: Checked via capable_wrt_inode_uidgid() in generic_permission()
 *     when standard permission check fails
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Overrides all DAC permission checks including execute on directories
 *     during path traversal. Does not bypass the CAP_SYS_CHROOT requirement.
 *   without: Process must have appropriate execute permissions for path traversal
 *   condition: Checked via capable_wrt_inode_uidgid() in generic_permission()
 *     when standard permission check fails
 *
 * constraint: LSM security modules
 *   desc: The security_path_chroot() hook is called to allow Linux Security
 *     Modules (SELinux, AppArmor, TOMOYO, Smack) to enforce additional access
 *     control policies. LSM modules may deny the chroot operation based on
 *     mandatory access control policy, returning -EPERM or -EACCES.
 *   expr: security_path_chroot(&path) == 0
 *
 * examples: chroot("/var/chroot/jail");  // Change root to jail directory
 *   chroot(".");  // Change root to current directory (still requires CAP_SYS_CHROOT)
 *   chroot("/"); chdir("/");  // Reset root to system root (requires capability)
 *
 * notes: chroot() is often mistakenly used as a security mechanism. It was
 *   designed for system administration tasks like installation and debugging,
 *   not for sandboxing untrusted code. Key security limitations include:
 *
 *   1. Does NOT change the current working directory - the process can still
 *      access files outside the new root via relative paths until it calls
 *      chdir("/") inside the new root.
 *
 *   2. Root users inside a chroot can escape trivially by creating a nested
 *      chroot and using ".." navigation.
 *
 *   3. Open file descriptors to directories outside the chroot allow escape.
 *
 *   4. /proc, if mounted, provides access outside the chroot.
 *
 *   5. Device nodes can be created (if permitted) to access raw devices.
 *
 *   6. setuid programs should not run inside chroots as they may have
 *      unexpected behavior when libraries or configuration files differ.
 *
 *   For actual security isolation, use: mount namespaces with pivot_root()
 *   (which properly changes both root and cwd, and can unmount old root),
 *   user namespaces, seccomp-bpf filters, or full container solutions.
 *   FreeBSD's jail() syscall provides much stronger isolation guarantees.
 *
 *   The root directory is visible via /proc/[pid]/root symbolic link, which
 *   reveals the process's root directory to processes with appropriate
 *   permissions.
 *
 *   Multiple chroot() calls do not stack - each call completely replaces
 *   the root. Calling chroot("/") from within a chroot (with CAP_SYS_CHROOT)
 *   resolves "/" relative to the current root, not the original system root.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE1(chroot, const char __user *, filename)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
retry:
	error = user_path_at(AT_FDCWD, filename, lookup_flags, &path);
	if (error)
		goto out;

	error = path_permission(&path, MAY_EXEC | MAY_CHDIR);
	if (error)
		goto dput_and_out;

	error = -EPERM;
	if (!ns_capable(current_user_ns(), CAP_SYS_CHROOT))
		goto dput_and_out;
	error = security_path_chroot(&path);
	if (error)
		goto dput_and_out;

	set_fs_root(current->fs, &path);
	error = 0;
dput_and_out:
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	return error;
}

int chmod_common(const struct path *path, umode_t mode)
{
	struct inode *inode = path->dentry->d_inode;
	struct delegated_inode delegated_inode = { };
	struct iattr newattrs;
	int error;

	error = mnt_want_write(path->mnt);
	if (error)
		return error;
retry_deleg:
	error = inode_lock_killable(inode);
	if (error)
		goto out_mnt_unlock;
	error = security_path_chmod(path, mode);
	if (error)
		goto out_unlock;
	newattrs.ia_mode = (mode & S_IALLUGO) | (inode->i_mode & ~S_IALLUGO);
	newattrs.ia_valid = ATTR_MODE | ATTR_CTIME;
	error = notify_change(mnt_idmap(path->mnt), path->dentry,
			      &newattrs, &delegated_inode);
out_unlock:
	inode_unlock(inode);
	if (is_delegated(&delegated_inode)) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
out_mnt_unlock:
	mnt_drop_write(path->mnt);
	return error;
}

int vfs_fchmod(struct file *file, umode_t mode)
{
	audit_file(file);
	return chmod_common(&file->f_path, mode);
}

SYSCALL_DEFINE2(fchmod, unsigned int, fd, umode_t, mode)
{
	CLASS(fd, f)(fd);

	if (fd_empty(f))
		return -EBADF;

	return vfs_fchmod(fd_file(f), mode);
}

static int do_fchmodat(int dfd, const char __user *filename, umode_t mode,
		       unsigned int flags)
{
	struct path path;
	int error;
	unsigned int lookup_flags;

	if (unlikely(flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)))
		return -EINVAL;

	lookup_flags = (flags & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW;
	if (flags & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;

retry:
	error = user_path_at(dfd, filename, lookup_flags, &path);
	if (!error) {
		error = chmod_common(&path, mode);
		path_put(&path);
		if (retry_estale(error, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}
	return error;
}

SYSCALL_DEFINE4(fchmodat2, int, dfd, const char __user *, filename,
		umode_t, mode, unsigned int, flags)
{
	return do_fchmodat(dfd, filename, mode, flags);
}

/**
 * sys_fchmodat - Change file permissions relative to a directory file descriptor
 * @dfd: Directory file descriptor or AT_FDCWD for current working directory
 * @filename: Pathname of the file whose permissions are to be changed
 * @mode: New permission bits to set on the file
 *
 * long-desc: Changes the permission bits of the file specified by @filename
 *   relative to the directory referred to by @dfd. If @filename is relative
 *   (does not start with '/'), it is interpreted relative to the directory
 *   referred to by @dfd. If @dfd is the special value AT_FDCWD, the path is
 *   interpreted relative to the current working directory. If @filename is
 *   absolute, @dfd is ignored.
 *
 *   The new permissions are specified in @mode and include the permission bits
 *   (S_IRWXU, S_IRWXG, S_IRWXO) and special bits (S_ISUID, S_ISGID, S_ISVTX).
 *   Only the bits covered by S_IALLUGO (07777 octal) are used; other bits in
 *   @mode are ignored. The file's existing mode bits outside S_IALLUGO are
 *   preserved.
 *
 *   Unlike fchmodat2(), this syscall does NOT accept a flags parameter and
 *   ALWAYS follows symbolic links. To change permissions on a symbolic link
 *   itself (which is not meaningful on Linux as symlink modes are ignored),
 *   use fchmodat2() with AT_SYMLINK_NOFOLLOW. However, Linux returns -EOPNOTSUPP
 *   for attempts to change symbolic link modes.
 *
 *   Permission requirements: The effective UID of the calling process must
 *   match the owner of the file, or the caller must have CAP_FOWNER capability
 *   in a user namespace with the file owner UID mapped. Root (CAP_FOWNER) can
 *   change permissions of any file.
 *
 *   The set-group-ID bit (S_ISGID) is automatically cleared from @mode if the
 *   caller is not the file owner or root AND the caller is not in the file's
 *   group (and doesn't have CAP_FSETID). This prevents privilege escalation.
 *
 *   On network filesystems (NFS), if the file has been deleted or renamed on
 *   the server (stale file handle), the syscall automatically retries once
 *   with path revalidation before returning -ESTALE.
 *
 *   If the file has an NFS delegation held by another client, the kernel will
 *   break the delegation and wait for the client to release it before
 *   proceeding. This wait is interruptible by signals.
 *
 *   POSIX.1-2001 and POSIX.1-2008 compliant. Available since Linux 2.6.16.
 *   The glibc wrapper function provides the POSIX-defined interface with a
 *   flags argument, but the underlying kernel syscall does not have flags.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: dfd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid directory file descriptor, the special value
 *     AT_FDCWD (-100) for current working directory, or ignored if @filename
 *     is an absolute path. When not AT_FDCWD and @filename is relative, @dfd
 *     must refer to a directory (not a regular file or other file type).
 *     O_PATH file descriptors are accepted if they refer to a directory.
 *
 * param: filename
 *   type: KAPI_TYPE_PATH
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid user-space pointer to a null-terminated
 *     pathname string. Maximum path length is PATH_MAX (4096) bytes including
 *     the null terminator. If relative, resolved from @dfd or cwd. Empty
 *     string is not allowed (returns -ENOENT) as this syscall doesn't support
 *     AT_EMPTY_PATH flag (use fchmodat2 for that).
 *
 * param: mode
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO
 *   constraint: Permission bits to set. Only the bits in S_IALLUGO (07777)
 *     are used; other bits are silently ignored. Common values include:
 *     S_IRWXU (0700) owner read/write/execute, S_IRWXG (0070) group r/w/x,
 *     S_IRWXO (0007) other r/w/x, S_ISUID (04000) set-user-ID, S_ISGID (02000)
 *     set-group-ID, S_ISVTX (01000) sticky bit. All combinations are valid.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. On error, returns a negative error code.
 *     The permission change is atomic with respect to other filesystem
 *     operations on the same inode.
 *
 * error: ENOENT, File does not exist
 *   desc: The file specified by @filename does not exist, or @filename is
 *     an empty string (empty paths not supported without AT_EMPTY_PATH flag).
 *     Also returned if a path component does not exist.
 *
 * error: EACCES, Permission denied for path traversal
 *   desc: Search permission is denied on a component of the path prefix.
 *     The calling process lacks execute (search) permission on a directory
 *     in the path leading to the target file.
 *
 * error: EBADF, Bad file descriptor
 *   desc: @dfd is neither AT_FDCWD nor a valid file descriptor, or @dfd is
 *     a valid file descriptor but does not refer to a directory when
 *     @filename is a relative path.
 *
 * error: EFAULT, Bad address
 *   desc: @filename points outside the process's accessible address space.
 *     The kernel was unable to copy the pathname from user space.
 *
 * error: ELOOP, Too many symbolic links
 *   desc: Too many symbolic links were encountered while resolving @filename.
 *     The limit is typically MAXSYMLINKS (40) to prevent infinite loops.
 *
 * error: ENAMETOOLONG, Filename too long
 *   desc: @filename or one of its path components exceeds the length limit.
 *     PATH_MAX is 4096 bytes; individual components are limited to NAME_MAX
 *     (typically 255 bytes).
 *
 * error: ENOTDIR, Not a directory
 *   desc: A component used as a directory in @filename is not actually a
 *     directory, or @dfd refers to a non-directory file and @filename is
 *     relative.
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory to complete the path lookup operation
 *     or allocate internal structures. This is a transient error.
 *
 * error: EROFS, Read-only filesystem
 *   desc: The file resides on a read-only filesystem. This includes
 *     filesystems mounted read-only and filesystems that have been remounted
 *     read-only due to errors (errors=remount-ro mount option).
 *
 * error: EPERM, Operation not permitted
 *   desc: The effective UID of the calling process does not match the owner
 *     of the file and the process does not have the CAP_FOWNER capability.
 *     Also returned if the file has the immutable attribute set (chattr +i)
 *     or the append-only attribute set (chattr +a), as mode changes are
 *     blocked on such files regardless of ownership.
 *
 * error: EOPNOTSUPP, Operation not supported
 *   desc: Attempting to change the mode of a symbolic link. Linux does not
 *     support changing the mode of symbolic links as their permissions are
 *     not used during permission checking. This was historically inconsistent
 *     across filesystems; as of Linux 6.6, it is uniformly blocked in the VFS.
 *
 * error: EIO, I/O error
 *   desc: An I/O error occurred while reading from or writing to the
 *     filesystem. This typically indicates hardware failure, network issues
 *     on remote filesystems, or filesystem corruption.
 *
 * error: ESTALE, Stale file handle
 *   desc: The file handle has become stale, typically on NFS when the file
 *     was deleted or renamed on the server. The syscall automatically retries
 *     once with path revalidation; this error is returned only if the retry
 *     also fails.
 *
 * error: EINTR, Interrupted system call
 *   desc: The syscall was interrupted by a signal while waiting for the
 *     inode lock or for an NFS delegation to be released. The operation
 *     was not completed and can be retried. Since Linux 6.15, the inode
 *     lock wait is killable (responds to fatal signals).
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Acquired exclusively via inode_lock_killable() before modifying the
 *     inode's mode. This serializes permission changes with other operations
 *     that modify or depend on file attributes. The lock is held while calling
 *     security hooks and the filesystem's setattr operation. Released before
 *     waiting for delegation break and before return.
 *
 * lock: sb_writers (SB_FREEZE_WRITE level)
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Acquired via mnt_want_write() which calls sb_start_write() to
 *     prevent filesystem freeze during the operation. This is a per-superblock
 *     percpu read-write semaphore. Released via mnt_drop_write() after the
 *     mode change completes.
 *
 * signal: fatal_signals
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: While waiting for the inode lock
 *   desc: Since Linux 6.15, inode_lock_killable() is used which allows fatal
 *     signals (SIGKILL, SIGTERM, etc.) to interrupt the wait for the inode
 *     lock. If interrupted, the syscall returns -EINTR (translated from
 *     -ERESTARTSYS).
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * signal: any_signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: While waiting for NFS delegation break
 *   desc: When the file has an NFSv4 delegation held by another client, the
 *     kernel must break the delegation and wait for acknowledgment. This wait
 *     via break_deleg_wait() is interruptible by any signal. If interrupted,
 *     returns -EINTR.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM | KAPI_EFFECT_MODIFY_STATE
 *   target: File inode mode bits
 *   desc: On success, the file's permission bits (i_mode & S_IALLUGO) are
 *     changed to the value specified in @mode. The file type bits and other
 *     flags in i_mode are preserved. This change is persisted to storage
 *     synchronously or asynchronously depending on filesystem mount options.
 *   condition: Operation succeeds (returns 0)
 *   reversible: yes (via another chmod call)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Inode ctime
 *   desc: The inode's change time (ctime) is updated to the current time
 *     to reflect the metadata modification. This occurs even if the new
 *     mode is identical to the old mode.
 *   condition: Operation succeeds
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: S_NOSEC inode flag
 *   desc: If the new mode includes set-user-ID (S_ISUID) or set-group-ID
 *     (S_ISGID) bits, the S_NOSEC flag is cleared from i_flags. This flag
 *     is an optimization hint indicating the file needs no security checks
 *     for clearing setuid/setgid on write; setting suid/sgid invalidates it.
 *   condition: When S_ISUID or S_ISGID is set in @mode
 *   reversible: no (automatically managed by kernel)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify events
 *   desc: On successful completion, fsnotify_change() is called to generate
 *     inotify IN_ATTRIB and fanotify FAN_ATTRIB events, notifying watchers
 *     of the attribute change.
 *   condition: Operation succeeds
 *   reversible: no
 *
 * capability: CAP_FOWNER
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass the permission check requiring the caller to be the file
 *     owner. With CAP_FOWNER, the caller can change permissions on any file
 *     accessible through the filesystem hierarchy.
 *   without: The effective UID must match the file owner UID. Non-owners
 *     without this capability receive -EPERM.
 *   condition: Checked in inode_owner_or_capable() during setattr_prepare()
 *     which is called from filesystem setattr handlers.
 *
 * capability: CAP_FSETID
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Preserve the set-group-ID bit when changing mode, even if the
 *     caller is not a member of the file's group.
 *   without: The S_ISGID bit in @mode is automatically cleared if the caller
 *     does not own the file and is not a member of the file's group. This
 *     prevents non-group-members from creating set-group-ID executables.
 *   condition: Checked in setattr_prepare() via in_group_or_capable().
 *
 * constraint: Immutable and Append-only Files
 *   desc: Files with the immutable attribute (FS_IMMUTABLE_FL, set via
 *     chattr +i) or append-only attribute (FS_APPEND_FL, set via chattr +a)
 *     cannot have their mode changed. These attributes must be removed first
 *     by the file owner or root using chattr.
 *   expr: !(inode->i_flags & (S_IMMUTABLE | S_APPEND))
 *
 * constraint: Filesystem Must Be Mounted Writable
 *   desc: The filesystem containing the file must be mounted read-write.
 *     Files on read-only filesystems or filesystems that have been emergency
 *     remounted read-only cannot have their permissions changed.
 *
 * constraint: Symbolic Links Cannot Be Changed
 *   desc: Linux does not allow changing the mode of symbolic links. The
 *     permission bits of symbolic links are ignored during access checks
 *     (symlinks always show lrwxrwxrwx in ls). Attempting to chmod a symlink
 *     returns -EOPNOTSUPP. This is enforced uniformly in the VFS since
 *     Linux 6.6.
 *
 * constraint: LSM Hooks
 *   desc: Linux Security Module hooks security_path_chmod() and
 *     security_inode_setattr() are called and may deny the operation based
 *     on security policy (SELinux, AppArmor, TOMOYO, etc.). The exact errors
 *     depend on the LSM configuration.
 *
 * examples: fchmodat(AT_FDCWD, "file.txt", 0644);  // rw-r--r--
 *   fchmodat(dirfd, "script.sh", 0755);  // rwxr-xr-x
 *   fchmodat(AT_FDCWD, "/etc/shadow", 0600);  // rw------- (requires root)
 *   fchmodat(dirfd, "data", S_IRUSR | S_IWUSR | S_IRGRP);  // rw-r-----
 *
 * notes: This syscall does not accept a flags parameter. The glibc wrapper
 *   fchmodat() provides POSIX-compliant behavior by accepting a flags argument
 *   but historically implemented AT_SYMLINK_NOFOLLOW in userspace using
 *   workarounds. As of Linux 6.6, use fchmodat2() for flag support including
 *   AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH.
 *
 *   On NFS, permission changes may not take effect immediately due to
 *   attribute caching. The server is authoritative for permission checks.
 *
 *   Changing permissions on files in /proc, /sys, or other pseudo-filesystems
 *   may silently fail or have no persistent effect, depending on the specific
 *   filesystem implementation.
 *
 *   For the fchmodat2() variant with flags support, see the separate
 *   specification above. For operating on open file descriptors, use fchmod().
 *
 * since-version: 2.6.16
 */
SYSCALL_DEFINE3(fchmodat, int, dfd, const char __user *, filename,
		umode_t, mode)
{
	return do_fchmodat(dfd, filename, mode, 0);
}

SYSCALL_DEFINE2(chmod, const char __user *, filename, umode_t, mode)
{
	return do_fchmodat(AT_FDCWD, filename, mode, 0);
}

/*
 * Check whether @kuid is valid and if so generate and set vfsuid_t in
 * ia_vfsuid.
 *
 * Return: true if @kuid is valid, false if not.
 */
static inline bool setattr_vfsuid(struct iattr *attr, kuid_t kuid)
{
	if (!uid_valid(kuid))
		return false;
	attr->ia_valid |= ATTR_UID;
	attr->ia_vfsuid = VFSUIDT_INIT(kuid);
	return true;
}

/*
 * Check whether @kgid is valid and if so generate and set vfsgid_t in
 * ia_vfsgid.
 *
 * Return: true if @kgid is valid, false if not.
 */
static inline bool setattr_vfsgid(struct iattr *attr, kgid_t kgid)
{
	if (!gid_valid(kgid))
		return false;
	attr->ia_valid |= ATTR_GID;
	attr->ia_vfsgid = VFSGIDT_INIT(kgid);
	return true;
}

int chown_common(const struct path *path, uid_t user, gid_t group)
{
	struct mnt_idmap *idmap;
	struct user_namespace *fs_userns;
	struct inode *inode = path->dentry->d_inode;
	struct delegated_inode delegated_inode = { };
	int error;
	struct iattr newattrs;
	kuid_t uid;
	kgid_t gid;

	uid = make_kuid(current_user_ns(), user);
	gid = make_kgid(current_user_ns(), group);

	idmap = mnt_idmap(path->mnt);
	fs_userns = i_user_ns(inode);

retry_deleg:
	newattrs.ia_vfsuid = INVALID_VFSUID;
	newattrs.ia_vfsgid = INVALID_VFSGID;
	newattrs.ia_valid =  ATTR_CTIME;
	if ((user != (uid_t)-1) && !setattr_vfsuid(&newattrs, uid))
		return -EINVAL;
	if ((group != (gid_t)-1) && !setattr_vfsgid(&newattrs, gid))
		return -EINVAL;
	error = inode_lock_killable(inode);
	if (error)
		return error;
	if (!S_ISDIR(inode->i_mode))
		newattrs.ia_valid |= ATTR_KILL_SUID | ATTR_KILL_PRIV |
				     setattr_should_drop_sgid(idmap, inode);
	/* Continue to send actual fs values, not the mount values. */
	error = security_path_chown(
		path,
		from_vfsuid(idmap, fs_userns, newattrs.ia_vfsuid),
		from_vfsgid(idmap, fs_userns, newattrs.ia_vfsgid));
	if (!error)
		error = notify_change(idmap, path->dentry, &newattrs,
				      &delegated_inode);
	inode_unlock(inode);
	if (is_delegated(&delegated_inode)) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	return error;
}

int do_fchownat(int dfd, const char __user *filename, uid_t user, gid_t group,
		int flag)
{
	struct path path;
	int error = -EINVAL;
	int lookup_flags;

	if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
		goto out;

	lookup_flags = (flag & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW;
	if (flag & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;
retry:
	error = user_path_at(dfd, filename, lookup_flags, &path);
	if (error)
		goto out;
	error = mnt_want_write(path.mnt);
	if (error)
		goto out_release;
	error = chown_common(&path, user, group);
	mnt_drop_write(path.mnt);
out_release:
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	return error;
}

/**
 * sys_fchownat - change file ownership relative to a directory file descriptor
 * @dfd: directory file descriptor for relative path resolution
 * @filename: pathname of the file to change ownership
 * @user: new owner user ID, or (uid_t)-1 to leave unchanged
 * @group: new owner group ID, or (gid_t)-1 to leave unchanged
 * @flag: flags controlling pathname resolution (AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH)
 *
 * long-desc: Changes the owner and/or group of the file specified by @filename.
 *   This syscall is part of the \*at() family introduced in Linux 2.6.16 to
 *   enable race-free directory traversal and per-thread working directories.
 *
 *   Path resolution: If @filename is a relative path (does not start with '/'),
 *   it is interpreted relative to the directory referred to by @dfd. If @dfd is
 *   the special value AT_FDCWD, the path is interpreted relative to the current
 *   working directory. If @filename is an absolute path, @dfd is ignored.
 *
 *   The @user and @group parameters specify the new owner and group. Passing
 *   the special value (uid_t)-1 for @user or (gid_t)-1 for @group leaves that
 *   attribute unchanged. This allows changing only the owner or only the group.
 *
 *   Flag handling: The @flag parameter controls pathname resolution:
 *   - AT_SYMLINK_NOFOLLOW (0x100): Do not dereference symbolic links. Operate
 *     on the symbolic link itself rather than the file it points to. This is
 *     equivalent to the lchown() syscall behavior.
 *   - AT_EMPTY_PATH (0x1000): If @filename is an empty string, operate on the
 *     file referred to by @dfd. This allows changing ownership of a file
 *     identified by an open file descriptor without needing the path.
 *
 *   Permission requirements: Only privileged processes (those with CAP_CHOWN in
 *   a user namespace where the file's uid/gid are mapped) can change a file's
 *   owner to an arbitrary value. Unprivileged users can only change the group
 *   of files they own to a group they are a member of.
 *
 *   Setuid/setgid handling: When ownership is changed by a non-privileged user,
 *   the set-user-ID and set-group-ID bits are automatically cleared from
 *   regular files to prevent security issues. The kernel also clears file
 *   capabilities (via ATTR_KILL_PRIV) on ownership changes for non-directories.
 *
 *   For network filesystems (NFS), if the file has been deleted or renamed on
 *   the server (stale file handle), the syscall automatically retries once with
 *   path revalidation before returning -ESTALE. If the file has an NFS delegation
 *   held by another client, the kernel will break the delegation and wait for
 *   the client to release it before proceeding.
 *
 *   POSIX.1-2008 compliant. The uid_t and gid_t parameters are 32-bit unsigned
 *   integers with (uid_t)-1 and (gid_t)-1 having special "no change" meaning.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: dfd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid directory file descriptor, the special value
 *     AT_FDCWD (-100) for current working directory, or ignored if @filename
 *     is an absolute path. When not AT_FDCWD and @filename is relative, @dfd
 *     must refer to a directory (not a regular file or other file type).
 *     O_PATH file descriptors are accepted if they refer to a directory.
 *     With AT_EMPTY_PATH flag and empty @filename, @dfd can refer to any
 *     file type and identifies the target file directly.
 *
 * param: filename
 *   type: KAPI_TYPE_PATH
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid user-space pointer to a null-terminated
 *     pathname string. Maximum path length is PATH_MAX (4096) bytes including
 *     the null terminator. If relative, resolved from @dfd or cwd. Empty
 *     string is only allowed when AT_EMPTY_PATH flag is set; otherwise returns
 *     -ENOENT. With AT_EMPTY_PATH, empty string causes operation on the file
 *     referred to by @dfd.
 *
 * param: user
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: New owner user ID, or the special value (uid_t)-1 (0xFFFFFFFF)
 *     to leave the owner unchanged. The uid must be valid in the caller's user
 *     namespace and must map to a valid uid in the filesystem's user namespace.
 *     Changing to an arbitrary uid requires CAP_CHOWN capability.
 *
 * param: group
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: New owner group ID, or the special value (gid_t)-1 (0xFFFFFFFF)
 *     to leave the group unchanged. The gid must be valid in the caller's user
 *     namespace and must map to a valid gid in the filesystem's user namespace.
 *     Unprivileged users can only change to a group they are a member of.
 *
 * param: flag
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH
 *   constraint: Bitwise OR of flags controlling pathname resolution. Zero for
 *     default behavior (follow symlinks, non-empty path required). Invalid flag
 *     combinations return -EINVAL. AT_SYMLINK_NOFOLLOW (0x100) prevents symlink
 *     dereferencing; AT_EMPTY_PATH (0x1000) allows empty @filename with @dfd
 *     identifying the target.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. On error, returns a negative error code.
 *     The ownership change is atomic with respect to other filesystem
 *     operations on the same inode.
 *
 * error: EINVAL, Invalid flags
 *   desc: The @flag argument contains bits other than AT_SYMLINK_NOFOLLOW and
 *     AT_EMPTY_PATH. Also returned if @user or @group cannot be converted to
 *     a valid kernel uid/gid (invalid in caller's user namespace).
 *
 * error: ENOENT, File does not exist
 *   desc: The file specified by @filename does not exist, or @filename is an
 *     empty string and AT_EMPTY_PATH flag was not specified. Also returned if
 *     a path component does not exist.
 *
 * error: EACCES, Permission denied for path traversal
 *   desc: Search permission is denied on a component of the path prefix.
 *     The calling process lacks execute (search) permission on a directory
 *     in the path leading to the target file.
 *
 * error: EBADF, Bad file descriptor
 *   desc: @dfd is neither AT_FDCWD nor a valid file descriptor, or @dfd is
 *     a valid file descriptor but does not refer to a directory when
 *     @filename is a non-empty relative path.
 *
 * error: EFAULT, Bad address
 *   desc: @filename points outside the process's accessible address space.
 *     The kernel was unable to copy the pathname from user space.
 *
 * error: ELOOP, Too many symbolic links
 *   desc: Too many symbolic links were encountered while resolving @filename.
 *     The limit is typically MAXSYMLINKS (40) to prevent infinite loops.
 *     Not returned when AT_SYMLINK_NOFOLLOW is set (symlinks not followed).
 *
 * error: ENAMETOOLONG, Filename too long
 *   desc: @filename or one of its path components exceeds the length limit.
 *     PATH_MAX is 4096 bytes; individual components are limited to NAME_MAX
 *     (typically 255 bytes).
 *
 * error: ENOTDIR, Not a directory
 *   desc: A component used as a directory in @filename is not actually a
 *     directory, or @dfd refers to a non-directory file and @filename is
 *     a non-empty relative path.
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory to complete the path lookup operation
 *     or allocate internal structures. This is a transient error.
 *
 * error: EROFS, Read-only filesystem
 *   desc: The file resides on a read-only filesystem. This includes
 *     filesystems mounted read-only and filesystems that have been remounted
 *     read-only due to errors (errors=remount-ro mount option).
 *
 * error: EPERM, Operation not permitted
 *   desc: The calling process does not have permission to change ownership.
 *     This occurs when: (1) changing uid without CAP_CHOWN and not the file
 *     owner changing to same uid, (2) changing gid without CAP_CHOWN and the
 *     caller is not the file owner or not a member of the target group,
 *     (3) the file has the immutable (chattr +i) or append-only (chattr +a)
 *     attribute set.
 *
 * error: EOVERFLOW, Value too large
 *   desc: The @user or @group value cannot be represented in the target
 *     filesystem's user namespace. This occurs when the uid/gid mapping
 *     doesn't exist between the mount's idmap and the filesystem's user
 *     namespace. Also returned if the file's current uid/gid is unmapped
 *     and is not being changed to a valid value.
 *
 * error: EIO, I/O error
 *   desc: An I/O error occurred while reading from or writing to the
 *     filesystem. This typically indicates hardware failure, network issues
 *     on remote filesystems, or filesystem corruption.
 *
 * error: ESTALE, Stale file handle
 *   desc: The file handle has become stale, typically on NFS when the file
 *     was deleted or renamed on the server. The syscall automatically retries
 *     once with path revalidation; this error is returned only if the retry
 *     also fails.
 *
 * error: EINTR, Interrupted system call
 *   desc: The syscall was interrupted by a signal while waiting for the
 *     inode lock or for an NFS delegation to be released. The operation
 *     was not completed and can be retried.
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Acquired exclusively via inode_lock_killable() before modifying the
 *     inode's ownership. This serializes ownership changes with other operations
 *     that modify or depend on file attributes. The lock is held while calling
 *     security hooks, clearing setuid/setgid bits, and the filesystem's setattr
 *     operation. Released before waiting for delegation break and before return.
 *
 * lock: sb_writers (SB_FREEZE_WRITE level)
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Acquired via mnt_want_write() which calls sb_start_write() to
 *     prevent filesystem freeze during the operation. This is a per-superblock
 *     percpu read-write semaphore. Released via mnt_drop_write() after the
 *     ownership change completes.
 *
 * signal: fatal_signals
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: While waiting for the inode lock
 *   desc: The inode_lock_killable() function allows fatal signals (SIGKILL,
 *     SIGTERM, etc.) to interrupt the wait for the inode lock. If interrupted,
 *     the syscall returns -EINTR (translated from -ERESTARTSYS).
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * signal: any_signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: While waiting for NFS delegation break
 *   desc: When the file has an NFSv4 delegation held by another client, the
 *     kernel must break the delegation and wait for acknowledgment. This wait
 *     via break_deleg_wait() is interruptible by any signal. If interrupted,
 *     returns -EINTR.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM | KAPI_EFFECT_MODIFY_STATE
 *   target: File inode uid/gid
 *   desc: On success, the file's owner (i_uid) and/or group (i_gid) are changed
 *     to the values specified in @user and @group (unless -1 was passed for
 *     either). This change is persisted to storage synchronously or
 *     asynchronously depending on filesystem mount options.
 *   condition: Operation succeeds and @user/@group are not -1
 *   reversible: yes (via another chown call)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Inode ctime
 *   desc: The inode's change time (ctime) is updated to the current time to
 *     reflect the metadata modification. This occurs even if @user and @group
 *     are both -1 (no actual ownership change).
 *   condition: Operation succeeds
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Set-user-ID and set-group-ID bits
 *   desc: For non-directory files, the set-user-ID (S_ISUID) bit is always
 *     cleared on ownership change. The set-group-ID (S_ISGID) bit is cleared
 *     if the file is group-executable and the caller lacks CAP_FSETID, or if
 *     the file is not group-executable and the caller is not in the file's
 *     group. This prevents security issues with setuid/setgid executables
 *     after ownership changes.
 *   condition: For regular files when ownership changes
 *   reversible: yes (via chmod)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: File capabilities (security.capability xattr)
 *   desc: File capabilities are cleared via ATTR_KILL_PRIV mechanism when
 *     ownership changes on non-directory files. This is handled by the
 *     security_inode_killpriv() hook which removes the security.capability
 *     extended attribute.
 *   condition: For non-directory files with file capabilities
 *   reversible: no (capabilities must be re-set manually)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify events
 *   desc: On successful completion, fsnotify_change() is called to generate
 *     inotify IN_ATTRIB and fanotify FAN_ATTRIB events, notifying watchers
 *     of the attribute change.
 *   condition: Operation succeeds
 *   reversible: no
 *
 * capability: CAP_CHOWN
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Change the owner (uid) of any file to any value. Change the group
 *     (gid) of any file to any value. Without this capability, users can only
 *     change ownership in limited ways.
 *   without: Users can only: (1) keep the current uid unchanged, (2) change
 *     the gid of files they own to a group they are a member of. Attempting
 *     to change uid or change gid to a non-member group returns -EPERM.
 *   condition: Checked in chown_ok() and chgrp_ok() via capable_wrt_inode_uidgid()
 *     during setattr_prepare(). The capability must be effective in a user
 *     namespace where the file's uid/gid are mapped.
 *
 * capability: CAP_FSETID
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Preserve set-group-ID bit on ownership change when the caller is
 *     not a member of the file's new group.
 *   without: The S_ISGID bit is cleared if the file is group-executable and
 *     the caller is not in the file's group, preventing creation of setgid
 *     executables with unexpected group ownership.
 *   condition: Checked via capable() in setattr_should_drop_suidgid() and
 *     in_group_or_capable() during attribute copying.
 *
 * constraint: Immutable and Append-only Files
 *   desc: Files with the immutable attribute (FS_IMMUTABLE_FL, set via
 *     chattr +i) or append-only attribute (FS_APPEND_FL, set via chattr +a)
 *     cannot have their ownership changed. These attributes must be removed
 *     first by root using chattr.
 *   expr: !(inode->i_flags & (S_IMMUTABLE | S_APPEND))
 *
 * constraint: Filesystem Must Be Mounted Writable
 *   desc: The filesystem containing the file must be mounted read-write.
 *     Files on read-only filesystems or filesystems that have been emergency
 *     remounted read-only cannot have their ownership changed.
 *
 * constraint: UID/GID Namespace Mapping
 *   desc: The @user and @group values must be valid in the caller's user
 *     namespace and must map to valid values in the filesystem's user namespace.
 *     On idmapped mounts, the mount's idmap is also applied. Invalid or unmapped
 *     IDs result in -EINVAL or -EOVERFLOW.
 *
 * constraint: LSM Hooks
 *   desc: Linux Security Module hooks security_path_chown() and
 *     security_inode_setattr() are called and may deny the operation based
 *     on security policy (SELinux, AppArmor, TOMOYO, etc.). The exact errors
 *     depend on the LSM configuration.
 *
 * examples: fchownat(AT_FDCWD, "file.txt", 1000, 1000, 0);  // Change owner and group
 *   fchownat(dirfd, "file", 0, -1, 0);  // Change owner to root, keep group
 *   fchownat(AT_FDCWD, "link", 1000, 1000, AT_SYMLINK_NOFOLLOW);  // chown symlink
 *   fchownat(fd, "", 1000, 1000, AT_EMPTY_PATH);  // chown file referred to by fd
 *   fchownat(AT_FDCWD, "/abs/path", -1, 100, 0);  // Change group only
 *
 * notes: The chown() syscall is equivalent to fchownat(AT_FDCWD, path, uid, gid, 0).
 *   The lchown() syscall is equivalent to fchownat(AT_FDCWD, path, uid, gid,
 *   AT_SYMLINK_NOFOLLOW). The fchown() syscall operates on an open file descriptor
 *   directly without path resolution.
 *
 *   On NFS, ownership changes may be subject to root squashing where the server
 *   maps root operations to an unprivileged user. This can cause unexpected
 *   permission denials.
 *
 *   Changing ownership of symbolic links via AT_SYMLINK_NOFOLLOW is allowed but
 *   may have no practical effect on some filesystems where symbolic link
 *   ownership is not stored or used.
 *
 *   The special values (uid_t)-1 and (gid_t)-1 are 0xFFFFFFFF. These are
 *   distinct from uid/gid 65534 which is often used for "nobody".
 *
 *   For files with POSIX ACLs, ownership changes may affect the interpretation
 *   of ACL entries and could require ACL updates for proper access control.
 *
 * since-version: 2.6.16
 */
SYSCALL_DEFINE5(fchownat, int, dfd, const char __user *, filename, uid_t, user,
		gid_t, group, int, flag)
{
	return do_fchownat(dfd, filename, user, group, flag);
}

SYSCALL_DEFINE3(chown, const char __user *, filename, uid_t, user, gid_t, group)
{
	return do_fchownat(AT_FDCWD, filename, user, group, 0);
}

SYSCALL_DEFINE3(lchown, const char __user *, filename, uid_t, user, gid_t, group)
{
	return do_fchownat(AT_FDCWD, filename, user, group,
			   AT_SYMLINK_NOFOLLOW);
}

int vfs_fchown(struct file *file, uid_t user, gid_t group)
{
	int error;

	error = mnt_want_write_file(file);
	if (error)
		return error;
	audit_file(file);
	error = chown_common(&file->f_path, user, group);
	mnt_drop_write_file(file);
	return error;
}

int ksys_fchown(unsigned int fd, uid_t user, gid_t group)
{
	CLASS(fd, f)(fd);

	if (fd_empty(f))
		return -EBADF;

	return vfs_fchown(fd_file(f), user, group);
}

/**
 * sys_fchown - change ownership of an open file
 * @fd: open file descriptor identifying the target file
 * @user: new owner user ID, or (uid_t)-1 to leave unchanged
 * @group: new owner group ID, or (gid_t)-1 to leave unchanged
 *
 * long-desc: Changes the owner and/or group of the file referred to by the
 *   open file descriptor @fd. Unlike chown() and lchown() which operate on
 *   pathnames, fchown() operates directly on an already-opened file,
 *   eliminating any race conditions from pathname resolution.
 *
 *   The @user and @group parameters specify the new owner and group. Passing
 *   the special value (uid_t)-1 for @user or (gid_t)-1 for @group leaves that
 *   attribute unchanged. This allows changing only the owner or only the group.
 *
 *   Permission requirements: Only privileged processes (those with CAP_CHOWN
 *   in a user namespace where the file's uid/gid are mapped) can change a
 *   file's owner to an arbitrary value. Unprivileged users can only change
 *   the group of files they own to a group they are a member of.
 *
 *   Setuid/setgid handling: When ownership is changed by a non-privileged user,
 *   the set-user-ID and set-group-ID bits are automatically cleared from
 *   regular files to prevent security issues. The kernel also clears file
 *   capabilities (via ATTR_KILL_PRIV) on ownership changes for non-directories.
 *
 *   File descriptor handling: The file descriptor @fd must be valid and open.
 *   Files opened with O_PATH can have their ownership changed since the
 *   operation modifies the underlying inode, not the file description.
 *   The file descriptor does not need to be opened with write permission.
 *
 *   NFS delegation handling: If the file has an NFSv4 delegation held by
 *   another client, the kernel will break the delegation and wait for the
 *   client to release it before proceeding with the ownership change.
 *
 *   POSIX.1-2001/2008 compliant. The uid_t and gid_t parameters are 32-bit
 *   unsigned integers with (uid_t)-1 and (gid_t)-1 having special "no change"
 *   meaning.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid open file descriptor. Any file type is
 *     accepted: regular files, directories, symbolic links, block/character
 *     devices, FIFOs, and sockets can all have their ownership changed.
 *     File descriptors opened with O_PATH are accepted. The fd does not
 *     need write permission on the file.
 *
 * param: user
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: New owner user ID, or the special value (uid_t)-1 (0xFFFFFFFF)
 *     to leave the owner unchanged. The uid must be valid in the caller's user
 *     namespace and must map to a valid uid in the filesystem's user namespace.
 *     Changing to an arbitrary uid requires CAP_CHOWN capability.
 *
 * param: group
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: New owner group ID, or the special value (gid_t)-1 (0xFFFFFFFF)
 *     to leave the group unchanged. The gid must be valid in the caller's user
 *     namespace and must map to a valid gid in the filesystem's user namespace.
 *     Unprivileged users can only change to a group they are a member of.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. On error, returns a negative error code.
 *     The ownership change is atomic with respect to other filesystem
 *     operations on the same inode.
 *
 * error: EBADF, Bad file descriptor
 *   desc: @fd is not a valid open file descriptor. The file descriptor table
 *     does not contain an entry for this descriptor number.
 *
 * error: EINVAL, Invalid user or group ID
 *   desc: The @user or @group value cannot be converted to a valid kernel
 *     uid/gid. This occurs when the value is not valid in the caller's user
 *     namespace (cannot be mapped to a kuid_t or kgid_t).
 *
 * error: EROFS, Read-only filesystem
 *   desc: The file resides on a read-only filesystem. This includes
 *     filesystems mounted read-only and filesystems that have been remounted
 *     read-only due to errors (errors=remount-ro mount option).
 *
 * error: EPERM, Operation not permitted
 *   desc: The calling process does not have permission to change ownership.
 *     This occurs when: (1) changing uid without CAP_CHOWN and not the file
 *     owner changing to same uid, (2) changing gid without CAP_CHOWN and the
 *     caller is not the file owner or not a member of the target group,
 *     (3) the file has the immutable (chattr +i) or append-only (chattr +a)
 *     attribute set, (4) an LSM policy denies the operation.
 *
 * error: EOVERFLOW, Value too large
 *   desc: The @user or @group value cannot be represented in the target
 *     filesystem's user namespace. This occurs when the uid/gid mapping
 *     doesn't exist between the mount's idmap and the filesystem's user
 *     namespace. Also returned if the file's current uid/gid is unmapped
 *     and is not being changed to a valid value.
 *
 * error: EINTR, Interrupted system call
 *   desc: The syscall was interrupted by a fatal signal while waiting for the
 *     inode lock or by any signal while waiting for an NFS delegation to be
 *     released. The operation was not completed and can be retried.
 *
 * error: EIO, I/O error
 *   desc: An I/O error occurred while reading from or writing to the
 *     filesystem. This typically indicates hardware failure, network issues
 *     on remote filesystems, or filesystem corruption.
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory to complete the operation or allocate
 *     internal structures. This is a transient error.
 *
 * error: EDQUOT, Disk quota exceeded
 *   desc: On filesystems with disk quotas enabled, the ownership change would
 *     cause the new owner's or group's disk quota to be exceeded. The file's
 *     current usage (blocks and inodes) would exceed the hard quota limits
 *     for the target user or group.
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Acquired exclusively via inode_lock_killable() before modifying the
 *     inode's ownership. This serializes ownership changes with other operations
 *     that modify or depend on file attributes. The lock is held while calling
 *     security hooks, clearing setuid/setgid bits, and the filesystem's setattr
 *     operation. Released before waiting for delegation break and before return.
 *
 * lock: sb_writers (SB_FREEZE_WRITE level)
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Acquired via mnt_want_write_file() which calls sb_start_write() to
 *     prevent filesystem freeze during the operation. This is a per-superblock
 *     percpu read-write semaphore. Released via mnt_drop_write_file() after the
 *     ownership change completes.
 *
 * signal: fatal_signals
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: While waiting for the inode lock
 *   desc: The inode_lock_killable() function allows fatal signals (SIGKILL,
 *     SIGTERM, etc.) to interrupt the wait for the inode lock. If interrupted,
 *     the syscall returns -EINTR (translated from -ERESTARTSYS).
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * signal: any_signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: While waiting for NFS delegation break
 *   desc: When the file has an NFSv4 delegation held by another client, the
 *     kernel must break the delegation and wait for acknowledgment. This wait
 *     via break_deleg_wait() is interruptible by any signal. If interrupted,
 *     returns -EINTR.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM | KAPI_EFFECT_MODIFY_STATE
 *   target: File inode uid/gid
 *   desc: On success, the file's owner (i_uid) and/or group (i_gid) are changed
 *     to the values specified in @user and @group (unless -1 was passed for
 *     either). This change is persisted to storage synchronously or
 *     asynchronously depending on filesystem mount options.
 *   condition: Operation succeeds and @user/@group are not -1
 *   reversible: yes (via another chown/fchown call)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Inode ctime
 *   desc: The inode's change time (ctime) is updated to the current time to
 *     reflect the metadata modification. This occurs even if @user and @group
 *     are both -1 (no actual ownership change).
 *   condition: Operation succeeds
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Set-user-ID and set-group-ID bits
 *   desc: For non-directory files, the set-user-ID (S_ISUID) bit is always
 *     cleared on ownership change. The set-group-ID (S_ISGID) bit is cleared
 *     if the file is group-executable and the caller lacks CAP_FSETID, or if
 *     the file is not group-executable and the caller is not in the file's
 *     group. This prevents security issues with setuid/setgid executables
 *     after ownership changes.
 *   condition: For regular files when ownership changes
 *   reversible: yes (via chmod/fchmod)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: File capabilities (security.capability xattr)
 *   desc: File capabilities are cleared via ATTR_KILL_PRIV mechanism when
 *     ownership changes on non-directory files. This is handled by the
 *     security_inode_killpriv() hook which removes the security.capability
 *     extended attribute.
 *   condition: For non-directory files with file capabilities
 *   reversible: no (capabilities must be re-set manually)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify events
 *   desc: On successful completion, fsnotify_change() is called to generate
 *     inotify IN_ATTRIB and fanotify FAN_ATTRIB events, notifying watchers
 *     of the attribute change.
 *   condition: Operation succeeds
 *   reversible: no
 *
 * capability: CAP_CHOWN
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Change the owner (uid) of any file to any value. Change the group
 *     (gid) of any file to any value. Without this capability, users can only
 *     change ownership in limited ways.
 *   without: Users can only: (1) keep the current uid unchanged, (2) change
 *     the gid of files they own to a group they are a member of. Attempting
 *     to change uid or change gid to a non-member group returns -EPERM.
 *   condition: Checked in chown_ok() and chgrp_ok() via capable_wrt_inode_uidgid()
 *     during setattr_prepare(). The capability must be effective in a user
 *     namespace where the file's uid/gid are mapped.
 *
 * capability: CAP_FSETID
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Preserve set-group-ID bit on ownership change when the caller is
 *     not a member of the file's new group.
 *   without: The S_ISGID bit is cleared if the file is group-executable and
 *     the caller is not in the file's group, preventing creation of setgid
 *     executables with unexpected group ownership.
 *   condition: Checked via capable() in setattr_should_drop_suidgid() and
 *     in_group_or_capable() during attribute copying.
 *
 * constraint: Immutable and Append-only Files
 *   desc: Files with the immutable attribute (FS_IMMUTABLE_FL, set via
 *     chattr +i) or append-only attribute (FS_APPEND_FL, set via chattr +a)
 *     cannot have their ownership changed. These attributes must be removed
 *     first by root using chattr.
 *   expr: !(inode->i_flags & (S_IMMUTABLE | S_APPEND))
 *
 * constraint: Filesystem Must Be Mounted Writable
 *   desc: The filesystem containing the file must be mounted read-write.
 *     Files on read-only filesystems or filesystems that have been emergency
 *     remounted read-only cannot have their ownership changed.
 *
 * constraint: UID/GID Namespace Mapping
 *   desc: The @user and @group values must be valid in the caller's user
 *     namespace and must map to valid values in the filesystem's user namespace.
 *     On idmapped mounts, the mount's idmap is also applied. Invalid or unmapped
 *     IDs result in -EINVAL or -EOVERFLOW.
 *
 * constraint: LSM Hooks
 *   desc: Linux Security Module hooks security_path_chown() and
 *     security_inode_setattr() are called and may deny the operation based
 *     on security policy (SELinux, AppArmor, TOMOYO, etc.). The exact errors
 *     depend on the LSM configuration.
 *
 * examples: fchown(fd, 1000, 1000);  // Change owner and group
 *   fchown(fd, 0, -1);  // Change owner to root, keep group
 *   fchown(fd, -1, 100);  // Keep owner, change group to gid 100
 *   fchown(fd, -1, -1);  // No change (but still updates ctime)
 *
 * notes: fchown() operates directly on an open file descriptor, avoiding race
 *   conditions that can occur with path-based chown(). This is especially
 *   important in security-sensitive applications where TOCTOU (time-of-check
 *   to time-of-use) vulnerabilities must be avoided.
 *
 *   The fchown() syscall is equivalent to fchownat(fd, "", uid, gid, AT_EMPTY_PATH)
 *   but is more efficient as it avoids path resolution entirely.
 *
 *   On NFS, ownership changes may be subject to root squashing where the server
 *   maps root operations to an unprivileged user. This can cause unexpected
 *   permission denials even when the caller has CAP_CHOWN locally.
 *
 *   The special values (uid_t)-1 and (gid_t)-1 are 0xFFFFFFFF. These are
 *   distinct from uid/gid 65534 which is often used for "nobody".
 *
 *   For files with POSIX ACLs, ownership changes may affect the interpretation
 *   of ACL entries and could require ACL updates for proper access control.
 *
 *   On some pseudo-filesystems (procfs, sysfs), ownership changes may silently
 *   succeed but have no persistent effect, as these filesystems generate file
 *   attributes dynamically.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE3(fchown, unsigned int, fd, uid_t, user, gid_t, group)
{
	return ksys_fchown(fd, user, group);
}

static inline int file_get_write_access(struct file *f)
{
	int error;

	error = get_write_access(f->f_inode);
	if (unlikely(error))
		return error;
	error = mnt_get_write_access(f->f_path.mnt);
	if (unlikely(error))
		goto cleanup_inode;
	if (unlikely(f->f_mode & FMODE_BACKING)) {
		error = mnt_get_write_access(backing_file_user_path(f)->mnt);
		if (unlikely(error))
			goto cleanup_mnt;
	}
	return 0;

cleanup_mnt:
	mnt_put_write_access(f->f_path.mnt);
cleanup_inode:
	put_write_access(f->f_inode);
	return error;
}

static int do_dentry_open(struct file *f,
			  int (*open)(struct inode *, struct file *))
{
	static const struct file_operations empty_fops = {};
	struct inode *inode = f->f_path.dentry->d_inode;
	int error;

	path_get(&f->f_path);
	f->f_inode = inode;
	f->f_mapping = inode->i_mapping;
	f->f_wb_err = filemap_sample_wb_err(f->f_mapping);
	f->f_sb_err = file_sample_sb_err(f);

	if (unlikely(f->f_flags & O_PATH)) {
		f->f_mode = FMODE_PATH | FMODE_OPENED;
		file_set_fsnotify_mode(f, FMODE_NONOTIFY);
		f->f_op = &empty_fops;
		return 0;
	}

	if ((f->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ) {
		i_readcount_inc(inode);
	} else if (f->f_mode & FMODE_WRITE && !special_file(inode->i_mode)) {
		error = file_get_write_access(f);
		if (unlikely(error))
			goto cleanup_file;
		f->f_mode |= FMODE_WRITER;
	}

	/* POSIX.1-2008/SUSv4 Section XSI 2.9.7 */
	if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))
		f->f_mode |= FMODE_ATOMIC_POS;

	f->f_op = fops_get(inode->i_fop);
	if (WARN_ON(!f->f_op)) {
		error = -ENODEV;
		goto cleanup_all;
	}

	error = security_file_open(f);
	if (unlikely(error))
		goto cleanup_all;

	/*
	 * Call fsnotify open permission hook and set FMODE_NONOTIFY_* bits
	 * according to existing permission watches.
	 * If FMODE_NONOTIFY mode was already set for an fanotify fd or for a
	 * pseudo file, this call will not change the mode.
	 */
	error = fsnotify_open_perm_and_set_mode(f);
	if (unlikely(error))
		goto cleanup_all;

	error = break_lease(file_inode(f), f->f_flags);
	if (unlikely(error))
		goto cleanup_all;

	/* normally all 3 are set; ->open() can clear them if needed */
	f->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
	if (!open)
		open = f->f_op->open;
	if (open) {
		error = open(inode, f);
		if (error)
			goto cleanup_all;
	}
	f->f_mode |= FMODE_OPENED;
	if ((f->f_mode & FMODE_READ) &&
	     likely(f->f_op->read || f->f_op->read_iter))
		f->f_mode |= FMODE_CAN_READ;
	if ((f->f_mode & FMODE_WRITE) &&
	     likely(f->f_op->write || f->f_op->write_iter))
		f->f_mode |= FMODE_CAN_WRITE;
	if ((f->f_mode & FMODE_LSEEK) && !f->f_op->llseek)
		f->f_mode &= ~FMODE_LSEEK;
	if (f->f_mapping->a_ops && f->f_mapping->a_ops->direct_IO)
		f->f_mode |= FMODE_CAN_ODIRECT;

	f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	f->f_iocb_flags = iocb_flags(f);

	file_ra_state_init(&f->f_ra, f->f_mapping->host->i_mapping);

	if ((f->f_flags & O_DIRECT) && !(f->f_mode & FMODE_CAN_ODIRECT))
		return -EINVAL;

	/*
	 * XXX: Huge page cache doesn't support writing yet. Drop all page
	 * cache for this file before processing writes.
	 */
	if (f->f_mode & FMODE_WRITE) {
		/*
		 * Depends on full fence from get_write_access() to synchronize
		 * against collapse_file() regarding i_writecount and nr_thps
		 * updates. Ensures subsequent insertion of THPs into the page
		 * cache will fail.
		 */
		if (filemap_nr_thps(inode->i_mapping)) {
			struct address_space *mapping = inode->i_mapping;

			filemap_invalidate_lock(inode->i_mapping);
			/*
			 * unmap_mapping_range just need to be called once
			 * here, because the private pages is not need to be
			 * unmapped mapping (e.g. data segment of dynamic
			 * shared libraries here).
			 */
			unmap_mapping_range(mapping, 0, 0, 0);
			truncate_inode_pages(mapping, 0);
			filemap_invalidate_unlock(inode->i_mapping);
		}
	}

	return 0;

cleanup_all:
	if (WARN_ON_ONCE(error > 0))
		error = -EINVAL;
	fops_put(f->f_op);
	put_file_access(f);
cleanup_file:
	path_put(&f->f_path);
	f->__f_path.mnt = NULL;
	f->__f_path.dentry = NULL;
	f->f_inode = NULL;
	return error;
}

/**
 * finish_open - finish opening a file
 * @file: file pointer
 * @dentry: pointer to dentry
 * @open: open callback
 *
 * This can be used to finish opening a file passed to i_op->atomic_open().
 *
 * If the open callback is set to NULL, then the standard f_op->open()
 * filesystem callback is substituted.
 *
 * NB: the dentry reference is _not_ consumed.  If, for example, the dentry is
 * the return value of d_splice_alias(), then the caller needs to perform dput()
 * on it after finish_open().
 *
 * Returns zero on success or -errno if the open failed.
 */
int finish_open(struct file *file, struct dentry *dentry,
		int (*open)(struct inode *, struct file *))
{
	BUG_ON(file->f_mode & FMODE_OPENED); /* once it's opened, it's opened */

	file->__f_path.dentry = dentry;
	return do_dentry_open(file, open);
}
EXPORT_SYMBOL(finish_open);

/**
 * finish_no_open - finish ->atomic_open() without opening the file
 *
 * @file: file pointer
 * @dentry: dentry, ERR_PTR(-E...) or NULL (as returned from ->lookup())
 *
 * This can be used to set the result of a lookup in ->atomic_open().
 *
 * NB: unlike finish_open() this function does consume the dentry reference and
 * the caller need not dput() it.
 *
 * Returns 0 or -E..., which must be the return value of ->atomic_open() after
 * having called this function.
 */
int finish_no_open(struct file *file, struct dentry *dentry)
{
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	file->__f_path.dentry = dentry;
	return 0;
}
EXPORT_SYMBOL(finish_no_open);

char *file_path(struct file *filp, char *buf, int buflen)
{
	return d_path(&filp->f_path, buf, buflen);
}
EXPORT_SYMBOL(file_path);

/**
 * vfs_open - open the file at the given path
 * @path: path to open
 * @file: newly allocated file with f_flag initialized
 */
int vfs_open(const struct path *path, struct file *file)
{
	int ret;

	file->__f_path = *path;
	ret = do_dentry_open(file, NULL);
	if (!ret) {
		/*
		 * Once we return a file with FMODE_OPENED, __fput() will call
		 * fsnotify_close(), so we need fsnotify_open() here for
		 * symmetry.
		 */
		fsnotify_open(file);
	}
	return ret;
}

struct file *dentry_open(const struct path *path, int flags,
			 const struct cred *cred)
{
	int error;
	struct file *f;

	/* We must always pass in a valid mount pointer. */
	BUG_ON(!path->mnt);

	f = alloc_empty_file(flags, cred);
	if (!IS_ERR(f)) {
		error = vfs_open(path, f);
		if (error) {
			fput(f);
			f = ERR_PTR(error);
		}
	}
	return f;
}
EXPORT_SYMBOL(dentry_open);

struct file *dentry_open_nonotify(const struct path *path, int flags,
				  const struct cred *cred)
{
	struct file *f = alloc_empty_file(flags, cred);
	if (!IS_ERR(f)) {
		int error;

		file_set_fsnotify_mode(f, FMODE_NONOTIFY);
		error = vfs_open(path, f);
		if (error) {
			fput(f);
			f = ERR_PTR(error);
		}
	}
	return f;
}

/**
 * dentry_create - Create and open a file
 * @path: path to create
 * @flags: O_ flags
 * @mode: mode bits for new file
 * @cred: credentials to use
 *
 * Caller must hold the parent directory's lock, and have prepared
 * a negative dentry, placed in @path->dentry, for the new file.
 *
 * Caller sets @path->mnt to the vfsmount of the filesystem where
 * the new file is to be created. The parent directory and the
 * negative dentry must reside on the same filesystem instance.
 *
 * On success, returns a "struct file *". Otherwise a ERR_PTR
 * is returned.
 */
struct file *dentry_create(const struct path *path, int flags, umode_t mode,
			   const struct cred *cred)
{
	struct file *f;
	int error;

	f = alloc_empty_file(flags, cred);
	if (IS_ERR(f))
		return f;

	error = vfs_create(mnt_idmap(path->mnt), path->dentry, mode, NULL);
	if (!error)
		error = vfs_open(path, f);

	if (unlikely(error)) {
		fput(f);
		return ERR_PTR(error);
	}
	return f;
}
EXPORT_SYMBOL(dentry_create);

/**
 * kernel_file_open - open a file for kernel internal use
 * @path:	path of the file to open
 * @flags:	open flags
 * @cred:	credentials for open
 *
 * Open a file for use by in-kernel consumers. The file is not accounted
 * against nr_files and must not be installed into the file descriptor
 * table.
 *
 * Return: Opened file on success, an error pointer on failure.
 */
struct file *kernel_file_open(const struct path *path, int flags,
				const struct cred *cred)
{
	struct file *f;
	int error;

	f = alloc_empty_file_noaccount(flags, cred);
	if (IS_ERR(f))
		return f;

	error = vfs_open(path, f);
	if (error) {
		fput(f);
		return ERR_PTR(error);
	}
	return f;
}
EXPORT_SYMBOL_GPL(kernel_file_open);

#define WILL_CREATE(flags)	(flags & (O_CREAT | __O_TMPFILE))
#define O_PATH_FLAGS		(O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC)

inline struct open_how build_open_how(int flags, umode_t mode)
{
	struct open_how how = {
		.flags = flags & VALID_OPEN_FLAGS,
		.mode = mode & S_IALLUGO,
	};

	/* O_PATH beats everything else. */
	if (how.flags & O_PATH)
		how.flags &= O_PATH_FLAGS;
	/* Modes should only be set for create-like flags. */
	if (!WILL_CREATE(how.flags))
		how.mode = 0;
	return how;
}

inline int build_open_flags(const struct open_how *how, struct open_flags *op)
{
	u64 flags = how->flags;
	u64 strip = O_CLOEXEC;
	int lookup_flags = 0;
	int acc_mode = ACC_MODE(flags);

	BUILD_BUG_ON_MSG(upper_32_bits(VALID_OPEN_FLAGS),
			 "struct open_flags doesn't yet handle flags > 32 bits");

	/*
	 * Strip flags that aren't relevant in determining struct open_flags.
	 */
	flags &= ~strip;

	/*
	 * Older syscalls implicitly clear all of the invalid flags or argument
	 * values before calling build_open_flags(), but openat2(2) checks all
	 * of its arguments.
	 */
	if (flags & ~VALID_OPEN_FLAGS)
		return -EINVAL;
	if (how->resolve & ~VALID_RESOLVE_FLAGS)
		return -EINVAL;

	/* Scoping flags are mutually exclusive. */
	if ((how->resolve & RESOLVE_BENEATH) && (how->resolve & RESOLVE_IN_ROOT))
		return -EINVAL;

	/* Deal with the mode. */
	if (WILL_CREATE(flags)) {
		if (how->mode & ~S_IALLUGO)
			return -EINVAL;
		op->mode = how->mode | S_IFREG;
	} else {
		if (how->mode != 0)
			return -EINVAL;
		op->mode = 0;
	}

	/*
	 * Block bugs where O_DIRECTORY | O_CREAT created regular files.
	 * Note, that blocking O_DIRECTORY | O_CREAT here also protects
	 * O_TMPFILE below which requires O_DIRECTORY being raised.
	 */
	if ((flags & (O_DIRECTORY | O_CREAT)) == (O_DIRECTORY | O_CREAT))
		return -EINVAL;

	/* Now handle the creative implementation of O_TMPFILE. */
	if (flags & __O_TMPFILE) {
		/*
		 * In order to ensure programs get explicit errors when trying
		 * to use O_TMPFILE on old kernels we enforce that O_DIRECTORY
		 * is raised alongside __O_TMPFILE.
		 */
		if (!(flags & O_DIRECTORY))
			return -EINVAL;
		if (!(acc_mode & MAY_WRITE))
			return -EINVAL;
	}
	if (flags & O_PATH) {
		/* O_PATH only permits certain other flags to be set. */
		if (flags & ~O_PATH_FLAGS)
			return -EINVAL;
		acc_mode = 0;
	}

	/*
	 * O_SYNC is implemented as __O_SYNC|O_DSYNC.  As many places only
	 * check for O_DSYNC if the need any syncing at all we enforce it's
	 * always set instead of having to deal with possibly weird behaviour
	 * for malicious applications setting only __O_SYNC.
	 */
	if (flags & __O_SYNC)
		flags |= O_DSYNC;

	op->open_flag = flags;

	/* O_TRUNC implies we need access checks for write permissions */
	if (flags & O_TRUNC)
		acc_mode |= MAY_WRITE;

	/* Allow the LSM permission hook to distinguish append
	   access from general write access. */
	if (flags & O_APPEND)
		acc_mode |= MAY_APPEND;

	op->acc_mode = acc_mode;

	op->intent = flags & O_PATH ? 0 : LOOKUP_OPEN;

	if (flags & O_CREAT) {
		op->intent |= LOOKUP_CREATE;
		if (flags & O_EXCL) {
			op->intent |= LOOKUP_EXCL;
			flags |= O_NOFOLLOW;
		}
	}

	if (flags & O_DIRECTORY)
		lookup_flags |= LOOKUP_DIRECTORY;
	if (!(flags & O_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;

	if (how->resolve & RESOLVE_NO_XDEV)
		lookup_flags |= LOOKUP_NO_XDEV;
	if (how->resolve & RESOLVE_NO_MAGICLINKS)
		lookup_flags |= LOOKUP_NO_MAGICLINKS;
	if (how->resolve & RESOLVE_NO_SYMLINKS)
		lookup_flags |= LOOKUP_NO_SYMLINKS;
	if (how->resolve & RESOLVE_BENEATH)
		lookup_flags |= LOOKUP_BENEATH;
	if (how->resolve & RESOLVE_IN_ROOT)
		lookup_flags |= LOOKUP_IN_ROOT;
	if (how->resolve & RESOLVE_CACHED) {
		/* Don't bother even trying for create/truncate/tmpfile open */
		if (flags & (O_TRUNC | O_CREAT | __O_TMPFILE))
			return -EAGAIN;
		lookup_flags |= LOOKUP_CACHED;
	}

	op->lookup_flags = lookup_flags;
	return 0;
}

/**
 * file_open_name - open file and return file pointer
 *
 * @name:	struct filename containing path to open
 * @flags:	open flags as per the open(2) second argument
 * @mode:	mode for the new file if O_CREAT is set, else ignored
 *
 * This is the helper to open a file from kernelspace if you really
 * have to.  But in generally you should not do this, so please move
 * along, nothing to see here..
 */
struct file *file_open_name(struct filename *name, int flags, umode_t mode)
{
	struct open_flags op;
	struct open_how how = build_open_how(flags, mode);
	int err = build_open_flags(&how, &op);
	if (err)
		return ERR_PTR(err);
	return do_filp_open(AT_FDCWD, name, &op);
}

/**
 * filp_open - open file and return file pointer
 *
 * @filename:	path to open
 * @flags:	open flags as per the open(2) second argument
 * @mode:	mode for the new file if O_CREAT is set, else ignored
 *
 * This is the helper to open a file from kernelspace if you really
 * have to.  But in generally you should not do this, so please move
 * along, nothing to see here..
 */
struct file *filp_open(const char *filename, int flags, umode_t mode)
{
	struct filename *name = getname_kernel(filename);
	struct file *file = ERR_CAST(name);

	if (!IS_ERR(name)) {
		file = file_open_name(name, flags, mode);
		putname(name);
	}
	return file;
}
EXPORT_SYMBOL(filp_open);

struct file *file_open_root(const struct path *root,
			    const char *filename, int flags, umode_t mode)
{
	struct open_flags op;
	struct open_how how = build_open_how(flags, mode);
	int err = build_open_flags(&how, &op);
	if (err)
		return ERR_PTR(err);
	return do_file_open_root(root, filename, &op);
}
EXPORT_SYMBOL(file_open_root);

static int do_sys_openat2(int dfd, const char __user *filename,
			  struct open_how *how)
{
	struct open_flags op;
	struct filename *tmp __free(putname) = NULL;
	int err;

	err = build_open_flags(how, &op);
	if (unlikely(err))
		return err;

	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	return FD_ADD(how->flags, do_filp_open(dfd, tmp, &op));
}

int do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
	struct open_how how = build_open_how(flags, mode);
	return do_sys_openat2(dfd, filename, &how);
}


/**
 * sys_open - Open or create a file
 * @filename: Pathname of the file to open or create
 * @flags: File access mode and behavior flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
 * @mode: File permission bits for newly created files (only with O_CREAT/O_TMPFILE)
 *
 * long-desc: Opens the file specified by pathname. If O_CREAT or O_TMPFILE is
 *   specified in flags, the file is created if it does not exist; its mode is
 *   set according to the mode parameter modified by the process's umask.
 *
 *   The flags argument must include one of the following access modes: O_RDONLY
 *   (read-only), O_WRONLY (write-only), or O_RDWR (read/write). These are the
 *   low-order two bits of flags. In addition, zero or more file creation and
 *   file status flags can be bitwise-ORed in flags.
 *
 *   File creation flags: O_CREAT, O_EXCL, O_NOCTTY, O_TRUNC, O_DIRECTORY,
 *   O_NOFOLLOW, O_CLOEXEC, O_TMPFILE. These flags affect open behavior.
 *
 *   File status flags: O_APPEND, O_ASYNC, O_DIRECT, O_DSYNC, O_LARGEFILE,
 *   O_NOATIME, O_NONBLOCK (O_NDELAY), O_PATH, O_SYNC. These become part of the
 *   file's open file description and can be retrieved/modified with fcntl().
 *
 *   The return value is a file descriptor, a small nonnegative integer used in
 *   subsequent system calls (read, write, lseek, fcntl, etc.) to refer to the
 *   open file. The file descriptor returned by a successful open is the lowest-
 *   numbered file descriptor not currently open for the process.
 *
 *   On 64-bit systems, O_LARGEFILE is automatically added to the flags. On 32-bit
 *   systems, files larger than 2GB require O_LARGEFILE to be explicitly set.
 *
 *   This syscall is a legacy interface. Modern code should prefer openat() for
 *   relative path operations and openat2() for additional control via resolve
 *   flags. The open() call is equivalent to openat(AT_FDCWD, pathname, flags).
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: filename
 *   type: KAPI_TYPE_PATH
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_USER_PATH
 *   constraint: Must be a valid null-terminated path string in user memory.
 *     Maximum path length is PATH_MAX (4096 bytes) including null terminator.
 *     For relative paths, resolution starts from current working directory.
 *     The path is followed (symlinks resolved) unless O_NOFOLLOW is specified.
 *
 * param: flags
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY |
 *               O_TRUNC | O_APPEND | O_NONBLOCK | O_DSYNC | O_SYNC | FASYNC |
 *               O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | O_NOATIME |
 *               O_CLOEXEC | O_PATH | O_TMPFILE
 *   constraint: Must include exactly one of O_RDONLY (0), O_WRONLY (1), or
 *     O_RDWR (2) as the access mode. Additional flags may be ORed. Invalid flag
 *     combinations (e.g., O_DIRECTORY|O_CREAT, O_PATH with incompatible flags,
 *     O_TMPFILE without O_DIRECTORY, O_TMPFILE with read-only mode) return
 *     EINVAL. Unknown flags are silently ignored for backward compatibility
 *     (unlike openat2 which rejects them).
 *
 * param: mode
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO
 *   constraint: Only meaningful when O_CREAT or O_TMPFILE is specified in
 *     flags. Specifies the file mode bits (permissions and setuid/setgid/sticky
 *     bits) for a newly created file. The effective mode is (mode & ~umask).
 *     When O_CREAT/O_TMPFILE is not set, mode is ignored. Mode values exceeding
 *     S_IALLUGO (07777) are masked off.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_FD
 *   success: >= 0
 *   desc: On success, returns a new file descriptor (non-negative integer).
 *     The returned file descriptor is the lowest-numbered descriptor not
 *     currently open for the process. On error, returns -1 and errno is set.
 *
 * error: EACCES, Permission denied
 *   desc: The requested access to the file is not allowed, or search permission
 *     is denied for one of the directories in the path prefix of pathname, or
 *     the file did not exist yet and write access to the parent directory is
 *     not allowed, or O_TRUNC is specified but write permission is denied, or
 *     the file is on a filesystem mounted with noexec and MAY_EXEC was implied.
 *
 * error: EBUSY, Device or resource busy
 *   desc: O_EXCL was specified in flags and pathname refers to a block device
 *     that is in use by the system (e.g., it is mounted).
 *
 * error: EDQUOT, Disk quota exceeded
 *   desc: O_CREAT is specified and the file does not exist, and the user's quota
 *     of disk blocks or inodes on the filesystem has been exhausted.
 *
 * error: EEXIST, File exists
 *   desc: O_CREAT and O_EXCL were specified in flags, but pathname already exists.
 *     This error is atomic with respect to file creation - it prevents race
 *     conditions (TOCTOU) when creating files.
 *
 * error: EFAULT, Bad address
 *   desc: pathname points outside the process's accessible address space.
 *
 * error: EINTR, Interrupted system call
 *   desc: The call was interrupted by a signal handler before completing file
 *     open. This can occur during lock acquisition or when breaking leases.
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned for several conditions: (1) Invalid O_* flag combinations
 *     (O_DIRECTORY|O_CREAT, O_TMPFILE without O_DIRECTORY, O_TMPFILE with
 *     read-only access, O_PATH with flags other than O_DIRECTORY|O_NOFOLLOW|
 *     O_CLOEXEC). (2) mode contains bits outside S_IALLUGO when O_CREAT/O_TMPFILE
 *     is set (openat2 only). (3) O_DIRECT requested but filesystem doesn't
 *     support it. (4) The filesystem does not support O_SYNC or O_DSYNC.
 *
 * error: EISDIR, Is a directory
 *   desc: pathname refers to a directory and the access requested involved
 *     writing (O_WRONLY, O_RDWR, or O_TRUNC). Also returned when O_TMPFILE is
 *     used on a directory that doesn't support tmpfile operations.
 *
 * error: ELOOP, Too many symbolic links
 *   desc: Too many symbolic links were encountered in resolving pathname, or
 *     O_NOFOLLOW was specified but pathname refers to a symbolic link.
 *
 * error: EMFILE, Too many open files
 *   desc: The per-process limit on the number of open file descriptors has been
 *     reached. This limit is RLIMIT_NOFILE (default typically 1024, max set by
 *     /proc/sys/fs/nr_open).
 *
 * error: ENAMETOOLONG, File name too long
 *   desc: pathname was too long, exceeding PATH_MAX (4096) bytes, or a single
 *     path component exceeded NAME_MAX (usually 255) bytes.
 *
 * error: ENFILE, Too many open files in system
 *   desc: The system-wide limit on the total number of open files has been
 *     reached (/proc/sys/fs/file-max). Processes with CAP_SYS_ADMIN can exceed
 *     this limit.
 *
 * error: ENODEV, No such device
 *   desc: pathname refers to a special file that has no corresponding device, or
 *     the file's inode has no file operations assigned.
 *
 * error: ENOENT, No such file or directory
 *   desc: A directory component in pathname does not exist or is a dangling
 *     symbolic link, or O_CREAT is not set and the named file does not exist,
 *     or pathname is an empty string (unless AT_EMPTY_PATH is used with openat2).
 *
 * error: ENOMEM, Out of memory
 *   desc: The kernel could not allocate sufficient memory for the file structure,
 *     path lookup structures, or the filename buffer.
 *
 * error: ENOSPC, No space left on device
 *   desc: O_CREAT was specified and the file does not exist, and the directory
 *     or filesystem containing the file has no room for a new file entry.
 *
 * error: ENOTDIR, Not a directory
 *   desc: A component used as a directory in pathname is not actually a directory,
 *     or O_DIRECTORY was specified and pathname was not a directory.
 *
 * error: ENXIO, No such device or address
 *   desc: O_NONBLOCK | O_WRONLY is set and the named file is a FIFO and no
 *     process has the FIFO open for reading. Also returned when opening a device
 *     special file that does not exist.
 *
 * error: EOPNOTSUPP, Operation not supported
 *   desc: The filesystem containing pathname does not support O_TMPFILE.
 *
 * error: EOVERFLOW, Value too large for defined data type
 *   desc: pathname refers to a regular file that is too large to be opened.
 *     This occurs on 32-bit systems without O_LARGEFILE when the file size
 *     exceeds 2GB (2^31 - 1 bytes).
 *
 * error: EPERM, Operation not permitted
 *   desc: O_NOATIME flag was specified but the effective UID of the caller did
 *     not match the owner of the file and the caller is not privileged, or the
 *     file is append-only and O_TRUNC was specified or write mode without
 *     O_APPEND, or the file is immutable, or a seal prevents the operation.
 *
 * error: EROFS, Read-only file system
 *   desc: pathname refers to a file on a read-only filesystem and write access
 *     was requested.
 *
 * error: ETXTBSY, Text file busy
 *   desc: pathname refers to an executable image which is currently being
 *     executed, or to a swap file, and write access or truncation was requested.
 *
 * error: EWOULDBLOCK, Resource temporarily unavailable
 *   desc: O_NONBLOCK was specified and an incompatible lease is held on the file.
 *
 * lock: files->file_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired when allocating a file descriptor slot. Held briefly during
 *     fd allocation via alloc_fd() and released before the syscall returns.
 *
 * lock: inode->i_rwsem (parent directory)
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: conditional
 *   released: true
 *   desc: Write lock acquired on parent directory inode when creating a new file
 *     (O_CREAT). Acquired via inode_lock_nested() in lookup path. May use
 *     killable variant which can return EINTR on fatal signal.
 *
 * lock: RCU read-side
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: Path lookup uses RCU mode initially for performance. If RCU lookup
 *     fails (returns -ECHILD), falls back to reference-based lookup.
 *
 * signal: Any signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: When blocked on interruptible or killable operations
 *   desc: The syscall may be interrupted during path lookup, lock acquisition,
 *     or lease breaking. Fatal signals (SIGKILL, etc.) will interrupt killable
 *     operations. Non-fatal signals may interrupt interruptible operations.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE | KAPI_EFFECT_ALLOC_MEMORY
 *   target: file descriptor, file structure, dentry cache
 *   desc: Allocates a new file descriptor in the process's fd table. Allocates
 *     a struct file from the filp slab cache. May allocate dentries and inodes
 *     during path lookup. System-wide file count (nr_files) is incremented.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: filesystem, inode
 *   condition: When O_CREAT is specified and file doesn't exist
 *   desc: Creates a new file on the filesystem. Creates new inode, allocates
 *     data blocks as needed, and creates directory entry. Updates parent
 *     directory mtime and ctime.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: file content
 *   condition: When O_TRUNC is specified for existing file
 *   desc: Truncates the file to zero length, releasing data blocks. Updates
 *     file mtime and ctime. May trigger notifications to lease holders.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: inode timestamps
 *   condition: Unless O_NOATIME is specified
 *   desc: Opens for reading may update inode access time (atime) unless mounted
 *     with noatime/relatime or O_NOATIME is specified. Opens for writing that
 *     truncate or create update mtime and ctime.
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass file read, write, and execute permission checks
 *   without: Standard DAC (discretionary access control) checks are applied
 *   condition: Checked when file permission would otherwise deny access
 *
 * capability: CAP_DAC_READ_SEARCH
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass read permission on files and search permission on directories
 *   without: Must have read permission on file or search permission on directory
 *   condition: Checked during path traversal and file open
 *
 * capability: CAP_FOWNER
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Use O_NOATIME on files not owned by caller
 *   without: O_NOATIME returns EPERM if caller is not file owner
 *   condition: Checked when O_NOATIME is specified and caller is not owner
 *
 * capability: CAP_SYS_ADMIN
 *   type: KAPI_CAP_INCREASE_LIMIT
 *   allows: Exceed the system-wide file limit (file-max)
 *   without: Returns ENFILE when system limit is reached
 *   condition: Checked in alloc_empty_file() when nr_files >= max_files
 *
 * constraint: RLIMIT_NOFILE (per-process fd limit)
 *   desc: The returned file descriptor must be less than the process's
 *     RLIMIT_NOFILE limit. Default is typically 1024, maximum is controlled
 *     by /proc/sys/fs/nr_open (default 1048576). Exceeding returns EMFILE.
 *   expr: fd < rlimit(RLIMIT_NOFILE)
 *
 * constraint: file-max (system-wide limit)
 *   desc: System-wide limit on open files in /proc/sys/fs/file-max. Processes
 *     without CAP_SYS_ADMIN receive ENFILE when this limit is reached. The
 *     limit is computed based on system memory at boot time.
 *   expr: nr_files < files_stat.max_files || capable(CAP_SYS_ADMIN)
 *
 * constraint: PATH_MAX
 *   desc: Maximum length of pathname including null terminator is PATH_MAX
 *     (4096 bytes). Individual path components must not exceed NAME_MAX (255).
 *
 * examples: fd = open("/etc/passwd", O_RDONLY);  // Read existing file
 *   fd = open("/tmp/newfile", O_WRONLY | O_CREAT | O_TRUNC, 0644);  // Create/truncate
 *   fd = open("/tmp/lockfile", O_WRONLY | O_CREAT | O_EXCL, 0600);  // Exclusive create
 *   fd = open("/dev/null", O_RDWR);  // Open device
 *   fd = open("/tmp", O_RDONLY | O_DIRECTORY);  // Open directory
 *   fd = open("/tmp", O_TMPFILE | O_RDWR, 0600);  // Anonymous temp file
 *
 * notes: The distinction between O_RDONLY, O_WRONLY, and O_RDWR is critical.
 *   O_RDONLY is defined as 0, so (flags & O_RDONLY) will be true for all flags.
 *   Test access mode using (flags & O_ACCMODE) == O_RDONLY.
 *
 *   When O_CREAT is specified without O_EXCL, there is a race condition between
 *   testing for file existence and creating it. Use O_CREAT | O_EXCL for atomic
 *   exclusive file creation.
 *
 *   O_CLOEXEC should be used in multithreaded programs to prevent file descriptor
 *   leaks to child processes between fork() and execve().
 *
 *   O_DIRECT has alignment requirements that vary by filesystem. Use statx()
 *   with STATX_DIOALIGN (Linux 6.1+) to query requirements. Unaligned I/O may
 *   fail with EINVAL or fall back to buffered I/O.
 *
 *   O_PATH opens a file descriptor that can be used only for certain operations
 *   (fstat, dup, fcntl, close, fchdir on directories, as dirfd for *at() calls).
 *   I/O operations will fail with EBADF.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	if (force_o_largefile())
		flags |= O_LARGEFILE;
	return do_sys_open(AT_FDCWD, filename, flags, mode);
}

SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags,
		umode_t, mode)
{
	if (force_o_largefile())
		flags |= O_LARGEFILE;
	return do_sys_open(dfd, filename, flags, mode);
}

SYSCALL_DEFINE4(openat2, int, dfd, const char __user *, filename,
		struct open_how __user *, how, size_t, usize)
{
	int err;
	struct open_how tmp;

	BUILD_BUG_ON(sizeof(struct open_how) < OPEN_HOW_SIZE_VER0);
	BUILD_BUG_ON(sizeof(struct open_how) != OPEN_HOW_SIZE_LATEST);

	if (unlikely(usize < OPEN_HOW_SIZE_VER0))
		return -EINVAL;
	if (unlikely(usize > PAGE_SIZE))
		return -E2BIG;

	err = copy_struct_from_user(&tmp, sizeof(tmp), how, usize);
	if (err)
		return err;

	audit_openat2_how(&tmp);

	/* O_LARGEFILE is only allowed for non-O_PATH. */
	if (!(tmp.flags & O_PATH) && force_o_largefile())
		tmp.flags |= O_LARGEFILE;

	return do_sys_openat2(dfd, filename, &tmp);
}

#ifdef CONFIG_COMPAT
/*
 * Exactly like sys_open(), except that it doesn't set the
 * O_LARGEFILE flag.
 */
COMPAT_SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	return do_sys_open(AT_FDCWD, filename, flags, mode);
}

/*
 * Exactly like sys_openat(), except that it doesn't set the
 * O_LARGEFILE flag.
 */
COMPAT_SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, umode_t, mode)
{
	return do_sys_open(dfd, filename, flags, mode);
}
#endif

#ifndef __alpha__

/*
 * For backward compatibility?  Maybe this should be moved
 * into arch/i386 instead?
 */
SYSCALL_DEFINE2(creat, const char __user *, pathname, umode_t, mode)
{
	int flags = O_CREAT | O_WRONLY | O_TRUNC;

	if (force_o_largefile())
		flags |= O_LARGEFILE;
	return do_sys_open(AT_FDCWD, pathname, flags, mode);
}
#endif

/*
 * "id" is the POSIX thread ID. We use the
 * files pointer for this..
 */
static int filp_flush(struct file *filp, fl_owner_t id)
{
	int retval = 0;

	if (CHECK_DATA_CORRUPTION(file_count(filp) == 0, filp,
			"VFS: Close: file count is 0 (f_op=%ps)",
			filp->f_op)) {
		return 0;
	}

	if (filp->f_op->flush)
		retval = filp->f_op->flush(filp, id);

	if (likely(!(filp->f_mode & FMODE_PATH))) {
		dnotify_flush(filp, id);
		locks_remove_posix(filp, id);
	}
	return retval;
}

int filp_close(struct file *filp, fl_owner_t id)
{
	int retval;

	retval = filp_flush(filp, id);
	fput_close(filp);

	return retval;
}
EXPORT_SYMBOL(filp_close);

/**
 * sys_close - Close a file descriptor
 * @fd: The file descriptor to close
 *
 * long-desc: Terminates access to an open file descriptor, releasing the file
 *   descriptor for reuse by subsequent open(), dup(), or similar syscalls. Any
 *   advisory record locks (POSIX locks, OFD locks, and flock locks) held on the
 *   associated file are released. When this is the last file descriptor
 *   referring to the underlying open file description, associated resources are
 *   freed. If the file was previously unlinked, the file itself is deleted when
 *   the last reference is closed.
 *
 *   CRITICAL: The file descriptor is ALWAYS closed, even when close() returns
 *   an error. This differs from POSIX semantics where the state of the file
 *   descriptor is unspecified after EINTR. On Linux, the fd is released early
 *   in close() processing before flush operations that may fail. Therefore,
 *   retrying close() after an error return is DANGEROUS and may close an
 *   unrelated file descriptor that was assigned to another thread.
 *
 *   Errors returned from close() (EIO, ENOSPC, EDQUOT) indicate that the final
 *   flush of buffered data failed. These errors commonly occur on network
 *   filesystems like NFS when write errors are deferred to close time. A
 *   successful return from close() does NOT guarantee that data has been
 *   successfully written to disk; the kernel uses buffer cache to defer writes.
 *   To ensure data persistence, call fsync() before close().
 *
 *   On close, the following cleanup operations are performed: POSIX advisory
 *   locks are removed, dnotify registrations are cleaned up, the file is
 *   flushed if the file operations define a flush callback, and the file
 *   reference is released. If this was the last reference, additional cleanup
 *   includes: fsnotify close notification, epoll cleanup, flock and lease
 *   removal, FASYNC cleanup, the file's release callback invocation, and
 *   the file structure deallocation.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, INT_MAX
 *   constraint: Must be a valid, open file descriptor for the current process.
 *     The value 0, 1, or 2 (stdin, stdout, stderr) may be closed like any other
 *     fd, though this is unusual and may cause issues with libraries that assume
 *     these descriptors are valid. The parameter is unsigned int to match kernel
 *     file descriptor table indexing, but values exceeding INT_MAX are effectively
 *     invalid due to internal checks.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. On error, returns a negative error code.
 *     IMPORTANT: Even when an error is returned, the file descriptor is still
 *     closed and must not be used again. The error indicates a problem with
 *     the final flush operation, not that the fd remains open.
 *
 * error: EBADF, Bad file descriptor
 *   desc: The file descriptor fd is not a valid open file descriptor, or was
 *     already closed. This is the only error that indicates the fd was NOT
 *     closed (because it was never open to begin with). Occurs when fd is out
 *     of range, has no file assigned, or was already closed.
 *
 * error: EINTR, Interrupted system call
 *   desc: The flush operation was interrupted by a signal before completion.
 *     This occurs when a file's flush callback (e.g., NFS) performs an
 *     interruptible wait that receives a signal. IMPORTANT: Despite this error,
 *     the file descriptor IS closed and must not be used again. This error
 *     is generated by converting kernel-internal restart codes (ERESTARTSYS,
 *     ERESTARTNOINTR, ERESTARTNOHAND, ERESTART_RESTARTBLOCK) to EINTR because
 *     restarting the syscall would be incorrect once the fd is freed.
 *
 * error: EIO, I/O error
 *   desc: An I/O error occurred during the flush of buffered data to the
 *     underlying storage. This typically indicates a hardware error, network
 *     failure on NFS, or other storage system error. The file descriptor is
 *     still closed. Previously buffered write data may have been lost.
 *
 * error: ENOSPC, No space left on device
 *   desc: There was insufficient space on the storage device to flush buffered
 *     writes. This is common on NFS when the server runs out of space between
 *     write() and close(). The file descriptor is still closed.
 *
 * error: EDQUOT, Disk quota exceeded
 *   desc: The user's disk quota was exceeded while attempting to flush buffered
 *     writes. Common on NFS when quota is exceeded between write() and close().
 *     The file descriptor is still closed.
 *
 * lock: files->file_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired via file_close_fd() to atomically lookup and remove the fd
 *     from the file descriptor table. Held only during the table manipulation;
 *     released before flush and final cleanup operations. This ensures that
 *     another thread cannot allocate the same fd number while close is in
 *     progress.
 *
 * lock: file->f_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired during epoll cleanup (eventpoll_release_file) and dnotify
 *     cleanup to safely unlink the file from monitoring structures. May also
 *     be acquired during lock context operations.
 *
 * lock: ep->mtx
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: Acquired during epoll cleanup if the file was monitored by epoll.
 *     Used to safely remove the file from epoll interest lists.
 *
 * lock: flc_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: File lock context spinlock, acquired during locks_remove_file() to
 *     safely remove POSIX, flock, and lease locks associated with the file.
 *
 * signal: pending_signals
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: When flush callback performs interruptible wait
 *   desc: If the file's flush callback (e.g., nfs_file_flush) performs an
 *     interruptible wait and a signal is pending, the wait is interrupted.
 *     Any kernel restart codes are converted to EINTR since close cannot be
 *     restarted after the fd is freed.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_RESOURCE_DESTROY | KAPI_EFFECT_IRREVERSIBLE
 *   target: File descriptor table entry
 *   desc: The file descriptor is removed from the process's file descriptor
 *     table, making the fd number available for reuse by subsequent open(),
 *     dup(), or similar calls. This occurs BEFORE any flush or cleanup that
 *     might fail, making the operation irreversible regardless of return value.
 *   condition: Always (when fd is valid)
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_LOCK_RELEASE
 *   target: POSIX advisory locks, OFD locks, flock locks
 *   desc: All advisory locks held on the file by this process are removed.
 *     POSIX locks are removed via locks_remove_posix() during filp_flush().
 *     All lock types (POSIX, OFD, flock) are removed via locks_remove_file()
 *     during __fput() when this is the last reference.
 *   condition: File has FMODE_OPENED and !(FMODE_PATH)
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_RESOURCE_DESTROY
 *   target: File leases
 *   desc: Any file leases held on the file are removed during locks_remove_file()
 *     when this is the last reference to the open file description.
 *   condition: File had leases and this is the last close
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: dnotify registrations
 *   desc: Directory notification (dnotify) registrations associated with this
 *     file are cleaned up via dnotify_flush(). This only applies to directories.
 *   condition: File is a directory with dnotify registrations
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: epoll interest lists
 *   desc: If the file was being monitored by epoll instances, it is removed
 *     from those interest lists via eventpoll_release().
 *   condition: File was added to epoll instances
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: Buffered data
 *   desc: The file's flush callback is invoked if defined (e.g., NFS calls
 *     nfs_file_flush). This attempts to write any buffered data to storage
 *     and may return errors (EIO, ENOSPC, EDQUOT) if the flush fails. The
 *     success of this flush is NOT guaranteed even with a 0 return; use
 *     fsync() before close() to ensure data persistence.
 *   condition: File has a flush callback and was opened for writing
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_FREE_MEMORY
 *   target: struct file and related structures
 *   desc: When this is the last reference to the file, __fput() is called
 *     synchronously (fput_close_sync), which frees the file structure, releases
 *     the dentry and mount references, and invokes the file's release callback.
 *   condition: This is the last reference to the file
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: Unlinked file deletion
 *   desc: If the file was previously unlinked (deleted) but kept open, closing
 *     the last reference causes the actual file data to be removed from the
 *     filesystem and the inode to be freed.
 *   condition: File was unlinked and this is the last reference
 *   reversible: no
 *
 * state-trans: file_descriptor
 *   from: open
 *   to: closed/free
 *   condition: Valid fd passed to close
 *   desc: The file descriptor transitions from open (usable) to closed (invalid).
 *     The fd number becomes available for reuse. This transition occurs early
 *     in close() processing, before any operations that might fail.
 *
 * state-trans: file_reference_count
 *   from: n
 *   to: n-1 (or freed if n was 1)
 *   condition: Always on successful fd lookup
 *   desc: The file's reference count is decremented. If this was the last
 *     reference, the file is fully cleaned up and freed.
 *
 * constraint: File Descriptor Reuse Race
 *   desc: Because the fd is freed early in close() processing, another thread
 *     may receive the same fd number from a concurrent open() before close()
 *     returns. Applications must not retry close() after an error return, as
 *     this could close an unrelated file opened by another thread.
 *   expr: After close(fd) returns (even with error), fd is invalid
 *
 * examples: close(fd);  // Basic usage - ignore errors (common but not ideal)
 *   if (close(fd) == -1) perror("close");  // Log errors for debugging
 *   fsync(fd); close(fd);  // Ensure data persistence before closing
 *
 * notes: This syscall has subtle non-POSIX semantics: the fd is ALWAYS closed
 *   regardless of the return value. POSIX specifies that on EINTR, the state
 *   of the fd is unspecified, but Linux always closes it. HP-UX requires
 *   retrying close() on EINTR, but doing so on Linux may close an unrelated
 *   fd that was reassigned by another thread. For portable code, the safest
 *   approach is to check for errors but never retry close().
 *
 *   Error codes from the flush callback (EIO, ENOSPC, EDQUOT) indicate that
 *   previously written data may have been lost. These errors are particularly
 *   common on NFS where write errors are often deferred to close time.
 *
 *   The driver's release() callback errors are explicitly ignored by the
 *   kernel, so device driver cleanup errors are not propagated to userspace.
 *
 *   Calling close() on a file descriptor while another thread is using it
 *   (e.g., in a blocking read() or write()) has implementation-defined
 *   behavior. On Linux, the blocked operation continues on the underlying
 *   file and may complete even after close() returns.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE1(close, unsigned int, fd)
{
	int retval;
	struct file *file;

	file = file_close_fd(fd);
	if (!file)
		return -EBADF;

	retval = filp_flush(file, current->files);

	/*
	 * We're returning to user space. Don't bother
	 * with any delayed fput() cases.
	 */
	fput_close_sync(file);

	if (likely(retval == 0))
		return 0;

	/* can't restart close syscall because file table entry was cleared */
	if (retval == -ERESTARTSYS ||
	    retval == -ERESTARTNOINTR ||
	    retval == -ERESTARTNOHAND ||
	    retval == -ERESTART_RESTARTBLOCK)
		retval = -EINTR;

	return retval;
}

/*
 * This routine simulates a hangup on the tty, to arrange that users
 * are given clean terminals at login time.
 */
SYSCALL_DEFINE0(vhangup)
{
	if (capable(CAP_SYS_TTY_CONFIG)) {
		tty_vhangup_self();
		return 0;
	}
	return -EPERM;
}

/*
 * Called when an inode is about to be open.
 * We use this to disallow opening large files on 32bit systems if
 * the caller didn't specify O_LARGEFILE.  On 64bit systems we force
 * on this flag in sys_open.
 */
int generic_file_open(struct inode * inode, struct file * filp)
{
	if (!(filp->f_flags & O_LARGEFILE) && i_size_read(inode) > MAX_NON_LFS)
		return -EOVERFLOW;
	return 0;
}

EXPORT_SYMBOL(generic_file_open);

/*
 * This is used by subsystems that don't want seekable
 * file descriptors. The function is not supposed to ever fail, the only
 * reason it returns an 'int' and not 'void' is so that it can be plugged
 * directly into file_operations structure.
 */
int nonseekable_open(struct inode *inode, struct file *filp)
{
	filp->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
	return 0;
}

EXPORT_SYMBOL(nonseekable_open);

/*
 * stream_open is used by subsystems that want stream-like file descriptors.
 * Such file descriptors are not seekable and don't have notion of position
 * (file.f_pos is always 0 and ppos passed to .read()/.write() is always NULL).
 * Contrary to file descriptors of other regular files, .read() and .write()
 * can run simultaneously.
 *
 * stream_open never fails and is marked to return int so that it could be
 * directly used as file_operations.open .
 */
int stream_open(struct inode *inode, struct file *filp)
{
	filp->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE | FMODE_ATOMIC_POS);
	filp->f_mode |= FMODE_STREAM;
	return 0;
}

EXPORT_SYMBOL(stream_open);
