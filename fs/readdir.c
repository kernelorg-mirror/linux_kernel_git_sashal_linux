// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/readdir.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/dirent.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/compat.h>
#include <linux/uaccess.h>

/*
 * Some filesystems were never converted to '->iterate_shared()'
 * and their directory iterators want the inode lock held for
 * writing. This wrapper allows for converting from the shared
 * semantics to the exclusive inode use.
 */
int wrap_directory_iterator(struct file *file,
			    struct dir_context *ctx,
			    int (*iter)(struct file *, struct dir_context *))
{
	struct inode *inode = file_inode(file);
	int ret;

	/*
	 * We'd love to have an 'inode_upgrade_trylock()' operation,
	 * see the comment in mmap_upgrade_trylock() in mm/memory.c.
	 *
	 * But considering this is for "filesystems that never got
	 * converted", it really doesn't matter.
	 *
	 * Also note that since we have to return with the lock held
	 * for reading, we can't use the "killable()" locking here,
	 * since we do need to get the lock even if we're dying.
	 *
	 * We could do the write part killably and then get the read
	 * lock unconditionally if it mattered, but see above on why
	 * this does the very simplistic conversion.
	 */
	up_read(&inode->i_rwsem);
	down_write(&inode->i_rwsem);

	/*
	 * Since we dropped the inode lock, we should do the
	 * DEADDIR test again. See 'iterate_dir()' below.
	 *
	 * Note that we don't need to re-do the f_pos games,
	 * since the file must be locked wrt f_pos anyway.
	 */
	ret = -ENOENT;
	if (!IS_DEADDIR(inode))
		ret = iter(file, ctx);

	downgrade_write(&inode->i_rwsem);
	return ret;
}
EXPORT_SYMBOL(wrap_directory_iterator);

/*
 * Note the "unsafe_put_user()" semantics: we goto a
 * label for errors.
 */
#define unsafe_copy_dirent_name(_dst, _src, _len, label) do {	\
	char __user *dst = (_dst);				\
	const char *src = (_src);				\
	size_t len = (_len);					\
	unsafe_put_user(0, dst+len, label);			\
	unsafe_copy_to_user(dst, src, len, label);		\
} while (0)


int iterate_dir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	int res = -ENOTDIR;

	if (!file->f_op->iterate_shared)
		goto out;

	res = security_file_permission(file, MAY_READ);
	if (res)
		goto out;

	res = fsnotify_file_perm(file, MAY_READ);
	if (res)
		goto out;

	res = down_read_killable(&inode->i_rwsem);
	if (res)
		goto out;

	res = -ENOENT;
	if (!IS_DEADDIR(inode)) {
		ctx->pos = file->f_pos;
		res = file->f_op->iterate_shared(file, ctx);
		file->f_pos = ctx->pos;
		fsnotify_access(file);
		file_accessed(file);
	}
	inode_unlock_shared(inode);
out:
	return res;
}
EXPORT_SYMBOL(iterate_dir);

/*
 * POSIX says that a dirent name cannot contain NULL or a '/'.
 *
 * It's not 100% clear what we should really do in this case.
 * The filesystem is clearly corrupted, but returning a hard
 * error means that you now don't see any of the other names
 * either, so that isn't a perfect alternative.
 *
 * And if you return an error, what error do you use? Several
 * filesystems seem to have decided on EUCLEAN being the error
 * code for EFSCORRUPTED, and that may be the error to use. Or
 * just EIO, which is perhaps more obvious to users.
 *
 * In order to see the other file names in the directory, the
 * caller might want to make this a "soft" error: skip the
 * entry, and return the error at the end instead.
 *
 * Note that this should likely do a "memchr(name, 0, len)"
 * check too, since that would be filesystem corruption as
 * well. However, that case can't actually confuse user space,
 * which has to do a strlen() on the name anyway to find the
 * filename length, and the above "soft error" worry means
 * that it's probably better left alone until we have that
 * issue clarified.
 *
 * Note the PATH_MAX check - it's arbitrary but the real
 * kernel limit on a possible path component, not NAME_MAX,
 * which is the technical standard limit.
 */
static int verify_dirent_name(const char *name, int len)
{
	if (len <= 0 || len >= PATH_MAX)
		return -EIO;
	if (memchr(name, '/', len))
		return -EIO;
	return 0;
}

/*
 * Traditional linux readdir() handling..
 *
 * "count=1" is a special case, meaning that the buffer is one
 * dirent-structure in size and that the code can't handle more
 * anyway. Thus the special "fillonedir()" function for that
 * case (the low-level handlers don't need to care about this).
 */

#ifdef __ARCH_WANT_OLD_READDIR

struct old_linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_offset;
	unsigned short	d_namlen;
	char		d_name[];
};

struct readdir_callback {
	struct dir_context ctx;
	struct old_linux_dirent __user * dirent;
	int result;
};

static bool fillonedir(struct dir_context *ctx, const char *name, int namlen,
		      loff_t offset, u64 ino, unsigned int d_type)
{
	struct readdir_callback *buf =
		container_of(ctx, struct readdir_callback, ctx);
	struct old_linux_dirent __user * dirent;
	unsigned long d_ino;

	if (buf->result)
		return false;
	buf->result = verify_dirent_name(name, namlen);
	if (buf->result)
		return false;
	d_ino = ino;
	if (sizeof(d_ino) < sizeof(ino) && d_ino != ino) {
		buf->result = -EOVERFLOW;
		return false;
	}
	buf->result++;
	dirent = buf->dirent;
	if (!user_write_access_begin(dirent,
			(unsigned long)(dirent->d_name + namlen + 1) -
				(unsigned long)dirent))
		goto efault;
	unsafe_put_user(d_ino, &dirent->d_ino, efault_end);
	unsafe_put_user(offset, &dirent->d_offset, efault_end);
	unsafe_put_user(namlen, &dirent->d_namlen, efault_end);
	unsafe_copy_dirent_name(dirent->d_name, name, namlen, efault_end);
	user_write_access_end();
	return true;
efault_end:
	user_write_access_end();
efault:
	buf->result = -EFAULT;
	return false;
}

SYSCALL_DEFINE3(old_readdir, unsigned int, fd,
		struct old_linux_dirent __user *, dirent, unsigned int, count)
{
	int error;
	CLASS(fd_pos, f)(fd);
	struct readdir_callback buf = {
		.ctx.actor = fillonedir,
		.ctx.count = 1, /* Hint to fs: just one entry. */
		.dirent = dirent
	};

	if (fd_empty(f))
		return -EBADF;

	error = iterate_dir(fd_file(f), &buf.ctx);
	if (buf.result)
		error = buf.result;

	return error;
}

#endif /* __ARCH_WANT_OLD_READDIR */

/*
 * New, all-improved, singing, dancing, iBCS2-compliant getdents()
 * interface. 
 */
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[];
};

struct getdents_callback {
	struct dir_context ctx;
	struct linux_dirent __user * current_dir;
	int prev_reclen;
	int error;
};

static bool filldir(struct dir_context *ctx, const char *name, int namlen,
		   loff_t offset, u64 ino, unsigned int d_type)
{
	struct linux_dirent __user *dirent, *prev;
	struct getdents_callback *buf =
		container_of(ctx, struct getdents_callback, ctx);
	unsigned long d_ino;
	int reclen = ALIGN(offsetof(struct linux_dirent, d_name) + namlen + 2,
		sizeof(long));
	int prev_reclen;
	unsigned int flags = d_type;

	BUILD_BUG_ON(FILLDIR_FLAG_NOINTR & S_DT_MASK);
	d_type &= S_DT_MASK;

	buf->error = verify_dirent_name(name, namlen);
	if (unlikely(buf->error))
		return false;
	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > ctx->count)
		return false;
	d_ino = ino;
	if (sizeof(d_ino) < sizeof(ino) && d_ino != ino) {
		buf->error = -EOVERFLOW;
		return false;
	}
	prev_reclen = buf->prev_reclen;
	if (!(flags & FILLDIR_FLAG_NOINTR) && prev_reclen && signal_pending(current))
		return false;
	dirent = buf->current_dir;
	prev = (void __user *) dirent - prev_reclen;
	if (!user_write_access_begin(prev, reclen + prev_reclen))
		goto efault;

	/* This might be 'dirent->d_off', but if so it will get overwritten */
	unsafe_put_user(offset, &prev->d_off, efault_end);
	unsafe_put_user(d_ino, &dirent->d_ino, efault_end);
	unsafe_put_user(reclen, &dirent->d_reclen, efault_end);
	unsafe_put_user(d_type, (char __user *) dirent + reclen - 1, efault_end);
	unsafe_copy_dirent_name(dirent->d_name, name, namlen, efault_end);
	user_write_access_end();

	buf->current_dir = (void __user *)dirent + reclen;
	buf->prev_reclen = reclen;
	ctx->count -= reclen;
	return true;
efault_end:
	user_write_access_end();
efault:
	buf->error = -EFAULT;
	return false;
}

SYSCALL_DEFINE3(getdents, unsigned int, fd,
		struct linux_dirent __user *, dirent, unsigned int, count)
{
	CLASS(fd_pos, f)(fd);
	struct getdents_callback buf = {
		.ctx.actor = filldir,
		.ctx.count = count,
		.current_dir = dirent
	};
	int error;

	if (fd_empty(f))
		return -EBADF;

	error = iterate_dir(fd_file(f), &buf.ctx);
	if (error >= 0)
		error = buf.error;
	if (buf.prev_reclen) {
		struct linux_dirent __user * lastdirent;
		lastdirent = (void __user *)buf.current_dir - buf.prev_reclen;

		if (put_user(buf.ctx.pos, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.ctx.count;
	}
	return error;
}

struct getdents_callback64 {
	struct dir_context ctx;
	struct linux_dirent64 __user * current_dir;
	int prev_reclen;
	int error;
};

static bool filldir64(struct dir_context *ctx, const char *name, int namlen,
		     loff_t offset, u64 ino, unsigned int d_type)
{
	struct linux_dirent64 __user *dirent, *prev;
	struct getdents_callback64 *buf =
		container_of(ctx, struct getdents_callback64, ctx);
	int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + namlen + 1,
		sizeof(u64));
	int prev_reclen;
	unsigned int flags = d_type;

	BUILD_BUG_ON(FILLDIR_FLAG_NOINTR & S_DT_MASK);
	d_type &= S_DT_MASK;

	buf->error = verify_dirent_name(name, namlen);
	if (unlikely(buf->error))
		return false;
	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > ctx->count)
		return false;
	prev_reclen = buf->prev_reclen;
	if (!(flags & FILLDIR_FLAG_NOINTR) && prev_reclen && signal_pending(current))
		return false;
	dirent = buf->current_dir;
	prev = (void __user *)dirent - prev_reclen;
	if (!user_write_access_begin(prev, reclen + prev_reclen))
		goto efault;

	/* This might be 'dirent->d_off', but if so it will get overwritten */
	unsafe_put_user(offset, &prev->d_off, efault_end);
	unsafe_put_user(ino, &dirent->d_ino, efault_end);
	unsafe_put_user(reclen, &dirent->d_reclen, efault_end);
	unsafe_put_user(d_type, &dirent->d_type, efault_end);
	unsafe_copy_dirent_name(dirent->d_name, name, namlen, efault_end);
	user_write_access_end();

	buf->prev_reclen = reclen;
	buf->current_dir = (void __user *)dirent + reclen;
	ctx->count -= reclen;
	return true;

efault_end:
	user_write_access_end();
efault:
	buf->error = -EFAULT;
	return false;
}

/**
 * sys_getdents64 - Read directory entries into a user buffer
 * @fd: File descriptor of an open directory
 * @dirent: Pointer to user-space buffer for directory entries
 * @count: Size of the user buffer in bytes
 *
 * long-desc: Reads multiple directory entries from a directory file descriptor
 *   into a user-space buffer. Each entry is formatted as a struct linux_dirent64
 *   containing the inode number (d_ino), offset to next entry (d_off), record
 *   length (d_reclen), file type (d_type), and null-terminated filename (d_name).
 *
 *   The @fd must be a file descriptor obtained by opening a directory with open()
 *   or openat(). The directory must have read permission for the calling process.
 *
 *   Entries are returned sequentially starting from the current file position.
 *   The file position is automatically updated after each successful call.
 *   Reading continues until the buffer cannot hold another complete entry or
 *   the end of the directory is reached.
 *
 *   The d_type field indicates the file type using values from dirent.h:
 *   DT_UNKNOWN (0), DT_FIFO (1), DT_CHR (2), DT_DIR (4), DT_BLK (6),
 *   DT_REG (8), DT_LNK (10), DT_SOCK (12), DT_WHT (14). Not all filesystems
 *   fill in d_type; if unknown, DT_UNKNOWN is returned and stat() should be
 *   used to determine the file type.
 *
 *   The d_off field contains an opaque value that can be used with lseek(2)
 *   to position the directory stream. It typically represents a cookie or
 *   offset for the next entry but its exact meaning is filesystem-dependent.
 *
 *   Unlike getdents(), this syscall uses 64-bit types for d_ino and d_off,
 *   avoiding overflow on filesystems with large inode numbers or offsets.
 *   The d_reclen field is always aligned to 8 bytes.
 *
 *   If the directory contents change during iteration (files created or
 *   deleted), the behavior is undefined - entries may be skipped or returned
 *   multiple times. Applications should handle this if directory contents
 *   may change.
 *
 *   The syscall may be interrupted by signals between directory entries.
 *   However, some filesystems (e.g., FUSE) use FILLDIR_FLAG_NOINTR to prevent
 *   signal interruption during the copying phase to userspace.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid file descriptor referring to a directory that
 *     was opened with read permission. The file descriptor table is accessed
 *     via fdget_pos() which also acquires the file position lock to prevent
 *     concurrent position modifications. If fd does not refer to a directory
 *     (i.e., the file has no iterate_shared operation), ENOTDIR is returned.
 *
 * param: dirent
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must point to a valid user-space buffer of at least @count
 *     bytes. The buffer receives struct linux_dirent64 entries packed
 *     sequentially. Each entry is variable-length due to the flexible d_name
 *     array and is padded to 8-byte alignment. The buffer must remain valid
 *     and writable throughout the syscall execution. A NULL or invalid pointer
 *     causes EFAULT to be returned.
 *
 * param: count
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Size of the @dirent buffer in bytes. Must be large enough to
 *     hold at least one struct linux_dirent64 entry (minimum ~24 bytes for a
 *     single-character filename). If the first entry cannot fit in the buffer,
 *     EINVAL is returned. A value of 0 will always return EINVAL since no
 *     entries can be returned. Typical buffer sizes are 4096-32768 bytes for
 *     efficient reading.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_RANGE
 *   success: >=0
 *   desc: On success, returns the number of bytes written to the @dirent buffer.
 *     Returns 0 when the end of directory is reached (no more entries). The
 *     return value indicates how much of the buffer was filled, not the number
 *     of entries. Applications must parse the entries by following d_reclen
 *     values until the return count is exhausted.
 *
 * error: EBADF, Invalid file descriptor
 *   desc: The @fd argument is not a valid open file descriptor. This is checked
 *     early via fd_empty() after fdget_pos(). Can also occur if the file
 *     descriptor table entry is empty or the fd number is out of range.
 *
 * error: ENOTDIR, Not a directory
 *   desc: The file descriptor @fd does not refer to a directory. This is
 *     detected when the file's f_op->iterate_shared operation is NULL, which
 *     is checked in iterate_dir(). Regular files, pipes, sockets, and other
 *     non-directory file types will trigger this error.
 *
 * error: ENOENT, Directory removed
 *   desc: The directory has been removed (unlinked) while still open. This is
 *     detected via IS_DEADDIR(inode) after acquiring the inode lock. The
 *     directory's contents are no longer accessible even though the file
 *     descriptor is still valid.
 *
 * error: EFAULT, Bad user address
 *   desc: The @dirent pointer is invalid or points to memory that cannot be
 *     written. This is detected during user_write_access_begin() or put_user()
 *     operations. Can occur at the start when setting up the initial entry or
 *     when writing subsequent entries. If detected after some entries were
 *     written, those bytes are lost.
 *
 * error: EINVAL, Buffer too small
 *   desc: The @count parameter specifies a buffer that is too small to hold
 *     even one directory entry. This occurs when the first entry's record
 *     length (aligned name length plus fixed fields) exceeds @count. The
 *     minimum practical buffer size depends on the longest filename in the
 *     directory. Also returned if count is 0.
 *
 * error: EIO, Corrupted directory entry
 *   desc: A directory entry has a corrupted name. This is detected by
 *     verify_dirent_name() which rejects names containing '/' characters
 *     (directory separators in pathnames) or names with invalid lengths
 *     (<=0 or >= PATH_MAX). This indicates filesystem corruption that should
 *     be investigated with fsck or similar tools.
 *
 * error: EACCES, Permission denied
 *   desc: The calling process does not have read permission on the directory.
 *     This is checked via security_file_permission() with MAY_READ mask.
 *     LSM modules (SELinux, AppArmor, etc.) may impose additional access
 *     controls that result in this error.
 *
 * error: EPERM, Operation not permitted
 *   desc: An LSM security module denied the operation. This can be returned by
 *     security_file_permission() or fsnotify_file_perm() hooks. More specific
 *     than EACCES and indicates policy-based denial rather than DAC permission
 *     denial.
 *
 * lock: file->f_pos_lock
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: The file position mutex is acquired via fdget_pos() to serialize
 *     directory reads on the same file descriptor from concurrent threads.
 *     This ensures that file->f_pos updates are atomic with respect to the
 *     directory iteration. The lock is held for the entire syscall duration
 *     and released in fdput_pos().
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: The directory inode's read-write semaphore is acquired for reading
 *     via down_read_killable() in iterate_dir(). This protects the directory
 *     contents from concurrent modifications (create, unlink, rename). The
 *     lock acquisition is killable, meaning it can be interrupted by fatal
 *     signals. The lock is downgraded or released before returning.
 *
 * signal: ANY
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: Signal pending during inode lock acquisition or between entries
 *   desc: The syscall can be interrupted by signals at two points. First,
 *     during down_read_killable() on the inode lock, fatal signals will cause
 *     immediate return. Second, between processing directory entries, a check
 *     for signal_pending(current) allows any pending signal to interrupt
 *     iteration. When interrupted, partial results (entries already copied)
 *     are returned. If interrupted before any entries are copied, the error
 *     from iterate_dir is returned. Some filesystems use FILLDIR_FLAG_NOINTR
 *     to prevent signal checks between entries.
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_FILE_POSITION
 *   target: File position (file->f_pos)
 *   desc: The file position is updated to reflect the current position in the
 *     directory after reading entries. The position is set from ctx->pos
 *     which is updated by the filesystem's iterate_shared callback as entries
 *     are emitted. The position value is opaque and filesystem-specific.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Directory inode access time
 *   desc: The directory's access time (atime) is updated via file_accessed()
 *     unless the file was opened with O_NOATIME or the filesystem is mounted
 *     with noatime/relatime options. This modification is performed after
 *     successful directory iteration. The update may be deferred based on
 *     relatime rules.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify access event
 *   desc: An FS_ACCESS fsnotify event is generated via fsnotify_access() after
 *     successful directory iteration. This allows inotify/fanotify watchers
 *     to be notified of directory reads. The event includes the directory's
 *     dentry and inode information.
 *   reversible: no
 *
 * constraint: File must be a directory
 *   desc: The file descriptor must reference a directory that implements the
 *     iterate_shared file operation. Regular files and other file types do not
 *     support directory iteration and will return ENOTDIR.
 *
 * constraint: Minimum buffer size
 *   desc: The buffer must be large enough to hold at least one directory entry.
 *     The minimum size is the aligned size of struct linux_dirent64 plus the
 *     shortest possible filename (1 byte) plus null terminator. In practice,
 *     buffers should be at least several hundred bytes to efficiently read
 *     typical directory entries.
 *
 * examples: getdents64(fd, buf, sizeof(buf));  // Read entries from directory fd
 *   getdents64(dirfd, dirents, 4096);  // Typical buffer size for efficient reading
 *
 * notes: This is the preferred syscall for reading directory entries on 64-bit
 *   systems. The older getdents() syscall may overflow on filesystems with
 *   large inode numbers (returning EOVERFLOW). Applications should typically
 *   use the POSIX readdir(3) wrapper from glibc which handles buffering and
 *   provides a simpler interface. However, direct use of getdents64() can be
 *   more efficient for applications that need to read many directory entries.
 *
 *   The d_off value written to the last entry's d_off field after the syscall
 *   returns represents the position for the next entry. This is stored via
 *   put_user() after all entries have been copied.
 *
 *   On some filesystems, the d_type field may be DT_UNKNOWN even when the
 *   type is known, as filling in d_type requires additional disk reads on
 *   some filesystem layouts. Applications must handle this by calling stat()
 *   when d_type is DT_UNKNOWN and the type is needed.
 *
 *   The syscall was introduced in Linux 2.4 to handle large filesystems.
 *   It is available on all modern Linux architectures. The x86_64 syscall
 *   number is 217, and on i386 it is 220.
 *
 * since-version: 2.4
 */
SYSCALL_DEFINE3(getdents64, unsigned int, fd,
		struct linux_dirent64 __user *, dirent, unsigned int, count)
{
	CLASS(fd_pos, f)(fd);
	struct getdents_callback64 buf = {
		.ctx.actor = filldir64,
		.ctx.count = count,
		.current_dir = dirent
	};
	int error;

	if (fd_empty(f))
		return -EBADF;

	error = iterate_dir(fd_file(f), &buf.ctx);
	if (error >= 0)
		error = buf.error;
	if (buf.prev_reclen) {
		struct linux_dirent64 __user * lastdirent;
		typeof(lastdirent->d_off) d_off = buf.ctx.pos;

		lastdirent = (void __user *) buf.current_dir - buf.prev_reclen;
		if (put_user(d_off, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.ctx.count;
	}
	return error;
}

#ifdef CONFIG_COMPAT
struct compat_old_linux_dirent {
	compat_ulong_t	d_ino;
	compat_ulong_t	d_offset;
	unsigned short	d_namlen;
	char		d_name[];
};

struct compat_readdir_callback {
	struct dir_context ctx;
	struct compat_old_linux_dirent __user *dirent;
	int result;
};

static bool compat_fillonedir(struct dir_context *ctx, const char *name,
			     int namlen, loff_t offset, u64 ino,
			     unsigned int d_type)
{
	struct compat_readdir_callback *buf =
		container_of(ctx, struct compat_readdir_callback, ctx);
	struct compat_old_linux_dirent __user *dirent;
	compat_ulong_t d_ino;

	if (buf->result)
		return false;
	buf->result = verify_dirent_name(name, namlen);
	if (buf->result)
		return false;
	d_ino = ino;
	if (sizeof(d_ino) < sizeof(ino) && d_ino != ino) {
		buf->result = -EOVERFLOW;
		return false;
	}
	buf->result++;
	dirent = buf->dirent;
	if (!user_write_access_begin(dirent,
			(unsigned long)(dirent->d_name + namlen + 1) -
				(unsigned long)dirent))
		goto efault;
	unsafe_put_user(d_ino, &dirent->d_ino, efault_end);
	unsafe_put_user(offset, &dirent->d_offset, efault_end);
	unsafe_put_user(namlen, &dirent->d_namlen, efault_end);
	unsafe_copy_dirent_name(dirent->d_name, name, namlen, efault_end);
	user_write_access_end();
	return true;
efault_end:
	user_write_access_end();
efault:
	buf->result = -EFAULT;
	return false;
}

COMPAT_SYSCALL_DEFINE3(old_readdir, unsigned int, fd,
		struct compat_old_linux_dirent __user *, dirent, unsigned int, count)
{
	int error;
	CLASS(fd_pos, f)(fd);
	struct compat_readdir_callback buf = {
		.ctx.actor = compat_fillonedir,
		.ctx.count = 1, /* Hint to fs: just one entry. */
		.dirent = dirent
	};

	if (fd_empty(f))
		return -EBADF;

	error = iterate_dir(fd_file(f), &buf.ctx);
	if (buf.result)
		error = buf.result;

	return error;
}

struct compat_linux_dirent {
	compat_ulong_t	d_ino;
	compat_ulong_t	d_off;
	unsigned short	d_reclen;
	char		d_name[];
};

struct compat_getdents_callback {
	struct dir_context ctx;
	struct compat_linux_dirent __user *current_dir;
	int prev_reclen;
	int error;
};

static bool compat_filldir(struct dir_context *ctx, const char *name, int namlen,
		loff_t offset, u64 ino, unsigned int d_type)
{
	struct compat_linux_dirent __user *dirent, *prev;
	struct compat_getdents_callback *buf =
		container_of(ctx, struct compat_getdents_callback, ctx);
	compat_ulong_t d_ino;
	int reclen = ALIGN(offsetof(struct compat_linux_dirent, d_name) +
		namlen + 2, sizeof(compat_long_t));
	int prev_reclen;
	unsigned int flags = d_type;

	BUILD_BUG_ON(FILLDIR_FLAG_NOINTR & S_DT_MASK);
	d_type &= S_DT_MASK;

	buf->error = verify_dirent_name(name, namlen);
	if (unlikely(buf->error))
		return false;
	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > ctx->count)
		return false;
	d_ino = ino;
	if (sizeof(d_ino) < sizeof(ino) && d_ino != ino) {
		buf->error = -EOVERFLOW;
		return false;
	}
	prev_reclen = buf->prev_reclen;
	if (!(flags & FILLDIR_FLAG_NOINTR) && prev_reclen && signal_pending(current))
		return false;
	dirent = buf->current_dir;
	prev = (void __user *) dirent - prev_reclen;
	if (!user_write_access_begin(prev, reclen + prev_reclen))
		goto efault;

	unsafe_put_user(offset, &prev->d_off, efault_end);
	unsafe_put_user(d_ino, &dirent->d_ino, efault_end);
	unsafe_put_user(reclen, &dirent->d_reclen, efault_end);
	unsafe_put_user(d_type, (char __user *) dirent + reclen - 1, efault_end);
	unsafe_copy_dirent_name(dirent->d_name, name, namlen, efault_end);
	user_write_access_end();

	buf->prev_reclen = reclen;
	buf->current_dir = (void __user *)dirent + reclen;
	ctx->count -= reclen;
	return true;
efault_end:
	user_write_access_end();
efault:
	buf->error = -EFAULT;
	return false;
}

COMPAT_SYSCALL_DEFINE3(getdents, unsigned int, fd,
		struct compat_linux_dirent __user *, dirent, unsigned int, count)
{
	CLASS(fd_pos, f)(fd);
	struct compat_getdents_callback buf = {
		.ctx.actor = compat_filldir,
		.ctx.count = count,
		.current_dir = dirent,
	};
	int error;

	if (fd_empty(f))
		return -EBADF;

	error = iterate_dir(fd_file(f), &buf.ctx);
	if (error >= 0)
		error = buf.error;
	if (buf.prev_reclen) {
		struct compat_linux_dirent __user * lastdirent;
		lastdirent = (void __user *)buf.current_dir - buf.prev_reclen;

		if (put_user(buf.ctx.pos, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.ctx.count;
	}
	return error;
}
#endif
