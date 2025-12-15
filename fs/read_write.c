// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/read_write.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/sched/xacct.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/splice.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include "internal.h"

#include <linux/uaccess.h>
#include <asm/unistd.h>

const struct file_operations generic_ro_fops = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.mmap_prepare	= generic_file_readonly_mmap_prepare,
	.splice_read	= filemap_splice_read,
};

EXPORT_SYMBOL(generic_ro_fops);

static inline bool unsigned_offsets(struct file *file)
{
	return file->f_op->fop_flags & FOP_UNSIGNED_OFFSET;
}

/**
 * vfs_setpos_cookie - update the file offset for lseek and reset cookie
 * @file:	file structure in question
 * @offset:	file offset to seek to
 * @maxsize:	maximum file size
 * @cookie:	cookie to reset
 *
 * Update the file offset to the value specified by @offset if the given
 * offset is valid and it is not equal to the current file offset and
 * reset the specified cookie to indicate that a seek happened.
 *
 * Return the specified offset on success and -EINVAL on invalid offset.
 */
static loff_t vfs_setpos_cookie(struct file *file, loff_t offset,
				loff_t maxsize, u64 *cookie)
{
	if (offset < 0 && !unsigned_offsets(file))
		return -EINVAL;
	if (offset > maxsize)
		return -EINVAL;

	if (offset != file->f_pos) {
		file->f_pos = offset;
		if (cookie)
			*cookie = 0;
	}
	return offset;
}

/**
 * vfs_setpos - update the file offset for lseek
 * @file:	file structure in question
 * @offset:	file offset to seek to
 * @maxsize:	maximum file size
 *
 * This is a low-level filesystem helper for updating the file offset to
 * the value specified by @offset if the given offset is valid and it is
 * not equal to the current file offset.
 *
 * Return the specified offset on success and -EINVAL on invalid offset.
 */
loff_t vfs_setpos(struct file *file, loff_t offset, loff_t maxsize)
{
	return vfs_setpos_cookie(file, offset, maxsize, NULL);
}
EXPORT_SYMBOL(vfs_setpos);

/**
 * must_set_pos - check whether f_pos has to be updated
 * @file: file to seek on
 * @offset: offset to use
 * @whence: type of seek operation
 * @eof: end of file
 *
 * Check whether f_pos needs to be updated and update @offset according
 * to @whence.
 *
 * Return: 0 if f_pos doesn't need to be updated, 1 if f_pos has to be
 * updated, and negative error code on failure.
 */
static int must_set_pos(struct file *file, loff_t *offset, int whence, loff_t eof)
{
	switch (whence) {
	case SEEK_END:
		*offset += eof;
		break;
	case SEEK_CUR:
		/*
		 * Here we special-case the lseek(fd, 0, SEEK_CUR)
		 * position-querying operation.  Avoid rewriting the "same"
		 * f_pos value back to the file because a concurrent read(),
		 * write() or lseek() might have altered it
		 */
		if (*offset == 0) {
			*offset = file->f_pos;
			return 0;
		}
		break;
	case SEEK_DATA:
		/*
		 * In the generic case the entire file is data, so as long as
		 * offset isn't at the end of the file then the offset is data.
		 */
		if ((unsigned long long)*offset >= eof)
			return -ENXIO;
		break;
	case SEEK_HOLE:
		/*
		 * There is a virtual hole at the end of the file, so as long as
		 * offset isn't i_size or larger, return i_size.
		 */
		if ((unsigned long long)*offset >= eof)
			return -ENXIO;
		*offset = eof;
		break;
	}

	return 1;
}

/**
 * generic_file_llseek_size - generic llseek implementation for regular files
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 * @maxsize:	max size of this file in file system
 * @eof:	offset used for SEEK_END position
 *
 * This is a variant of generic_file_llseek that allows passing in a custom
 * maximum file size and a custom EOF position, for e.g. hashed directories
 *
 * Synchronization:
 * SEEK_SET and SEEK_END are unsynchronized (but atomic on 64bit platforms)
 * SEEK_CUR is synchronized against other SEEK_CURs, but not read/writes.
 * read/writes behave like SEEK_SET against seeks.
 */
loff_t
generic_file_llseek_size(struct file *file, loff_t offset, int whence,
		loff_t maxsize, loff_t eof)
{
	int ret;

	ret = must_set_pos(file, &offset, whence, eof);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return offset;

	if (whence == SEEK_CUR) {
		/*
		 * If the file requires locking via f_pos_lock we know
		 * that mutual exclusion for SEEK_CUR on the same file
		 * is guaranteed. If the file isn't locked, we take
		 * f_lock to protect against f_pos races with other
		 * SEEK_CURs.
		 */
		if (file_seek_cur_needs_f_lock(file)) {
			guard(spinlock)(&file->f_lock);
			return vfs_setpos(file, file->f_pos + offset, maxsize);
		}
		return vfs_setpos(file, file->f_pos + offset, maxsize);
	}

	return vfs_setpos(file, offset, maxsize);
}
EXPORT_SYMBOL(generic_file_llseek_size);

/**
 * generic_llseek_cookie - versioned llseek implementation
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 * @cookie:	cookie to update
 *
 * See generic_file_llseek for a general description and locking assumptions.
 *
 * In contrast to generic_file_llseek, this function also resets a
 * specified cookie to indicate a seek took place.
 */
loff_t generic_llseek_cookie(struct file *file, loff_t offset, int whence,
			     u64 *cookie)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxsize = inode->i_sb->s_maxbytes;
	loff_t eof = i_size_read(inode);
	int ret;

	if (WARN_ON_ONCE(!cookie))
		return -EINVAL;

	/*
	 * Require that this is only used for directories that guarantee
	 * synchronization between readdir and seek so that an update to
	 * @cookie is correctly synchronized with concurrent readdir.
	 */
	if (WARN_ON_ONCE(!(file->f_mode & FMODE_ATOMIC_POS)))
		return -EINVAL;

	ret = must_set_pos(file, &offset, whence, eof);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return offset;

	/* No need to hold f_lock because we know that f_pos_lock is held. */
	if (whence == SEEK_CUR)
		return vfs_setpos_cookie(file, file->f_pos + offset, maxsize, cookie);

	return vfs_setpos_cookie(file, offset, maxsize, cookie);
}
EXPORT_SYMBOL(generic_llseek_cookie);

/**
 * generic_file_llseek - generic llseek implementation for regular files
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 *
 * This is a generic implementation of ->llseek useable for all normal local
 * filesystems.  It just updates the file offset to the value specified by
 * @offset and @whence.
 */
loff_t generic_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;

	return generic_file_llseek_size(file, offset, whence,
					inode->i_sb->s_maxbytes,
					i_size_read(inode));
}
EXPORT_SYMBOL(generic_file_llseek);

/**
 * fixed_size_llseek - llseek implementation for fixed-sized devices
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 * @size:	size of the file
 *
 */
loff_t fixed_size_llseek(struct file *file, loff_t offset, int whence, loff_t size)
{
	switch (whence) {
	case SEEK_SET: case SEEK_CUR: case SEEK_END:
		return generic_file_llseek_size(file, offset, whence,
						size, size);
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL(fixed_size_llseek);

/**
 * no_seek_end_llseek - llseek implementation for fixed-sized devices
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 *
 */
loff_t no_seek_end_llseek(struct file *file, loff_t offset, int whence)
{
	switch (whence) {
	case SEEK_SET: case SEEK_CUR:
		return generic_file_llseek_size(file, offset, whence,
						OFFSET_MAX, 0);
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL(no_seek_end_llseek);

/**
 * no_seek_end_llseek_size - llseek implementation for fixed-sized devices
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 * @size:	maximal offset allowed
 *
 */
loff_t no_seek_end_llseek_size(struct file *file, loff_t offset, int whence, loff_t size)
{
	switch (whence) {
	case SEEK_SET: case SEEK_CUR:
		return generic_file_llseek_size(file, offset, whence,
						size, 0);
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL(no_seek_end_llseek_size);

/**
 * noop_llseek - No Operation Performed llseek implementation
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 *
 * This is an implementation of ->llseek useable for the rare special case when
 * userspace expects the seek to succeed but the (device) file is actually not
 * able to perform the seek. In this case you use noop_llseek() instead of
 * falling back to the default implementation of ->llseek.
 */
loff_t noop_llseek(struct file *file, loff_t offset, int whence)
{
	return file->f_pos;
}
EXPORT_SYMBOL(noop_llseek);

loff_t default_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	loff_t retval;

	retval = inode_lock_killable(inode);
	if (retval)
		return retval;
	switch (whence) {
		case SEEK_END:
			offset += i_size_read(inode);
			break;
		case SEEK_CUR:
			if (offset == 0) {
				retval = file->f_pos;
				goto out;
			}
			offset += file->f_pos;
			break;
		case SEEK_DATA:
			/*
			 * In the generic case the entire file is data, so as
			 * long as offset isn't at the end of the file then the
			 * offset is data.
			 */
			if (offset >= inode->i_size) {
				retval = -ENXIO;
				goto out;
			}
			break;
		case SEEK_HOLE:
			/*
			 * There is a virtual hole at the end of the file, so
			 * as long as offset isn't i_size or larger, return
			 * i_size.
			 */
			if (offset >= inode->i_size) {
				retval = -ENXIO;
				goto out;
			}
			offset = inode->i_size;
			break;
	}
	retval = -EINVAL;
	if (offset >= 0 || unsigned_offsets(file)) {
		if (offset != file->f_pos)
			file->f_pos = offset;
		retval = offset;
	}
out:
	inode_unlock(inode);
	return retval;
}
EXPORT_SYMBOL(default_llseek);

loff_t vfs_llseek(struct file *file, loff_t offset, int whence)
{
	if (!(file->f_mode & FMODE_LSEEK))
		return -ESPIPE;
	return file->f_op->llseek(file, offset, whence);
}
EXPORT_SYMBOL(vfs_llseek);

static off_t ksys_lseek(unsigned int fd, off_t offset, unsigned int whence)
{
	off_t retval;
	CLASS(fd_pos, f)(fd);
	if (fd_empty(f))
		return -EBADF;

	retval = -EINVAL;
	if (whence <= SEEK_MAX) {
		loff_t res = vfs_llseek(fd_file(f), offset, whence);
		retval = res;
		if (res != (loff_t)retval)
			retval = -EOVERFLOW;	/* LFS: should only happen on 32 bit platforms */
	}
	return retval;
}

SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, whence)
{
	return ksys_lseek(fd, offset, whence);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE3(lseek, unsigned int, fd, compat_off_t, offset, unsigned int, whence)
{
	return ksys_lseek(fd, offset, whence);
}
#endif

#if !defined(CONFIG_64BIT) || defined(CONFIG_COMPAT) || \
	defined(__ARCH_WANT_SYS_LLSEEK)
SYSCALL_DEFINE5(llseek, unsigned int, fd, unsigned long, offset_high,
		unsigned long, offset_low, loff_t __user *, result,
		unsigned int, whence)
{
	int retval;
	CLASS(fd_pos, f)(fd);
	loff_t offset;

	if (fd_empty(f))
		return -EBADF;

	if (whence > SEEK_MAX)
		return -EINVAL;

	offset = vfs_llseek(fd_file(f), ((loff_t) offset_high << 32) | offset_low,
			whence);

	retval = (int)offset;
	if (offset >= 0) {
		retval = -EFAULT;
		if (!copy_to_user(result, &offset, sizeof(offset)))
			retval = 0;
	}
	return retval;
}
#endif

int rw_verify_area(int read_write, struct file *file, const loff_t *ppos, size_t count)
{
	int mask = read_write == READ ? MAY_READ : MAY_WRITE;
	int ret;

	if (unlikely((ssize_t) count < 0))
		return -EINVAL;

	if (ppos) {
		loff_t pos = *ppos;

		if (unlikely(pos < 0)) {
			if (!unsigned_offsets(file))
				return -EINVAL;
			if (count >= -pos) /* both values are in 0..LLONG_MAX */
				return -EOVERFLOW;
		} else if (unlikely((loff_t) (pos + count) < 0)) {
			if (!unsigned_offsets(file))
				return -EINVAL;
		}
	}

	ret = security_file_permission(file, mask);
	if (ret)
		return ret;

	return fsnotify_file_area_perm(file, mask, ppos, count);
}
EXPORT_SYMBOL(rw_verify_area);

static ssize_t new_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = (ppos ? *ppos : 0);
	iov_iter_ubuf(&iter, ITER_DEST, buf, len);

	ret = filp->f_op->read_iter(&kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ppos)
		*ppos = kiocb.ki_pos;
	return ret;
}

static int warn_unsupported(struct file *file, const char *op)
{
	pr_warn_ratelimited(
		"kernel %s not supported for file %pD4 (pid: %d comm: %.20s)\n",
		op, file, current->pid, current->comm);
	return -EINVAL;
}

ssize_t __kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
	struct kvec iov = {
		.iov_base	= buf,
		.iov_len	= min_t(size_t, count, MAX_RW_COUNT),
	};
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	if (WARN_ON_ONCE(!(file->f_mode & FMODE_READ)))
		return -EINVAL;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	/*
	 * Also fail if ->read_iter and ->read are both wired up as that
	 * implies very convoluted semantics.
	 */
	if (unlikely(!file->f_op->read_iter || file->f_op->read))
		return warn_unsupported(file, "read");

	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = pos ? *pos : 0;
	iov_iter_kvec(&iter, ITER_DEST, &iov, 1, iov.iov_len);
	ret = file->f_op->read_iter(&kiocb, &iter);
	if (ret > 0) {
		if (pos)
			*pos = kiocb.ki_pos;
		fsnotify_access(file);
		add_rchar(current, ret);
	}
	inc_syscr(current);
	return ret;
}

ssize_t kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	ret = rw_verify_area(READ, file, pos, count);
	if (ret)
		return ret;
	return __kernel_read(file, buf, count, pos);
}
EXPORT_SYMBOL(kernel_read);

ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;

	ret = rw_verify_area(READ, file, pos, count);
	if (ret)
		return ret;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;

	if (file->f_op->read)
		ret = file->f_op->read(file, buf, count, pos);
	else if (file->f_op->read_iter)
		ret = new_sync_read(file, buf, count, pos);
	else
		ret = -EINVAL;
	if (ret > 0) {
		fsnotify_access(file);
		add_rchar(current, ret);
	}
	inc_syscr(current);
	return ret;
}

static ssize_t new_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = (ppos ? *ppos : 0);
	iov_iter_ubuf(&iter, ITER_SOURCE, (void __user *)buf, len);

	ret = filp->f_op->write_iter(&kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ret > 0 && ppos)
		*ppos = kiocb.ki_pos;
	return ret;
}

/* caller is responsible for file_start_write/file_end_write */
ssize_t __kernel_write_iter(struct file *file, struct iov_iter *from, loff_t *pos)
{
	struct kiocb kiocb;
	ssize_t ret;

	if (WARN_ON_ONCE(!(file->f_mode & FMODE_WRITE)))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	/*
	 * Also fail if ->write_iter and ->write are both wired up as that
	 * implies very convoluted semantics.
	 */
	if (unlikely(!file->f_op->write_iter || file->f_op->write))
		return warn_unsupported(file, "write");

	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = pos ? *pos : 0;
	ret = file->f_op->write_iter(&kiocb, from);
	if (ret > 0) {
		if (pos)
			*pos = kiocb.ki_pos;
		fsnotify_modify(file);
		add_wchar(current, ret);
	}
	inc_syscw(current);
	return ret;
}

/* caller is responsible for file_start_write/file_end_write */
ssize_t __kernel_write(struct file *file, const void *buf, size_t count, loff_t *pos)
{
	struct kvec iov = {
		.iov_base	= (void *)buf,
		.iov_len	= min_t(size_t, count, MAX_RW_COUNT),
	};
	struct iov_iter iter;
	iov_iter_kvec(&iter, ITER_SOURCE, &iov, 1, iov.iov_len);
	return __kernel_write_iter(file, &iter, pos);
}
/*
 * This "EXPORT_SYMBOL_GPL()" is more of a "EXPORT_SYMBOL_DONTUSE()",
 * but autofs is one of the few internal kernel users that actually
 * wants this _and_ can be built as a module. So we need to export
 * this symbol for autofs, even though it really isn't appropriate
 * for any other kernel modules.
 */
EXPORT_SYMBOL_GPL(__kernel_write);

ssize_t kernel_write(struct file *file, const void *buf, size_t count,
			    loff_t *pos)
{
	ssize_t ret;

	ret = rw_verify_area(WRITE, file, pos, count);
	if (ret)
		return ret;

	file_start_write(file);
	ret =  __kernel_write(file, buf, count, pos);
	file_end_write(file);
	return ret;
}
EXPORT_SYMBOL(kernel_write);

ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;

	ret = rw_verify_area(WRITE, file, pos, count);
	if (ret)
		return ret;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;
	file_start_write(file);
	if (file->f_op->write)
		ret = file->f_op->write(file, buf, count, pos);
	else if (file->f_op->write_iter)
		ret = new_sync_write(file, buf, count, pos);
	else
		ret = -EINVAL;
	if (ret > 0) {
		fsnotify_modify(file);
		add_wchar(current, ret);
	}
	inc_syscw(current);
	file_end_write(file);
	return ret;
}

/* file_ppos returns &file->f_pos or NULL if file is stream */
static inline loff_t *file_ppos(struct file *file)
{
	return file->f_mode & FMODE_STREAM ? NULL : &file->f_pos;
}

ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
	CLASS(fd_pos, f)(fd);
	ssize_t ret = -EBADF;

	if (!fd_empty(f)) {
		loff_t pos, *ppos = file_ppos(fd_file(f));
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_read(fd_file(f), buf, count, ppos);
		if (ret >= 0 && ppos)
			fd_file(f)->f_pos = pos;
	}
	return ret;
}

/**
 * sys_read - Read data from a file descriptor
 * @fd: File descriptor to read from
 * @buf: User-space buffer to read data into
 * @count: Maximum number of bytes to read
 *
 * long-desc: Attempts to read up to count bytes from file descriptor fd into
 *   the buffer starting at buf. For seekable files (regular files, block
 *   devices), the read begins at the current file offset, and the file offset
 *   is advanced by the number of bytes read. For non-seekable files (pipes,
 *   FIFOs, sockets, character devices), the file offset is not used.
 *
 *   If count is zero and fd refers to a regular file, read() may detect errors
 *   as described below. In the absence of errors, or if read() does not check
 *   for errors, a read() with a count of 0 returns zero and has no other effects.
 *
 *   On success, the number of bytes read is returned (zero indicates end of
 *   file for regular files). It is not an error if this number is smaller than
 *   the number of bytes requested; this may happen because fewer bytes are
 *   actually available right now (maybe because we were close to end-of-file,
 *   or because we are reading from a pipe, socket, or terminal), or because
 *   read() was interrupted by a signal.
 *
 *   On Linux, read() transfers at most MAX_RW_COUNT (0x7ffff000, approximately
 *   2GB) bytes per call, regardless of whether the filesystem would allow more.
 *   This is to avoid issues with signed arithmetic overflow on 32-bit systems.
 *
 *   POSIX allows reads that are interrupted after reading some data to either
 *   return -1 (with errno set to EINTR) or return the number of bytes already
 *   read. Linux follows the latter behavior: if data has been read before a
 *   signal arrives, the call returns the bytes read rather than failing.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, INT_MAX
 *   constraint: Must be a valid, open file descriptor with read permission.
 *     The file must have been opened with O_RDONLY or O_RDWR. Special values
 *     like AT_FDCWD are not valid. File descriptors for directories return
 *     EISDIR. Standard file descriptors 0 (stdin), 1 (stdout), 2 (stderr) are
 *     valid if open and readable.
 *
 * param: buf
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must point to a valid, writable user-space memory region of at
 *     least count bytes. The buffer is validated via access_ok() before any
 *     read operation. NULL is invalid and will return EFAULT. The buffer may
 *     be partially written if an error occurs mid-read. For O_DIRECT reads,
 *     the buffer may need to be aligned to the filesystem's block size (varies
 *     by filesystem, check via statx() with STATX_DIOALIGN).
 *
 * param: count
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, SIZE_MAX
 *   constraint: Maximum number of bytes to read. Clamped internally to
 *     MAX_RW_COUNT (INT_MAX & PAGE_MASK, approximately 0x7ffff000 bytes) to
 *     prevent signed overflow issues. A count of 0 returns immediately with 0
 *     without accessing the file (but may still detect errors). Large values
 *     are not errors but will be clamped. Cast to ssize_t must not be negative.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_RANGE
 *   success: >= 0
 *   desc: On success, returns the number of bytes read (non-negative). Zero
 *     indicates end-of-file (EOF) for regular files, or no data available
 *     from a device that does not block. The return value may be less than
 *     count if fewer bytes were available (short read). Partial reads are
 *     not errors. On error, returns a negative error code.
 *
 * error: EBADF, Bad file descriptor
 *   desc: fd is not a valid file descriptor, or fd was not opened for reading.
 *     This includes file descriptors opened with O_WRONLY, O_PATH, or file
 *     descriptors that have been closed. Also returned if the file structure
 *     does not have FMODE_READ set.
 *
 * error: EFAULT, Bad address
 *   desc: buf points outside the accessible address space. The buffer address
 *     failed access_ok() validation. Can also occur if a fault happens during
 *     copy_to_user() when transferring data to user space after the read
 *     completes in kernel space.
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned in several cases: (1) The file descriptor refers to an
 *     object that is not suitable for reading (no read or read_iter method).
 *     (2) The file was opened with O_DIRECT and the buffer alignment, offset,
 *     or count does not meet the filesystem's alignment requirements. (3) For
 *     timerfd file descriptors, the buffer is smaller than 8 bytes. (4) The
 *     count argument, when cast to ssize_t, is negative.
 *
 * error: EISDIR, Is a directory
 *   desc: fd refers to a directory. Directories cannot be read using read();
 *     use getdents64() instead. This error is returned by the generic_read_dir()
 *     handler installed for directory file operations.
 *
 * error: EAGAIN, Resource temporarily unavailable
 *   desc: fd refers to a file (pipe, socket, device) that is marked non-blocking
 *     (O_NONBLOCK) and the read would block. Also returned with IOCB_NOWAIT
 *     when data is not immediately available. Equivalent to EWOULDBLOCK.
 *     The application should retry the read later or use select/poll/epoll.
 *
 * error: EINTR, Interrupted system call
 *   desc: The call was interrupted by a signal before any data was read. This
 *     only occurs if no data has been transferred; if some data was read before
 *     the signal, the call returns the number of bytes read. The caller should
 *     typically restart the read.
 *
 * error: EIO, Input/output error
 *   desc: A low-level I/O error occurred. For regular files, this typically
 *     indicates a hardware error on the storage device, a filesystem error,
 *     or a network filesystem timeout. For terminals, this may indicate the
 *     controlling terminal has been closed for a background process.
 *
 * error: EOVERFLOW, Value too large for defined data type
 *   desc: The file position plus count would exceed LLONG_MAX. Also returned
 *     when reading from certain files (e.g., some /proc files) where the file
 *     position would overflow. For files without FOP_UNSIGNED_OFFSET flag,
 *     negative file positions are not allowed.
 *
 * error: ENOBUFS, No buffer space available
 *   desc: Returned when reading from pipe-based watch queues (CONFIG_WATCH_QUEUE)
 *     when the buffer is too small to hold a complete notification, or when
 *     reading packets from pipes with PIPE_BUF_FLAG_WHOLE set.
 *
 * error: ERESTARTSYS, Restart system call (internal)
 *   desc: Internal error code indicating the syscall should be restarted. This
 *     is typically translated to EINTR if SA_RESTART is not set on the signal
 *     handler, or the syscall is transparently restarted if SA_RESTART is set.
 *     User space should not see this error code directly.
 *
 * error: EACCES, Permission denied
 *   desc: The security subsystem (LSM such as SELinux or AppArmor) denied
 *     the read operation via security_file_permission(). This can occur even
 *     if the file was successfully opened, as LSM policies may enforce per-
 *     operation checks.
 *
 * error: EPERM, Operation not permitted
 *   desc: Returned by fanotify permission events (CONFIG_FANOTIFY_ACCESS_PERMISSIONS)
 *     when a user-space fanotify listener denies the read operation via
 *     fsnotify_file_area_perm().
 *
 * lock: file->f_pos_lock
 *   type: KAPI_LOCK_MUTEX
 *   acquired: conditional
 *   released: true
 *   desc: For regular files that require atomic position updates (FMODE_ATOMIC_POS),
 *     the f_pos_lock mutex is acquired by fdget_pos() at syscall entry and released
 *     by fdput_pos() at syscall exit. This serializes concurrent reads that share
 *     the same file description. Not acquired for files opened with FMODE_STREAM
 *     (pipes, sockets) or when the file is not shared.
 *
 * lock: Filesystem-specific locks
 *   type: KAPI_LOCK_CUSTOM
 *   acquired: conditional
 *   released: true
 *   desc: The filesystem's read_iter or read method may acquire additional locks.
 *     For regular files, this typically includes the inode's i_rwsem for certain
 *     operations. For pipes, the pipe->mutex is acquired. For sockets, socket
 *     lock is acquired. These are internal to the file operation and released
 *     before return.
 *
 * lock: RCU read-side
 *   type: KAPI_LOCK_RCU
 *   acquired: conditional
 *   released: true
 *   desc: Used during file descriptor lookup via fdget(). RCU read lock protects
 *     access to the file descriptor table. Released by fdput() at syscall exit.
 *
 * signal: Any signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: When blocked waiting for data on interruptible operations
 *   desc: The syscall may be interrupted by signals while waiting for data to
 *     become available (pipes, sockets, terminals) or waiting for locks. If
 *     interrupted before any data is read, returns -EINTR or -ERESTARTSYS.
 *     If data has already been read, returns the number of bytes read.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_FILE_POSITION
 *   target: file->f_pos
 *   condition: For seekable files when read succeeds (returns > 0)
 *   desc: The file offset (f_pos) is advanced by the number of bytes read.
 *     For stream files (FMODE_STREAM such as pipes and sockets), the offset
 *     is not used or modified. The offset update is protected by f_pos_lock
 *     when the file is shared between threads/processes.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: inode access time (atime)
 *   condition: When read succeeds and O_NOATIME is not set
 *   desc: Updates the file's access time (atime) via touch_atime(). The update
 *     may be suppressed by mount options (noatime, relatime), the O_NOATIME
 *     flag, or if the filesystem does not support atime. Relatime only updates
 *     atime if it is older than mtime or ctime, or more than a day old.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task I/O accounting
 *   condition: Always
 *   desc: Updates the current task's I/O accounting statistics. The rchar field
 *     (read characters) is incremented by bytes read via add_rchar(). The syscr
 *     field (syscall read count) is incremented via inc_syscr(). These statistics
 *     are visible in /proc/[pid]/io. Updated regardless of success or failure.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify events
 *   condition: When read returns > 0
 *   desc: Generates an FS_ACCESS fsnotify event via fsnotify_access() allowing
 *     inotify, fanotify, and dnotify watchers to be notified of the read. This
 *     occurs after data transfer completes successfully.
 *   reversible: no
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass discretionary access control on read permission
 *   without: Standard DAC checks are enforced
 *   condition: Checked via security_file_permission() during rw_verify_area()
 *
 * capability: CAP_DAC_READ_SEARCH
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass read permission checks on regular files
 *   without: Must have read permission on file
 *   condition: Checked by LSM hooks during the read operation
 *
 * constraint: MAX_RW_COUNT
 *   desc: The count parameter is silently clamped to MAX_RW_COUNT (INT_MAX &
 *     PAGE_MASK, approximately 2GB minus one page) to prevent integer overflow
 *     in internal calculations. This is transparent to the caller; the syscall
 *     succeeds but reads at most MAX_RW_COUNT bytes.
 *   expr: actual_count = min(count, MAX_RW_COUNT)
 *
 * constraint: File must be open for reading
 *   desc: The file descriptor must have been opened with O_RDONLY or O_RDWR.
 *     Files opened with O_WRONLY or O_PATH cannot be read and return EBADF.
 *     The file must have both FMODE_READ and FMODE_CAN_READ flags set.
 *   expr: (file->f_mode & FMODE_READ) && (file->f_mode & FMODE_CAN_READ)
 *
 * examples: n = read(fd, buf, sizeof(buf));  // Basic read
 *   n = read(STDIN_FILENO, buf, 1024);  // Read from stdin
 *   while ((n = read(fd, buf, 4096)) > 0) { process(buf, n); }  // Read loop
 *   if (read(fd, buf, count) == 0) { handle_eof(); }  // Check for EOF
 *
 * notes: The behavior of read() varies significantly depending on the type of
 *   file descriptor:
 *
 *   - Regular files: Reads from current position, advances position, returns 0
 *     at EOF. Short reads are rare but possible near EOF or on signal.
 *
 *   - Pipes and FIFOs: Blocking by default. Returns available data (up to count)
 *     or blocks until data is available. Returns 0 when all writers have closed.
 *     O_NONBLOCK returns EAGAIN when empty instead of blocking.
 *
 *   - Sockets: Similar to pipes. Specific behavior depends on socket type and
 *     protocol. MSG_* flags can be specified via recv() for more control.
 *
 *   - Terminals: Line-buffered in canonical mode; read returns when newline is
 *     entered or buffer is full. Raw mode returns immediately when data available.
 *     Special handling for signals (SIGINT on Ctrl+C, etc.).
 *
 *   - Device special files: Behavior is device-specific. Some devices support
 *     seeking, others do not. Read size may be constrained by device.
 *
 *   Race condition: Concurrent reads from the same file description (not just
 *   file descriptor) can race on the file position. Linux 3.14+ provides atomic
 *   position updates for regular files via f_pos_lock, but applications should
 *   use pread() for concurrent positioned reads.
 *
 *   O_DIRECT reads bypass the page cache and typically require aligned buffers
 *   and positions. Alignment requirements are filesystem-specific; use statx()
 *   with STATX_DIOALIGN (Linux 6.1+) to query. Unaligned O_DIRECT reads fail
 *   with EINVAL on most filesystems.
 *
 *   For splice(2)-like zero-copy reads, consider using splice(), sendfile(),
 *   or copy_file_range() instead of read() + write().
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	return ksys_read(fd, buf, count);
}

ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
	CLASS(fd_pos, f)(fd);
	ssize_t ret = -EBADF;

	if (!fd_empty(f)) {
		loff_t pos, *ppos = file_ppos(fd_file(f));
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_write(fd_file(f), buf, count, ppos);
		if (ret >= 0 && ppos)
			fd_file(f)->f_pos = pos;
	}

	return ret;
}

/**
 * sys_write - Write data to a file descriptor
 * @fd: File descriptor to write to
 * @buf: User-space buffer containing data to write
 * @count: Maximum number of bytes to write
 *
 * long-desc: Attempts to write up to count bytes from the buffer starting at
 *   buf to the file referred to by the file descriptor fd. For seekable files
 *   (regular files, block devices), the write begins at the current file offset,
 *   and the file offset is advanced by the number of bytes written. If the file
 *   was opened with O_APPEND, the file offset is first set to the end of the
 *   file before writing. For non-seekable files (pipes, FIFOs, sockets, character
 *   devices), the file offset is not used and writing occurs at the current
 *   position as defined by the device.
 *
 *   The number of bytes written may be less than count if, for example, there is
 *   insufficient space on the underlying physical medium, or the RLIMIT_FSIZE
 *   resource limit is encountered, or the call was interrupted by a signal
 *   handler after having written less than count bytes. In the event of a
 *   successful partial write, the caller should make another write() call to
 *   transfer the remaining bytes. This behavior is called a "short write."
 *
 *   On Linux, write() transfers at most MAX_RW_COUNT (0x7ffff000, approximately
 *   2GB minus one page) bytes per call, regardless of whether the file or
 *   filesystem would allow more. This prevents signed arithmetic overflow.
 *
 *   For regular files, a successful write() does not guarantee that data has been
 *   committed to disk. Use fsync(2) or fdatasync(2) if durability is required.
 *   For O_SYNC or O_DSYNC files, the kernel automatically syncs data on write.
 *
 *   POSIX permits writes that are interrupted after partial writes to either
 *   return -1 with errno=EINTR, or to return the count of bytes already written.
 *   Linux implements the latter behavior: if some data has been written before
 *   a signal arrives, write() returns the number of bytes written rather than
 *   failing with EINTR.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, INT_MAX
 *   constraint: Must be a valid, open file descriptor with write permission.
 *     The file must have been opened with O_WRONLY or O_RDWR. File descriptors
 *     opened with O_RDONLY, O_PATH, or that have been closed return EBADF.
 *     Standard file descriptors 0 (stdin), 1 (stdout), 2 (stderr) are valid if
 *     open and writable. AT_FDCWD and other special values are not valid.
 *
 * param: buf
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must point to a valid, readable user-space memory region of at
 *     least count bytes. The buffer is validated via access_ok() before any
 *     write operation. NULL is invalid and returns EFAULT. For O_DIRECT writes,
 *     the buffer may need to be aligned to the filesystem's block size (varies
 *     by filesystem; query with statx() using STATX_DIOALIGN on Linux 6.1+).
 *
 * param: count
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, SIZE_MAX
 *   constraint: Maximum number of bytes to write. Clamped internally to
 *     MAX_RW_COUNT (INT_MAX & PAGE_MASK, approximately 0x7ffff000 bytes) to
 *     prevent signed overflow. A count of 0 returns 0 immediately without any
 *     file operations. Cast to ssize_t must not be negative.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_RANGE
 *   success: >= 0
 *   desc: On success, returns the number of bytes written (non-negative). Zero
 *     indicates that nothing was written (count was 0, or no space available
 *     for non-blocking writes). The return value may be less than count due to
 *     resource limits, signal interruption, or device constraints (short write).
 *     On error, returns a negative error code.
 *
 * error: EBADF, Bad file descriptor
 *   desc: fd is not a valid file descriptor, or fd was not opened for writing.
 *     This includes file descriptors opened with O_RDONLY, O_PATH, or file
 *     descriptors that have been closed. Also returned if the file structure
 *     does not have FMODE_WRITE or FMODE_CAN_WRITE set.
 *
 * error: EFAULT, Bad address
 *   desc: buf points outside the accessible address space. The buffer address
 *     failed access_ok() validation. Can also occur if a fault happens during
 *     copy_from_user() when reading data from user space.
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned in several cases: (1) The file descriptor refers to an
 *     object that is not suitable for writing (no write or write_iter method).
 *     (2) The file was opened with O_DIRECT and the buffer alignment, offset,
 *     or count does not meet the filesystem's alignment requirements. (3) The
 *     count argument, when cast to ssize_t, is negative. (4) For IOCB_NOWAIT
 *     operations on non-O_DIRECT files that don't support WASYNC.
 *
 * error: EAGAIN, Resource temporarily unavailable
 *   desc: fd refers to a file (pipe, socket, device) that is marked non-blocking
 *     (O_NONBLOCK) and the write would block because the buffer is full. Also
 *     returned with IOCB_NOWAIT when data cannot be written immediately.
 *     Equivalent to EWOULDBLOCK. The application should retry later or use
 *     select/poll/epoll to wait for writability.
 *
 * error: EINTR, Interrupted system call
 *   desc: The call was interrupted by a signal before any data was written. This
 *     only occurs if no data has been transferred; if some data was written
 *     before the signal, the call returns the number of bytes written. The
 *     caller should typically restart the write.
 *
 * error: EPIPE, Broken pipe
 *   desc: fd refers to a pipe or socket whose reading end has been closed.
 *     When this condition occurs, the calling process also receives a SIGPIPE
 *     signal unless MSG_NOSIGNAL is used (for sockets) or IOCB_NOSIGNAL is set.
 *     If the signal is caught or ignored, EPIPE is still returned.
 *
 * error: EFBIG, File too large
 *   desc: An attempt was made to write a file that exceeds the implementation-
 *     defined maximum file size or the file size limit (RLIMIT_FSIZE) of the
 *     process. When RLIMIT_FSIZE is exceeded, the process also receives SIGXFSZ.
 *     For files not opened with O_LARGEFILE on 32-bit systems, the limit is 2GB.
 *
 * error: ENOSPC, No space left on device
 *   desc: The device containing the file has no room for the data. This can
 *     occur mid-write resulting in a short write followed by ENOSPC on retry.
 *
 * error: EDQUOT, Disk quota exceeded
 *   desc: The user's quota of disk blocks on the filesystem has been exhausted.
 *     Like ENOSPC, this can result in a short write.
 *
 * error: EIO, Input/output error
 *   desc: A low-level I/O error occurred while modifying the inode or writing
 *     data. This typically indicates hardware failure, filesystem corruption,
 *     or network filesystem timeout. Some data may have been written.
 *
 * error: EPERM, Operation not permitted
 *   desc: The operation was prevented: (1) by a file seal (F_SEAL_WRITE or
 *     F_SEAL_FUTURE_WRITE on memfd/shmem), (2) writing to an immutable inode
 *     (IS_IMMUTABLE), (3) by an LSM hook denying the operation, or (4) by a
 *     fanotify permission event denying the write.
 *
 * error: EOVERFLOW, Value too large for defined data type
 *   desc: The file position plus count would exceed LLONG_MAX. Also returned
 *     when the offset would exceed filesystem limits after the write.
 *
 * error: EDESTADDRREQ, Destination address required
 *   desc: fd is a datagram socket for which no peer address has been set using
 *     connect(2). Use sendto(2) to specify the destination address.
 *
 * error: ETXTBSY, Text file busy
 *   desc: The file is being used as a swap file (IS_SWAPFILE).
 *
 * error: EXDEV, Cross-device link
 *   desc: When writing to a pipe that has been configured as a watch queue
 *     (CONFIG_WATCH_QUEUE), direct write() calls are not supported.
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory was available for the write operation.
 *     For pipes, this occurs when allocating pages for the pipe buffer.
 *
 * error: ERESTARTSYS, Restart system call (internal)
 *   desc: Internal error code indicating the syscall should be restarted. This
 *     is converted to EINTR if SA_RESTART is not set on the signal handler, or
 *     the syscall is transparently restarted if SA_RESTART is set. User space
 *     should not see this error code directly.
 *
 * error: EACCES, Permission denied
 *   desc: The security subsystem (LSM such as SELinux or AppArmor) denied the
 *     write operation via security_file_permission(). This can occur even if
 *     the file was successfully opened.
 *
 * lock: file->f_pos_lock
 *   type: KAPI_LOCK_MUTEX
 *   acquired: conditional
 *   released: true
 *   desc: For regular files that require atomic position updates (FMODE_ATOMIC_POS),
 *     the f_pos_lock mutex is acquired by fdget_pos() at syscall entry and released
 *     by fdput_pos() at syscall exit. This serializes concurrent writes sharing
 *     the same file description. Not acquired for stream files (FMODE_STREAM like
 *     pipes and sockets) or when the file is not shared.
 *
 * lock: sb->s_writers (freeze protection)
 *   type: KAPI_LOCK_CUSTOM
 *   acquired: conditional
 *   released: true
 *   desc: For regular files, file_start_write() acquires freeze protection on
 *     the superblock via sb_start_write() before the write, and file_end_write()
 *     releases it after. This prevents writes during filesystem freeze. Not
 *     acquired for non-regular files (pipes, sockets, devices).
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: conditional
 *   released: true
 *   desc: For regular files using generic_file_write_iter(), the inode's i_rwsem
 *     is acquired in write mode before modifying file data. This is internal to
 *     the filesystem and released before return. Not all filesystems use this
 *     pattern.
 *
 * lock: pipe->mutex
 *   type: KAPI_LOCK_MUTEX
 *   acquired: conditional
 *   released: true
 *   desc: For pipes and FIFOs, the pipe's mutex is held while modifying pipe
 *     buffers. Released temporarily while waiting for space, then reacquired.
 *
 * lock: RCU read-side
 *   type: KAPI_LOCK_RCU
 *   acquired: conditional
 *   released: true
 *   desc: Used during file descriptor lookup via fdget(). RCU read lock protects
 *     access to the file descriptor table. Released by fdput() at syscall exit.
 *
 * signal: SIGPIPE
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_TERMINATE
 *   condition: Writing to a pipe or socket with no readers
 *   desc: When writing to a pipe whose read end is closed, or a socket whose
 *     peer has closed, SIGPIPE is sent to the calling process. The default
 *     action terminates the process. Use signal(SIGPIPE, SIG_IGN) or set
 *     IOCB_NOSIGNAL/MSG_NOSIGNAL to suppress. EPIPE is returned regardless.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * signal: SIGXFSZ
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_COREDUMP
 *   condition: Writing exceeds RLIMIT_FSIZE
 *   desc: When a write would exceed the soft file size limit (RLIMIT_FSIZE),
 *     SIGXFSZ is sent. The default action terminates with a core dump. The
 *     write returns EFBIG. If RLIMIT_FSIZE is RLIM_INFINITY, no signal is sent.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * signal: Any signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: While blocked waiting for space (pipes, sockets)
 *   desc: The syscall may be interrupted by signals while waiting for buffer
 *     space to become available. If interrupted before any data is written,
 *     returns -EINTR or -ERESTARTSYS. If data was already written, returns the
 *     byte count. Restartable if SA_RESTART is set and no data was written.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_FILE_POSITION
 *   target: file->f_pos
 *   condition: For seekable files when write succeeds (returns > 0)
 *   desc: The file offset (f_pos) is advanced by the number of bytes written.
 *     For files opened with O_APPEND, f_pos is first set to file size. For
 *     stream files (FMODE_STREAM such as pipes and sockets), the offset is not
 *     used or modified. Position updates are protected by f_pos_lock when
 *     shared.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: inode timestamps (mtime, ctime)
 *   condition: When write succeeds (returns > 0)
 *   desc: Updates the file's modification time (mtime) and change time (ctime)
 *     via file_update_time(). The update precision depends on filesystem mount
 *     options (fine-grained timestamps for multigrain inodes).
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: SUID/SGID bits (mode)
 *   condition: When writing to a setuid/setgid file
 *   desc: The SUID bit is cleared when a non-root user writes to a file with
 *     the bit set. The SGID bit may also be cleared. This is a security feature
 *     to prevent privilege escalation via modified setuid binaries. Done via
 *     file_remove_privs().
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: file data
 *   condition: When write succeeds (returns > 0)
 *   desc: Modifies the file's data content. For regular files, data is written
 *     to the page cache (buffered I/O) or directly to storage (O_DIRECT).
 *     Data may not be persistent until fsync() is called or the file is closed.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task I/O accounting
 *   condition: Always
 *   desc: Updates the current task's I/O accounting statistics. The wchar field
 *     (write characters) is incremented by bytes written via add_wchar(). The
 *     syscw field (syscall write count) is incremented via inc_syscw(). These
 *     statistics are visible in /proc/[pid]/io.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify events
 *   condition: When write returns > 0
 *   desc: Generates an FS_MODIFY fsnotify event via fsnotify_modify(), allowing
 *     inotify, fanotify, and dnotify watchers to be notified of the write.
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass discretionary access control on write permission
 *   without: Standard DAC checks are enforced
 *   condition: Checked via security_file_permission() during rw_verify_area()
 *
 * capability: CAP_FOWNER
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass ownership checks for SUID/SGID clearing
 *   without: SUID/SGID bits are cleared on write by non-owner
 *   condition: Checked during file_remove_privs()
 *
 * constraint: MAX_RW_COUNT
 *   desc: The count parameter is silently clamped to MAX_RW_COUNT (INT_MAX &
 *     PAGE_MASK, approximately 2GB minus one page) to prevent integer overflow
 *     in internal calculations. This is transparent to the caller.
 *   expr: actual_count = min(count, MAX_RW_COUNT)
 *
 * constraint: File must be open for writing
 *   desc: The file descriptor must have been opened with O_WRONLY or O_RDWR.
 *     Files opened with O_RDONLY or O_PATH cannot be written and return EBADF.
 *     The file must have both FMODE_WRITE and FMODE_CAN_WRITE flags set.
 *   expr: (file->f_mode & FMODE_WRITE) && (file->f_mode & FMODE_CAN_WRITE)
 *
 * constraint: RLIMIT_FSIZE
 *   desc: The size of data written is constrained by the RLIMIT_FSIZE resource
 *     limit. If writing would exceed this limit, SIGXFSZ is sent and EFBIG is
 *     returned. The limit does not apply to files beyond the limit - only to
 *     writes that would cross it.
 *   expr: pos + count <= rlimit(RLIMIT_FSIZE) || rlimit(RLIMIT_FSIZE) == RLIM_INFINITY
 *
 * constraint: File seals
 *   desc: For memfd or shmem files with F_SEAL_WRITE or F_SEAL_FUTURE_WRITE
 *     seals applied, all write operations fail with EPERM. With F_SEAL_GROW,
 *     writes that would extend file size fail with EPERM.
 *
 * examples: n = write(fd, buf, sizeof(buf));  // Basic write
 *   n = write(STDOUT_FILENO, msg, strlen(msg));  // Write to stdout
 *   while (total < len) { n = write(fd, buf+total, len-total); if (n<0) break; total += n; }  // Handle short writes
 *   if (write(pipefd[1], &byte, 1) < 0 && errno == EPIPE) { handle_broken_pipe(); }  // Pipe error handling
 *
 * notes: The behavior of write() varies significantly depending on the type of
 *   file descriptor:
 *
 *   - Regular files: Writes to the page cache (buffered) or directly to storage
 *     (O_DIRECT). Short writes are rare except near RLIMIT_FSIZE or disk full.
 *     O_APPEND is atomic for determining write position.
 *
 *   - Pipes and FIFOs: Blocking by default. Writes up to PIPE_BUF (4096 bytes
 *     on Linux) are guaranteed atomic. Larger writes may be interleaved with
 *     writes from other processes. Blocks if pipe is full; returns EAGAIN with
 *     O_NONBLOCK. SIGPIPE/EPIPE if no readers.
 *
 *   - Sockets: Behavior depends on socket type and protocol. Stream sockets
 *     (TCP) may return partial writes. Datagram sockets (UDP) typically write
 *     complete messages or fail. SIGPIPE/EPIPE for broken connections (unless
 *     MSG_NOSIGNAL). EDESTADDRREQ for unconnected datagram sockets.
 *
 *   - Terminals: May block on flow control. Canonical vs raw mode affects
 *     behavior. Special characters may be interpreted.
 *
 *   - Device special files: Behavior is device-specific. Block devices behave
 *     similarly to regular files. Character device behavior varies.
 *
 *   Race condition considerations: Concurrent writes from threads sharing a
 *   file description race on the file position. Linux 3.14+ provides atomic
 *   position updates via f_pos_lock for regular files (FMODE_ATOMIC_POS), but
 *   for maximum safety, use pwrite() for concurrent positioned writes.
 *
 *   O_DIRECT writes bypass the page cache and typically require buffer and
 *   offset alignment to filesystem block size. Query requirements via statx()
 *   with STATX_DIOALIGN (Linux 6.1+). Unaligned O_DIRECT writes return EINVAL
 *   on most filesystems.
 *
 *   For zero-copy writes, consider using splice(2), sendfile(2), or vmsplice(2)
 *   instead of copying data through user-space buffers with write().
 *
 *   Partial writes (short writes) must be handled by application code.
 *   Applications should loop until all data is written or an error occurs.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	return ksys_write(fd, buf, count);
}

ssize_t ksys_pread64(unsigned int fd, char __user *buf, size_t count,
		     loff_t pos)
{
	if (pos < 0)
		return -EINVAL;

	CLASS(fd, f)(fd);
	if (fd_empty(f))
		return -EBADF;

	if (fd_file(f)->f_mode & FMODE_PREAD)
		return vfs_read(fd_file(f), buf, count, &pos);

	return -ESPIPE;
}

/**
 * sys_pread64 - Read data from a file descriptor at a specified position
 * @fd: File descriptor to read from
 * @buf: User-space buffer to read data into
 * @count: Maximum number of bytes to read
 * @pos: File offset at which to begin reading
 *
 * long-desc: Reads up to count bytes from file descriptor fd into the buffer
 *   starting at buf, beginning at position pos in the file. Unlike read(),
 *   pread64() does not modify the file offset (file position), making it ideal
 *   for concurrent access by multiple threads without requiring external
 *   synchronization of the file position.
 *
 *   The pread64() syscall is equivalent to atomically performing lseek() to
 *   position pos, reading count bytes, and then restoring the original file
 *   position - except that it is truly atomic and the file position is never
 *   actually modified. This atomicity is crucial for multithreaded applications
 *   that need to read from different parts of a file simultaneously.
 *
 *   On success, the number of bytes read is returned (zero indicates end of
 *   file). It is not an error if this number is smaller than the number of
 *   bytes requested; this may happen because fewer bytes are actually available
 *   (e.g., near end-of-file), or because pread64() was interrupted by a signal.
 *
 *   On Linux, pread64() transfers at most MAX_RW_COUNT (0x7ffff000, approximately
 *   2GB minus one page) bytes per call to prevent signed arithmetic overflow.
 *
 *   The file descriptor must refer to a file that supports positioned reads
 *   (FMODE_PREAD flag). Regular files, block devices, and some character devices
 *   support positioned reads. Pipes, FIFOs, sockets, and terminals do not support
 *   positioned reads and will return ESPIPE.
 *
 *   POSIX permits reads that are interrupted after reading some data to either
 *   return -1 with errno EINTR, or to return the bytes already read. Linux
 *   follows the latter behavior: if data has been read before a signal arrives,
 *   the call returns the number of bytes read rather than failing.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, INT_MAX
 *   constraint: Must be a valid, open file descriptor with read permission.
 *     The file must have been opened with O_RDONLY or O_RDWR. The file must
 *     support positioned reads (FMODE_PREAD); pipes, FIFOs, sockets, and
 *     terminals return ESPIPE. File descriptors opened with O_WRONLY, O_PATH,
 *     or that have been closed return EBADF. Standard file descriptors
 *     0 (stdin), 1 (stdout), 2 (stderr) are valid if open and readable,
 *     though stdin may not support pread if connected to a terminal or pipe.
 *     AT_FDCWD and other special directory values are not valid.
 *
 * param: buf
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must point to a valid, writable user-space memory region of at
 *     least count bytes. The buffer is validated via access_ok() before any
 *     read operation. NULL is invalid and will return EFAULT. The buffer may
 *     be partially written if an error occurs mid-read. For O_DIRECT reads,
 *     the buffer may need to be aligned to the filesystem's block size (varies
 *     by filesystem; query with statx() using STATX_DIOALIGN on Linux 6.1+).
 *
 * param: count
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, SIZE_MAX
 *   constraint: Maximum number of bytes to read. Clamped internally to
 *     MAX_RW_COUNT (INT_MAX & PAGE_MASK, approximately 0x7ffff000 bytes) to
 *     prevent signed overflow. A count of 0 returns immediately with 0
 *     without accessing the file (but may still detect errors). Large values
 *     are not errors but will be clamped. Cast to ssize_t must not be negative.
 *
 * param: pos
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, LLONG_MAX
 *   constraint: File offset at which to begin reading. Must be non-negative;
 *     negative values return EINVAL. For files without unsigned offset support
 *     (most regular files), pos + count must not overflow or exceed LLONG_MAX.
 *     For files with FOP_UNSIGNED_OFFSET (some special files like /dev/mem),
 *     the entire 64-bit range may be valid. The position is not validated
 *     against the file size; reading beyond EOF simply returns 0 bytes.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_RANGE
 *   success: >= 0
 *   desc: On success, returns the number of bytes read (non-negative). Zero
 *     indicates end-of-file (EOF) or that pos is at or beyond the file size.
 *     The return value may be less than count if fewer bytes were available
 *     (short read) or if interrupted by a signal after partial read. Partial
 *     reads are not errors. On error, returns a negative error code.
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned in several cases: (1) The pos argument is negative. (2) The
 *     count argument, when cast to ssize_t, is negative. (3) The file descriptor
 *     does not have a read or read_iter method (e.g., trying to read from a
 *     write-only special file). (4) For O_DIRECT reads, the buffer alignment,
 *     file offset, or count does not meet the filesystem's alignment requirements.
 *     (5) For timerfd file descriptors, the buffer is smaller than 8 bytes.
 *     (6) The file position plus count would overflow for files without unsigned
 *     offset support.
 *
 * error: EBADF, Bad file descriptor
 *   desc: fd is not a valid file descriptor, or fd was not opened for reading.
 *     This includes file descriptors opened with O_WRONLY, O_PATH, or file
 *     descriptors that have been closed. Also returned if the file structure
 *     does not have FMODE_READ or FMODE_CAN_READ flags set.
 *
 * error: ESPIPE, Illegal seek
 *   desc: The file descriptor refers to a file type that does not support
 *     positioned reads (FMODE_PREAD flag not set). This includes pipes, FIFOs,
 *     sockets, and terminal devices. Use read() instead for these file types,
 *     or for pipes consider splice() for better performance.
 *
 * error: EFAULT, Bad address
 *   desc: buf points outside the accessible address space. The buffer address
 *     failed access_ok() validation. Can also occur if a fault happens during
 *     copy_to_user() when transferring data to user space after the read
 *     completes in kernel space.
 *
 * error: EOVERFLOW, Value too large for defined data type
 *   desc: The file position (pos) plus count would exceed LLONG_MAX, causing
 *     arithmetic overflow. This is checked in rw_verify_area() before the read
 *     begins. For files without FOP_UNSIGNED_OFFSET, this also applies if pos
 *     alone would cause issues.
 *
 * error: EISDIR, Is a directory
 *   desc: fd refers to a directory. Directories cannot be read using pread64();
 *     use getdents64() instead. This error is returned by the generic_read_dir()
 *     handler installed for directory file operations.
 *
 * error: EAGAIN, Resource temporarily unavailable
 *   desc: fd refers to a file (device, network filesystem) that is marked
 *     non-blocking (O_NONBLOCK) and the read would block because no data is
 *     available. Also returned when using io_uring with IOCB_NOWAIT flag and
 *     the read cannot complete immediately. Equivalent to EWOULDBLOCK. The
 *     application should retry the read later or use select/poll/epoll.
 *
 * error: EINTR, Interrupted system call
 *   desc: The call was interrupted by a signal before any data was read. This
 *     only occurs if no data has been transferred; if some data was read before
 *     the signal, the call returns the number of bytes read. For regular files,
 *     EINTR is rare but can occur during disk I/O waits if a fatal signal arrives.
 *     The caller should typically restart the read.
 *
 * error: EIO, Input/output error
 *   desc: A low-level I/O error occurred. For regular files, this typically
 *     indicates a hardware error on the storage device, filesystem corruption,
 *     or a network filesystem timeout. May also indicate that the page could
 *     not be read from disk (e.g., bad blocks).
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory to allocate necessary data structures for
 *     the read operation, such as page cache folios. This is rare under normal
 *     circumstances but can occur under memory pressure.
 *
 * error: EACCES, Permission denied
 *   desc: The security subsystem (LSM such as SELinux or AppArmor) denied
 *     the read operation via security_file_permission(). This can occur even
 *     if the file was successfully opened, as LSM policies may enforce per-
 *     operation checks. The specific policy that denied access may be logged.
 *
 * error: EPERM, Operation not permitted
 *   desc: Returned by fanotify permission events (CONFIG_FANOTIFY_ACCESS_PERMISSIONS)
 *     when a user-space fanotify listener denies the read operation via
 *     fsnotify_file_area_perm(). This allows user-space HSM or antivirus
 *     programs to block reads.
 *
 * error: ENOBUFS, No buffer space available
 *   desc: Returned when reading from pipe-based watch queues (CONFIG_WATCH_QUEUE)
 *     when the buffer is too small to hold a complete notification, or when
 *     reading packets from pipes with PIPE_BUF_FLAG_WHOLE set.
 *
 * lock: Filesystem-specific locks
 *   type: KAPI_LOCK_CUSTOM
 *   acquired: conditional
 *   released: true
 *   desc: The filesystem's read_iter or read method may acquire additional locks.
 *     For regular files, this typically includes the inode's i_rwsem (shared mode)
 *     for certain operations, and the mapping's invalidate_lock. For O_DIRECT
 *     reads, additional serialization with page cache may occur. These locks are
 *     internal to the file operation and released before return.
 *
 * lock: RCU read-side
 *   type: KAPI_LOCK_RCU
 *   acquired: conditional
 *   released: true
 *   desc: Used during file descriptor lookup via fdget(). RCU read lock protects
 *     access to the file descriptor table. Released by fdput() at syscall exit.
 *
 * signal: Any signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: When blocked waiting for data or during disk I/O
 *   desc: The syscall may be interrupted by signals while waiting for data to
 *     become available from disk I/O or network operations. If interrupted
 *     before any data is read, returns -EINTR or -ERESTARTSYS. If data has
 *     already been read, returns the number of bytes read. Fatal signals
 *     (SIGKILL, SIGSTOP) cause immediate return during killable waits.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: inode access time (atime)
 *   condition: When read succeeds and O_NOATIME is not set
 *   desc: Updates the file's access time (atime) via touch_atime(). The update
 *     may be suppressed by mount options (noatime, relatime), the O_NOATIME
 *     flag, or if the filesystem does not support atime. Relatime only updates
 *     atime if it is older than mtime or ctime, or more than a day old.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task I/O accounting
 *   condition: Always
 *   desc: Updates the current task's I/O accounting statistics. The rchar field
 *     (read characters) is incremented by bytes read via add_rchar(). The syscr
 *     field (syscall read count) is incremented via inc_syscr(). These statistics
 *     are visible in /proc/[pid]/io. Updated regardless of success or failure.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify events
 *   condition: When read returns > 0
 *   desc: Generates an FS_ACCESS fsnotify event via fsnotify_access() allowing
 *     inotify, fanotify, and dnotify watchers to be notified of the read. This
 *     occurs after data transfer completes successfully.
 *   reversible: no
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass discretionary access control on read permission
 *   without: Standard DAC checks are enforced
 *   condition: Checked via security_file_permission() during rw_verify_area()
 *
 * capability: CAP_DAC_READ_SEARCH
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass read permission checks on regular files
 *   without: Must have read permission on file
 *   condition: Checked by LSM hooks during the read operation
 *
 * constraint: MAX_RW_COUNT
 *   desc: The count parameter is silently clamped to MAX_RW_COUNT (INT_MAX &
 *     PAGE_MASK, approximately 2GB minus one page) to prevent integer overflow
 *     in internal calculations. This is transparent to the caller; the syscall
 *     succeeds but reads at most MAX_RW_COUNT bytes per call.
 *   expr: actual_count = min(count, MAX_RW_COUNT)
 *
 * constraint: File must be open for reading
 *   desc: The file descriptor must have been opened with O_RDONLY or O_RDWR.
 *     Files opened with O_WRONLY or O_PATH cannot be read and return EBADF.
 *     The file must have both FMODE_READ and FMODE_CAN_READ flags set.
 *   expr: (file->f_mode & FMODE_READ) && (file->f_mode & FMODE_CAN_READ)
 *
 * constraint: File must support positioned reads
 *   desc: The file must have FMODE_PREAD flag set, indicating it supports
 *     reading at arbitrary positions. Regular files and block devices have
 *     this flag set by default. Pipes, FIFOs, sockets, and terminals do not.
 *     Some device drivers may or may not support positioned reads.
 *   expr: file->f_mode & FMODE_PREAD
 *
 * examples: n = pread64(fd, buf, sizeof(buf), 0);  // Read from start of file
 *   n = pread64(fd, buf, 4096, offset);  // Read 4KB at specific offset
 *   while ((n = pread64(fd, buf, sizeof(buf), pos)) > 0) { pos += n; }  // Sequential
 *   pread64(fd, &header, sizeof(header), 0);  // Read file header
 *
 * notes: pread64() is essential for multithreaded file I/O because it provides
 *   atomic positioned reads without modifying the shared file offset:
 *
 *   - Thread safety: Multiple threads can call pread64() concurrently on the
 *     same file descriptor without race conditions on the file position. Each
 *     call specifies its own independent position.
 *
 *   - Unlike read(), pread64() does NOT acquire or need the f_pos_lock mutex
 *     because it never accesses or modifies file->f_pos. This eliminates a
 *     potential serialization point.
 *
 *   - Database applications commonly use pread64() to read different pages of
 *     a database file from multiple threads without coordination.
 *
 *   - For pipes, sockets, and terminals, positioned reads make no sense, so
 *     ESPIPE is returned. Use read() for these file types.
 *
 *   - The pos parameter is of type loff_t (64-bit signed), supporting files
 *     larger than 4GB. The syscall name includes "64" to distinguish from
 *     the older 32-bit pread() on some architectures.
 *
 *   - O_DIRECT reads bypass the page cache and typically require aligned
 *     buffers and positions. Use statx() with STATX_DIOALIGN to query
 *     alignment requirements (Linux 6.1+).
 *
 *   - Some special files in /proc and /sys support pread64() to allow reading
 *     at position 0 to restart reading from the beginning, as these files
 *     often generate content dynamically.
 *
 *   - Race condition: While pread64() itself is atomic with respect to file
 *     position, concurrent writes to the same file region can still race with
 *     reads. Use file locking (flock, fcntl) if consistency is required.
 *
 *   - The return value semantics match read(): zero means EOF, positive means
 *     bytes read (possibly less than requested), negative means error.
 *
 * since-version: 2.2
 */
SYSCALL_DEFINE4(pread64, unsigned int, fd, char __user *, buf,
			size_t, count, loff_t, pos)
{
	return ksys_pread64(fd, buf, count, pos);
}

#if defined(CONFIG_COMPAT) && defined(__ARCH_WANT_COMPAT_PREAD64)
COMPAT_SYSCALL_DEFINE5(pread64, unsigned int, fd, char __user *, buf,
		       size_t, count, compat_arg_u64_dual(pos))
{
	return ksys_pread64(fd, buf, count, compat_arg_u64_glue(pos));
}
#endif

ssize_t ksys_pwrite64(unsigned int fd, const char __user *buf,
		      size_t count, loff_t pos)
{
	if (pos < 0)
		return -EINVAL;

	CLASS(fd, f)(fd);
	if (fd_empty(f))
		return -EBADF;

	if (fd_file(f)->f_mode & FMODE_PWRITE)
		return vfs_write(fd_file(f), buf, count, &pos);

	return -ESPIPE;
}

/**
 * sys_pwrite64 - Write data to a file descriptor at a specified position
 * @fd: File descriptor to write to
 * @buf: User-space buffer containing data to write
 * @count: Maximum number of bytes to write
 * @pos: File offset at which to begin writing
 *
 * long-desc: Writes up to count bytes from the buffer starting at buf to
 *   the file referred to by file descriptor fd, beginning at position pos
 *   in the file. Unlike write(), pwrite64() does not modify the file offset
 *   (file position), making it ideal for concurrent access by multiple threads
 *   without requiring external synchronization of the file position.
 *
 *   The pwrite64() syscall is equivalent to atomically performing lseek() to
 *   position pos, writing count bytes, and then restoring the original file
 *   position - except that it is truly atomic and the file position is never
 *   actually modified. This atomicity is crucial for multithreaded applications
 *   that need to write to different parts of a file simultaneously.
 *
 *   On success, the number of bytes written is returned. It is not an error if
 *   this number is smaller than the number of bytes requested; this may happen
 *   because there was insufficient space on the physical medium, the RLIMIT_FSIZE
 *   limit was encountered, or the call was interrupted by a signal after having
 *   written some data. This is called a "short write."
 *
 *   On Linux, pwrite64() transfers at most MAX_RW_COUNT (0x7ffff000, approximately
 *   2GB minus one page) bytes per call to prevent signed arithmetic overflow.
 *
 *   The file descriptor must refer to a file that supports positioned writes
 *   (FMODE_PWRITE flag). Regular files, block devices, and some character devices
 *   support positioned writes. Pipes, FIFOs, sockets, and terminals do not support
 *   positioned writes and will return ESPIPE.
 *
 *   Important POSIX deviation: On Linux, if a file is opened with O_APPEND,
 *   pwrite64() writes data to the end of the file regardless of the value of pos.
 *   POSIX requires that pwrite() write at the specified position even for O_APPEND
 *   files, but Linux does not follow this requirement.
 *
 *   POSIX permits writes that are interrupted after writing some data to either
 *   return -1 with errno EINTR, or to return the bytes already written. Linux
 *   follows the latter behavior: if data has been written before a signal arrives,
 *   the call returns the number of bytes written rather than failing.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, INT_MAX
 *   constraint: Must be a valid, open file descriptor with write permission.
 *     The file must have been opened with O_WRONLY or O_RDWR. The file must
 *     support positioned writes (FMODE_PWRITE); pipes, FIFOs, sockets, and
 *     terminals return ESPIPE. File descriptors opened with O_RDONLY, O_PATH,
 *     or that have been closed return EBADF. Standard file descriptors
 *     0 (stdin), 1 (stdout), 2 (stderr) are valid if open and writable,
 *     though stdout/stderr may not support pwrite if connected to a terminal.
 *     AT_FDCWD and other special directory values are not valid.
 *
 * param: buf
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must point to a valid, readable user-space memory region of at
 *     least count bytes. The buffer is validated via access_ok() before any
 *     write operation. NULL is invalid and will return EFAULT. For O_DIRECT
 *     writes, the buffer may need to be aligned to the filesystem's block size
 *     (varies by filesystem; query with statx() using STATX_DIOALIGN on Linux
 *     6.1+).
 *
 * param: count
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, SIZE_MAX
 *   constraint: Maximum number of bytes to write. Clamped internally to
 *     MAX_RW_COUNT (INT_MAX & PAGE_MASK, approximately 0x7ffff000 bytes) to
 *     prevent signed overflow. A count of 0 returns immediately with 0
 *     without accessing the file (but may still detect errors). Large values
 *     are not errors but will be clamped. Cast to ssize_t must not be negative.
 *
 * param: pos
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, LLONG_MAX
 *   constraint: File offset at which to begin writing. Must be non-negative;
 *     negative values return EINVAL. For files without unsigned offset support
 *     (most regular files), pos + count must not overflow or exceed LLONG_MAX.
 *     For files with FOP_UNSIGNED_OFFSET (some special files like /dev/mem),
 *     the entire 64-bit range may be valid. The position is validated against
 *     RLIMIT_FSIZE and filesystem limits. Note: For O_APPEND files, this
 *     parameter is ignored and writing occurs at end-of-file.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_RANGE
 *   success: >= 0
 *   desc: On success, returns the number of bytes written (non-negative). Zero
 *     indicates that nothing was written (count was 0, or RLIMIT_FSIZE reached
 *     at current position). The return value may be less than count if space
 *     was insufficient, resource limits were hit, or interrupted by a signal
 *     after partial write. Partial writes are not errors. On error, returns a
 *     negative error code.
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned in several cases: (1) The pos argument is negative. (2) The
 *     count argument, when cast to ssize_t, is negative. (3) The file descriptor
 *     does not have a write or write_iter method (e.g., trying to write to a
 *     read-only special file). (4) For O_DIRECT writes, the buffer alignment,
 *     file offset, or count does not meet the filesystem's alignment requirements.
 *     (5) For IOCB_NOWAIT on non-O_DIRECT files without FOP_BUFFER_WASYNC support.
 *     (6) The file position plus count would overflow for files without unsigned
 *     offset support.
 *
 * error: EBADF, Bad file descriptor
 *   desc: fd is not a valid file descriptor, or fd was not opened for writing.
 *     This includes file descriptors opened with O_RDONLY, O_PATH, or file
 *     descriptors that have been closed. Also returned if the file structure
 *     does not have FMODE_WRITE or FMODE_CAN_WRITE flags set.
 *
 * error: ESPIPE, Illegal seek
 *   desc: The file descriptor refers to a file type that does not support
 *     positioned writes (FMODE_PWRITE flag not set). This includes pipes, FIFOs,
 *     sockets, and terminal devices. Use write() instead for these file types.
 *
 * error: EFAULT, Bad address
 *   desc: buf points outside the accessible address space. The buffer address
 *     failed access_ok() validation. Can also occur if a fault happens during
 *     copy_from_user() when reading data from user space.
 *
 * error: EOVERFLOW, Value too large for defined data type
 *   desc: The file position (pos) plus count would exceed LLONG_MAX, causing
 *     arithmetic overflow. This is checked in rw_verify_area() before the write
 *     begins. For files without FOP_UNSIGNED_OFFSET, this also applies if pos
 *     alone would cause issues.
 *
 * error: EFBIG, File too large
 *   desc: An attempt was made to write at a position that exceeds the
 *     implementation-defined maximum file size (s_maxbytes), the process's file
 *     size limit (RLIMIT_FSIZE), or MAX_NON_LFS for files not opened with
 *     O_LARGEFILE. When RLIMIT_FSIZE is exceeded, SIGXFSZ is sent before
 *     returning this error.
 *
 * error: EAGAIN, Resource temporarily unavailable
 *   desc: fd refers to a file (device, network filesystem) that is marked
 *     non-blocking (O_NONBLOCK) and the write would block because the buffer
 *     is full or the operation cannot complete immediately. Also returned when
 *     IOCB_NOWAIT is used and the operation cannot complete without blocking.
 *     For regular files with IOCB_NOWAIT, returned if privs must be removed or
 *     timestamps must be updated and this would block. Equivalent to EWOULDBLOCK.
 *
 * error: EINTR, Interrupted system call
 *   desc: The call was interrupted by a signal before any data was written. This
 *     only occurs if no data has been transferred; if some data was written before
 *     the signal, the call returns the number of bytes written. For regular files,
 *     EINTR is rare but can occur during disk I/O waits if a fatal signal arrives.
 *     The caller should typically restart the write.
 *
 * error: EIO, Input/output error
 *   desc: A low-level I/O error occurred while modifying the inode or writing
 *     data. For regular files, this typically indicates a hardware error on the
 *     storage device, filesystem corruption, or network filesystem timeout.
 *     Some data may have been written before the error occurred.
 *
 * error: ENOSPC, No space left on device
 *   desc: The device containing the file has no room for the data. This can
 *     occur mid-write resulting in a short write followed by ENOSPC on retry.
 *
 * error: EDQUOT, Disk quota exceeded
 *   desc: The user's quota of disk blocks on the filesystem has been exhausted.
 *     Like ENOSPC, this can result in a short write.
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory to allocate necessary data structures for
 *     the write operation, such as page cache folios or I/O buffers. This is
 *     rare under normal circumstances but can occur under memory pressure.
 *
 * error: EACCES, Permission denied
 *   desc: The security subsystem (LSM such as SELinux or AppArmor) denied
 *     the write operation via security_file_permission(). This can occur even
 *     if the file was successfully opened, as LSM policies may enforce per-
 *     operation checks. The specific policy that denied access may be logged.
 *
 * error: EPERM, Operation not permitted
 *   desc: The operation was prevented: (1) by a fanotify permission event
 *     (CONFIG_FANOTIFY_ACCESS_PERMISSIONS) when a user-space listener denies
 *     the write via fsnotify_file_area_perm(), (2) by a file seal (F_SEAL_WRITE
 *     or F_SEAL_FUTURE_WRITE on memfd/shmem), (3) writing to an immutable inode
 *     (IS_IMMUTABLE), or (4) by an LSM policy.
 *
 * error: ETXTBSY, Text file busy
 *   desc: The file is being used as a swap file (IS_SWAPFILE). Writing to
 *     active swap files is not permitted to prevent data corruption.
 *
 * lock: sb->s_writers (freeze protection)
 *   type: KAPI_LOCK_CUSTOM
 *   acquired: true
 *   released: true
 *   desc: For regular files, file_start_write() acquires freeze protection on
 *     the superblock via sb_start_write() before the write, and file_end_write()
 *     releases it after. This prevents writes during filesystem freeze. Not
 *     acquired for non-regular files (block devices, character devices).
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: conditional
 *   released: true
 *   desc: For regular files using generic_file_write_iter(), the inode's i_rwsem
 *     is acquired in write mode before modifying file data. This is internal to
 *     the filesystem and released before return. Protects against concurrent
 *     truncation and hole punching operations.
 *
 * lock: Filesystem-specific locks
 *   type: KAPI_LOCK_CUSTOM
 *   acquired: conditional
 *   released: true
 *   desc: The filesystem's write_iter method may acquire additional locks such
 *     as extent locks, allocation locks, or journal locks depending on the
 *     filesystem implementation. These are internal and released before return.
 *
 * lock: RCU read-side
 *   type: KAPI_LOCK_RCU
 *   acquired: conditional
 *   released: true
 *   desc: Used during file descriptor lookup via fdget(). RCU read lock protects
 *     access to the file descriptor table. Released by fdput() at syscall exit.
 *
 * signal: SIGXFSZ
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_COREDUMP
 *   condition: Writing exceeds RLIMIT_FSIZE
 *   desc: When a write would exceed the soft file size limit (RLIMIT_FSIZE),
 *     SIGXFSZ is sent before returning EFBIG. The default action terminates the
 *     process with a core dump. If RLIMIT_FSIZE is RLIM_INFINITY, no signal is
 *     sent. The signal is sent via send_sig() from generic_write_check_limits().
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * signal: Any signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: When blocked waiting for disk I/O or locks
 *   desc: The syscall may be interrupted by signals while waiting for data to
 *     be written to disk or while acquiring locks. If interrupted before any
 *     data is written, returns -EINTR or -ERESTARTSYS. If data has already been
 *     written, returns the number of bytes written. Fatal signals (SIGKILL,
 *     SIGSTOP) cause immediate return during killable waits.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: inode timestamps (mtime, ctime)
 *   condition: When write succeeds (returns > 0)
 *   desc: Updates the file's modification time (mtime) and change time (ctime)
 *     via file_update_time(). The update may be suppressed if IS_NOCMTIME is
 *     set or FMODE_NOCMTIME is in effect. Update precision depends on filesystem.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: SUID/SGID bits (mode)
 *   condition: When writing to a setuid/setgid file
 *   desc: The SUID bit is cleared when a non-root user writes to a file with
 *     the bit set. The SGID bit may also be cleared if group-execute is set.
 *     This is a security feature to prevent privilege escalation via modified
 *     setuid binaries. Done via file_remove_privs() before the write.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: file data
 *   condition: When write succeeds (returns > 0)
 *   desc: Modifies the file's data content at the specified position. For
 *     regular files, data is written to the page cache (buffered I/O) or
 *     directly to storage (O_DIRECT). Data may not be persistent until fsync()
 *     is called or the file is closed (for O_SYNC files, sync is automatic).
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: file size (inode->i_size)
 *   condition: When write extends beyond current EOF
 *   desc: If the write position plus bytes written exceeds the current file
 *     size, the file is extended. For O_APPEND writes, the file is always
 *     extended (on success). The i_size is updated atomically.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task I/O accounting
 *   condition: Always
 *   desc: Updates the current task's I/O accounting statistics. The wchar field
 *     (write characters) is incremented by bytes written via add_wchar(). The
 *     syscw field (syscall write count) is incremented via inc_syscw(). These
 *     statistics are visible in /proc/[pid]/io. Updated regardless of success.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify events
 *   condition: When write returns > 0
 *   desc: Generates an FS_MODIFY fsnotify event via fsnotify_modify() allowing
 *     inotify, fanotify, and dnotify watchers to be notified of the write. This
 *     occurs after data transfer completes successfully.
 *   reversible: no
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass discretionary access control on write permission
 *   without: Standard DAC checks are enforced
 *   condition: Checked via security_file_permission() during rw_verify_area()
 *
 * capability: CAP_FOWNER
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass ownership checks for SUID/SGID clearing
 *   without: SUID/SGID bits are cleared on write by non-owner
 *   condition: Checked during file_remove_privs()
 *
 * constraint: MAX_RW_COUNT
 *   desc: The count parameter is silently clamped to MAX_RW_COUNT (INT_MAX &
 *     PAGE_MASK, approximately 2GB minus one page) to prevent integer overflow
 *     in internal calculations. This is transparent to the caller; the syscall
 *     succeeds but writes at most MAX_RW_COUNT bytes per call.
 *   expr: actual_count = min(count, MAX_RW_COUNT)
 *
 * constraint: File must be open for writing
 *   desc: The file descriptor must have been opened with O_WRONLY or O_RDWR.
 *     Files opened with O_RDONLY or O_PATH cannot be written and return EBADF.
 *     The file must have both FMODE_WRITE and FMODE_CAN_WRITE flags set.
 *   expr: (file->f_mode & FMODE_WRITE) && (file->f_mode & FMODE_CAN_WRITE)
 *
 * constraint: File must support positioned writes
 *   desc: The file must have FMODE_PWRITE flag set, indicating it supports
 *     writing at arbitrary positions. Regular files and block devices have
 *     this flag set by default. Pipes, FIFOs, sockets, and terminals do not.
 *     Some device drivers may or may not support positioned writes.
 *   expr: file->f_mode & FMODE_PWRITE
 *
 * constraint: RLIMIT_FSIZE
 *   desc: The position and size of data written is constrained by RLIMIT_FSIZE.
 *     If writing at pos would exceed this limit, SIGXFSZ is sent and EFBIG is
 *     returned. The write may be truncated to fit within the limit, resulting
 *     in a short write if pos is below the limit but pos + count exceeds it.
 *   expr: pos < rlimit(RLIMIT_FSIZE) || rlimit(RLIMIT_FSIZE) == RLIM_INFINITY
 *
 * constraint: Filesystem maximum size
 *   desc: Each filesystem has a maximum file size (s_maxbytes) which cannot be
 *     exceeded. For files not opened with O_LARGEFILE on 32-bit systems, the
 *     limit is MAX_NON_LFS (2GB - 1). Writing beyond these limits returns EFBIG.
 *
 * examples: n = pwrite64(fd, buf, sizeof(buf), 0);  // Write at start of file
 *   n = pwrite64(fd, buf, 4096, offset);  // Write 4KB at specific offset
 *   pwrite64(fd, &header, sizeof(header), 0);  // Write file header
 *   pwrite64(fd, record, sizeof(record), recnum * sizeof(record));  // Random access
 *
 * notes: pwrite64() is essential for multithreaded file I/O because it provides
 *   atomic positioned writes without modifying the shared file offset:
 *
 *   - Thread safety: Multiple threads can call pwrite64() concurrently on the
 *     same file descriptor without race conditions on the file position. Each
 *     call specifies its own independent position.
 *
 *   - Unlike write(), pwrite64() does NOT acquire or need the f_pos_lock mutex
 *     because it never accesses or modifies file->f_pos. This eliminates a
 *     potential serialization point between threads.
 *
 *   - Database applications commonly use pwrite64() to write different pages of
 *     a database file from multiple threads without coordination.
 *
 *   - For pipes, sockets, and terminals, positioned writes make no sense, so
 *     ESPIPE is returned. Use write() for these file types.
 *
 *   - The pos parameter is of type loff_t (64-bit signed), supporting files
 *     larger than 4GB. The syscall name includes "64" to distinguish from
 *     the older 32-bit pwrite() on some architectures.
 *
 *   - O_DIRECT writes bypass the page cache and typically require aligned
 *     buffers and positions. Use statx() with STATX_DIOALIGN to query
 *     alignment requirements (Linux 6.1+).
 *
 *   - IMPORTANT: Linux deviates from POSIX by honoring O_APPEND even with
 *     pwrite64(). On Linux, if O_APPEND is set, data is written at the end of
 *     the file regardless of the pos argument. POSIX specifies that pwrite()
 *     should ignore O_APPEND and write at the specified position.
 *
 *   - Race condition: While pwrite64() itself is atomic with respect to file
 *     position, concurrent writes to overlapping file regions can still race
 *     with each other. Use file locking (flock, fcntl) if consistency is
 *     required between concurrent writes to the same region.
 *
 *   - The return value semantics match write(): positive means bytes written
 *     (possibly less than requested), zero means nothing written (when count
 *     is 0 or at resource limit), negative means error.
 *
 *   - For O_SYNC or O_DSYNC files, pwrite64() ensures data is synced to storage
 *     before returning, which may significantly increase latency.
 *
 * since-version: 2.2
 */
SYSCALL_DEFINE4(pwrite64, unsigned int, fd, const char __user *, buf,
			 size_t, count, loff_t, pos)
{
	return ksys_pwrite64(fd, buf, count, pos);
}

#if defined(CONFIG_COMPAT) && defined(__ARCH_WANT_COMPAT_PWRITE64)
COMPAT_SYSCALL_DEFINE5(pwrite64, unsigned int, fd, const char __user *, buf,
		       size_t, count, compat_arg_u64_dual(pos))
{
	return ksys_pwrite64(fd, buf, count, compat_arg_u64_glue(pos));
}
#endif

static ssize_t do_iter_readv_writev(struct file *filp, struct iov_iter *iter,
		loff_t *ppos, int type, rwf_t flags)
{
	struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	ret = kiocb_set_rw_flags(&kiocb, flags, type);
	if (ret)
		return ret;
	kiocb.ki_pos = (ppos ? *ppos : 0);

	if (type == READ)
		ret = filp->f_op->read_iter(&kiocb, iter);
	else
		ret = filp->f_op->write_iter(&kiocb, iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ppos)
		*ppos = kiocb.ki_pos;
	return ret;
}

/* Do it by hand, with file-ops */
static ssize_t do_loop_readv_writev(struct file *filp, struct iov_iter *iter,
		loff_t *ppos, int type, rwf_t flags)
{
	ssize_t ret = 0;

	if (flags & ~RWF_HIPRI)
		return -EOPNOTSUPP;

	while (iov_iter_count(iter)) {
		ssize_t nr;

		if (type == READ) {
			nr = filp->f_op->read(filp, iter_iov_addr(iter),
						iter_iov_len(iter), ppos);
		} else {
			nr = filp->f_op->write(filp, iter_iov_addr(iter),
						iter_iov_len(iter), ppos);
		}

		if (nr < 0) {
			if (!ret)
				ret = nr;
			break;
		}
		ret += nr;
		if (nr != iter_iov_len(iter))
			break;
		iov_iter_advance(iter, nr);
	}

	return ret;
}

ssize_t vfs_iocb_iter_read(struct file *file, struct kiocb *iocb,
			   struct iov_iter *iter)
{
	size_t tot_len;
	ssize_t ret = 0;

	if (!file->f_op->read_iter)
		return -EINVAL;
	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;

	tot_len = iov_iter_count(iter);
	if (!tot_len)
		goto out;
	ret = rw_verify_area(READ, file, &iocb->ki_pos, tot_len);
	if (ret < 0)
		return ret;

	ret = file->f_op->read_iter(iocb, iter);
out:
	if (ret >= 0)
		fsnotify_access(file);
	return ret;
}
EXPORT_SYMBOL(vfs_iocb_iter_read);

ssize_t vfs_iter_read(struct file *file, struct iov_iter *iter, loff_t *ppos,
		      rwf_t flags)
{
	size_t tot_len;
	ssize_t ret = 0;

	if (!file->f_op->read_iter)
		return -EINVAL;
	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;

	tot_len = iov_iter_count(iter);
	if (!tot_len)
		goto out;
	ret = rw_verify_area(READ, file, ppos, tot_len);
	if (ret < 0)
		return ret;

	ret = do_iter_readv_writev(file, iter, ppos, READ, flags);
out:
	if (ret >= 0)
		fsnotify_access(file);
	return ret;
}
EXPORT_SYMBOL(vfs_iter_read);

/*
 * Caller is responsible for calling kiocb_end_write() on completion
 * if async iocb was queued.
 */
ssize_t vfs_iocb_iter_write(struct file *file, struct kiocb *iocb,
			    struct iov_iter *iter)
{
	size_t tot_len;
	ssize_t ret = 0;

	if (!file->f_op->write_iter)
		return -EINVAL;
	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;

	tot_len = iov_iter_count(iter);
	if (!tot_len)
		return 0;
	ret = rw_verify_area(WRITE, file, &iocb->ki_pos, tot_len);
	if (ret < 0)
		return ret;

	kiocb_start_write(iocb);
	ret = file->f_op->write_iter(iocb, iter);
	if (ret != -EIOCBQUEUED)
		kiocb_end_write(iocb);
	if (ret > 0)
		fsnotify_modify(file);

	return ret;
}
EXPORT_SYMBOL(vfs_iocb_iter_write);

ssize_t vfs_iter_write(struct file *file, struct iov_iter *iter, loff_t *ppos,
		       rwf_t flags)
{
	size_t tot_len;
	ssize_t ret;

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	if (!file->f_op->write_iter)
		return -EINVAL;

	tot_len = iov_iter_count(iter);
	if (!tot_len)
		return 0;

	ret = rw_verify_area(WRITE, file, ppos, tot_len);
	if (ret < 0)
		return ret;

	file_start_write(file);
	ret = do_iter_readv_writev(file, iter, ppos, WRITE, flags);
	if (ret > 0)
		fsnotify_modify(file);
	file_end_write(file);

	return ret;
}
EXPORT_SYMBOL(vfs_iter_write);

static ssize_t vfs_readv(struct file *file, const struct iovec __user *vec,
			 unsigned long vlen, loff_t *pos, rwf_t flags)
{
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	size_t tot_len;
	ssize_t ret = 0;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;

	ret = import_iovec(ITER_DEST, vec, vlen, ARRAY_SIZE(iovstack), &iov,
			   &iter);
	if (ret < 0)
		return ret;

	tot_len = iov_iter_count(&iter);
	if (!tot_len)
		goto out;

	ret = rw_verify_area(READ, file, pos, tot_len);
	if (ret < 0)
		goto out;

	if (file->f_op->read_iter)
		ret = do_iter_readv_writev(file, &iter, pos, READ, flags);
	else
		ret = do_loop_readv_writev(file, &iter, pos, READ, flags);
out:
	if (ret >= 0)
		fsnotify_access(file);
	kfree(iov);
	return ret;
}

static ssize_t vfs_writev(struct file *file, const struct iovec __user *vec,
			  unsigned long vlen, loff_t *pos, rwf_t flags)
{
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	size_t tot_len;
	ssize_t ret = 0;

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;

	ret = import_iovec(ITER_SOURCE, vec, vlen, ARRAY_SIZE(iovstack), &iov,
			   &iter);
	if (ret < 0)
		return ret;

	tot_len = iov_iter_count(&iter);
	if (!tot_len)
		goto out;

	ret = rw_verify_area(WRITE, file, pos, tot_len);
	if (ret < 0)
		goto out;

	file_start_write(file);
	if (file->f_op->write_iter)
		ret = do_iter_readv_writev(file, &iter, pos, WRITE, flags);
	else
		ret = do_loop_readv_writev(file, &iter, pos, WRITE, flags);
	if (ret > 0)
		fsnotify_modify(file);
	file_end_write(file);
out:
	kfree(iov);
	return ret;
}

static ssize_t do_readv(unsigned long fd, const struct iovec __user *vec,
			unsigned long vlen, rwf_t flags)
{
	CLASS(fd_pos, f)(fd);
	ssize_t ret = -EBADF;

	if (!fd_empty(f)) {
		loff_t pos, *ppos = file_ppos(fd_file(f));
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_readv(fd_file(f), vec, vlen, ppos, flags);
		if (ret >= 0 && ppos)
			fd_file(f)->f_pos = pos;
	}

	if (ret > 0)
		add_rchar(current, ret);
	inc_syscr(current);
	return ret;
}

static ssize_t do_writev(unsigned long fd, const struct iovec __user *vec,
			 unsigned long vlen, rwf_t flags)
{
	CLASS(fd_pos, f)(fd);
	ssize_t ret = -EBADF;

	if (!fd_empty(f)) {
		loff_t pos, *ppos = file_ppos(fd_file(f));
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_writev(fd_file(f), vec, vlen, ppos, flags);
		if (ret >= 0 && ppos)
			fd_file(f)->f_pos = pos;
	}

	if (ret > 0)
		add_wchar(current, ret);
	inc_syscw(current);
	return ret;
}

static inline loff_t pos_from_hilo(unsigned long high, unsigned long low)
{
#define HALF_LONG_BITS (BITS_PER_LONG / 2)
	return (((loff_t)high << HALF_LONG_BITS) << HALF_LONG_BITS) | low;
}

static ssize_t do_preadv(unsigned long fd, const struct iovec __user *vec,
			 unsigned long vlen, loff_t pos, rwf_t flags)
{
	ssize_t ret = -EBADF;

	if (pos < 0)
		return -EINVAL;

	CLASS(fd, f)(fd);
	if (!fd_empty(f)) {
		ret = -ESPIPE;
		if (fd_file(f)->f_mode & FMODE_PREAD)
			ret = vfs_readv(fd_file(f), vec, vlen, &pos, flags);
	}

	if (ret > 0)
		add_rchar(current, ret);
	inc_syscr(current);
	return ret;
}

static ssize_t do_pwritev(unsigned long fd, const struct iovec __user *vec,
			  unsigned long vlen, loff_t pos, rwf_t flags)
{
	ssize_t ret = -EBADF;

	if (pos < 0)
		return -EINVAL;

	CLASS(fd, f)(fd);
	if (!fd_empty(f)) {
		ret = -ESPIPE;
		if (fd_file(f)->f_mode & FMODE_PWRITE)
			ret = vfs_writev(fd_file(f), vec, vlen, &pos, flags);
	}

	if (ret > 0)
		add_wchar(current, ret);
	inc_syscw(current);
	return ret;
}

/**
 * sys_readv - Read data from a file into multiple buffers (scatter read)
 * @fd: File descriptor to read from
 * @vec: Pointer to array of iovec structures describing buffers
 * @vlen: Number of iovec structures in the array
 *
 * long-desc: Performs scatter input by reading data from the file descriptor
 *   fd into multiple buffers specified by the iovec array vec. This syscall
 *   reads iovcnt buffers from the file associated with fd into the buffers
 *   described by vec, processing them in order from vec[0] to vec[vlen-1].
 *   Each iovec structure specifies a base address and length for one buffer.
 *
 *   The readv() syscall works like read(2) except that multiple buffers are
 *   filled. The buffers are filled in array order: vec[0] is completely filled
 *   before vec[1], and so on. This allows efficient scatter I/O where data
 *   naturally breaks into multiple non-contiguous memory regions (e.g., a
 *   header and payload in separate buffers).
 *
 *   The data transfer performed by readv() is atomic: the data read appears as
 *   a contiguous block that is not intermingled with reads in other processes.
 *   For seekable files, the read begins at the current file offset, which is
 *   then incremented by the number of bytes read. For non-seekable files
 *   (pipes, sockets, FMODE_STREAM), the file offset is not used.
 *
 *   On Linux, readv() transfers at most MAX_RW_COUNT (approximately 2GB minus
 *   one page) bytes per call, regardless of the total length specified in the
 *   iovec array. Individual iov_len values are clamped to ensure the total
 *   does not exceed this limit. This is transparent to the caller.
 *
 *   The number of bytes read may be less than the total requested if fewer
 *   bytes are available (e.g., near end-of-file), the read was interrupted
 *   by a signal after some data was transferred, or the underlying file type
 *   does not guarantee full reads (pipes, sockets, terminals).
 *
 *   POSIX requires that readv() fail with EINVAL if the sum of iov_len values
 *   overflows ssize_t. Linux prevents this overflow by clamping to MAX_RW_COUNT.
 *   POSIX also permits readv() to fail if iovcnt is <= 0 or > IOV_MAX; Linux
 *   returns 0 for iovcnt == 0 and EINVAL for iovcnt > UIO_MAXIOV (1024).
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, ULONG_MAX
 *   constraint: Must be a valid, open file descriptor with read permission.
 *     The file must have been opened with O_RDONLY or O_RDWR. File descriptors
 *     opened with O_WRONLY, O_PATH, or that have been closed return EBADF.
 *     Standard file descriptors 0 (stdin), 1 (stdout), 2 (stderr) are valid if
 *     open and readable. AT_FDCWD and other special values are not valid.
 *     Despite being unsigned long, values > INT_MAX may fail fdget().
 *
 * param: vec
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must point to a valid, readable user-space array of struct
 *     iovec containing vlen elements. Each iovec structure contains:
 *     - iov_base: pointer to a writable user-space buffer
 *     - iov_len: size of the buffer (must be non-negative when cast to ssize_t)
 *     NULL is valid only when vlen is 0 (returns 0 immediately). Each iov_base
 *     must pass access_ok() validation; invalid addresses return EFAULT.
 *     On compat syscalls (32-bit process on 64-bit kernel), the iovec structure
 *     uses compat_uptr_t and compat_size_t for its members.
 *
 * param: vlen
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, UIO_MAXIOV
 *   constraint: Number of iovec structures in vec array. Must be <= UIO_MAXIOV
 *     (1024); values > 1024 return EINVAL. A value of 0 returns 0 immediately
 *     without reading any data or accessing the file (but fd must still be
 *     valid). For vlen <= UIO_FASTIOV (8), the iovec array is copied to a
 *     stack buffer; larger arrays require heap allocation which may fail with
 *     ENOMEM under memory pressure.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_RANGE
 *   success: >= 0
 *   desc: On success, returns the number of bytes read (non-negative). Zero
 *     indicates end-of-file (EOF) for regular files, no data available from
 *     a non-blocking device, or vlen was 0. The return value may be less than
 *     the total requested if fewer bytes were available (short read). Partial
 *     reads are not errors and buffers may be partially filled. On error,
 *     returns a negative error code.
 *
 * error: EBADF, Bad file descriptor
 *   desc: fd is not a valid file descriptor, or fd was not opened for reading.
 *     This includes file descriptors opened with O_WRONLY, O_PATH, or file
 *     descriptors that have been closed. Also returned if the file structure
 *     does not have FMODE_READ set.
 *
 * error: EFAULT, Bad address
 *   desc: vec points outside the accessible address space, or one of the
 *     iov_base pointers in the iovec array points to invalid memory. The
 *     validation occurs via access_ok() in import_iovec() before any read
 *     operation. Can also occur if copy_from_user() fails when reading the
 *     iovec array itself, or copy_to_user() fails during data transfer.
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned in several cases: (1) vlen exceeds UIO_MAXIOV (1024).
 *     (2) An iov_len value, when cast to ssize_t, is negative (indicating the
 *     user passed an excessively large unsigned value). (3) The file does not
 *     support reading (FMODE_CAN_READ not set). (4) The file was opened with
 *     O_DIRECT and alignment requirements are not met. (5) For special files
 *     that require specific buffer sizes (e.g., timerfd requires 8 bytes).
 *
 * error: ENOMEM, Out of memory
 *   desc: Memory allocation failed when vlen > UIO_FASTIOV (8). For small
 *     iovec arrays (<= 8 elements), a stack-allocated buffer is used, avoiding
 *     this error. Larger arrays require kmalloc_array() which can fail under
 *     memory pressure. Rare in practice on systems with adequate memory.
 *
 * error: EISDIR, Is a directory
 *   desc: fd refers to a directory. Directories cannot be read using readv();
 *     use getdents64() instead. This error is returned by the generic_read_dir()
 *     handler installed for directory file operations.
 *
 * error: EAGAIN, Resource temporarily unavailable
 *   desc: fd refers to a file (pipe, socket, device) that is marked non-blocking
 *     (O_NONBLOCK) and the read would block because no data is available.
 *     Equivalent to EWOULDBLOCK. The application should retry later or use
 *     select/poll/epoll to wait for data availability.
 *
 * error: EINTR, Interrupted system call
 *   desc: The call was interrupted by a signal before any data was read. This
 *     only occurs if no data has been transferred; if some data was read before
 *     the signal, the call returns the number of bytes read. The caller should
 *     typically check for this error and restart the read.
 *
 * error: EIO, Input/output error
 *   desc: A low-level I/O error occurred. For regular files, this typically
 *     indicates a hardware error on the storage device, a filesystem error,
 *     or a network filesystem timeout. For terminals, this may indicate the
 *     controlling terminal has been closed for a background process.
 *
 * error: EOVERFLOW, Value too large for defined data type
 *   desc: The file position plus total count would exceed LLONG_MAX. Also
 *     returned when reading from certain special files where the position would
 *     overflow. For files without FOP_UNSIGNED_OFFSET, negative positions are
 *     not allowed after the operation would complete.
 *
 * error: EACCES, Permission denied
 *   desc: The security subsystem (LSM such as SELinux or AppArmor) denied
 *     the read operation via security_file_permission(). This can occur even
 *     if the file was successfully opened, as LSM policies may enforce per-
 *     operation checks. The specific policy that denied access may be logged.
 *
 * error: EPERM, Operation not permitted
 *   desc: Returned by fanotify permission events (CONFIG_FANOTIFY_ACCESS_PERMISSIONS)
 *     when a user-space fanotify listener denies the read operation via
 *     fsnotify_file_area_perm(). This allows user-space HSM or antivirus
 *     programs to block reads.
 *
 * error: ERESTARTSYS, Restart system call (internal)
 *   desc: Internal error code indicating the syscall should be restarted. This
 *     is typically translated to EINTR if SA_RESTART is not set on the signal
 *     handler, or the syscall is transparently restarted if SA_RESTART is set.
 *     User space should not see this error code directly.
 *
 * error: ENOBUFS, No buffer space available
 *   desc: Returned when reading from pipe-based watch queues (CONFIG_WATCH_QUEUE)
 *     when the buffer is too small to hold a complete notification, or when
 *     reading packets from pipes with PIPE_BUF_FLAG_WHOLE set.
 *
 * lock: file->f_pos_lock
 *   type: KAPI_LOCK_MUTEX
 *   acquired: conditional
 *   released: true
 *   desc: For regular files that require atomic position updates (FMODE_ATOMIC_POS),
 *     the f_pos_lock mutex is acquired by fdget_pos() at syscall entry and released
 *     by fdput_pos() at syscall exit. This serializes concurrent readv() calls that
 *     share the same file description. Not acquired for stream files (FMODE_STREAM
 *     such as pipes, sockets) or when the file is not shared between threads.
 *
 * lock: Filesystem-specific locks
 *   type: KAPI_LOCK_CUSTOM
 *   acquired: conditional
 *   released: true
 *   desc: The filesystem's read_iter or read method may acquire additional locks.
 *     For regular files, this typically includes the inode's i_rwsem for certain
 *     operations. For pipes, the pipe->mutex is acquired. For sockets, socket
 *     lock is acquired. These are internal to the file operation and released
 *     before return.
 *
 * lock: RCU read-side
 *   type: KAPI_LOCK_RCU
 *   acquired: conditional
 *   released: true
 *   desc: Used during file descriptor lookup via fdget_pos(). RCU read lock
 *     protects access to the file descriptor table. Released by fdput_pos()
 *     at syscall exit.
 *
 * signal: Any signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: When blocked waiting for data on interruptible operations
 *   desc: The syscall may be interrupted by signals while waiting for data to
 *     become available (pipes, sockets, terminals) or waiting for locks. If
 *     interrupted before any data is read, returns -EINTR or -ERESTARTSYS.
 *     If data has already been read, returns the number of bytes read.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_FILE_POSITION
 *   target: file->f_pos
 *   condition: For seekable files when read succeeds (returns > 0)
 *   desc: The file offset (f_pos) is advanced by the number of bytes read.
 *     For stream files (FMODE_STREAM such as pipes and sockets), the offset
 *     is not used or modified. The offset update is protected by f_pos_lock
 *     when the file is shared between threads/processes.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: inode access time (atime)
 *   condition: When read succeeds and O_NOATIME is not set
 *   desc: Updates the file's access time (atime) via touch_atime(). The update
 *     may be suppressed by mount options (noatime, relatime), the O_NOATIME
 *     flag, or if the filesystem does not support atime. Relatime only updates
 *     atime if it is older than mtime or ctime, or more than a day old.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task I/O accounting
 *   condition: Always (after read attempt)
 *   desc: Updates the current task's I/O accounting statistics. The rchar field
 *     (read characters) is incremented by bytes read via add_rchar(). The syscr
 *     field (syscall read count) is incremented via inc_syscr(). These statistics
 *     are visible in /proc/[pid]/io. Updated regardless of success or failure
 *     (syscr always incremented, rchar only on successful reads).
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify events
 *   condition: When read returns >= 0
 *   desc: Generates an FS_ACCESS fsnotify event via fsnotify_access() allowing
 *     inotify, fanotify, and dnotify watchers to be notified of the read. This
 *     occurs after data transfer completes successfully.
 *   reversible: no
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass discretionary access control on read permission
 *   without: Standard DAC checks are enforced
 *   condition: Checked via security_file_permission() during rw_verify_area()
 *
 * capability: CAP_DAC_READ_SEARCH
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass read permission checks on regular files
 *   without: Must have read permission on file
 *   condition: Checked by LSM hooks during the read operation
 *
 * constraint: UIO_MAXIOV limit
 *   desc: The vlen parameter must not exceed UIO_MAXIOV (1024). This limit is
 *     defined by POSIX (IOV_MAX) and prevents excessive memory allocation for
 *     the iovec array. Historical Linux kernels (2.0) had a limit of 16.
 *   expr: vlen <= 1024
 *
 * constraint: MAX_RW_COUNT limit
 *   desc: The total bytes to read (sum of all iov_len values) is clamped to
 *     MAX_RW_COUNT (INT_MAX & PAGE_MASK, approximately 2GB minus one page) to
 *     prevent integer overflow in internal calculations. This is transparent
 *     to the caller; individual iov_len values are truncated as needed.
 *   expr: actual_total = min(sum(iov_len), MAX_RW_COUNT)
 *
 * constraint: File must be open for reading
 *   desc: The file descriptor must have been opened with O_RDONLY or O_RDWR.
 *     Files opened with O_WRONLY or O_PATH cannot be read and return EBADF.
 *     The file must have both FMODE_READ and FMODE_CAN_READ flags set.
 *   expr: (file->f_mode & FMODE_READ) && (file->f_mode & FMODE_CAN_READ)
 *
 * examples: n = readv(fd, iov, 3);  // Read into 3 buffers
 *   struct iovec iov[2] = {{header, sizeof(header)}, {payload, payload_len}};
 *   n = readv(sockfd, iov, 2);  // Scatter read from socket
 *   while ((n = readv(fd, iov, iovcnt)) > 0) { process(iov, n); }  // Read loop
 *
 * notes: readv() is particularly useful when data has a known structure with
 *   a header and payload, or when reassembling fragmented data into a single
 *   logical record. Common use cases include:
 *
 *   - Network protocols: Reading a fixed-size header into one buffer and
 *     variable-length payload into another.
 *
 *   - Database systems: Reading a record header and data fields separately.
 *
 *   - Multimedia: Reading metadata and sample data into separate buffers.
 *
 *   The atomic nature of readv() ensures that for regular files, the entire
 *   operation uses a single file position snapshot, preventing interleaving
 *   with concurrent operations on the same file description.
 *
 *   For optimal performance with small iovec counts (<= 8), readv() uses a
 *   stack-allocated buffer, avoiding heap allocation overhead. For larger
 *   counts, consider whether the overhead is justified.
 *
 *   When reading from pipes or sockets, the scatter behavior allows efficient
 *   protocol parsing without copying data. However, short reads are common;
 *   the caller must handle partial fills across the iovec array.
 *
 *   Related syscalls: preadv() combines readv() with positioned read (like
 *   pread()), preadv2() adds flags for per-operation control (RWF_HIPRI,
 *   RWF_NOWAIT, etc.), and process_vm_readv() reads from another process.
 *
 * since-version: 2.0
 */
SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	return do_readv(fd, vec, vlen, 0);
}

/**
 * sys_writev - Write data from multiple buffers to a file (gather write)
 * @fd: File descriptor to write to
 * @vec: Pointer to array of iovec structures describing buffers
 * @vlen: Number of iovec structures in the array
 *
 * long-desc: Performs gather output by writing data from multiple buffers
 *   specified by the iovec array vec to the file descriptor fd. This syscall
 *   writes vlen buffers from the buffers described by vec to the file
 *   associated with fd, processing them in order from vec[0] to vec[vlen-1].
 *   Each iovec structure specifies a base address and length for one buffer.
 *
 *   The writev() syscall works like write(2) except that multiple buffers are
 *   written. The buffers are processed in array order: all of vec[0] is written
 *   before vec[1], and so on. This allows efficient gather I/O where data
 *   naturally resides in multiple non-contiguous memory regions (e.g., a
 *   protocol header and payload in separate buffers).
 *
 *   The data transfer performed by writev() is atomic with respect to other
 *   writes: the data written appears as a contiguous block that is not
 *   intermingled with writes from other processes or threads. For seekable
 *   files, the write begins at the current file offset, which is then
 *   incremented by the number of bytes written. For non-seekable files
 *   (pipes, sockets, FMODE_STREAM), the file offset is not used.
 *
 *   On Linux, writev() transfers at most MAX_RW_COUNT (approximately 2GB minus
 *   one page) bytes per call, regardless of the total length specified in the
 *   iovec array. Individual iov_len values are clamped to ensure the total
 *   does not exceed this limit. This is transparent to the caller.
 *
 *   The number of bytes written may be less than the total requested if the
 *   disk becomes full, the process hits its resource limits (RLIMIT_FSIZE),
 *   the write was interrupted by a signal after some data was transferred,
 *   or the underlying file type does not guarantee full writes (pipes,
 *   sockets, terminals, non-blocking devices).
 *
 *   Unlike read operations, writes to regular files may modify multiple
 *   file metadata attributes: modification time (mtime), change time (ctime),
 *   and may clear the setuid/setgid bits if the file has them set.
 *
 *   POSIX requires that writev() fail with EINVAL if the sum of iov_len values
 *   overflows ssize_t. Linux prevents this overflow by clamping to MAX_RW_COUNT.
 *   POSIX also permits writev() to fail if iovcnt is <= 0 or > IOV_MAX; Linux
 *   returns 0 for iovcnt == 0 and EINVAL for iovcnt > UIO_MAXIOV (1024).
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, ULONG_MAX
 *   constraint: Must be a valid, open file descriptor with write permission.
 *     The file must have been opened with O_WRONLY, O_RDWR, or O_APPEND.
 *     File descriptors opened with O_RDONLY, O_PATH, or that have been closed
 *     return EBADF. Standard file descriptors 0 (stdin), 1 (stdout), 2 (stderr)
 *     are valid if open and writable. AT_FDCWD and other special values are
 *     not valid. Despite being unsigned long, values > INT_MAX may fail fdget().
 *
 * param: vec
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must point to a valid, readable user-space array of struct
 *     iovec containing vlen elements. Each iovec structure contains:
 *     - iov_base: pointer to a readable user-space buffer containing data
 *     - iov_len: size of the buffer (must be non-negative when cast to ssize_t)
 *     NULL is valid only when vlen is 0 (returns 0 immediately). Each iov_base
 *     must pass access_ok() validation; invalid addresses return EFAULT.
 *     On compat syscalls (32-bit process on 64-bit kernel), the iovec structure
 *     uses compat_uptr_t and compat_size_t for its members.
 *
 * param: vlen
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, UIO_MAXIOV
 *   constraint: Number of iovec structures in vec array. Must be <= UIO_MAXIOV
 *     (1024); values > 1024 return EINVAL. A value of 0 returns 0 immediately
 *     without writing any data or accessing the file (but fd must still be
 *     valid). For vlen <= UIO_FASTIOV (8), the iovec array is copied to a
 *     stack buffer; larger arrays require heap allocation which may fail with
 *     ENOMEM under memory pressure.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_RANGE
 *   success: >= 0
 *   desc: On success, returns the number of bytes written (non-negative). Zero
 *     indicates that either no data was available to write, the total iov_len
 *     was 0, or vlen was 0. The return value may be less than the total
 *     requested if the disk fills up, RLIMIT_FSIZE is reached, a non-blocking
 *     operation would block, or a signal interrupts after partial write.
 *     Partial writes are not errors; the caller should retry with adjusted
 *     buffers. On error, returns a negative error code.
 *
 * error: EBADF, Bad file descriptor
 *   desc: fd is not a valid file descriptor, or fd was not opened for writing.
 *     This includes file descriptors opened with O_RDONLY, O_PATH, or file
 *     descriptors that have been closed. Also returned if the file structure
 *     does not have FMODE_WRITE set.
 *
 * error: EFAULT, Bad address
 *   desc: vec points outside the accessible address space, or one of the
 *     iov_base pointers in the iovec array points to invalid memory. The
 *     validation occurs via access_ok() in import_iovec() before any write
 *     operation. Can also occur if copy_from_user() fails when reading the
 *     iovec array itself, or copy_from_user() fails during data transfer.
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned in several cases: (1) vlen exceeds UIO_MAXIOV (1024).
 *     (2) An iov_len value, when cast to ssize_t, is negative (indicating the
 *     user passed an excessively large unsigned value). (3) The file does not
 *     support writing (FMODE_CAN_WRITE not set). (4) The file was opened with
 *     O_DIRECT and alignment requirements are not met. (5) For atomic writes
 *     (RWF_ATOMIC via pwritev2), the length is not power of 2 or position is
 *     not aligned. (6) RWF_NOWAIT specified but file doesn't support it.
 *
 * error: ENOMEM, Out of memory
 *   desc: Memory allocation failed when vlen > UIO_FASTIOV (8). For small
 *     iovec arrays (<= 8 elements), a stack-allocated buffer is used, avoiding
 *     this error. Larger arrays require kmalloc_array() which can fail under
 *     memory pressure. Can also occur during page cache allocation for
 *     buffered writes.
 *
 * error: EAGAIN, Resource temporarily unavailable
 *   desc: fd refers to a file (pipe, socket, device) that is marked non-blocking
 *     (O_NONBLOCK) and the write would block because the output buffer is full
 *     or the resource is temporarily unavailable. Equivalent to EWOULDBLOCK.
 *     Also returned if RWF_NOWAIT is used and the write would block. The
 *     application should retry later or use select/poll/epoll to wait.
 *
 * error: EINTR, Interrupted system call
 *   desc: The call was interrupted by a signal before any data was written. This
 *     only occurs if no data has been transferred; if some data was written
 *     before the signal, the call returns the number of bytes written. The
 *     caller should typically check for this error and restart the write.
 *
 * error: EIO, Input/output error
 *   desc: A low-level I/O error occurred. For regular files, this typically
 *     indicates a hardware error on the storage device, a filesystem error,
 *     or a network filesystem timeout. May also indicate previous asynchronous
 *     write errors being reported synchronously.
 *
 * error: ENOSPC, No space left on device
 *   desc: The device containing the file has no room for the data. For regular
 *     files, this indicates the filesystem is full. For tmpfs/ramfs, this
 *     indicates memory exhaustion. Partial writes may have occurred before
 *     hitting this condition; check the return value.
 *
 * error: EDQUOT, Disk quota exceeded
 *   desc: The user's disk quota for the filesystem has been exhausted. This
 *     can occur even if the filesystem has free space. Quota limits are
 *     per-user or per-group depending on filesystem configuration.
 *
 * error: EFBIG, File too large
 *   desc: An attempt was made to write data that would cause the file size to
 *     exceed the implementation-defined maximum file size (s_maxbytes) or the
 *     process's file size limit (RLIMIT_FSIZE). For files not opened with
 *     O_LARGEFILE, the limit is 2GB (MAX_NON_LFS). When RLIMIT_FSIZE is hit,
 *     SIGXFSZ is also sent to the process.
 *
 * error: EPIPE, Broken pipe
 *   desc: fd refers to a pipe or socket whose reading end has been closed.
 *     When this occurs, SIGPIPE is also sent to the calling process unless
 *     the MSG_NOSIGNAL flag is used (for sockets) or SIGPIPE is blocked.
 *     Commonly encountered when writing to a closed network connection.
 *
 * error: EOVERFLOW, Value too large for defined data type
 *   desc: The file position plus total count would exceed LLONG_MAX. Also
 *     returned when writing to certain special files where the position would
 *     overflow. For files without FOP_UNSIGNED_OFFSET, negative positions are
 *     not allowed after the operation would complete.
 *
 * error: EACCES, Permission denied
 *   desc: The security subsystem (LSM such as SELinux or AppArmor) denied
 *     the write operation via security_file_permission(). This can occur even
 *     if the file was successfully opened, as LSM policies may enforce per-
 *     operation checks. The specific policy that denied access may be logged.
 *
 * error: EPERM, Operation not permitted
 *   desc: Returned in several cases: (1) fanotify permission events when a
 *     user-space listener denies the write via fsnotify_file_area_perm().
 *     (2) Attempting to write to a file with the immutable attribute (chattr +i).
 *     (3) RWF_NOAPPEND specified on an append-only file (chattr +a).
 *
 * error: EROFS, Read-only file system
 *   desc: The filesystem containing the file is mounted read-only. This can
 *     happen if the filesystem was remounted read-only after the file was
 *     opened, or for inherently read-only filesystems.
 *
 * error: ETXTBSY, Text file busy
 *   desc: An attempt was made to write to a file that is currently being used
 *     as a swap file. This is a specialized check to prevent corruption of
 *     active swap space.
 *
 * error: ERESTARTSYS, Restart system call (internal)
 *   desc: Internal error code indicating the syscall should be restarted. This
 *     is typically translated to EINTR if SA_RESTART is not set on the signal
 *     handler, or the syscall is transparently restarted if SA_RESTART is set.
 *     User space should not see this error code directly.
 *
 * error: EOPNOTSUPP, Operation not supported
 *   desc: The file does not support the requested operation. This can occur
 *     with RWF_* flags via pwritev2() when the file or filesystem doesn't
 *     support the requested behavior (RWF_NOWAIT, RWF_ATOMIC, RWF_DONTCACHE).
 *     Also returned by do_loop_readv_writev() if flags other than RWF_HIPRI
 *     are used with the legacy write() path.
 *
 * lock: file->f_pos_lock
 *   type: KAPI_LOCK_MUTEX
 *   acquired: conditional
 *   released: true
 *   desc: For regular files that require atomic position updates (FMODE_ATOMIC_POS),
 *     the f_pos_lock mutex is acquired by fdget_pos() at syscall entry and released
 *     by fdput_pos() at syscall exit. This serializes concurrent writev() calls that
 *     share the same file description. Not acquired for stream files (FMODE_STREAM
 *     such as pipes, sockets) or when the file is not shared between threads.
 *
 * lock: sb_writers (freeze protection)
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: conditional
 *   released: true
 *   desc: For regular files, file_start_write() acquires the superblock's write
 *     freeze protection (SB_FREEZE_WRITE level) via sb_start_write(). This prevents
 *     the filesystem from being frozen while a write is in progress. Released by
 *     file_end_write() after the write completes. Not acquired for non-regular
 *     files (pipes, sockets, devices, directories).
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: conditional
 *   released: true
 *   desc: The filesystem's write_iter method typically acquires the inode's
 *     i_rwsem for exclusive access during writes. For generic_file_write_iter(),
 *     this is acquired via inode_lock(). Provides serialization against other
 *     writes and certain reads (e.g., direct I/O). Some filesystems may use
 *     different locking strategies.
 *
 * lock: Filesystem-specific locks
 *   type: KAPI_LOCK_CUSTOM
 *   acquired: conditional
 *   released: true
 *   desc: The filesystem's write_iter or write method may acquire additional locks.
 *     For pipes, the pipe->mutex is acquired. For sockets, the socket lock is
 *     acquired. For ext4, the i_data_sem may be acquired for extent manipulation.
 *     These are internal to the file operation and released before return.
 *
 * lock: RCU read-side
 *   type: KAPI_LOCK_RCU
 *   acquired: conditional
 *   released: true
 *   desc: Used during file descriptor lookup via fdget_pos(). RCU read lock
 *     protects access to the file descriptor table. Released by fdput_pos()
 *     at syscall exit.
 *
 * signal: SIGXFSZ
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_TERMINATE
 *   condition: When write would exceed RLIMIT_FSIZE
 *   desc: If the write would cause the file to exceed the process's file size
 *     limit (RLIMIT_FSIZE), the kernel sends SIGXFSZ to the process before
 *     returning EFBIG. The default action is to terminate the process. If the
 *     signal is caught or ignored, the syscall returns EFBIG.
 *   timing: KAPI_SIGNAL_TIME_BEFORE
 *
 * signal: SIGPIPE
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_TERMINATE
 *   condition: When writing to a pipe or socket with no readers
 *   desc: When writing to a pipe or socket whose reading end has been closed,
 *     the kernel sends SIGPIPE to the process. The default action terminates
 *     the process. If SIGPIPE is blocked, caught, or ignored, the syscall
 *     returns EPIPE instead. For sockets, MSG_NOSIGNAL prevents SIGPIPE.
 *   error: -EPIPE
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * signal: Any signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: When blocked waiting for buffer space or locks
 *   desc: The syscall may be interrupted by signals while waiting for buffer
 *     space (pipes, sockets), waiting for locks, or during slow I/O. If
 *     interrupted before any data is written, returns -EINTR or -ERESTARTSYS.
 *     If data has already been written, returns the number of bytes written.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_FILE_POSITION
 *   target: file->f_pos
 *   condition: For seekable files when write succeeds (returns > 0)
 *   desc: The file offset (f_pos) is advanced by the number of bytes written.
 *     For stream files (FMODE_STREAM such as pipes and sockets), the offset
 *     is not used or modified. For O_APPEND files, the position is first set
 *     to the end of file before writing. The offset update is protected by
 *     f_pos_lock when the file is shared between threads/processes.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: inode timestamps (mtime, ctime)
 *   condition: When write succeeds and modifies file content
 *   desc: Updates the file's modification time (mtime) and change time (ctime)
 *     via file_update_time(). The update may be delayed by lazytime mount
 *     option or filesystem-specific behaviors. For O_NOATIME files, only
 *     mtime/ctime are updated, not atime.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: inode SUID/SGID bits
 *   condition: When writing to a setuid/setgid file by non-root
 *   desc: For security, writing to a file clears its setuid bit and (if the
 *     writer is not in the file's group) the setgid bit via file_remove_privs().
 *     This prevents creating setuid/setgid executables through modification.
 *     The check uses dentry_needs_remove_privs() and notify_change().
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task I/O accounting
 *   condition: Always (after write attempt)
 *   desc: Updates the current task's I/O accounting statistics. The wchar field
 *     (write characters) is incremented by bytes written via add_wchar(). The
 *     syscw field (syscall write count) is incremented via inc_syscw(). These
 *     statistics are visible in /proc/[pid]/io. Updated regardless of success
 *     or failure (syscw always incremented, wchar only on successful writes).
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify events
 *   condition: When write returns > 0
 *   desc: Generates an FS_MODIFY fsnotify event via fsnotify_modify() allowing
 *     inotify, fanotify, and dnotify watchers to be notified of the write. This
 *     occurs after data transfer completes successfully.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: file content and size
 *   condition: When write succeeds
 *   desc: The file's content is modified with the data from the iovec buffers.
 *     If writing beyond the current end-of-file, the file size is extended.
 *     For buffered I/O, data may be written to page cache first and flushed
 *     later. For O_DIRECT or O_SYNC files, data is written synchronously.
 *   reversible: no
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass discretionary access control on write permission
 *   without: Standard DAC checks are enforced
 *   condition: Checked via security_file_permission() during rw_verify_area()
 *
 * capability: CAP_FOWNER
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass permission checks for file modification operations
 *   without: Must be file owner for certain operations
 *   condition: Checked when clearing SUID/SGID bits via file_remove_privs()
 *
 * constraint: UIO_MAXIOV limit
 *   desc: The vlen parameter must not exceed UIO_MAXIOV (1024). This limit is
 *     defined by POSIX (IOV_MAX) and prevents excessive memory allocation for
 *     the iovec array. Historical Linux kernels (2.0) had a limit of 16.
 *   expr: vlen <= 1024
 *
 * constraint: MAX_RW_COUNT limit
 *   desc: The total bytes to write (sum of all iov_len values) is clamped to
 *     MAX_RW_COUNT (INT_MAX & PAGE_MASK, approximately 2GB minus one page) to
 *     prevent integer overflow in internal calculations. This is transparent
 *     to the caller; individual iov_len values are truncated as needed.
 *   expr: actual_total = min(sum(iov_len), MAX_RW_COUNT)
 *
 * constraint: RLIMIT_FSIZE limit
 *   desc: The write is limited by the process's soft RLIMIT_FSIZE resource
 *     limit. If the current file position plus bytes to write exceeds this
 *     limit, the write is truncated to the limit boundary and SIGXFSZ may be
 *     sent. If the position already exceeds the limit, EFBIG is returned
 *     immediately with SIGXFSZ sent.
 *   expr: pos + count <= rlimit(RLIMIT_FSIZE) || rlimit(RLIMIT_FSIZE) == RLIM_INFINITY
 *
 * constraint: File must be open for writing
 *   desc: The file descriptor must have been opened with O_WRONLY or O_RDWR.
 *     Files opened with O_RDONLY or O_PATH cannot be written and return EBADF.
 *     The file must have both FMODE_WRITE and FMODE_CAN_WRITE flags set.
 *   expr: (file->f_mode & FMODE_WRITE) && (file->f_mode & FMODE_CAN_WRITE)
 *
 * examples: n = writev(fd, iov, 3);  // Write from 3 buffers
 *   struct iovec iov[2] = {{header, hdr_len}, {payload, payload_len}};
 *   n = writev(sockfd, iov, 2);  // Gather write to socket
 *   while (remaining > 0 && (n = writev(fd, iov, iovcnt)) > 0) { adjust(iov, n); }
 *
 * notes: writev() is particularly useful when data has a known structure with
 *   a header and payload, or when sending protocol messages without copying.
 *   Common use cases include:
 *
 *   - Network protocols: Writing a fixed-size header from one buffer and
 *     variable-length payload from another without copying into a single buffer.
 *
 *   - Database systems: Writing a record header and data fields separately.
 *
 *   - Logging systems: Writing timestamp, level, and message from separate buffers.
 *
 *   The atomic nature of writev() ensures that for regular files, the entire
 *   operation uses a single file position snapshot, preventing interleaving
 *   with concurrent operations on the same file description.
 *
 *   For optimal performance with small iovec counts (<= 8), writev() uses a
 *   stack-allocated buffer (UIO_FASTIOV), avoiding heap allocation overhead.
 *   For larger counts, consider whether the overhead is justified.
 *
 *   Unlike read operations, writes may fail mid-transfer due to disk full or
 *   quota exhaustion. Always check the return value and be prepared to handle
 *   partial writes by adjusting the iovec array and retrying.
 *
 *   For pipes and FIFOs, writes of PIPE_BUF (typically 4096) bytes or less are
 *   guaranteed to be atomic. Larger writes may be interleaved with other writers.
 *
 *   Related syscalls: pwritev() combines writev() with positioned write (like
 *   pwrite()), pwritev2() adds flags for per-operation control (RWF_DSYNC,
 *   RWF_SYNC, RWF_APPEND, RWF_NOWAIT, RWF_ATOMIC), and process_vm_writev()
 *   writes to another process's address space.
 *
 * since-version: 2.0
 */
SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	return do_writev(fd, vec, vlen, 0);
}

/**
 * sys_preadv - Read data from a file at a given offset into multiple buffers
 * @fd: File descriptor to read from
 * @vec: Pointer to array of iovec structures describing destination buffers
 * @vlen: Number of iovec structures in the array
 * @pos_l: Low 32 bits of the file offset at which to begin reading
 * @pos_h: High 32 bits of the file offset (combined with pos_l for 64-bit offset)
 *
 * long-desc: Performs positioned scatter input by reading data from the file
 *   descriptor fd at the specified offset into multiple buffers specified by
 *   the iovec array vec. This syscall combines the functionality of pread(2)
 *   (positioned read) and readv(2) (scatter I/O), allowing vectored I/O at an
 *   explicit file position.
 *
 *   The file offset argument is split into two 32-bit parts (pos_l and pos_h)
 *   which are combined to form a 64-bit offset: ((pos_h << 32) | pos_l) on
 *   64-bit architectures, or ((pos_h << HALF_LONG_BITS) << HALF_LONG_BITS) | pos_l
 *   on 32-bit architectures. This encoding allows 64-bit offsets to be passed
 *   through the syscall interface on all architectures.
 *
 *   The buffers are processed in array order: vec[0] is completely filled
 *   before vec[1], and so on. Each iovec structure specifies a base address
 *   (iov_base) and length (iov_len) for one buffer. The data transfer is atomic
 *   with respect to other processes: the data read appears as a contiguous
 *   block that is not intermingled with reads from other processes.
 *
 *   Unlike readv(), preadv() does NOT update the file offset (f_pos). The read
 *   occurs at the specified position, and the current file position remains
 *   unchanged. This makes preadv() inherently thread-safe: multiple threads
 *   can read from different positions in the same file descriptor concurrently
 *   without interfering with each other.
 *
 *   The file referred to by fd must support positioned reads (FMODE_PREAD flag).
 *   Regular files, block devices, and most character devices support this.
 *   Pipes, FIFOs, sockets, and terminals do NOT support positioned reads and
 *   return ESPIPE. For such files, use readv() instead.
 *
 *   On Linux, preadv() transfers at most MAX_RW_COUNT (approximately 2GB minus
 *   one page) bytes per call, regardless of the total length specified in the
 *   iovec array. Individual iov_len values are clamped to ensure the total
 *   does not exceed this limit. This is transparent to the caller.
 *
 *   The number of bytes read may be less than the total requested if fewer
 *   bytes are available (e.g., near end-of-file), the read was interrupted
 *   by a signal after some data was transferred, or the underlying file type
 *   does not guarantee full reads.
 *
 *   preadv() was introduced in Linux 2.6.30 and is not part of POSIX, though
 *   it is available on BSD systems. For additional per-operation control flags,
 *   use preadv2() which extends preadv() with a flags argument.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, ULONG_MAX
 *   constraint: Must be a valid, open file descriptor with read permission.
 *     The file must have been opened with O_RDONLY or O_RDWR. Additionally,
 *     the file must support positioned reads (FMODE_PREAD flag set). Regular
 *     files and block devices support positioned reads; pipes, FIFOs, sockets,
 *     and terminals do not. File descriptors opened with O_WRONLY, O_PATH, or
 *     that have been closed return EBADF. Standard file descriptors 0 (stdin),
 *     1 (stdout), 2 (stderr) are valid if open and readable, though stdin may
 *     not support preadv if connected to a terminal or pipe. AT_FDCWD and other
 *     special directory values are not valid. Despite being unsigned long,
 *     values > INT_MAX may fail fdget().
 *
 * param: vec
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must point to a valid, readable user-space array of struct
 *     iovec containing vlen elements. Each iovec structure contains:
 *     - iov_base: pointer to a writable user-space buffer
 *     - iov_len: size of the buffer (must be non-negative when cast to ssize_t)
 *     NULL is valid only when vlen is 0 (returns 0 immediately). Each iov_base
 *     must pass access_ok() validation; invalid addresses return EFAULT.
 *     On compat syscalls (32-bit process on 64-bit kernel), the iovec structure
 *     uses compat_uptr_t and compat_size_t for its members.
 *
 * param: vlen
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, UIO_MAXIOV
 *   constraint: Number of iovec structures in vec array. Must be <= UIO_MAXIOV
 *     (1024); values > 1024 return EINVAL. A value of 0 returns 0 immediately
 *     without reading any data or accessing the file (but fd must still be
 *     valid). For vlen <= UIO_FASTIOV (8), the iovec array is copied to a
 *     stack buffer; larger arrays require heap allocation which may fail with
 *     ENOMEM under memory pressure.
 *
 * param: pos_l
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, ULONG_MAX
 *   constraint: Low bits of the 64-bit file offset. On 64-bit systems, this is
 *     the lower half of the 64-bit offset (bits 0-31). On 32-bit systems with
 *     HALF_LONG_BITS=16, this is the lower 32 bits. Combined with pos_h to form
 *     the complete offset. When the combined offset is negative, EINVAL is
 *     returned.
 *
 * param: pos_h
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, ULONG_MAX
 *   constraint: High bits of the 64-bit file offset. On 64-bit systems, this is
 *     the upper half of the 64-bit offset (bits 32-63). On 32-bit systems, this
 *     is shifted by HALF_LONG_BITS twice. The combined offset (pos_h, pos_l)
 *     must result in a non-negative loff_t value; if the combined value is
 *     negative when interpreted as a signed 64-bit integer, EINVAL is returned.
 *     For most use cases, pos_h should be 0 unless reading beyond 4GB offset.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_RANGE
 *   success: >= 0
 *   desc: On success, returns the number of bytes read (non-negative). Zero
 *     indicates end-of-file (EOF) for regular files, no data available from
 *     a non-blocking device, vlen was 0, or pos is at or beyond the file size.
 *     The return value may be less than the total requested if fewer bytes were
 *     available (short read). Partial reads are not errors and buffers may be
 *     partially filled. On error, returns a negative error code.
 *
 * error: EBADF, Bad file descriptor
 *   desc: fd is not a valid file descriptor, or fd was not opened for reading.
 *     This includes file descriptors opened with O_WRONLY, O_PATH, or file
 *     descriptors that have been closed. Also returned if the file structure
 *     does not have FMODE_READ or FMODE_CAN_READ flags set.
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned in several cases: (1) The combined offset (pos_l, pos_h)
 *     results in a negative value. (2) vlen exceeds UIO_MAXIOV (1024).
 *     (3) An iov_len value, when cast to ssize_t, is negative (indicating the
 *     user passed an excessively large unsigned value). (4) The file does not
 *     support reading (FMODE_CAN_READ not set). (5) The file was opened with
 *     O_DIRECT and alignment requirements are not met. (6) For special files
 *     that require specific buffer sizes (e.g., timerfd requires 8 bytes).
 *     (7) The position plus total count would overflow for files without
 *     unsigned offset support.
 *
 * error: ESPIPE, Illegal seek
 *   desc: The file descriptor refers to a file type that does not support
 *     positioned reads (FMODE_PREAD flag not set). This includes pipes, FIFOs,
 *     sockets, and terminal devices. Use readv() instead for these file types.
 *     This error is checked early, before any buffer validation.
 *
 * error: EFAULT, Bad address
 *   desc: vec points outside the accessible address space, or one of the
 *     iov_base pointers in the iovec array points to invalid memory. The
 *     validation occurs via access_ok() in import_iovec() before any read
 *     operation. Can also occur if copy_from_user() fails when reading the
 *     iovec array itself, or copy_to_user() fails during data transfer.
 *
 * error: ENOMEM, Out of memory
 *   desc: Memory allocation failed when vlen > UIO_FASTIOV (8). For small
 *     iovec arrays (<= 8 elements), a stack-allocated buffer is used, avoiding
 *     this error. Larger arrays require kmalloc_array() which can fail under
 *     memory pressure. Rare in practice on systems with adequate memory.
 *
 * error: EOVERFLOW, Value too large for defined data type
 *   desc: The file position plus total count would exceed LLONG_MAX, causing
 *     arithmetic overflow. This is checked in rw_verify_area() before the read
 *     begins. For files without FOP_UNSIGNED_OFFSET, this also applies if the
 *     position alone would cause issues.
 *
 * error: EISDIR, Is a directory
 *   desc: fd refers to a directory. Directories cannot be read using preadv();
 *     use getdents64() instead. This error is returned by the generic_read_dir()
 *     handler installed for directory file operations.
 *
 * error: EAGAIN, Resource temporarily unavailable
 *   desc: fd refers to a file (device, network filesystem) that is marked
 *     non-blocking (O_NONBLOCK) and the read would block because no data is
 *     available. Equivalent to EWOULDBLOCK. The application should retry later
 *     or use select/poll/epoll to wait for data availability.
 *
 * error: EINTR, Interrupted system call
 *   desc: The call was interrupted by a signal before any data was read. This
 *     only occurs if no data has been transferred; if some data was read before
 *     the signal, the call returns the number of bytes read. The caller should
 *     typically check for this error and restart the read.
 *
 * error: EIO, Input/output error
 *   desc: A low-level I/O error occurred. For regular files, this typically
 *     indicates a hardware error on the storage device, a filesystem error,
 *     or a network filesystem timeout. May also indicate that the page could
 *     not be read from disk (e.g., bad blocks).
 *
 * error: EACCES, Permission denied
 *   desc: The security subsystem (LSM such as SELinux or AppArmor) denied
 *     the read operation via security_file_permission(). This can occur even
 *     if the file was successfully opened, as LSM policies may enforce per-
 *     operation checks. The specific policy that denied access may be logged.
 *
 * error: EPERM, Operation not permitted
 *   desc: Returned by fanotify permission events (CONFIG_FANOTIFY_ACCESS_PERMISSIONS)
 *     when a user-space fanotify listener denies the read operation via
 *     fsnotify_file_area_perm(). This allows user-space HSM or antivirus
 *     programs to block reads.
 *
 * error: ENOBUFS, No buffer space available
 *   desc: Returned when reading from pipe-based watch queues (CONFIG_WATCH_QUEUE)
 *     when the buffer is too small to hold a complete notification, or when
 *     reading packets from pipes with PIPE_BUF_FLAG_WHOLE set.
 *
 * error: ERESTARTSYS, Restart system call (internal)
 *   desc: Internal error code indicating the syscall should be restarted. This
 *     is typically translated to EINTR if SA_RESTART is not set on the signal
 *     handler, or the syscall is transparently restarted if SA_RESTART is set.
 *     User space should not see this error code directly.
 *
 * lock: Filesystem-specific locks
 *   type: KAPI_LOCK_CUSTOM
 *   acquired: conditional
 *   released: true
 *   desc: The filesystem's read_iter or read method may acquire additional locks.
 *     For regular files, this typically includes the inode's i_rwsem (shared mode)
 *     for certain operations, and the mapping's invalidate_lock. For O_DIRECT
 *     reads, additional serialization with page cache may occur. These locks are
 *     internal to the file operation and released before return.
 *
 * lock: RCU read-side
 *   type: KAPI_LOCK_RCU
 *   acquired: conditional
 *   released: true
 *   desc: Used during file descriptor lookup via fdget() (called through the
 *     CLASS(fd, f) macro). RCU read lock protects access to the file descriptor
 *     table. Released by fdput() at the end of the CLASS scope.
 *
 * signal: Any signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: When blocked waiting for data or I/O completion
 *   desc: The syscall may be interrupted by signals while waiting for data to
 *     become available or while waiting for I/O to complete. If interrupted
 *     before any data is read, returns -EINTR or -ERESTARTSYS. If data has
 *     already been read, returns the number of bytes read instead of an error.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: inode access time (atime)
 *   condition: When read succeeds and O_NOATIME is not set
 *   desc: Updates the file's access time (atime) via touch_atime(). The update
 *     may be suppressed by mount options (noatime, relatime), the O_NOATIME
 *     flag, or if the filesystem does not support atime. Relatime only updates
 *     atime if it is older than mtime or ctime, or more than a day old.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task I/O accounting
 *   condition: Always (after read attempt)
 *   desc: Updates the current task's I/O accounting statistics. The rchar field
 *     (read characters) is incremented by bytes read via add_rchar(). The syscr
 *     field (syscall read count) is incremented via inc_syscr(). These statistics
 *     are visible in /proc/[pid]/io. Updated regardless of success or failure
 *     (syscr always incremented, rchar only on successful reads).
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify events
 *   condition: When read returns >= 0
 *   desc: Generates an FS_ACCESS fsnotify event via fsnotify_access() allowing
 *     inotify, fanotify, and dnotify watchers to be notified of the read. This
 *     occurs after data transfer completes successfully.
 *   reversible: no
 *
 * capability: CAP_DAC_OVERRIDE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass discretionary access control on read permission
 *   without: Standard DAC checks are enforced
 *   condition: Checked via security_file_permission() during rw_verify_area()
 *
 * capability: CAP_DAC_READ_SEARCH
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypass read permission checks on regular files
 *   without: Must have read permission on file
 *   condition: Checked by LSM hooks during the read operation
 *
 * constraint: UIO_MAXIOV limit
 *   desc: The vlen parameter must not exceed UIO_MAXIOV (1024). This limit is
 *     defined by POSIX (IOV_MAX) and prevents excessive memory allocation for
 *     the iovec array. Historical Linux kernels (2.0) had a limit of 16.
 *   expr: vlen <= 1024
 *
 * constraint: MAX_RW_COUNT limit
 *   desc: The total bytes to read (sum of all iov_len values) is clamped to
 *     MAX_RW_COUNT (INT_MAX & PAGE_MASK, approximately 2GB minus one page) to
 *     prevent integer overflow in internal calculations. This is transparent
 *     to the caller; individual iov_len values are truncated as needed.
 *   expr: actual_total = min(sum(iov_len), MAX_RW_COUNT)
 *
 * constraint: File must be open for reading
 *   desc: The file descriptor must have been opened with O_RDONLY or O_RDWR.
 *     Files opened with O_WRONLY or O_PATH cannot be read and return EBADF.
 *     The file must have both FMODE_READ and FMODE_CAN_READ flags set.
 *   expr: (file->f_mode & FMODE_READ) && (file->f_mode & FMODE_CAN_READ)
 *
 * constraint: File must support positioned reads
 *   desc: The file must have FMODE_PREAD flag set, indicating it supports
 *     reading at arbitrary positions. Regular files and block devices have
 *     this flag set by default. Pipes, FIFOs, sockets, and terminals do not.
 *     Some device drivers may or may not support positioned reads.
 *   expr: file->f_mode & FMODE_PREAD
 *
 * constraint: Non-negative position
 *   desc: The combined file offset (pos_h << 32 | pos_l) must be non-negative
 *     when interpreted as a signed 64-bit integer (loff_t). Negative offsets
 *     are invalid and return EINVAL. The position is not validated against
 *     file size; reading beyond EOF simply returns 0 bytes.
 *   expr: pos >= 0
 *
 * examples: n = preadv(fd, iov, 3, 4096);  // Read at offset 4096 into 3 buffers
 *   struct iovec iov[2] = {{header, sizeof(header)}, {payload, payload_len}};
 *   n = preadv(fd, iov, 2, record_offset);  // Read record at specific offset
 *   n = preadv(fd, iov, iovcnt, pos_l, pos_h);  // 64-bit offset via split args
 *
 * notes: preadv() is particularly useful in multi-threaded applications where
 *   multiple threads need to read from different positions in the same file
 *   without interfering with each other. Unlike readv() followed by lseek(),
 *   preadv() is atomic with respect to the file position.
 *
 *   Key differences from readv():
 *   - Does NOT update the file position (f_pos) - the specified offset is used
 *   - Requires the file to support positioned reads (FMODE_PREAD)
 *   - No f_pos_lock contention between concurrent preadv() calls
 *
 *   Common use cases include:
 *
 *   - Database systems: Reading records at known offsets without position tracking
 *
 *   - Parallel file processing: Multiple threads reading different regions
 *
 *   - Log file analysis: Reading specific portions without affecting other readers
 *
 *   - File format parsing: Reading headers and data at known offsets
 *
 *   The split offset encoding (pos_l, pos_h) is necessary because some 32-bit
 *   architectures (MIPS, PARISC, ARM, PowerPC) require 64-bit arguments to be
 *   passed in aligned register pairs. The glibc wrapper typically handles this
 *   encoding transparently, providing a single off_t parameter to applications.
 *
 *   For per-call behavior modifications (e.g., RWF_HIPRI for high-priority I/O,
 *   RWF_NOWAIT for non-blocking attempts), use preadv2() which adds a flags
 *   parameter. Note that preadv2() with a position of -1 falls back to readv()
 *   semantics (using and updating the current file position).
 *
 *   Unlike pread(), which reads into a single buffer, preadv() can read into
 *   multiple non-contiguous buffers atomically, making it ideal for reading
 *   structured data with separate header and payload regions.
 *
 * since-version: 2.6.30
 */
SYSCALL_DEFINE5(preadv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
{
	loff_t pos = pos_from_hilo(pos_h, pos_l);

	return do_preadv(fd, vec, vlen, pos, 0);
}

SYSCALL_DEFINE6(preadv2, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h,
		rwf_t, flags)
{
	loff_t pos = pos_from_hilo(pos_h, pos_l);

	if (pos == -1)
		return do_readv(fd, vec, vlen, flags);

	return do_preadv(fd, vec, vlen, pos, flags);
}

SYSCALL_DEFINE5(pwritev, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
{
	loff_t pos = pos_from_hilo(pos_h, pos_l);

	return do_pwritev(fd, vec, vlen, pos, 0);
}

SYSCALL_DEFINE6(pwritev2, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h,
		rwf_t, flags)
{
	loff_t pos = pos_from_hilo(pos_h, pos_l);

	if (pos == -1)
		return do_writev(fd, vec, vlen, flags);

	return do_pwritev(fd, vec, vlen, pos, flags);
}

/*
 * Various compat syscalls.  Note that they all pretend to take a native
 * iovec - import_iovec will properly treat those as compat_iovecs based on
 * in_compat_syscall().
 */
#ifdef CONFIG_COMPAT
#ifdef __ARCH_WANT_COMPAT_SYS_PREADV64
COMPAT_SYSCALL_DEFINE4(preadv64, unsigned long, fd,
		const struct iovec __user *, vec,
		unsigned long, vlen, loff_t, pos)
{
	return do_preadv(fd, vec, vlen, pos, 0);
}
#endif

COMPAT_SYSCALL_DEFINE5(preadv, compat_ulong_t, fd,
		const struct iovec __user *, vec,
		compat_ulong_t, vlen, u32, pos_low, u32, pos_high)
{
	loff_t pos = ((loff_t)pos_high << 32) | pos_low;

	return do_preadv(fd, vec, vlen, pos, 0);
}

#ifdef __ARCH_WANT_COMPAT_SYS_PREADV64V2
COMPAT_SYSCALL_DEFINE5(preadv64v2, unsigned long, fd,
		const struct iovec __user *, vec,
		unsigned long, vlen, loff_t, pos, rwf_t, flags)
{
	if (pos == -1)
		return do_readv(fd, vec, vlen, flags);
	return do_preadv(fd, vec, vlen, pos, flags);
}
#endif

COMPAT_SYSCALL_DEFINE6(preadv2, compat_ulong_t, fd,
		const struct iovec __user *, vec,
		compat_ulong_t, vlen, u32, pos_low, u32, pos_high,
		rwf_t, flags)
{
	loff_t pos = ((loff_t)pos_high << 32) | pos_low;

	if (pos == -1)
		return do_readv(fd, vec, vlen, flags);
	return do_preadv(fd, vec, vlen, pos, flags);
}

#ifdef __ARCH_WANT_COMPAT_SYS_PWRITEV64
COMPAT_SYSCALL_DEFINE4(pwritev64, unsigned long, fd,
		const struct iovec __user *, vec,
		unsigned long, vlen, loff_t, pos)
{
	return do_pwritev(fd, vec, vlen, pos, 0);
}
#endif

COMPAT_SYSCALL_DEFINE5(pwritev, compat_ulong_t, fd,
		const struct iovec __user *,vec,
		compat_ulong_t, vlen, u32, pos_low, u32, pos_high)
{
	loff_t pos = ((loff_t)pos_high << 32) | pos_low;

	return do_pwritev(fd, vec, vlen, pos, 0);
}

#ifdef __ARCH_WANT_COMPAT_SYS_PWRITEV64V2
COMPAT_SYSCALL_DEFINE5(pwritev64v2, unsigned long, fd,
		const struct iovec __user *, vec,
		unsigned long, vlen, loff_t, pos, rwf_t, flags)
{
	if (pos == -1)
		return do_writev(fd, vec, vlen, flags);
	return do_pwritev(fd, vec, vlen, pos, flags);
}
#endif

COMPAT_SYSCALL_DEFINE6(pwritev2, compat_ulong_t, fd,
		const struct iovec __user *,vec,
		compat_ulong_t, vlen, u32, pos_low, u32, pos_high, rwf_t, flags)
{
	loff_t pos = ((loff_t)pos_high << 32) | pos_low;

	if (pos == -1)
		return do_writev(fd, vec, vlen, flags);
	return do_pwritev(fd, vec, vlen, pos, flags);
}
#endif /* CONFIG_COMPAT */

static ssize_t do_sendfile(int out_fd, int in_fd, loff_t *ppos,
			   size_t count, loff_t max)
{
	struct inode *in_inode, *out_inode;
	struct pipe_inode_info *opipe;
	loff_t pos;
	loff_t out_pos;
	ssize_t retval;
	int fl;

	/*
	 * Get input file, and verify that it is ok..
	 */
	CLASS(fd, in)(in_fd);
	if (fd_empty(in))
		return -EBADF;
	if (!(fd_file(in)->f_mode & FMODE_READ))
		return -EBADF;
	if (!ppos) {
		pos = fd_file(in)->f_pos;
	} else {
		pos = *ppos;
		if (!(fd_file(in)->f_mode & FMODE_PREAD))
			return -ESPIPE;
	}
	retval = rw_verify_area(READ, fd_file(in), &pos, count);
	if (retval < 0)
		return retval;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;

	/*
	 * Get output file, and verify that it is ok..
	 */
	CLASS(fd, out)(out_fd);
	if (fd_empty(out))
		return -EBADF;
	if (!(fd_file(out)->f_mode & FMODE_WRITE))
		return -EBADF;
	in_inode = file_inode(fd_file(in));
	out_inode = file_inode(fd_file(out));
	out_pos = fd_file(out)->f_pos;

	if (!max)
		max = min(in_inode->i_sb->s_maxbytes, out_inode->i_sb->s_maxbytes);

	if (unlikely(pos + count > max)) {
		if (pos >= max)
			return -EOVERFLOW;
		count = max - pos;
	}

	fl = 0;
#if 0
	/*
	 * We need to debate whether we can enable this or not. The
	 * man page documents EAGAIN return for the output at least,
	 * and the application is arguably buggy if it doesn't expect
	 * EAGAIN on a non-blocking file descriptor.
	 */
	if (fd_file(in)->f_flags & O_NONBLOCK)
		fl = SPLICE_F_NONBLOCK;
#endif
	opipe = get_pipe_info(fd_file(out), true);
	if (!opipe) {
		retval = rw_verify_area(WRITE, fd_file(out), &out_pos, count);
		if (retval < 0)
			return retval;
		retval = do_splice_direct(fd_file(in), &pos, fd_file(out), &out_pos,
					  count, fl);
	} else {
		if (fd_file(out)->f_flags & O_NONBLOCK)
			fl |= SPLICE_F_NONBLOCK;

		retval = splice_file_to_pipe(fd_file(in), opipe, &pos, count, fl);
	}

	if (retval > 0) {
		add_rchar(current, retval);
		add_wchar(current, retval);
		fsnotify_access(fd_file(in));
		fsnotify_modify(fd_file(out));
		fd_file(out)->f_pos = out_pos;
		if (ppos)
			*ppos = pos;
		else
			fd_file(in)->f_pos = pos;
	}

	inc_syscr(current);
	inc_syscw(current);
	if (pos > max)
		retval = -EOVERFLOW;
	return retval;
}

SYSCALL_DEFINE4(sendfile, int, out_fd, int, in_fd, off_t __user *, offset, size_t, count)
{
	loff_t pos;
	off_t off;
	ssize_t ret;

	if (offset) {
		if (unlikely(get_user(off, offset)))
			return -EFAULT;
		pos = off;
		ret = do_sendfile(out_fd, in_fd, &pos, count, MAX_NON_LFS);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}

SYSCALL_DEFINE4(sendfile64, int, out_fd, int, in_fd, loff_t __user *, offset, size_t, count)
{
	loff_t pos;
	ssize_t ret;

	if (offset) {
		if (unlikely(copy_from_user(&pos, offset, sizeof(loff_t))))
			return -EFAULT;
		ret = do_sendfile(out_fd, in_fd, &pos, count, 0);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(sendfile, int, out_fd, int, in_fd,
		compat_off_t __user *, offset, compat_size_t, count)
{
	loff_t pos;
	off_t off;
	ssize_t ret;

	if (offset) {
		if (unlikely(get_user(off, offset)))
			return -EFAULT;
		pos = off;
		ret = do_sendfile(out_fd, in_fd, &pos, count, MAX_NON_LFS);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}

COMPAT_SYSCALL_DEFINE4(sendfile64, int, out_fd, int, in_fd,
		compat_loff_t __user *, offset, compat_size_t, count)
{
	loff_t pos;
	ssize_t ret;

	if (offset) {
		if (unlikely(copy_from_user(&pos, offset, sizeof(loff_t))))
			return -EFAULT;
		ret = do_sendfile(out_fd, in_fd, &pos, count, 0);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}
#endif

/*
 * Performs necessary checks before doing a file copy
 *
 * Can adjust amount of bytes to copy via @req_count argument.
 * Returns appropriate error code that caller should return or
 * zero in case the copy should be allowed.
 */
static int generic_copy_file_checks(struct file *file_in, loff_t pos_in,
				    struct file *file_out, loff_t pos_out,
				    size_t *req_count, unsigned int flags)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	uint64_t count = *req_count;
	loff_t size_in;
	int ret;

	ret = generic_file_rw_checks(file_in, file_out);
	if (ret)
		return ret;

	/*
	 * We allow some filesystems to handle cross sb copy, but passing
	 * a file of the wrong filesystem type to filesystem driver can result
	 * in an attempt to dereference the wrong type of ->private_data, so
	 * avoid doing that until we really have a good reason.
	 *
	 * nfs and cifs define several different file_system_type structures
	 * and several different sets of file_operations, but they all end up
	 * using the same ->copy_file_range() function pointer.
	 */
	if (flags & COPY_FILE_SPLICE) {
		/* cross sb splice is allowed */
	} else if (file_out->f_op->copy_file_range) {
		if (file_in->f_op->copy_file_range !=
		    file_out->f_op->copy_file_range)
			return -EXDEV;
	} else if (file_inode(file_in)->i_sb != file_inode(file_out)->i_sb) {
		return -EXDEV;
	}

	/* Don't touch certain kinds of inodes */
	if (IS_IMMUTABLE(inode_out))
		return -EPERM;

	if (IS_SWAPFILE(inode_in) || IS_SWAPFILE(inode_out))
		return -ETXTBSY;

	/* Ensure offsets don't wrap. */
	if (pos_in + count < pos_in || pos_out + count < pos_out)
		return -EOVERFLOW;

	/* Shorten the copy to EOF */
	size_in = i_size_read(inode_in);
	if (pos_in >= size_in)
		count = 0;
	else
		count = min(count, size_in - (uint64_t)pos_in);

	ret = generic_write_check_limits(file_out, pos_out, &count);
	if (ret)
		return ret;

	/* Don't allow overlapped copying within the same file. */
	if (inode_in == inode_out &&
	    pos_out + count > pos_in &&
	    pos_out < pos_in + count)
		return -EINVAL;

	*req_count = count;
	return 0;
}

/*
 * copy_file_range() differs from regular file read and write in that it
 * specifically allows return partial success.  When it does so is up to
 * the copy_file_range method.
 */
ssize_t vfs_copy_file_range(struct file *file_in, loff_t pos_in,
			    struct file *file_out, loff_t pos_out,
			    size_t len, unsigned int flags)
{
	ssize_t ret;
	bool splice = flags & COPY_FILE_SPLICE;
	bool samesb = file_inode(file_in)->i_sb == file_inode(file_out)->i_sb;

	if (flags & ~COPY_FILE_SPLICE)
		return -EINVAL;

	ret = generic_copy_file_checks(file_in, pos_in, file_out, pos_out, &len,
				       flags);
	if (unlikely(ret))
		return ret;

	ret = rw_verify_area(READ, file_in, &pos_in, len);
	if (unlikely(ret))
		return ret;

	ret = rw_verify_area(WRITE, file_out, &pos_out, len);
	if (unlikely(ret))
		return ret;

	if (len == 0)
		return 0;

	/*
	 * Make sure return value doesn't overflow in 32bit compat mode.  Also
	 * limit the size for all cases except when calling ->copy_file_range().
	 */
	if (splice || !file_out->f_op->copy_file_range || in_compat_syscall())
		len = min_t(size_t, MAX_RW_COUNT, len);

	file_start_write(file_out);

	/*
	 * Cloning is supported by more file systems, so we implement copy on
	 * same sb using clone, but for filesystems where both clone and copy
	 * are supported (e.g. nfs,cifs), we only call the copy method.
	 */
	if (!splice && file_out->f_op->copy_file_range) {
		ret = file_out->f_op->copy_file_range(file_in, pos_in,
						      file_out, pos_out,
						      len, flags);
	} else if (!splice && file_in->f_op->remap_file_range && samesb) {
		ret = file_in->f_op->remap_file_range(file_in, pos_in,
				file_out, pos_out, len, REMAP_FILE_CAN_SHORTEN);
		/* fallback to splice */
		if (ret <= 0)
			splice = true;
	} else if (samesb) {
		/* Fallback to splice for same sb copy for backward compat */
		splice = true;
	}

	file_end_write(file_out);

	if (!splice)
		goto done;

	/*
	 * We can get here for same sb copy of filesystems that do not implement
	 * ->copy_file_range() in case filesystem does not support clone or in
	 * case filesystem supports clone but rejected the clone request (e.g.
	 * because it was not block aligned).
	 *
	 * In both cases, fall back to kernel copy so we are able to maintain a
	 * consistent story about which filesystems support copy_file_range()
	 * and which filesystems do not, that will allow userspace tools to
	 * make consistent desicions w.r.t using copy_file_range().
	 *
	 * We also get here if caller (e.g. nfsd) requested COPY_FILE_SPLICE
	 * for server-side-copy between any two sb.
	 *
	 * In any case, we call do_splice_direct() and not splice_file_range(),
	 * without file_start_write() held, to avoid possible deadlocks related
	 * to splicing from input file, while file_start_write() is held on
	 * the output file on a different sb.
	 */
	ret = do_splice_direct(file_in, &pos_in, file_out, &pos_out, len, 0);
done:
	if (ret > 0) {
		fsnotify_access(file_in);
		add_rchar(current, ret);
		fsnotify_modify(file_out);
		add_wchar(current, ret);
	}

	inc_syscr(current);
	inc_syscw(current);

	return ret;
}
EXPORT_SYMBOL(vfs_copy_file_range);

SYSCALL_DEFINE6(copy_file_range, int, fd_in, loff_t __user *, off_in,
		int, fd_out, loff_t __user *, off_out,
		size_t, len, unsigned int, flags)
{
	loff_t pos_in;
	loff_t pos_out;
	ssize_t ret = -EBADF;

	CLASS(fd, f_in)(fd_in);
	if (fd_empty(f_in))
		return -EBADF;

	CLASS(fd, f_out)(fd_out);
	if (fd_empty(f_out))
		return -EBADF;

	if (off_in) {
		if (copy_from_user(&pos_in, off_in, sizeof(loff_t)))
			return -EFAULT;
	} else {
		pos_in = fd_file(f_in)->f_pos;
	}

	if (off_out) {
		if (copy_from_user(&pos_out, off_out, sizeof(loff_t)))
			return -EFAULT;
	} else {
		pos_out = fd_file(f_out)->f_pos;
	}

	if (flags != 0)
		return -EINVAL;

	ret = vfs_copy_file_range(fd_file(f_in), pos_in, fd_file(f_out), pos_out, len,
				  flags);
	if (ret > 0) {
		pos_in += ret;
		pos_out += ret;

		if (off_in) {
			if (copy_to_user(off_in, &pos_in, sizeof(loff_t)))
				ret = -EFAULT;
		} else {
			fd_file(f_in)->f_pos = pos_in;
		}

		if (off_out) {
			if (copy_to_user(off_out, &pos_out, sizeof(loff_t)))
				ret = -EFAULT;
		} else {
			fd_file(f_out)->f_pos = pos_out;
		}
	}
	return ret;
}

/*
 * Don't operate on ranges the page cache doesn't support, and don't exceed the
 * LFS limits.  If pos is under the limit it becomes a short access.  If it
 * exceeds the limit we return -EFBIG.
 */
int generic_write_check_limits(struct file *file, loff_t pos, loff_t *count)
{
	struct inode *inode = file->f_mapping->host;
	loff_t max_size = inode->i_sb->s_maxbytes;
	loff_t limit = rlimit(RLIMIT_FSIZE);

	if (limit != RLIM_INFINITY) {
		if (pos >= limit) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
		*count = min(*count, limit - pos);
	}

	if (!(file->f_flags & O_LARGEFILE))
		max_size = MAX_NON_LFS;

	if (unlikely(pos >= max_size))
		return -EFBIG;

	*count = min(*count, max_size - pos);

	return 0;
}
EXPORT_SYMBOL_GPL(generic_write_check_limits);

/* Like generic_write_checks(), but takes size of write instead of iter. */
int generic_write_checks_count(struct kiocb *iocb, loff_t *count)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;

	if (IS_SWAPFILE(inode))
		return -ETXTBSY;

	if (!*count)
		return 0;

	if (iocb->ki_flags & IOCB_APPEND)
		iocb->ki_pos = i_size_read(inode);

	if ((iocb->ki_flags & IOCB_NOWAIT) &&
	    !((iocb->ki_flags & IOCB_DIRECT) ||
	      (file->f_op->fop_flags & FOP_BUFFER_WASYNC)))
		return -EINVAL;

	return generic_write_check_limits(iocb->ki_filp, iocb->ki_pos, count);
}
EXPORT_SYMBOL(generic_write_checks_count);

/*
 * Performs necessary checks before doing a write
 *
 * Can adjust writing position or amount of bytes to write.
 * Returns appropriate error code that caller should return or
 * zero in case that write should be allowed.
 */
ssize_t generic_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	loff_t count = iov_iter_count(from);
	int ret;

	ret = generic_write_checks_count(iocb, &count);
	if (ret)
		return ret;

	iov_iter_truncate(from, count);
	return iov_iter_count(from);
}
EXPORT_SYMBOL(generic_write_checks);

/*
 * Performs common checks before doing a file copy/clone
 * from @file_in to @file_out.
 */
int generic_file_rw_checks(struct file *file_in, struct file *file_out)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);

	/* Don't copy dirs, pipes, sockets... */
	if (S_ISDIR(inode_in->i_mode) || S_ISDIR(inode_out->i_mode))
		return -EISDIR;
	if (!S_ISREG(inode_in->i_mode) || !S_ISREG(inode_out->i_mode))
		return -EINVAL;

	if (!(file_in->f_mode & FMODE_READ) ||
	    !(file_out->f_mode & FMODE_WRITE) ||
	    (file_out->f_flags & O_APPEND))
		return -EBADF;

	return 0;
}

int generic_atomic_write_valid(struct kiocb *iocb, struct iov_iter *iter)
{
	size_t len = iov_iter_count(iter);

	if (!iter_is_ubuf(iter))
		return -EINVAL;

	if (!is_power_of_2(len))
		return -EINVAL;

	if (!IS_ALIGNED(iocb->ki_pos, len))
		return -EINVAL;

	if (!(iocb->ki_flags & IOCB_DIRECT))
		return -EOPNOTSUPP;

	return 0;
}
EXPORT_SYMBOL_GPL(generic_atomic_write_valid);
