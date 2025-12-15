// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ioctl.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>
#include <linux/falloc.h>
#include <linux/sched/signal.h>
#include <linux/fiemap.h>
#include <linux/mount.h>
#include <linux/fscrypt.h>
#include <linux/fileattr.h>

#include "internal.h"

#include <asm/ioctls.h>

/* So that the fiemap access checks can't overflow on 32 bit machines. */
#define FIEMAP_MAX_EXTENTS	(UINT_MAX / sizeof(struct fiemap_extent))

/**
 * vfs_ioctl - call filesystem specific ioctl methods
 * @filp:	open file to invoke ioctl method on
 * @cmd:	ioctl command to execute
 * @arg:	command-specific argument for ioctl
 *
 * Invokes filesystem specific ->unlocked_ioctl, if one exists; otherwise
 * returns -ENOTTY.
 *
 * Returns 0 on success, -errno on error.
 */
static int vfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int error = -ENOTTY;

	if (!filp->f_op->unlocked_ioctl)
		goto out;

	error = filp->f_op->unlocked_ioctl(filp, cmd, arg);
	if (error == -ENOIOCTLCMD)
		error = -ENOTTY;
 out:
	return error;
}

static int ioctl_fibmap(struct file *filp, int __user *p)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	int error, ur_block;
	sector_t block;

	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	error = get_user(ur_block, p);
	if (error)
		return error;

	if (ur_block < 0)
		return -EINVAL;

	block = ur_block;
	error = bmap(inode, &block);

	if (block > INT_MAX) {
		error = -ERANGE;
		pr_warn_ratelimited("[%s/%d] FS: %s File: %pD4 would truncate fibmap result\n",
				    current->comm, task_pid_nr(current),
				    sb->s_id, filp);
	}

	if (error)
		ur_block = 0;
	else
		ur_block = block;

	if (put_user(ur_block, p))
		error = -EFAULT;

	return error;
}

/**
 * fiemap_fill_next_extent - Fiemap helper function
 * @fieinfo:	Fiemap context passed into ->fiemap
 * @logical:	Extent logical start offset, in bytes
 * @phys:	Extent physical start offset, in bytes
 * @len:	Extent length, in bytes
 * @flags:	FIEMAP_EXTENT flags that describe this extent
 *
 * Called from file system ->fiemap callback. Will populate extent
 * info as passed in via arguments and copy to user memory. On
 * success, extent count on fieinfo is incremented.
 *
 * Returns 0 on success, -errno on error, 1 if this was the last
 * extent that will fit in user array.
 */
int fiemap_fill_next_extent(struct fiemap_extent_info *fieinfo, u64 logical,
			    u64 phys, u64 len, u32 flags)
{
	struct fiemap_extent extent;
	struct fiemap_extent __user *dest = fieinfo->fi_extents_start;

	/* only count the extents */
	if (fieinfo->fi_extents_max == 0) {
		fieinfo->fi_extents_mapped++;
		return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
	}

	if (fieinfo->fi_extents_mapped >= fieinfo->fi_extents_max)
		return 1;

#define SET_UNKNOWN_FLAGS	(FIEMAP_EXTENT_DELALLOC)
#define SET_NO_UNMOUNTED_IO_FLAGS	(FIEMAP_EXTENT_DATA_ENCRYPTED)
#define SET_NOT_ALIGNED_FLAGS	(FIEMAP_EXTENT_DATA_TAIL|FIEMAP_EXTENT_DATA_INLINE)

	if (flags & SET_UNKNOWN_FLAGS)
		flags |= FIEMAP_EXTENT_UNKNOWN;
	if (flags & SET_NO_UNMOUNTED_IO_FLAGS)
		flags |= FIEMAP_EXTENT_ENCODED;
	if (flags & SET_NOT_ALIGNED_FLAGS)
		flags |= FIEMAP_EXTENT_NOT_ALIGNED;

	memset(&extent, 0, sizeof(extent));
	extent.fe_logical = logical;
	extent.fe_physical = phys;
	extent.fe_length = len;
	extent.fe_flags = flags;

	dest += fieinfo->fi_extents_mapped;
	if (copy_to_user(dest, &extent, sizeof(extent)))
		return -EFAULT;

	fieinfo->fi_extents_mapped++;
	if (fieinfo->fi_extents_mapped == fieinfo->fi_extents_max)
		return 1;
	return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
}
EXPORT_SYMBOL(fiemap_fill_next_extent);

/**
 * fiemap_prep - check validity of requested flags for fiemap
 * @inode:	Inode to operate on
 * @fieinfo:	Fiemap context passed into ->fiemap
 * @start:	Start of the mapped range
 * @len:	Length of the mapped range, can be truncated by this function.
 * @supported_flags:	Set of fiemap flags that the file system understands
 *
 * This function must be called from each ->fiemap instance to validate the
 * fiemap request against the file system parameters.
 *
 * Returns 0 on success, or a negative error on failure.
 */
int fiemap_prep(struct inode *inode, struct fiemap_extent_info *fieinfo,
		u64 start, u64 *len, u32 supported_flags)
{
	u64 maxbytes = inode->i_sb->s_maxbytes;
	u32 incompat_flags;
	int ret = 0;

	if (*len == 0)
		return -EINVAL;
	if (start >= maxbytes)
		return -EFBIG;

	/*
	 * Shrink request scope to what the fs can actually handle.
	 */
	if (*len > maxbytes || (maxbytes - *len) < start)
		*len = maxbytes - start;

	supported_flags |= FIEMAP_FLAG_SYNC;
	supported_flags &= FIEMAP_FLAGS_COMPAT;
	incompat_flags = fieinfo->fi_flags & ~supported_flags;
	if (incompat_flags) {
		fieinfo->fi_flags = incompat_flags;
		return -EBADR;
	}

	if (fieinfo->fi_flags & FIEMAP_FLAG_SYNC)
		ret = filemap_write_and_wait(inode->i_mapping);
	return ret;
}
EXPORT_SYMBOL(fiemap_prep);

static int ioctl_fiemap(struct file *filp, struct fiemap __user *ufiemap)
{
	struct fiemap fiemap;
	struct fiemap_extent_info fieinfo = { 0, };
	struct inode *inode = file_inode(filp);
	int error;

	if (!inode->i_op->fiemap)
		return -EOPNOTSUPP;

	if (copy_from_user(&fiemap, ufiemap, sizeof(fiemap)))
		return -EFAULT;

	if (fiemap.fm_extent_count > FIEMAP_MAX_EXTENTS)
		return -EINVAL;

	fieinfo.fi_flags = fiemap.fm_flags;
	fieinfo.fi_extents_max = fiemap.fm_extent_count;
	fieinfo.fi_extents_start = ufiemap->fm_extents;

	error = inode->i_op->fiemap(inode, &fieinfo, fiemap.fm_start,
			fiemap.fm_length);

	fiemap.fm_flags = fieinfo.fi_flags;
	fiemap.fm_mapped_extents = fieinfo.fi_extents_mapped;
	if (copy_to_user(ufiemap, &fiemap, sizeof(fiemap)))
		error = -EFAULT;

	return error;
}

static int ioctl_file_clone(struct file *dst_file, unsigned long srcfd,
			    u64 off, u64 olen, u64 destoff)
{
	CLASS(fd, src_file)(srcfd);
	loff_t cloned;
	int ret;

	if (fd_empty(src_file))
		return -EBADF;
	cloned = vfs_clone_file_range(fd_file(src_file), off, dst_file, destoff,
				      olen, 0);
	if (cloned < 0)
		ret = cloned;
	else if (olen && cloned != olen)
		ret = -EINVAL;
	else
		ret = 0;
	return ret;
}

static int ioctl_file_clone_range(struct file *file,
				  struct file_clone_range __user *argp)
{
	struct file_clone_range args;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;
	return ioctl_file_clone(file, args.src_fd, args.src_offset,
				args.src_length, args.dest_offset);
}

/*
 * This provides compatibility with legacy XFS pre-allocation ioctls
 * which predate the fallocate syscall.
 *
 * Only the l_start, l_len and l_whence fields of the 'struct space_resv'
 * are used here, rest are ignored.
 */
static int ioctl_preallocate(struct file *filp, int mode, void __user *argp)
{
	struct inode *inode = file_inode(filp);
	struct space_resv sr;

	if (copy_from_user(&sr, argp, sizeof(sr)))
		return -EFAULT;

	switch (sr.l_whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		sr.l_start += filp->f_pos;
		break;
	case SEEK_END:
		sr.l_start += i_size_read(inode);
		break;
	default:
		return -EINVAL;
	}

	return vfs_fallocate(filp, mode | FALLOC_FL_KEEP_SIZE, sr.l_start,
			sr.l_len);
}

/* on ia32 l_start is on a 32-bit boundary */
#if defined CONFIG_COMPAT && defined(CONFIG_X86_64)
/* just account for different alignment */
static int compat_ioctl_preallocate(struct file *file, int mode,
				    struct space_resv_32 __user *argp)
{
	struct inode *inode = file_inode(file);
	struct space_resv_32 sr;

	if (copy_from_user(&sr, argp, sizeof(sr)))
		return -EFAULT;

	switch (sr.l_whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		sr.l_start += file->f_pos;
		break;
	case SEEK_END:
		sr.l_start += i_size_read(inode);
		break;
	default:
		return -EINVAL;
	}

	return vfs_fallocate(file, mode | FALLOC_FL_KEEP_SIZE, sr.l_start, sr.l_len);
}
#endif

static int file_ioctl(struct file *filp, unsigned int cmd, int __user *p)
{
	switch (cmd) {
	case FIBMAP:
		return ioctl_fibmap(filp, p);
	case FS_IOC_RESVSP:
	case FS_IOC_RESVSP64:
		return ioctl_preallocate(filp, 0, p);
	case FS_IOC_UNRESVSP:
	case FS_IOC_UNRESVSP64:
		return ioctl_preallocate(filp, FALLOC_FL_PUNCH_HOLE, p);
	case FS_IOC_ZERO_RANGE:
		return ioctl_preallocate(filp, FALLOC_FL_ZERO_RANGE, p);
	}

	return -ENOIOCTLCMD;
}

static int ioctl_fionbio(struct file *filp, int __user *argp)
{
	unsigned int flag;
	int on, error;

	error = get_user(on, argp);
	if (error)
		return error;
	flag = O_NONBLOCK;
#ifdef __sparc__
	/* SunOS compatibility item. */
	if (O_NONBLOCK != O_NDELAY)
		flag |= O_NDELAY;
#endif
	spin_lock(&filp->f_lock);
	if (on)
		filp->f_flags |= flag;
	else
		filp->f_flags &= ~flag;
	spin_unlock(&filp->f_lock);
	return error;
}

static int ioctl_fioasync(unsigned int fd, struct file *filp,
			  int __user *argp)
{
	unsigned int flag;
	int on, error;

	error = get_user(on, argp);
	if (error)
		return error;
	flag = on ? FASYNC : 0;

	/* Did FASYNC state change ? */
	if ((flag ^ filp->f_flags) & FASYNC) {
		if (filp->f_op->fasync)
			/* fasync() adjusts filp->f_flags */
			error = filp->f_op->fasync(fd, filp, on);
		else
			error = -ENOTTY;
	}
	return error < 0 ? error : 0;
}

static int ioctl_fsfreeze(struct file *filp)
{
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!ns_capable(sb->s_user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	/* If filesystem doesn't support freeze feature, return. */
	if (sb->s_op->freeze_fs == NULL && sb->s_op->freeze_super == NULL)
		return -EOPNOTSUPP;

	/* Freeze */
	if (sb->s_op->freeze_super)
		return sb->s_op->freeze_super(sb, FREEZE_HOLDER_USERSPACE, NULL);
	return freeze_super(sb, FREEZE_HOLDER_USERSPACE, NULL);
}

static int ioctl_fsthaw(struct file *filp)
{
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!ns_capable(sb->s_user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	/* Thaw */
	if (sb->s_op->thaw_super)
		return sb->s_op->thaw_super(sb, FREEZE_HOLDER_USERSPACE, NULL);
	return thaw_super(sb, FREEZE_HOLDER_USERSPACE, NULL);
}

static int ioctl_file_dedupe_range(struct file *file,
				   struct file_dedupe_range __user *argp)
{
	struct file_dedupe_range *same = NULL;
	int ret;
	unsigned long size;
	u16 count;

	if (get_user(count, &argp->dest_count)) {
		ret = -EFAULT;
		goto out;
	}

	size = struct_size(same, info, count);
	if (size > PAGE_SIZE) {
		ret = -ENOMEM;
		goto out;
	}

	same = memdup_user(argp, size);
	if (IS_ERR(same)) {
		ret = PTR_ERR(same);
		same = NULL;
		goto out;
	}

	same->dest_count = count;
	ret = vfs_dedupe_file_range(file, same);
	if (ret)
		goto out;

	ret = copy_to_user(argp, same, size);
	if (ret)
		ret = -EFAULT;

out:
	kfree(same);
	return ret;
}

static int ioctl_getfsuuid(struct file *file, void __user *argp)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct fsuuid2 u = { .len = sb->s_uuid_len, };

	if (!sb->s_uuid_len)
		return -ENOTTY;

	memcpy(&u.uuid[0], &sb->s_uuid, sb->s_uuid_len);

	return copy_to_user(argp, &u, sizeof(u)) ? -EFAULT : 0;
}

static int ioctl_get_fs_sysfs_path(struct file *file, void __user *argp)
{
	struct super_block *sb = file_inode(file)->i_sb;

	if (!strlen(sb->s_sysfs_name))
		return -ENOTTY;

	struct fs_sysfs_path u = {};

	u.len = scnprintf(u.name, sizeof(u.name), "%s/%s", sb->s_type->name, sb->s_sysfs_name);

	return copy_to_user(argp, &u, sizeof(u)) ? -EFAULT : 0;
}

/*
 * do_vfs_ioctl() is not for drivers and not intended to be EXPORT_SYMBOL()'d.
 * It's just a simple helper for sys_ioctl and compat_sys_ioctl.
 *
 * When you add any new common ioctls to the switches above and below,
 * please ensure they have compatible arguments in compat mode.
 *
 * The LSM mailing list should also be notified of any command additions or
 * changes, as specific LSMs may be affected.
 */
static int do_vfs_ioctl(struct file *filp, unsigned int fd,
			unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct inode *inode = file_inode(filp);

	switch (cmd) {
	case FIOCLEX:
		set_close_on_exec(fd, 1);
		return 0;

	case FIONCLEX:
		set_close_on_exec(fd, 0);
		return 0;

	case FIONBIO:
		return ioctl_fionbio(filp, argp);

	case FIOASYNC:
		return ioctl_fioasync(fd, filp, argp);

	case FIOQSIZE:
		if (S_ISDIR(inode->i_mode) ||
		    (S_ISREG(inode->i_mode) && !IS_ANON_FILE(inode)) ||
		    S_ISLNK(inode->i_mode)) {
			loff_t res = inode_get_bytes(inode);
			return copy_to_user(argp, &res, sizeof(res)) ?
					    -EFAULT : 0;
		}

		return -ENOTTY;

	case FIFREEZE:
		return ioctl_fsfreeze(filp);

	case FITHAW:
		return ioctl_fsthaw(filp);

	case FS_IOC_FIEMAP:
		return ioctl_fiemap(filp, argp);

	case FIGETBSZ:
		/* anon_bdev filesystems may not have a block size */
		if (!inode->i_sb->s_blocksize)
			return -EINVAL;

		return put_user(inode->i_sb->s_blocksize, (int __user *)argp);

	case FICLONE:
		return ioctl_file_clone(filp, arg, 0, 0, 0);

	case FICLONERANGE:
		return ioctl_file_clone_range(filp, argp);

	case FIDEDUPERANGE:
		return ioctl_file_dedupe_range(filp, argp);

	case FIONREAD:
		if (!S_ISREG(inode->i_mode) || IS_ANON_FILE(inode))
			return vfs_ioctl(filp, cmd, arg);

		return put_user(i_size_read(inode) - filp->f_pos,
				(int __user *)argp);

	case FS_IOC_GETFLAGS:
		return ioctl_getflags(filp, argp);

	case FS_IOC_SETFLAGS:
		return ioctl_setflags(filp, argp);

	case FS_IOC_FSGETXATTR:
		return ioctl_fsgetxattr(filp, argp);

	case FS_IOC_FSSETXATTR:
		return ioctl_fssetxattr(filp, argp);

	case FS_IOC_GETFSUUID:
		return ioctl_getfsuuid(filp, argp);

	case FS_IOC_GETFSSYSFSPATH:
		return ioctl_get_fs_sysfs_path(filp, argp);

	default:
		if (S_ISREG(inode->i_mode) && !IS_ANON_FILE(inode))
			return file_ioctl(filp, cmd, argp);
		break;
	}

	return -ENOIOCTLCMD;
}

/**
 * sys_ioctl - Control device parameters and perform device-specific operations
 * @fd: File descriptor to operate on
 * @cmd: Device-specific request code encoding operation type and parameters
 * @arg: Optional argument, interpretation depends on @cmd
 *
 * long-desc: The ioctl syscall is a general-purpose interface for performing
 *   device-specific or file-specific operations that do not fit into the
 *   standard UNIX I/O model. It acts as a multiplexer, dispatching requests
 *   to appropriate handlers based on the file type and command code.
 *
 *   The @cmd parameter encodes the operation to perform using a conventional
 *   32-bit structure: 2 bits for direction (none/read/write/read-write),
 *   14 bits for argument size, 8 bits for type (magic number), and 8 bits
 *   for serial number. Macros _IO(), _IOR(), _IOW(), and _IOWR() in
 *   <asm/ioctl.h> construct these codes, though many legacy codes do not
 *   follow this convention.
 *
 *   The syscall first invokes the LSM security hook security_file_ioctl()
 *   which may deny the operation based on security policy (e.g., SELinux,
 *   AppArmor). If permitted, do_vfs_ioctl() handles common VFS-level
 *   commands. For unrecognized commands, vfs_ioctl() invokes the
 *   file_operations->unlocked_ioctl callback, allowing device drivers and
 *   filesystems to implement custom operations.
 *
 *   Common VFS-level ioctls handled by the kernel include:
 *   - FIOCLEX/FIONCLEX: Set/clear close-on-exec flag on the file descriptor
 *   - FIONBIO: Set/clear non-blocking I/O mode (O_NONBLOCK)
 *   - FIOASYNC: Enable/disable async notification (FASYNC)
 *   - FIOQSIZE: Get file size in bytes (regular files, directories, symlinks)
 *   - FIONREAD: Get bytes available for reading
 *   - FIFREEZE/FITHAW: Freeze/thaw filesystem for consistent snapshots
 *   - FIGETBSZ: Get filesystem block size
 *   - FICLONE/FICLONERANGE: Clone file data (copy-on-write)
 *   - FIDEDUPERANGE: Deduplicate identical file ranges
 *   - FS_IOC_FIEMAP: Get file extent map for files
 *   - FS_IOC_GETFLAGS/SETFLAGS: Get/set inode flags (immutable, append, etc.)
 *   - FS_IOC_FSGETXATTR/FSSETXATTR: Get/set extended attributes (XFS-style)
 *   - FS_IOC_GETFSUUID: Get filesystem UUID
 *   - FS_IOC_GETFSSYSFSPATH: Get sysfs path for filesystem
 *
 *   For regular files, additional ioctls are handled:
 *   - FIBMAP: Map logical to physical block number (requires CAP_SYS_RAWIO)
 *   - FS_IOC_RESVSP/RESVSP64: Reserve disk space (preallocation)
 *   - FS_IOC_UNRESVSP/UNRESVSP64: Unreserve disk space (punch hole)
 *   - FS_IOC_ZERO_RANGE: Zero a range of the file
 *
 *   The behavior and return value semantics are entirely command-dependent.
 *   Some commands return 0 on success, others return positive values as
 *   output (e.g., FIONREAD returns the number of available bytes). The @arg
 *   parameter may be an integer value, a pointer to a user-space structure,
 *   or unused, depending on the specific command.
 *
 *   Historically, ioctl has been described as an "uncontrolled entry point"
 *   into the kernel due to the difficulty of auditing the vast number of
 *   device-specific implementations. Security modules must handle the
 *   complexity of ioctl command spaces. New code should prefer dedicated
 *   syscalls, netlink, or configfs when possible.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, INT_MAX
 *   constraint: Must be a valid, open file descriptor. The descriptor type
 *     (regular file, directory, block device, character device, socket, pipe,
 *     etc.) determines which ioctl commands are available. Some commands work
 *     only on specific file types; using an inappropriate command returns ENOTTY.
 *
 * param: cmd
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: The ioctl command code. Valid commands depend on the file type
 *     underlying @fd. Commands are encoded using _IO/_IOR/_IOW/_IOWR macros or
 *     legacy fixed values. The kernel does not validate the command before
 *     dispatch; invalid commands return ENOTTY from the final handler.
 *     Commands are typically defined in UAPI headers such as <linux/fs.h>,
 *     <asm/ioctls.h>, <linux/termios.h>, and device-specific headers.
 *
 * param: arg
 *   type: KAPI_TYPE_ULONG
 *   flags: KAPI_PARAM_INOUT
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Interpretation is entirely command-dependent. May be: (1) an
 *     integer value passed directly, (2) a pointer to a user-space input
 *     structure, (3) a pointer to a user-space output buffer, (4) a pointer
 *     to an input/output structure, or (5) ignored (for commands taking no
 *     argument). When a pointer, must reference accessible user memory of
 *     appropriate size for the command. NULL pointers cause EFAULT for
 *     commands expecting valid pointers.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_CUSTOM
 *   success: >= 0
 *   desc: Return value semantics are command-dependent. Most commands return
 *     0 on success. Some return positive values as output (e.g., FIONREAD
 *     returns bytes available). Device-specific ioctls may use return values
 *     as output parameters. On error, returns a negative errno value.
 *
 * error: EBADF, Invalid file descriptor
 *   desc: The @fd argument is not a valid open file descriptor. This is
 *     checked first via fd_empty() after obtaining the file reference using
 *     the CLASS(fd, f) RAII wrapper which calls fdget().
 *
 * error: ENOTTY, Inappropriate ioctl for device
 *   desc: The @cmd is not recognized or not applicable to the object that @fd
 *     refers to. This is the catch-all error for unsupported commands. Occurs
 *     when: (1) the file's f_op->unlocked_ioctl is NULL, (2) the driver/fs
 *     ioctl handler returns -ENOIOCTLCMD (converted to -ENOTTY), or (3) the
 *     command requires a specific file type (e.g., FIOQSIZE on a socket).
 *     Legacy code may also return EINVAL for unrecognized commands.
 *
 * error: EFAULT, Bad address
 *   desc: The @arg pointer (when interpreted as an address) points to memory
 *     that is not accessible. Returned by copy_from_user(), copy_to_user(),
 *     get_user(), or put_user() when they fail. Also returned if a structure
 *     embedded pointer (e.g., in FIDEDUPERANGE) is invalid.
 *
 * error: EINVAL, Invalid argument
 *   desc: The @cmd or @arg contains invalid data. Common causes: (1) negative
 *     block number for FIBMAP, (2) invalid whence value in preallocation,
 *     (3) reserved fields not zeroed in structures (FIDEDUPERANGE),
 *     (4) invalid flags in FS_IOC_SETFLAGS, (5) filesystem doesn't have a
 *     block size (FIGETBSZ), (6) source not a regular file (FIDEDUPERANGE).
 *
 * error: EPERM, Operation not permitted
 *   desc: The operation requires a privilege the caller lacks. Causes:
 *     (1) FIBMAP requires CAP_SYS_RAWIO, (2) FIFREEZE/FITHAW require
 *     CAP_SYS_ADMIN in the filesystem's user namespace, (3) FS_IOC_SETFLAGS
 *     changing IMMUTABLE or APPEND flags requires CAP_LINUX_IMMUTABLE,
 *     (4) FIDEDUPERANGE requires write permission or ownership or CAP_SYS_ADMIN,
 *     (5) FS_IOC_FSSETXATTR requires inode ownership or appropriate capability.
 *     Also returned by LSM security_file_ioctl() hook denials.
 *
 * error: EOPNOTSUPP, Operation not supported
 *   desc: The operation is recognized but not implemented by this file/device.
 *     Causes: (1) FS_IOC_FIEMAP on inode without i_op->fiemap callback,
 *     (2) FIFREEZE on filesystem without freeze_fs or freeze_super ops,
 *     (3) FICLONE/FIDEDUPERANGE on filesystem without remap_file_range,
 *     (4) invalid xflags in FS_IOC_FSSETXATTR.
 *
 * error: ENOMEM, Out of memory
 *   desc: Kernel memory allocation failed during the operation. Can occur in
 *     FIDEDUPERANGE when allocating the file_dedupe_range structure via
 *     memdup_user(), or in various filesystem-specific ioctl handlers.
 *
 * error: EBUSY, Resource busy
 *   desc: The resource is temporarily unavailable. FIFREEZE returns this if
 *     the filesystem is already frozen (and nesting is not allowed). Also
 *     returned by some filesystems if the operation conflicts with ongoing
 *     activity.
 *
 * error: EXDEV, Cross-device link
 *   desc: FICLONE, FICLONERANGE, or FIDEDUPERANGE attempted to operate across
 *     different filesystems. Both source and destination files must reside
 *     on the same superblock for reflink/dedupe operations.
 *
 * error: EISDIR, Is a directory
 *   desc: The operation is not valid on directories. FIDEDUPERANGE returns
 *     this if the destination file descriptor refers to a directory. Clone
 *     and dedupe operations work only on regular files.
 *
 * error: ERANGE, Result too large
 *   desc: FIBMAP returns this when the mapped block number exceeds INT_MAX,
 *     as the result must fit in an int. Large files on filesystems with
 *     large block addresses may trigger this.
 *
 * error: EFBIG, File too big
 *   desc: FS_IOC_FIEMAP returns this if the requested start offset exceeds
 *     the filesystem's maximum file size (s_maxbytes). Also possible from
 *     preallocation ioctls if the resulting file would exceed limits.
 *
 * error: EBADR, Invalid request descriptor
 *   desc: FS_IOC_FIEMAP returns this if unsupported flags are passed in the
 *     fiemap.fm_flags field. Only FIEMAP_FLAG_SYNC and filesystem-supported
 *     flags are permitted.
 *
 * error: EROFS, Read-only filesystem
 *   desc: Write operations (FS_IOC_SETFLAGS, FS_IOC_FSSETXATTR, preallocation,
 *     clone, dedupe) attempted on a read-only filesystem. Returned by
 *     mnt_want_write_file() checks.
 *
 * lock: files->file_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired by set_close_on_exec() for FIOCLEX and FIONCLEX commands
 *     to safely modify the close-on-exec flag in the file descriptor table.
 *   condition: Only for FIOCLEX/FIONCLEX commands
 *
 * lock: filp->f_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired by ioctl_fionbio() when modifying filp->f_flags for the
 *     FIONBIO command. Protects concurrent access to file status flags.
 *   condition: Only for FIONBIO command
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired by vfs_fileattr_set() (via inode_lock) for FS_IOC_SETFLAGS
 *     and FS_IOC_FSSETXATTR to serialize attribute modifications. Also
 *     acquired by various other commands that modify inode state.
 *   condition: For commands modifying inode attributes
 *
 * lock: sb->s_umount
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired exclusively by freeze_super() for FIFREEZE and
 *     thaw_super() for FITHAW. Prevents concurrent mount/unmount operations
 *     and other freeze/thaw requests during filesystem freeze transitions.
 *   condition: Only for FIFREEZE/FITHAW commands
 *
 * lock: file_start_write/file_end_write
 *   type: KAPI_LOCK_CUSTOM
 *   acquired: true
 *   released: true
 *   desc: sb_start_write()/sb_end_write() protection acquired via
 *     file_start_write() for write operations like FICLONE, FICLONERANGE,
 *     and preallocation ioctls. Prevents freeze during write operations.
 *   condition: For commands that modify file data
 *
 * signal: any
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: When blocked in filesystem operations
 *   desc: Many ioctl operations can sleep waiting for I/O or locks. Most
 *     filesystem operations are interruptible by fatal signals. The exact
 *     signal handling depends on the specific command and filesystem
 *     implementation. Some operations use interruptible waits and can
 *     return -EINTR or -ERESTARTSYS.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_BLOCKING
 *   restartable: command-dependent
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: File descriptor flags
 *   desc: FIOCLEX sets and FIONCLEX clears the close-on-exec flag (FD_CLOEXEC)
 *     for the file descriptor @fd. This flag is per-descriptor, not per-file.
 *   condition: FIOCLEX or FIONCLEX command
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: File status flags (O_NONBLOCK)
 *   desc: FIONBIO modifies the O_NONBLOCK flag on the file based on the
 *     integer value pointed to by @arg. Non-zero sets non-blocking mode,
 *     zero clears it. Affects all processes sharing this file description.
 *   condition: FIONBIO command with valid int pointer at @arg
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: File async notification (FASYNC flag)
 *   desc: FIOASYNC enables or disables SIGIO/SIGURG delivery when I/O becomes
 *     possible. Calls the file's fasync() operation to register or unregister
 *     the async notification. Modifies filp->f_flags FASYNC bit.
 *   condition: FIOASYNC command with file supporting fasync
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: Filesystem state
 *   desc: FIFREEZE freezes the filesystem, blocking all writes and flushing
 *     dirty data for a consistent snapshot. FITHAW reverses this, allowing
 *     writes to resume. The filesystem remains frozen until all freeze holders
 *     (userspace and kernel) have released it.
 *   condition: FIFREEZE or FITHAW command with appropriate privilege
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: File data and metadata
 *   desc: FICLONE, FICLONERANGE create copy-on-write clones of file data.
 *     FS_IOC_RESVSP/UNRESVSP modify file preallocation. FS_IOC_ZERO_RANGE
 *     zeroes file content. These operations modify file data, metadata, and
 *     potentially allocate or free disk blocks.
 *   condition: Clone/preallocation commands on supporting filesystems
 *   reversible: partially
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Inode flags and attributes
 *   desc: FS_IOC_SETFLAGS modifies inode flags (FS_IMMUTABLE_FL, FS_APPEND_FL,
 *     FS_NODUMP_FL, etc.). FS_IOC_FSSETXATTR modifies extended attributes
 *     including project ID, extent size hints, and xflags.
 *   condition: Flag/attribute modification commands
 *   reversible: yes
 *
 * capability: CAP_SYS_RAWIO
 *   type: KAPI_CAP_PERFORM_OPERATION
 *   allows: Use of FIBMAP ioctl to query physical block mapping
 *   without: FIBMAP returns -EPERM
 *   condition: FIBMAP command
 *
 * capability: CAP_SYS_ADMIN
 *   type: KAPI_CAP_PERFORM_OPERATION
 *   allows: Filesystem freeze (FIFREEZE) and thaw (FITHAW) operations
 *   without: FIFREEZE/FITHAW return -EPERM
 *   condition: FIFREEZE or FITHAW command; checked in fs user namespace
 *
 * capability: CAP_LINUX_IMMUTABLE
 *   type: KAPI_CAP_OVERRIDE_RESTRICTION
 *   allows: Changing immutable (FS_IMMUTABLE_FL) and append-only (FS_APPEND_FL)
 *     inode flags via FS_IOC_SETFLAGS or FS_IOC_FSSETXATTR
 *   without: Cannot modify immutable/append-only flags; returns -EPERM
 *   condition: FS_IOC_SETFLAGS or FS_IOC_FSSETXATTR changing protected flags
 *
 * constraint: LSM Security Hooks
 *   desc: security_file_ioctl() is invoked before any command processing,
 *     allowing SELinux, AppArmor, Smack, or other LSMs to deny the operation.
 *     Each LSM may have different policies for different ioctl commands.
 *     The @arg parameter is passed to the hook but should not be dereferenced
 *     as it may be an integer rather than a pointer.
 *
 * constraint: File Type Restrictions
 *   desc: Many commands are restricted to specific file types. FIBMAP and
 *     preallocation work only on regular files. FIOQSIZE works on regular
 *     files, directories, and symlinks. FIFREEZE/FITHAW work on any file
 *     on a freezable filesystem. Clone and dedupe work only on regular files.
 *     Using a command on an unsupported file type returns ENOTTY or EINVAL.
 *
 * constraint: Read-Only Mount
 *   desc: Operations that modify file content or metadata (FS_IOC_SETFLAGS,
 *     FS_IOC_FSSETXATTR, preallocation, clone, dedupe) fail with EROFS on
 *     read-only mounted filesystems. This is checked via mnt_want_write_file().
 *
 * constraint: Command-Specific Structure Layout
 *   desc: Many commands expect @arg to point to specific structures with
 *     particular layouts and alignment. Structure definitions are in UAPI
 *     headers and may differ between 32-bit and 64-bit userspace. The compat
 *     ioctl handler (compat_sys_ioctl) handles some translations.
 *
 * examples: ioctl(fd, FIOCLEX);  // Set close-on-exec
 *   int nb = 1; ioctl(fd, FIONBIO, &nb);  // Enable non-blocking I/O
 *   int avail; ioctl(fd, FIONREAD, &avail);  // Get bytes available
 *   ioctl(fd, FIFREEZE);  // Freeze filesystem (requires CAP_SYS_ADMIN)
 *   ioctl(destfd, FICLONE, srcfd);  // Clone file via reflink
 *
 * notes: The ioctl() interface predates POSIX and is not standardized,
 *   though individual commands may have POSIX equivalents (e.g., FIONREAD
 *   approximates what poll() provides differently).
 *
 *   ioctl commands are inherently device and filesystem-specific. The VFS
 *   layer handles only generic file operations; all other commands are
 *   dispatched to the file's f_op->unlocked_ioctl or f_op->compat_ioctl.
 *   There are thousands of ioctl commands defined across the kernel for
 *   block devices, character devices, network interfaces, TTYs, etc.
 *
 *   32-bit compatibility: The compat_sys_ioctl() entry point handles 32-bit
 *   processes on 64-bit kernels. It translates some common commands and
 *   delegates to f_op->compat_ioctl for device-specific translation.
 *   Structures passed via @arg may have different layouts (alignment, size)
 *   between 32 and 64-bit userspace.
 *
 *   Security considerations: ioctl has historically been a source of kernel
 *   vulnerabilities due to: (1) the vast number of implementations across
 *   drivers, (2) complex structure handling with user pointers, (3) lack of
 *   centralized validation. New driver code should carefully validate all
 *   inputs, use copy_from_user/copy_to_user safely, and avoid embedding
 *   user pointers in structures where possible.
 *
 *   The -ENOIOCTLCMD return value is internal to the kernel and converted
 *   to -ENOTTY before returning to userspace. Drivers should return
 *   -ENOIOCTLCMD for unrecognized commands to allow fallback handling,
 *   or -ENOTTY to definitively reject the command.
 *
 *   Restartability: Whether an ioctl is automatically restarted after signal
 *   interruption depends on the specific implementation and SA_RESTART flag.
 *   Most VFS-level ioctls complete quickly and are not interruptible.
 *   Device-specific ioctls that block may be interruptible.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
	CLASS(fd, f)(fd);
	int error;

	if (fd_empty(f))
		return -EBADF;

	error = security_file_ioctl(fd_file(f), cmd, arg);
	if (error)
		return error;

	error = do_vfs_ioctl(fd_file(f), fd, cmd, arg);
	if (error == -ENOIOCTLCMD)
		error = vfs_ioctl(fd_file(f), cmd, arg);

	return error;
}

#ifdef CONFIG_COMPAT
/**
 * compat_ptr_ioctl - generic implementation of .compat_ioctl file operation
 * @file: The file to operate on.
 * @cmd: The ioctl command number.
 * @arg: The argument to the ioctl.
 *
 * This is not normally called as a function, but instead set in struct
 * file_operations as
 *
 *     .compat_ioctl = compat_ptr_ioctl,
 *
 * On most architectures, the compat_ptr_ioctl() just passes all arguments
 * to the corresponding ->ioctl handler. The exception is arch/s390, where
 * compat_ptr() clears the top bit of a 32-bit pointer value, so user space
 * pointers to the second 2GB alias the first 2GB, as is the case for
 * native 32-bit s390 user space.
 *
 * The compat_ptr_ioctl() function must therefore be used only with ioctl
 * functions that either ignore the argument or pass a pointer to a
 * compatible data type.
 *
 * If any ioctl command handled by fops->unlocked_ioctl passes a plain
 * integer instead of a pointer, or any of the passed data types
 * is incompatible between 32-bit and 64-bit architectures, a proper
 * handler is required instead of compat_ptr_ioctl.
 */
long compat_ptr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (!file->f_op->unlocked_ioctl)
		return -ENOIOCTLCMD;

	return file->f_op->unlocked_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
EXPORT_SYMBOL(compat_ptr_ioctl);

COMPAT_SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd,
		       compat_ulong_t, arg)
{
	CLASS(fd, f)(fd);
	int error;

	if (fd_empty(f))
		return -EBADF;

	error = security_file_ioctl_compat(fd_file(f), cmd, arg);
	if (error)
		return error;

	switch (cmd) {
	/* FICLONE takes an int argument, so don't use compat_ptr() */
	case FICLONE:
		error = ioctl_file_clone(fd_file(f), arg, 0, 0, 0);
		break;

#if defined(CONFIG_X86_64)
	/* these get messy on amd64 due to alignment differences */
	case FS_IOC_RESVSP_32:
	case FS_IOC_RESVSP64_32:
		error = compat_ioctl_preallocate(fd_file(f), 0, compat_ptr(arg));
		break;
	case FS_IOC_UNRESVSP_32:
	case FS_IOC_UNRESVSP64_32:
		error = compat_ioctl_preallocate(fd_file(f), FALLOC_FL_PUNCH_HOLE,
				compat_ptr(arg));
		break;
	case FS_IOC_ZERO_RANGE_32:
		error = compat_ioctl_preallocate(fd_file(f), FALLOC_FL_ZERO_RANGE,
				compat_ptr(arg));
		break;
#endif

	/*
	 * These access 32-bit values anyway so no further handling is
	 * necessary.
	 */
	case FS_IOC32_GETFLAGS:
	case FS_IOC32_SETFLAGS:
		cmd = (cmd == FS_IOC32_GETFLAGS) ?
			FS_IOC_GETFLAGS : FS_IOC_SETFLAGS;
		fallthrough;
	/*
	 * everything else in do_vfs_ioctl() takes either a compatible
	 * pointer argument or no argument -- call it with a modified
	 * argument.
	 */
	default:
		error = do_vfs_ioctl(fd_file(f), fd, cmd,
				     (unsigned long)compat_ptr(arg));
		if (error != -ENOIOCTLCMD)
			break;

		if (fd_file(f)->f_op->compat_ioctl)
			error = fd_file(f)->f_op->compat_ioctl(fd_file(f), cmd, arg);
		if (error == -ENOIOCTLCMD)
			error = -ENOTTY;
		break;
	}
	return error;
}
#endif
