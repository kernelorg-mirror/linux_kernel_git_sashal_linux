// SPDX-License-Identifier: GPL-2.0-only
/*
  File: fs/xattr.c

  Extended attribute handling.

  Copyright (C) 2001 by Andreas Gruenbacher <a.gruenbacher@computer.org>
  Copyright (C) 2001 SGI - Silicon Graphics, Inc <linux-xfs@oss.sgi.com>
  Copyright (c) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 */
#include <linux/fs.h>
#include <linux/filelock.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fsnotify.h>
#include <linux/audit.h>
#include <linux/vmalloc.h>
#include <linux/posix_acl_xattr.h>

#include <linux/uaccess.h>

#include "internal.h"

static const char *
strcmp_prefix(const char *a, const char *a_prefix)
{
	while (*a_prefix && *a == *a_prefix) {
		a++;
		a_prefix++;
	}
	return *a_prefix ? NULL : a;
}

/*
 * In order to implement different sets of xattr operations for each xattr
 * prefix, a filesystem should create a null-terminated array of struct
 * xattr_handler (one for each prefix) and hang a pointer to it off of the
 * s_xattr field of the superblock.
 */
#define for_each_xattr_handler(handlers, handler)		\
	if (handlers)						\
		for ((handler) = *(handlers)++;			\
			(handler) != NULL;			\
			(handler) = *(handlers)++)

/*
 * Find the xattr_handler with the matching prefix.
 */
static const struct xattr_handler *
xattr_resolve_name(struct inode *inode, const char **name)
{
	const struct xattr_handler * const *handlers = inode->i_sb->s_xattr;
	const struct xattr_handler *handler;

	if (!(inode->i_opflags & IOP_XATTR)) {
		if (unlikely(is_bad_inode(inode)))
			return ERR_PTR(-EIO);
		return ERR_PTR(-EOPNOTSUPP);
	}
	for_each_xattr_handler(handlers, handler) {
		const char *n;

		n = strcmp_prefix(*name, xattr_prefix(handler));
		if (n) {
			if (!handler->prefix ^ !*n) {
				if (*n)
					continue;
				return ERR_PTR(-EINVAL);
			}
			*name = n;
			return handler;
		}
	}
	return ERR_PTR(-EOPNOTSUPP);
}

/**
 * may_write_xattr - check whether inode allows writing xattr
 * @idmap: idmap of the mount the inode was found from
 * @inode: the inode on which to set an xattr
 *
 * Check whether the inode allows writing xattrs. Specifically, we can never
 * set or remove an extended attribute on a read-only filesystem  or on an
 * immutable / append-only inode.
 *
 * We also need to ensure that the inode has a mapping in the mount to
 * not risk writing back invalid i_{g,u}id values.
 *
 * Return: On success zero is returned. On error a negative errno is returned.
 */
int may_write_xattr(struct mnt_idmap *idmap, struct inode *inode)
{
	if (IS_IMMUTABLE(inode))
		return -EPERM;
	if (IS_APPEND(inode))
		return -EPERM;
	if (HAS_UNMAPPED_ID(idmap, inode))
		return -EPERM;
	return 0;
}

/*
 * Check permissions for extended attribute access.  This is a bit complicated
 * because different namespaces have very different rules.
 */
static int
xattr_permission(struct mnt_idmap *idmap, struct inode *inode,
		 const char *name, int mask)
{
	if (mask & MAY_WRITE) {
		int ret;

		ret = may_write_xattr(idmap, inode);
		if (ret)
			return ret;
	}

	/*
	 * No restriction for security.* and system.* from the VFS.  Decision
	 * on these is left to the underlying filesystem / security module.
	 */
	if (!strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN) ||
	    !strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN))
		return 0;

	/*
	 * The trusted.* namespace can only be accessed by privileged users.
	 */
	if (!strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN)) {
		if (!capable(CAP_SYS_ADMIN))
			return (mask & MAY_WRITE) ? -EPERM : -ENODATA;
		return 0;
	}

	/*
	 * In the user.* namespace, only regular files and directories can have
	 * extended attributes. For sticky directories, only the owner and
	 * privileged users can write attributes.
	 */
	if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN)) {
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			return (mask & MAY_WRITE) ? -EPERM : -ENODATA;
		if (S_ISDIR(inode->i_mode) && (inode->i_mode & S_ISVTX) &&
		    (mask & MAY_WRITE) &&
		    !inode_owner_or_capable(idmap, inode))
			return -EPERM;
	}

	return inode_permission(idmap, inode, mask);
}

/*
 * Look for any handler that deals with the specified namespace.
 */
int
xattr_supports_user_prefix(struct inode *inode)
{
	const struct xattr_handler * const *handlers = inode->i_sb->s_xattr;
	const struct xattr_handler *handler;

	if (!(inode->i_opflags & IOP_XATTR)) {
		if (unlikely(is_bad_inode(inode)))
			return -EIO;
		return -EOPNOTSUPP;
	}

	for_each_xattr_handler(handlers, handler) {
		if (!strncmp(xattr_prefix(handler), XATTR_USER_PREFIX,
			     XATTR_USER_PREFIX_LEN))
			return 0;
	}

	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(xattr_supports_user_prefix);

int
__vfs_setxattr(struct mnt_idmap *idmap, struct dentry *dentry,
	       struct inode *inode, const char *name, const void *value,
	       size_t size, int flags)
{
	const struct xattr_handler *handler;

	if (is_posix_acl_xattr(name))
		return -EOPNOTSUPP;

	handler = xattr_resolve_name(inode, &name);
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->set)
		return -EOPNOTSUPP;
	if (size == 0)
		value = "";  /* empty EA, do not remove */
	return handler->set(handler, idmap, dentry, inode, name, value,
			    size, flags);
}
EXPORT_SYMBOL(__vfs_setxattr);

/**
 *  __vfs_setxattr_noperm - perform setxattr operation without performing
 *  permission checks.
 *
 *  @idmap: idmap of the mount the inode was found from
 *  @dentry: object to perform setxattr on
 *  @name: xattr name to set
 *  @value: value to set @name to
 *  @size: size of @value
 *  @flags: flags to pass into filesystem operations
 *
 *  returns the result of the internal setxattr or setsecurity operations.
 *
 *  This function requires the caller to lock the inode's i_rwsem before it
 *  is executed. It also assumes that the caller will make the appropriate
 *  permission checks.
 */
int __vfs_setxattr_noperm(struct mnt_idmap *idmap,
			  struct dentry *dentry, const char *name,
			  const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	int error = -EAGAIN;
	int issec = !strncmp(name, XATTR_SECURITY_PREFIX,
				   XATTR_SECURITY_PREFIX_LEN);

	if (issec)
		inode->i_flags &= ~S_NOSEC;
	if (inode->i_opflags & IOP_XATTR) {
		error = __vfs_setxattr(idmap, dentry, inode, name, value,
				       size, flags);
		if (!error) {
			fsnotify_xattr(dentry);
			security_inode_post_setxattr(dentry, name, value,
						     size, flags);
		}
	} else {
		if (unlikely(is_bad_inode(inode)))
			return -EIO;
	}
	if (error == -EAGAIN) {
		error = -EOPNOTSUPP;

		if (issec) {
			const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;

			error = security_inode_setsecurity(inode, suffix, value,
							   size, flags);
			if (!error)
				fsnotify_xattr(dentry);
		}
	}

	return error;
}

/**
 * __vfs_setxattr_locked - set an extended attribute while holding the inode
 * lock
 *
 *  @idmap: idmap of the mount of the target inode
 *  @dentry: object to perform setxattr on
 *  @name: xattr name to set
 *  @value: value to set @name to
 *  @size: size of @value
 *  @flags: flags to pass into filesystem operations
 *  @delegated_inode: on return, will contain an inode pointer that
 *  a delegation was broken on, NULL if none.
 */
int
__vfs_setxattr_locked(struct mnt_idmap *idmap, struct dentry *dentry,
		      const char *name, const void *value, size_t size,
		      int flags, struct delegated_inode *delegated_inode)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = xattr_permission(idmap, inode, name, MAY_WRITE);
	if (error)
		return error;

	error = security_inode_setxattr(idmap, dentry, name, value, size,
					flags);
	if (error)
		goto out;

	error = try_break_deleg(inode, delegated_inode);
	if (error)
		goto out;

	error = __vfs_setxattr_noperm(idmap, dentry, name, value,
				      size, flags);

out:
	return error;
}
EXPORT_SYMBOL_GPL(__vfs_setxattr_locked);

int
vfs_setxattr(struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	struct delegated_inode delegated_inode = { };
	const void  *orig_value = value;
	int error;

	if (size && strcmp(name, XATTR_NAME_CAPS) == 0) {
		error = cap_convert_nscap(idmap, dentry, &value, size);
		if (error < 0)
			return error;
		size = error;
	}

retry_deleg:
	inode_lock(inode);
	error = __vfs_setxattr_locked(idmap, dentry, name, value, size,
				      flags, &delegated_inode);
	inode_unlock(inode);

	if (is_delegated(&delegated_inode)) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	if (value != orig_value)
		kfree(value);

	return error;
}
EXPORT_SYMBOL_GPL(vfs_setxattr);

static ssize_t
xattr_getsecurity(struct mnt_idmap *idmap, struct inode *inode,
		  const char *name, void *value, size_t size)
{
	void *buffer = NULL;
	ssize_t len;

	if (!value || !size) {
		len = security_inode_getsecurity(idmap, inode, name,
						 &buffer, false);
		goto out_noalloc;
	}

	len = security_inode_getsecurity(idmap, inode, name, &buffer,
					 true);
	if (len < 0)
		return len;
	if (size < len) {
		len = -ERANGE;
		goto out;
	}
	memcpy(value, buffer, len);
out:
	kfree(buffer);
out_noalloc:
	return len;
}

/*
 * vfs_getxattr_alloc - allocate memory, if necessary, before calling getxattr
 *
 * Allocate memory, if not already allocated, or re-allocate correct size,
 * before retrieving the extended attribute.  The xattr value buffer should
 * always be freed by the caller, even on error.
 *
 * Returns the result of alloc, if failed, or the getxattr operation.
 */
int
vfs_getxattr_alloc(struct mnt_idmap *idmap, struct dentry *dentry,
		   const char *name, char **xattr_value, size_t xattr_size,
		   gfp_t flags)
{
	const struct xattr_handler *handler;
	struct inode *inode = dentry->d_inode;
	char *value = *xattr_value;
	int error;

	error = xattr_permission(idmap, inode, name, MAY_READ);
	if (error)
		return error;

	handler = xattr_resolve_name(inode, &name);
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->get)
		return -EOPNOTSUPP;
	error = handler->get(handler, dentry, inode, name, NULL, 0);
	if (error < 0)
		return error;

	if (!value || (error > xattr_size)) {
		value = krealloc(*xattr_value, error + 1, flags);
		if (!value)
			return -ENOMEM;
		memset(value, 0, error + 1);
	}

	error = handler->get(handler, dentry, inode, name, value, error);
	*xattr_value = value;
	return error;
}

ssize_t
__vfs_getxattr(struct dentry *dentry, struct inode *inode, const char *name,
	       void *value, size_t size)
{
	const struct xattr_handler *handler;

	if (is_posix_acl_xattr(name))
		return -EOPNOTSUPP;

	handler = xattr_resolve_name(inode, &name);
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->get)
		return -EOPNOTSUPP;
	return handler->get(handler, dentry, inode, name, value, size);
}
EXPORT_SYMBOL(__vfs_getxattr);

ssize_t
vfs_getxattr(struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, void *value, size_t size)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = xattr_permission(idmap, inode, name, MAY_READ);
	if (error)
		return error;

	error = security_inode_getxattr(dentry, name);
	if (error)
		return error;

	if (!strncmp(name, XATTR_SECURITY_PREFIX,
				XATTR_SECURITY_PREFIX_LEN)) {
		const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;
		int ret = xattr_getsecurity(idmap, inode, suffix, value,
					    size);
		/*
		 * Only overwrite the return value if a security module
		 * is actually active.
		 */
		if (ret == -EOPNOTSUPP)
			goto nolsm;
		return ret;
	}
nolsm:
	return __vfs_getxattr(dentry, inode, name, value, size);
}
EXPORT_SYMBOL_GPL(vfs_getxattr);

/**
 * vfs_listxattr - retrieve \0 separated list of xattr names
 * @dentry: the dentry from whose inode the xattr names are retrieved
 * @list: buffer to store xattr names into
 * @size: size of the buffer
 *
 * This function returns the names of all xattrs associated with the
 * inode of @dentry.
 *
 * Note, for legacy reasons the vfs_listxattr() function lists POSIX
 * ACLs as well. Since POSIX ACLs are decoupled from IOP_XATTR the
 * vfs_listxattr() function doesn't check for this flag since a
 * filesystem could implement POSIX ACLs without implementing any other
 * xattrs.
 *
 * However, since all codepaths that remove IOP_XATTR also assign of
 * inode operations that either don't implement or implement a stub
 * ->listxattr() operation.
 *
 * Return: On success, the size of the buffer that was used. On error a
 *         negative error code.
 */
ssize_t
vfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	struct inode *inode = d_inode(dentry);
	ssize_t error;

	error = security_inode_listxattr(dentry);
	if (error)
		return error;

	if (inode->i_op->listxattr) {
		error = inode->i_op->listxattr(dentry, list, size);
	} else {
		error = security_inode_listsecurity(inode, list, size);
		if (size && error > size)
			error = -ERANGE;
	}
	return error;
}
EXPORT_SYMBOL_GPL(vfs_listxattr);

int
__vfs_removexattr(struct mnt_idmap *idmap, struct dentry *dentry,
		  const char *name)
{
	struct inode *inode = d_inode(dentry);
	const struct xattr_handler *handler;

	if (is_posix_acl_xattr(name))
		return -EOPNOTSUPP;

	handler = xattr_resolve_name(inode, &name);
	if (IS_ERR(handler))
		return PTR_ERR(handler);
	if (!handler->set)
		return -EOPNOTSUPP;
	return handler->set(handler, idmap, dentry, inode, name, NULL, 0,
			    XATTR_REPLACE);
}
EXPORT_SYMBOL(__vfs_removexattr);

/**
 * __vfs_removexattr_locked - set an extended attribute while holding the inode
 * lock
 *
 *  @idmap: idmap of the mount of the target inode
 *  @dentry: object to perform setxattr on
 *  @name: name of xattr to remove
 *  @delegated_inode: on return, will contain an inode pointer that
 *  a delegation was broken on, NULL if none.
 */
int
__vfs_removexattr_locked(struct mnt_idmap *idmap,
			 struct dentry *dentry, const char *name,
			 struct delegated_inode *delegated_inode)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = xattr_permission(idmap, inode, name, MAY_WRITE);
	if (error)
		return error;

	error = security_inode_removexattr(idmap, dentry, name);
	if (error)
		goto out;

	error = try_break_deleg(inode, delegated_inode);
	if (error)
		goto out;

	error = __vfs_removexattr(idmap, dentry, name);
	if (error)
		return error;

	fsnotify_xattr(dentry);
	security_inode_post_removexattr(dentry, name);

out:
	return error;
}
EXPORT_SYMBOL_GPL(__vfs_removexattr_locked);

int
vfs_removexattr(struct mnt_idmap *idmap, struct dentry *dentry,
		const char *name)
{
	struct inode *inode = dentry->d_inode;
	struct delegated_inode delegated_inode = { };
	int error;

retry_deleg:
	inode_lock(inode);
	error = __vfs_removexattr_locked(idmap, dentry,
					 name, &delegated_inode);
	inode_unlock(inode);

	if (is_delegated(&delegated_inode)) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}

	return error;
}
EXPORT_SYMBOL_GPL(vfs_removexattr);

int import_xattr_name(struct xattr_name *kname, const char __user *name)
{
	int error = strncpy_from_user(kname->name, name,
					sizeof(kname->name));
	if (error == 0 || error == sizeof(kname->name))
		return -ERANGE;
	if (error < 0)
		return error;
	return 0;
}

/*
 * Extended attribute SET operations
 */

int setxattr_copy(const char __user *name, struct kernel_xattr_ctx *ctx)
{
	int error;

	if (ctx->flags & ~(XATTR_CREATE|XATTR_REPLACE))
		return -EINVAL;

	error = import_xattr_name(ctx->kname, name);
	if (error)
		return error;

	if (ctx->size) {
		if (ctx->size > XATTR_SIZE_MAX)
			return -E2BIG;

		ctx->kvalue = vmemdup_user(ctx->cvalue, ctx->size);
		if (IS_ERR(ctx->kvalue)) {
			error = PTR_ERR(ctx->kvalue);
			ctx->kvalue = NULL;
		}
	}

	return error;
}

static int do_setxattr(struct mnt_idmap *idmap, struct dentry *dentry,
		struct kernel_xattr_ctx *ctx)
{
	if (is_posix_acl_xattr(ctx->kname->name))
		return do_set_acl(idmap, dentry, ctx->kname->name,
				  ctx->kvalue, ctx->size);

	return vfs_setxattr(idmap, dentry, ctx->kname->name,
			ctx->kvalue, ctx->size, ctx->flags);
}

int file_setxattr(struct file *f, struct kernel_xattr_ctx *ctx)
{
	int error = mnt_want_write_file(f);

	if (!error) {
		audit_file(f);
		error = do_setxattr(file_mnt_idmap(f), f->f_path.dentry, ctx);
		mnt_drop_write_file(f);
	}
	return error;
}

/* unconditionally consumes filename */
int filename_setxattr(int dfd, struct filename *filename,
		      unsigned int lookup_flags, struct kernel_xattr_ctx *ctx)
{
	struct path path;
	int error;

retry:
	error = filename_lookup(dfd, filename, lookup_flags, &path, NULL);
	if (error)
		goto out;
	error = mnt_want_write(path.mnt);
	if (!error) {
		error = do_setxattr(mnt_idmap(path.mnt), path.dentry, ctx);
		mnt_drop_write(path.mnt);
	}
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}

out:
	putname(filename);
	return error;
}

static int path_setxattrat(int dfd, const char __user *pathname,
			   unsigned int at_flags, const char __user *name,
			   const void __user *value, size_t size, int flags)
{
	struct xattr_name kname;
	struct kernel_xattr_ctx ctx = {
		.cvalue	= value,
		.kvalue	= NULL,
		.size	= size,
		.kname	= &kname,
		.flags	= flags,
	};
	struct filename *filename;
	unsigned int lookup_flags = 0;
	int error;

	if ((at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
		return -EINVAL;

	if (!(at_flags & AT_SYMLINK_NOFOLLOW))
		lookup_flags = LOOKUP_FOLLOW;

	error = setxattr_copy(name, &ctx);
	if (error)
		return error;

	filename = getname_maybe_null(pathname, at_flags);
	if (!filename && dfd >= 0) {
		CLASS(fd, f)(dfd);
		if (fd_empty(f))
			error = -EBADF;
		else
			error = file_setxattr(fd_file(f), &ctx);
	} else {
		error = filename_setxattr(dfd, filename, lookup_flags, &ctx);
	}
	kvfree(ctx.kvalue);
	return error;
}

SYSCALL_DEFINE6(setxattrat, int, dfd, const char __user *, pathname, unsigned int, at_flags,
		const char __user *, name, const struct xattr_args __user *, uargs,
		size_t, usize)
{
	struct xattr_args args = {};
	int error;

	BUILD_BUG_ON(sizeof(struct xattr_args) < XATTR_ARGS_SIZE_VER0);
	BUILD_BUG_ON(sizeof(struct xattr_args) != XATTR_ARGS_SIZE_LATEST);

	if (unlikely(usize < XATTR_ARGS_SIZE_VER0))
		return -EINVAL;
	if (usize > PAGE_SIZE)
		return -E2BIG;

	error = copy_struct_from_user(&args, sizeof(args), uargs, usize);
	if (error)
		return error;

	return path_setxattrat(dfd, pathname, at_flags, name,
			       u64_to_user_ptr(args.value), args.size,
			       args.flags);
}

/**
 * sys_setxattr - Set an extended attribute value on a file
 * @pathname: Path to the file on which to set the extended attribute
 * @name: Null-terminated name of the extended attribute (includes namespace prefix)
 * @value: Buffer containing the attribute value to set
 * @size: Size of the value buffer in bytes
 * @flags: Flags controlling attribute creation/replacement behavior
 *
 * long-desc: Sets the value of an extended attribute identified by name on
 *   the file specified by pathname. Extended attributes are name:value pairs
 *   associated with inodes (files, directories, symbolic links, etc.) that
 *   extend the normal attributes (stat data) associated with all inodes.
 *
 *   The attribute name must include a namespace prefix. Valid namespaces are:
 *   - "user." - User-defined attributes (regular files and directories only)
 *   - "trusted." - Trusted attributes (requires CAP_SYS_ADMIN)
 *   - "security." - Security module attributes (e.g., SELinux, Smack, capabilities)
 *   - "system." - System attributes (e.g., POSIX ACLs via system.posix_acl_access)
 *
 *   The value can be arbitrary binary data or text. A zero-length value is
 *   permitted and creates an attribute with an empty value (different from
 *   removing the attribute).
 *
 *   This syscall follows symbolic links. Use lsetxattr() to operate on the
 *   symbolic link itself, or fsetxattr() to operate on an open file descriptor.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: pathname
 *   type: KAPI_TYPE_PATH
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_USER_PATH
 *   constraint: Must be a valid null-terminated path string in user memory.
 *     The path is resolved following symbolic links. Maximum path length is
 *     PATH_MAX (4096 bytes). The file must exist and the caller must have
 *     appropriate permissions.
 *
 * param: name
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_USER_STRING
 *   range: 1, 255
 *   constraint: Must be a valid null-terminated string in user memory containing
 *     the extended attribute name with namespace prefix (e.g., "user.myattr").
 *     The name (including prefix) must be between 1 and XATTR_NAME_MAX (255)
 *     characters. An empty name returns ERANGE.
 *
 * param: value
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER | KAPI_PARAM_OPTIONAL
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid pointer to user memory containing the attribute
 *     value, or NULL if size is 0. When size is non-zero, the pointer must be
 *     valid and accessible for size bytes.
 *
 * param: size
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, 65536
 *   constraint: Size of the value in bytes. Must not exceed XATTR_SIZE_MAX
 *     (65536 bytes). Zero is permitted and creates an attribute with empty value.
 *     Filesystem-specific limits may be smaller (e.g., ext4 limits total xattr
 *     space to one filesystem block, typically 4KB).
 *
 * param: flags
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: XATTR_CREATE | XATTR_REPLACE
 *   constraint: Controls creation/replacement behavior. Valid values are 0,
 *     XATTR_CREATE (0x1), or XATTR_REPLACE (0x2). XATTR_CREATE fails if the
 *     attribute already exists. XATTR_REPLACE fails if the attribute does not
 *     exist. With flags=0, the attribute is created if it doesn't exist or
 *     replaced if it does. XATTR_CREATE and XATTR_REPLACE are mutually exclusive.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. The extended attribute is set with the specified
 *     value. Any previous value for the attribute is replaced.
 *
 * error: ENOENT, File not found
 *   desc: The file specified by pathname does not exist, or a directory component
 *     in the path does not exist. Returned from path lookup (filename_lookup).
 *
 * error: EACCES, Permission denied
 *   desc: Permission denied during path resolution (search permission on a directory
 *     component) or write access to the file is denied based on DAC permissions.
 *
 * error: EPERM, Operation not permitted
 *   desc: Returned in several cases: (1) The file is marked immutable (chattr +i)
 *     or append-only (chattr +a). (2) For trusted.* namespace, caller lacks
 *     CAP_SYS_ADMIN in the filesystem's user namespace. (3) For security.*
 *     namespace (except security.capability), caller lacks CAP_SYS_ADMIN.
 *     (4) For user.* namespace on sticky directories, caller is not the owner
 *     and lacks CAP_FOWNER. (5) The inode has an unmapped ID in an idmapped mount.
 *
 * error: ENODATA, Attribute not found
 *   desc: XATTR_REPLACE was specified but the named attribute does not exist on
 *     the file. Also returned when reading trusted.* without CAP_SYS_ADMIN (for
 *     read operations, but included here for completeness with the flag).
 *
 * error: EEXIST, Attribute already exists
 *   desc: XATTR_CREATE was specified but the named attribute already exists on
 *     the file.
 *
 * error: ERANGE, Name out of range
 *   desc: The attribute name is empty (zero length) or exceeds XATTR_NAME_MAX
 *     (255 characters). Returned from import_xattr_name() via strncpy_from_user().
 *
 * error: E2BIG, Value too large
 *   desc: The size parameter exceeds XATTR_SIZE_MAX (65536 bytes). Returned from
 *     setxattr_copy() before attempting to copy the value from userspace.
 *
 * error: EINVAL, Invalid argument
 *   desc: The flags parameter contains bits other than XATTR_CREATE and
 *     XATTR_REPLACE. Also returned for malformed capability values when setting
 *     security.capability, or when the xattr name doesn't match any handler prefix.
 *
 * error: EFAULT, Bad address
 *   desc: One of the user pointers (pathname, name, or value) is invalid or
 *     points to memory that cannot be accessed. Returned from strncpy_from_user()
 *     for pathname/name or vmemdup_user()/copy_from_user() for value.
 *
 * error: ENOMEM, Out of memory
 *   desc: Kernel could not allocate memory to copy the attribute value from
 *     userspace (via vmemdup_user), or for namespace capability conversion
 *     (cap_convert_nscap allocates memory for v3 capability format).
 *
 * error: EOPNOTSUPP, Operation not supported
 *   desc: The filesystem does not support extended attributes (IOP_XATTR not set),
 *     or no xattr handler exists for the given namespace prefix, or the handler
 *     does not implement the set operation. Also returned for POSIX ACL xattrs
 *     (system.posix_acl_*) when CONFIG_FS_POSIX_ACL is disabled.
 *
 * error: EROFS, Read-only filesystem
 *   desc: The filesystem containing the file is mounted read-only. Returned from
 *     mnt_want_write() before attempting any modification.
 *
 * error: EIO, I/O error
 *   desc: The inode is marked as bad (is_bad_inode), indicating filesystem
 *     corruption or I/O failure. Also may be returned by filesystem-specific
 *     xattr handler operations.
 *
 * error: EDQUOT, Disk quota exceeded
 *   desc: The user's disk quota for extended attributes has been exceeded.
 *     Filesystem-specific error returned from the handler's set operation.
 *
 * error: ENOSPC, No space left on device
 *   desc: The filesystem has insufficient space to store the extended attribute.
 *     Filesystem-specific error from handler's set operation.
 *
 * error: ELOOP, Too many symbolic links
 *   desc: Too many symbolic links were encountered during path resolution
 *     (more than MAXSYMLINKS, typically 40).
 *
 * error: ENAMETOOLONG, Filename too long
 *   desc: The pathname or a component of the pathname exceeds the system limit
 *     (PATH_MAX or NAME_MAX).
 *
 * error: ENOTDIR, Not a directory
 *   desc: A component of the path prefix is not a directory.
 *
 * error: ESTALE, Stale file handle
 *   desc: The file handle became stale during the operation (NFS). The syscall
 *     automatically retries with LOOKUP_REVAL in this case.
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_MUTEX
 *   desc: The inode's read-write semaphore is acquired exclusively via inode_lock()
 *     before calling __vfs_setxattr_locked() and released via inode_unlock() after.
 *     This serializes concurrent xattr modifications on the same inode.
 *
 * lock: sb->s_writers (superblock freeze protection)
 *   type: KAPI_LOCK_SEMAPHORE
 *   desc: Write access to the mount is acquired via mnt_want_write() which calls
 *     sb_start_write(). This prevents filesystem freeze during the operation.
 *     Released via mnt_drop_write() after the operation completes.
 *
 * lock: file_rwsem (delegation breaking)
 *   type: KAPI_LOCK_SEMAPHORE
 *   desc: If the file has NFSv4 delegations, the percpu file_rwsem is acquired
 *     during delegation breaking in __break_lease(). The syscall may wait for
 *     delegation holders to acknowledge the break.
 *
 * signal: Any
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RESTART
 *   condition: Signal arrives during interruptible waits (delegation breaking)
 *   desc: The syscall may wait for NFSv4 delegation holders to release their
 *     delegations. During this wait, signals can interrupt the operation. If a
 *     signal is pending, the wait may be interrupted and the operation retried.
 *     Most blocking points in this syscall use non-interruptible waits.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: Kernel buffer for attribute value
 *   desc: The attribute value is copied from userspace to a kernel buffer
 *     allocated via vmemdup_user(). This memory is freed (kvfree) after the
 *     operation completes, regardless of success or failure.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: File's extended attributes
 *   desc: On success, the specified extended attribute is created or modified.
 *     The change is typically persisted to storage synchronously or asynchronously
 *     depending on filesystem and mount options.
 *   reversible: yes
 *   condition: Operation succeeds
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Inode flags (S_NOSEC)
 *   desc: When setting security.* attributes, the S_NOSEC flag is cleared from
 *     the inode. This flag is an optimization that indicates no security xattrs
 *     exist; clearing it ensures proper security checks on subsequent accesses.
 *   condition: Setting security.* namespace attribute
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify event
 *   desc: On success, fsnotify_xattr() is called to notify any registered
 *     watchers (inotify, fanotify) of the extended attribute modification.
 *     This generates an IN_ATTRIB event.
 *   condition: Operation succeeds
 *
 * state-trans: extended attribute
 *   from: nonexistent or has old value
 *   to: has new value
 *   condition: Operation succeeds with flags=0 or appropriate flags
 *   desc: The extended attribute transitions from not existing (or having its
 *     previous value) to containing the new value. With XATTR_CREATE, the
 *     attribute must not exist beforehand. With XATTR_REPLACE, it must exist.
 *
 * capability: CAP_SYS_ADMIN
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Setting trusted.* namespace attributes and most security.* attributes
 *   without: Setting trusted.* returns EPERM. Setting security.* (except
 *     security.capability) returns EPERM. The check uses ns_capable() against
 *     the filesystem's user namespace.
 *   condition: Attribute name starts with "trusted." or "security." (except
 *     security.capability)
 *
 * capability: CAP_SETFCAP
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Setting the security.capability extended attribute
 *   without: Setting security.capability returns EPERM
 *   condition: Attribute name is "security.capability". Checked via
 *     capable_wrt_inode_uidgid() which considers the inode's ownership.
 *
 * capability: CAP_FOWNER
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypassing owner check for user.* on sticky directories
 *   without: Non-owners cannot set user.* attributes on files in sticky
 *     directories without this capability
 *   condition: Setting user.* namespace attribute on a file in a sticky directory
 *
 * constraint: Filesystem support
 *   desc: The filesystem must support extended attributes (have IOP_XATTR flag
 *     set and provide xattr handlers). Common filesystems supporting xattrs
 *     include ext4, XFS, Btrfs, and tmpfs. Some filesystems (e.g., FAT, older
 *     ext2) do not support extended attributes.
 *
 * constraint: Filesystem-specific size limits
 *   desc: While the VFS limit is 64KB (XATTR_SIZE_MAX), filesystems may impose
 *     smaller limits. For example, ext4 limits all xattrs on an inode to fit
 *     in a single filesystem block (typically 4KB). XFS and ReiserFS support
 *     the full 64KB. Exceeding filesystem limits returns ENOSPC or E2BIG.
 *
 * constraint: user.* namespace restrictions
 *   desc: The user.* namespace is only supported on regular files and directories.
 *     Attempting to set user.* attributes on other file types (symlinks, devices,
 *     sockets, FIFOs) returns EPERM (for write) or ENODATA (for read).
 *
 * constraint: LSM checks
 *   desc: Linux Security Modules (SELinux, Smack, AppArmor) may impose additional
 *     restrictions via security_inode_setxattr() hook. These can return various
 *     error codes depending on the security policy. The LSM is called after
 *     permission checks but before the actual xattr modification.
 *
 * examples: setxattr("/path/file", "user.comment", "test", 4, 0);  // Set user attr
 *   setxattr("/path/file", "user.new", "val", 3, XATTR_CREATE);  // Create only
 *   setxattr("/path/file", "user.existing", "new", 3, XATTR_REPLACE);  // Replace
 *
 * notes: Extended attributes provide a way to associate arbitrary metadata with
 *   files beyond the standard stat attributes. They are commonly used for:
 *   - SELinux security contexts (security.selinux)
 *   - File capabilities (security.capability)
 *   - POSIX ACLs (system.posix_acl_access, system.posix_acl_default)
 *   - User-defined metadata (user.* namespace)
 *
 *   The trusted.* namespace is designed for use by privileged processes to store
 *   data that should not be accessible to unprivileged users (e.g., during
 *   backup/restore operations).
 *
 *   NFSv4 delegation support means this syscall may need to wait for remote
 *   clients to release their delegations before the operation can complete.
 *   This can introduce unbounded delays in pathological cases.
 *
 *   For security.capability specifically, the kernel may convert between v2
 *   (non-namespaced) and v3 (namespaced) capability formats depending on the
 *   filesystem's user namespace and caller's capabilities.
 *
 *   The setxattrat() syscall (added in Linux 6.17) provides more flexibility
 *   with AT_FDCWD and AT_* flags for specifying the file location.
 *
 * since-version: 2.4
 */
SYSCALL_DEFINE5(setxattr, const char __user *, pathname,
		const char __user *, name, const void __user *, value,
		size_t, size, int, flags)
{
	return path_setxattrat(AT_FDCWD, pathname, 0, name, value, size, flags);
}

/**
 * sys_lsetxattr - Set an extended attribute value on a symbolic link
 * @pathname: Path to the file or symbolic link on which to set the attribute
 * @name: Null-terminated name of the extended attribute (includes namespace prefix)
 * @value: Buffer containing the attribute value to set
 * @size: Size of the value buffer in bytes
 * @flags: Flags controlling attribute creation/replacement behavior
 *
 * long-desc: Sets the value of an extended attribute identified by name on
 *   the file specified by pathname. Unlike setxattr(), this syscall does not
 *   follow symbolic links - if pathname refers to a symbolic link, the
 *   extended attribute is set on the link itself, not on the file it refers to.
 *
 *   Extended attributes are name:value pairs associated with inodes (files,
 *   directories, symbolic links, etc.) that extend the normal attributes
 *   (stat data) associated with all inodes.
 *
 *   The attribute name must include a namespace prefix. Valid namespaces are:
 *   - "user." - User-defined attributes (regular files and directories only)
 *   - "trusted." - Trusted attributes (requires CAP_SYS_ADMIN)
 *   - "security." - Security module attributes (e.g., SELinux, Smack, capabilities)
 *   - "system." - System attributes (e.g., POSIX ACLs via system.posix_acl_access)
 *
 *   The value can be arbitrary binary data or text. A zero-length value is
 *   permitted and creates an attribute with an empty value (different from
 *   removing the attribute).
 *
 *   Note that not all filesystems support extended attributes on symbolic links.
 *   Additionally, the user.* namespace is not available on symbolic links since
 *   they are not regular files or directories.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: pathname
 *   type: KAPI_TYPE_PATH
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_USER_PATH
 *   constraint: Must be a valid null-terminated path string in user memory.
 *     The path is resolved WITHOUT following symbolic links - if the final
 *     component is a symbolic link, the operation applies to the link itself.
 *     Maximum path length is PATH_MAX (4096 bytes). The file or link must
 *     exist and the caller must have appropriate permissions.
 *
 * param: name
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_USER_STRING
 *   range: 1, 255
 *   constraint: Must be a valid null-terminated string in user memory containing
 *     the extended attribute name with namespace prefix (e.g., "security.selinux").
 *     The name (including prefix) must be between 1 and XATTR_NAME_MAX (255)
 *     characters. An empty name returns ERANGE. Note that user.* namespace is
 *     not supported on symbolic links.
 *
 * param: value
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER | KAPI_PARAM_OPTIONAL
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid pointer to user memory containing the attribute
 *     value, or NULL if size is 0. When size is non-zero, the pointer must be
 *     valid and accessible for size bytes.
 *
 * param: size
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, 65536
 *   constraint: Size of the value in bytes. Must not exceed XATTR_SIZE_MAX
 *     (65536 bytes). Zero is permitted and creates an attribute with empty value.
 *     Filesystem-specific limits may be smaller (e.g., ext4 limits total xattr
 *     space to one filesystem block, typically 4KB).
 *
 * param: flags
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: XATTR_CREATE | XATTR_REPLACE
 *   constraint: Controls creation/replacement behavior. Valid values are 0,
 *     XATTR_CREATE (0x1), or XATTR_REPLACE (0x2). XATTR_CREATE fails if the
 *     attribute already exists. XATTR_REPLACE fails if the attribute does not
 *     exist. With flags=0, the attribute is created if it doesn't exist or
 *     replaced if it does. XATTR_CREATE and XATTR_REPLACE are mutually exclusive.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. The extended attribute is set with the specified
 *     value on the symbolic link itself. Any previous value for the attribute
 *     is replaced.
 *
 * error: ENOENT, File or symlink not found
 *   desc: The file or symbolic link specified by pathname does not exist, or a
 *     directory component in the path does not exist. Returned from path lookup.
 *
 * error: EACCES, Permission denied
 *   desc: Permission denied during path resolution (search permission on a directory
 *     component) or write access to the file is denied based on DAC permissions.
 *
 * error: EPERM, Operation not permitted
 *   desc: Returned in several cases: (1) The file is marked immutable (chattr +i)
 *     or append-only (chattr +a). (2) For trusted.* namespace, caller lacks
 *     CAP_SYS_ADMIN in the filesystem's user namespace. (3) For security.*
 *     namespace (except security.capability), caller lacks CAP_SYS_ADMIN.
 *     (4) For user.* namespace on sticky directories, caller is not the owner
 *     and lacks CAP_FOWNER. (5) The inode has an unmapped ID in an idmapped mount.
 *     (6) Attempting to set user.* namespace on a symbolic link (not supported).
 *
 * error: ENODATA, Attribute not found
 *   desc: XATTR_REPLACE was specified but the named attribute does not exist on
 *     the symbolic link.
 *
 * error: EEXIST, Attribute already exists
 *   desc: XATTR_CREATE was specified but the named attribute already exists on
 *     the symbolic link.
 *
 * error: ERANGE, Name out of range
 *   desc: The attribute name is empty (zero length) or exceeds XATTR_NAME_MAX
 *     (255 characters). Returned from import_xattr_name() via strncpy_from_user().
 *
 * error: E2BIG, Value too large
 *   desc: The size parameter exceeds XATTR_SIZE_MAX (65536 bytes). Returned from
 *     setxattr_copy() before attempting to copy the value from userspace.
 *
 * error: EINVAL, Invalid argument
 *   desc: The flags parameter contains bits other than XATTR_CREATE and
 *     XATTR_REPLACE. Also returned for malformed capability values when setting
 *     security.capability, or when the xattr name doesn't match any handler prefix.
 *
 * error: EFAULT, Bad address
 *   desc: One of the user pointers (pathname, name, or value) is invalid or
 *     points to memory that cannot be accessed. Returned from strncpy_from_user()
 *     for pathname/name or vmemdup_user()/copy_from_user() for value.
 *
 * error: ENOMEM, Out of memory
 *   desc: Kernel could not allocate memory to copy the attribute value from
 *     userspace (via vmemdup_user), or for namespace capability conversion
 *     (cap_convert_nscap allocates memory for v3 capability format).
 *
 * error: EOPNOTSUPP, Operation not supported
 *   desc: The filesystem does not support extended attributes on symbolic links,
 *     or no xattr handler exists for the given namespace prefix, or the handler
 *     does not implement the set operation. Many filesystems do not support
 *     setting xattrs on symbolic links.
 *
 * error: EROFS, Read-only filesystem
 *   desc: The filesystem containing the symbolic link is mounted read-only.
 *     Returned from mnt_want_write() before attempting any modification.
 *
 * error: EIO, I/O error
 *   desc: The inode is marked as bad (is_bad_inode), indicating filesystem
 *     corruption or I/O failure. Also may be returned by filesystem-specific
 *     xattr handler operations.
 *
 * error: EDQUOT, Disk quota exceeded
 *   desc: The user's disk quota for extended attributes has been exceeded.
 *     Filesystem-specific error returned from the handler's set operation.
 *
 * error: ENOSPC, No space left on device
 *   desc: The filesystem has insufficient space to store the extended attribute.
 *     Filesystem-specific error from handler's set operation.
 *
 * error: ELOOP, Too many symbolic links
 *   desc: Too many symbolic links were encountered during path resolution of
 *     directory components (more than MAXSYMLINKS, typically 40). Note that the
 *     final component (the target of the operation) is not followed.
 *
 * error: ENAMETOOLONG, Filename too long
 *   desc: The pathname or a component of the pathname exceeds the system limit
 *     (PATH_MAX or NAME_MAX).
 *
 * error: ENOTDIR, Not a directory
 *   desc: A component of the path prefix is not a directory.
 *
 * error: ESTALE, Stale file handle
 *   desc: The file handle became stale during the operation (NFS). The syscall
 *     automatically retries with LOOKUP_REVAL in this case.
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: The inode's read-write semaphore is acquired exclusively via inode_lock()
 *     before calling __vfs_setxattr_locked() and released via inode_unlock() after.
 *     This serializes concurrent xattr modifications on the same inode.
 *
 * lock: sb->s_writers (superblock freeze protection)
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Write access to the mount is acquired via mnt_want_write() which calls
 *     sb_start_write(). This prevents filesystem freeze during the operation.
 *     Released via mnt_drop_write() after the operation completes.
 *
 * lock: file_rwsem (delegation breaking)
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: If the file has NFSv4 delegations, the percpu file_rwsem is acquired
 *     during delegation breaking in __break_lease(). The syscall may wait for
 *     delegation holders to acknowledge the break.
 *
 * signal: Any
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RESTART
 *   condition: Signal arrives during interruptible waits (delegation breaking)
 *   desc: The syscall may wait for NFSv4 delegation holders to release their
 *     delegations. During this wait, signals can interrupt the operation. If a
 *     signal is pending, the wait may be interrupted and the operation retried.
 *     Most blocking points in this syscall use non-interruptible waits.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: Kernel buffer for attribute value
 *   desc: The attribute value is copied from userspace to a kernel buffer
 *     allocated via vmemdup_user(). This memory is freed (kvfree) after the
 *     operation completes, regardless of success or failure.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: Symbolic link's extended attributes
 *   desc: On success, the specified extended attribute is created or modified
 *     on the symbolic link itself. The change is typically persisted to storage
 *     synchronously or asynchronously depending on filesystem and mount options.
 *   reversible: yes
 *   condition: Operation succeeds
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Inode flags (S_NOSEC)
 *   desc: When setting security.* attributes, the S_NOSEC flag is cleared from
 *     the inode. This flag is an optimization that indicates no security xattrs
 *     exist; clearing it ensures proper security checks on subsequent accesses.
 *   condition: Setting security.* namespace attribute
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify event
 *   desc: On success, fsnotify_xattr() is called to notify any registered
 *     watchers (inotify, fanotify) of the extended attribute modification.
 *     This generates an IN_ATTRIB event.
 *   condition: Operation succeeds
 *
 * state-trans: extended attribute
 *   from: nonexistent or has old value
 *   to: has new value
 *   condition: Operation succeeds with flags=0 or appropriate flags
 *   desc: The extended attribute on the symbolic link transitions from not
 *     existing (or having its previous value) to containing the new value.
 *     With XATTR_CREATE, the attribute must not exist beforehand. With
 *     XATTR_REPLACE, it must exist.
 *
 * capability: CAP_SYS_ADMIN
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Setting trusted.* namespace attributes and most security.* attributes
 *   without: Setting trusted.* returns EPERM. Setting security.* (except
 *     security.capability) returns EPERM. The check uses ns_capable() against
 *     the filesystem's user namespace.
 *   condition: Attribute name starts with "trusted." or "security." (except
 *     security.capability)
 *
 * capability: CAP_SETFCAP
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Setting the security.capability extended attribute
 *   without: Setting security.capability returns EPERM
 *   condition: Attribute name is "security.capability". Checked via
 *     capable_wrt_inode_uidgid() which considers the inode's ownership.
 *
 * capability: CAP_FOWNER
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypassing owner check for user.* on sticky directories
 *   without: Non-owners cannot set user.* attributes on files in sticky
 *     directories without this capability
 *   condition: Setting user.* namespace attribute on a file in a sticky directory
 *
 * constraint: Filesystem support for symlinks
 *   desc: Not all filesystems support extended attributes on symbolic links.
 *     Some filesystems (like ext4) may only support certain xattr namespaces
 *     on symlinks. The user.* namespace is explicitly not supported on symbolic
 *     links since they are not regular files or directories.
 *
 * constraint: Filesystem-specific size limits
 *   desc: While the VFS limit is 64KB (XATTR_SIZE_MAX), filesystems may impose
 *     smaller limits. For example, ext4 limits all xattrs on an inode to fit
 *     in a single filesystem block (typically 4KB). XFS and ReiserFS support
 *     the full 64KB. Exceeding filesystem limits returns ENOSPC or E2BIG.
 *
 * constraint: user.* namespace restrictions on symlinks
 *   desc: The user.* namespace is only supported on regular files and directories.
 *     Attempting to set user.* attributes on symbolic links returns EPERM.
 *     This is because user.* xattrs have permission semantics that don't apply
 *     to symbolic links which anyone can follow.
 *
 * constraint: LSM checks
 *   desc: Linux Security Modules (SELinux, Smack, AppArmor) may impose additional
 *     restrictions via security_inode_setxattr() hook. These can return various
 *     error codes depending on the security policy. The LSM is called after
 *     permission checks but before the actual xattr modification.
 *
 * examples: lsetxattr("/path/symlink", "security.selinux", ctx, len, 0);  // Set SELinux context on link
 *   lsetxattr("/path/symlink", "trusted.overlay.opaque", "y", 1, XATTR_CREATE);  // Set overlay attr
 *
 * notes: This syscall is primarily used for security labeling of symbolic links
 *   themselves (as opposed to their targets). Common use cases include:
 *   - SELinux security contexts on symbolic links (security.selinux)
 *   - Overlay filesystem metadata (trusted.overlay.*)
 *   - IMA/EVM integrity metadata (security.ima, security.evm)
 *
 *   Unlike regular files and directories, symbolic links do not support the
 *   user.* xattr namespace. This is because user.* xattrs require ownership
 *   or capability checks that don't make sense for symlinks which can be
 *   followed by anyone with directory access.
 *
 *   The trusted.* namespace on symbolic links requires CAP_SYS_ADMIN and is
 *   commonly used by overlay filesystems to store metadata about redirected
 *   or opaque directories.
 *
 *   NFSv4 delegation support means this syscall may need to wait for remote
 *   clients to release their delegations before the operation can complete.
 *
 *   This syscall was introduced alongside setxattr(), fsetxattr(), and the
 *   corresponding get/list/remove variants in Linux 2.4 to provide the
 *   non-following behavior needed for backup/restore tools and security
 *   labeling of links.
 *
 * since-version: 2.4
 */
SYSCALL_DEFINE5(lsetxattr, const char __user *, pathname,
		const char __user *, name, const void __user *, value,
		size_t, size, int, flags)
{
	return path_setxattrat(AT_FDCWD, pathname, AT_SYMLINK_NOFOLLOW, name,
			       value, size, flags);
}

/**
 * sys_fsetxattr - Set an extended attribute value on an open file descriptor
 * @fd: File descriptor of the file on which to set the extended attribute
 * @name: Null-terminated name of the extended attribute (includes namespace prefix)
 * @value: Buffer containing the attribute value to set
 * @size: Size of the value buffer in bytes
 * @flags: Flags controlling attribute creation/replacement behavior
 *
 * long-desc: Sets the value of an extended attribute identified by name on
 *   the file referred to by the open file descriptor fd. Extended attributes
 *   are name:value pairs associated with inodes (files, directories, symbolic
 *   links, etc.) that extend the normal attributes (stat data) associated with
 *   all inodes.
 *
 *   This syscall is similar to setxattr() but operates on an already-open file
 *   descriptor rather than a pathname. This is useful when the file is already
 *   open, when the caller wants to avoid race conditions between opening and
 *   setting attributes, or when operating on file descriptors that cannot be
 *   easily reopened.
 *
 *   The attribute name must include a namespace prefix. Valid namespaces are:
 *   - "user." - User-defined attributes (regular files and directories only)
 *   - "trusted." - Trusted attributes (requires CAP_SYS_ADMIN)
 *   - "security." - Security module attributes (e.g., SELinux, Smack, capabilities)
 *   - "system." - System attributes (e.g., POSIX ACLs via system.posix_acl_access)
 *
 *   The value can be arbitrary binary data or text. A zero-length value is
 *   permitted and creates an attribute with an empty value (different from
 *   removing the attribute).
 *
 *   The file descriptor must have been opened for writing to modify extended
 *   attributes. The file descriptor cannot be an O_PATH file descriptor.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: fd
 *   type: KAPI_TYPE_FD
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid file descriptor returned by open(), creat(),
 *     or similar syscalls. The file descriptor cannot be an O_PATH file
 *     descriptor. The file must be on a filesystem that is not mounted
 *     read-only. AT_FDCWD (-100) is NOT valid for this syscall as it operates
 *     on file descriptors, not directory handles.
 *
 * param: name
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_USER_STRING
 *   range: 1, 255
 *   constraint: Must be a valid null-terminated string in user memory containing
 *     the extended attribute name with namespace prefix (e.g., "user.myattr").
 *     The name (including prefix) must be between 1 and XATTR_NAME_MAX (255)
 *     characters. An empty name returns ERANGE.
 *
 * param: value
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER | KAPI_PARAM_OPTIONAL
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid pointer to user memory containing the attribute
 *     value, or NULL if size is 0. When size is non-zero, the pointer must be
 *     valid and accessible for size bytes.
 *
 * param: size
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, 65536
 *   constraint: Size of the value in bytes. Must not exceed XATTR_SIZE_MAX
 *     (65536 bytes). Zero is permitted and creates an attribute with empty value.
 *     Filesystem-specific limits may be smaller (e.g., ext4 limits total xattr
 *     space to one filesystem block, typically 4KB).
 *
 * param: flags
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: XATTR_CREATE | XATTR_REPLACE
 *   constraint: Controls creation/replacement behavior. Valid values are 0,
 *     XATTR_CREATE (0x1), or XATTR_REPLACE (0x2). XATTR_CREATE fails if the
 *     attribute already exists. XATTR_REPLACE fails if the attribute does not
 *     exist. With flags=0, the attribute is created if it doesn't exist or
 *     replaced if it does. XATTR_CREATE and XATTR_REPLACE are mutually exclusive.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. The extended attribute is set with the specified
 *     value. Any previous value for the attribute is replaced.
 *
 * error: EBADF, Bad file descriptor
 *   desc: The file descriptor fd is not valid or is not open for writing. This
 *     is returned from the fd class lookup when the file descriptor does not
 *     refer to an open file.
 *
 * error: EPERM, Operation not permitted
 *   desc: Returned when: (1) file is immutable or append-only, (2) trusted.*
 *     without CAP_SYS_ADMIN, (3) security.* (except capability) without
 *     CAP_SYS_ADMIN, (4) user.* on sticky dir without ownership/CAP_FOWNER,
 *     (5) unmapped ID in idmapped mount, (6) user.* on non-regular/non-dir.
 *
 * error: ENODATA, Attribute not found
 *   desc: XATTR_REPLACE was specified but the named attribute does not exist on
 *     the file. Also returned when reading trusted.* without CAP_SYS_ADMIN.
 *
 * error: EEXIST, Attribute already exists
 *   desc: XATTR_CREATE was specified but the named attribute already exists on
 *     the file.
 *
 * error: ERANGE, Name out of range
 *   desc: The attribute name is empty (zero length) or exceeds XATTR_NAME_MAX
 *     (255 characters). Returned from import_xattr_name() via strncpy_from_user().
 *
 * error: E2BIG, Value too large
 *   desc: The size parameter exceeds XATTR_SIZE_MAX (65536 bytes). Returned from
 *     setxattr_copy() before attempting to copy the value from userspace.
 *
 * error: EINVAL, Invalid argument
 *   desc: The flags parameter contains bits other than XATTR_CREATE and
 *     XATTR_REPLACE. Also returned for malformed capability values when setting
 *     security.capability (invalid header format, invalid rootid mapping), or
 *     when the xattr name doesn't match any handler prefix.
 *
 * error: EFAULT, Bad address
 *   desc: One of the user pointers (name or value) is invalid or points to
 *     memory that cannot be accessed. Returned from strncpy_from_user() for
 *     name or vmemdup_user()/copy_from_user() for value.
 *
 * error: ENOMEM, Out of memory
 *   desc: Kernel could not allocate memory to copy the attribute value from
 *     userspace (via vmemdup_user), or for namespace capability conversion
 *     (cap_convert_nscap allocates memory for v3 capability format).
 *
 * error: EOPNOTSUPP, Operation not supported
 *   desc: The filesystem does not support extended attributes (IOP_XATTR not set),
 *     or no xattr handler exists for the given namespace prefix, or the handler
 *     does not implement the set operation. Also returned for POSIX ACL xattrs
 *     (system.posix_acl_*) when CONFIG_FS_POSIX_ACL is disabled.
 *
 * error: EROFS, Read-only filesystem
 *   desc: The filesystem containing the file is mounted read-only. Returned from
 *     mnt_want_write_file() before attempting any modification.
 *
 * error: EIO, I/O error
 *   desc: The inode is marked as bad (is_bad_inode), indicating filesystem
 *     corruption or I/O failure. Also may be returned by filesystem-specific
 *     xattr handler operations.
 *
 * error: EDQUOT, Disk quota exceeded
 *   desc: The user's disk quota for extended attributes has been exceeded.
 *     Filesystem-specific error returned from the handler's set operation.
 *
 * error: ENOSPC, No space left on device
 *   desc: The filesystem has insufficient space to store the extended attribute.
 *     Filesystem-specific error from handler's set operation.
 *
 * error: EACCES, Permission denied
 *   desc: Write access to the file is denied based on DAC permissions. The caller
 *     does not have appropriate permission to modify xattrs on this file.
 *
 * lock: inode->i_rwsem
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: The inode's read-write semaphore is acquired exclusively via inode_lock()
 *     before calling __vfs_setxattr_locked() and released via inode_unlock() after.
 *     This serializes concurrent xattr modifications on the same inode.
 *
 * lock: sb->s_writers (superblock freeze protection)
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: Write access to the mount is acquired via mnt_want_write_file() which
 *     calls sb_start_write(). This prevents filesystem freeze during the operation.
 *     Released via mnt_drop_write_file() after the operation completes.
 *
 * lock: file_rwsem (delegation breaking)
 *   type: KAPI_LOCK_SEMAPHORE
 *   acquired: true
 *   released: true
 *   desc: If the file has NFSv4 delegations, the percpu file_rwsem is acquired
 *     during delegation breaking in __break_lease(). The syscall may wait for
 *     delegation holders to acknowledge the break.
 *
 * signal: Any
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RESTART
 *   condition: Signal arrives during interruptible wait for delegation breaking
 *   desc: The syscall may wait for NFSv4 delegation holders to release their
 *     delegations via wait_event_interruptible_timeout() in __break_lease().
 *     During this wait, signals can interrupt the operation. If a signal is
 *     pending, the wait is interrupted and the operation may be retried by
 *     the kernel automatically if the signal disposition allows (SA_RESTART).
 *   error: -ERESTARTSYS
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: Kernel buffer for attribute value
 *   desc: The attribute value is copied from userspace to a kernel buffer
 *     allocated via vmemdup_user(). This memory is freed (kvfree) after the
 *     operation completes, regardless of success or failure.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: File's extended attributes
 *   desc: On success, the specified extended attribute is created or modified.
 *     The change is typically persisted to storage synchronously or asynchronously
 *     depending on filesystem and mount options.
 *   reversible: yes
 *   condition: Operation succeeds
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Inode flags (S_NOSEC)
 *   desc: When setting security.* attributes, the S_NOSEC flag is cleared from
 *     the inode. This flag is an optimization that indicates no security xattrs
 *     exist; clearing it ensures proper security checks on subsequent accesses.
 *   condition: Setting security.* namespace attribute
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: fsnotify event
 *   desc: On success, fsnotify_xattr() is called to notify any registered
 *     watchers (inotify, fanotify) of the extended attribute modification.
 *     This generates an IN_ATTRIB event.
 *   condition: Operation succeeds
 *
 * state-trans: extended attribute
 *   from: nonexistent or has old value
 *   to: has new value
 *   condition: Operation succeeds with flags=0 or appropriate flags
 *   desc: The extended attribute transitions from not existing (or having its
 *     previous value) to containing the new value. With XATTR_CREATE, the
 *     attribute must not exist beforehand. With XATTR_REPLACE, it must exist.
 *
 * capability: CAP_SYS_ADMIN
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Setting trusted.* namespace attributes and most security.* attributes
 *   without: Setting trusted.* returns EPERM. Setting security.* (except
 *     security.capability) returns EPERM. The check uses ns_capable() against
 *     the filesystem's user namespace.
 *   condition: Attribute name starts with "trusted." or "security." (except
 *     security.capability)
 *
 * capability: CAP_SETFCAP
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Setting the security.capability extended attribute
 *   without: Setting security.capability returns EPERM
 *   condition: Attribute name is "security.capability". Checked via
 *     capable_wrt_inode_uidgid() which considers the inode's ownership.
 *
 * capability: CAP_FOWNER
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Bypassing owner check for user.* on sticky directories
 *   without: Non-owners cannot set user.* attributes on files in sticky
 *     directories without this capability
 *   condition: Setting user.* namespace attribute on a file in a sticky directory
 *
 * constraint: Filesystem support
 *   desc: The filesystem must support extended attributes (have IOP_XATTR flag
 *     set and provide xattr handlers). Common filesystems supporting xattrs
 *     include ext4, XFS, Btrfs, and tmpfs. Some filesystems (e.g., FAT, older
 *     ext2) do not support extended attributes.
 *
 * constraint: Filesystem-specific size limits
 *   desc: While the VFS limit is 64KB (XATTR_SIZE_MAX), filesystems may impose
 *     smaller limits. For example, ext4 limits all xattrs on an inode to fit
 *     in a single filesystem block (typically 4KB). XFS and ReiserFS support
 *     the full 64KB. Exceeding filesystem limits returns ENOSPC or E2BIG.
 *
 * constraint: user.* namespace restrictions
 *   desc: The user.* namespace is only supported on regular files and directories.
 *     Attempting to set user.* attributes on other file types (symlinks, devices,
 *     sockets, FIFOs) returns EPERM (for write) or ENODATA (for read).
 *
 * constraint: LSM checks
 *   desc: Linux Security Modules (SELinux, Smack, AppArmor) may impose additional
 *     restrictions via security_inode_setxattr() hook. These can return various
 *     error codes depending on the security policy. The LSM is called after
 *     permission checks but before the actual xattr modification.
 *
 * constraint: File descriptor must not be O_PATH
 *   desc: The file descriptor must be a regular file descriptor, not one opened
 *     with O_PATH. O_PATH file descriptors do not provide access to the file
 *     contents or metadata modification operations.
 *
 * examples: fsetxattr(fd, "user.comment", "test", 4, 0);  // Set user attr
 *   fsetxattr(fd, "user.new", "val", 3, XATTR_CREATE);  // Create only, fail if exists
 *   fsetxattr(fd, "user.existing", "new", 3, XATTR_REPLACE);  // Replace only
 *   fsetxattr(fd, "user.empty", "", 0, 0);  // Create attribute with empty value
 *
 * notes: Extended attributes provide a way to associate arbitrary metadata with
 *   files beyond the standard stat attributes. They are commonly used for:
 *   - SELinux security contexts (security.selinux)
 *   - File capabilities (security.capability)
 *   - POSIX ACLs (system.posix_acl_access, system.posix_acl_default)
 *   - User-defined metadata (user.* namespace)
 *
 *   Using fsetxattr() with an already-open file descriptor avoids potential
 *   TOCTOU (time-of-check-time-of-use) race conditions that can occur when
 *   using setxattr() with a pathname, where the file might be replaced between
 *   opening and setting the attribute.
 *
 *   The trusted.* namespace is designed for use by privileged processes to store
 *   data that should not be accessible to unprivileged users (e.g., during
 *   backup/restore operations).
 *
 *   NFSv4 delegation support means this syscall may need to wait for remote
 *   clients to release their delegations before the operation can complete.
 *   This can introduce unbounded delays in pathological cases.
 *
 *   For security.capability specifically, the kernel may convert between v2
 *   (non-namespaced) and v3 (namespaced) capability formats depending on the
 *   filesystem's user namespace and caller's capabilities.
 *
 *   Unlike setxattr() and lsetxattr(), fsetxattr() does not involve path
 *   resolution, so errors related to path traversal (ENOENT, ENOTDIR,
 *   ENAMETOOLONG, ELOOP, ESTALE) are not possible.
 *
 * since-version: 2.4
 */
SYSCALL_DEFINE5(fsetxattr, int, fd, const char __user *, name,
		const void __user *,value, size_t, size, int, flags)
{
	return path_setxattrat(fd, NULL, AT_EMPTY_PATH, name,
			       value, size, flags);
}

/*
 * Extended attribute GET operations
 */
static ssize_t
do_getxattr(struct mnt_idmap *idmap, struct dentry *d,
	struct kernel_xattr_ctx *ctx)
{
	ssize_t error;
	char *kname = ctx->kname->name;
	void *kvalue = NULL;

	if (ctx->size) {
		if (ctx->size > XATTR_SIZE_MAX)
			ctx->size = XATTR_SIZE_MAX;
		kvalue = kvzalloc(ctx->size, GFP_KERNEL);
		if (!kvalue)
			return -ENOMEM;
	}

	if (is_posix_acl_xattr(kname))
		error = do_get_acl(idmap, d, kname, kvalue, ctx->size);
	else
		error = vfs_getxattr(idmap, d, kname, kvalue, ctx->size);
	if (error > 0) {
		if (ctx->size && copy_to_user(ctx->value, kvalue, error))
			error = -EFAULT;
	} else if (error == -ERANGE && ctx->size >= XATTR_SIZE_MAX) {
		/* The file system tried to returned a value bigger
		   than XATTR_SIZE_MAX bytes. Not possible. */
		error = -E2BIG;
	}

	kvfree(kvalue);
	return error;
}

ssize_t file_getxattr(struct file *f, struct kernel_xattr_ctx *ctx)
{
	audit_file(f);
	return do_getxattr(file_mnt_idmap(f), f->f_path.dentry, ctx);
}

/* unconditionally consumes filename */
ssize_t filename_getxattr(int dfd, struct filename *filename,
			  unsigned int lookup_flags, struct kernel_xattr_ctx *ctx)
{
	struct path path;
	ssize_t error;
retry:
	error = filename_lookup(dfd, filename, lookup_flags, &path, NULL);
	if (error)
		goto out;
	error = do_getxattr(mnt_idmap(path.mnt), path.dentry, ctx);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	putname(filename);
	return error;
}

static ssize_t path_getxattrat(int dfd, const char __user *pathname,
			       unsigned int at_flags, const char __user *name,
			       void __user *value, size_t size)
{
	struct xattr_name kname;
	struct kernel_xattr_ctx ctx = {
		.value    = value,
		.size     = size,
		.kname    = &kname,
		.flags    = 0,
	};
	struct filename *filename;
	ssize_t error;

	if ((at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
		return -EINVAL;

	error = import_xattr_name(&kname, name);
	if (error)
		return error;

	filename = getname_maybe_null(pathname, at_flags);
	if (!filename && dfd >= 0) {
		CLASS(fd, f)(dfd);
		if (fd_empty(f))
			return -EBADF;
		return file_getxattr(fd_file(f), &ctx);
	} else {
		int lookup_flags = 0;
		if (!(at_flags & AT_SYMLINK_NOFOLLOW))
			lookup_flags = LOOKUP_FOLLOW;
		return filename_getxattr(dfd, filename, lookup_flags, &ctx);
	}
}

SYSCALL_DEFINE6(getxattrat, int, dfd, const char __user *, pathname, unsigned int, at_flags,
		const char __user *, name, struct xattr_args __user *, uargs, size_t, usize)
{
	struct xattr_args args = {};
	int error;

	BUILD_BUG_ON(sizeof(struct xattr_args) < XATTR_ARGS_SIZE_VER0);
	BUILD_BUG_ON(sizeof(struct xattr_args) != XATTR_ARGS_SIZE_LATEST);

	if (unlikely(usize < XATTR_ARGS_SIZE_VER0))
		return -EINVAL;
	if (usize > PAGE_SIZE)
		return -E2BIG;

	error = copy_struct_from_user(&args, sizeof(args), uargs, usize);
	if (error)
		return error;

	if (args.flags != 0)
		return -EINVAL;

	return path_getxattrat(dfd, pathname, at_flags, name,
			       u64_to_user_ptr(args.value), args.size);
}

/**
 * sys_getxattr - Retrieve an extended attribute value from a file
 * @pathname: Path to the file from which to retrieve the attribute
 * @name: Null-terminated name of the extended attribute (includes namespace prefix)
 * @value: Buffer to receive the attribute value, or NULL for size query
 * @size: Size of the value buffer in bytes, or 0 to query current size
 *
 * long-desc: Retrieves the value of an extended attribute identified by name
 *   from the file specified by pathname. Extended attributes are name:value
 *   pairs associated with inodes (files, directories, symbolic links, etc.)
 *   that extend the normal attributes (stat data) associated with all inodes.
 *
 *   The attribute name must include a namespace prefix. Valid namespaces are:
 *   - "user." - User-defined attributes (regular files and directories only)
 *   - "trusted." - Trusted attributes (requires CAP_SYS_ADMIN to read)
 *   - "security." - Security module attributes (e.g., SELinux, Smack, capabilities)
 *   - "system." - System attributes (e.g., POSIX ACLs via system.posix_acl_access)
 *
 *   If size is specified as zero, the call returns the current size of the
 *   attribute value without copying it to the buffer. This can be used to
 *   determine an appropriate buffer size for a subsequent call. However, the
 *   attribute value may change between calls (race condition with setxattr).
 *
 *   If size is non-zero and less than the actual attribute size, ERANGE is
 *   returned and no data is copied.
 *
 *   This syscall follows symbolic links. Use lgetxattr() to operate on the
 *   symbolic link itself, or fgetxattr() to operate on an open file descriptor.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: pathname
 *   type: KAPI_TYPE_PATH
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_USER_PATH
 *   constraint: Must be a valid null-terminated path string in user memory.
 *     The path is resolved following symbolic links. Maximum path length is
 *     PATH_MAX (4096 bytes). The file must exist and the caller must have
 *     search permission on all directory components.
 *
 * param: name
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_USER_STRING
 *   range: 1, 255
 *   constraint: Must be a valid null-terminated string in user memory containing
 *     the extended attribute name with namespace prefix (e.g., "user.myattr").
 *     The name (including prefix) must be between 1 and XATTR_NAME_MAX (255)
 *     characters. An empty name returns ERANGE.
 *
 * param: value
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER | KAPI_PARAM_OPTIONAL
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: When size is non-zero, must be a valid pointer to user memory
 *     that can receive up to size bytes. Can be NULL only when size is 0.
 *     The kernel writes the attribute value to this buffer on success.
 *
 * param: size
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, 65536
 *   constraint: Size of the value buffer in bytes. If zero, the syscall returns
 *     the current attribute size without copying data. If non-zero, must be at
 *     least as large as the attribute value; smaller buffers cause ERANGE.
 *     Values larger than XATTR_SIZE_MAX (65536) are silently clamped.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: >= 0
 *   desc: On success, returns the size of the extended attribute value in bytes.
 *     When size > 0, this is the number of bytes copied to the value buffer.
 *     When size = 0, this is the current size of the attribute (size query).
 *     The returned size may be 0 for attributes with empty values.
 *
 * error: ENODATA, Attribute not found
 *   desc: The named extended attribute does not exist on the file. Also returned
 *     when attempting to read user.* attributes on file types other than regular
 *     files or directories (symlinks, devices, sockets, FIFOs). Also returned
 *     when reading trusted.* namespace without CAP_SYS_ADMIN capability.
 *
 * error: ENOENT, File not found
 *   desc: The file specified by pathname does not exist, or a directory component
 *     in the path does not exist. Returned from path lookup (filename_lookup).
 *
 * error: ERANGE, Buffer too small
 *   desc: The size parameter is non-zero but smaller than the actual attribute
 *     value size. Also returned if the attribute name is empty (zero length) or
 *     exceeds XATTR_NAME_MAX (255 characters).
 *
 * error: EACCES, Permission denied
 *   desc: Permission denied during path resolution (search permission on a
 *     directory component), or read permission on the file is denied based on
 *     DAC permissions. Returned from inode_permission() check.
 *
 * error: EOPNOTSUPP, Operation not supported
 *   desc: The filesystem does not support extended attributes (IOP_XATTR flag
 *     not set), or no xattr handler exists for the given namespace prefix, or
 *     the handler does not implement the get operation. Also returned for
 *     direct POSIX ACL xattr reads (system.posix_acl_*) when processed through
 *     the normal xattr path (use do_get_acl instead).
 *
 * error: E2BIG, Value too large
 *   desc: The filesystem returned an attribute value larger than XATTR_SIZE_MAX
 *     (65536 bytes). This indicates a filesystem bug or corruption, as values
 *     exceeding this limit should not be storable.
 *
 * error: EFAULT, Bad address
 *   desc: One of the user pointers (pathname, name, or value) is invalid or
 *     points to memory that cannot be accessed. Returned from strncpy_from_user()
 *     for pathname/name or copy_to_user() for value.
 *
 * error: ENOMEM, Out of memory
 *   desc: Kernel could not allocate memory for the temporary buffer to hold
 *     the attribute value (via kvzalloc). The allocation size is capped at
 *     min(size, XATTR_SIZE_MAX).
 *
 * error: EIO, I/O error
 *   desc: The inode is marked as bad (is_bad_inode), indicating filesystem
 *     corruption or I/O failure. Also may be returned by filesystem-specific
 *     xattr handler operations.
 *
 * error: EINVAL, Invalid argument
 *   desc: The xattr name format is invalid - it matches a handler prefix but
 *     the remainder is malformed. Returned from xattr_resolve_name().
 *
 * error: ELOOP, Too many symbolic links
 *   desc: Too many symbolic links were encountered during path resolution
 *     (more than MAXSYMLINKS, typically 40).
 *
 * error: ENAMETOOLONG, Filename too long
 *   desc: The pathname or a component of the pathname exceeds the system limit
 *     (PATH_MAX or NAME_MAX).
 *
 * error: ENOTDIR, Not a directory
 *   desc: A component of the path prefix is not a directory.
 *
 * error: ESTALE, Stale file handle
 *   desc: The file handle became stale during the operation (NFS). The syscall
 *     automatically retries with LOOKUP_REVAL before returning this error.
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: Kernel buffer for attribute value
 *   desc: When size > 0, a kernel buffer is allocated via kvzalloc() to hold
 *     the attribute value before copying to userspace. This memory is freed
 *     (kvfree) after the operation completes, regardless of success or failure.
 *   reversible: yes
 *
 * capability: CAP_SYS_ADMIN
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Reading trusted.* namespace attributes
 *   without: Reading trusted.* returns ENODATA (appears as if attribute does
 *     not exist). This hides the existence and value of trusted attributes
 *     from unprivileged processes.
 *   condition: Attribute name starts with "trusted."
 *
 * constraint: Filesystem support
 *   desc: The filesystem must support extended attributes (have IOP_XATTR flag
 *     set and provide xattr handlers). Common filesystems supporting xattrs
 *     include ext4, XFS, Btrfs, and tmpfs. Some filesystems (e.g., FAT, older
 *     ext2) do not support extended attributes.
 *
 * constraint: user.* namespace restrictions
 *   desc: The user.* namespace is only supported on regular files and directories.
 *     Attempting to read user.* attributes from other file types (symlinks,
 *     devices, sockets, FIFOs) returns ENODATA as if the attribute doesn't exist.
 *
 * constraint: LSM checks
 *   desc: Linux Security Modules (SELinux, Smack, AppArmor) may impose additional
 *     restrictions via security_inode_getxattr() hook. These can deny access to
 *     certain attributes based on security policy. For security.* namespace
 *     attributes, the LSM's own getsecurity handler may be used instead of the
 *     filesystem's handler.
 *
 * examples: getxattr("/path/file", "user.comment", buf, sizeof(buf));  // Read user attr
 *   getxattr("/path/file", "security.selinux", buf, sizeof(buf));  // Read SELinux label
 *   getxattr("/path/file", "user.test", NULL, 0);  // Query attribute size
 *
 * notes: Extended attributes provide a way to retrieve arbitrary metadata from
 *   files beyond the standard stat attributes. Common uses include:
 *   - SELinux security contexts (security.selinux)
 *   - File capabilities (security.capability)
 *   - POSIX ACLs (system.posix_acl_access, system.posix_acl_default)
 *   - User-defined metadata (user.* namespace)
 *
 *   The common pattern for reading an xattr of unknown size is:
 *   1. Call getxattr() with size=0 to get the current size
 *   2. Allocate a buffer of that size
 *   3. Call getxattr() again with the buffer
 *   Note: The attribute value may change between steps 1 and 3 if another
 *   process modifies it. Handle ERANGE by retrying with a larger buffer.
 *
 *   The trusted.* namespace is designed for use by privileged processes to store
 *   data that should not be readable by unprivileged users. Without CAP_SYS_ADMIN,
 *   these attributes appear to not exist (ENODATA), hiding even their presence.
 *
 *   For POSIX ACL attributes (system.posix_acl_access, system.posix_acl_default),
 *   the kernel handles translation between the internal ACL format and the
 *   xattr representation. In user namespaces, uid/gid values in ACLs are mapped
 *   appropriately.
 *
 *   Historical note: A bug fix (commit 82c9a927bc5d) corrected an issue where
 *   user namespace ACL fixup was skipped when the buffer size had certain
 *   alignment characteristics.
 *
 * since-version: 2.4
 */
SYSCALL_DEFINE4(getxattr, const char __user *, pathname,
		const char __user *, name, void __user *, value, size_t, size)
{
	return path_getxattrat(AT_FDCWD, pathname, 0, name, value, size);
}

SYSCALL_DEFINE4(lgetxattr, const char __user *, pathname,
		const char __user *, name, void __user *, value, size_t, size)
{
	return path_getxattrat(AT_FDCWD, pathname, AT_SYMLINK_NOFOLLOW, name,
			       value, size);
}

SYSCALL_DEFINE4(fgetxattr, int, fd, const char __user *, name,
		void __user *, value, size_t, size)
{
	return path_getxattrat(fd, NULL, AT_EMPTY_PATH, name, value, size);
}

/*
 * Extended attribute LIST operations
 */
static ssize_t
listxattr(struct dentry *d, char __user *list, size_t size)
{
	ssize_t error;
	char *klist = NULL;

	if (size) {
		if (size > XATTR_LIST_MAX)
			size = XATTR_LIST_MAX;
		klist = kvmalloc(size, GFP_KERNEL);
		if (!klist)
			return -ENOMEM;
	}

	error = vfs_listxattr(d, klist, size);
	if (error > 0) {
		if (size && copy_to_user(list, klist, error))
			error = -EFAULT;
	} else if (error == -ERANGE && size >= XATTR_LIST_MAX) {
		/* The file system tried to returned a list bigger
		   than XATTR_LIST_MAX bytes. Not possible. */
		error = -E2BIG;
	}

	kvfree(klist);

	return error;
}

static
ssize_t file_listxattr(struct file *f, char __user *list, size_t size)
{
	audit_file(f);
	return listxattr(f->f_path.dentry, list, size);
}

/* unconditionally consumes filename */
static
ssize_t filename_listxattr(int dfd, struct filename *filename,
			   unsigned int lookup_flags,
			   char __user *list, size_t size)
{
	struct path path;
	ssize_t error;
retry:
	error = filename_lookup(dfd, filename, lookup_flags, &path, NULL);
	if (error)
		goto out;
	error = listxattr(path.dentry, list, size);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	putname(filename);
	return error;
}

static ssize_t path_listxattrat(int dfd, const char __user *pathname,
				unsigned int at_flags, char __user *list,
				size_t size)
{
	struct filename *filename;
	int lookup_flags;

	if ((at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
		return -EINVAL;

	filename = getname_maybe_null(pathname, at_flags);
	if (!filename) {
		CLASS(fd, f)(dfd);
		if (fd_empty(f))
			return -EBADF;
		return file_listxattr(fd_file(f), list, size);
	}

	lookup_flags = (at_flags & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW;
	return filename_listxattr(dfd, filename, lookup_flags, list, size);
}

SYSCALL_DEFINE5(listxattrat, int, dfd, const char __user *, pathname,
		unsigned int, at_flags,
		char __user *, list, size_t, size)
{
	return path_listxattrat(dfd, pathname, at_flags, list, size);
}

SYSCALL_DEFINE3(listxattr, const char __user *, pathname, char __user *, list,
		size_t, size)
{
	return path_listxattrat(AT_FDCWD, pathname, 0, list, size);
}

SYSCALL_DEFINE3(llistxattr, const char __user *, pathname, char __user *, list,
		size_t, size)
{
	return path_listxattrat(AT_FDCWD, pathname, AT_SYMLINK_NOFOLLOW, list, size);
}

SYSCALL_DEFINE3(flistxattr, int, fd, char __user *, list, size_t, size)
{
	return path_listxattrat(fd, NULL, AT_EMPTY_PATH, list, size);
}

/*
 * Extended attribute REMOVE operations
 */
static long
removexattr(struct mnt_idmap *idmap, struct dentry *d, const char *name)
{
	if (is_posix_acl_xattr(name))
		return vfs_remove_acl(idmap, d, name);
	return vfs_removexattr(idmap, d, name);
}

static int file_removexattr(struct file *f, struct xattr_name *kname)
{
	int error = mnt_want_write_file(f);

	if (!error) {
		audit_file(f);
		error = removexattr(file_mnt_idmap(f),
				    f->f_path.dentry, kname->name);
		mnt_drop_write_file(f);
	}
	return error;
}

/* unconditionally consumes filename */
static int filename_removexattr(int dfd, struct filename *filename,
				unsigned int lookup_flags, struct xattr_name *kname)
{
	struct path path;
	int error;

retry:
	error = filename_lookup(dfd, filename, lookup_flags, &path, NULL);
	if (error)
		goto out;
	error = mnt_want_write(path.mnt);
	if (!error) {
		error = removexattr(mnt_idmap(path.mnt), path.dentry, kname->name);
		mnt_drop_write(path.mnt);
	}
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	putname(filename);
	return error;
}

static int path_removexattrat(int dfd, const char __user *pathname,
			      unsigned int at_flags, const char __user *name)
{
	struct xattr_name kname;
	struct filename *filename;
	unsigned int lookup_flags;
	int error;

	if ((at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
		return -EINVAL;

	error = import_xattr_name(&kname, name);
	if (error)
		return error;

	filename = getname_maybe_null(pathname, at_flags);
	if (!filename) {
		CLASS(fd, f)(dfd);
		if (fd_empty(f))
			return -EBADF;
		return file_removexattr(fd_file(f), &kname);
	}
	lookup_flags = (at_flags & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW;
	return filename_removexattr(dfd, filename, lookup_flags, &kname);
}

SYSCALL_DEFINE4(removexattrat, int, dfd, const char __user *, pathname,
		unsigned int, at_flags, const char __user *, name)
{
	return path_removexattrat(dfd, pathname, at_flags, name);
}

SYSCALL_DEFINE2(removexattr, const char __user *, pathname,
		const char __user *, name)
{
	return path_removexattrat(AT_FDCWD, pathname, 0, name);
}

SYSCALL_DEFINE2(lremovexattr, const char __user *, pathname,
		const char __user *, name)
{
	return path_removexattrat(AT_FDCWD, pathname, AT_SYMLINK_NOFOLLOW, name);
}

SYSCALL_DEFINE2(fremovexattr, int, fd, const char __user *, name)
{
	return path_removexattrat(fd, NULL, AT_EMPTY_PATH, name);
}

int xattr_list_one(char **buffer, ssize_t *remaining_size, const char *name)
{
	size_t len;

	len = strlen(name) + 1;
	if (*buffer) {
		if (*remaining_size < len)
			return -ERANGE;
		memcpy(*buffer, name, len);
		*buffer += len;
	}
	*remaining_size -= len;
	return 0;
}

/**
 * generic_listxattr - run through a dentry's xattr list() operations
 * @dentry: dentry to list the xattrs
 * @buffer: result buffer
 * @buffer_size: size of @buffer
 *
 * Combine the results of the list() operation from every xattr_handler in the
 * xattr_handler stack.
 *
 * Note that this will not include the entries for POSIX ACLs.
 */
ssize_t
generic_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	const struct xattr_handler *handler, * const *handlers = dentry->d_sb->s_xattr;
	ssize_t remaining_size = buffer_size;

	for_each_xattr_handler(handlers, handler) {
		int err;

		if (!handler->name || (handler->list && !handler->list(dentry)))
			continue;
		err = xattr_list_one(&buffer, &remaining_size, handler->name);
		if (err)
			return err;
	}

	return buffer_size - remaining_size;
}
EXPORT_SYMBOL(generic_listxattr);

/**
 * xattr_full_name  -  Compute full attribute name from suffix
 *
 * @handler:	handler of the xattr_handler operation
 * @name:	name passed to the xattr_handler operation
 *
 * The get and set xattr handler operations are called with the remainder of
 * the attribute name after skipping the handler's prefix: for example, "foo"
 * is passed to the get operation of a handler with prefix "user." to get
 * attribute "user.foo".  The full name is still "there" in the name though.
 *
 * Note: the list xattr handler operation when called from the vfs is passed a
 * NULL name; some file systems use this operation internally, with varying
 * semantics.
 */
const char *xattr_full_name(const struct xattr_handler *handler,
			    const char *name)
{
	size_t prefix_len = strlen(xattr_prefix(handler));

	return name - prefix_len;
}
EXPORT_SYMBOL(xattr_full_name);

/**
 * simple_xattr_space - estimate the memory used by a simple xattr
 * @name: the full name of the xattr
 * @size: the size of its value
 *
 * This takes no account of how much larger the two slab objects actually are:
 * that would depend on the slab implementation, when what is required is a
 * deterministic number, which grows with name length and size and quantity.
 *
 * Return: The approximate number of bytes of memory used by such an xattr.
 */
size_t simple_xattr_space(const char *name, size_t size)
{
	/*
	 * Use "40" instead of sizeof(struct simple_xattr), to return the
	 * same result on 32-bit and 64-bit, and even if simple_xattr grows.
	 */
	return 40 + size + strlen(name);
}

/**
 * simple_xattr_free - free an xattr object
 * @xattr: the xattr object
 *
 * Free the xattr object. Can handle @xattr being NULL.
 */
void simple_xattr_free(struct simple_xattr *xattr)
{
	if (xattr)
		kfree(xattr->name);
	kvfree(xattr);
}

/**
 * simple_xattr_alloc - allocate new xattr object
 * @value: value of the xattr object
 * @size: size of @value
 *
 * Allocate a new xattr object and initialize respective members. The caller is
 * responsible for handling the name of the xattr.
 *
 * Return: On success a new xattr object is returned. On failure NULL is
 * returned.
 */
struct simple_xattr *simple_xattr_alloc(const void *value, size_t size)
{
	struct simple_xattr *new_xattr;
	size_t len;

	/* wrap around? */
	len = sizeof(*new_xattr) + size;
	if (len < sizeof(*new_xattr))
		return NULL;

	new_xattr = kvmalloc(len, GFP_KERNEL_ACCOUNT);
	if (!new_xattr)
		return NULL;

	new_xattr->size = size;
	memcpy(new_xattr->value, value, size);
	return new_xattr;
}

/**
 * rbtree_simple_xattr_cmp - compare xattr name with current rbtree xattr entry
 * @key: xattr name
 * @node: current node
 *
 * Compare the xattr name with the xattr name attached to @node in the rbtree.
 *
 * Return: Negative value if continuing left, positive if continuing right, 0
 * if the xattr attached to @node matches @key.
 */
static int rbtree_simple_xattr_cmp(const void *key, const struct rb_node *node)
{
	const char *xattr_name = key;
	const struct simple_xattr *xattr;

	xattr = rb_entry(node, struct simple_xattr, rb_node);
	return strcmp(xattr->name, xattr_name);
}

/**
 * rbtree_simple_xattr_node_cmp - compare two xattr rbtree nodes
 * @new_node: new node
 * @node: current node
 *
 * Compare the xattr attached to @new_node with the xattr attached to @node.
 *
 * Return: Negative value if continuing left, positive if continuing right, 0
 * if the xattr attached to @new_node matches the xattr attached to @node.
 */
static int rbtree_simple_xattr_node_cmp(struct rb_node *new_node,
					const struct rb_node *node)
{
	struct simple_xattr *xattr;
	xattr = rb_entry(new_node, struct simple_xattr, rb_node);
	return rbtree_simple_xattr_cmp(xattr->name, node);
}

/**
 * simple_xattr_get - get an xattr object
 * @xattrs: the header of the xattr object
 * @name: the name of the xattr to retrieve
 * @buffer: the buffer to store the value into
 * @size: the size of @buffer
 *
 * Try to find and retrieve the xattr object associated with @name.
 * If @buffer is provided store the value of @xattr in @buffer
 * otherwise just return the length. The size of @buffer is limited
 * to XATTR_SIZE_MAX which currently is 65536.
 *
 * Return: On success the length of the xattr value is returned. On error a
 * negative error code is returned.
 */
int simple_xattr_get(struct simple_xattrs *xattrs, const char *name,
		     void *buffer, size_t size)
{
	struct simple_xattr *xattr = NULL;
	struct rb_node *rbp;
	int ret = -ENODATA;

	read_lock(&xattrs->lock);
	rbp = rb_find(name, &xattrs->rb_root, rbtree_simple_xattr_cmp);
	if (rbp) {
		xattr = rb_entry(rbp, struct simple_xattr, rb_node);
		ret = xattr->size;
		if (buffer) {
			if (size < xattr->size)
				ret = -ERANGE;
			else
				memcpy(buffer, xattr->value, xattr->size);
		}
	}
	read_unlock(&xattrs->lock);
	return ret;
}

/**
 * simple_xattr_set - set an xattr object
 * @xattrs: the header of the xattr object
 * @name: the name of the xattr to retrieve
 * @value: the value to store along the xattr
 * @size: the size of @value
 * @flags: the flags determining how to set the xattr
 *
 * Set a new xattr object.
 * If @value is passed a new xattr object will be allocated. If XATTR_REPLACE
 * is specified in @flags a matching xattr object for @name must already exist.
 * If it does it will be replaced with the new xattr object. If it doesn't we
 * fail. If XATTR_CREATE is specified and a matching xattr does already exist
 * we fail. If it doesn't we create a new xattr. If @flags is zero we simply
 * insert the new xattr replacing any existing one.
 *
 * If @value is empty and a matching xattr object is found we delete it if
 * XATTR_REPLACE is specified in @flags or @flags is zero.
 *
 * If @value is empty and no matching xattr object for @name is found we do
 * nothing if XATTR_CREATE is specified in @flags or @flags is zero. For
 * XATTR_REPLACE we fail as mentioned above.
 *
 * Return: On success, the removed or replaced xattr is returned, to be freed
 * by the caller; or NULL if none. On failure a negative error code is returned.
 */
struct simple_xattr *simple_xattr_set(struct simple_xattrs *xattrs,
				      const char *name, const void *value,
				      size_t size, int flags)
{
	struct simple_xattr *old_xattr = NULL, *new_xattr = NULL;
	struct rb_node *parent = NULL, **rbp;
	int err = 0, ret;

	/* value == NULL means remove */
	if (value) {
		new_xattr = simple_xattr_alloc(value, size);
		if (!new_xattr)
			return ERR_PTR(-ENOMEM);

		new_xattr->name = kstrdup(name, GFP_KERNEL_ACCOUNT);
		if (!new_xattr->name) {
			simple_xattr_free(new_xattr);
			return ERR_PTR(-ENOMEM);
		}
	}

	write_lock(&xattrs->lock);
	rbp = &xattrs->rb_root.rb_node;
	while (*rbp) {
		parent = *rbp;
		ret = rbtree_simple_xattr_cmp(name, *rbp);
		if (ret < 0)
			rbp = &(*rbp)->rb_left;
		else if (ret > 0)
			rbp = &(*rbp)->rb_right;
		else
			old_xattr = rb_entry(*rbp, struct simple_xattr, rb_node);
		if (old_xattr)
			break;
	}

	if (old_xattr) {
		/* Fail if XATTR_CREATE is requested and the xattr exists. */
		if (flags & XATTR_CREATE) {
			err = -EEXIST;
			goto out_unlock;
		}

		if (new_xattr)
			rb_replace_node(&old_xattr->rb_node,
					&new_xattr->rb_node, &xattrs->rb_root);
		else
			rb_erase(&old_xattr->rb_node, &xattrs->rb_root);
	} else {
		/* Fail if XATTR_REPLACE is requested but no xattr is found. */
		if (flags & XATTR_REPLACE) {
			err = -ENODATA;
			goto out_unlock;
		}

		/*
		 * If XATTR_CREATE or no flags are specified together with a
		 * new value simply insert it.
		 */
		if (new_xattr) {
			rb_link_node(&new_xattr->rb_node, parent, rbp);
			rb_insert_color(&new_xattr->rb_node, &xattrs->rb_root);
		}

		/*
		 * If XATTR_CREATE or no flags are specified and neither an
		 * old or new xattr exist then we don't need to do anything.
		 */
	}

out_unlock:
	write_unlock(&xattrs->lock);
	if (!err)
		return old_xattr;
	simple_xattr_free(new_xattr);
	return ERR_PTR(err);
}

static bool xattr_is_trusted(const char *name)
{
	return !strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN);
}

static bool xattr_is_maclabel(const char *name)
{
	const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;

	return !strncmp(name, XATTR_SECURITY_PREFIX,
			XATTR_SECURITY_PREFIX_LEN) &&
		security_ismaclabel(suffix);
}

/**
 * simple_xattr_list - list all xattr objects
 * @inode: inode from which to get the xattrs
 * @xattrs: the header of the xattr object
 * @buffer: the buffer to store all xattrs into
 * @size: the size of @buffer
 *
 * List all xattrs associated with @inode. If @buffer is NULL we returned
 * the required size of the buffer. If @buffer is provided we store the
 * xattrs value into it provided it is big enough.
 *
 * Note, the number of xattr names that can be listed with listxattr(2) is
 * limited to XATTR_LIST_MAX aka 65536 bytes. If a larger buffer is passed
 * then vfs_listxattr() caps it to XATTR_LIST_MAX and if more xattr names
 * are found it will return -E2BIG.
 *
 * Return: On success the required size or the size of the copied xattrs is
 * returned. On error a negative error code is returned.
 */
ssize_t simple_xattr_list(struct inode *inode, struct simple_xattrs *xattrs,
			  char *buffer, size_t size)
{
	bool trusted = ns_capable_noaudit(&init_user_ns, CAP_SYS_ADMIN);
	struct simple_xattr *xattr;
	struct rb_node *rbp;
	ssize_t remaining_size = size;
	int err = 0;

	err = posix_acl_listxattr(inode, &buffer, &remaining_size);
	if (err)
		return err;

	err = security_inode_listsecurity(inode, buffer, remaining_size);
	if (err < 0)
		return err;

	if (buffer) {
		if (remaining_size < err)
			return -ERANGE;
		buffer += err;
	}
	remaining_size -= err;
	err = 0;

	read_lock(&xattrs->lock);
	for (rbp = rb_first(&xattrs->rb_root); rbp; rbp = rb_next(rbp)) {
		xattr = rb_entry(rbp, struct simple_xattr, rb_node);

		/* skip "trusted." attributes for unprivileged callers */
		if (!trusted && xattr_is_trusted(xattr->name))
			continue;

		/* skip MAC labels; these are provided by LSM above */
		if (xattr_is_maclabel(xattr->name))
			continue;

		err = xattr_list_one(&buffer, &remaining_size, xattr->name);
		if (err)
			break;
	}
	read_unlock(&xattrs->lock);

	return err ? err : size - remaining_size;
}

/**
 * rbtree_simple_xattr_less - compare two xattr rbtree nodes
 * @new_node: new node
 * @node: current node
 *
 * Compare the xattr attached to @new_node with the xattr attached to @node.
 * Note that this function technically tolerates duplicate entries.
 *
 * Return: True if insertion point in the rbtree is found.
 */
static bool rbtree_simple_xattr_less(struct rb_node *new_node,
				     const struct rb_node *node)
{
	return rbtree_simple_xattr_node_cmp(new_node, node) < 0;
}

/**
 * simple_xattr_add - add xattr objects
 * @xattrs: the header of the xattr object
 * @new_xattr: the xattr object to add
 *
 * Add an xattr object to @xattrs. This assumes no replacement or removal
 * of matching xattrs is wanted. Should only be called during inode
 * initialization when a few distinct initial xattrs are supposed to be set.
 */
void simple_xattr_add(struct simple_xattrs *xattrs,
		      struct simple_xattr *new_xattr)
{
	write_lock(&xattrs->lock);
	rb_add(&new_xattr->rb_node, &xattrs->rb_root, rbtree_simple_xattr_less);
	write_unlock(&xattrs->lock);
}

/**
 * simple_xattrs_init - initialize new xattr header
 * @xattrs: header to initialize
 *
 * Initialize relevant fields of a an xattr header.
 */
void simple_xattrs_init(struct simple_xattrs *xattrs)
{
	xattrs->rb_root = RB_ROOT;
	rwlock_init(&xattrs->lock);
}

/**
 * simple_xattrs_free - free xattrs
 * @xattrs: xattr header whose xattrs to destroy
 * @freed_space: approximate number of bytes of memory freed from @xattrs
 *
 * Destroy all xattrs in @xattr. When this is called no one can hold a
 * reference to any of the xattrs anymore.
 */
void simple_xattrs_free(struct simple_xattrs *xattrs, size_t *freed_space)
{
	struct rb_node *rbp;

	if (freed_space)
		*freed_space = 0;
	rbp = rb_first(&xattrs->rb_root);
	while (rbp) {
		struct simple_xattr *xattr;
		struct rb_node *rbp_next;

		rbp_next = rb_next(rbp);
		xattr = rb_entry(rbp, struct simple_xattr, rb_node);
		rb_erase(&xattr->rb_node, &xattrs->rb_root);
		if (freed_space)
			*freed_space += simple_xattr_space(xattr->name,
							   xattr->size);
		simple_xattr_free(xattr);
		rbp = rbp_next;
	}
}
