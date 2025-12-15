/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/prefetch.h>
#include "mount.h"
#include "internal.h"

struct prepend_buffer {
	char *buf;
	int len;
};
#define DECLARE_BUFFER(__name, __buf, __len) \
	struct prepend_buffer __name = {.buf = __buf + __len, .len = __len}

static char *extract_string(struct prepend_buffer *p)
{
	if (likely(p->len >= 0))
		return p->buf;
	return ERR_PTR(-ENAMETOOLONG);
}

static bool prepend_char(struct prepend_buffer *p, unsigned char c)
{
	if (likely(p->len > 0)) {
		p->len--;
		*--p->buf = c;
		return true;
	}
	p->len = -1;
	return false;
}

/*
 * The source of the prepend data can be an optimistic load
 * of a dentry name and length. And because we don't hold any
 * locks, the length and the pointer to the name may not be
 * in sync if a concurrent rename happens, and the kernel
 * copy might fault as a result.
 *
 * The end result will correct itself when we check the
 * rename sequence count, but we need to be able to handle
 * the fault gracefully.
 */
static bool prepend_copy(void *dst, const void *src, int len)
{
	if (unlikely(copy_from_kernel_nofault(dst, src, len))) {
		memset(dst, 'x', len);
		return false;
	}
	return true;
}

static bool prepend(struct prepend_buffer *p, const char *str, int namelen)
{
	// Already overflowed?
	if (p->len < 0)
		return false;

	// Will overflow?
	if (p->len < namelen) {
		// Fill as much as possible from the end of the name
		str += namelen - p->len;
		p->buf -= p->len;
		prepend_copy(p->buf, str, p->len);
		p->len = -1;
		return false;
	}

	// Fits fully
	p->len -= namelen;
	p->buf -= namelen;
	return prepend_copy(p->buf, str, namelen);
}

/**
 * prepend_name - prepend a pathname in front of current buffer pointer
 * @p: prepend buffer which contains buffer pointer and allocated length
 * @name: name string and length qstr structure
 *
 * With RCU path tracing, it may race with d_move(). Use READ_ONCE() to
 * make sure that either the old or the new name pointer and length are
 * fetched. However, there may be mismatch between length and pointer.
 * But since the length cannot be trusted, we need to copy the name very
 * carefully when doing the prepend_copy(). It also prepends "/" at
 * the beginning of the name. The sequence number check at the caller will
 * retry it again when a d_move() does happen. So any garbage in the buffer
 * due to mismatched pointer and length will be discarded.
 *
 * Load acquire is needed to make sure that we see the new name data even
 * if we might get the length wrong.
 */
static bool prepend_name(struct prepend_buffer *p, const struct qstr *name)
{
	const char *dname = smp_load_acquire(&name->name); /* ^^^ */
	u32 dlen = READ_ONCE(name->len);

	return prepend(p, dname, dlen) && prepend_char(p, '/');
}

static int __prepend_path(const struct dentry *dentry, const struct mount *mnt,
			  const struct path *root, struct prepend_buffer *p)
{
	while (dentry != root->dentry || &mnt->mnt != root->mnt) {
		const struct dentry *parent = READ_ONCE(dentry->d_parent);

		if (dentry == mnt->mnt.mnt_root) {
			struct mount *m = READ_ONCE(mnt->mnt_parent);
			struct mnt_namespace *mnt_ns;

			if (likely(mnt != m)) {
				dentry = READ_ONCE(mnt->mnt_mountpoint);
				mnt = m;
				continue;
			}
			/* Global root */
			mnt_ns = READ_ONCE(mnt->mnt_ns);
			/* open-coded is_mounted() to use local mnt_ns */
			if (!IS_ERR_OR_NULL(mnt_ns) && !is_anon_ns(mnt_ns))
				return 1;	// absolute root
			else
				return 2;	// detached or not attached yet
		}

		if (unlikely(dentry == parent))
			/* Escaped? */
			return 3;

		prefetch(parent);
		if (!prepend_name(p, &dentry->d_name))
			break;
		dentry = parent;
	}
	return 0;
}

/**
 * prepend_path - Prepend path string to a buffer
 * @path: the dentry/vfsmount to report
 * @root: root vfsmnt/dentry
 * @p: prepend buffer which contains buffer pointer and allocated length
 *
 * The function will first try to write out the pathname without taking any
 * lock other than the RCU read lock to make sure that dentries won't go away.
 * It only checks the sequence number of the global rename_lock as any change
 * in the dentry's d_seq will be preceded by changes in the rename_lock
 * sequence number. If the sequence number had been changed, it will restart
 * the whole pathname back-tracing sequence again by taking the rename_lock.
 * In this case, there is no need to take the RCU read lock as the recursive
 * parent pointer references will keep the dentry chain alive as long as no
 * rename operation is performed.
 */
static int prepend_path(const struct path *path,
			const struct path *root,
			struct prepend_buffer *p)
{
	unsigned seq, m_seq = 0;
	struct prepend_buffer b;
	int error;

	rcu_read_lock();
restart_mnt:
	read_seqbegin_or_lock(&mount_lock, &m_seq);
	seq = 0;
	rcu_read_lock();
restart:
	b = *p;
	read_seqbegin_or_lock(&rename_lock, &seq);
	error = __prepend_path(path->dentry, real_mount(path->mnt), root, &b);
	if (!(seq & 1))
		rcu_read_unlock();
	if (need_seqretry(&rename_lock, seq)) {
		seq = 1;
		goto restart;
	}
	done_seqretry(&rename_lock, seq);

	if (!(m_seq & 1))
		rcu_read_unlock();
	if (need_seqretry(&mount_lock, m_seq)) {
		m_seq = 1;
		goto restart_mnt;
	}
	done_seqretry(&mount_lock, m_seq);

	if (unlikely(error == 3))
		b = *p;

	if (b.len == p->len)
		prepend_char(&b, '/');

	*p = b;
	return error;
}

/**
 * __d_path - return the path of a dentry
 * @path: the dentry/vfsmount to report
 * @root: root vfsmnt/dentry
 * @buf: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name.
 *
 * Returns a pointer into the buffer or an error code if the
 * path was too long.
 *
 * "buflen" should be positive.
 *
 * If the path is not reachable from the supplied root, return %NULL.
 */
char *__d_path(const struct path *path,
	       const struct path *root,
	       char *buf, int buflen)
{
	DECLARE_BUFFER(b, buf, buflen);

	prepend_char(&b, 0);
	if (unlikely(prepend_path(path, root, &b) > 0))
		return NULL;
	return extract_string(&b);
}

char *d_absolute_path(const struct path *path,
	       char *buf, int buflen)
{
	struct path root = {};
	DECLARE_BUFFER(b, buf, buflen);

	prepend_char(&b, 0);
	if (unlikely(prepend_path(path, &root, &b) > 1))
		return ERR_PTR(-EINVAL);
	return extract_string(&b);
}

static void get_fs_root_rcu(struct fs_struct *fs, struct path *root)
{
	unsigned seq;

	do {
		seq = read_seqbegin(&fs->seq);
		*root = fs->root;
	} while (read_seqretry(&fs->seq, seq));
}

/**
 * d_path - return the path of a dentry
 * @path: path to report
 * @buf: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name. If the entry has been deleted
 * the string " (deleted)" is appended. Note that this is ambiguous.
 *
 * Returns a pointer into the buffer or an error code if the path was
 * too long. Note: Callers should use the returned pointer, not the passed
 * in buffer, to use the name! The implementation often starts at an offset
 * into the buffer, and may leave 0 bytes at the start.
 *
 * "buflen" should be positive.
 */
char *d_path(const struct path *path, char *buf, int buflen)
{
	DECLARE_BUFFER(b, buf, buflen);
	struct path root;

	/*
	 * We have various synthetic filesystems that never get mounted.  On
	 * these filesystems dentries are never used for lookup purposes, and
	 * thus don't need to be hashed.  They also don't need a name until a
	 * user wants to identify the object in /proc/pid/fd/.  The little hack
	 * below allows us to generate a name for these objects on demand:
	 *
	 * Some pseudo inodes are mountable.  When they are mounted
	 * path->dentry == path->mnt->mnt_root.  In that case don't call d_dname
	 * and instead have d_path return the mounted path.
	 */
	if (path->dentry->d_op && path->dentry->d_op->d_dname &&
	    (!IS_ROOT(path->dentry) || path->dentry != path->mnt->mnt_root))
		return path->dentry->d_op->d_dname(path->dentry, buf, buflen);

	rcu_read_lock();
	get_fs_root_rcu(current->fs, &root);
	if (unlikely(d_unlinked(path->dentry)))
		prepend(&b, " (deleted)", 11);
	else
		prepend_char(&b, 0);
	prepend_path(path, &root, &b);
	rcu_read_unlock();

	return extract_string(&b);
}
EXPORT_SYMBOL(d_path);

/*
 * Helper function for dentry_operations.d_dname() members
 */
char *dynamic_dname(char *buffer, int buflen, const char *fmt, ...)
{
	va_list args;
	char temp[64];
	int sz;

	va_start(args, fmt);
	sz = vsnprintf(temp, sizeof(temp), fmt, args) + 1;
	va_end(args);

	if (sz > sizeof(temp) || sz > buflen)
		return ERR_PTR(-ENAMETOOLONG);

	buffer += buflen - sz;
	return memcpy(buffer, temp, sz);
}

char *simple_dname(struct dentry *dentry, char *buffer, int buflen)
{
	DECLARE_BUFFER(b, buffer, buflen);
	/* these dentries are never renamed, so d_lock is not needed */
	prepend(&b, " (deleted)", 11);
	prepend(&b, dentry->d_name.name, dentry->d_name.len);
	prepend_char(&b, '/');
	return extract_string(&b);
}

/*
 * Write full pathname from the root of the filesystem into the buffer.
 */
static char *__dentry_path(const struct dentry *d, struct prepend_buffer *p)
{
	const struct dentry *dentry;
	struct prepend_buffer b;
	int seq = 0;

	rcu_read_lock();
restart:
	dentry = d;
	b = *p;
	read_seqbegin_or_lock(&rename_lock, &seq);
	while (!IS_ROOT(dentry)) {
		const struct dentry *parent = dentry->d_parent;

		prefetch(parent);
		if (!prepend_name(&b, &dentry->d_name))
			break;
		dentry = parent;
	}
	if (!(seq & 1))
		rcu_read_unlock();
	if (need_seqretry(&rename_lock, seq)) {
		seq = 1;
		goto restart;
	}
	done_seqretry(&rename_lock, seq);
	if (b.len == p->len)
		prepend_char(&b, '/');
	return extract_string(&b);
}

char *dentry_path_raw(const struct dentry *dentry, char *buf, int buflen)
{
	DECLARE_BUFFER(b, buf, buflen);

	prepend_char(&b, 0);
	return __dentry_path(dentry, &b);
}
EXPORT_SYMBOL(dentry_path_raw);

char *dentry_path(const struct dentry *dentry, char *buf, int buflen)
{
	DECLARE_BUFFER(b, buf, buflen);

	if (unlikely(d_unlinked(dentry)))
		prepend(&b, "//deleted", 10);
	else
		prepend_char(&b, 0);
	return __dentry_path(dentry, &b);
}

static void get_fs_root_and_pwd_rcu(struct fs_struct *fs, struct path *root,
				    struct path *pwd)
{
	unsigned seq;

	do {
		seq = read_seqbegin(&fs->seq);
		*root = fs->root;
		*pwd = fs->pwd;
	} while (read_seqretry(&fs->seq, seq));
}

/**
 * sys_getcwd - Get the pathname of the current working directory
 * @buf: User-space buffer to receive the null-terminated pathname
 * @size: Size of the user-space buffer in bytes
 *
 * long-desc: Returns the absolute pathname of the current working directory
 *   for the calling process. The pathname is written to the user-provided
 *   buffer including the null terminator. This is a fundamental filesystem
 *   operation used by shells, file managers, and applications that need to
 *   track their location in the filesystem hierarchy.
 *
 *   The kernel syscall differs from the POSIX getcwd(3) library function.
 *   While the library function returns a pointer to the buffer on success
 *   and NULL on error (with errno set), the syscall returns the length of
 *   the pathname (including the null terminator) on success, or a negative
 *   error code on failure.
 *
 *   The syscall does NOT support NULL buffer with automatic allocation -
 *   that is a glibc extension handled entirely in userspace. The kernel
 *   always requires a valid user buffer.
 *
 *   If the current working directory is not reachable from the process's
 *   root directory (for example, after chroot() without chdir()), the
 *   returned pathname is prefixed with "(unreachable)". Since Linux 2.6.36,
 *   this prefix is added; glibc 2.27+ correctly returns ENOENT for such
 *   unreachable paths instead of returning the prefixed path.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: buf
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid writable user-space buffer of at least size
 *     bytes. The buffer receives the null-terminated absolute pathname of the
 *     current working directory. If buf is NULL or points to invalid memory,
 *     the syscall returns EFAULT. The kernel does not support NULL buffer with
 *     automatic allocation (unlike glibc's getcwd wrapper).
 *
 * param: size
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 2, 4294967295
 *   constraint: Size of the user buffer in bytes. Must be large enough to hold
 *     the complete pathname including the null terminator. The minimum valid
 *     path is "/" (2 bytes with null), so size must be at least 2 for any
 *     success. If size is smaller than the actual path length, ERANGE is
 *     returned. Internally, pathnames are limited to PATH_MAX (4096 bytes).
 *     Values of 0 or 1 always result in ERANGE since no valid path fits.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: positive length (includes null terminator)
 *   desc: On success, returns the length of the pathname written to buf,
 *     including the terminating null byte. This is always at least 2 (for "/").
 *     The returned value can be used to determine exactly how much of the buffer
 *     was used. On error, returns a negative error code. Note this differs from
 *     the POSIX getcwd(3) which returns the buffer pointer on success.
 *
 * error: ERANGE, Buffer too small
 *   desc: The size argument is less than the length of the absolute pathname
 *     of the current working directory, including the null terminator. This
 *     includes the case where size is 0 or 1, since even the shortest path "/"
 *     requires 2 bytes. The caller should retry with a larger buffer, typically
 *     PATH_MAX (4096) bytes to guarantee success for any valid path.
 *
 * error: ENOENT, Directory unlinked
 *   desc: The current working directory has been unlinked (deleted). This occurs
 *     when a process's working directory is removed while the process still has
 *     it as cwd. The directory still exists on disk (the inode is pinned by the
 *     process's reference) but has no name in the filesystem namespace. The
 *     condition is detected via d_unlinked() which checks both that the dentry
 *     is unhashed and is not the root.
 *
 * error: ENOMEM, Memory allocation failure
 *   desc: The kernel could not allocate internal memory to construct the pathname.
 *     Specifically, __getname() calls kmem_cache_alloc() with GFP_KERNEL to
 *     allocate a PATH_MAX-sized buffer from the names_cachep slab. Under severe
 *     memory pressure, this allocation may fail. This is rare in practice.
 *
 * error: EFAULT, Bad user address
 *   desc: The buf pointer is NULL, points to invalid memory, or points to memory
 *     that is not writable by the calling process. This is detected by
 *     copy_to_user() which safely handles invalid user addresses. Unlike glibc's
 *     getcwd wrapper, the kernel does not support NULL buffer for automatic
 *     allocation.
 *
 * error: ENAMETOOLONG, Path too long
 *   desc: The absolute pathname of the current working directory exceeds
 *     PATH_MAX (4096) bytes. This is extremely rare in practice as most
 *     filesystems enforce PATH_MAX during path creation. This could theoretically
 *     occur with deeply nested bind mounts or unusual filesystem configurations.
 *     The check is performed internally after constructing the path in an
 *     internal kernel buffer.
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is acquired to safely traverse the dentry hierarchy and
 *     mount tree without holding traditional locks. This protects against
 *     concurrent mount/unmount operations and directory renames. The lock is
 *     acquired at the start of the operation and released after path construction
 *     or may be re-acquired during seqlock retry loops. RCU allows multiple
 *     readers to proceed concurrently.
 *
 * lock: rename_lock
 *   type: KAPI_LOCK_SEQLOCK
 *   acquired: true
 *   released: true
 *   desc: Global seqlock protecting dentry renames (defined in fs/dcache.c).
 *     Used via read_seqbegin_or_lock() which first attempts a lockless read
 *     (optimistic path) and falls back to exclusive locking if contention is
 *     detected. This ensures the constructed pathname is consistent even if
 *     d_move() renames directories during traversal. The seqlock retry mechanism
 *     handles races by reconstructing the path if a rename occurred.
 *
 * lock: mount_lock
 *   type: KAPI_LOCK_SEQLOCK
 *   acquired: true
 *   released: true
 *   desc: Global seqlock protecting the mount tree (defined in fs/namespace.c).
 *     Used via read_seqbegin_or_lock() similar to rename_lock. This ensures
 *     consistent mount point traversal if mounts change during path construction.
 *     The syscall may retry path construction if mount_lock sequence indicates
 *     concurrent mount activity.
 *
 * lock: fs->seq
 *   type: KAPI_LOCK_SEQLOCK
 *   acquired: true
 *   released: true
 *   desc: Per-process seqlock in struct fs_struct protecting the root and pwd
 *     paths. Accessed via read_seqbegin()/read_seqretry() in
 *     get_fs_root_and_pwd_rcu(). This ensures atomic snapshot of the process's
 *     current working directory and root directory even if another thread calls
 *     chdir() or chroot() concurrently.
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: Kernel path buffer (names_cachep slab)
 *   desc: Allocates a PATH_MAX-sized buffer from names_cachep slab via
 *     __getname() for internal path construction. This memory is always freed
 *     via __putname() before the syscall returns, regardless of success or
 *     failure. The allocation uses GFP_KERNEL and may sleep.
 *   reversible: yes
 *
 * constraint: Process context required
 *   desc: Must be called from process context. Cannot be called from interrupt
 *     context or softirq because the syscall may sleep during memory allocation
 *     (__getname with GFP_KERNEL) and user memory access (copy_to_user may
 *     trigger page faults).
 *
 * constraint: Path length limit
 *   desc: The kernel limits pathname length to PATH_MAX (4096 bytes including
 *     the null terminator). This is enforced during path construction. Paths
 *     exceeding this limit cannot be returned even with an arbitrarily large
 *     user buffer.
 *   expr: path_length <= PATH_MAX
 *
 * examples: char buf[PATH_MAX]; long len = syscall(SYS_getcwd, buf, sizeof(buf));
 *   // len contains length including null, or negative error code
 *   // For most programs, use the glibc getcwd() wrapper instead
 *
 * notes: The kernel syscall behavior differs significantly from the POSIX C
 *   library function getcwd(3). The library function returns a pointer to the
 *   buffer on success and NULL on error (with errno set), while the syscall
 *   returns the length on success or negative error on failure.
 *
 *   The glibc wrapper provides additional functionality not present in the
 *   syscall: when buf is NULL, glibc allocates a buffer of sufficient size
 *   (or size bytes if size is non-zero) using malloc(). This is a GNU extension
 *   not part of POSIX.
 *
 *   Thread safety: This syscall is fully thread-safe. The seqlock-based
 *   synchronization ensures that concurrent chdir(), chroot(), rename(), and
 *   mount/unmount operations are handled correctly without corrupting the
 *   returned pathname.
 *
 *   Historical note: A race condition between getcwd() and d_move() was fixed
 *   in commit 61647823aa920 (2017). The race could cause getcwd() to return
 *   ENOENT during a concurrent directory rename, even though the directory
 *   was not actually deleted.
 *
 *   Performance: The syscall uses an optimistic lockless read path using RCU
 *   and seqlocks. In the common case with no concurrent modifications, no
 *   exclusive locks are taken. This makes getcwd() efficient even under high
 *   filesystem activity.
 *
 * since-version: 2.1.92
 */
SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
{
	int error;
	struct path pwd, root;
	char *page = __getname();

	if (!page)
		return -ENOMEM;

	rcu_read_lock();
	get_fs_root_and_pwd_rcu(current->fs, &root, &pwd);

	if (unlikely(d_unlinked(pwd.dentry))) {
		rcu_read_unlock();
		error = -ENOENT;
	} else {
		unsigned len;
		DECLARE_BUFFER(b, page, PATH_MAX);

		prepend_char(&b, 0);
		if (unlikely(prepend_path(&pwd, &root, &b) > 0))
			prepend(&b, "(unreachable)", 13);
		rcu_read_unlock();

		len = PATH_MAX - b.len;
		if (unlikely(len > PATH_MAX))
			error = -ENAMETOOLONG;
		else if (unlikely(len > size))
			error = -ERANGE;
		else if (copy_to_user(buf, b.buf, len))
			error = -EFAULT;
		else
			error = len;
	}
	__putname(page);
	return error;
}
