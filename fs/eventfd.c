// SPDX-License-Identifier: GPL-2.0-only
/*
 *  fs/eventfd.c
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#include <linux/file.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched/signal.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/anon_inodes.h>
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/kref.h>
#include <linux/eventfd.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/idr.h>
#include <linux/uio.h>

static DEFINE_IDA(eventfd_ida);

struct eventfd_ctx {
	struct kref kref;
	wait_queue_head_t wqh;
	/*
	 * Every time that a write(2) is performed on an eventfd, the
	 * value of the __u64 being written is added to "count" and a
	 * wakeup is performed on "wqh". If EFD_SEMAPHORE flag was not
	 * specified, a read(2) will return the "count" value to userspace,
	 * and will reset "count" to zero. The kernel side eventfd_signal()
	 * also, adds to the "count" counter and issue a wakeup.
	 */
	__u64 count;
	unsigned int flags;
	int id;
};

/**
 * eventfd_signal_mask - Increment the event counter
 * @ctx: [in] Pointer to the eventfd context.
 * @mask: [in] poll mask
 *
 * This function is supposed to be called by the kernel in paths that do not
 * allow sleeping. In this function we allow the counter to reach the ULLONG_MAX
 * value, and we signal this as overflow condition by returning a EPOLLERR
 * to poll(2).
 */
void eventfd_signal_mask(struct eventfd_ctx *ctx, __poll_t mask)
{
	unsigned long flags;

	/*
	 * Deadlock or stack overflow issues can happen if we recurse here
	 * through waitqueue wakeup handlers. If the caller users potentially
	 * nested waitqueues with custom wakeup handlers, then it should
	 * check eventfd_signal_allowed() before calling this function. If
	 * it returns false, the eventfd_signal() call should be deferred to a
	 * safe context.
	 */
	if (WARN_ON_ONCE(current->in_eventfd))
		return;

	spin_lock_irqsave(&ctx->wqh.lock, flags);
	current->in_eventfd = 1;
	if (ctx->count < ULLONG_MAX)
		ctx->count++;
	if (waitqueue_active(&ctx->wqh))
		wake_up_locked_poll(&ctx->wqh, EPOLLIN | mask);
	current->in_eventfd = 0;
	spin_unlock_irqrestore(&ctx->wqh.lock, flags);
}
EXPORT_SYMBOL_GPL(eventfd_signal_mask);

static void eventfd_free_ctx(struct eventfd_ctx *ctx)
{
	if (ctx->id >= 0)
		ida_free(&eventfd_ida, ctx->id);
	kfree(ctx);
}

static void eventfd_free(struct kref *kref)
{
	struct eventfd_ctx *ctx = container_of(kref, struct eventfd_ctx, kref);

	eventfd_free_ctx(ctx);
}

/**
 * eventfd_ctx_put - Releases a reference to the internal eventfd context.
 * @ctx: [in] Pointer to eventfd context.
 *
 * The eventfd context reference must have been previously acquired either
 * with eventfd_ctx_fdget() or eventfd_ctx_fileget().
 */
void eventfd_ctx_put(struct eventfd_ctx *ctx)
{
	kref_put(&ctx->kref, eventfd_free);
}
EXPORT_SYMBOL_GPL(eventfd_ctx_put);

static int eventfd_release(struct inode *inode, struct file *file)
{
	struct eventfd_ctx *ctx = file->private_data;

	wake_up_poll(&ctx->wqh, EPOLLHUP);
	eventfd_ctx_put(ctx);
	return 0;
}

static __poll_t eventfd_poll(struct file *file, poll_table *wait)
{
	struct eventfd_ctx *ctx = file->private_data;
	__poll_t events = 0;
	u64 count;

	poll_wait(file, &ctx->wqh, wait);

	/*
	 * All writes to ctx->count occur within ctx->wqh.lock.  This read
	 * can be done outside ctx->wqh.lock because we know that poll_wait
	 * takes that lock (through add_wait_queue) if our caller will sleep.
	 *
	 * The read _can_ therefore seep into add_wait_queue's critical
	 * section, but cannot move above it!  add_wait_queue's spin_lock acts
	 * as an acquire barrier and ensures that the read be ordered properly
	 * against the writes.  The following CAN happen and is safe:
	 *
	 *     poll                               write
	 *     -----------------                  ------------
	 *     lock ctx->wqh.lock (in poll_wait)
	 *     count = ctx->count
	 *     __add_wait_queue
	 *     unlock ctx->wqh.lock
	 *                                        lock ctx->qwh.lock
	 *                                        ctx->count += n
	 *                                        if (waitqueue_active)
	 *                                          wake_up_locked_poll
	 *                                        unlock ctx->qwh.lock
	 *     eventfd_poll returns 0
	 *
	 * but the following, which would miss a wakeup, cannot happen:
	 *
	 *     poll                               write
	 *     -----------------                  ------------
	 *     count = ctx->count (INVALID!)
	 *                                        lock ctx->qwh.lock
	 *                                        ctx->count += n
	 *                                        **waitqueue_active is false**
	 *                                        **no wake_up_locked_poll!**
	 *                                        unlock ctx->qwh.lock
	 *     lock ctx->wqh.lock (in poll_wait)
	 *     __add_wait_queue
	 *     unlock ctx->wqh.lock
	 *     eventfd_poll returns 0
	 */
	count = READ_ONCE(ctx->count);

	if (count > 0)
		events |= EPOLLIN;
	if (count == ULLONG_MAX)
		events |= EPOLLERR;
	if (ULLONG_MAX - 1 > count)
		events |= EPOLLOUT;

	return events;
}

void eventfd_ctx_do_read(struct eventfd_ctx *ctx, __u64 *cnt)
{
	lockdep_assert_held(&ctx->wqh.lock);

	*cnt = ((ctx->flags & EFD_SEMAPHORE) && ctx->count) ? 1 : ctx->count;
	ctx->count -= *cnt;
}
EXPORT_SYMBOL_GPL(eventfd_ctx_do_read);

/**
 * eventfd_ctx_remove_wait_queue - Read the current counter and removes wait queue.
 * @ctx: [in] Pointer to eventfd context.
 * @wait: [in] Wait queue to be removed.
 * @cnt: [out] Pointer to the 64-bit counter value.
 *
 * Returns %0 if successful, or the following error codes:
 *
 * -EAGAIN      : The operation would have blocked.
 *
 * This is used to atomically remove a wait queue entry from the eventfd wait
 * queue head, and read/reset the counter value.
 */
int eventfd_ctx_remove_wait_queue(struct eventfd_ctx *ctx, wait_queue_entry_t *wait,
				  __u64 *cnt)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->wqh.lock, flags);
	eventfd_ctx_do_read(ctx, cnt);
	__remove_wait_queue(&ctx->wqh, wait);
	if (*cnt != 0 && waitqueue_active(&ctx->wqh))
		wake_up_locked_poll(&ctx->wqh, EPOLLOUT);
	spin_unlock_irqrestore(&ctx->wqh.lock, flags);

	return *cnt != 0 ? 0 : -EAGAIN;
}
EXPORT_SYMBOL_GPL(eventfd_ctx_remove_wait_queue);

static ssize_t eventfd_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct eventfd_ctx *ctx = file->private_data;
	__u64 ucnt = 0;

	if (iov_iter_count(to) < sizeof(ucnt))
		return -EINVAL;
	spin_lock_irq(&ctx->wqh.lock);
	if (!ctx->count) {
		if ((file->f_flags & O_NONBLOCK) ||
		    (iocb->ki_flags & IOCB_NOWAIT)) {
			spin_unlock_irq(&ctx->wqh.lock);
			return -EAGAIN;
		}

		if (wait_event_interruptible_locked_irq(ctx->wqh, ctx->count)) {
			spin_unlock_irq(&ctx->wqh.lock);
			return -ERESTARTSYS;
		}
	}
	eventfd_ctx_do_read(ctx, &ucnt);
	current->in_eventfd = 1;
	if (waitqueue_active(&ctx->wqh))
		wake_up_locked_poll(&ctx->wqh, EPOLLOUT);
	current->in_eventfd = 0;
	spin_unlock_irq(&ctx->wqh.lock);
	if (unlikely(copy_to_iter(&ucnt, sizeof(ucnt), to) != sizeof(ucnt)))
		return -EFAULT;

	return sizeof(ucnt);
}

static ssize_t eventfd_write(struct file *file, const char __user *buf, size_t count,
			     loff_t *ppos)
{
	struct eventfd_ctx *ctx = file->private_data;
	ssize_t res;
	__u64 ucnt;

	if (count != sizeof(ucnt))
		return -EINVAL;
	if (copy_from_user(&ucnt, buf, sizeof(ucnt)))
		return -EFAULT;
	if (ucnt == ULLONG_MAX)
		return -EINVAL;
	spin_lock_irq(&ctx->wqh.lock);
	res = -EAGAIN;
	if (ULLONG_MAX - ctx->count > ucnt)
		res = sizeof(ucnt);
	else if (!(file->f_flags & O_NONBLOCK)) {
		res = wait_event_interruptible_locked_irq(ctx->wqh,
				ULLONG_MAX - ctx->count > ucnt);
		if (!res)
			res = sizeof(ucnt);
	}
	if (likely(res > 0)) {
		ctx->count += ucnt;
		current->in_eventfd = 1;
		if (waitqueue_active(&ctx->wqh))
			wake_up_locked_poll(&ctx->wqh, EPOLLIN);
		current->in_eventfd = 0;
	}
	spin_unlock_irq(&ctx->wqh.lock);

	return res;
}

#ifdef CONFIG_PROC_FS
static void eventfd_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct eventfd_ctx *ctx = f->private_data;
	__u64 cnt;

	spin_lock_irq(&ctx->wqh.lock);
	cnt = ctx->count;
	spin_unlock_irq(&ctx->wqh.lock);

	seq_printf(m,
		   "eventfd-count: %16llx\n"
		   "eventfd-id: %d\n"
		   "eventfd-semaphore: %d\n",
		   cnt,
		   ctx->id,
		   !!(ctx->flags & EFD_SEMAPHORE));
}
#endif

static const struct file_operations eventfd_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= eventfd_show_fdinfo,
#endif
	.release	= eventfd_release,
	.poll		= eventfd_poll,
	.read_iter	= eventfd_read,
	.write		= eventfd_write,
	.llseek		= noop_llseek,
};

/**
 * eventfd_fget - Acquire a reference of an eventfd file descriptor.
 * @fd: [in] Eventfd file descriptor.
 *
 * Returns a pointer to the eventfd file structure in case of success, or the
 * following error pointer:
 *
 * -EBADF    : Invalid @fd file descriptor.
 * -EINVAL   : The @fd file descriptor is not an eventfd file.
 */
struct file *eventfd_fget(int fd)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	if (file->f_op != &eventfd_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}

	return file;
}
EXPORT_SYMBOL_GPL(eventfd_fget);

/**
 * eventfd_ctx_fdget - Acquires a reference to the internal eventfd context.
 * @fd: [in] Eventfd file descriptor.
 *
 * Returns a pointer to the internal eventfd context, otherwise the error
 * pointers returned by the following functions:
 *
 * eventfd_fget
 */
struct eventfd_ctx *eventfd_ctx_fdget(int fd)
{
	CLASS(fd, f)(fd);
	if (fd_empty(f))
		return ERR_PTR(-EBADF);
	return eventfd_ctx_fileget(fd_file(f));
}
EXPORT_SYMBOL_GPL(eventfd_ctx_fdget);

/**
 * eventfd_ctx_fileget - Acquires a reference to the internal eventfd context.
 * @file: [in] Eventfd file pointer.
 *
 * Returns a pointer to the internal eventfd context, otherwise the error
 * pointer:
 *
 * -EINVAL   : The @fd file descriptor is not an eventfd file.
 */
struct eventfd_ctx *eventfd_ctx_fileget(struct file *file)
{
	struct eventfd_ctx *ctx;

	if (file->f_op != &eventfd_fops)
		return ERR_PTR(-EINVAL);

	ctx = file->private_data;
	kref_get(&ctx->kref);
	return ctx;
}
EXPORT_SYMBOL_GPL(eventfd_ctx_fileget);

static int do_eventfd(unsigned int count, int flags)
{
	struct eventfd_ctx *ctx __free(kfree) = NULL;

	/* Check the EFD_* constants for consistency.  */
	BUILD_BUG_ON(EFD_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON(EFD_NONBLOCK != O_NONBLOCK);
	BUILD_BUG_ON(EFD_SEMAPHORE != (1 << 0));

	if (flags & ~EFD_FLAGS_SET)
		return -EINVAL;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	kref_init(&ctx->kref);
	init_waitqueue_head(&ctx->wqh);
	ctx->count = count;
	ctx->flags = flags;

	flags &= EFD_SHARED_FCNTL_FLAGS;
	flags |= O_RDWR;

	FD_PREPARE(fdf, flags,
		   anon_inode_getfile_fmode("[eventfd]", &eventfd_fops, ctx,
					    flags, FMODE_NOWAIT));
	if (fdf.err)
		return fdf.err;

	ctx->id = ida_alloc(&eventfd_ida, GFP_KERNEL);
	retain_and_null_ptr(ctx);
	return fd_publish(fdf);
}

/**
 * sys_eventfd2 - Create an event notification file descriptor
 * @count: Initial value for the eventfd counter
 * @flags: Bitmask of flags modifying the eventfd behavior
 *
 * long-desc: Creates an "eventfd object" that provides a kernel-supported
 *   mechanism for event wait/notify between userspace applications or between
 *   the kernel and userspace. The syscall returns a new file descriptor that
 *   refers to the eventfd object, which contains a 64-bit unsigned integer
 *   (uint64_t) counter maintained by the kernel.
 *
 *   The counter is initialized with the value specified in @count. The eventfd
 *   file descriptor supports read(2), write(2), poll(2)/select(2)/epoll(7),
 *   and close(2) operations:
 *
 *   - read(2): If the counter is nonzero, read returns 8 bytes containing the
 *     counter value (or 1 if EFD_SEMAPHORE is set), and resets (or decrements)
 *     the counter. If zero, blocks until counter becomes nonzero (or returns
 *     EAGAIN if O_NONBLOCK is set).
 *
 *   - write(2): Adds an 8-byte integer value to the counter. If the addition
 *     would cause overflow (counter would exceed ULLONG_MAX-1), blocks (or
 *     returns EAGAIN if O_NONBLOCK). Writing the value 0xffffffffffffffff
 *     returns EINVAL.
 *
 *   - poll/select/epoll: The file descriptor is readable (POLLIN) when the
 *     counter is greater than zero. It is writable (POLLOUT) when writing at
 *     least the value 1 would not block. POLLERR is returned if the counter
 *     value overflows (reaches ULLONG_MAX).
 *
 *   eventfd provides a more lightweight alternative to pipes for event
 *   notification, requiring only one file descriptor (versus two for a pipe)
 *   and having lower kernel overhead. It is commonly used for signal-safe IPC,
 *   integration with event loops, and kernel-to-userspace notification (e.g.,
 *   with KVM, VFIO, io_uring, and AIO).
 *
 *   The file descriptor is automatically inherited across fork(2). The child
 *   gets a copy referring to the same eventfd object, allowing parent-child
 *   communication. The file descriptor is preserved across execve(2) unless
 *   EFD_CLOEXEC is specified.
 *
 *   The eventfd2 syscall was introduced in Linux 2.6.27 to add flags support.
 *   The older eventfd(2) syscall is equivalent to eventfd2(count, 0).
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: count
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, UINT_MAX
 *   constraint: Initial counter value. Any unsigned 32-bit integer is valid.
 *     The counter itself is stored as a 64-bit value internally, so subsequent
 *     writes can increase it beyond the initial value up to 0xfffffffffffffffe.
 *
 * param: flags
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE
 *   constraint: Bitmask of zero or more of: EFD_CLOEXEC (set close-on-exec flag
 *     on the new fd), EFD_NONBLOCK (set O_NONBLOCK on the file, making read/write
 *     non-blocking), EFD_SEMAPHORE (provide semaphore-like semantics where read
 *     returns 1 and decrements counter by 1, rather than returning full counter
 *     and resetting to zero). Any bits outside this mask cause EINVAL.
 *
 * return:
 *   type: KAPI_TYPE_FD
 *   check-type: KAPI_RETURN_FD
 *   success: >= 0
 *   desc: On success, returns a new file descriptor referring to the eventfd
 *     object. The file descriptor will be the lowest-numbered available fd.
 *     The returned fd should be closed with close(2) when no longer needed.
 *
 * error: EINVAL, Invalid flags
 *   desc: The @flags argument contains bits other than EFD_CLOEXEC, EFD_NONBLOCK,
 *     and EFD_SEMAPHORE. The kernel validates flags against EFD_FLAGS_SET mask
 *     (defined as EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE) before any resource
 *     allocation. This error is returned early, before any memory is allocated.
 *
 * error: EMFILE, Per-process fd limit exceeded
 *   desc: The per-process limit on the number of open file descriptors has been
 *     reached. This limit is controlled by RLIMIT_NOFILE (typically 1024 soft,
 *     higher hard limit) and can be viewed/modified with getrlimit/setrlimit or
 *     ulimit -n. The kernel checks this in get_unused_fd_flags() -> alloc_fd().
 *
 * error: ENFILE, System-wide fd limit exceeded
 *   desc: The system-wide limit on the total number of open files has been
 *     reached. This limit is controlled by /proc/sys/fs/file-max. Processes
 *     with CAP_SYS_ADMIN capability can exceed this limit. This error is
 *     returned from alloc_empty_file() during struct file allocation.
 *
 * error: ENOMEM, Out of memory
 *   desc: Insufficient kernel memory was available to allocate the eventfd_ctx
 *     structure (from kmalloc), the struct file (from kmem_cache_alloc), or
 *     the dentry for the anonymous inode (from d_alloc_pseudo). The eventfd_ctx
 *     is approximately 64 bytes; total memory for an eventfd is several hundred
 *     bytes including all associated kernel structures.
 *
 * error: ENODEV, Anonymous inode mount failed
 *   desc: The internal anonymous inode filesystem could not be accessed. This
 *     is an extremely rare error that can only occur if the anon_inode_inode
 *     initialization failed during kernel boot (which would cause a panic) or
 *     if there is severe kernel memory corruption. Under normal operation,
 *     this error should never be returned to userspace.
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: eventfd_ctx structure, struct file, dentry
 *   desc: Allocates an eventfd_ctx structure (~64 bytes) containing the counter,
 *     flags, wait queue head, and reference count. Also allocates a struct file
 *     and associated dentry for the anonymous inode. All memory is freed when
 *     the last reference to the file descriptor is released (via close or
 *     process exit).
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: File descriptor
 *   desc: Allocates a new file descriptor in the calling process's file
 *     descriptor table. The fd number is chosen as the lowest available value.
 *     The file descriptor remains valid until explicitly closed or the process
 *     exits.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: eventfd identifier
 *   desc: Allocates a unique ID from the eventfd_ida IDA allocator. This ID is
 *     visible in /proc/[pid]/fdinfo/[fd] as "eventfd-id:" and can be used to
 *     correlate eventfd instances across different processes or for debugging.
 *     The ID is freed when the eventfd is destroyed.
 *   reversible: yes
 *
 * capability: CAP_SYS_ADMIN
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Exceeding the system-wide file-max limit
 *   without: Returns ENFILE if system-wide file limit is reached
 *   condition: Checked in alloc_empty_file() when nr_files >= files_stat.max_files
 *
 * constraint: File Descriptor Limits
 *   desc: The calling process must not have exhausted its per-process file
 *     descriptor limit (RLIMIT_NOFILE). The system must not have exhausted its
 *     system-wide file limit (/proc/sys/fs/file-max) unless caller has
 *     CAP_SYS_ADMIN.
 *
 * constraint: Memory Availability
 *   desc: Sufficient kernel memory must be available for allocation of the
 *     eventfd context and associated structures. Allocation uses GFP_KERNEL
 *     which allows the kernel to reclaim memory and sleep if necessary.
 *
 * examples: fd = eventfd2(0, 0);  // Basic eventfd with counter=0
 *   fd = eventfd2(1, EFD_CLOEXEC);  // Initial count=1, close-on-exec
 *   fd = eventfd2(0, EFD_NONBLOCK | EFD_SEMAPHORE);  // Non-blocking semaphore
 *   fd = eventfd2(100, EFD_CLOEXEC | EFD_NONBLOCK);  // All common flags
 *
 * notes: The eventfd2 syscall was introduced to allow specifying flags. The
 *   original eventfd() syscall (Linux 2.6.22) is equivalent to eventfd2(count, 0).
 *   glibc's eventfd() wrapper uses eventfd2() when available (since glibc 2.9).
 *
 *   The counter maximum value is 0xfffffffffffffffe (ULLONG_MAX - 1). Attempting
 *   to write the value 0xffffffffffffffff returns EINVAL. This design allows
 *   overflow detection via POLLERR when the counter reaches ULLONG_MAX.
 *
 *   For semaphore mode (EFD_SEMAPHORE), the counter effectively acts as a
 *   counting semaphore where each read decrements by 1 and returns 1. This
 *   allows multiple waiters to be woken one at a time. Without EFD_SEMAPHORE,
 *   a single read consumes the entire counter value.
 *
 *   When using eventfd with fork(), both parent and child share the same
 *   underlying eventfd object. Writes by either process are visible to both.
 *   This is useful for parent-child synchronization. For thread synchronization
 *   within a single process, the same fd can be shared directly.
 *
 *   The file descriptor supports the following fdinfo fields visible in
 *   /proc/[pid]/fdinfo/[fd]: eventfd-count (current counter in hex),
 *   eventfd-id (unique id), eventfd-semaphore (1 if EFD_SEMAPHORE set).
 *
 *   Historical note: The underflow bug (commit 758b492047816) was fixed in
 *   kernel 6.5 where reading from an EFD_SEMAPHORE eventfd with count=0
 *   would cause underflow to ULLONG_MAX. The fix ensures the semaphore
 *   decrement only occurs when count > 0.
 *
 * since-version: 2.6.27
 */
SYSCALL_DEFINE2(eventfd2, unsigned int, count, int, flags)
{
	return do_eventfd(count, flags);
}

SYSCALL_DEFINE1(eventfd, unsigned int, count)
{
	return do_eventfd(count, 0);
}

