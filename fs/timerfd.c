// SPDX-License-Identifier: GPL-2.0
/*
 *  fs/timerfd.c
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 *
 *  Thanks to Thomas Gleixner for code reviews and useful comments.
 *
 */

#include <linux/alarmtimer.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/hrtimer.h>
#include <linux/anon_inodes.h>
#include <linux/timerfd.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/rcupdate.h>
#include <linux/time_namespace.h>

struct timerfd_ctx {
	union {
		struct hrtimer tmr;
		struct alarm alarm;
	} t;
	ktime_t tintv;
	ktime_t moffs;
	wait_queue_head_t wqh;
	u64 ticks;
	int clockid;
	short unsigned expired;
	short unsigned settime_flags;	/* to show in fdinfo */
	struct rcu_head rcu;
	struct list_head clist;
	spinlock_t cancel_lock;
	bool might_cancel;
};

static LIST_HEAD(cancel_list);
static DEFINE_SPINLOCK(cancel_lock);

static inline bool isalarm(struct timerfd_ctx *ctx)
{
	return ctx->clockid == CLOCK_REALTIME_ALARM ||
		ctx->clockid == CLOCK_BOOTTIME_ALARM;
}

/*
 * This gets called when the timer event triggers. We set the "expired"
 * flag, but we do not re-arm the timer (in case it's necessary,
 * tintv != 0) until the timer is accessed.
 */
static void timerfd_triggered(struct timerfd_ctx *ctx)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->wqh.lock, flags);
	ctx->expired = 1;
	ctx->ticks++;
	wake_up_locked_poll(&ctx->wqh, EPOLLIN);
	spin_unlock_irqrestore(&ctx->wqh.lock, flags);
}

static enum hrtimer_restart timerfd_tmrproc(struct hrtimer *htmr)
{
	struct timerfd_ctx *ctx = container_of(htmr, struct timerfd_ctx,
					       t.tmr);
	timerfd_triggered(ctx);
	return HRTIMER_NORESTART;
}

static void timerfd_alarmproc(struct alarm *alarm, ktime_t now)
{
	struct timerfd_ctx *ctx = container_of(alarm, struct timerfd_ctx,
					       t.alarm);
	timerfd_triggered(ctx);
}

/*
 * Called when the clock was set to cancel the timers in the cancel
 * list. This will wake up processes waiting on these timers. The
 * wake-up requires ctx->ticks to be non zero, therefore we increment
 * it before calling wake_up_locked().
 */
void timerfd_clock_was_set(void)
{
	ktime_t moffs = ktime_mono_to_real(0);
	struct timerfd_ctx *ctx;
	unsigned long flags;

	rcu_read_lock();
	list_for_each_entry_rcu(ctx, &cancel_list, clist) {
		if (!ctx->might_cancel)
			continue;
		spin_lock_irqsave(&ctx->wqh.lock, flags);
		if (ctx->moffs != moffs) {
			ctx->moffs = KTIME_MAX;
			ctx->ticks++;
			wake_up_locked_poll(&ctx->wqh, EPOLLIN);
		}
		spin_unlock_irqrestore(&ctx->wqh.lock, flags);
	}
	rcu_read_unlock();
}

static void timerfd_resume_work(struct work_struct *work)
{
	timerfd_clock_was_set();
}

static DECLARE_WORK(timerfd_work, timerfd_resume_work);

/*
 * Invoked from timekeeping_resume(). Defer the actual update to work so
 * timerfd_clock_was_set() runs in task context.
 */
void timerfd_resume(void)
{
	schedule_work(&timerfd_work);
}

static void __timerfd_remove_cancel(struct timerfd_ctx *ctx)
{
	if (ctx->might_cancel) {
		ctx->might_cancel = false;
		spin_lock(&cancel_lock);
		list_del_rcu(&ctx->clist);
		spin_unlock(&cancel_lock);
	}
}

static void timerfd_remove_cancel(struct timerfd_ctx *ctx)
{
	spin_lock(&ctx->cancel_lock);
	__timerfd_remove_cancel(ctx);
	spin_unlock(&ctx->cancel_lock);
}

static bool timerfd_canceled(struct timerfd_ctx *ctx)
{
	if (!ctx->might_cancel || ctx->moffs != KTIME_MAX)
		return false;
	ctx->moffs = ktime_mono_to_real(0);
	return true;
}

static void timerfd_setup_cancel(struct timerfd_ctx *ctx, int flags)
{
	spin_lock(&ctx->cancel_lock);
	if ((ctx->clockid == CLOCK_REALTIME ||
	     ctx->clockid == CLOCK_REALTIME_ALARM) &&
	    (flags & TFD_TIMER_ABSTIME) && (flags & TFD_TIMER_CANCEL_ON_SET)) {
		if (!ctx->might_cancel) {
			ctx->might_cancel = true;
			spin_lock(&cancel_lock);
			list_add_rcu(&ctx->clist, &cancel_list);
			spin_unlock(&cancel_lock);
		}
	} else {
		__timerfd_remove_cancel(ctx);
	}
	spin_unlock(&ctx->cancel_lock);
}

static ktime_t timerfd_get_remaining(struct timerfd_ctx *ctx)
{
	ktime_t remaining;

	if (isalarm(ctx))
		remaining = alarm_expires_remaining(&ctx->t.alarm);
	else
		remaining = hrtimer_expires_remaining_adjusted(&ctx->t.tmr);

	return remaining < 0 ? 0: remaining;
}

static int timerfd_setup(struct timerfd_ctx *ctx, int flags,
			 const struct itimerspec64 *ktmr)
{
	enum hrtimer_mode htmode;
	ktime_t texp;
	int clockid = ctx->clockid;

	htmode = (flags & TFD_TIMER_ABSTIME) ?
		HRTIMER_MODE_ABS: HRTIMER_MODE_REL;

	texp = timespec64_to_ktime(ktmr->it_value);
	ctx->expired = 0;
	ctx->ticks = 0;
	ctx->tintv = timespec64_to_ktime(ktmr->it_interval);

	if (isalarm(ctx)) {
		alarm_init(&ctx->t.alarm,
			   ctx->clockid == CLOCK_REALTIME_ALARM ?
			   ALARM_REALTIME : ALARM_BOOTTIME,
			   timerfd_alarmproc);
	} else {
		hrtimer_setup(&ctx->t.tmr, timerfd_tmrproc, clockid, htmode);
		hrtimer_set_expires(&ctx->t.tmr, texp);
	}

	if (texp != 0) {
		if (flags & TFD_TIMER_ABSTIME)
			texp = timens_ktime_to_host(clockid, texp);
		if (isalarm(ctx)) {
			if (flags & TFD_TIMER_ABSTIME)
				alarm_start(&ctx->t.alarm, texp);
			else
				alarm_start_relative(&ctx->t.alarm, texp);
		} else {
			hrtimer_start(&ctx->t.tmr, texp, htmode);
		}

		if (timerfd_canceled(ctx))
			return -ECANCELED;
	}

	ctx->settime_flags = flags & TFD_SETTIME_FLAGS;
	return 0;
}

static int timerfd_release(struct inode *inode, struct file *file)
{
	struct timerfd_ctx *ctx = file->private_data;

	timerfd_remove_cancel(ctx);

	if (isalarm(ctx))
		alarm_cancel(&ctx->t.alarm);
	else
		hrtimer_cancel(&ctx->t.tmr);
	kfree_rcu(ctx, rcu);
	return 0;
}

static __poll_t timerfd_poll(struct file *file, poll_table *wait)
{
	struct timerfd_ctx *ctx = file->private_data;
	__poll_t events = 0;
	unsigned long flags;

	poll_wait(file, &ctx->wqh, wait);

	spin_lock_irqsave(&ctx->wqh.lock, flags);
	if (ctx->ticks)
		events |= EPOLLIN;
	spin_unlock_irqrestore(&ctx->wqh.lock, flags);

	return events;
}

static ssize_t timerfd_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct timerfd_ctx *ctx = file->private_data;
	ssize_t res;
	u64 ticks = 0;

	if (iov_iter_count(to) < sizeof(ticks))
		return -EINVAL;

	spin_lock_irq(&ctx->wqh.lock);
	if (file->f_flags & O_NONBLOCK || iocb->ki_flags & IOCB_NOWAIT)
		res = -EAGAIN;
	else
		res = wait_event_interruptible_locked_irq(ctx->wqh, ctx->ticks);

	/*
	 * If clock has changed, we do not care about the
	 * ticks and we do not rearm the timer. Userspace must
	 * reevaluate anyway.
	 */
	if (timerfd_canceled(ctx)) {
		ctx->ticks = 0;
		ctx->expired = 0;
		res = -ECANCELED;
	}

	if (ctx->ticks) {
		ticks = ctx->ticks;

		if (ctx->expired && ctx->tintv) {
			/*
			 * If tintv != 0, this is a periodic timer that
			 * needs to be re-armed. We avoid doing it in the timer
			 * callback to avoid DoS attacks specifying a very
			 * short timer period.
			 */
			if (isalarm(ctx)) {
				ticks += alarm_forward_now(
					&ctx->t.alarm, ctx->tintv) - 1;
				alarm_restart(&ctx->t.alarm);
			} else {
				ticks += hrtimer_forward_now(&ctx->t.tmr,
							     ctx->tintv) - 1;
				hrtimer_restart(&ctx->t.tmr);
			}
		}
		ctx->expired = 0;
		ctx->ticks = 0;
	}
	spin_unlock_irq(&ctx->wqh.lock);
	if (ticks) {
		res = copy_to_iter(&ticks, sizeof(ticks), to);
		if (!res)
			res = -EFAULT;
	}
	return res;
}

#ifdef CONFIG_PROC_FS
static void timerfd_show(struct seq_file *m, struct file *file)
{
	struct timerfd_ctx *ctx = file->private_data;
	struct timespec64 value, interval;

	spin_lock_irq(&ctx->wqh.lock);
	value = ktime_to_timespec64(timerfd_get_remaining(ctx));
	interval = ktime_to_timespec64(ctx->tintv);
	spin_unlock_irq(&ctx->wqh.lock);

	seq_printf(m,
		   "clockid: %d\n"
		   "ticks: %llu\n"
		   "settime flags: 0%o\n"
		   "it_value: (%llu, %llu)\n"
		   "it_interval: (%llu, %llu)\n",
		   ctx->clockid,
		   (unsigned long long)ctx->ticks,
		   ctx->settime_flags,
		   (unsigned long long)value.tv_sec,
		   (unsigned long long)value.tv_nsec,
		   (unsigned long long)interval.tv_sec,
		   (unsigned long long)interval.tv_nsec);
}
#else
#define timerfd_show NULL
#endif

#ifdef CONFIG_CHECKPOINT_RESTORE
static long timerfd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct timerfd_ctx *ctx = file->private_data;
	int ret = 0;

	switch (cmd) {
	case TFD_IOC_SET_TICKS: {
		u64 ticks;

		if (copy_from_user(&ticks, (u64 __user *)arg, sizeof(ticks)))
			return -EFAULT;
		if (!ticks)
			return -EINVAL;

		spin_lock_irq(&ctx->wqh.lock);
		if (!timerfd_canceled(ctx)) {
			ctx->ticks = ticks;
			wake_up_locked_poll(&ctx->wqh, EPOLLIN);
		} else
			ret = -ECANCELED;
		spin_unlock_irq(&ctx->wqh.lock);
		break;
	}
	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}
#else
#define timerfd_ioctl NULL
#endif

static const struct file_operations timerfd_fops = {
	.release	= timerfd_release,
	.poll		= timerfd_poll,
	.read_iter	= timerfd_read_iter,
	.llseek		= noop_llseek,
	.show_fdinfo	= timerfd_show,
	.unlocked_ioctl	= timerfd_ioctl,
};

/**
 * sys_timerfd_create - Create a timer file descriptor for timer event delivery
 * @clockid: Clock source for the timer (CLOCK_MONOTONIC, CLOCK_REALTIME, etc.)
 * @flags: Flags modifying file descriptor behavior (TFD_CLOEXEC, TFD_NONBLOCK)
 *
 * long-desc: Creates a new timer object accessible via a file descriptor,
 *   enabling timer expiration notifications through standard file descriptor
 *   polling mechanisms (poll(2), select(2), epoll(7)) rather than signals.
 *   This provides a more convenient interface for event-driven applications
 *   compared to POSIX interval timers created via timer_create(2).
 *
 *   The returned file descriptor supports the following operations:
 *   - read(2): Blocks until timer expires, returns an 8-byte unsigned integer
 *     containing the number of expirations since the last read. For periodic
 *     timers, this count accumulates while the application is not reading.
 *     Returns EAGAIN in non-blocking mode if no expiration occurred.
 *   - poll(2)/select(2)/epoll(7): Reports EPOLLIN when timer has expired.
 *   - close(2): Releases the timer and associated resources.
 *   - timerfd_settime(2): Arms or disarms the timer with an expiration value.
 *   - timerfd_gettime(2): Queries the current timer setting.
 *
 *   The clockid parameter selects which system clock to use:
 *   - CLOCK_REALTIME: System-wide wall-clock time. This clock is affected
 *     by discontinuous jumps (e.g., NTP adjustments, manual changes).
 *     Suitable when absolute wall-clock times matter.
 *   - CLOCK_MONOTONIC: Monotonically increasing clock from an unspecified
 *     starting point. Not affected by system time changes. Does not include
 *     time spent in suspend. Recommended for measuring elapsed time.
 *   - CLOCK_BOOTTIME: Like CLOCK_MONOTONIC but includes time spent in
 *     system suspend. Useful for timers that should account for sleep time.
 *     Available since Linux 3.15.
 *   - CLOCK_REALTIME_ALARM: Like CLOCK_REALTIME but can wake the system
 *     from suspend when the timer expires. Requires CAP_WAKE_ALARM.
 *     Available since Linux 3.11.
 *   - CLOCK_BOOTTIME_ALARM: Like CLOCK_BOOTTIME but can wake the system
 *     from suspend when the timer expires. Requires CAP_WAKE_ALARM.
 *     Available since Linux 3.11.
 *
 *   The flags parameter is a bitwise OR of optional flags:
 *   - TFD_CLOEXEC: Set the close-on-exec (FD_CLOEXEC) flag on the new file
 *     descriptor. This prevents the file descriptor from being inherited
 *     by child processes after exec(). Recommended for most applications.
 *   - TFD_NONBLOCK: Set the O_NONBLOCK flag on the new file descriptor.
 *     This causes read() to return EAGAIN instead of blocking when no
 *     timer expiration has occurred.
 *
 *   Timer files are preserved across fork() - child processes inherit
 *   references to the same timer object. The timer state (armed/disarmed,
 *   expiration count) is shared. The file descriptor persists across exec()
 *   unless TFD_CLOEXEC is set.
 *
 *   When a CLOCK_REALTIME or CLOCK_REALTIME_ALARM timer is set with absolute
 *   time (TFD_TIMER_ABSTIME) and TFD_TIMER_CANCEL_ON_SET is used in
 *   timerfd_settime(), the timer will be canceled (returning ECANCELED from
 *   read()) if the system clock is discontinuously changed. This allows
 *   applications to detect clock changes and recompute their timeouts.
 *
 *   For alarm timers (CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM), the
 *   system uses the alarm timer infrastructure that can schedule wakeups
 *   via the RTC or other platform wake sources. These timers are useful
 *   for implementing scheduled wakeup functionality but require elevated
 *   privileges (CAP_WAKE_ALARM) to prevent unprivileged users from
 *   preventing system suspend.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: clockid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_ENUM
 *   constraint: Must be one of CLOCK_MONOTONIC (1), CLOCK_REALTIME (0),
 *     CLOCK_BOOTTIME (7), CLOCK_REALTIME_ALARM (8), or CLOCK_BOOTTIME_ALARM (9).
 *     Other clock values such as CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
 *     CLOCK_MONOTONIC_COARSE, CLOCK_PROCESS_CPUTIME_ID, or CLOCK_THREAD_CPUTIME_ID
 *     are not supported and return EINVAL. The alarm clocks additionally require
 *     CAP_WAKE_ALARM capability.
 *
 * param: flags
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: TFD_CLOEXEC | TFD_NONBLOCK
 *   constraint: Must be a bitwise OR of zero or more valid flags. Setting any
 *     bits other than TFD_CLOEXEC or TFD_NONBLOCK causes EINVAL. The value 0
 *     is valid and results in a file descriptor with neither close-on-exec
 *     nor non-blocking mode set.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_FD
 *   success: >= 0
 *   desc: On success, returns a new file descriptor referring to the timer
 *     object. This is the lowest-numbered file descriptor not currently open
 *     for the calling process. The returned fd can be used with read(),
 *     poll(), select(), epoll(), timerfd_settime(), timerfd_gettime(), and
 *     close(). The timer is initially disarmed (will not expire until armed
 *     via timerfd_settime()).
 *
 * error: EINVAL, Invalid clock ID or flags
 *   desc: The clockid is not one of the supported clock types (CLOCK_MONOTONIC,
 *     CLOCK_REALTIME, CLOCK_BOOTTIME, CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM),
 *     or the flags contain bits other than TFD_CLOEXEC and TFD_NONBLOCK. Note
 *     that valid POSIX clocks like CLOCK_MONOTONIC_RAW or CLOCK_PROCESS_CPUTIME_ID
 *     are intentionally not supported for timerfd.
 *
 * error: EPERM, Operation not permitted for alarm clocks
 *   desc: The clockid was CLOCK_REALTIME_ALARM or CLOCK_BOOTTIME_ALARM and
 *     the calling process does not have the CAP_WAKE_ALARM capability. Alarm
 *     clocks can wake the system from suspend, so they require elevated
 *     privileges to prevent unprivileged users from interfering with power
 *     management. This check was added in Linux 3.11 to match timer_create()
 *     behavior for POSIX alarm timers.
 *
 * error: ENOMEM, Kernel memory allocation failed
 *   desc: Insufficient kernel memory to allocate the timerfd_ctx structure
 *     (approximately 200 bytes) or supporting data structures such as the
 *     dentry for the anonymous inode. This can occur under severe memory
 *     pressure or if the kernel has exhausted its memory pools.
 *
 * error: EMFILE, Per-process file descriptor limit reached
 *   desc: The calling process has already reached its maximum number of open
 *     file descriptors as defined by RLIMIT_NOFILE. This limit can be queried
 *     and modified via getrlimit(2)/setrlimit(2) or prlimit(2). The default
 *     soft limit is typically 1024. Applications can increase this limit up
 *     to the hard limit or request higher limits via PAM configuration.
 *
 * error: ENFILE, System-wide file table full
 *   desc: The system-wide limit on the total number of open files has been
 *     reached. This limit is set by /proc/sys/fs/file-max. Even privileged
 *     processes (CAP_SYS_ADMIN) cannot exceed this limit. This error is rare
 *     on modern systems but can occur under extreme file descriptor usage.
 *
 * lock: files->file_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The process's file descriptor table spinlock is acquired briefly
 *     during file descriptor allocation in get_unused_fd_flags(). This lock
 *     protects the fd table from concurrent modifications by other threads
 *     in the same process. The lock is held only during the fd allocation
 *     phase, not during the entire syscall.
 *
 * lock: ctx->wqh.lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: false
 *   released: false
 *   desc: The wait queue head spinlock is initialized during timerfd_create()
 *     via init_waitqueue_head() but is not explicitly acquired during creation.
 *     This lock protects the wait queue and timer state (ticks, expired flags)
 *     during subsequent read() and timer callback operations.
 *
 * lock: ctx->cancel_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: false
 *   released: false
 *   desc: The cancel lock is initialized during timerfd_create() via
 *     spin_lock_init() but is not acquired during creation. This lock
 *     protects the might_cancel state and the cancel_list linkage when
 *     timers are set with TFD_TIMER_CANCEL_ON_SET.
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DISCARD
 *   condition: During memory allocation
 *   desc: The syscall uses GFP_KERNEL for memory allocation which can sleep
 *     but uses TASK_UNINTERRUPTIBLE state. Signals delivered during memory
 *     allocation remain pending and are handled after the syscall returns.
 *     The syscall itself does not return EINTR.
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: File descriptor
 *   desc: Creates a new file descriptor in the calling process's file
 *     descriptor table. The fd references an anonymous inode with the
 *     timerfd_fops operations. The file descriptor remains valid until
 *     explicitly closed via close(2) or until the process terminates.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: timerfd_ctx structure
 *   desc: Allocates a timerfd_ctx structure (approximately 200 bytes) using
 *     kzalloc() with GFP_KERNEL. This structure contains the hrtimer or alarm
 *     timer, wait queue head, tick counter, clock ID, and synchronization
 *     primitives. The memory is freed via kfree_rcu() when the file descriptor
 *     is closed.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: hrtimer or alarm timer initialization
 *   desc: For regular clocks (CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_BOOTTIME),
 *     initializes an hrtimer via hrtimer_setup(). For alarm clocks
 *     (CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM), initializes an alarm timer
 *     via alarm_init(). The timer is created in a disarmed state and will not
 *     fire until armed via timerfd_settime().
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Anonymous inode reference count
 *   desc: Increments the reference count on the anonymous inode filesystem's
 *     shared inode via ihold(). All timerfd file descriptors share a single
 *     anonymous inode, reducing memory overhead. The reference is released
 *     when the file is closed.
 *   reversible: yes
 *
 * capability: CAP_WAKE_ALARM
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Creating timers with CLOCK_REALTIME_ALARM or CLOCK_BOOTTIME_ALARM
 *   without: Returns -EPERM when attempting to use alarm clocks
 *   condition: Only checked when clockid is CLOCK_REALTIME_ALARM or
 *     CLOCK_BOOTTIME_ALARM. Not required for CLOCK_MONOTONIC, CLOCK_REALTIME,
 *     or CLOCK_BOOTTIME. The capability check uses capable() which checks the
 *     effective capability set of the calling process.
 *
 * constraint: Clock selection
 *   desc: The clock must be explicitly selected at creation time and cannot
 *     be changed later. The clock determines the time base for all subsequent
 *     timer operations via timerfd_settime(). Applications should carefully
 *     consider which clock to use based on their requirements for handling
 *     system time changes and suspend/resume behavior.
 *
 * constraint: Resource limits
 *   desc: Subject to the RLIMIT_NOFILE per-process limit on open file
 *     descriptors and the system-wide /proc/sys/fs/file-max limit. Each
 *     timerfd consumes one file descriptor and one file structure.
 *
 * constraint: Memory accounting
 *   desc: The timerfd_ctx memory allocation is accounted to the calling
 *     process's memory cgroup if memory cgroups are enabled. Under memory
 *     pressure, the allocation may fail with ENOMEM even if system memory
 *     is available but the cgroup is at its limit.
 *
 * examples: fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);  // Recommended usage
 *   fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);  // Non-blocking real-time timer
 *   fd = timerfd_create(CLOCK_BOOTTIME_ALARM, TFD_CLOEXEC);  // Wake-capable timer (needs CAP_WAKE_ALARM)
 *   if (fd < 0) { perror("timerfd_create"); exit(1); }
 *
 * notes: The timerfd API was introduced in Linux 2.6.25 after significant
 *   design discussions. The original 2.6.22 implementation was disabled in
 *   2.6.23 due to interface concerns and was redesigned into the current
 *   three-syscall API (timerfd_create, timerfd_settime, timerfd_gettime).
 *
 *   Unlike POSIX timers (timer_create), timerfd timers do not deliver signals.
 *   This makes them safer to use in multi-threaded programs and easier to
 *   integrate with event loops using poll/epoll.
 *
 *   The returned file descriptor shows up as "[timerfd]" in /proc/pid/fd/
 *   and /proc/pid/fdinfo/ which provides timer details including the clock ID,
 *   tick count, settime flags, and remaining/interval values.
 *
 *   For ARM architectures with OABI (old ABI), the timerfd syscalls are
 *   available but may have different syscall numbers due to ABI constraints.
 *
 *   Thread safety: The timerfd_ctx structure is protected by spinlocks for
 *   concurrent access from multiple threads. Multiple threads can safely
 *   read from the same timerfd (though only one will get each expiration
 *   notification) or call timerfd_settime/timerfd_gettime concurrently.
 *
 *   glibc provides timerfd_create() wrapper starting from version 2.8. The
 *   wrapper is a thin syscall passthrough with no additional logic.
 *
 * since-version: 2.6.25
 */
SYSCALL_DEFINE2(timerfd_create, int, clockid, int, flags)
{
	struct timerfd_ctx *ctx __free(kfree) = NULL;
	int ret;

	/* Check the TFD_* constants for consistency.  */
	BUILD_BUG_ON(TFD_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON(TFD_NONBLOCK != O_NONBLOCK);

	if ((flags & ~TFD_CREATE_FLAGS) ||
	    (clockid != CLOCK_MONOTONIC &&
	     clockid != CLOCK_REALTIME &&
	     clockid != CLOCK_REALTIME_ALARM &&
	     clockid != CLOCK_BOOTTIME &&
	     clockid != CLOCK_BOOTTIME_ALARM))
		return -EINVAL;

	if ((clockid == CLOCK_REALTIME_ALARM ||
	     clockid == CLOCK_BOOTTIME_ALARM) &&
	    !capable(CAP_WAKE_ALARM))
		return -EPERM;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	init_waitqueue_head(&ctx->wqh);
	spin_lock_init(&ctx->cancel_lock);
	ctx->clockid = clockid;

	if (isalarm(ctx))
		alarm_init(&ctx->t.alarm,
			   ctx->clockid == CLOCK_REALTIME_ALARM ?
			   ALARM_REALTIME : ALARM_BOOTTIME,
			   timerfd_alarmproc);
	else
		hrtimer_setup(&ctx->t.tmr, timerfd_tmrproc, clockid, HRTIMER_MODE_ABS);

	ctx->moffs = ktime_mono_to_real(0);

	ret = FD_ADD(flags & TFD_SHARED_FCNTL_FLAGS,
		     anon_inode_getfile_fmode("[timerfd]", &timerfd_fops, ctx,
					      O_RDWR | (flags & TFD_SHARED_FCNTL_FLAGS),
					      FMODE_NOWAIT));
	if (ret >= 0)
		retain_and_null_ptr(ctx);
	return ret;
}

static int do_timerfd_settime(int ufd, int flags, 
		const struct itimerspec64 *new,
		struct itimerspec64 *old)
{
	struct timerfd_ctx *ctx;
	int ret;

	if ((flags & ~TFD_SETTIME_FLAGS) ||
		 !itimerspec64_valid(new))
		return -EINVAL;

	CLASS(fd, f)(ufd);
	if (fd_empty(f))
		return -EBADF;

	if (fd_file(f)->f_op != &timerfd_fops)
		return -EINVAL;

	ctx = fd_file(f)->private_data;

	if (isalarm(ctx) && !capable(CAP_WAKE_ALARM))
		return -EPERM;

	timerfd_setup_cancel(ctx, flags);

	/*
	 * We need to stop the existing timer before reprogramming
	 * it to the new values.
	 */
	for (;;) {
		spin_lock_irq(&ctx->wqh.lock);

		if (isalarm(ctx)) {
			if (alarm_try_to_cancel(&ctx->t.alarm) >= 0)
				break;
		} else {
			if (hrtimer_try_to_cancel(&ctx->t.tmr) >= 0)
				break;
		}
		spin_unlock_irq(&ctx->wqh.lock);

		if (isalarm(ctx))
			hrtimer_cancel_wait_running(&ctx->t.alarm.timer);
		else
			hrtimer_cancel_wait_running(&ctx->t.tmr);
	}

	/*
	 * If the timer is expired and it's periodic, we need to advance it
	 * because the caller may want to know the previous expiration time.
	 * We do not update "ticks" and "expired" since the timer will be
	 * re-programmed again in the following timerfd_setup() call.
	 */
	if (ctx->expired && ctx->tintv) {
		if (isalarm(ctx))
			alarm_forward_now(&ctx->t.alarm, ctx->tintv);
		else
			hrtimer_forward_now(&ctx->t.tmr, ctx->tintv);
	}

	old->it_value = ktime_to_timespec64(timerfd_get_remaining(ctx));
	old->it_interval = ktime_to_timespec64(ctx->tintv);

	/*
	 * Re-program the timer to the new value ...
	 */
	ret = timerfd_setup(ctx, flags, new);

	spin_unlock_irq(&ctx->wqh.lock);
	return ret;
}

static int do_timerfd_gettime(int ufd, struct itimerspec64 *t)
{
	struct timerfd_ctx *ctx;
	CLASS(fd, f)(ufd);

	if (fd_empty(f))
		return -EBADF;
	if (fd_file(f)->f_op != &timerfd_fops)
		return -EINVAL;
	ctx = fd_file(f)->private_data;

	spin_lock_irq(&ctx->wqh.lock);
	if (ctx->expired && ctx->tintv) {
		ctx->expired = 0;

		if (isalarm(ctx)) {
			ctx->ticks +=
				alarm_forward_now(
					&ctx->t.alarm, ctx->tintv) - 1;
			alarm_restart(&ctx->t.alarm);
		} else {
			ctx->ticks +=
				hrtimer_forward_now(&ctx->t.tmr, ctx->tintv)
				- 1;
			hrtimer_restart(&ctx->t.tmr);
		}
	}
	t->it_value = ktime_to_timespec64(timerfd_get_remaining(ctx));
	t->it_interval = ktime_to_timespec64(ctx->tintv);
	spin_unlock_irq(&ctx->wqh.lock);
	return 0;
}

SYSCALL_DEFINE4(timerfd_settime, int, ufd, int, flags,
		const struct __kernel_itimerspec __user *, utmr,
		struct __kernel_itimerspec __user *, otmr)
{
	struct itimerspec64 new, old;
	int ret;

	if (get_itimerspec64(&new, utmr))
		return -EFAULT;
	ret = do_timerfd_settime(ufd, flags, &new, &old);
	if (ret)
		return ret;
	if (otmr && put_itimerspec64(&old, otmr))
		return -EFAULT;

	return ret;
}

SYSCALL_DEFINE2(timerfd_gettime, int, ufd, struct __kernel_itimerspec __user *, otmr)
{
	struct itimerspec64 kotmr;
	int ret = do_timerfd_gettime(ufd, &kotmr);
	if (ret)
		return ret;
	return put_itimerspec64(&kotmr, otmr) ? -EFAULT : 0;
}

#ifdef CONFIG_COMPAT_32BIT_TIME
SYSCALL_DEFINE4(timerfd_settime32, int, ufd, int, flags,
		const struct old_itimerspec32 __user *, utmr,
		struct old_itimerspec32 __user *, otmr)
{
	struct itimerspec64 new, old;
	int ret;

	if (get_old_itimerspec32(&new, utmr))
		return -EFAULT;
	ret = do_timerfd_settime(ufd, flags, &new, &old);
	if (ret)
		return ret;
	if (otmr && put_old_itimerspec32(&old, otmr))
		return -EFAULT;
	return ret;
}

SYSCALL_DEFINE2(timerfd_gettime32, int, ufd,
		struct old_itimerspec32 __user *, otmr)
{
	struct itimerspec64 kotmr;
	int ret = do_timerfd_gettime(ufd, &kotmr);
	if (ret)
		return ret;
	return put_old_itimerspec32(&kotmr, otmr) ? -EFAULT : 0;
}
#endif
