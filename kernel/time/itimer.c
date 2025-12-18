// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992 Darren Senn
 */

/* These are all the functions necessary to implement itimers */

#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/sched/signal.h>
#include <linux/sched/cputime.h>
#include <linux/posix-timers.h>
#include <linux/hrtimer.h>
#include <trace/events/timer.h>
#include <linux/compat.h>

#include <linux/uaccess.h>

/**
 * itimer_get_remtime - get remaining time for the timer
 *
 * @timer: the timer to read
 *
 * Returns the delta between the expiry time and now, which can be
 * less than zero or 1usec for an pending expired timer
 */
static struct timespec64 itimer_get_remtime(struct hrtimer *timer)
{
	ktime_t rem = __hrtimer_get_remaining(timer, true);

	/*
	 * Racy but safe: if the itimer expires after the above
	 * hrtimer_get_remtime() call but before this condition
	 * then we return 0 - which is correct.
	 */
	if (hrtimer_active(timer)) {
		if (rem <= 0)
			rem = NSEC_PER_USEC;
	} else
		rem = 0;

	return ktime_to_timespec64(rem);
}

static void get_cpu_itimer(struct task_struct *tsk, unsigned int clock_id,
			   struct itimerspec64 *const value)
{
	u64 val, interval;
	struct cpu_itimer *it = &tsk->signal->it[clock_id];

	spin_lock_irq(&tsk->sighand->siglock);

	val = it->expires;
	interval = it->incr;
	if (val) {
		u64 t, samples[CPUCLOCK_MAX];

		thread_group_sample_cputime(tsk, samples);
		t = samples[clock_id];

		if (val < t)
			/* about to fire */
			val = TICK_NSEC;
		else
			val -= t;
	}

	spin_unlock_irq(&tsk->sighand->siglock);

	value->it_value = ns_to_timespec64(val);
	value->it_interval = ns_to_timespec64(interval);
}

static int do_getitimer(int which, struct itimerspec64 *value)
{
	struct task_struct *tsk = current;

	switch (which) {
	case ITIMER_REAL:
		spin_lock_irq(&tsk->sighand->siglock);
		value->it_value = itimer_get_remtime(&tsk->signal->real_timer);
		value->it_interval =
			ktime_to_timespec64(tsk->signal->it_real_incr);
		spin_unlock_irq(&tsk->sighand->siglock);
		break;
	case ITIMER_VIRTUAL:
		get_cpu_itimer(tsk, CPUCLOCK_VIRT, value);
		break;
	case ITIMER_PROF:
		get_cpu_itimer(tsk, CPUCLOCK_PROF, value);
		break;
	default:
		return(-EINVAL);
	}
	return 0;
}

static int put_itimerval(struct __kernel_old_itimerval __user *o,
			 const struct itimerspec64 *i)
{
	struct __kernel_old_itimerval v;

	v.it_interval.tv_sec = i->it_interval.tv_sec;
	v.it_interval.tv_usec = i->it_interval.tv_nsec / NSEC_PER_USEC;
	v.it_value.tv_sec = i->it_value.tv_sec;
	v.it_value.tv_usec = i->it_value.tv_nsec / NSEC_PER_USEC;
	return copy_to_user(o, &v, sizeof(struct __kernel_old_itimerval)) ? -EFAULT : 0;
}


/**
 * sys_getitimer - Get value of an interval timer
 * @which: Timer type selector (ITIMER_REAL, ITIMER_VIRTUAL, or ITIMER_PROF)
 * @value: User pointer to receive the timer value
 *
 * long-desc: Retrieves the current value of one of the three per-process
 *   interval timers. The timer value is returned in a struct itimerval
 *   containing both the current remaining time until the next expiration
 *   (it_value) and the interval for periodic timers (it_interval).
 *
 *   Three timer types are available:
 *   - ITIMER_REAL (0): A wall-clock timer that counts down in real time
 *     regardless of process execution. When it expires, SIGALRM is delivered
 *     to the process. This timer uses high-resolution timers (hrtimers)
 *     internally.
 *   - ITIMER_VIRTUAL (1): A CPU time timer that counts only when the process
 *     is executing in user mode. When it expires, SIGVTALRM is delivered.
 *   - ITIMER_PROF (2): A CPU time timer that counts when the process is
 *     executing in either user or kernel mode (total CPU time). When it
 *     expires, SIGPROF is delivered. This is commonly used for profiling.
 *
 *   For ITIMER_VIRTUAL and ITIMER_PROF, the timer value represents CPU time
 *   consumed by the entire thread group (process), sampled from the thread
 *   group cputimer. For ITIMER_REAL, the remaining time is obtained from the
 *   underlying hrtimer.
 *
 *   If the timer is disarmed (not running), both it_value fields will be zero.
 *   If the timer is armed as a single-shot timer (not periodic), it_interval
 *   fields will be zero.
 *
 *   The returned time values have microsecond resolution (struct timeval),
 *   though the actual timer resolution may be coarser depending on system
 *   configuration. For pending expired timers that haven't been processed yet,
 *   it_value may show 1 microsecond rather than zero.
 *
 *   This syscall is read-only and does not modify any timer state. It can be
 *   called safely from any process context. A 32-bit compatible version
 *   (compat_sys_getitimer) exists for 32-bit processes on 64-bit kernels.
 *
 *   Each process has exactly one timer of each type. Timers are inherited
 *   across fork() as disarmed (not running), and persist across execve().
 *   POSIX recommends using timer_gettime() instead, as interval timers are
 *   considered obsolescent.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: which
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_ENUM
 *   constraint: Must be one of ITIMER_REAL (0), ITIMER_VIRTUAL (1), or
 *     ITIMER_PROF (2). Any other value returns EINVAL. These constants are
 *     defined in <linux/time.h>.
 *
 * param: value
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid pointer to a struct __kernel_old_itimerval
 *     (or struct itimerval in userspace). The structure must be writable by
 *     the process. NULL pointer or invalid address returns EFAULT. The
 *     structure contains two struct timeval members: it_interval (timer
 *     period) and it_value (time remaining).
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success with the timer value written to @value.
 *     On error, returns a negative errno value and @value contents are
 *     undefined.
 *
 * error: EINVAL, Invalid timer type
 *   desc: The @which parameter is not one of ITIMER_REAL (0), ITIMER_VIRTUAL
 *     (1), or ITIMER_PROF (2). This check is performed first in do_getitimer()
 *     via a switch statement default case.
 *
 * error: EFAULT, Invalid user pointer
 *   desc: The @value pointer is NULL, points to an invalid address, or points
 *     to memory that is not writable by the process. The copy_to_user() call
 *     in put_itimerval() fails. This error is only returned after successfully
 *     retrieving the timer value, so EINVAL takes precedence.
 *
 * lock: sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The signal handler spinlock is held with interrupts disabled
 *     (spin_lock_irq/spin_unlock_irq) while reading timer state. For
 *     ITIMER_REAL, this protects access to signal->real_timer and
 *     signal->it_real_incr. For ITIMER_VIRTUAL and ITIMER_PROF, this
 *     protects access to signal->it[clock_id] (struct cpu_itimer) and
 *     the thread group cputime sampling.
 *
 * lock: hrtimer_base->cpu_base->lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: For ITIMER_REAL only, the hrtimer base lock is briefly acquired
 *     inside __hrtimer_get_remaining() to read the timer expiry time. This
 *     is nested inside sighand->siglock but uses raw spinlocks internally.
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: This syscall does not interact with signals
 *   desc: This syscall is a simple read operation that does not check for
 *     pending signals or send any signals. It is not interruptible by signals
 *     because it completes quickly and only performs a copy_to_user() which
 *     handles faults internally without returning EINTR.
 *
 * side-effect: KAPI_EFFECT_NONE
 *   target: None
 *   desc: This is a read-only syscall that does not modify any kernel state.
 *     It only reads timer values and copies them to userspace.
 *
 * examples: getitimer(ITIMER_REAL, &val);  // Get wall-clock timer
 *   getitimer(ITIMER_VIRTUAL, &val);  // Get user CPU time timer
 *   getitimer(ITIMER_PROF, &val);  // Get profiling timer
 *
 * notes: The ITIMER_VIRTUAL and ITIMER_PROF timers require active CPU time
 *   accounting, which is enabled when any POSIX CPU timer is active for the
 *   process. For very short timer values, the returned it_value may show a
 *   minimum of 1 microsecond (TICK_NSEC converted to microseconds) for timers
 *   that are about to expire, to distinguish from disarmed timers which show
 *   zero. There is an inherent race between reading the timer and acting on
 *   the value - the timer continues to run (or may expire) after getitimer()
 *   returns. For ITIMER_REAL, CONFIG_TIME_LOW_RES affects the timer adjustment
 *   behavior. The microsecond values returned may be truncated (not rounded)
 *   from the internal nanosecond representation.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE2(getitimer, int, which, struct __kernel_old_itimerval __user *, value)
{
	struct itimerspec64 get_buffer;
	int error = do_getitimer(which, &get_buffer);

	if (!error && put_itimerval(value, &get_buffer))
		error = -EFAULT;
	return error;
}

#if defined(CONFIG_COMPAT) || defined(CONFIG_ALPHA)
struct old_itimerval32 {
	struct old_timeval32	it_interval;
	struct old_timeval32	it_value;
};

static int put_old_itimerval32(struct old_itimerval32 __user *o,
			       const struct itimerspec64 *i)
{
	struct old_itimerval32 v32;

	v32.it_interval.tv_sec = i->it_interval.tv_sec;
	v32.it_interval.tv_usec = i->it_interval.tv_nsec / NSEC_PER_USEC;
	v32.it_value.tv_sec = i->it_value.tv_sec;
	v32.it_value.tv_usec = i->it_value.tv_nsec / NSEC_PER_USEC;
	return copy_to_user(o, &v32, sizeof(struct old_itimerval32)) ? -EFAULT : 0;
}

COMPAT_SYSCALL_DEFINE2(getitimer, int, which,
		       struct old_itimerval32 __user *, value)
{
	struct itimerspec64 get_buffer;
	int error = do_getitimer(which, &get_buffer);

	if (!error && put_old_itimerval32(value, &get_buffer))
		error = -EFAULT;
	return error;
}
#endif

/*
 * Invoked from dequeue_signal() when SIG_ALRM is delivered.
 *
 * Restart the ITIMER_REAL timer if it is armed as periodic timer.  Doing
 * this in the signal delivery path instead of self rearming prevents a DoS
 * with small increments in the high reolution timer case and reduces timer
 * noise in general.
 */
void posixtimer_rearm_itimer(struct task_struct *tsk)
{
	struct hrtimer *tmr = &tsk->signal->real_timer;

	if (!hrtimer_is_queued(tmr) && tsk->signal->it_real_incr != 0) {
		hrtimer_forward_now(tmr, tsk->signal->it_real_incr);
		hrtimer_restart(tmr);
	}
}

/*
 * Interval timers are restarted in the signal delivery path.  See
 * posixtimer_rearm_itimer().
 */
enum hrtimer_restart it_real_fn(struct hrtimer *timer)
{
	struct signal_struct *sig =
		container_of(timer, struct signal_struct, real_timer);
	struct pid *leader_pid = sig->pids[PIDTYPE_TGID];

	trace_itimer_expire(ITIMER_REAL, leader_pid, 0);
	kill_pid_info(SIGALRM, SEND_SIG_PRIV, leader_pid);

	return HRTIMER_NORESTART;
}

static void set_cpu_itimer(struct task_struct *tsk, unsigned int clock_id,
			   const struct itimerspec64 *const value,
			   struct itimerspec64 *const ovalue)
{
	u64 oval, nval, ointerval, ninterval;
	struct cpu_itimer *it = &tsk->signal->it[clock_id];

	nval = timespec64_to_ns(&value->it_value);
	ninterval = timespec64_to_ns(&value->it_interval);

	spin_lock_irq(&tsk->sighand->siglock);

	oval = it->expires;
	ointerval = it->incr;
	if (oval || nval) {
		if (nval > 0)
			nval += TICK_NSEC;
		set_process_cpu_timer(tsk, clock_id, &nval, &oval);
	}
	it->expires = nval;
	it->incr = ninterval;
	trace_itimer_state(clock_id == CPUCLOCK_VIRT ?
			   ITIMER_VIRTUAL : ITIMER_PROF, value, nval);

	spin_unlock_irq(&tsk->sighand->siglock);

	if (ovalue) {
		ovalue->it_value = ns_to_timespec64(oval);
		ovalue->it_interval = ns_to_timespec64(ointerval);
	}
}

/*
 * Returns true if the timeval is in canonical form
 */
#define timeval_valid(t) \
	(((t)->tv_sec >= 0) && (((unsigned long) (t)->tv_usec) < USEC_PER_SEC))

static int do_setitimer(int which, struct itimerspec64 *value,
			struct itimerspec64 *ovalue)
{
	struct task_struct *tsk = current;
	struct hrtimer *timer;
	ktime_t expires;

	switch (which) {
	case ITIMER_REAL:
again:
		spin_lock_irq(&tsk->sighand->siglock);
		timer = &tsk->signal->real_timer;
		if (ovalue) {
			ovalue->it_value = itimer_get_remtime(timer);
			ovalue->it_interval
				= ktime_to_timespec64(tsk->signal->it_real_incr);
		}
		/* We are sharing ->siglock with it_real_fn() */
		if (hrtimer_try_to_cancel(timer) < 0) {
			spin_unlock_irq(&tsk->sighand->siglock);
			hrtimer_cancel_wait_running(timer);
			goto again;
		}
		expires = timespec64_to_ktime(value->it_value);
		if (expires != 0) {
			tsk->signal->it_real_incr =
				timespec64_to_ktime(value->it_interval);
			hrtimer_start(timer, expires, HRTIMER_MODE_REL);
		} else
			tsk->signal->it_real_incr = 0;

		trace_itimer_state(ITIMER_REAL, value, 0);
		spin_unlock_irq(&tsk->sighand->siglock);
		break;
	case ITIMER_VIRTUAL:
		set_cpu_itimer(tsk, CPUCLOCK_VIRT, value, ovalue);
		break;
	case ITIMER_PROF:
		set_cpu_itimer(tsk, CPUCLOCK_PROF, value, ovalue);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

#ifdef CONFIG_SECURITY_SELINUX
void clear_itimer(void)
{
	struct itimerspec64 v = {};
	int i;

	for (i = 0; i < 3; i++)
		do_setitimer(i, &v, NULL);
}
#endif

#ifdef __ARCH_WANT_SYS_ALARM

/**
 * alarm_setitimer - set alarm in seconds
 *
 * @seconds:	number of seconds until alarm
 *		0 disables the alarm
 *
 * Returns the remaining time in seconds of a pending timer or 0 when
 * the timer is not active.
 *
 * On 32 bit machines the seconds value is limited to (INT_MAX/2) to avoid
 * negative timeval settings which would cause immediate expiry.
 */
static unsigned int alarm_setitimer(unsigned int seconds)
{
	struct itimerspec64 it_new, it_old;

#if BITS_PER_LONG < 64
	if (seconds > INT_MAX)
		seconds = INT_MAX;
#endif
	it_new.it_value.tv_sec = seconds;
	it_new.it_value.tv_nsec = 0;
	it_new.it_interval.tv_sec = it_new.it_interval.tv_nsec = 0;

	do_setitimer(ITIMER_REAL, &it_new, &it_old);

	/*
	 * We can't return 0 if we have an alarm pending ...  And we'd
	 * better return too much than too little anyway
	 */
	if ((!it_old.it_value.tv_sec && it_old.it_value.tv_nsec) ||
	      it_old.it_value.tv_nsec >= (NSEC_PER_SEC / 2))
		it_old.it_value.tv_sec++;

	return it_old.it_value.tv_sec;
}

/*
 * For backwards compatibility?  This can be done in libc so Alpha
 * and all newer ports shouldn't need it.
 */
SYSCALL_DEFINE1(alarm, unsigned int, seconds)
{
	return alarm_setitimer(seconds);
}

#endif

static int get_itimerval(struct itimerspec64 *o, const struct __kernel_old_itimerval __user *i)
{
	struct __kernel_old_itimerval v;

	if (copy_from_user(&v, i, sizeof(struct __kernel_old_itimerval)))
		return -EFAULT;

	/* Validate the timevals in value. */
	if (!timeval_valid(&v.it_value) ||
	    !timeval_valid(&v.it_interval))
		return -EINVAL;

	o->it_interval.tv_sec = v.it_interval.tv_sec;
	o->it_interval.tv_nsec = v.it_interval.tv_usec * NSEC_PER_USEC;
	o->it_value.tv_sec = v.it_value.tv_sec;
	o->it_value.tv_nsec = v.it_value.tv_usec * NSEC_PER_USEC;
	return 0;
}

SYSCALL_DEFINE3(setitimer, int, which, struct __kernel_old_itimerval __user *, value,
		struct __kernel_old_itimerval __user *, ovalue)
{
	struct itimerspec64 set_buffer, get_buffer;
	int error;

	if (value) {
		error = get_itimerval(&set_buffer, value);
		if (error)
			return error;
	} else {
		memset(&set_buffer, 0, sizeof(set_buffer));
		printk_once(KERN_WARNING "%s calls setitimer() with new_value NULL pointer."
			    " Misfeature support will be removed\n",
			    current->comm);
	}

	error = do_setitimer(which, &set_buffer, ovalue ? &get_buffer : NULL);
	if (error || !ovalue)
		return error;

	if (put_itimerval(ovalue, &get_buffer))
		return -EFAULT;
	return 0;
}

#if defined(CONFIG_COMPAT) || defined(CONFIG_ALPHA)
static int get_old_itimerval32(struct itimerspec64 *o, const struct old_itimerval32 __user *i)
{
	struct old_itimerval32 v32;

	if (copy_from_user(&v32, i, sizeof(struct old_itimerval32)))
		return -EFAULT;

	/* Validate the timevals in value.  */
	if (!timeval_valid(&v32.it_value) ||
	    !timeval_valid(&v32.it_interval))
		return -EINVAL;

	o->it_interval.tv_sec = v32.it_interval.tv_sec;
	o->it_interval.tv_nsec = v32.it_interval.tv_usec * NSEC_PER_USEC;
	o->it_value.tv_sec = v32.it_value.tv_sec;
	o->it_value.tv_nsec = v32.it_value.tv_usec * NSEC_PER_USEC;
	return 0;
}

COMPAT_SYSCALL_DEFINE3(setitimer, int, which,
		       struct old_itimerval32 __user *, value,
		       struct old_itimerval32 __user *, ovalue)
{
	struct itimerspec64 set_buffer, get_buffer;
	int error;

	if (value) {
		error = get_old_itimerval32(&set_buffer, value);
		if (error)
			return error;
	} else {
		memset(&set_buffer, 0, sizeof(set_buffer));
		printk_once(KERN_WARNING "%s calls setitimer() with new_value NULL pointer."
			    " Misfeature support will be removed\n",
			    current->comm);
	}

	error = do_setitimer(which, &set_buffer, ovalue ? &get_buffer : NULL);
	if (error || !ovalue)
		return error;
	if (put_old_itimerval32(ovalue, &get_buffer))
		return -EFAULT;
	return 0;
}
#endif
