// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/signal.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  1997-11-02  Modified for POSIX.1b signals by Richard Henderson
 *
 *  2003-06-02  Jim Houston - Concurrent Computer Corp.
 *		Changes to use preallocated sigqueue structures
 *		to allow signals to be sent reliably.
 */

#include <linux/slab.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/user.h>
#include <linux/sched/debug.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/cputime.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/tty.h>
#include <linux/binfmts.h>
#include <linux/coredump.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/ptrace.h>
#include <linux/signal.h>
#include <linux/signalfd.h>
#include <linux/ratelimit.h>
#include <linux/task_work.h>
#include <linux/capability.h>
#include <linux/freezer.h>
#include <linux/pid_namespace.h>
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>
#include <linux/uprobes.h>
#include <linux/compat.h>
#include <linux/cn_proc.h>
#include <linux/compiler.h>
#include <linux/posix-timers.h>
#include <linux/cgroup.h>
#include <linux/audit.h>
#include <linux/sysctl.h>
#include <uapi/linux/pidfd.h>

#define CREATE_TRACE_POINTS
#include <trace/events/signal.h>

#include <asm/param.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>
#include <asm/siginfo.h>
#include <asm/cacheflush.h>
#include <asm/syscall.h>	/* for syscall_get_* */

#include "time/posix-timers.h"

/*
 * SLAB caches for signal bits.
 */

static struct kmem_cache *sigqueue_cachep;

int print_fatal_signals __read_mostly;

static void __user *sig_handler(struct task_struct *t, int sig)
{
	return t->sighand->action[sig - 1].sa.sa_handler;
}

static inline bool sig_handler_ignored(void __user *handler, int sig)
{
	/* Is it explicitly or implicitly ignored? */
	return handler == SIG_IGN ||
	       (handler == SIG_DFL && sig_kernel_ignore(sig));
}

static bool sig_task_ignored(struct task_struct *t, int sig, bool force)
{
	void __user *handler;

	handler = sig_handler(t, sig);

	/* SIGKILL and SIGSTOP may not be sent to the global init */
	if (unlikely(is_global_init(t) && sig_kernel_only(sig)))
		return true;

	if (unlikely(t->signal->flags & SIGNAL_UNKILLABLE) &&
	    handler == SIG_DFL && !(force && sig_kernel_only(sig)))
		return true;

	/* Only allow kernel generated signals to this kthread */
	if (unlikely((t->flags & PF_KTHREAD) &&
		     (handler == SIG_KTHREAD_KERNEL) && !force))
		return true;

	return sig_handler_ignored(handler, sig);
}

static bool sig_ignored(struct task_struct *t, int sig, bool force)
{
	/*
	 * Blocked signals are never ignored, since the
	 * signal handler may change by the time it is
	 * unblocked.
	 */
	if (sigismember(&t->blocked, sig) || sigismember(&t->real_blocked, sig))
		return false;

	/*
	 * Tracers may want to know about even ignored signal unless it
	 * is SIGKILL which can't be reported anyway but can be ignored
	 * by SIGNAL_UNKILLABLE task.
	 */
	if (t->ptrace && sig != SIGKILL)
		return false;

	return sig_task_ignored(t, sig, force);
}

/*
 * Re-calculate pending state from the set of locally pending
 * signals, globally pending signals, and blocked signals.
 */
static inline bool has_pending_signals(sigset_t *signal, sigset_t *blocked)
{
	unsigned long ready;
	long i;

	switch (_NSIG_WORDS) {
	default:
		for (i = _NSIG_WORDS, ready = 0; --i >= 0 ;)
			ready |= signal->sig[i] &~ blocked->sig[i];
		break;

	case 4: ready  = signal->sig[3] &~ blocked->sig[3];
		ready |= signal->sig[2] &~ blocked->sig[2];
		ready |= signal->sig[1] &~ blocked->sig[1];
		ready |= signal->sig[0] &~ blocked->sig[0];
		break;

	case 2: ready  = signal->sig[1] &~ blocked->sig[1];
		ready |= signal->sig[0] &~ blocked->sig[0];
		break;

	case 1: ready  = signal->sig[0] &~ blocked->sig[0];
	}
	return ready !=	0;
}

#define PENDING(p,b) has_pending_signals(&(p)->signal, (b))

static bool recalc_sigpending_tsk(struct task_struct *t)
{
	if ((t->jobctl & (JOBCTL_PENDING_MASK | JOBCTL_TRAP_FREEZE)) ||
	    PENDING(&t->pending, &t->blocked) ||
	    PENDING(&t->signal->shared_pending, &t->blocked) ||
	    cgroup_task_frozen(t)) {
		set_tsk_thread_flag(t, TIF_SIGPENDING);
		return true;
	}

	/*
	 * We must never clear the flag in another thread, or in current
	 * when it's possible the current syscall is returning -ERESTART*.
	 * So we don't clear it here, and only callers who know they should do.
	 */
	return false;
}

void recalc_sigpending(void)
{
	if (!recalc_sigpending_tsk(current) && !freezing(current)) {
		if (unlikely(test_thread_flag(TIF_SIGPENDING)))
			clear_thread_flag(TIF_SIGPENDING);
	}
}
EXPORT_SYMBOL(recalc_sigpending);

void calculate_sigpending(void)
{
	/* Have any signals or users of TIF_SIGPENDING been delayed
	 * until after fork?
	 */
	spin_lock_irq(&current->sighand->siglock);
	set_tsk_thread_flag(current, TIF_SIGPENDING);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
}

/* Given the mask, find the first available signal that should be serviced. */

#define SYNCHRONOUS_MASK \
	(sigmask(SIGSEGV) | sigmask(SIGBUS) | sigmask(SIGILL) | \
	 sigmask(SIGTRAP) | sigmask(SIGFPE) | sigmask(SIGSYS))

int next_signal(struct sigpending *pending, sigset_t *mask)
{
	unsigned long i, *s, *m, x;
	int sig = 0;

	s = pending->signal.sig;
	m = mask->sig;

	/*
	 * Handle the first word specially: it contains the
	 * synchronous signals that need to be dequeued first.
	 */
	x = *s &~ *m;
	if (x) {
		if (x & SYNCHRONOUS_MASK)
			x &= SYNCHRONOUS_MASK;
		sig = ffz(~x) + 1;
		return sig;
	}

	switch (_NSIG_WORDS) {
	default:
		for (i = 1; i < _NSIG_WORDS; ++i) {
			x = *++s &~ *++m;
			if (!x)
				continue;
			sig = ffz(~x) + i*_NSIG_BPW + 1;
			break;
		}
		break;

	case 2:
		x = s[1] &~ m[1];
		if (!x)
			break;
		sig = ffz(~x) + _NSIG_BPW + 1;
		break;

	case 1:
		/* Nothing to do */
		break;
	}

	return sig;
}

static inline void print_dropped_signal(int sig)
{
	static DEFINE_RATELIMIT_STATE(ratelimit_state, 5 * HZ, 10);

	if (!print_fatal_signals)
		return;

	if (!__ratelimit(&ratelimit_state))
		return;

	pr_info("%s/%d: reached RLIMIT_SIGPENDING, dropped signal %d\n",
				current->comm, current->pid, sig);
}

/**
 * task_set_jobctl_pending - set jobctl pending bits
 * @task: target task
 * @mask: pending bits to set
 *
 * Clear @mask from @task->jobctl.  @mask must be subset of
 * %JOBCTL_PENDING_MASK | %JOBCTL_STOP_CONSUME | %JOBCTL_STOP_SIGMASK |
 * %JOBCTL_TRAPPING.  If stop signo is being set, the existing signo is
 * cleared.  If @task is already being killed or exiting, this function
 * becomes noop.
 *
 * CONTEXT:
 * Must be called with @task->sighand->siglock held.
 *
 * RETURNS:
 * %true if @mask is set, %false if made noop because @task was dying.
 */
bool task_set_jobctl_pending(struct task_struct *task, unsigned long mask)
{
	BUG_ON(mask & ~(JOBCTL_PENDING_MASK | JOBCTL_STOP_CONSUME |
			JOBCTL_STOP_SIGMASK | JOBCTL_TRAPPING));
	BUG_ON((mask & JOBCTL_TRAPPING) && !(mask & JOBCTL_PENDING_MASK));

	if (unlikely(fatal_signal_pending(task) || (task->flags & PF_EXITING)))
		return false;

	if (mask & JOBCTL_STOP_SIGMASK)
		task->jobctl &= ~JOBCTL_STOP_SIGMASK;

	task->jobctl |= mask;
	return true;
}

/**
 * task_clear_jobctl_trapping - clear jobctl trapping bit
 * @task: target task
 *
 * If JOBCTL_TRAPPING is set, a ptracer is waiting for us to enter TRACED.
 * Clear it and wake up the ptracer.  Note that we don't need any further
 * locking.  @task->siglock guarantees that @task->parent points to the
 * ptracer.
 *
 * CONTEXT:
 * Must be called with @task->sighand->siglock held.
 */
void task_clear_jobctl_trapping(struct task_struct *task)
{
	if (unlikely(task->jobctl & JOBCTL_TRAPPING)) {
		task->jobctl &= ~JOBCTL_TRAPPING;
		smp_mb();	/* advised by wake_up_bit() */
		wake_up_bit(&task->jobctl, JOBCTL_TRAPPING_BIT);
	}
}

/**
 * task_clear_jobctl_pending - clear jobctl pending bits
 * @task: target task
 * @mask: pending bits to clear
 *
 * Clear @mask from @task->jobctl.  @mask must be subset of
 * %JOBCTL_PENDING_MASK.  If %JOBCTL_STOP_PENDING is being cleared, other
 * STOP bits are cleared together.
 *
 * If clearing of @mask leaves no stop or trap pending, this function calls
 * task_clear_jobctl_trapping().
 *
 * CONTEXT:
 * Must be called with @task->sighand->siglock held.
 */
void task_clear_jobctl_pending(struct task_struct *task, unsigned long mask)
{
	BUG_ON(mask & ~JOBCTL_PENDING_MASK);

	if (mask & JOBCTL_STOP_PENDING)
		mask |= JOBCTL_STOP_CONSUME | JOBCTL_STOP_DEQUEUED;

	task->jobctl &= ~mask;

	if (!(task->jobctl & JOBCTL_PENDING_MASK))
		task_clear_jobctl_trapping(task);
}

/**
 * task_participate_group_stop - participate in a group stop
 * @task: task participating in a group stop
 *
 * @task has %JOBCTL_STOP_PENDING set and is participating in a group stop.
 * Group stop states are cleared and the group stop count is consumed if
 * %JOBCTL_STOP_CONSUME was set.  If the consumption completes the group
 * stop, the appropriate `SIGNAL_*` flags are set.
 *
 * CONTEXT:
 * Must be called with @task->sighand->siglock held.
 *
 * RETURNS:
 * %true if group stop completion should be notified to the parent, %false
 * otherwise.
 */
static bool task_participate_group_stop(struct task_struct *task)
{
	struct signal_struct *sig = task->signal;
	bool consume = task->jobctl & JOBCTL_STOP_CONSUME;

	WARN_ON_ONCE(!(task->jobctl & JOBCTL_STOP_PENDING));

	task_clear_jobctl_pending(task, JOBCTL_STOP_PENDING);

	if (!consume)
		return false;

	if (!WARN_ON_ONCE(sig->group_stop_count == 0))
		sig->group_stop_count--;

	/*
	 * Tell the caller to notify completion iff we are entering into a
	 * fresh group stop.  Read comment in do_signal_stop() for details.
	 */
	if (!sig->group_stop_count && !(sig->flags & SIGNAL_STOP_STOPPED)) {
		signal_set_stop_flags(sig, SIGNAL_STOP_STOPPED);
		return true;
	}
	return false;
}

void task_join_group_stop(struct task_struct *task)
{
	unsigned long mask = current->jobctl & JOBCTL_STOP_SIGMASK;
	struct signal_struct *sig = current->signal;

	if (sig->group_stop_count) {
		sig->group_stop_count++;
		mask |= JOBCTL_STOP_CONSUME;
	} else if (!(sig->flags & SIGNAL_STOP_STOPPED))
		return;

	/* Have the new thread join an on-going signal group stop */
	task_set_jobctl_pending(task, mask | JOBCTL_STOP_PENDING);
}

static struct ucounts *sig_get_ucounts(struct task_struct *t, int sig,
				       int override_rlimit)
{
	struct ucounts *ucounts;
	long sigpending;

	/*
	 * Protect access to @t credentials. This can go away when all
	 * callers hold rcu read lock.
	 *
	 * NOTE! A pending signal will hold on to the user refcount,
	 * and we get/put the refcount only when the sigpending count
	 * changes from/to zero.
	 */
	rcu_read_lock();
	ucounts = task_ucounts(t);
	sigpending = inc_rlimit_get_ucounts(ucounts, UCOUNT_RLIMIT_SIGPENDING,
					    override_rlimit);
	rcu_read_unlock();
	if (!sigpending)
		return NULL;

	if (unlikely(!override_rlimit && sigpending > task_rlimit(t, RLIMIT_SIGPENDING))) {
		dec_rlimit_put_ucounts(ucounts, UCOUNT_RLIMIT_SIGPENDING);
		print_dropped_signal(sig);
		return NULL;
	}

	return ucounts;
}

static void __sigqueue_init(struct sigqueue *q, struct ucounts *ucounts,
			    const unsigned int sigqueue_flags)
{
	INIT_LIST_HEAD(&q->list);
	q->flags = sigqueue_flags;
	q->ucounts = ucounts;
}

/*
 * allocate a new signal queue record
 * - this may be called without locks if and only if t == current, otherwise an
 *   appropriate lock must be held to stop the target task from exiting
 */
static struct sigqueue *sigqueue_alloc(int sig, struct task_struct *t, gfp_t gfp_flags,
				       int override_rlimit)
{
	struct ucounts *ucounts = sig_get_ucounts(t, sig, override_rlimit);
	struct sigqueue *q;

	if (!ucounts)
		return NULL;

	q = kmem_cache_alloc(sigqueue_cachep, gfp_flags);
	if (!q) {
		dec_rlimit_put_ucounts(ucounts, UCOUNT_RLIMIT_SIGPENDING);
		return NULL;
	}

	__sigqueue_init(q, ucounts, 0);
	return q;
}

static void __sigqueue_free(struct sigqueue *q)
{
	if (q->flags & SIGQUEUE_PREALLOC) {
		posixtimer_sigqueue_putref(q);
		return;
	}
	if (q->ucounts) {
		dec_rlimit_put_ucounts(q->ucounts, UCOUNT_RLIMIT_SIGPENDING);
		q->ucounts = NULL;
	}
	kmem_cache_free(sigqueue_cachep, q);
}

void flush_sigqueue(struct sigpending *queue)
{
	struct sigqueue *q;

	sigemptyset(&queue->signal);
	while (!list_empty(&queue->list)) {
		q = list_entry(queue->list.next, struct sigqueue , list);
		list_del_init(&q->list);
		__sigqueue_free(q);
	}
}

/*
 * Flush all pending signals for this kthread.
 */
void flush_signals(struct task_struct *t)
{
	unsigned long flags;

	spin_lock_irqsave(&t->sighand->siglock, flags);
	clear_tsk_thread_flag(t, TIF_SIGPENDING);
	flush_sigqueue(&t->pending);
	flush_sigqueue(&t->signal->shared_pending);
	spin_unlock_irqrestore(&t->sighand->siglock, flags);
}
EXPORT_SYMBOL(flush_signals);

void ignore_signals(struct task_struct *t)
{
	int i;

	for (i = 0; i < _NSIG; ++i)
		t->sighand->action[i].sa.sa_handler = SIG_IGN;

	flush_signals(t);
}

/*
 * Flush all handlers for a task.
 */

void
flush_signal_handlers(struct task_struct *t, int force_default)
{
	int i;
	struct k_sigaction *ka = &t->sighand->action[0];
	for (i = _NSIG ; i != 0 ; i--) {
		if (force_default || ka->sa.sa_handler != SIG_IGN)
			ka->sa.sa_handler = SIG_DFL;
		ka->sa.sa_flags = 0;
#ifdef __ARCH_HAS_SA_RESTORER
		ka->sa.sa_restorer = NULL;
#endif
		sigemptyset(&ka->sa.sa_mask);
		ka++;
	}
}

bool unhandled_signal(struct task_struct *tsk, int sig)
{
	void __user *handler = tsk->sighand->action[sig-1].sa.sa_handler;
	if (is_global_init(tsk))
		return true;

	if (handler != SIG_IGN && handler != SIG_DFL)
		return false;

	/* If dying, we handle all new signals by ignoring them */
	if (fatal_signal_pending(tsk))
		return false;

	/* if ptraced, let the tracer determine */
	return !tsk->ptrace;
}

static void collect_signal(int sig, struct sigpending *list, kernel_siginfo_t *info,
			   struct sigqueue **timer_sigq)
{
	struct sigqueue *q, *first = NULL;

	/*
	 * Collect the siginfo appropriate to this signal.  Check if
	 * there is another siginfo for the same signal.
	*/
	list_for_each_entry(q, &list->list, list) {
		if (q->info.si_signo == sig) {
			if (first)
				goto still_pending;
			first = q;
		}
	}

	sigdelset(&list->signal, sig);

	if (first) {
still_pending:
		list_del_init(&first->list);
		copy_siginfo(info, &first->info);

		/*
		 * posix-timer signals are preallocated and freed when the last
		 * reference count is dropped in posixtimer_deliver_signal() or
		 * immediately on timer deletion when the signal is not pending.
		 * Spare the extra round through __sigqueue_free() which is
		 * ignoring preallocated signals.
		 */
		if (unlikely((first->flags & SIGQUEUE_PREALLOC) && (info->si_code == SI_TIMER)))
			*timer_sigq = first;
		else
			__sigqueue_free(first);
	} else {
		/*
		 * Ok, it wasn't in the queue.  This must be
		 * a fast-pathed signal or we must have been
		 * out of queue space.  So zero out the info.
		 */
		clear_siginfo(info);
		info->si_signo = sig;
		info->si_errno = 0;
		info->si_code = SI_USER;
		info->si_pid = 0;
		info->si_uid = 0;
	}
}

static int __dequeue_signal(struct sigpending *pending, sigset_t *mask,
			    kernel_siginfo_t *info, struct sigqueue **timer_sigq)
{
	int sig = next_signal(pending, mask);

	if (sig)
		collect_signal(sig, pending, info, timer_sigq);
	return sig;
}

/*
 * Try to dequeue a signal. If a deliverable signal is found fill in the
 * caller provided siginfo and return the signal number. Otherwise return
 * 0.
 */
int dequeue_signal(sigset_t *mask, kernel_siginfo_t *info, enum pid_type *type)
{
	struct task_struct *tsk = current;
	struct sigqueue *timer_sigq;
	int signr;

	lockdep_assert_held(&tsk->sighand->siglock);

again:
	*type = PIDTYPE_PID;
	timer_sigq = NULL;
	signr = __dequeue_signal(&tsk->pending, mask, info, &timer_sigq);
	if (!signr) {
		*type = PIDTYPE_TGID;
		signr = __dequeue_signal(&tsk->signal->shared_pending,
					 mask, info, &timer_sigq);

		if (unlikely(signr == SIGALRM))
			posixtimer_rearm_itimer(tsk);
	}

	recalc_sigpending();
	if (!signr)
		return 0;

	if (unlikely(sig_kernel_stop(signr))) {
		/*
		 * Set a marker that we have dequeued a stop signal.  Our
		 * caller might release the siglock and then the pending
		 * stop signal it is about to process is no longer in the
		 * pending bitmasks, but must still be cleared by a SIGCONT
		 * (and overruled by a SIGKILL).  So those cases clear this
		 * shared flag after we've set it.  Note that this flag may
		 * remain set after the signal we return is ignored or
		 * handled.  That doesn't matter because its only purpose
		 * is to alert stop-signal processing code when another
		 * processor has come along and cleared the flag.
		 */
		current->jobctl |= JOBCTL_STOP_DEQUEUED;
	}

	if (IS_ENABLED(CONFIG_POSIX_TIMERS) && unlikely(timer_sigq)) {
		if (!posixtimer_deliver_signal(info, timer_sigq))
			goto again;
	}

	return signr;
}
EXPORT_SYMBOL_GPL(dequeue_signal);

static int dequeue_synchronous_signal(kernel_siginfo_t *info)
{
	struct task_struct *tsk = current;
	struct sigpending *pending = &tsk->pending;
	struct sigqueue *q, *sync = NULL;

	/*
	 * Might a synchronous signal be in the queue?
	 */
	if (!((pending->signal.sig[0] & ~tsk->blocked.sig[0]) & SYNCHRONOUS_MASK))
		return 0;

	/*
	 * Return the first synchronous signal in the queue.
	 */
	list_for_each_entry(q, &pending->list, list) {
		/* Synchronous signals have a positive si_code */
		if ((q->info.si_code > SI_USER) &&
		    (sigmask(q->info.si_signo) & SYNCHRONOUS_MASK)) {
			sync = q;
			goto next;
		}
	}
	return 0;
next:
	/*
	 * Check if there is another siginfo for the same signal.
	 */
	list_for_each_entry_continue(q, &pending->list, list) {
		if (q->info.si_signo == sync->info.si_signo)
			goto still_pending;
	}

	sigdelset(&pending->signal, sync->info.si_signo);
	recalc_sigpending();
still_pending:
	list_del_init(&sync->list);
	copy_siginfo(info, &sync->info);
	__sigqueue_free(sync);
	return info->si_signo;
}

/*
 * Tell a process that it has a new active signal..
 *
 * NOTE! we rely on the previous spin_lock to
 * lock interrupts for us! We can only be called with
 * "siglock" held, and the local interrupt must
 * have been disabled when that got acquired!
 *
 * No need to set need_resched since signal event passing
 * goes through ->blocked
 */
void signal_wake_up_state(struct task_struct *t, unsigned int state)
{
	lockdep_assert_held(&t->sighand->siglock);

	set_tsk_thread_flag(t, TIF_SIGPENDING);

	/*
	 * TASK_WAKEKILL also means wake it up in the stopped/traced/killable
	 * case. We don't check t->state here because there is a race with it
	 * executing another processor and just now entering stopped state.
	 * By using wake_up_state, we ensure the process will wake up and
	 * handle its death signal.
	 */
	if (!wake_up_state(t, state | TASK_INTERRUPTIBLE))
		kick_process(t);
}

static inline void posixtimer_sig_ignore(struct task_struct *tsk, struct sigqueue *q);

static void sigqueue_free_ignored(struct task_struct *tsk, struct sigqueue *q)
{
	if (likely(!(q->flags & SIGQUEUE_PREALLOC) || q->info.si_code != SI_TIMER))
		__sigqueue_free(q);
	else
		posixtimer_sig_ignore(tsk, q);
}

/* Remove signals in mask from the pending set and queue. */
static void flush_sigqueue_mask(struct task_struct *p, sigset_t *mask, struct sigpending *s)
{
	struct sigqueue *q, *n;
	sigset_t m;

	lockdep_assert_held(&p->sighand->siglock);

	sigandsets(&m, mask, &s->signal);
	if (sigisemptyset(&m))
		return;

	sigandnsets(&s->signal, &s->signal, mask);
	list_for_each_entry_safe(q, n, &s->list, list) {
		if (sigismember(mask, q->info.si_signo)) {
			list_del_init(&q->list);
			sigqueue_free_ignored(p, q);
		}
	}
}

static inline int is_si_special(const struct kernel_siginfo *info)
{
	return info <= SEND_SIG_PRIV;
}

static inline bool si_fromuser(const struct kernel_siginfo *info)
{
	return info == SEND_SIG_NOINFO ||
		(!is_si_special(info) && SI_FROMUSER(info));
}

/*
 * called with RCU read lock from check_kill_permission()
 */
static bool kill_ok_by_cred(struct task_struct *t)
{
	const struct cred *cred = current_cred();
	const struct cred *tcred = __task_cred(t);

	return uid_eq(cred->euid, tcred->suid) ||
	       uid_eq(cred->euid, tcred->uid) ||
	       uid_eq(cred->uid, tcred->suid) ||
	       uid_eq(cred->uid, tcred->uid) ||
	       ns_capable(tcred->user_ns, CAP_KILL);
}

/*
 * Bad permissions for sending the signal
 * - the caller must hold the RCU read lock
 */
static int check_kill_permission(int sig, struct kernel_siginfo *info,
				 struct task_struct *t)
{
	struct pid *sid;
	int error;

	if (!valid_signal(sig))
		return -EINVAL;

	if (!si_fromuser(info))
		return 0;

	error = audit_signal_info(sig, t); /* Let audit system see the signal */
	if (error)
		return error;

	if (!same_thread_group(current, t) &&
	    !kill_ok_by_cred(t)) {
		switch (sig) {
		case SIGCONT:
			sid = task_session(t);
			/*
			 * We don't return the error if sid == NULL. The
			 * task was unhashed, the caller must notice this.
			 */
			if (!sid || sid == task_session(current))
				break;
			fallthrough;
		default:
			return -EPERM;
		}
	}

	return security_task_kill(t, info, sig, NULL);
}

/**
 * ptrace_trap_notify - schedule trap to notify ptracer
 * @t: tracee wanting to notify tracer
 *
 * This function schedules sticky ptrace trap which is cleared on the next
 * TRAP_STOP to notify ptracer of an event.  @t must have been seized by
 * ptracer.
 *
 * If @t is running, STOP trap will be taken.  If trapped for STOP and
 * ptracer is listening for events, tracee is woken up so that it can
 * re-trap for the new event.  If trapped otherwise, STOP trap will be
 * eventually taken without returning to userland after the existing traps
 * are finished by PTRACE_CONT.
 *
 * CONTEXT:
 * Must be called with @task->sighand->siglock held.
 */
static void ptrace_trap_notify(struct task_struct *t)
{
	WARN_ON_ONCE(!(t->ptrace & PT_SEIZED));
	lockdep_assert_held(&t->sighand->siglock);

	task_set_jobctl_pending(t, JOBCTL_TRAP_NOTIFY);
	ptrace_signal_wake_up(t, t->jobctl & JOBCTL_LISTENING);
}

/*
 * Handle magic process-wide effects of stop/continue signals. Unlike
 * the signal actions, these happen immediately at signal-generation
 * time regardless of blocking, ignoring, or handling.  This does the
 * actual continuing for SIGCONT, but not the actual stopping for stop
 * signals. The process stop is done as a signal action for SIG_DFL.
 *
 * Returns true if the signal should be actually delivered, otherwise
 * it should be dropped.
 */
static bool prepare_signal(int sig, struct task_struct *p, bool force)
{
	struct signal_struct *signal = p->signal;
	struct task_struct *t;
	sigset_t flush;

	if (signal->flags & SIGNAL_GROUP_EXIT) {
		if (signal->core_state)
			return sig == SIGKILL;
		/*
		 * The process is in the middle of dying, drop the signal.
		 */
		return false;
	} else if (sig_kernel_stop(sig)) {
		/*
		 * This is a stop signal.  Remove SIGCONT from all queues.
		 */
		siginitset(&flush, sigmask(SIGCONT));
		flush_sigqueue_mask(p, &flush, &signal->shared_pending);
		for_each_thread(p, t)
			flush_sigqueue_mask(p, &flush, &t->pending);
	} else if (sig == SIGCONT) {
		unsigned int why;
		/*
		 * Remove all stop signals from all queues, wake all threads.
		 */
		siginitset(&flush, SIG_KERNEL_STOP_MASK);
		flush_sigqueue_mask(p, &flush, &signal->shared_pending);
		for_each_thread(p, t) {
			flush_sigqueue_mask(p, &flush, &t->pending);
			task_clear_jobctl_pending(t, JOBCTL_STOP_PENDING);
			if (likely(!(t->ptrace & PT_SEIZED))) {
				t->jobctl &= ~JOBCTL_STOPPED;
				wake_up_state(t, __TASK_STOPPED);
			} else
				ptrace_trap_notify(t);
		}

		/*
		 * Notify the parent with CLD_CONTINUED if we were stopped.
		 *
		 * If we were in the middle of a group stop, we pretend it
		 * was already finished, and then continued. Since SIGCHLD
		 * doesn't queue we report only CLD_STOPPED, as if the next
		 * CLD_CONTINUED was dropped.
		 */
		why = 0;
		if (signal->flags & SIGNAL_STOP_STOPPED)
			why |= SIGNAL_CLD_CONTINUED;
		else if (signal->group_stop_count)
			why |= SIGNAL_CLD_STOPPED;

		if (why) {
			/*
			 * The first thread which returns from do_signal_stop()
			 * will take ->siglock, notice SIGNAL_CLD_MASK, and
			 * notify its parent. See get_signal().
			 */
			signal_set_stop_flags(signal, why | SIGNAL_STOP_CONTINUED);
			signal->group_stop_count = 0;
			signal->group_exit_code = 0;
		}
	}

	return !sig_ignored(p, sig, force);
}

/*
 * Test if P wants to take SIG.  After we've checked all threads with this,
 * it's equivalent to finding no threads not blocking SIG.  Any threads not
 * blocking SIG were ruled out because they are not running and already
 * have pending signals.  Such threads will dequeue from the shared queue
 * as soon as they're available, so putting the signal on the shared queue
 * will be equivalent to sending it to one such thread.
 */
static inline bool wants_signal(int sig, struct task_struct *p)
{
	if (sigismember(&p->blocked, sig))
		return false;

	if (p->flags & PF_EXITING)
		return false;

	if (sig == SIGKILL)
		return true;

	if (task_is_stopped_or_traced(p))
		return false;

	return task_curr(p) || !task_sigpending(p);
}

static void complete_signal(int sig, struct task_struct *p, enum pid_type type)
{
	struct signal_struct *signal = p->signal;
	struct task_struct *t;

	/*
	 * Now find a thread we can wake up to take the signal off the queue.
	 *
	 * Try the suggested task first (may or may not be the main thread).
	 */
	if (wants_signal(sig, p))
		t = p;
	else if ((type == PIDTYPE_PID) || thread_group_empty(p))
		/*
		 * There is just one thread and it does not need to be woken.
		 * It will dequeue unblocked signals before it runs again.
		 */
		return;
	else {
		/*
		 * Otherwise try to find a suitable thread.
		 */
		t = signal->curr_target;
		while (!wants_signal(sig, t)) {
			t = next_thread(t);
			if (t == signal->curr_target)
				/*
				 * No thread needs to be woken.
				 * Any eligible threads will see
				 * the signal in the queue soon.
				 */
				return;
		}
		signal->curr_target = t;
	}

	/*
	 * Found a killable thread.  If the signal will be fatal,
	 * then start taking the whole group down immediately.
	 */
	if (sig_fatal(p, sig) &&
	    (signal->core_state || !(signal->flags & SIGNAL_GROUP_EXIT)) &&
	    !sigismember(&t->real_blocked, sig) &&
	    (sig == SIGKILL || !p->ptrace)) {
		/*
		 * This signal will be fatal to the whole group.
		 */
		if (!sig_kernel_coredump(sig)) {
			/*
			 * Start a group exit and wake everybody up.
			 * This way we don't have other threads
			 * running and doing things after a slower
			 * thread has the fatal signal pending.
			 */
			signal->flags = SIGNAL_GROUP_EXIT;
			signal->group_exit_code = sig;
			signal->group_stop_count = 0;
			__for_each_thread(signal, t) {
				task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK);
				sigaddset(&t->pending.signal, SIGKILL);
				signal_wake_up(t, 1);
			}
			return;
		}
	}

	/*
	 * The signal is already in the shared-pending queue.
	 * Tell the chosen thread to wake up and dequeue it.
	 */
	signal_wake_up(t, sig == SIGKILL);
	return;
}

static inline bool legacy_queue(struct sigpending *signals, int sig)
{
	return (sig < SIGRTMIN) && sigismember(&signals->signal, sig);
}

static int __send_signal_locked(int sig, struct kernel_siginfo *info,
				struct task_struct *t, enum pid_type type, bool force)
{
	struct sigpending *pending;
	struct sigqueue *q;
	int override_rlimit;
	int ret = 0, result;

	lockdep_assert_held(&t->sighand->siglock);

	result = TRACE_SIGNAL_IGNORED;
	if (!prepare_signal(sig, t, force))
		goto ret;

	pending = (type != PIDTYPE_PID) ? &t->signal->shared_pending : &t->pending;
	/*
	 * Short-circuit ignored signals and support queuing
	 * exactly one non-rt signal, so that we can get more
	 * detailed information about the cause of the signal.
	 */
	result = TRACE_SIGNAL_ALREADY_PENDING;
	if (legacy_queue(pending, sig))
		goto ret;

	result = TRACE_SIGNAL_DELIVERED;
	/*
	 * Skip useless siginfo allocation for SIGKILL and kernel threads.
	 */
	if ((sig == SIGKILL) || (t->flags & PF_KTHREAD))
		goto out_set;

	/*
	 * Real-time signals must be queued if sent by sigqueue, or
	 * some other real-time mechanism.  It is implementation
	 * defined whether kill() does so.  We attempt to do so, on
	 * the principle of least surprise, but since kill is not
	 * allowed to fail with EAGAIN when low on memory we just
	 * make sure at least one signal gets delivered and don't
	 * pass on the info struct.
	 */
	if (sig < SIGRTMIN)
		override_rlimit = (is_si_special(info) || info->si_code >= 0);
	else
		override_rlimit = 0;

	q = sigqueue_alloc(sig, t, GFP_ATOMIC, override_rlimit);

	if (q) {
		list_add_tail(&q->list, &pending->list);
		switch ((unsigned long) info) {
		case (unsigned long) SEND_SIG_NOINFO:
			clear_siginfo(&q->info);
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_USER;
			q->info.si_pid = task_tgid_nr_ns(current,
							task_active_pid_ns(t));
			rcu_read_lock();
			q->info.si_uid =
				from_kuid_munged(task_cred_xxx(t, user_ns),
						 current_uid());
			rcu_read_unlock();
			break;
		case (unsigned long) SEND_SIG_PRIV:
			clear_siginfo(&q->info);
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_KERNEL;
			q->info.si_pid = 0;
			q->info.si_uid = 0;
			break;
		default:
			copy_siginfo(&q->info, info);
			break;
		}
	} else if (!is_si_special(info) &&
		   sig >= SIGRTMIN && info->si_code != SI_USER) {
		/*
		 * Queue overflow, abort.  We may abort if the
		 * signal was rt and sent by user using something
		 * other than kill().
		 */
		result = TRACE_SIGNAL_OVERFLOW_FAIL;
		ret = -EAGAIN;
		goto ret;
	} else {
		/*
		 * This is a silent loss of information.  We still
		 * send the signal, but the *info bits are lost.
		 */
		result = TRACE_SIGNAL_LOSE_INFO;
	}

out_set:
	signalfd_notify(t, sig);
	sigaddset(&pending->signal, sig);

	/* Let multiprocess signals appear after on-going forks */
	if (type > PIDTYPE_TGID) {
		struct multiprocess_signals *delayed;
		hlist_for_each_entry(delayed, &t->signal->multiprocess, node) {
			sigset_t *signal = &delayed->signal;
			/* Can't queue both a stop and a continue signal */
			if (sig == SIGCONT)
				sigdelsetmask(signal, SIG_KERNEL_STOP_MASK);
			else if (sig_kernel_stop(sig))
				sigdelset(signal, SIGCONT);
			sigaddset(signal, sig);
		}
	}

	complete_signal(sig, t, type);
ret:
	trace_signal_generate(sig, info, t, type != PIDTYPE_PID, result);
	return ret;
}

static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
{
	bool ret = false;
	switch (siginfo_layout(info->si_signo, info->si_code)) {
	case SIL_KILL:
	case SIL_CHLD:
	case SIL_RT:
		ret = true;
		break;
	case SIL_TIMER:
	case SIL_POLL:
	case SIL_FAULT:
	case SIL_FAULT_TRAPNO:
	case SIL_FAULT_MCEERR:
	case SIL_FAULT_BNDERR:
	case SIL_FAULT_PKUERR:
	case SIL_FAULT_PERF_EVENT:
	case SIL_SYS:
		ret = false;
		break;
	}
	return ret;
}

int send_signal_locked(int sig, struct kernel_siginfo *info,
		       struct task_struct *t, enum pid_type type)
{
	/* Should SIGKILL or SIGSTOP be received by a pid namespace init? */
	bool force = false;

	if (info == SEND_SIG_NOINFO) {
		/* Force if sent from an ancestor pid namespace */
		force = !task_pid_nr_ns(current, task_active_pid_ns(t));
	} else if (info == SEND_SIG_PRIV) {
		/* Don't ignore kernel generated signals */
		force = true;
	} else if (has_si_pid_and_uid(info)) {
		/* SIGKILL and SIGSTOP is special or has ids */
		struct user_namespace *t_user_ns;

		rcu_read_lock();
		t_user_ns = task_cred_xxx(t, user_ns);
		if (current_user_ns() != t_user_ns) {
			kuid_t uid = make_kuid(current_user_ns(), info->si_uid);
			info->si_uid = from_kuid_munged(t_user_ns, uid);
		}
		rcu_read_unlock();

		/* A kernel generated signal? */
		force = (info->si_code == SI_KERNEL);

		/* From an ancestor pid namespace? */
		if (!task_pid_nr_ns(current, task_active_pid_ns(t))) {
			info->si_pid = 0;
			force = true;
		}
	}
	return __send_signal_locked(sig, info, t, type, force);
}

static void print_fatal_signal(int signr)
{
	struct pt_regs *regs = task_pt_regs(current);
	struct file *exe_file;

	exe_file = get_task_exe_file(current);
	if (exe_file) {
		pr_info("%pD: %s: potentially unexpected fatal signal %d.\n",
			exe_file, current->comm, signr);
		fput(exe_file);
	} else {
		pr_info("%s: potentially unexpected fatal signal %d.\n",
			current->comm, signr);
	}

#if defined(__i386__) && !defined(__arch_um__)
	pr_info("code at %08lx: ", regs->ip);
	{
		int i;
		for (i = 0; i < 16; i++) {
			unsigned char insn;

			if (get_user(insn, (unsigned char *)(regs->ip + i)))
				break;
			pr_cont("%02x ", insn);
		}
	}
	pr_cont("\n");
#endif
	preempt_disable();
	show_regs(regs);
	preempt_enable();
}

static int __init setup_print_fatal_signals(char *str)
{
	get_option (&str, &print_fatal_signals);

	return 1;
}

__setup("print-fatal-signals=", setup_print_fatal_signals);

int do_send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p,
			enum pid_type type)
{
	unsigned long flags;
	int ret = -ESRCH;

	if (lock_task_sighand(p, &flags)) {
		ret = send_signal_locked(sig, info, p, type);
		unlock_task_sighand(p, &flags);
	}

	return ret;
}

enum sig_handler {
	HANDLER_CURRENT, /* If reachable use the current handler */
	HANDLER_SIG_DFL, /* Always use SIG_DFL handler semantics */
	HANDLER_EXIT,	 /* Only visible as the process exit code */
};

/*
 * Force a signal that the process can't ignore: if necessary
 * we unblock the signal and change any SIG_IGN to SIG_DFL.
 *
 * Note: If we unblock the signal, we always reset it to SIG_DFL,
 * since we do not want to have a signal handler that was blocked
 * be invoked when user space had explicitly blocked it.
 *
 * We don't want to have recursive SIGSEGV's etc, for example,
 * that is why we also clear SIGNAL_UNKILLABLE.
 */
static int
force_sig_info_to_task(struct kernel_siginfo *info, struct task_struct *t,
	enum sig_handler handler)
{
	unsigned long int flags;
	int ret, blocked, ignored;
	struct k_sigaction *action;
	int sig = info->si_signo;

	spin_lock_irqsave(&t->sighand->siglock, flags);
	action = &t->sighand->action[sig-1];
	ignored = action->sa.sa_handler == SIG_IGN;
	blocked = sigismember(&t->blocked, sig);
	if (blocked || ignored || (handler != HANDLER_CURRENT)) {
		action->sa.sa_handler = SIG_DFL;
		if (handler == HANDLER_EXIT)
			action->sa.sa_flags |= SA_IMMUTABLE;
		if (blocked)
			sigdelset(&t->blocked, sig);
	}
	/*
	 * Don't clear SIGNAL_UNKILLABLE for traced tasks, users won't expect
	 * debugging to leave init killable. But HANDLER_EXIT is always fatal.
	 */
	if (action->sa.sa_handler == SIG_DFL &&
	    (!t->ptrace || (handler == HANDLER_EXIT)))
		t->signal->flags &= ~SIGNAL_UNKILLABLE;
	ret = send_signal_locked(sig, info, t, PIDTYPE_PID);
	/* This can happen if the signal was already pending and blocked */
	if (!task_sigpending(t))
		signal_wake_up(t, 0);
	spin_unlock_irqrestore(&t->sighand->siglock, flags);

	return ret;
}

int force_sig_info(struct kernel_siginfo *info)
{
	return force_sig_info_to_task(info, current, HANDLER_CURRENT);
}

/*
 * Nuke all other threads in the group.
 */
int zap_other_threads(struct task_struct *p)
{
	struct task_struct *t;
	int count = 0;

	p->signal->group_stop_count = 0;

	for_other_threads(p, t) {
		task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK);
		count++;

		/* Don't bother with already dead threads */
		if (t->exit_state)
			continue;
		sigaddset(&t->pending.signal, SIGKILL);
		signal_wake_up(t, 1);
	}

	return count;
}

struct sighand_struct *__lock_task_sighand(struct task_struct *tsk,
					   unsigned long *flags)
{
	struct sighand_struct *sighand;

	rcu_read_lock();
	for (;;) {
		sighand = rcu_dereference(tsk->sighand);
		if (unlikely(sighand == NULL))
			break;

		/*
		 * This sighand can be already freed and even reused, but
		 * we rely on SLAB_TYPESAFE_BY_RCU and sighand_ctor() which
		 * initializes ->siglock: this slab can't go away, it has
		 * the same object type, ->siglock can't be reinitialized.
		 *
		 * We need to ensure that tsk->sighand is still the same
		 * after we take the lock, we can race with de_thread() or
		 * __exit_signal(). In the latter case the next iteration
		 * must see ->sighand == NULL.
		 */
		spin_lock_irqsave(&sighand->siglock, *flags);
		if (likely(sighand == rcu_access_pointer(tsk->sighand)))
			break;
		spin_unlock_irqrestore(&sighand->siglock, *flags);
	}
	rcu_read_unlock();

	return sighand;
}

#ifdef CONFIG_LOCKDEP
void lockdep_assert_task_sighand_held(struct task_struct *task)
{
	struct sighand_struct *sighand;

	rcu_read_lock();
	sighand = rcu_dereference(task->sighand);
	if (sighand)
		lockdep_assert_held(&sighand->siglock);
	else
		WARN_ON_ONCE(1);
	rcu_read_unlock();
}
#endif

/*
 * send signal info to all the members of a thread group or to the
 * individual thread if type == PIDTYPE_PID.
 */
int group_send_sig_info(int sig, struct kernel_siginfo *info,
			struct task_struct *p, enum pid_type type)
{
	int ret;

	rcu_read_lock();
	ret = check_kill_permission(sig, info, p);
	rcu_read_unlock();

	if (!ret && sig)
		ret = do_send_sig_info(sig, info, p, type);

	return ret;
}

/*
 * __kill_pgrp_info() sends a signal to a process group: this is what the tty
 * control characters do (^C, ^Z etc)
 * - the caller must hold at least a readlock on tasklist_lock
 */
int __kill_pgrp_info(int sig, struct kernel_siginfo *info, struct pid *pgrp)
{
	struct task_struct *p = NULL;
	int ret = -ESRCH;

	do_each_pid_task(pgrp, PIDTYPE_PGID, p) {
		int err = group_send_sig_info(sig, info, p, PIDTYPE_PGID);
		/*
		 * If group_send_sig_info() succeeds at least once ret
		 * becomes 0 and after that the code below has no effect.
		 * Otherwise we return the last err or -ESRCH if this
		 * process group is empty.
		 */
		if (ret)
			ret = err;
	} while_each_pid_task(pgrp, PIDTYPE_PGID, p);

	return ret;
}

static int kill_pid_info_type(int sig, struct kernel_siginfo *info,
				struct pid *pid, enum pid_type type)
{
	int error = -ESRCH;
	struct task_struct *p;

	for (;;) {
		rcu_read_lock();
		p = pid_task(pid, PIDTYPE_PID);
		if (p)
			error = group_send_sig_info(sig, info, p, type);
		rcu_read_unlock();
		if (likely(!p || error != -ESRCH))
			return error;
		/*
		 * The task was unhashed in between, try again.  If it
		 * is dead, pid_task() will return NULL, if we race with
		 * de_thread() it will find the new leader.
		 */
	}
}

int kill_pid_info(int sig, struct kernel_siginfo *info, struct pid *pid)
{
	return kill_pid_info_type(sig, info, pid, PIDTYPE_TGID);
}

static int kill_proc_info(int sig, struct kernel_siginfo *info, pid_t pid)
{
	int error;
	rcu_read_lock();
	error = kill_pid_info(sig, info, find_vpid(pid));
	rcu_read_unlock();
	return error;
}

static inline bool kill_as_cred_perm(const struct cred *cred,
				     struct task_struct *target)
{
	const struct cred *pcred = __task_cred(target);

	return uid_eq(cred->euid, pcred->suid) ||
	       uid_eq(cred->euid, pcred->uid) ||
	       uid_eq(cred->uid, pcred->suid) ||
	       uid_eq(cred->uid, pcred->uid);
}

/*
 * The usb asyncio usage of siginfo is wrong.  The glibc support
 * for asyncio which uses SI_ASYNCIO assumes the layout is SIL_RT.
 * AKA after the generic fields:
 *	kernel_pid_t	si_pid;
 *	kernel_uid32_t	si_uid;
 *	sigval_t	si_value;
 *
 * Unfortunately when usb generates SI_ASYNCIO it assumes the layout
 * after the generic fields is:
 *	void __user 	*si_addr;
 *
 * This is a practical problem when there is a 64bit big endian kernel
 * and a 32bit userspace.  As the 32bit address will encoded in the low
 * 32bits of the pointer.  Those low 32bits will be stored at higher
 * address than appear in a 32 bit pointer.  So userspace will not
 * see the address it was expecting for it's completions.
 *
 * There is nothing in the encoding that can allow
 * copy_siginfo_to_user32 to detect this confusion of formats, so
 * handle this by requiring the caller of kill_pid_usb_asyncio to
 * notice when this situration takes place and to store the 32bit
 * pointer in sival_int, instead of sival_addr of the sigval_t addr
 * parameter.
 */
int kill_pid_usb_asyncio(int sig, int errno, sigval_t addr,
			 struct pid *pid, const struct cred *cred)
{
	struct kernel_siginfo info;
	struct task_struct *p;
	unsigned long flags;
	int ret = -EINVAL;

	if (!valid_signal(sig))
		return ret;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = errno;
	info.si_code = SI_ASYNCIO;
	*((sigval_t *)&info.si_pid) = addr;

	rcu_read_lock();
	p = pid_task(pid, PIDTYPE_PID);
	if (!p) {
		ret = -ESRCH;
		goto out_unlock;
	}
	if (!kill_as_cred_perm(cred, p)) {
		ret = -EPERM;
		goto out_unlock;
	}
	ret = security_task_kill(p, &info, sig, cred);
	if (ret)
		goto out_unlock;

	if (sig) {
		if (lock_task_sighand(p, &flags)) {
			ret = __send_signal_locked(sig, &info, p, PIDTYPE_TGID, false);
			unlock_task_sighand(p, &flags);
		} else
			ret = -ESRCH;
	}
out_unlock:
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(kill_pid_usb_asyncio);

/*
 * kill_something_info() interprets pid in interesting ways just like kill(2).
 *
 * POSIX specifies that kill(-1,sig) is unspecified, but what we have
 * is probably wrong.  Should make it like BSD or SYSV.
 */

static int kill_something_info(int sig, struct kernel_siginfo *info, pid_t pid)
{
	int ret;

	if (pid > 0)
		return kill_proc_info(sig, info, pid);

	/* -INT_MIN is undefined.  Exclude this case to avoid a UBSAN warning */
	if (pid == INT_MIN)
		return -ESRCH;

	read_lock(&tasklist_lock);
	if (pid != -1) {
		ret = __kill_pgrp_info(sig, info,
				pid ? find_vpid(-pid) : task_pgrp(current));
	} else {
		int retval = 0, count = 0;
		struct task_struct * p;

		for_each_process(p) {
			if (task_pid_vnr(p) > 1 &&
					!same_thread_group(p, current)) {
				int err = group_send_sig_info(sig, info, p,
							      PIDTYPE_MAX);
				++count;
				if (err != -EPERM)
					retval = err;
			}
		}
		ret = count ? retval : -ESRCH;
	}
	read_unlock(&tasklist_lock);

	return ret;
}

/*
 * These are for backward compatibility with the rest of the kernel source.
 */

int send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p)
{
	/*
	 * Make sure legacy kernel users don't send in bad values
	 * (normal paths check this in check_kill_permission).
	 */
	if (!valid_signal(sig))
		return -EINVAL;

	return do_send_sig_info(sig, info, p, PIDTYPE_PID);
}
EXPORT_SYMBOL(send_sig_info);

#define __si_special(priv) \
	((priv) ? SEND_SIG_PRIV : SEND_SIG_NOINFO)

int
send_sig(int sig, struct task_struct *p, int priv)
{
	return send_sig_info(sig, __si_special(priv), p);
}
EXPORT_SYMBOL(send_sig);

void force_sig(int sig)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_KERNEL;
	info.si_pid = 0;
	info.si_uid = 0;
	force_sig_info(&info);
}
EXPORT_SYMBOL(force_sig);

void force_fatal_sig(int sig)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_KERNEL;
	info.si_pid = 0;
	info.si_uid = 0;
	force_sig_info_to_task(&info, current, HANDLER_SIG_DFL);
}

void force_exit_sig(int sig)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_KERNEL;
	info.si_pid = 0;
	info.si_uid = 0;
	force_sig_info_to_task(&info, current, HANDLER_EXIT);
}

/*
 * When things go south during signal handling, we
 * will force a SIGSEGV. And if the signal that caused
 * the problem was already a SIGSEGV, we'll want to
 * make sure we don't even try to deliver the signal..
 */
void force_sigsegv(int sig)
{
	if (sig == SIGSEGV)
		force_fatal_sig(SIGSEGV);
	else
		force_sig(SIGSEGV);
}

int force_sig_fault_to_task(int sig, int code, void __user *addr,
			    struct task_struct *t)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code  = code;
	info.si_addr  = addr;
	return force_sig_info_to_task(&info, t, HANDLER_CURRENT);
}

int force_sig_fault(int sig, int code, void __user *addr)
{
	return force_sig_fault_to_task(sig, code, addr, current);
}

int send_sig_fault(int sig, int code, void __user *addr, struct task_struct *t)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code  = code;
	info.si_addr  = addr;
	return send_sig_info(info.si_signo, &info, t);
}

int force_sig_mceerr(int code, void __user *addr, short lsb)
{
	struct kernel_siginfo info;

	WARN_ON((code != BUS_MCEERR_AO) && (code != BUS_MCEERR_AR));
	clear_siginfo(&info);
	info.si_signo = SIGBUS;
	info.si_errno = 0;
	info.si_code = code;
	info.si_addr = addr;
	info.si_addr_lsb = lsb;
	return force_sig_info(&info);
}

int send_sig_mceerr(int code, void __user *addr, short lsb, struct task_struct *t)
{
	struct kernel_siginfo info;

	WARN_ON((code != BUS_MCEERR_AO) && (code != BUS_MCEERR_AR));
	clear_siginfo(&info);
	info.si_signo = SIGBUS;
	info.si_errno = 0;
	info.si_code = code;
	info.si_addr = addr;
	info.si_addr_lsb = lsb;
	return send_sig_info(info.si_signo, &info, t);
}
EXPORT_SYMBOL(send_sig_mceerr);

int force_sig_bnderr(void __user *addr, void __user *lower, void __user *upper)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = SIGSEGV;
	info.si_errno = 0;
	info.si_code  = SEGV_BNDERR;
	info.si_addr  = addr;
	info.si_lower = lower;
	info.si_upper = upper;
	return force_sig_info(&info);
}

#ifdef SEGV_PKUERR
int force_sig_pkuerr(void __user *addr, u32 pkey)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = SIGSEGV;
	info.si_errno = 0;
	info.si_code  = SEGV_PKUERR;
	info.si_addr  = addr;
	info.si_pkey  = pkey;
	return force_sig_info(&info);
}
#endif

int send_sig_perf(void __user *addr, u32 type, u64 sig_data)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo     = SIGTRAP;
	info.si_errno     = 0;
	info.si_code      = TRAP_PERF;
	info.si_addr      = addr;
	info.si_perf_data = sig_data;
	info.si_perf_type = type;

	/*
	 * Signals generated by perf events should not terminate the whole
	 * process if SIGTRAP is blocked, however, delivering the signal
	 * asynchronously is better than not delivering at all. But tell user
	 * space if the signal was asynchronous, so it can clearly be
	 * distinguished from normal synchronous ones.
	 */
	info.si_perf_flags = sigismember(&current->blocked, info.si_signo) ?
				     TRAP_PERF_FLAG_ASYNC :
				     0;

	return send_sig_info(info.si_signo, &info, current);
}

/**
 * force_sig_seccomp - signals the task to allow in-process syscall emulation
 * @syscall: syscall number to send to userland
 * @reason: filter-supplied reason code to send to userland (via si_errno)
 * @force_coredump: true to trigger a coredump
 *
 * Forces a SIGSYS with a code of SYS_SECCOMP and related sigsys info.
 */
int force_sig_seccomp(int syscall, int reason, bool force_coredump)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = SIGSYS;
	info.si_code = SYS_SECCOMP;
	info.si_call_addr = (void __user *)KSTK_EIP(current);
	info.si_errno = reason;
	info.si_arch = syscall_get_arch(current);
	info.si_syscall = syscall;
	return force_sig_info_to_task(&info, current,
		force_coredump ? HANDLER_EXIT : HANDLER_CURRENT);
}

/* For the crazy architectures that include trap information in
 * the errno field, instead of an actual errno value.
 */
int force_sig_ptrace_errno_trap(int errno, void __user *addr)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = SIGTRAP;
	info.si_errno = errno;
	info.si_code  = TRAP_HWBKPT;
	info.si_addr  = addr;
	return force_sig_info(&info);
}

/* For the rare architectures that include trap information using
 * si_trapno.
 */
int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code  = code;
	info.si_addr  = addr;
	info.si_trapno = trapno;
	return force_sig_info(&info);
}

/* For the rare architectures that include trap information using
 * si_trapno.
 */
int send_sig_fault_trapno(int sig, int code, void __user *addr, int trapno,
			  struct task_struct *t)
{
	struct kernel_siginfo info;

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code  = code;
	info.si_addr  = addr;
	info.si_trapno = trapno;
	return send_sig_info(info.si_signo, &info, t);
}

static int kill_pgrp_info(int sig, struct kernel_siginfo *info, struct pid *pgrp)
{
	int ret;
	read_lock(&tasklist_lock);
	ret = __kill_pgrp_info(sig, info, pgrp);
	read_unlock(&tasklist_lock);
	return ret;
}

int kill_pgrp(struct pid *pid, int sig, int priv)
{
	return kill_pgrp_info(sig, __si_special(priv), pid);
}
EXPORT_SYMBOL(kill_pgrp);

int kill_pid(struct pid *pid, int sig, int priv)
{
	return kill_pid_info(sig, __si_special(priv), pid);
}
EXPORT_SYMBOL(kill_pid);

#ifdef CONFIG_POSIX_TIMERS
/*
 * These functions handle POSIX timer signals. POSIX timers use
 * preallocated sigqueue structs for sending signals.
 */
static void __flush_itimer_signals(struct sigpending *pending)
{
	sigset_t signal, retain;
	struct sigqueue *q, *n;

	signal = pending->signal;
	sigemptyset(&retain);

	list_for_each_entry_safe(q, n, &pending->list, list) {
		int sig = q->info.si_signo;

		if (likely(q->info.si_code != SI_TIMER)) {
			sigaddset(&retain, sig);
		} else {
			sigdelset(&signal, sig);
			list_del_init(&q->list);
			__sigqueue_free(q);
		}
	}

	sigorsets(&pending->signal, &signal, &retain);
}

void flush_itimer_signals(void)
{
	struct task_struct *tsk = current;

	guard(spinlock_irqsave)(&tsk->sighand->siglock);
	__flush_itimer_signals(&tsk->pending);
	__flush_itimer_signals(&tsk->signal->shared_pending);
}

bool posixtimer_init_sigqueue(struct sigqueue *q)
{
	struct ucounts *ucounts = sig_get_ucounts(current, -1, 0);

	if (!ucounts)
		return false;
	clear_siginfo(&q->info);
	__sigqueue_init(q, ucounts, SIGQUEUE_PREALLOC);
	return true;
}

static void posixtimer_queue_sigqueue(struct sigqueue *q, struct task_struct *t, enum pid_type type)
{
	struct sigpending *pending;
	int sig = q->info.si_signo;

	signalfd_notify(t, sig);
	pending = (type != PIDTYPE_PID) ? &t->signal->shared_pending : &t->pending;
	list_add_tail(&q->list, &pending->list);
	sigaddset(&pending->signal, sig);
	complete_signal(sig, t, type);
}

/*
 * This function is used by POSIX timers to deliver a timer signal.
 * Where type is PIDTYPE_PID (such as for timers with SIGEV_THREAD_ID
 * set), the signal must be delivered to the specific thread (queues
 * into t->pending).
 *
 * Where type is not PIDTYPE_PID, signals must be delivered to the
 * process. In this case, prefer to deliver to current if it is in
 * the same thread group as the target process and its sighand is
 * stable, which avoids unnecessarily waking up a potentially idle task.
 */
static inline struct task_struct *posixtimer_get_target(struct k_itimer *tmr)
{
	struct task_struct *t = pid_task(tmr->it_pid, tmr->it_pid_type);

	if (t && tmr->it_pid_type != PIDTYPE_PID &&
	    same_thread_group(t, current) && !current->exit_state)
		t = current;
	return t;
}

void posixtimer_send_sigqueue(struct k_itimer *tmr)
{
	struct sigqueue *q = &tmr->sigq;
	int sig = q->info.si_signo;
	struct task_struct *t;
	unsigned long flags;
	int result;

	guard(rcu)();

	t = posixtimer_get_target(tmr);
	if (!t)
		return;

	if (!likely(lock_task_sighand(t, &flags)))
		return;

	/*
	 * Update @tmr::sigqueue_seq for posix timer signals with sighand
	 * locked to prevent a race against dequeue_signal().
	 */
	tmr->it_sigqueue_seq = tmr->it_signal_seq;

	/*
	 * Set the signal delivery status under sighand lock, so that the
	 * ignored signal handling can distinguish between a periodic and a
	 * non-periodic timer.
	 */
	tmr->it_sig_periodic = tmr->it_status == POSIX_TIMER_REQUEUE_PENDING;

	if (!prepare_signal(sig, t, false)) {
		result = TRACE_SIGNAL_IGNORED;

		if (!list_empty(&q->list)) {
			/*
			 * The signal was ignored and blocked. The timer
			 * expiry queued it because blocked signals are
			 * queued independent of the ignored state.
			 *
			 * The unblocking set SIGPENDING, but the signal
			 * was not yet dequeued from the pending list.
			 * So prepare_signal() sees unblocked and ignored,
			 * which ends up here. Leave it queued like a
			 * regular signal.
			 *
			 * The same happens when the task group is exiting
			 * and the signal is already queued.
			 * prepare_signal() treats SIGNAL_GROUP_EXIT as
			 * ignored independent of its queued state. This
			 * gets cleaned up in __exit_signal().
			 */
			goto out;
		}

		/* Periodic timers with SIG_IGN are queued on the ignored list */
		if (tmr->it_sig_periodic) {
			/*
			 * Already queued means the timer was rearmed after
			 * the previous expiry got it on the ignore list.
			 * Nothing to do for that case.
			 */
			if (hlist_unhashed(&tmr->ignored_list)) {
				/*
				 * Take a signal reference and queue it on
				 * the ignored list.
				 */
				posixtimer_sigqueue_getref(q);
				posixtimer_sig_ignore(t, q);
			}
		} else if (!hlist_unhashed(&tmr->ignored_list)) {
			/*
			 * Covers the case where a timer was periodic and
			 * then the signal was ignored. Later it was rearmed
			 * as oneshot timer. The previous signal is invalid
			 * now, and this oneshot signal has to be dropped.
			 * Remove it from the ignored list and drop the
			 * reference count as the signal is not longer
			 * queued.
			 */
			hlist_del_init(&tmr->ignored_list);
			posixtimer_putref(tmr);
		}
		goto out;
	}

	if (unlikely(!list_empty(&q->list))) {
		/* This holds a reference count already */
		result = TRACE_SIGNAL_ALREADY_PENDING;
		goto out;
	}

	/*
	 * If the signal is on the ignore list, it got blocked after it was
	 * ignored earlier. But nothing lifted the ignore. Move it back to
	 * the pending list to be consistent with the regular signal
	 * handling. This already holds a reference count.
	 *
	 * If it's not on the ignore list acquire a reference count.
	 */
	if (likely(hlist_unhashed(&tmr->ignored_list)))
		posixtimer_sigqueue_getref(q);
	else
		hlist_del_init(&tmr->ignored_list);

	posixtimer_queue_sigqueue(q, t, tmr->it_pid_type);
	result = TRACE_SIGNAL_DELIVERED;
out:
	trace_signal_generate(sig, &q->info, t, tmr->it_pid_type != PIDTYPE_PID, result);
	unlock_task_sighand(t, &flags);
}

static inline void posixtimer_sig_ignore(struct task_struct *tsk, struct sigqueue *q)
{
	struct k_itimer *tmr = container_of(q, struct k_itimer, sigq);

	/*
	 * If the timer is marked deleted already or the signal originates
	 * from a non-periodic timer, then just drop the reference
	 * count. Otherwise queue it on the ignored list.
	 */
	if (posixtimer_valid(tmr) && tmr->it_sig_periodic)
		hlist_add_head(&tmr->ignored_list, &tsk->signal->ignored_posix_timers);
	else
		posixtimer_putref(tmr);
}

static void posixtimer_sig_unignore(struct task_struct *tsk, int sig)
{
	struct hlist_head *head = &tsk->signal->ignored_posix_timers;
	struct hlist_node *tmp;
	struct k_itimer *tmr;

	if (likely(hlist_empty(head)))
		return;

	/*
	 * Rearming a timer with sighand lock held is not possible due to
	 * lock ordering vs. tmr::it_lock. Just stick the sigqueue back and
	 * let the signal delivery path deal with it whether it needs to be
	 * rearmed or not. This cannot be decided here w/o dropping sighand
	 * lock and creating a loop retry horror show.
	 */
	hlist_for_each_entry_safe(tmr, tmp , head, ignored_list) {
		struct task_struct *target;

		/*
		 * tmr::sigq.info.si_signo is immutable, so accessing it
		 * without holding tmr::it_lock is safe.
		 */
		if (tmr->sigq.info.si_signo != sig)
			continue;

		hlist_del_init(&tmr->ignored_list);

		/* This should never happen and leaks a reference count */
		if (WARN_ON_ONCE(!list_empty(&tmr->sigq.list)))
			continue;

		/*
		 * Get the target for the signal. If target is a thread and
		 * has exited by now, drop the reference count.
		 */
		guard(rcu)();
		target = posixtimer_get_target(tmr);
		if (target)
			posixtimer_queue_sigqueue(&tmr->sigq, target, tmr->it_pid_type);
		else
			posixtimer_putref(tmr);
	}
}
#else /* CONFIG_POSIX_TIMERS */
static inline void posixtimer_sig_ignore(struct task_struct *tsk, struct sigqueue *q) { }
static inline void posixtimer_sig_unignore(struct task_struct *tsk, int sig) { }
#endif /* !CONFIG_POSIX_TIMERS */

void do_notify_pidfd(struct task_struct *task)
{
	struct pid *pid = task_pid(task);

	WARN_ON(task->exit_state == 0);

	__wake_up(&pid->wait_pidfd, TASK_NORMAL, 0,
			poll_to_key(EPOLLIN | EPOLLRDNORM));
}

/*
 * Let a parent know about the death of a child.
 * For a stopped/continued status change, use do_notify_parent_cldstop instead.
 *
 * Returns true if our parent ignored us and so we've switched to
 * self-reaping.
 */
bool do_notify_parent(struct task_struct *tsk, int sig)
{
	struct kernel_siginfo info;
	unsigned long flags;
	struct sighand_struct *psig;
	bool autoreap = false;
	u64 utime, stime;

	WARN_ON_ONCE(sig == -1);

	/* do_notify_parent_cldstop should have been called instead.  */
	WARN_ON_ONCE(task_is_stopped_or_traced(tsk));

	WARN_ON_ONCE(!tsk->ptrace &&
	       (tsk->group_leader != tsk || !thread_group_empty(tsk)));

	/* ptraced, or group-leader without sub-threads */
	do_notify_pidfd(tsk);

	if (sig != SIGCHLD) {
		/*
		 * This is only possible if parent == real_parent.
		 * Check if it has changed security domain.
		 */
		if (tsk->parent_exec_id != READ_ONCE(tsk->parent->self_exec_id))
			sig = SIGCHLD;
	}

	clear_siginfo(&info);
	info.si_signo = sig;
	info.si_errno = 0;
	/*
	 * We are under tasklist_lock here so our parent is tied to
	 * us and cannot change.
	 *
	 * task_active_pid_ns will always return the same pid namespace
	 * until a task passes through release_task.
	 *
	 * write_lock() currently calls preempt_disable() which is the
	 * same as rcu_read_lock(), but according to Oleg, this is not
	 * correct to rely on this
	 */
	rcu_read_lock();
	info.si_pid = task_pid_nr_ns(tsk, task_active_pid_ns(tsk->parent));
	info.si_uid = from_kuid_munged(task_cred_xxx(tsk->parent, user_ns),
				       task_uid(tsk));
	rcu_read_unlock();

	task_cputime(tsk, &utime, &stime);
	info.si_utime = nsec_to_clock_t(utime + tsk->signal->utime);
	info.si_stime = nsec_to_clock_t(stime + tsk->signal->stime);

	info.si_status = tsk->exit_code & 0x7f;
	if (tsk->exit_code & 0x80)
		info.si_code = CLD_DUMPED;
	else if (tsk->exit_code & 0x7f)
		info.si_code = CLD_KILLED;
	else {
		info.si_code = CLD_EXITED;
		info.si_status = tsk->exit_code >> 8;
	}

	psig = tsk->parent->sighand;
	spin_lock_irqsave(&psig->siglock, flags);
	if (!tsk->ptrace && sig == SIGCHLD &&
	    (psig->action[SIGCHLD-1].sa.sa_handler == SIG_IGN ||
	     (psig->action[SIGCHLD-1].sa.sa_flags & SA_NOCLDWAIT))) {
		/*
		 * We are exiting and our parent doesn't care.  POSIX.1
		 * defines special semantics for setting SIGCHLD to SIG_IGN
		 * or setting the SA_NOCLDWAIT flag: we should be reaped
		 * automatically and not left for our parent's wait4 call.
		 * Rather than having the parent do it as a magic kind of
		 * signal handler, we just set this to tell do_exit that we
		 * can be cleaned up without becoming a zombie.  Note that
		 * we still call __wake_up_parent in this case, because a
		 * blocked sys_wait4 might now return -ECHILD.
		 *
		 * Whether we send SIGCHLD or not for SA_NOCLDWAIT
		 * is implementation-defined: we do (if you don't want
		 * it, just use SIG_IGN instead).
		 */
		autoreap = true;
		if (psig->action[SIGCHLD-1].sa.sa_handler == SIG_IGN)
			sig = 0;
	}
	/*
	 * Send with __send_signal as si_pid and si_uid are in the
	 * parent's namespaces.
	 */
	if (valid_signal(sig) && sig)
		__send_signal_locked(sig, &info, tsk->parent, PIDTYPE_TGID, false);
	__wake_up_parent(tsk, tsk->parent);
	spin_unlock_irqrestore(&psig->siglock, flags);

	return autoreap;
}

/**
 * do_notify_parent_cldstop - notify parent of stopped/continued state change
 * @tsk: task reporting the state change
 * @for_ptracer: the notification is for ptracer
 * @why: CLD_{CONTINUED|STOPPED|TRAPPED} to report
 *
 * Notify @tsk's parent that the stopped/continued state has changed.  If
 * @for_ptracer is %false, @tsk's group leader notifies to its real parent.
 * If %true, @tsk reports to @tsk->parent which should be the ptracer.
 *
 * CONTEXT:
 * Must be called with tasklist_lock at least read locked.
 */
static void do_notify_parent_cldstop(struct task_struct *tsk,
				     bool for_ptracer, int why)
{
	struct kernel_siginfo info;
	unsigned long flags;
	struct task_struct *parent;
	struct sighand_struct *sighand;
	u64 utime, stime;

	if (for_ptracer) {
		parent = tsk->parent;
	} else {
		tsk = tsk->group_leader;
		parent = tsk->real_parent;
	}

	clear_siginfo(&info);
	info.si_signo = SIGCHLD;
	info.si_errno = 0;
	/*
	 * see comment in do_notify_parent() about the following 4 lines
	 */
	rcu_read_lock();
	info.si_pid = task_pid_nr_ns(tsk, task_active_pid_ns(parent));
	info.si_uid = from_kuid_munged(task_cred_xxx(parent, user_ns), task_uid(tsk));
	rcu_read_unlock();

	task_cputime(tsk, &utime, &stime);
	info.si_utime = nsec_to_clock_t(utime);
	info.si_stime = nsec_to_clock_t(stime);

 	info.si_code = why;
 	switch (why) {
 	case CLD_CONTINUED:
 		info.si_status = SIGCONT;
 		break;
 	case CLD_STOPPED:
 		info.si_status = tsk->signal->group_exit_code & 0x7f;
 		break;
 	case CLD_TRAPPED:
 		info.si_status = tsk->exit_code & 0x7f;
 		break;
 	default:
 		BUG();
 	}

	sighand = parent->sighand;
	spin_lock_irqsave(&sighand->siglock, flags);
	if (sighand->action[SIGCHLD-1].sa.sa_handler != SIG_IGN &&
	    !(sighand->action[SIGCHLD-1].sa.sa_flags & SA_NOCLDSTOP))
		send_signal_locked(SIGCHLD, &info, parent, PIDTYPE_TGID);
	/*
	 * Even if SIGCHLD is not generated, we must wake up wait4 calls.
	 */
	__wake_up_parent(tsk, parent);
	spin_unlock_irqrestore(&sighand->siglock, flags);
}

/*
 * This must be called with current->sighand->siglock held.
 *
 * This should be the path for all ptrace stops.
 * We always set current->last_siginfo while stopped here.
 * That makes it a way to test a stopped process for
 * being ptrace-stopped vs being job-control-stopped.
 *
 * Returns the signal the ptracer requested the code resume
 * with.  If the code did not stop because the tracer is gone,
 * the stop signal remains unchanged unless clear_code.
 */
static int ptrace_stop(int exit_code, int why, unsigned long message,
		       kernel_siginfo_t *info)
	__releases(&current->sighand->siglock)
	__acquires(&current->sighand->siglock)
{
	bool gstop_done = false;

	if (arch_ptrace_stop_needed()) {
		/*
		 * The arch code has something special to do before a
		 * ptrace stop.  This is allowed to block, e.g. for faults
		 * on user stack pages.  We can't keep the siglock while
		 * calling arch_ptrace_stop, so we must release it now.
		 * To preserve proper semantics, we must do this before
		 * any signal bookkeeping like checking group_stop_count.
		 */
		spin_unlock_irq(&current->sighand->siglock);
		arch_ptrace_stop();
		spin_lock_irq(&current->sighand->siglock);
	}

	/*
	 * After this point ptrace_signal_wake_up or signal_wake_up
	 * will clear TASK_TRACED if ptrace_unlink happens or a fatal
	 * signal comes in.  Handle previous ptrace_unlinks and fatal
	 * signals here to prevent ptrace_stop sleeping in schedule.
	 */
	if (!current->ptrace || __fatal_signal_pending(current))
		return exit_code;

	set_special_state(TASK_TRACED);
	current->jobctl |= JOBCTL_TRACED;

	/*
	 * We're committing to trapping.  TRACED should be visible before
	 * TRAPPING is cleared; otherwise, the tracer might fail do_wait().
	 * Also, transition to TRACED and updates to ->jobctl should be
	 * atomic with respect to siglock and should be done after the arch
	 * hook as siglock is released and regrabbed across it.
	 *
	 *     TRACER				    TRACEE
	 *
	 *     ptrace_attach()
	 * [L]   wait_on_bit(JOBCTL_TRAPPING)	[S] set_special_state(TRACED)
	 *     do_wait()
	 *       set_current_state()                smp_wmb();
	 *       ptrace_do_wait()
	 *         wait_task_stopped()
	 *           task_stopped_code()
	 * [L]         task_is_traced()		[S] task_clear_jobctl_trapping();
	 */
	smp_wmb();

	current->ptrace_message = message;
	current->last_siginfo = info;
	current->exit_code = exit_code;

	/*
	 * If @why is CLD_STOPPED, we're trapping to participate in a group
	 * stop.  Do the bookkeeping.  Note that if SIGCONT was delievered
	 * across siglock relocks since INTERRUPT was scheduled, PENDING
	 * could be clear now.  We act as if SIGCONT is received after
	 * TASK_TRACED is entered - ignore it.
	 */
	if (why == CLD_STOPPED && (current->jobctl & JOBCTL_STOP_PENDING))
		gstop_done = task_participate_group_stop(current);

	/* any trap clears pending STOP trap, STOP trap clears NOTIFY */
	task_clear_jobctl_pending(current, JOBCTL_TRAP_STOP);
	if (info && info->si_code >> 8 == PTRACE_EVENT_STOP)
		task_clear_jobctl_pending(current, JOBCTL_TRAP_NOTIFY);

	/* entering a trap, clear TRAPPING */
	task_clear_jobctl_trapping(current);

	spin_unlock_irq(&current->sighand->siglock);
	read_lock(&tasklist_lock);
	/*
	 * Notify parents of the stop.
	 *
	 * While ptraced, there are two parents - the ptracer and
	 * the real_parent of the group_leader.  The ptracer should
	 * know about every stop while the real parent is only
	 * interested in the completion of group stop.  The states
	 * for the two don't interact with each other.  Notify
	 * separately unless they're gonna be duplicates.
	 */
	if (current->ptrace)
		do_notify_parent_cldstop(current, true, why);
	if (gstop_done && (!current->ptrace || ptrace_reparented(current)))
		do_notify_parent_cldstop(current, false, why);

	/*
	 * The previous do_notify_parent_cldstop() invocation woke ptracer.
	 * One a PREEMPTION kernel this can result in preemption requirement
	 * which will be fulfilled after read_unlock() and the ptracer will be
	 * put on the CPU.
	 * The ptracer is in wait_task_inactive(, __TASK_TRACED) waiting for
	 * this task wait in schedule(). If this task gets preempted then it
	 * remains enqueued on the runqueue. The ptracer will observe this and
	 * then sleep for a delay of one HZ tick. In the meantime this task
	 * gets scheduled, enters schedule() and will wait for the ptracer.
	 *
	 * This preemption point is not bad from a correctness point of
	 * view but extends the runtime by one HZ tick time due to the
	 * ptracer's sleep.  The preempt-disable section ensures that there
	 * will be no preemption between unlock and schedule() and so
	 * improving the performance since the ptracer will observe that
	 * the tracee is scheduled out once it gets on the CPU.
	 *
	 * On PREEMPT_RT locking tasklist_lock does not disable preemption.
	 * Therefore the task can be preempted after do_notify_parent_cldstop()
	 * before unlocking tasklist_lock so there is no benefit in doing this.
	 *
	 * In fact disabling preemption is harmful on PREEMPT_RT because
	 * the spinlock_t in cgroup_enter_frozen() must not be acquired
	 * with preemption disabled due to the 'sleeping' spinlock
	 * substitution of RT.
	 */
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))
		preempt_disable();
	read_unlock(&tasklist_lock);
	cgroup_enter_frozen();
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))
		preempt_enable_no_resched();
	schedule();
	cgroup_leave_frozen(true);

	/*
	 * We are back.  Now reacquire the siglock before touching
	 * last_siginfo, so that we are sure to have synchronized with
	 * any signal-sending on another CPU that wants to examine it.
	 */
	spin_lock_irq(&current->sighand->siglock);
	exit_code = current->exit_code;
	current->last_siginfo = NULL;
	current->ptrace_message = 0;
	current->exit_code = 0;

	/* LISTENING can be set only during STOP traps, clear it */
	current->jobctl &= ~(JOBCTL_LISTENING | JOBCTL_PTRACE_FROZEN);

	/*
	 * Queued signals ignored us while we were stopped for tracing.
	 * So check for any that we should take before resuming user mode.
	 * This sets TIF_SIGPENDING, but never clears it.
	 */
	recalc_sigpending_tsk(current);
	return exit_code;
}

static int ptrace_do_notify(int signr, int exit_code, int why, unsigned long message)
{
	kernel_siginfo_t info;

	clear_siginfo(&info);
	info.si_signo = signr;
	info.si_code = exit_code;
	info.si_pid = task_pid_vnr(current);
	info.si_uid = from_kuid_munged(current_user_ns(), current_uid());

	/* Let the debugger run.  */
	return ptrace_stop(exit_code, why, message, &info);
}

int ptrace_notify(int exit_code, unsigned long message)
{
	int signr;

	BUG_ON((exit_code & (0x7f | ~0xffff)) != SIGTRAP);
	if (unlikely(task_work_pending(current)))
		task_work_run();

	spin_lock_irq(&current->sighand->siglock);
	signr = ptrace_do_notify(SIGTRAP, exit_code, CLD_TRAPPED, message);
	spin_unlock_irq(&current->sighand->siglock);
	return signr;
}

/**
 * do_signal_stop - handle group stop for SIGSTOP and other stop signals
 * @signr: signr causing group stop if initiating
 *
 * If %JOBCTL_STOP_PENDING is not set yet, initiate group stop with @signr
 * and participate in it.  If already set, participate in the existing
 * group stop.  If participated in a group stop (and thus slept), %true is
 * returned with siglock released.
 *
 * If ptraced, this function doesn't handle stop itself.  Instead,
 * %JOBCTL_TRAP_STOP is scheduled and %false is returned with siglock
 * untouched.  The caller must ensure that INTERRUPT trap handling takes
 * places afterwards.
 *
 * CONTEXT:
 * Must be called with @current->sighand->siglock held, which is released
 * on %true return.
 *
 * RETURNS:
 * %false if group stop is already cancelled or ptrace trap is scheduled.
 * %true if participated in group stop.
 */
static bool do_signal_stop(int signr)
	__releases(&current->sighand->siglock)
{
	struct signal_struct *sig = current->signal;

	if (!(current->jobctl & JOBCTL_STOP_PENDING)) {
		unsigned long gstop = JOBCTL_STOP_PENDING | JOBCTL_STOP_CONSUME;
		struct task_struct *t;

		/* signr will be recorded in task->jobctl for retries */
		WARN_ON_ONCE(signr & ~JOBCTL_STOP_SIGMASK);

		if (!likely(current->jobctl & JOBCTL_STOP_DEQUEUED) ||
		    unlikely(sig->flags & SIGNAL_GROUP_EXIT) ||
		    unlikely(sig->group_exec_task))
			return false;
		/*
		 * There is no group stop already in progress.  We must
		 * initiate one now.
		 *
		 * While ptraced, a task may be resumed while group stop is
		 * still in effect and then receive a stop signal and
		 * initiate another group stop.  This deviates from the
		 * usual behavior as two consecutive stop signals can't
		 * cause two group stops when !ptraced.  That is why we
		 * also check !task_is_stopped(t) below.
		 *
		 * The condition can be distinguished by testing whether
		 * SIGNAL_STOP_STOPPED is already set.  Don't generate
		 * group_exit_code in such case.
		 *
		 * This is not necessary for SIGNAL_STOP_CONTINUED because
		 * an intervening stop signal is required to cause two
		 * continued events regardless of ptrace.
		 */
		if (!(sig->flags & SIGNAL_STOP_STOPPED))
			sig->group_exit_code = signr;

		sig->group_stop_count = 0;
		if (task_set_jobctl_pending(current, signr | gstop))
			sig->group_stop_count++;

		for_other_threads(current, t) {
			/*
			 * Setting state to TASK_STOPPED for a group
			 * stop is always done with the siglock held,
			 * so this check has no races.
			 */
			if (!task_is_stopped(t) &&
			    task_set_jobctl_pending(t, signr | gstop)) {
				sig->group_stop_count++;
				if (likely(!(t->ptrace & PT_SEIZED)))
					signal_wake_up(t, 0);
				else
					ptrace_trap_notify(t);
			}
		}
	}

	if (likely(!current->ptrace)) {
		int notify = 0;

		/*
		 * If there are no other threads in the group, or if there
		 * is a group stop in progress and we are the last to stop,
		 * report to the parent.
		 */
		if (task_participate_group_stop(current))
			notify = CLD_STOPPED;

		current->jobctl |= JOBCTL_STOPPED;
		set_special_state(TASK_STOPPED);
		spin_unlock_irq(&current->sighand->siglock);

		/*
		 * Notify the parent of the group stop completion.  Because
		 * we're not holding either the siglock or tasklist_lock
		 * here, ptracer may attach inbetween; however, this is for
		 * group stop and should always be delivered to the real
		 * parent of the group leader.  The new ptracer will get
		 * its notification when this task transitions into
		 * TASK_TRACED.
		 */
		if (notify) {
			read_lock(&tasklist_lock);
			do_notify_parent_cldstop(current, false, notify);
			read_unlock(&tasklist_lock);
		}

		/* Now we don't run again until woken by SIGCONT or SIGKILL */
		cgroup_enter_frozen();
		schedule();
		return true;
	} else {
		/*
		 * While ptraced, group stop is handled by STOP trap.
		 * Schedule it and let the caller deal with it.
		 */
		task_set_jobctl_pending(current, JOBCTL_TRAP_STOP);
		return false;
	}
}

/**
 * do_jobctl_trap - take care of ptrace jobctl traps
 *
 * When PT_SEIZED, it's used for both group stop and explicit
 * SEIZE/INTERRUPT traps.  Both generate PTRACE_EVENT_STOP trap with
 * accompanying siginfo.  If stopped, lower eight bits of exit_code contain
 * the stop signal; otherwise, %SIGTRAP.
 *
 * When !PT_SEIZED, it's used only for group stop trap with stop signal
 * number as exit_code and no siginfo.
 *
 * CONTEXT:
 * Must be called with @current->sighand->siglock held, which may be
 * released and re-acquired before returning with intervening sleep.
 */
static void do_jobctl_trap(void)
{
	struct signal_struct *signal = current->signal;
	int signr = current->jobctl & JOBCTL_STOP_SIGMASK;

	if (current->ptrace & PT_SEIZED) {
		if (!signal->group_stop_count &&
		    !(signal->flags & SIGNAL_STOP_STOPPED))
			signr = SIGTRAP;
		WARN_ON_ONCE(!signr);
		ptrace_do_notify(signr, signr | (PTRACE_EVENT_STOP << 8),
				 CLD_STOPPED, 0);
	} else {
		WARN_ON_ONCE(!signr);
		ptrace_stop(signr, CLD_STOPPED, 0, NULL);
	}
}

/**
 * do_freezer_trap - handle the freezer jobctl trap
 *
 * Puts the task into frozen state, if only the task is not about to quit.
 * In this case it drops JOBCTL_TRAP_FREEZE.
 *
 * CONTEXT:
 * Must be called with @current->sighand->siglock held,
 * which is always released before returning.
 */
static void do_freezer_trap(void)
	__releases(&current->sighand->siglock)
{
	/*
	 * If there are other trap bits pending except JOBCTL_TRAP_FREEZE,
	 * let's make another loop to give it a chance to be handled.
	 * In any case, we'll return back.
	 */
	if ((current->jobctl & (JOBCTL_PENDING_MASK | JOBCTL_TRAP_FREEZE)) !=
	     JOBCTL_TRAP_FREEZE) {
		spin_unlock_irq(&current->sighand->siglock);
		return;
	}

	/*
	 * Now we're sure that there is no pending fatal signal and no
	 * pending traps. Clear TIF_SIGPENDING to not get out of schedule()
	 * immediately (if there is a non-fatal signal pending), and
	 * put the task into sleep.
	 */
	__set_current_state(TASK_INTERRUPTIBLE|TASK_FREEZABLE);
	clear_thread_flag(TIF_SIGPENDING);
	spin_unlock_irq(&current->sighand->siglock);
	cgroup_enter_frozen();
	schedule();

	/*
	 * We could've been woken by task_work, run it to clear
	 * TIF_NOTIFY_SIGNAL. The caller will retry if necessary.
	 */
	clear_notify_signal();
	if (unlikely(task_work_pending(current)))
		task_work_run();
}

static int ptrace_signal(int signr, kernel_siginfo_t *info, enum pid_type type)
{
	/*
	 * We do not check sig_kernel_stop(signr) but set this marker
	 * unconditionally because we do not know whether debugger will
	 * change signr. This flag has no meaning unless we are going
	 * to stop after return from ptrace_stop(). In this case it will
	 * be checked in do_signal_stop(), we should only stop if it was
	 * not cleared by SIGCONT while we were sleeping. See also the
	 * comment in dequeue_signal().
	 */
	current->jobctl |= JOBCTL_STOP_DEQUEUED;
	signr = ptrace_stop(signr, CLD_TRAPPED, 0, info);

	/* We're back.  Did the debugger cancel the sig?  */
	if (signr == 0)
		return signr;

	/*
	 * Update the siginfo structure if the signal has
	 * changed.  If the debugger wanted something
	 * specific in the siginfo structure then it should
	 * have updated *info via PTRACE_SETSIGINFO.
	 */
	if (signr != info->si_signo) {
		clear_siginfo(info);
		info->si_signo = signr;
		info->si_errno = 0;
		info->si_code = SI_USER;
		rcu_read_lock();
		info->si_pid = task_pid_vnr(current->parent);
		info->si_uid = from_kuid_munged(current_user_ns(),
						task_uid(current->parent));
		rcu_read_unlock();
	}

	/* If the (new) signal is now blocked, requeue it.  */
	if (sigismember(&current->blocked, signr) ||
	    fatal_signal_pending(current)) {
		send_signal_locked(signr, info, current, type);
		signr = 0;
	}

	return signr;
}

static void hide_si_addr_tag_bits(struct ksignal *ksig)
{
	switch (siginfo_layout(ksig->sig, ksig->info.si_code)) {
	case SIL_FAULT:
	case SIL_FAULT_TRAPNO:
	case SIL_FAULT_MCEERR:
	case SIL_FAULT_BNDERR:
	case SIL_FAULT_PKUERR:
	case SIL_FAULT_PERF_EVENT:
		ksig->info.si_addr = arch_untagged_si_addr(
			ksig->info.si_addr, ksig->sig, ksig->info.si_code);
		break;
	case SIL_KILL:
	case SIL_TIMER:
	case SIL_POLL:
	case SIL_CHLD:
	case SIL_RT:
	case SIL_SYS:
		break;
	}
}

bool get_signal(struct ksignal *ksig)
{
	struct sighand_struct *sighand = current->sighand;
	struct signal_struct *signal = current->signal;
	int signr;

	clear_notify_signal();
	if (unlikely(task_work_pending(current)))
		task_work_run();

	if (!task_sigpending(current))
		return false;

	if (unlikely(uprobe_deny_signal()))
		return false;

	/*
	 * Do this once, we can't return to user-mode if freezing() == T.
	 * do_signal_stop() and ptrace_stop() do freezable_schedule() and
	 * thus do not need another check after return.
	 */
	try_to_freeze();

relock:
	spin_lock_irq(&sighand->siglock);

	/*
	 * Every stopped thread goes here after wakeup. Check to see if
	 * we should notify the parent, prepare_signal(SIGCONT) encodes
	 * the CLD_ si_code into SIGNAL_CLD_MASK bits.
	 */
	if (unlikely(signal->flags & SIGNAL_CLD_MASK)) {
		int why;

		if (signal->flags & SIGNAL_CLD_CONTINUED)
			why = CLD_CONTINUED;
		else
			why = CLD_STOPPED;

		signal->flags &= ~SIGNAL_CLD_MASK;

		spin_unlock_irq(&sighand->siglock);

		/*
		 * Notify the parent that we're continuing.  This event is
		 * always per-process and doesn't make whole lot of sense
		 * for ptracers, who shouldn't consume the state via
		 * wait(2) either, but, for backward compatibility, notify
		 * the ptracer of the group leader too unless it's gonna be
		 * a duplicate.
		 */
		read_lock(&tasklist_lock);
		do_notify_parent_cldstop(current, false, why);

		if (ptrace_reparented(current->group_leader))
			do_notify_parent_cldstop(current->group_leader,
						true, why);
		read_unlock(&tasklist_lock);

		goto relock;
	}

	for (;;) {
		struct k_sigaction *ka;
		enum pid_type type;

		/* Has this task already been marked for death? */
		if ((signal->flags & SIGNAL_GROUP_EXIT) ||
		     signal->group_exec_task) {
			signr = SIGKILL;
			sigdelset(&current->pending.signal, SIGKILL);
			trace_signal_deliver(SIGKILL, SEND_SIG_NOINFO,
					     &sighand->action[SIGKILL-1]);
			recalc_sigpending();
			/*
			 * implies do_group_exit() or return to PF_USER_WORKER,
			 * no need to initialize ksig->info/etc.
			 */
			goto fatal;
		}

		if (unlikely(current->jobctl & JOBCTL_STOP_PENDING) &&
		    do_signal_stop(0))
			goto relock;

		if (unlikely(current->jobctl &
			     (JOBCTL_TRAP_MASK | JOBCTL_TRAP_FREEZE))) {
			if (current->jobctl & JOBCTL_TRAP_MASK) {
				do_jobctl_trap();
				spin_unlock_irq(&sighand->siglock);
			} else if (current->jobctl & JOBCTL_TRAP_FREEZE)
				do_freezer_trap();

			goto relock;
		}

		/*
		 * If the task is leaving the frozen state, let's update
		 * cgroup counters and reset the frozen bit.
		 */
		if (unlikely(cgroup_task_frozen(current))) {
			spin_unlock_irq(&sighand->siglock);
			cgroup_leave_frozen(false);
			goto relock;
		}

		/*
		 * Signals generated by the execution of an instruction
		 * need to be delivered before any other pending signals
		 * so that the instruction pointer in the signal stack
		 * frame points to the faulting instruction.
		 */
		type = PIDTYPE_PID;
		signr = dequeue_synchronous_signal(&ksig->info);
		if (!signr)
			signr = dequeue_signal(&current->blocked, &ksig->info, &type);

		if (!signr)
			break; /* will return 0 */

		if (unlikely(current->ptrace) && (signr != SIGKILL) &&
		    !(sighand->action[signr -1].sa.sa_flags & SA_IMMUTABLE)) {
			signr = ptrace_signal(signr, &ksig->info, type);
			if (!signr)
				continue;
		}

		ka = &sighand->action[signr-1];

		/* Trace actually delivered signals. */
		trace_signal_deliver(signr, &ksig->info, ka);

		if (ka->sa.sa_handler == SIG_IGN) /* Do nothing.  */
			continue;
		if (ka->sa.sa_handler != SIG_DFL) {
			/* Run the handler.  */
			ksig->ka = *ka;

			if (ka->sa.sa_flags & SA_ONESHOT)
				ka->sa.sa_handler = SIG_DFL;

			break; /* will return non-zero "signr" value */
		}

		/*
		 * Now we are doing the default action for this signal.
		 */
		if (sig_kernel_ignore(signr)) /* Default is nothing. */
			continue;

		/*
		 * Global init gets no signals it doesn't want.
		 * Container-init gets no signals it doesn't want from same
		 * container.
		 *
		 * Note that if global/container-init sees a sig_kernel_only()
		 * signal here, the signal must have been generated internally
		 * or must have come from an ancestor namespace. In either
		 * case, the signal cannot be dropped.
		 */
		if (unlikely(signal->flags & SIGNAL_UNKILLABLE) &&
				!sig_kernel_only(signr))
			continue;

		if (sig_kernel_stop(signr)) {
			/*
			 * The default action is to stop all threads in
			 * the thread group.  The job control signals
			 * do nothing in an orphaned pgrp, but SIGSTOP
			 * always works.  Note that siglock needs to be
			 * dropped during the call to is_orphaned_pgrp()
			 * because of lock ordering with tasklist_lock.
			 * This allows an intervening SIGCONT to be posted.
			 * We need to check for that and bail out if necessary.
			 */
			if (signr != SIGSTOP) {
				spin_unlock_irq(&sighand->siglock);

				/* signals can be posted during this window */

				if (is_current_pgrp_orphaned())
					goto relock;

				spin_lock_irq(&sighand->siglock);
			}

			if (likely(do_signal_stop(signr))) {
				/* It released the siglock.  */
				goto relock;
			}

			/*
			 * We didn't actually stop, due to a race
			 * with SIGCONT or something like that.
			 */
			continue;
		}

	fatal:
		spin_unlock_irq(&sighand->siglock);
		if (unlikely(cgroup_task_frozen(current)))
			cgroup_leave_frozen(true);

		/*
		 * Anything else is fatal, maybe with a core dump.
		 */
		current->flags |= PF_SIGNALED;

		if (sig_kernel_coredump(signr)) {
			if (print_fatal_signals)
				print_fatal_signal(signr);
			proc_coredump_connector(current);
			/*
			 * If it was able to dump core, this kills all
			 * other threads in the group and synchronizes with
			 * their demise.  If we lost the race with another
			 * thread getting here, it set group_exit_code
			 * first and our do_group_exit call below will use
			 * that value and ignore the one we pass it.
			 */
			vfs_coredump(&ksig->info);
		}

		/*
		 * PF_USER_WORKER threads will catch and exit on fatal signals
		 * themselves. They have cleanup that must be performed, so we
		 * cannot call do_exit() on their behalf. Note that ksig won't
		 * be properly initialized, PF_USER_WORKER's shouldn't use it.
		 */
		if (current->flags & PF_USER_WORKER)
			goto out;

		/*
		 * Death signals, no core dump.
		 */
		do_group_exit(signr);
		/* NOTREACHED */
	}
	spin_unlock_irq(&sighand->siglock);

	ksig->sig = signr;

	if (signr && !(ksig->ka.sa.sa_flags & SA_EXPOSE_TAGBITS))
		hide_si_addr_tag_bits(ksig);
out:
	return signr > 0;
}

/**
 * signal_delivered - called after signal delivery to update blocked signals
 * @ksig:		kernel signal struct
 * @stepping:		nonzero if debugger single-step or block-step in use
 *
 * This function should be called when a signal has successfully been
 * delivered. It updates the blocked signals accordingly (@ksig->ka.sa.sa_mask
 * is always blocked), and the signal itself is blocked unless %SA_NODEFER
 * is set in @ksig->ka.sa.sa_flags.  Tracing is notified.
 */
static void signal_delivered(struct ksignal *ksig, int stepping)
{
	sigset_t blocked;

	/* A signal was successfully delivered, and the
	   saved sigmask was stored on the signal frame,
	   and will be restored by sigreturn.  So we can
	   simply clear the restore sigmask flag.  */
	clear_restore_sigmask();

	sigorsets(&blocked, &current->blocked, &ksig->ka.sa.sa_mask);
	if (!(ksig->ka.sa.sa_flags & SA_NODEFER))
		sigaddset(&blocked, ksig->sig);
	set_current_blocked(&blocked);
	if (current->sas_ss_flags & SS_AUTODISARM)
		sas_ss_reset(current);
	if (stepping)
		ptrace_notify(SIGTRAP, 0);
}

void signal_setup_done(int failed, struct ksignal *ksig, int stepping)
{
	if (failed)
		force_sigsegv(ksig->sig);
	else
		signal_delivered(ksig, stepping);
}

/*
 * It could be that complete_signal() picked us to notify about the
 * group-wide signal. Other threads should be notified now to take
 * the shared signals in @which since we will not.
 */
static void retarget_shared_pending(struct task_struct *tsk, sigset_t *which)
{
	sigset_t retarget;
	struct task_struct *t;

	sigandsets(&retarget, &tsk->signal->shared_pending.signal, which);
	if (sigisemptyset(&retarget))
		return;

	for_other_threads(tsk, t) {
		if (t->flags & PF_EXITING)
			continue;

		if (!has_pending_signals(&retarget, &t->blocked))
			continue;
		/* Remove the signals this thread can handle. */
		sigandsets(&retarget, &retarget, &t->blocked);

		if (!task_sigpending(t))
			signal_wake_up(t, 0);

		if (sigisemptyset(&retarget))
			break;
	}
}

void exit_signals(struct task_struct *tsk)
{
	int group_stop = 0;
	sigset_t unblocked;

	/*
	 * @tsk is about to have PF_EXITING set - lock out users which
	 * expect stable threadgroup.
	 */
	cgroup_threadgroup_change_begin(tsk);

	if (thread_group_empty(tsk) || (tsk->signal->flags & SIGNAL_GROUP_EXIT)) {
		tsk->flags |= PF_EXITING;
		cgroup_threadgroup_change_end(tsk);
		return;
	}

	spin_lock_irq(&tsk->sighand->siglock);
	/*
	 * From now this task is not visible for group-wide signals,
	 * see wants_signal(), do_signal_stop().
	 */
	tsk->flags |= PF_EXITING;

	cgroup_threadgroup_change_end(tsk);

	if (!task_sigpending(tsk))
		goto out;

	unblocked = tsk->blocked;
	signotset(&unblocked);
	retarget_shared_pending(tsk, &unblocked);

	if (unlikely(tsk->jobctl & JOBCTL_STOP_PENDING) &&
	    task_participate_group_stop(tsk))
		group_stop = CLD_STOPPED;
out:
	spin_unlock_irq(&tsk->sighand->siglock);

	/*
	 * If group stop has completed, deliver the notification.  This
	 * should always go to the real parent of the group leader.
	 */
	if (unlikely(group_stop)) {
		read_lock(&tasklist_lock);
		do_notify_parent_cldstop(tsk, false, group_stop);
		read_unlock(&tasklist_lock);
	}
}

/*
 * System call entry points.
 */

/**
 * sys_restart_syscall - restart a system call after signal interruption
 *
 * long-desc: Restarts a system call that was interrupted by a signal and needs
 *   special handling for its restart. This syscall is NEVER called directly by
 *   user applications - it is invoked automatically by the kernel's signal
 *   delivery mechanism when a syscall returns -ERESTART_RESTARTBLOCK.
 *
 *   The restart mechanism exists to handle syscalls like nanosleep(), poll(),
 *   futex(), and clock_nanosleep() that need to adjust their behavior when
 *   restarted after a signal. Unlike simple syscalls that can be restarted by
 *   re-executing with the original arguments (handled via -ERESTARTSYS), these
 *   syscalls need to account for time that elapsed during signal handling.
 *
 *   When a syscall like nanosleep() is interrupted by a signal:
 *   1. The syscall stores restart information in current->restart_block,
 *      including a pointer to a restart handler function (restart_block.fn)
 *   2. The syscall returns -ERESTART_RESTARTBLOCK (516)
 *   3. If the signal has a handler, that handler executes
 *   4. When returning from the signal handler, the kernel replaces the return
 *      value with the syscall number for restart_syscall (__NR_restart_syscall)
 *   5. The kernel decrements the instruction pointer to re-execute the syscall
 *      instruction, but now it invokes restart_syscall instead
 *   6. restart_syscall calls the registered restart handler function, which
 *      resumes the original operation with adjusted parameters
 *
 *   The restart_block structure contains a union with operation-specific data:
 *   - futex: stores uaddr, val, flags, bitset, time, uaddr2 for futex_wait
 *   - nanosleep: stores clockid, type, rmtp/compat_rmtp, expires for sleep ops
 *   - poll: stores ufds, nfds, has_timeout, tv_sec, tv_nsec for poll()
 *
 *   For nanosleep and similar time-based syscalls, the restart handler uses
 *   the absolute expiration time stored in restart_block rather than the
 *   original relative duration. This ensures the process sleeps only for the
 *   remaining time, accounting for time spent in the signal handler. This
 *   behavior is required by POSIX which specifies that nanosleep() must not
 *   return early due to signals if no handler is registered.
 *
 *   The restart_block.fn pointer defaults to do_no_restart_syscall() which
 *   simply returns -EINTR. This ensures that if userspace erroneously calls
 *   restart_syscall without a valid restart block, or after sigreturn() has
 *   cleared the restart block, the call fails gracefully with EINTR.
 *
 *   Security note: Since kernel 6.3, nanosleep and related syscalls initialize
 *   restart_block.fn to do_no_restart_syscall at entry to prevent union field
 *   confusion if restart_syscall is called after a different syscall (like
 *   futex or poll) had set up a restart block.
 *
 *   Architecture note: On x86-64, the syscall number is 219. On i386, it is 0
 *   (replacing the original setup() syscall). The kernel handles 32-bit
 *   compatibility via TS_COMPAT_RESTART flag and __NR_ia32_restart_syscall.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_CUSTOM
 *   success: depends on restart handler
 *   desc: The return value is determined entirely by the restart handler
 *     function stored in restart_block.fn. Common return values include:
 *     - 0: The restarted operation completed successfully (e.g., sleep expired)
 *     - Positive value: Operation-specific success (e.g., poll returns count)
 *     - -EINTR: The restart handler was do_no_restart_syscall, or the restarted
 *       operation was interrupted again by a signal with a handler
 *     - -EFAULT: The restart handler accessed invalid user memory (e.g., rmtp
 *       pointer in nanosleep became invalid)
 *     - -ETIMEDOUT: For futex operations that timed out
 *     - -EWOULDBLOCK: For futex operations where the value changed
 *     - Any other error from the specific restart handler
 *
 * error: EINTR, No valid restart block or interrupted again
 *   desc: Returned by do_no_restart_syscall() when restart_block.fn was not
 *     set to a valid restart handler. This occurs when: (1) userspace calls
 *     restart_syscall directly without a pending restart, (2) sigreturn()
 *     cleared the restart block, (3) another syscall overwrote the restart
 *     block, or (4) the restarted operation was interrupted by another signal.
 *     This is the most common error and indicates the original operation
 *     should be considered interrupted.
 *
 * error: EFAULT, Invalid user-space pointer in restart block
 *   desc: Returned by restart handlers (e.g., hrtimer_nanosleep_restart,
 *     do_restart_poll) when user-space pointers stored in the restart block
 *     have become invalid. For nanosleep, this occurs if the rmtp pointer for
 *     writing remaining time is no longer accessible. For poll, this occurs if
 *     the ufds array is no longer accessible. This can happen if the user
 *     unmapped the memory during signal handling.
 *
 * error: ETIMEDOUT, Futex wait operation timed out
 *   desc: Returned by futex_wait_restart() when the restarted futex wait
 *     operation times out without being woken by futex_wake(). The timeout
 *     is based on the absolute time stored in restart_block.futex.time.
 *
 * error: EWOULDBLOCK, Futex value mismatch
 *   desc: Returned by futex_wait_restart() when the futex value at uaddr has
 *     changed from the expected value stored in restart_block.futex.val.
 *     This indicates the waited condition may have been satisfied.
 *
 * error: ERESTART_RESTARTBLOCK, Another restart needed
 *   desc: Returned by restart handlers (e.g., hrtimer_nanosleep_restart,
 *     do_restart_poll) when the restarted operation is again interrupted by
 *     a stop signal (SIGSTOP, SIGTSTP, etc.) followed by SIGCONT. In this case,
 *     the restart_block is updated with new parameters and this error code
 *     triggers another restart_syscall invocation when the process resumes.
 *     This is an internal kernel error code that is never seen by userspace.
 *
 * signal: Any signal during restart handler execution
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RESTART
 *   condition: Signal delivered while restart handler is sleeping
 *   desc: The restart handlers (nanosleep, futex, poll) perform blocking
 *     operations that can be interrupted by signals. If interrupted by a stop
 *     signal followed by SIGCONT, the handler returns -ERESTART_RESTARTBLOCK
 *     to trigger another restart. If interrupted by a signal with a handler,
 *     the kernel converts this to -EINTR or allows restart depending on the
 *     SA_RESTART flag. The key purpose of restart_syscall is to ensure that
 *     time spent stopped (SIGSTOP/SIGTSTP then SIGCONT) is properly accounted
 *     for in timeout calculations.
 *   error: -EINTR, -ERESTART_RESTARTBLOCK
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: yes (via this syscall)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: current->restart_block
 *   desc: Restart handlers may modify the restart_block to prepare for another
 *     potential restart. For example, hrtimer_nanosleep_restart() updates the
 *     nanosleep.expires field with the new absolute expiration time. After
 *     successful completion, sigreturn() typically resets restart_block.fn to
 *     do_no_restart_syscall to invalidate the restart block.
 *   reversible: yes (via sigreturn or another syscall)
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: calling thread
 *   desc: Restart handlers like hrtimer_nanosleep_restart(), do_restart_poll(),
 *     and futex_wait_restart() cause the calling thread to sleep until their
 *     completion condition is met (timeout expires, poll events occur, futex
 *     is woken, etc.). This can cause the thread to be descheduled for
 *     significant periods.
 *   reversible: yes (when handler returns)
 *
 * state-trans: restart_block
 *   from: fn points to valid restart handler (e.g., hrtimer_nanosleep_restart)
 *   to: fn points to do_no_restart_syscall (after sigreturn completes)
 *   condition: Normal completion of signal handling sequence
 *   desc: The restart_block is set up by the original syscall when it returns
 *     -ERESTART_RESTARTBLOCK. After the signal is handled and sigreturn()
 *     returns, the restart_block.fn is reset to do_no_restart_syscall by the
 *     arch-specific sigreturn implementation to prevent stale restart data
 *     from being used by a subsequent erroneous restart_syscall call.
 *
 * constraint: Kernel-internal use only
 *   desc: This syscall should NEVER be called directly by applications. It is
 *     invoked automatically by the kernel's signal handling mechanism. Direct
 *     calls will either return -EINTR (if restart_block.fn is the default
 *     do_no_restart_syscall) or produce undefined behavior if a stale restart
 *     block from a previous syscall is present. There is no glibc wrapper for
 *     this syscall.
 *
 * constraint: Valid restart_block required
 *   desc: The syscall relies on current->restart_block being properly
 *     initialized by a previous syscall that returned -ERESTART_RESTARTBLOCK.
 *     The restart_block.fn pointer must point to a valid restart handler
 *     function, and the union fields must contain valid data for that handler.
 *     If these conditions are not met, behavior is undefined (though typically
 *     results in -EINTR or crashes in the restart handler).
 *
 * examples:
 *   // This syscall is NEVER called directly. Example of kernel-internal flow:
 *   // 1. User calls: nanosleep(&req, &rem);
 *   // 2. nanosleep() is interrupted by SIGSTOP, then resumed by SIGCONT
 *   // 3. Kernel automatically invokes restart_syscall() to continue sleeping
 *   // 4. hrtimer_nanosleep_restart() calculates remaining time and sleeps
 *   // 5. Returns 0 when sleep completes, or remaining time written to rem
 *
 * notes:
 *   - Introduced in Linux 2.5.51 to solve the nanosleep POSIX compliance issue.
 *     Prior to this, nanosleep could not properly account for time spent in
 *     signal handlers or stopped state.
 *   - The syscall number varies by architecture: 219 on x86-64, 0 on i386
 *     (replacing the obsolete setup() syscall), 128 on generic architectures.
 *   - Applications that use ptrace to trace syscalls will see restart_syscall
 *     invocations after SIGSTOP/SIGCONT sequences during blocking operations.
 *     This is normal and expected behavior.
 *   - The kernel selftests in tools/testing/selftests/seccomp/seccomp_bpf.c
 *     include tests that verify restart_syscall is correctly invoked after
 *     SIGSTOP/SIGCONT interrupts nanosleep.
 *   - seccomp filters can intercept restart_syscall. The seccomp test suite
 *     demonstrates using SECCOMP_RET_TRACE to observe restart_syscall(0x200).
 *   - Race condition note: A security fix in kernel 6.3 (commit 9f76d59173d9d)
 *     addressed potential union confusion where nanosleep could clobber futex
 *     or poll restart data if restart_syscall was erroneously called.
 *
 * since-version: 2.5.51
 */
SYSCALL_DEFINE0(restart_syscall)
{
	struct restart_block *restart = &current->restart_block;
	return restart->fn(restart);
}

long do_no_restart_syscall(struct restart_block *param)
{
	return -EINTR;
}

static void __set_task_blocked(struct task_struct *tsk, const sigset_t *newset)
{
	if (task_sigpending(tsk) && !thread_group_empty(tsk)) {
		sigset_t newblocked;
		/* A set of now blocked but previously unblocked signals. */
		sigandnsets(&newblocked, newset, &current->blocked);
		retarget_shared_pending(tsk, &newblocked);
	}
	tsk->blocked = *newset;
	recalc_sigpending();
}

/**
 * set_current_blocked - change current->blocked mask
 * @newset: new mask
 *
 * It is wrong to change ->blocked directly, this helper should be used
 * to ensure the process can't miss a shared signal we are going to block.
 */
void set_current_blocked(sigset_t *newset)
{
	sigdelsetmask(newset, sigmask(SIGKILL) | sigmask(SIGSTOP));
	__set_current_blocked(newset);
}

void __set_current_blocked(const sigset_t *newset)
{
	struct task_struct *tsk = current;

	/*
	 * In case the signal mask hasn't changed, there is nothing we need
	 * to do. The current->blocked shouldn't be modified by other task.
	 */
	if (sigequalsets(&tsk->blocked, newset))
		return;

	spin_lock_irq(&tsk->sighand->siglock);
	__set_task_blocked(tsk, newset);
	spin_unlock_irq(&tsk->sighand->siglock);
}

/*
 * This is also useful for kernel threads that want to temporarily
 * (or permanently) block certain signals.
 *
 * NOTE! Unlike the user-mode sys_sigprocmask(), the kernel
 * interface happily blocks "unblockable" signals like SIGKILL
 * and friends.
 */
int sigprocmask(int how, sigset_t *set, sigset_t *oldset)
{
	struct task_struct *tsk = current;
	sigset_t newset;

	/* Lockless, only current can change ->blocked, never from irq */
	if (oldset)
		*oldset = tsk->blocked;

	switch (how) {
	case SIG_BLOCK:
		sigorsets(&newset, &tsk->blocked, set);
		break;
	case SIG_UNBLOCK:
		sigandnsets(&newset, &tsk->blocked, set);
		break;
	case SIG_SETMASK:
		newset = *set;
		break;
	default:
		return -EINVAL;
	}

	__set_current_blocked(&newset);
	return 0;
}
EXPORT_SYMBOL(sigprocmask);

/*
 * The api helps set app-provided sigmasks.
 *
 * This is useful for syscalls such as ppoll, pselect, io_pgetevents and
 * epoll_pwait where a new sigmask is passed from userland for the syscalls.
 *
 * Note that it does set_restore_sigmask() in advance, so it must be always
 * paired with restore_saved_sigmask_unless() before return from syscall.
 */
int set_user_sigmask(const sigset_t __user *umask, size_t sigsetsize)
{
	sigset_t kmask;

	if (!umask)
		return 0;
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;
	if (copy_from_user(&kmask, umask, sizeof(sigset_t)))
		return -EFAULT;

	set_restore_sigmask();
	current->saved_sigmask = current->blocked;
	set_current_blocked(&kmask);

	return 0;
}

#ifdef CONFIG_COMPAT
int set_compat_user_sigmask(const compat_sigset_t __user *umask,
			    size_t sigsetsize)
{
	sigset_t kmask;

	if (!umask)
		return 0;
	if (sigsetsize != sizeof(compat_sigset_t))
		return -EINVAL;
	if (get_compat_sigset(&kmask, umask))
		return -EFAULT;

	set_restore_sigmask();
	current->saved_sigmask = current->blocked;
	set_current_blocked(&kmask);

	return 0;
}
#endif

/**
 * sys_rt_sigprocmask - examine and change the calling thread's blocked signal mask
 * @how: Specifies the operation: SIG_BLOCK, SIG_UNBLOCK, or SIG_SETMASK
 * @nset: Pointer to the new signal mask (input), or NULL to not modify
 * @oset: Pointer to buffer for the previous signal mask (output), or NULL
 * @sigsetsize: Size of the sigset_t type (must equal sizeof(sigset_t))
 *
 * long-desc: Examines and/or changes the signal mask of the calling thread.
 *   The signal mask is the set of signals currently blocked for the thread.
 *   Blocked signals are held pending until unblocked; they are then delivered.
 *   This is the real-time signal variant introduced in Linux 2.2 to support the
 *   enlarged 64-signal sigset_t (replacing the original 32-signal sigprocmask).
 *
 *   The @how parameter determines how @nset is interpreted when non-NULL:
 *   - SIG_BLOCK (0): The set of blocked signals is the union of the current set
 *     and the signal set pointed to by @nset. Adds signals to the blocked mask.
 *   - SIG_UNBLOCK (1): The signals in @nset are removed from the current set of
 *     blocked signals. Unblocks the specified signals.
 *   - SIG_SETMASK (2): The set of blocked signals is set to @nset, replacing the
 *     current blocked set entirely.
 *
 *   If @nset is NULL, the signal mask is not changed; in this case @how is ignored
 *   and the syscall can be used purely to query the current mask via @oset.
 *
 *   If @oset is non-NULL, the previous signal mask is written to it before any
 *   modifications are applied. This allows atomic read-modify-write operations
 *   and provides the previous mask for later restoration.
 *
 *   It is not possible to block SIGKILL (9) or SIGSTOP (19). Attempts to add
 *   these signals to the blocked mask are silently ignored (they are removed
 *   from @nset via sigdelsetmask before applying). This is enforced by POSIX and
 *   ensures these signals can always terminate or stop a process.
 *
 *   The signal mask is per-thread: each thread in a multithreaded process has
 *   its own signal mask. The main thread's mask is inherited by new threads
 *   created with pthread_create(). Note that POSIX specifies sigprocmask()
 *   behavior is unspecified in multithreaded programs; applications should use
 *   pthread_sigmask() instead, though on Linux they are functionally equivalent.
 *
 *   Signal mask inheritance:
 *   - fork(): Child inherits the parent's signal mask
 *   - exec(): Signal mask is preserved across exec()
 *   - clone(): New thread inherits the signal mask if CLONE_SIGHAND is set
 *
 *   If any signals become unblocked by this call and are pending (either in the
 *   thread's private pending queue or the process-wide shared pending queue),
 *   at least one of them will be delivered before the syscall returns. The order
 *   of delivery is: standard signals in numerical order, then real-time signals
 *   in the order they were queued.
 *
 *   Implementation note: When the signal mask changes, the kernel checks if
 *   there are shared pending signals that this thread was blocking but other
 *   threads might handle. If so, the kernel retargets these signals to other
 *   eligible threads via retarget_shared_pending(). This ensures signals are
 *   not lost when a thread blocks a signal another thread could handle.
 *
 *   Performance optimization: The kernel avoids acquiring sighand->siglock if
 *   the new signal mask equals the current mask (sigequalsets check). This
 *   significantly reduces lock contention in applications that frequently call
 *   sigprocmask with unchanged masks, such as swapcontext() in glibc.
 *
 *   glibc wrapping: The glibc sigprocmask() function transparently calls
 *   rt_sigprocmask() with the correct sigsetsize. Additionally, glibc internally
 *   uses two signals (SIGRTMIN and SIGRTMIN+1, signals 32-33) for NPTL threading
 *   implementation and silently prevents blocking these via sigprocmask().
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: how
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_ENUM
 *   valid-mask: SIG_BLOCK | SIG_UNBLOCK | SIG_SETMASK
 *   constraint: Must be SIG_BLOCK (0), SIG_UNBLOCK (1), or SIG_SETMASK (2).
 *     Ignored if @nset is NULL. Returns EINVAL for any other value.
 *     SIG_BLOCK adds signals to the mask (union), SIG_UNBLOCK removes signals
 *     (intersection with complement), SIG_SETMASK replaces the mask entirely.
 *
 * param: nset
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_OPTIONAL | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Pointer to a sigset_t containing the new signal mask, or NULL
 *     to skip modification. When non-NULL, the memory must be readable and
 *     contain a valid sigset_t of @sigsetsize bytes. SIGKILL and SIGSTOP bits
 *     are automatically cleared from this set before applying.
 *
 * param: oset
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_OPTIONAL | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Pointer to a sigset_t buffer to receive the previous signal
 *     mask, or NULL to skip retrieval. When non-NULL, the memory must be
 *     writable for @sigsetsize bytes. The previous mask is written before
 *     any modifications, enabling atomic save-and-modify operations.
 *
 * param: sigsetsize
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must exactly equal sizeof(sigset_t), which is 8 bytes on most
 *     architectures (64 signals / 8 bits per byte = 8 bytes). This parameter
 *     exists to allow future kernel versions to support larger signal sets
 *     while maintaining backward compatibility. Returns EINVAL if mismatched.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. The signal mask has been modified according
 *     to @how and @nset (if @nset was non-NULL), and the previous mask has
 *     been written to @oset (if @oset was non-NULL). If both @nset and @oset
 *     are NULL, the syscall is a no-op and returns 0.
 *
 * error: EINVAL, Invalid sigsetsize
 *   desc: The @sigsetsize parameter does not equal sizeof(sigset_t). This
 *     indicates an ABI mismatch between the calling program and the kernel.
 *     On most architectures, sigsetsize must be exactly 8. The glibc wrapper
 *     handles this automatically, so this error typically only occurs when
 *     calling the syscall directly with an incorrect size.
 *
 * error: EINVAL, Invalid how value
 *   desc: The @how parameter is not SIG_BLOCK (0), SIG_UNBLOCK (1), or
 *     SIG_SETMASK (2), and @nset is non-NULL. This error is returned by the
 *     sigprocmask() helper function after the new mask has been copied from
 *     userspace. If @nset is NULL, @how is ignored and this error cannot occur.
 *
 * error: EFAULT, Bad nset pointer
 *   desc: The @nset pointer is non-NULL but points to memory that cannot be
 *     read by the calling process. The copy_from_user() operation failed.
 *     The signal mask is unchanged when this error occurs.
 *
 * error: EFAULT, Bad oset pointer
 *   desc: The @oset pointer is non-NULL but points to memory that cannot be
 *     written by the calling process. The copy_to_user() operation failed.
 *     Important: this error is checked AFTER the signal mask has been modified
 *     (if @nset was valid), so partial effects are possible. The old mask was
 *     captured before modification but could not be written to userspace.
 *
 * lock: current->sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: conditionally
 *   released: conditionally
 *   desc: The signal handler spinlock is acquired with IRQs disabled
 *     (spin_lock_irq) in __set_current_blocked() only when the new signal mask
 *     differs from the current mask. If the masks are equal (checked via
 *     sigequalsets), no lock is acquired - an optimization added in kernel 4.10
 *     to reduce contention from glibc's swapcontext() which calls sigprocmask
 *     frequently with unchanged masks. When acquired, the lock is held briefly
 *     while updating tsk->blocked and calling recalc_sigpending().
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE | KAPI_EFFECT_PROCESS_STATE
 *   target: Current thread's signal mask (current->blocked)
 *   desc: Modifies the signal mask field (blocked) in the calling thread's
 *     task_struct. This determines which signals are blocked (held pending)
 *     for this specific thread. Other threads in the same process are not
 *     affected; each has its own signal mask. The modification persists until
 *     changed by another sigprocmask call, the thread exits, or affected by
 *     signal handler execution (which temporarily extends the mask).
 *   condition: @nset is non-NULL and the new mask differs from current mask
 *   reversible: yes (by calling rt_sigprocmask with saved @oset value)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Thread flag TIF_SIGPENDING
 *   desc: The recalc_sigpending() function is called after modifying the
 *     signal mask, which may set or clear the TIF_SIGPENDING thread flag.
 *     This flag indicates whether there are pending signals that should be
 *     delivered. If signals become unblocked and are pending, TIF_SIGPENDING
 *     is set, triggering signal delivery before the syscall returns.
 *   condition: Signal mask is modified
 *   reversible: yes (automatically managed by kernel)
 *
 * side-effect: KAPI_EFFECT_SIGNAL_SEND
 *   target: Other threads in thread group (via retarget_shared_pending)
 *   desc: When blocking signals that are in the shared pending queue, the
 *     kernel retargets them to other threads that can handle them via
 *     retarget_shared_pending(). This wakes up eligible threads via
 *     signal_wake_up() if they weren't already marked as having pending
 *     signals. This ensures process-directed signals are not lost when the
 *     receiving thread blocks them but other threads can handle them.
 *   condition: Blocking signals and shared pending signals exist
 *   reversible: no (wakeups cannot be undone)
 *
 * state-trans: thread_signal_mask
 *   from: previous blocked signal set
 *   to: new blocked signal set (union with nset for SIG_BLOCK)
 *   condition: @how is SIG_BLOCK and @nset is non-NULL
 *   desc: Signals specified in @nset are added to the blocked mask. This is
 *     equivalent to: new_mask = old_mask | (*nset & ~(SIGKILL|SIGSTOP))
 *
 * state-trans: thread_signal_mask
 *   from: previous blocked signal set
 *   to: new blocked signal set (with nset signals removed for SIG_UNBLOCK)
 *   condition: @how is SIG_UNBLOCK and @nset is non-NULL
 *   desc: Signals specified in @nset are removed from the blocked mask. This
 *     is equivalent to: new_mask = old_mask & ~(*nset). Pending signals that
 *     become unblocked will be delivered before the syscall returns.
 *
 * state-trans: thread_signal_mask
 *   from: previous blocked signal set
 *   to: signal set in nset (for SIG_SETMASK)
 *   condition: @how is SIG_SETMASK and @nset is non-NULL
 *   desc: The blocked mask is replaced entirely with @nset (after removing
 *     SIGKILL and SIGSTOP). This is equivalent to: new_mask = *nset & ~(SIGKILL|SIGSTOP)
 *
 * constraint: Per-thread operation
 *   desc: The signal mask is per-thread, not per-process. In a multithreaded
 *     application, each thread has its own signal mask. This syscall only
 *     affects the calling thread's mask. Use pthread_sigmask() for clearer
 *     semantics in threaded programs, though on Linux it has identical behavior.
 *
 * constraint: SIGKILL and SIGSTOP cannot be blocked
 *   desc: SIGKILL (signal 9) and SIGSTOP (signal 19) are automatically removed
 *     from any signal set before applying to the blocked mask. These signals
 *     cannot be caught, blocked, or ignored, as mandated by POSIX. Attempts to
 *     block them are silently ignored (not an error).
 *   expr: !(blocked_mask & (sigmask(SIGKILL) | sigmask(SIGSTOP)))
 *
 * constraint: Undefined behavior for blocking synchronous signals
 *   desc: If SIGBUS, SIGFPE, SIGILL, or SIGSEGV are blocked while being
 *     generated synchronously (by the hardware due to program errors), the
 *     result is undefined. These signals may only be safely blocked if generated
 *     asynchronously via kill(), sigqueue(), or raise(). Blocking a synchronous
 *     SIGSEGV during execution typically leads to immediate re-generation and
 *     undefined behavior or termination.
 *
 * examples:
 *   // Block SIGINT and SIGTERM
 *   sigset_t newmask, oldmask;
 *   sigemptyset(&newmask);
 *   sigaddset(&newmask, SIGINT);
 *   sigaddset(&newmask, SIGTERM);
 *   rt_sigprocmask(SIG_BLOCK, &newmask, &oldmask, sizeof(sigset_t));
 *
 *   // Unblock SIGUSR1
 *   sigemptyset(&newmask);
 *   sigaddset(&newmask, SIGUSR1);
 *   rt_sigprocmask(SIG_UNBLOCK, &newmask, NULL, sizeof(sigset_t));
 *
 *   // Query current mask without changing it
 *   rt_sigprocmask(SIG_BLOCK, NULL, &oldmask, sizeof(sigset_t));
 *
 *   // Restore previously saved mask
 *   rt_sigprocmask(SIG_SETMASK, &oldmask, NULL, sizeof(sigset_t));
 *
 * notes: This syscall is typically accessed via the glibc sigprocmask() or
 *   pthread_sigmask() wrapper functions, which handle the sigsetsize parameter
 *   and provide a more standard interface.
 *
 *   The original sigprocmask() syscall (still present on some architectures)
 *   used a 32-bit signal mask. rt_sigprocmask() was introduced in Linux 2.2
 *   to support 64 signals (including 32 real-time signals SIGRTMIN to SIGRTMAX).
 *
 *   When a signal handler is invoked, the signals specified in sa_mask (from
 *   sigaction) are added to the blocked mask for the duration of the handler,
 *   in addition to the signal being handled (unless SA_NODEFER is set). The
 *   original mask is restored when the handler returns via sigreturn().
 *
 *   A 32-bit compatibility variant (compat_sys_rt_sigprocmask) exists for
 *   32-bit processes running on 64-bit kernels, using compat_sigset_t and
 *   appropriate conversion functions (get_compat_sigset/put_compat_sigset).
 *
 *   glibc internally reserves SIGRTMIN and SIGRTMIN+1 (signals 32-33) for
 *   NPTL threading implementation and silently filters these from sigprocmask
 *   calls. Direct syscalls bypass this filtering.
 *
 *   No capabilities are required to modify a thread's own signal mask.
 *
 * since-version: 2.2
 */
SYSCALL_DEFINE4(rt_sigprocmask, int, how, sigset_t __user *, nset,
		sigset_t __user *, oset, size_t, sigsetsize)
{
	sigset_t old_set, new_set;
	int error;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	old_set = current->blocked;

	if (nset) {
		if (copy_from_user(&new_set, nset, sizeof(sigset_t)))
			return -EFAULT;
		sigdelsetmask(&new_set, sigmask(SIGKILL)|sigmask(SIGSTOP));

		error = sigprocmask(how, &new_set, NULL);
		if (error)
			return error;
	}

	if (oset) {
		if (copy_to_user(oset, &old_set, sizeof(sigset_t)))
			return -EFAULT;
	}

	return 0;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(rt_sigprocmask, int, how, compat_sigset_t __user *, nset,
		compat_sigset_t __user *, oset, compat_size_t, sigsetsize)
{
	sigset_t old_set = current->blocked;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (nset) {
		sigset_t new_set;
		int error;
		if (get_compat_sigset(&new_set, nset))
			return -EFAULT;
		sigdelsetmask(&new_set, sigmask(SIGKILL)|sigmask(SIGSTOP));

		error = sigprocmask(how, &new_set, NULL);
		if (error)
			return error;
	}
	return oset ? put_compat_sigset(oset, &old_set, sizeof(*oset)) : 0;
}
#endif

static void do_sigpending(sigset_t *set)
{
	spin_lock_irq(&current->sighand->siglock);
	sigorsets(set, &current->pending.signal,
		  &current->signal->shared_pending.signal);
	spin_unlock_irq(&current->sighand->siglock);

	/* Outside the lock because only this thread touches it.  */
	sigandsets(set, &current->blocked, set);
}

/**
 * sys_rt_sigpending - retrieve the set of pending signals blocked for delivery
 * @uset: Pointer to user-space buffer to receive the pending signal mask
 * @sigsetsize: Size of the signal set buffer in bytes
 *
 * long-desc: Returns the set of signals that are pending for delivery to the
 *   calling thread and are currently blocked. A signal is "pending" if it has
 *   been raised (via kill(), raise(), sigqueue(), or hardware fault) but not yet
 *   delivered. Only signals that are BOTH pending AND blocked appear in the
 *   returned set - unblocked pending signals would already have been delivered.
 *
 *   The returned signal set is the intersection of the thread's blocked signal
 *   mask (current->blocked) with the union of:
 *   - Thread-specific pending signals (current->pending.signal): Signals sent
 *     specifically to this thread via tkill(), tgkill(), or pthread_kill().
 *   - Process-wide pending signals (current->signal->shared_pending.signal):
 *     Signals sent to the process as a whole via kill() or generated by the
 *     kernel (e.g., SIGCHLD, SIGPIPE).
 *
 *   This is the real-time signal variant introduced in Linux 2.2 to support
 *   the enlarged 64-signal sigset_t. The original sigpending() syscall used a
 *   32-bit signal mask (old_sigset_t). The @sigsetsize parameter allows for
 *   future expansion while maintaining backward compatibility.
 *
 *   Important behaviors:
 *   - Signals that are both blocked AND ignored (SIG_IGN) do not appear in the
 *     pending mask. When a signal is set to SIG_IGN, pending instances of that
 *     signal are discarded.
 *   - SIGKILL and SIGSTOP cannot be blocked, so they never appear in the result.
 *   - The syscall is a read-only query - it does not modify the signal state,
 *     does not dequeue signals, and has no side effects.
 *   - Real-time signals (SIGRTMIN through SIGRTMAX) can be queued multiple
 *     times, but sigpending() only indicates their presence, not the count.
 *
 *   Signal mask inheritance:
 *   - fork(): Child process starts with an empty pending signal set.
 *   - execve(): The pending signal set is preserved across exec.
 *   - clone(): New thread starts with empty thread-specific pending signals,
 *     but shares process-wide pending signals via shared signal_struct.
 *
 *   Typical usage pattern:
 *   1. Block some signals with sigprocmask(SIG_BLOCK, ...)
 *   2. Do work that might generate those signals
 *   3. Call sigpending() to check if signals arrived while blocked
 *   4. Optionally handle the pending signals by unblocking them
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: uset
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Pointer to a user-space buffer of at least @sigsetsize bytes
 *     where the pending signal mask will be stored. Must be a valid writable
 *     address. The buffer receives a sigset_t (or partial sigset_t if
 *     @sigsetsize is smaller) containing bits set for each pending blocked
 *     signal. Cannot be NULL; passing NULL results in EFAULT.
 *
 * param: sigsetsize
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, sizeof(sigset_t)
 *   constraint: Size of the signal set buffer in bytes. Must be less than or
 *     equal to sizeof(sigset_t), which is 8 bytes on most 64-bit architectures
 *     (64 signals / 8 bits per byte). Unlike rt_sigprocmask which requires an
 *     exact match, this syscall allows smaller sizes for backward compatibility
 *     with old 32-bit signal masks. Only the first @sigsetsize bytes of the
 *     pending mask are copied to @uset. The glibc sigpending() wrapper always
 *     passes sizeof(sigset_t).
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. The pending signal mask has been written to
 *     the user-space buffer pointed to by @uset. Each bit set in the mask
 *     corresponds to a signal number that is both pending and blocked.
 *     Signal N is pending if bit (N-1) is set in the returned mask.
 *
 * error: EINVAL, sigsetsize too large
 *   desc: The @sigsetsize parameter exceeds sizeof(sigset_t). This check
 *     prevents buffer overruns in the kernel and ensures the caller isn't
 *     expecting more signal bits than the kernel supports. On most 64-bit
 *     systems, sigsetsize must be <= 8 bytes. This error typically indicates
 *     an ABI mismatch or programming error.
 *
 * error: EFAULT, Invalid user pointer
 *   desc: The @uset pointer is invalid or points to memory that cannot be
 *     written by the calling process. The copy_to_user() operation failed.
 *     This includes NULL pointers, unmapped addresses, and read-only memory
 *     regions. No partial write occurs - either the entire mask is copied
 *     or the syscall fails with EFAULT.
 *
 * lock: current->sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The signal handler spinlock is acquired with IRQs disabled
 *     (spin_lock_irq) to read the thread-pending and shared-pending signal
 *     masks atomically. The lock is released (spin_unlock_irq) before
 *     accessing current->blocked, which is safe because only the current
 *     thread can modify its own blocked mask. The lock is held only briefly
 *     during the OR operation on the two pending masks.
 *
 * constraint: Read-only operation
 *   desc: This syscall is a pure query with no side effects. It does not
 *     modify the pending signal set, does not dequeue signals, and does not
 *     affect signal delivery. To actually handle pending signals, the
 *     application must unblock them (via sigprocmask) or wait for them
 *     (via sigwait/sigtimedwait).
 *
 * constraint: No capability requirements
 *   desc: No special capabilities are required. Any process can query its
 *     own pending signals. There is no way to query another process's
 *     pending signals via this syscall.
 *
 * constraint: Signal set semantics
 *   desc: The returned mask only indicates presence of pending signals, not
 *     their count. Standard signals (1-31) cannot be queued; multiple
 *     instances merge into one pending instance. Real-time signals (32-64)
 *     can be queued, but sigpending() only shows that at least one instance
 *     is pending. Use sigtimedwait() or sigwaitinfo() to dequeue individual
 *     signal instances with their associated data.
 *
 * examples:
 *   sigpending(&pending_mask);  // Check which blocked signals are pending
 *   rt_sigpending(&set, sizeof(sigset_t));  // Direct syscall with full mask
 *   rt_sigpending(&set, 4);  // Only retrieve first 32 signals (compat)
 *
 * notes: This syscall is typically accessed via the glibc sigpending() wrapper
 *   function, which handles the sigsetsize parameter automatically.
 *
 *   The original sigpending() syscall (still present on some architectures as
 *   __NR_sigpending) used a 32-bit signal mask. rt_sigpending() was introduced
 *   in Linux 2.2 to support 64 signals including real-time signals SIGRTMIN
 *   through SIGRTMAX.
 *
 *   Race condition note: The returned pending mask represents a snapshot at
 *   the time of the syscall. New signals may arrive or pending signals may
 *   be delivered to other threads between the syscall return and when the
 *   caller examines the result. For process-wide signals, another thread
 *   might handle the signal before the calling thread can act on it.
 *
 *   A 32-bit compatibility variant (compat_sys_rt_sigpending) exists for
 *   32-bit processes running on 64-bit kernels. It uses compat_sigset_t and
 *   handles endianness conversion via put_compat_sigset().
 *
 *   Glibc versions through 2.2.1 had a bug where pending real-time signal
 *   information was not correctly returned.
 *
 * since-version: 2.2
 */
SYSCALL_DEFINE2(rt_sigpending, sigset_t __user *, uset, size_t, sigsetsize)
{
	sigset_t set;

	if (sigsetsize > sizeof(*uset))
		return -EINVAL;

	do_sigpending(&set);

	if (copy_to_user(uset, &set, sigsetsize))
		return -EFAULT;

	return 0;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(rt_sigpending, compat_sigset_t __user *, uset,
		compat_size_t, sigsetsize)
{
	sigset_t set;

	if (sigsetsize > sizeof(*uset))
		return -EINVAL;

	do_sigpending(&set);

	return put_compat_sigset(uset, &set, sigsetsize);
}
#endif

static const struct {
	unsigned char limit, layout;
} sig_sicodes[] = {
	[SIGILL]  = { NSIGILL,  SIL_FAULT },
	[SIGFPE]  = { NSIGFPE,  SIL_FAULT },
	[SIGSEGV] = { NSIGSEGV, SIL_FAULT },
	[SIGBUS]  = { NSIGBUS,  SIL_FAULT },
	[SIGTRAP] = { NSIGTRAP, SIL_FAULT },
#if defined(SIGEMT)
	[SIGEMT]  = { NSIGEMT,  SIL_FAULT },
#endif
	[SIGCHLD] = { NSIGCHLD, SIL_CHLD },
	[SIGPOLL] = { NSIGPOLL, SIL_POLL },
	[SIGSYS]  = { NSIGSYS,  SIL_SYS },
};

static bool known_siginfo_layout(unsigned sig, int si_code)
{
	if (si_code == SI_KERNEL)
		return true;
	else if ((si_code > SI_USER)) {
		if (sig_specific_sicodes(sig)) {
			if (si_code <= sig_sicodes[sig].limit)
				return true;
		}
		else if (si_code <= NSIGPOLL)
			return true;
	}
	else if (si_code >= SI_DETHREAD)
		return true;
	else if (si_code == SI_ASYNCNL)
		return true;
	return false;
}

enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
{
	enum siginfo_layout layout = SIL_KILL;
	if ((si_code > SI_USER) && (si_code < SI_KERNEL)) {
		if ((sig < ARRAY_SIZE(sig_sicodes)) &&
		    (si_code <= sig_sicodes[sig].limit)) {
			layout = sig_sicodes[sig].layout;
			/* Handle the exceptions */
			if ((sig == SIGBUS) &&
			    (si_code >= BUS_MCEERR_AR) && (si_code <= BUS_MCEERR_AO))
				layout = SIL_FAULT_MCEERR;
			else if ((sig == SIGSEGV) && (si_code == SEGV_BNDERR))
				layout = SIL_FAULT_BNDERR;
#ifdef SEGV_PKUERR
			else if ((sig == SIGSEGV) && (si_code == SEGV_PKUERR))
				layout = SIL_FAULT_PKUERR;
#endif
			else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
				layout = SIL_FAULT_PERF_EVENT;
			else if (IS_ENABLED(CONFIG_SPARC) &&
				 (sig == SIGILL) && (si_code == ILL_ILLTRP))
				layout = SIL_FAULT_TRAPNO;
			else if (IS_ENABLED(CONFIG_ALPHA) &&
				 ((sig == SIGFPE) ||
				  ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
				layout = SIL_FAULT_TRAPNO;
		}
		else if (si_code <= NSIGPOLL)
			layout = SIL_POLL;
	} else {
		if (si_code == SI_TIMER)
			layout = SIL_TIMER;
		else if (si_code == SI_SIGIO)
			layout = SIL_POLL;
		else if (si_code < 0)
			layout = SIL_RT;
	}
	return layout;
}

static inline char __user *si_expansion(const siginfo_t __user *info)
{
	return ((char __user *)info) + sizeof(struct kernel_siginfo);
}

int copy_siginfo_to_user(siginfo_t __user *to, const kernel_siginfo_t *from)
{
	char __user *expansion = si_expansion(to);
	if (copy_to_user(to, from , sizeof(struct kernel_siginfo)))
		return -EFAULT;
	if (clear_user(expansion, SI_EXPANSION_SIZE))
		return -EFAULT;
	return 0;
}

static int post_copy_siginfo_from_user(kernel_siginfo_t *info,
				       const siginfo_t __user *from)
{
	if (unlikely(!known_siginfo_layout(info->si_signo, info->si_code))) {
		char __user *expansion = si_expansion(from);
		char buf[SI_EXPANSION_SIZE];
		int i;
		/*
		 * An unknown si_code might need more than
		 * sizeof(struct kernel_siginfo) bytes.  Verify all of the
		 * extra bytes are 0.  This guarantees copy_siginfo_to_user
		 * will return this data to userspace exactly.
		 */
		if (copy_from_user(&buf, expansion, SI_EXPANSION_SIZE))
			return -EFAULT;
		for (i = 0; i < SI_EXPANSION_SIZE; i++) {
			if (buf[i] != 0)
				return -E2BIG;
		}
	}
	return 0;
}

static int __copy_siginfo_from_user(int signo, kernel_siginfo_t *to,
				    const siginfo_t __user *from)
{
	if (copy_from_user(to, from, sizeof(struct kernel_siginfo)))
		return -EFAULT;
	to->si_signo = signo;
	return post_copy_siginfo_from_user(to, from);
}

int copy_siginfo_from_user(kernel_siginfo_t *to, const siginfo_t __user *from)
{
	if (copy_from_user(to, from, sizeof(struct kernel_siginfo)))
		return -EFAULT;
	return post_copy_siginfo_from_user(to, from);
}

#ifdef CONFIG_COMPAT
/**
 * copy_siginfo_to_external32 - copy a kernel siginfo into a compat user siginfo
 * @to: compat siginfo destination
 * @from: kernel siginfo source
 *
 * Note: This function does not work properly for the SIGCHLD on x32, but
 * fortunately it doesn't have to.  The only valid callers for this function are
 * copy_siginfo_to_user32, which is overriden for x32 and the coredump code.
 * The latter does not care because SIGCHLD will never cause a coredump.
 */
void copy_siginfo_to_external32(struct compat_siginfo *to,
		const struct kernel_siginfo *from)
{
	memset(to, 0, sizeof(*to));

	to->si_signo = from->si_signo;
	to->si_errno = from->si_errno;
	to->si_code  = from->si_code;
	switch(siginfo_layout(from->si_signo, from->si_code)) {
	case SIL_KILL:
		to->si_pid = from->si_pid;
		to->si_uid = from->si_uid;
		break;
	case SIL_TIMER:
		to->si_tid     = from->si_tid;
		to->si_overrun = from->si_overrun;
		to->si_int     = from->si_int;
		break;
	case SIL_POLL:
		to->si_band = from->si_band;
		to->si_fd   = from->si_fd;
		break;
	case SIL_FAULT:
		to->si_addr = ptr_to_compat(from->si_addr);
		break;
	case SIL_FAULT_TRAPNO:
		to->si_addr = ptr_to_compat(from->si_addr);
		to->si_trapno = from->si_trapno;
		break;
	case SIL_FAULT_MCEERR:
		to->si_addr = ptr_to_compat(from->si_addr);
		to->si_addr_lsb = from->si_addr_lsb;
		break;
	case SIL_FAULT_BNDERR:
		to->si_addr = ptr_to_compat(from->si_addr);
		to->si_lower = ptr_to_compat(from->si_lower);
		to->si_upper = ptr_to_compat(from->si_upper);
		break;
	case SIL_FAULT_PKUERR:
		to->si_addr = ptr_to_compat(from->si_addr);
		to->si_pkey = from->si_pkey;
		break;
	case SIL_FAULT_PERF_EVENT:
		to->si_addr = ptr_to_compat(from->si_addr);
		to->si_perf_data = from->si_perf_data;
		to->si_perf_type = from->si_perf_type;
		to->si_perf_flags = from->si_perf_flags;
		break;
	case SIL_CHLD:
		to->si_pid = from->si_pid;
		to->si_uid = from->si_uid;
		to->si_status = from->si_status;
		to->si_utime = from->si_utime;
		to->si_stime = from->si_stime;
		break;
	case SIL_RT:
		to->si_pid = from->si_pid;
		to->si_uid = from->si_uid;
		to->si_int = from->si_int;
		break;
	case SIL_SYS:
		to->si_call_addr = ptr_to_compat(from->si_call_addr);
		to->si_syscall   = from->si_syscall;
		to->si_arch      = from->si_arch;
		break;
	}
}

int __copy_siginfo_to_user32(struct compat_siginfo __user *to,
			   const struct kernel_siginfo *from)
{
	struct compat_siginfo new;

	copy_siginfo_to_external32(&new, from);
	if (copy_to_user(to, &new, sizeof(struct compat_siginfo)))
		return -EFAULT;
	return 0;
}

static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
					 const struct compat_siginfo *from)
{
	clear_siginfo(to);
	to->si_signo = from->si_signo;
	to->si_errno = from->si_errno;
	to->si_code  = from->si_code;
	switch(siginfo_layout(from->si_signo, from->si_code)) {
	case SIL_KILL:
		to->si_pid = from->si_pid;
		to->si_uid = from->si_uid;
		break;
	case SIL_TIMER:
		to->si_tid     = from->si_tid;
		to->si_overrun = from->si_overrun;
		to->si_int     = from->si_int;
		break;
	case SIL_POLL:
		to->si_band = from->si_band;
		to->si_fd   = from->si_fd;
		break;
	case SIL_FAULT:
		to->si_addr = compat_ptr(from->si_addr);
		break;
	case SIL_FAULT_TRAPNO:
		to->si_addr = compat_ptr(from->si_addr);
		to->si_trapno = from->si_trapno;
		break;
	case SIL_FAULT_MCEERR:
		to->si_addr = compat_ptr(from->si_addr);
		to->si_addr_lsb = from->si_addr_lsb;
		break;
	case SIL_FAULT_BNDERR:
		to->si_addr = compat_ptr(from->si_addr);
		to->si_lower = compat_ptr(from->si_lower);
		to->si_upper = compat_ptr(from->si_upper);
		break;
	case SIL_FAULT_PKUERR:
		to->si_addr = compat_ptr(from->si_addr);
		to->si_pkey = from->si_pkey;
		break;
	case SIL_FAULT_PERF_EVENT:
		to->si_addr = compat_ptr(from->si_addr);
		to->si_perf_data = from->si_perf_data;
		to->si_perf_type = from->si_perf_type;
		to->si_perf_flags = from->si_perf_flags;
		break;
	case SIL_CHLD:
		to->si_pid    = from->si_pid;
		to->si_uid    = from->si_uid;
		to->si_status = from->si_status;
#ifdef CONFIG_X86_X32_ABI
		if (in_x32_syscall()) {
			to->si_utime = from->_sifields._sigchld_x32._utime;
			to->si_stime = from->_sifields._sigchld_x32._stime;
		} else
#endif
		{
			to->si_utime = from->si_utime;
			to->si_stime = from->si_stime;
		}
		break;
	case SIL_RT:
		to->si_pid = from->si_pid;
		to->si_uid = from->si_uid;
		to->si_int = from->si_int;
		break;
	case SIL_SYS:
		to->si_call_addr = compat_ptr(from->si_call_addr);
		to->si_syscall   = from->si_syscall;
		to->si_arch      = from->si_arch;
		break;
	}
	return 0;
}

static int __copy_siginfo_from_user32(int signo, struct kernel_siginfo *to,
				      const struct compat_siginfo __user *ufrom)
{
	struct compat_siginfo from;

	if (copy_from_user(&from, ufrom, sizeof(struct compat_siginfo)))
		return -EFAULT;

	from.si_signo = signo;
	return post_copy_siginfo_from_user32(to, &from);
}

int copy_siginfo_from_user32(struct kernel_siginfo *to,
			     const struct compat_siginfo __user *ufrom)
{
	struct compat_siginfo from;

	if (copy_from_user(&from, ufrom, sizeof(struct compat_siginfo)))
		return -EFAULT;

	return post_copy_siginfo_from_user32(to, &from);
}
#endif /* CONFIG_COMPAT */

/**
 *  do_sigtimedwait - wait for queued signals specified in @which
 *  @which: queued signals to wait for
 *  @info: if non-null, the signal's siginfo is returned here
 *  @ts: upper bound on process time suspension
 */
static int do_sigtimedwait(const sigset_t *which, kernel_siginfo_t *info,
		    const struct timespec64 *ts)
{
	ktime_t *to = NULL, timeout = KTIME_MAX;
	struct task_struct *tsk = current;
	sigset_t mask = *which;
	enum pid_type type;
	int sig, ret = 0;

	if (ts) {
		if (!timespec64_valid(ts))
			return -EINVAL;
		timeout = timespec64_to_ktime(*ts);
		to = &timeout;
	}

	/*
	 * Invert the set of allowed signals to get those we want to block.
	 */
	sigdelsetmask(&mask, sigmask(SIGKILL) | sigmask(SIGSTOP));
	signotset(&mask);

	spin_lock_irq(&tsk->sighand->siglock);
	sig = dequeue_signal(&mask, info, &type);
	if (!sig && timeout) {
		/*
		 * None ready, temporarily unblock those we're interested
		 * while we are sleeping in so that we'll be awakened when
		 * they arrive. Unblocking is always fine, we can avoid
		 * set_current_blocked().
		 */
		tsk->real_blocked = tsk->blocked;
		sigandsets(&tsk->blocked, &tsk->blocked, &mask);
		recalc_sigpending();
		spin_unlock_irq(&tsk->sighand->siglock);

		__set_current_state(TASK_INTERRUPTIBLE|TASK_FREEZABLE);
		ret = schedule_hrtimeout_range(to, tsk->timer_slack_ns,
					       HRTIMER_MODE_REL);
		spin_lock_irq(&tsk->sighand->siglock);
		__set_task_blocked(tsk, &tsk->real_blocked);
		sigemptyset(&tsk->real_blocked);
		sig = dequeue_signal(&mask, info, &type);
	}
	spin_unlock_irq(&tsk->sighand->siglock);

	if (sig)
		return sig;
	return ret ? -EINTR : -EAGAIN;
}

/**
 *  sys_rt_sigtimedwait - synchronously wait for queued signals specified
 *			in @uthese
 *  @uthese: queued signals to wait for
 *  @uinfo: if non-null, the signal's siginfo is returned here
 *  @uts: upper bound on process time suspension
 *  @sigsetsize: size of sigset_t type
 */
SYSCALL_DEFINE4(rt_sigtimedwait, const sigset_t __user *, uthese,
		siginfo_t __user *, uinfo,
		const struct __kernel_timespec __user *, uts,
		size_t, sigsetsize)
{
	sigset_t these;
	struct timespec64 ts;
	kernel_siginfo_t info;
	int ret;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (copy_from_user(&these, uthese, sizeof(these)))
		return -EFAULT;

	if (uts) {
		if (get_timespec64(&ts, uts))
			return -EFAULT;
	}

	ret = do_sigtimedwait(&these, &info, uts ? &ts : NULL);

	if (ret > 0 && uinfo) {
		if (copy_siginfo_to_user(uinfo, &info))
			ret = -EFAULT;
	}

	return ret;
}

#ifdef CONFIG_COMPAT_32BIT_TIME
SYSCALL_DEFINE4(rt_sigtimedwait_time32, const sigset_t __user *, uthese,
		siginfo_t __user *, uinfo,
		const struct old_timespec32 __user *, uts,
		size_t, sigsetsize)
{
	sigset_t these;
	struct timespec64 ts;
	kernel_siginfo_t info;
	int ret;

	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (copy_from_user(&these, uthese, sizeof(these)))
		return -EFAULT;

	if (uts) {
		if (get_old_timespec32(&ts, uts))
			return -EFAULT;
	}

	ret = do_sigtimedwait(&these, &info, uts ? &ts : NULL);

	if (ret > 0 && uinfo) {
		if (copy_siginfo_to_user(uinfo, &info))
			ret = -EFAULT;
	}

	return ret;
}
#endif

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(rt_sigtimedwait_time64, compat_sigset_t __user *, uthese,
		struct compat_siginfo __user *, uinfo,
		struct __kernel_timespec __user *, uts, compat_size_t, sigsetsize)
{
	sigset_t s;
	struct timespec64 t;
	kernel_siginfo_t info;
	long ret;

	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (get_compat_sigset(&s, uthese))
		return -EFAULT;

	if (uts) {
		if (get_timespec64(&t, uts))
			return -EFAULT;
	}

	ret = do_sigtimedwait(&s, &info, uts ? &t : NULL);

	if (ret > 0 && uinfo) {
		if (copy_siginfo_to_user32(uinfo, &info))
			ret = -EFAULT;
	}

	return ret;
}

#ifdef CONFIG_COMPAT_32BIT_TIME
COMPAT_SYSCALL_DEFINE4(rt_sigtimedwait_time32, compat_sigset_t __user *, uthese,
		struct compat_siginfo __user *, uinfo,
		struct old_timespec32 __user *, uts, compat_size_t, sigsetsize)
{
	sigset_t s;
	struct timespec64 t;
	kernel_siginfo_t info;
	long ret;

	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (get_compat_sigset(&s, uthese))
		return -EFAULT;

	if (uts) {
		if (get_old_timespec32(&t, uts))
			return -EFAULT;
	}

	ret = do_sigtimedwait(&s, &info, uts ? &t : NULL);

	if (ret > 0 && uinfo) {
		if (copy_siginfo_to_user32(uinfo, &info))
			ret = -EFAULT;
	}

	return ret;
}
#endif
#endif

static void prepare_kill_siginfo(int sig, struct kernel_siginfo *info,
				 enum pid_type type)
{
	clear_siginfo(info);
	info->si_signo = sig;
	info->si_errno = 0;
	info->si_code = (type == PIDTYPE_PID) ? SI_TKILL : SI_USER;
	info->si_pid = task_tgid_vnr(current);
	info->si_uid = from_kuid_munged(current_user_ns(), current_uid());
}

/**
 * sys_kill - send a signal to a process or process group
 * @pid: target process or process group identifier
 * @sig: signal number to send, or 0 for existence/permission check
 *
 * long-desc: Sends a signal to a process or group of processes identified by
 *   @pid. The interpretation of @pid determines the signal destination:
 *
 *   - pid > 0: Signal is sent to the process with the specified process ID.
 *   - pid == 0: Signal is sent to every process in the process group of the
 *     calling process, including the caller itself.
 *   - pid == -1: Signal is sent to every process for which the caller has
 *     permission to send signals, except for process 1 (init) and the calling
 *     process itself. This is a broadcast to all accessible processes.
 *   - pid < -1: Signal is sent to every process in the process group whose
 *     PGID equals the absolute value of pid (i.e., process group -pid).
 *
 *   When @sig is 0 (the null signal), no signal is sent, but existence and
 *   permission checks are still performed. This can be used to check if a
 *   process exists and the caller has permission to signal it. Note that
 *   zombie processes are considered to exist until reaped by wait().
 *
 *   Permission to send a signal requires one of the following:
 *   1. The caller has the CAP_KILL capability in the target's user namespace.
 *   2. The caller's real or effective UID matches the target's real or saved
 *      set-user-ID.
 *
 *   Exception: SIGCONT can always be sent to any process in the same session
 *   as the caller, regardless of UID matching. This enables job control to
 *   work correctly.
 *
 *   For process groups (pid <= 0), the syscall succeeds if the signal was
 *   successfully sent to at least one member of the group. EPERM errors from
 *   individual processes are ignored as long as at least one delivery succeeds.
 *   The special case of pid == -1 excludes the calling process from receiving
 *   the signal.
 *
 *   When a process signals itself with an unblocked signal (and no other
 *   thread in the process is waiting to accept it), the signal is guaranteed
 *   to be delivered before kill() returns. This enables synchronous
 *   self-signaling patterns.
 *
 *   Special handling exists for signals sent to init (PID 1): only signals
 *   for which init has explicitly installed a handler can be delivered.
 *   SIGKILL and SIGSTOP are ignored by init unless forced by the kernel.
 *   Processes with the SIGNAL_UNKILLABLE flag (init and its descendants in
 *   certain configurations) have similar protection.
 *
 *   The signal information (siginfo_t) passed to the target's signal handler
 *   will have si_code set to SI_USER, si_pid set to the caller's thread group
 *   ID (TGID), and si_uid set to the caller's real UID. For signals sent
 *   across user namespaces, si_uid is translated appropriately.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: pid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: INT_MIN + 1, INT_MAX
 *   constraint: pid_t value interpreted as process ID, process group ID, or
 *     special broadcast value. INT_MIN is explicitly rejected to avoid
 *     undefined behavior from negation (-INT_MIN is undefined in C).
 *
 * param: sig
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, _NSIG
 *   constraint: Signal number from 0 to _NSIG (typically 64 on most
 *     architectures, 128 on MIPS). Signal 0 is the null signal used for
 *     existence/permission checking only. Standard signals are 1-31,
 *     real-time signals are SIGRTMIN (typically 32) to SIGRTMAX.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. For process groups (pid <= 0), success means
 *     the signal was delivered to at least one process in the group. For the
 *     null signal (sig == 0), success means the target exists and the caller
 *     has permission to signal it.
 *
 * error: EINVAL, Invalid signal number
 *   desc: The signal number @sig is invalid (less than 0 or greater than
 *     _NSIG, which is typically 64). Also returned if @pid equals INT_MIN,
 *     which would cause undefined behavior when negated to find the process
 *     group ID.
 *
 * error: ESRCH, No such process or process group
 *   desc: No process or process group matching @pid could be found. For
 *     pid > 0, the specified process does not exist (or is a zombie that has
 *     not yet been reaped, but note that zombies DO exist). For pid == 0,
 *     the caller's process group is empty (should never happen in practice).
 *     For pid < -1, no process group with PGID == -pid exists. For pid == -1,
 *     no process other than init and the caller exists that can be signaled.
 *     Also returned for pid == INT_MIN as a special case to avoid undefined
 *     behavior.
 *
 * error: EPERM, Permission denied
 *   desc: The caller lacks permission to signal the target. Permission requires
 *     CAP_KILL capability in the target's user namespace, or real/effective UID
 *     matching target's real/saved-set-UID. SIGCONT only requires same session.
 *     For process groups (pid <= 0), EPERM is returned only if permission was
 *     denied for ALL members; success if at least one signal was delivered.
 *
 * error: EACCES, LSM security module denied the signal
 *   desc: A Linux Security Module (SELinux, AppArmor, Smack, or Landlock)
 *     denied permission to send the signal. This occurs after standard Unix
 *     permission checks pass. SELinux maps signal types to permissions
 *     (e.g., SIGKILL requires 'sigkill' permission, SIGSTOP requires 'sigstop',
 *     sig == 0 requires 'signull' for existence checks). The specific error
 *     code may vary by LSM; some use EPERM instead of EACCES.
 *
 * error: ENOMEM, Memory allocation failed for audit record
 *   desc: The kernel could not allocate memory for an audit record. This can
 *     occur when auditing is enabled and the syscall needs to log multiple
 *     target processes (pid == -1 broadcast case). The allocation uses
 *     GFP_ATOMIC, so this error is rare but possible under memory pressure.
 *     This error is returned before any signals are sent.
 *
 * lock: tasklist_lock
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: Read lock acquired when iterating over processes for process group
 *     or broadcast signals (pid <= 0). Held while calling group_send_sig_info()
 *     for each target process. The lock protects the task list from concurrent
 *     modification during iteration.
 *
 * lock: RCU read lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is held during process lookup (find_vpid, pid_task)
 *     and permission checking (check_kill_permission). Also held briefly when
 *     accessing task credentials. Multiple acquire/release cycles may occur
 *     during syscall execution.
 *
 * lock: sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Per-process signal handler spinlock acquired via lock_task_sighand()
 *     when actually delivering the signal in do_send_sig_info(). Acquired with
 *     interrupts disabled (spin_lock_irqsave). Protects the signal queue and
 *     signal handler state during signal delivery.
 *
 * signal: Signal delivery to target
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_QUEUE
 *   condition: Valid signal number (sig > 0) and permission granted
 *   desc: The specified signal is queued to the target process's pending
 *     signal set. For standard signals (1-31), if the signal is already
 *     pending, no additional signal is queued (signals do not stack). For
 *     real-time signals (SIGRTMIN-SIGRTMAX), signals are always queued and
 *     delivered in order. The target thread is woken if necessary.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * side-effect: KAPI_EFFECT_SIGNAL_SEND
 *   target: Target process(es) identified by @pid
 *   desc: Queues the signal to the target process's pending signal set and
 *     may wake sleeping threads. For SIGKILL, all threads in the target
 *     process are woken and marked for termination. For SIGSTOP/SIGTSTP/
 *     SIGTTIN/SIGTTOU, the process group stop machinery is initiated.
 *   condition: sig > 0 and permission granted
 *   reversible: no (signal delivery cannot be undone)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE | KAPI_EFFECT_PROCESS_STATE
 *   target: Target process signal state
 *   desc: For SIGCONT, any pending stop signals (SIGSTOP, SIGTSTP, SIGTTIN,
 *     SIGTTOU) are removed from all threads' pending queues, and stopped
 *     threads are woken. For stop signals, any pending SIGCONT is removed.
 *     This mutual exclusion ensures consistent process state.
 *   condition: sig is SIGCONT or a stop signal
 *   reversible: yes (by sending the opposite signal)
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: Target process threads
 *   desc: Target threads may be woken from sleep to process the signal. For
 *     SIGKILL, all threads are woken unconditionally. For other signals,
 *     at least one thread that is not blocking the signal is woken.
 *   condition: sig > 0 and signal not ignored
 *   reversible: yes (thread eventually returns to sleep or continues)
 *
 * capability: CAP_KILL
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Sending signals to any process in the target's user namespace
 *     without requiring UID matching
 *   without: Must have real/effective UID matching target's real/saved UID,
 *     or for SIGCONT, same session membership
 *   condition: Checked in kill_ok_by_cred() via ns_capable() for each
 *     target process
 *
 * constraint: PID namespace isolation
 *   desc: The @pid argument is interpreted within the caller's PID namespace.
 *     A process can only signal processes visible in its PID namespace or
 *     child namespaces. PID translation is handled by find_vpid() and
 *     task_pid_vnr(). Cross-namespace signaling requires the target to be
 *     in a descendant PID namespace.
 *
 * constraint: Init process protection
 *   desc: The init process (PID 1) can only receive signals for which it has
 *     installed explicit signal handlers. SIGKILL and SIGSTOP sent to init
 *     are silently dropped unless the signal originates from an ancestor PID
 *     namespace. Processes with SIGNAL_UNKILLABLE flag have similar protection.
 *
 * constraint: Thread-group semantics
 *   desc: kill() sends signals to the thread group leader and the signal is
 *     shared among all threads. Use tgkill() or tkill() to target specific
 *     threads. For pid > 0, the signal is sent to the process (thread group),
 *     not to a specific thread with that TID.
 *
 * examples:
 *   kill(1234, SIGTERM);     // Send SIGTERM to process 1234
 *   kill(1234, 0);           // Check if process 1234 exists and is signalable
 *   kill(0, SIGINT);         // Send SIGINT to all processes in caller's pgrp
 *   kill(-1, SIGTERM);       // Broadcast SIGTERM to all accessible processes
 *   kill(-4567, SIGHUP);     // Send SIGHUP to process group 4567
 *
 * notes:
 *   - POSIX.1-2008 compliant. Linux semantics match System V rather than BSD
 *     for permission checking (checks saved-set-UID, not just real/effective).
 *   - The kill(-1, sig) broadcast case has a historical bug in kernels 2.6.0
 *     through 2.6.7 where EPERM was returned if ANY process could not be
 *     signaled, even though signals were delivered to permitted processes.
 *     This was fixed to return success if at least one signal was delivered.
 *   - A race condition fix in kernel 2.6.24 (commit d36174bc2bce) handles the
 *     case where a process is executing exec() while being signaled. The
 *     kill_pid_info_type() function retries if lock_task_sighand() fails due
 *     to the target being in the middle of de_thread() or __exit_signal().
 *   - For real-time signals (SIGRTMIN-SIGRTMAX) sent via kill(), the signal
 *     is queued if possible but may fall back to non-queued delivery under
 *     memory pressure. Use sigqueue() for guaranteed queuing with siginfo.
 *   - Kernel threads (PF_KTHREAD) can only receive signals from the kernel,
 *     not from user processes. Attempts to signal kernel threads silently
 *     succeed but the signal is ignored unless force is set.
 *   - The si_pid and si_uid fields in the siginfo_t delivered to the target
 *     are translated appropriately for cross-namespace signaling. If the
 *     caller's PID is not visible in the target's namespace, si_pid is set
 *     to 0.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
{
	struct kernel_siginfo info;

	prepare_kill_siginfo(sig, &info, PIDTYPE_TGID);

	return kill_something_info(sig, &info, pid);
}

/*
 * Verify that the signaler and signalee either are in the same pid namespace
 * or that the signaler's pid namespace is an ancestor of the signalee's pid
 * namespace.
 */
static bool access_pidfd_pidns(struct pid *pid)
{
	struct pid_namespace *active = task_active_pid_ns(current);
	struct pid_namespace *p = ns_of_pid(pid);

	for (;;) {
		if (!p)
			return false;
		if (p == active)
			break;
		p = p->parent;
	}

	return true;
}

static int copy_siginfo_from_user_any(kernel_siginfo_t *kinfo,
		siginfo_t __user *info)
{
#ifdef CONFIG_COMPAT
	/*
	 * Avoid hooking up compat syscalls and instead handle necessary
	 * conversions here. Note, this is a stop-gap measure and should not be
	 * considered a generic solution.
	 */
	if (in_compat_syscall())
		return copy_siginfo_from_user32(
			kinfo, (struct compat_siginfo __user *)info);
#endif
	return copy_siginfo_from_user(kinfo, info);
}

static struct pid *pidfd_to_pid(const struct file *file)
{
	struct pid *pid;

	pid = pidfd_pid(file);
	if (!IS_ERR(pid))
		return pid;

	return tgid_pidfd_to_pid(file);
}

#define PIDFD_SEND_SIGNAL_FLAGS                            \
	(PIDFD_SIGNAL_THREAD | PIDFD_SIGNAL_THREAD_GROUP | \
	 PIDFD_SIGNAL_PROCESS_GROUP)

static int do_pidfd_send_signal(struct pid *pid, int sig, enum pid_type type,
				siginfo_t __user *info, unsigned int flags)
{
	kernel_siginfo_t kinfo;

	switch (flags) {
	case PIDFD_SIGNAL_THREAD:
		type = PIDTYPE_PID;
		break;
	case PIDFD_SIGNAL_THREAD_GROUP:
		type = PIDTYPE_TGID;
		break;
	case PIDFD_SIGNAL_PROCESS_GROUP:
		type = PIDTYPE_PGID;
		break;
	}

	if (info) {
		int ret;

		ret = copy_siginfo_from_user_any(&kinfo, info);
		if (unlikely(ret))
			return ret;

		if (unlikely(sig != kinfo.si_signo))
			return -EINVAL;

		/* Only allow sending arbitrary signals to yourself. */
		if ((task_pid(current) != pid || type > PIDTYPE_TGID) &&
		    (kinfo.si_code >= 0 || kinfo.si_code == SI_TKILL))
			return -EPERM;
	} else {
		prepare_kill_siginfo(sig, &kinfo, type);
	}

	if (type == PIDTYPE_PGID)
		return kill_pgrp_info(sig, &kinfo, pid);

	return kill_pid_info_type(sig, &kinfo, pid, type);
}

/**
 * sys_pidfd_send_signal - Signal a process through a pidfd
 * @pidfd:  file descriptor of the process
 * @sig:    signal to send
 * @info:   signal info
 * @flags:  future flags
 *
 * Send the signal to the thread group or to the individual thread depending
 * on PIDFD_THREAD.
 * In the future extension to @flags may be used to override the default scope
 * of @pidfd.
 *
 * Return: 0 on success, negative errno on failure
 */
SYSCALL_DEFINE4(pidfd_send_signal, int, pidfd, int, sig,
		siginfo_t __user *, info, unsigned int, flags)
{
	struct pid *pid;
	enum pid_type type;
	int ret;

	/* Enforce flags be set to 0 until we add an extension. */
	if (flags & ~PIDFD_SEND_SIGNAL_FLAGS)
		return -EINVAL;

	/* Ensure that only a single signal scope determining flag is set. */
	if (hweight32(flags & PIDFD_SEND_SIGNAL_FLAGS) > 1)
		return -EINVAL;

	switch (pidfd) {
	case PIDFD_SELF_THREAD:
		pid = get_task_pid(current, PIDTYPE_PID);
		type = PIDTYPE_PID;
		break;
	case PIDFD_SELF_THREAD_GROUP:
		pid = get_task_pid(current, PIDTYPE_TGID);
		type = PIDTYPE_TGID;
		break;
	default: {
		CLASS(fd, f)(pidfd);
		if (fd_empty(f))
			return -EBADF;

		/* Is this a pidfd? */
		pid = pidfd_to_pid(fd_file(f));
		if (IS_ERR(pid))
			return PTR_ERR(pid);

		if (!access_pidfd_pidns(pid))
			return -EINVAL;

		/* Infer scope from the type of pidfd. */
		if (fd_file(f)->f_flags & PIDFD_THREAD)
			type = PIDTYPE_PID;
		else
			type = PIDTYPE_TGID;

		return do_pidfd_send_signal(pid, sig, type, info, flags);
	}
	}

	ret = do_pidfd_send_signal(pid, sig, type, info, flags);
	put_pid(pid);

	return ret;
}

static int
do_send_specific(pid_t tgid, pid_t pid, int sig, struct kernel_siginfo *info)
{
	struct task_struct *p;
	int error = -ESRCH;

	rcu_read_lock();
	p = find_task_by_vpid(pid);
	if (p && (tgid <= 0 || task_tgid_vnr(p) == tgid)) {
		error = check_kill_permission(sig, info, p);
		/*
		 * The null signal is a permissions and process existence
		 * probe.  No signal is actually delivered.
		 */
		if (!error && sig) {
			error = do_send_sig_info(sig, info, p, PIDTYPE_PID);
			/*
			 * If lock_task_sighand() failed we pretend the task
			 * dies after receiving the signal. The window is tiny,
			 * and the signal is private anyway.
			 */
			if (unlikely(error == -ESRCH))
				error = 0;
		}
	}
	rcu_read_unlock();

	return error;
}

static int do_tkill(pid_t tgid, pid_t pid, int sig)
{
	struct kernel_siginfo info;

	prepare_kill_siginfo(sig, &info, PIDTYPE_PID);

	return do_send_specific(tgid, pid, sig, &info);
}

/**
 * sys_tgkill - send signal to one specific thread with thread group verification
 * @tgid: the thread group ID (process ID) containing the target thread
 * @pid: the thread ID (TID) of the target thread within the thread group
 * @sig: signal number to send, or 0 for existence/permission check
 *
 * long-desc: Sends a signal to a specific thread identified by both its thread
 *   group ID (TGID, which is the process ID) and its thread ID (TID). This
 *   syscall provides a race-condition-free alternative to tkill() by verifying
 *   that the target thread still belongs to the expected thread group before
 *   delivering the signal.
 *
 *   The key advantage over tkill() is protection against TID recycling: if a
 *   thread terminates and its TID is assigned to a new thread in a different
 *   process, tgkill() will return -ESRCH because the TGID won't match. This
 *   prevents accidentally signaling unintended targets.
 *
 *   The signal is delivered directly to the specified thread's private pending
 *   signal queue (not the process-wide shared queue). The signal information
 *   (siginfo_t) passed to the target's signal handler will have si_code set
 *   to SI_TKILL (-6), si_pid set to the caller's thread group ID (TGID), and
 *   si_uid set to the caller's real UID.
 *
 *   When @sig is 0 (the null signal), no signal is sent, but existence and
 *   permission checks are still performed. This can be used to verify that
 *   a thread exists in the specified thread group and the caller has
 *   permission to signal it.
 *
 *   Permission to send a signal requires one of the following:
 *   1. The caller and target are in the same thread group (same process).
 *   2. The caller has the CAP_KILL capability in the target's user namespace.
 *   3. The caller's real or effective UID matches the target's real or saved
 *      set-user-ID.
 *
 *   Exception: SIGCONT can always be sent to any thread in the same session
 *   as the caller, regardless of UID matching.
 *
 *   For standard signals (1-31), if the same signal is already pending for
 *   the target thread, no additional signal is queued (standard signals do
 *   not stack). For real-time signals (SIGRTMIN to SIGRTMAX), each signal
 *   is queued individually and delivered in order, subject to the
 *   RLIMIT_SIGPENDING resource limit.
 *
 *   This syscall is the preferred method for thread-directed signal delivery
 *   and is used internally by pthread_kill() and pthread_cancel() in glibc's
 *   NPTL implementation.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: tgid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 1, PID_MAX_LIMIT
 *   constraint: Thread group ID (TGID/PID) of the process containing the target
 *     thread. Must be a positive integer; values <= 0 are rejected with EINVAL.
 *     The TGID is interpreted within the caller's PID namespace. For a
 *     single-threaded process, the TGID equals the process's PID. For
 *     multi-threaded processes, the TGID equals the PID of the thread group
 *     leader (the initial thread that called clone() to create other threads).
 *
 * param: pid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 1, PID_MAX_LIMIT
 *   constraint: Thread ID (TID) of the target thread within the thread group.
 *     Must be a positive integer; values <= 0 are rejected with EINVAL.
 *     The TID is interpreted within the caller's PID namespace. Note: despite
 *     the parameter name "pid", this is semantically a TID. For single-threaded
 *     processes, TID equals TGID. For multi-threaded processes, each thread
 *     has a unique TID assigned at creation via clone().
 *
 * param: sig
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, _NSIG
 *   constraint: Signal number from 0 to _NSIG (typically 64). Signal 0 is
 *     the null signal used for existence/permission checking only. Standard
 *     signals are 1-31, real-time signals are SIGRTMIN (32) to SIGRTMAX (64).
 *     Invalid signal numbers cause EINVAL to be returned.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success, indicating the signal was successfully queued
 *     for delivery to the target thread (or for sig == 0, that the thread
 *     exists in the specified thread group and is signalable). Note that
 *     success does not guarantee the signal will be delivered; the target
 *     may have blocked or ignored it, or may be an init process protected
 *     from signals it hasn't explicitly handled.
 *
 * error: EINVAL, Invalid thread group ID, thread ID, or signal number
 *   desc: Returned if @tgid is less than or equal to 0, if @pid is less than
 *     or equal to 0, or if @sig is greater than _NSIG (typically 64). Both
 *     @tgid and @pid must be valid positive identifiers. Unlike kill(),
 *     tgkill() does not accept special values like -1 or process group IDs.
 *
 * error: ESRCH, No such thread or thread group mismatch
 *   desc: Returned in one of these conditions: (1) No thread with the
 *     specified TID exists in the caller's PID namespace. (2) A thread with
 *     the specified TID exists but does not belong to the thread group
 *     identified by @tgid. This second case is the key protection tgkill()
 *     provides against TID recycling races. The thread may have terminated
 *     and its TID recycled to a thread in a different process.
 *
 * error: EPERM, Permission denied
 *   desc: The caller lacks permission to signal the target thread. Permission
 *     requires either: (1) being in the same thread group, (2) CAP_KILL
 *     capability in the target's user namespace, or (3) real/effective UID
 *     matching target's real/saved-set-UID. For SIGCONT, same session
 *     membership is also sufficient. This error is returned after verifying
 *     the thread exists in the specified thread group but before attempting
 *     signal delivery.
 *
 * error: EACCES, LSM security module denied the signal
 *   desc: A Linux Security Module (SELinux, AppArmor, Smack, or Landlock)
 *     denied permission to send the signal via the security_task_kill() hook.
 *     This check occurs after standard Unix permission checks pass. The
 *     specific error code may vary by LSM; some modules use EPERM instead.
 *
 * error: EAGAIN, Signal queue limit exceeded
 *   desc: The target thread's pending signal queue is full, exceeding the
 *     RLIMIT_SIGPENDING resource limit. This error only occurs for real-time
 *     signals (SIGRTMIN to SIGRTMAX) that must be queued. Standard signals
 *     (1-31) never return EAGAIN; they either coalesce with an existing
 *     pending signal or are delivered without queueing additional siginfo.
 *     Also returned if kernel memory allocation for the signal queue entry
 *     fails under memory pressure.
 *
 * error: ENOMEM, Audit subsystem memory allocation failed
 *   desc: When audit is enabled, the kernel may need to allocate memory to
 *     record signal delivery information. If this allocation fails, -ENOMEM
 *     is returned. This is rare and only occurs when: (1) audit is enabled,
 *     (2) multiple target PIDs are being tracked in a single syscall context,
 *     and (3) kernel memory is exhausted. Most tgkill() calls will not
 *     encounter this error.
 *
 * lock: RCU read lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is held during thread lookup via find_task_by_vpid()
 *     and during permission checking in check_kill_permission(). Also held
 *     when accessing task credentials. The lock is held across both the
 *     lookup and permission check phases but released before signal delivery.
 *     Protects against task_struct being freed during lookup.
 *
 * lock: sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Per-thread signal handler spinlock acquired via lock_task_sighand()
 *     when delivering the signal in do_send_sig_info(). Acquired with
 *     interrupts disabled (spin_lock_irqsave). Protects the pending signal
 *     queue and signal handler state. If this lock cannot be acquired (thread
 *     exiting with sighand == NULL), the syscall succeeds anyway as the thread
 *     is considered to have received the signal just before termination.
 *
 * signal: Signal delivery to target thread
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_QUEUE
 *   condition: Valid signal number (sig > 0) and permission granted
 *   desc: The specified signal is queued to the target thread's private
 *     pending signal queue (not the process-wide shared queue). The siginfo_t
 *     has si_code set to SI_TKILL, si_pid set to caller's TGID, and si_uid
 *     set to caller's real UID. The target thread is woken if it was sleeping
 *     in an interruptible state and the signal is not blocked.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * side-effect: KAPI_EFFECT_SIGNAL_SEND
 *   target: Target thread identified by @tgid:@pid
 *   desc: Queues the signal to the target thread's pending signal set and
 *     may wake the thread. For SIGKILL, the thread is woken unconditionally
 *     and marked for termination (though only affects the specific thread,
 *     not the entire process unless sent to all threads). For SIGSTOP and
 *     other stop signals, process group stop machinery may be initiated.
 *   condition: sig > 0 and permission granted
 *   reversible: no (signal delivery cannot be undone once queued)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE | KAPI_EFFECT_PROCESS_STATE
 *   target: Target thread signal state
 *   desc: For SIGCONT, any pending stop signals (SIGSTOP, SIGTSTP, SIGTTIN,
 *     SIGTTOU) are removed from both the thread's private queue and the
 *     process shared queue. For stop signals, any pending SIGCONT is removed.
 *     This mutual exclusion ensures consistent thread/process state.
 *   condition: sig is SIGCONT or a stop signal
 *   reversible: yes (by sending the opposite signal)
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: Target thread
 *   desc: The target thread may be woken from interruptible sleep to process
 *     the signal. For SIGKILL or SIGSTOP, the thread is woken unconditionally.
 *     For other signals, the thread is woken only if the signal is not blocked
 *     and not ignored. Uses signal_wake_up() internally.
 *   condition: sig > 0 and signal not blocked/ignored
 *   reversible: yes (thread returns to prior state after signal handling)
 *
 * capability: CAP_KILL
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Sending signals to any thread in the target's user namespace
 *     without requiring UID matching or same-thread-group membership
 *   without: Must be in same thread group, or have real/effective UID matching
 *     target's real/saved UID, or for SIGCONT, same session membership
 *   condition: Checked in kill_ok_by_cred() via ns_capable() against the
 *     target thread's user namespace
 *
 * constraint: PID namespace isolation
 *   desc: Both @tgid and @pid arguments are interpreted within the caller's
 *     PID namespace. A thread can only signal threads visible in its PID
 *     namespace or descendant namespaces. PID/TID translation is handled by
 *     find_task_by_vpid() and task_tgid_vnr(). Cross-namespace signaling
 *     requires the target to be in the caller's namespace or a descendant.
 *
 * constraint: Init process protection
 *   desc: The init process (PID 1) and threads within container init processes
 *     can only receive signals for which they have installed explicit handlers.
 *     SIGKILL and SIGSTOP sent to init threads are silently dropped unless
 *     forced by the kernel or sent from an ancestor PID namespace. Threads
 *     with the SIGNAL_UNKILLABLE flag have similar protection.
 *
 * constraint: RLIMIT_SIGPENDING for real-time signals
 *   desc: For real-time signals (SIGRTMIN-SIGRTMAX), the number of pending
 *     signals is limited by the sender's RLIMIT_SIGPENDING resource limit.
 *     When this limit is exceeded, sigqueue_alloc() fails and -EAGAIN is
 *     returned. Standard signals bypass this limit by coalescing with
 *     existing pending signals of the same type.
 *
 * examples:
 *   tgkill(getpid(), gettid(), SIGUSR1);  // Signal self (always safe)
 *   tgkill(child_pid, child_tid, SIGTERM); // Signal specific child thread
 *   tgkill(tgid, tid, 0);  // Check if thread exists in thread group
 *   tgkill(1, 1, SIGTERM); // Signal init (requires CAP_KILL or UID match)
 *
 * notes:
 *   - RECOMMENDED: Always use tgkill() instead of tkill() to avoid TID
 *     recycling race conditions. The tgkill() syscall verifies both the
 *     thread group ID and thread ID before delivering the signal.
 *   - Available since Linux 2.5.75. Glibc wrapper added in version 2.30.
 *   - Linux-specific; not portable to other Unix systems; not POSIX.
 *   - The pthread_kill() and pthread_cancel() functions in glibc internally
 *     use tgkill(), not tkill().
 *   - A kernel memory info leak via tkill/tgkill was fixed in commit
 *     b9e146d8eb3b9 (kernel 3.10): the si_ptr field could leak kernel memory
 *     to compat (32-bit) processes receiving signals from 64-bit processes.
 *   - For kernel threads (PF_KTHREAD), signals are silently ignored unless
 *     the kernel explicitly enables signal handling for that thread.
 *   - When the target thread is in the middle of exec() via de_thread(), the
 *     signal may be delivered to the new thread group leader instead.
 *   - If lock_task_sighand() fails because the thread is exiting, the syscall
 *     returns success (0) as the thread is considered to have received the
 *     signal just before death.
 *   - Real-time signals sent via tgkill() include full siginfo (unlike kill()
 *     which may drop siginfo under memory pressure for RT signals).
 *   - The original design goal (LWN 2003) was that tgkill could theoretically
 *     replace kill() and tkill() using special -1 values, but this flexibility
 *     was not implemented; both tgid and pid must be positive.
 *
 * since-version: 2.5.75
 */
SYSCALL_DEFINE3(tgkill, pid_t, tgid, pid_t, pid, int, sig)
{
	/* This is only valid for single tasks */
	if (pid <= 0 || tgid <= 0)
		return -EINVAL;

	return do_tkill(tgid, pid, sig);
}

/**
 * sys_tkill - send signal to one specific thread (obsolete)
 * @pid: the thread ID (TID) of the target thread
 * @sig: signal number to send, or 0 for existence/permission check
 *
 * long-desc: Sends a signal to a specific thread identified by its thread ID
 *   (TID). Unlike kill(), which signals an entire process (thread group),
 *   tkill() targets a single thread within a potentially multi-threaded
 *   process. The signal is delivered directly to the specified thread's
 *   private pending signal queue, not the shared process-wide queue.
 *
 *   WARNING: This syscall is OBSOLETE and has a critical race condition.
 *   If a thread terminates and its TID is recycled to a new thread before
 *   the tkill() call completes, the signal may be delivered to the wrong
 *   thread. Use tgkill() instead, which requires both the thread group ID
 *   (TGID) and thread ID (TID), preventing this race condition.
 *
 *   When @sig is 0 (the null signal), no signal is sent, but existence and
 *   permission checks are still performed. This can be used to verify that
 *   a thread exists and the caller has permission to signal it.
 *
 *   Permission to send a signal requires one of the following:
 *   1. The caller and target are in the same thread group (same process).
 *   2. The caller has the CAP_KILL capability in the target's user namespace.
 *   3. The caller's real or effective UID matches the target's real or saved
 *      set-user-ID.
 *
 *   Exception: SIGCONT can always be sent to any thread in the same session
 *   as the caller, regardless of UID matching.
 *
 *   The signal information (siginfo_t) passed to the target's signal handler
 *   will have si_code set to SI_TKILL (-6), si_pid set to the caller's thread
 *   group ID (TGID), and si_uid set to the caller's real UID. This allows the
 *   signal handler to distinguish tkill() signals from kill() signals (which
 *   use SI_USER).
 *
 *   For standard signals (1-31), if the same signal is already pending for
 *   the target thread, no additional signal is queued (standard signals do
 *   not stack). For real-time signals (SIGRTMIN to SIGRTMAX), each signal
 *   is queued individually and delivered in order, subject to the
 *   RLIMIT_SIGPENDING resource limit.
 *
 *   This syscall is intended for internal use by thread libraries (such as
 *   NPTL) and is not typically called directly by applications. The pthread
 *   library uses tgkill() internally for pthread_kill() and pthread_cancel().
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: pid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 1, PID_MAX_LIMIT
 *   constraint: Thread ID (TID) of the target thread. Despite the parameter
 *     name, this is interpreted as a TID, not a PID. Must be a positive
 *     integer; values <= 0 are rejected with EINVAL. The TID is interpreted
 *     within the caller's PID namespace.
 *
 * param: sig
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, _NSIG
 *   constraint: Signal number from 0 to _NSIG (typically 64). Signal 0 is
 *     the null signal used for existence/permission checking only. Standard
 *     signals are 1-31, real-time signals are SIGRTMIN (32) to SIGRTMAX (64).
 *     Invalid signal numbers cause EINVAL to be returned.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success, indicating the signal was successfully queued
 *     for delivery to the target thread (or for sig == 0, that the thread
 *     exists and is signalable). Note that success does not guarantee the
 *     signal will be delivered; the target may have blocked or ignored it.
 *
 * error: EINVAL, Invalid thread ID or signal number
 *   desc: Returned if @pid is less than or equal to 0, or if @sig is greater
 *     than _NSIG (typically 64). The @pid parameter must be a valid positive
 *     thread ID. Note that unlike kill(), tkill() does not accept process
 *     group IDs or special values like -1.
 *
 * error: ESRCH, No such thread
 *   desc: No thread with the specified TID exists in the caller's PID
 *     namespace. The thread may have terminated, or the TID may never have
 *     existed. Note that due to TID recycling, this error does not guarantee
 *     the original target thread has terminated; another thread may have
 *     been assigned the same TID. Also returned if lock_task_sighand() fails
 *     because the target thread is in the process of exiting, though this
 *     is treated as success (signal delivered just before death).
 *
 * error: EPERM, Permission denied
 *   desc: The caller lacks permission to signal the target thread. Permission
 *     requires either: (1) being in the same thread group, (2) CAP_KILL
 *     capability in the target's user namespace, or (3) real/effective UID
 *     matching target's real/saved-set-UID. For SIGCONT, same session
 *     membership is also sufficient. This error is returned after verifying
 *     the thread exists but before attempting signal delivery.
 *
 * error: EACCES, LSM security module denied the signal
 *   desc: A Linux Security Module (SELinux, AppArmor, Smack, or Landlock)
 *     denied permission to send the signal via the security_task_kill() hook.
 *     This check occurs after standard Unix permission checks pass. The
 *     specific error code may vary by LSM; some modules use EPERM instead.
 *
 * error: EAGAIN, Signal queue limit exceeded
 *   desc: The target thread's pending signal queue is full, exceeding the
 *     RLIMIT_SIGPENDING resource limit. This error only occurs for real-time
 *     signals (SIGRTMIN to SIGRTMAX) that must be queued. Standard signals
 *     (1-31) never return EAGAIN; they either coalesce with an existing
 *     pending signal or are delivered without queueing additional siginfo.
 *     Also returned if kernel memory allocation for the signal queue entry
 *     fails under memory pressure.
 *
 * lock: RCU read lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is held during thread lookup via find_task_by_vpid()
 *     and during permission checking in check_kill_permission(). Also held
 *     when accessing task credentials. The lock is held across both the
 *     lookup and permission check phases but released before signal delivery.
 *
 * lock: sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Per-thread signal handler spinlock acquired via lock_task_sighand()
 *     when delivering the signal in do_send_sig_info(). Acquired with
 *     interrupts disabled (spin_lock_irqsave). Protects the pending signal
 *     queue and signal handler state. If this lock cannot be acquired (thread
 *     exiting), the syscall succeeds anyway as the thread is considered to
 *     have received the signal just before termination.
 *
 * signal: Signal delivery to target thread
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_QUEUE
 *   condition: Valid signal number (sig > 0) and permission granted
 *   desc: The specified signal is queued to the target thread's private
 *     pending signal queue (not the process-wide shared queue). The siginfo_t
 *     has si_code set to SI_TKILL, si_pid set to caller's TGID, and si_uid
 *     set to caller's real UID. The target thread is woken if it was sleeping
 *     in an interruptible state and the signal is not blocked.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * side-effect: KAPI_EFFECT_SIGNAL_SEND
 *   target: Target thread identified by @pid
 *   desc: Queues the signal to the target thread's pending signal set and
 *     may wake the thread. For SIGKILL, the thread is woken unconditionally
 *     and marked for termination (though only affects the specific thread,
 *     not the entire process unless sent to all threads). For SIGSTOP and
 *     other stop signals, process group stop machinery may be initiated.
 *   condition: sig > 0 and permission granted
 *   reversible: no (signal delivery cannot be undone once queued)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE | KAPI_EFFECT_PROCESS_STATE
 *   target: Target thread signal state
 *   desc: For SIGCONT, any pending stop signals (SIGSTOP, SIGTSTP, SIGTTIN,
 *     SIGTTOU) are removed from the thread's pending queue. For stop signals,
 *     any pending SIGCONT is removed. This mutual exclusion ensures consistent
 *     thread/process state.
 *   condition: sig is SIGCONT or a stop signal
 *   reversible: yes (by sending the opposite signal)
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: Target thread
 *   desc: The target thread may be woken from interruptible sleep to process
 *     the signal. For SIGKILL or SIGSTOP, the thread is woken unconditionally.
 *     For other signals, the thread is woken only if the signal is not blocked
 *     and not ignored.
 *   condition: sig > 0 and signal not blocked/ignored
 *   reversible: yes (thread returns to prior state after signal handling)
 *
 * capability: CAP_KILL
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Sending signals to any thread in the target's user namespace
 *     without requiring UID matching or same-thread-group membership
 *   without: Must be in same thread group, or have real/effective UID matching
 *     target's real/saved UID, or for SIGCONT, same session membership
 *   condition: Checked in kill_ok_by_cred() via ns_capable() against the
 *     target thread's user namespace
 *
 * constraint: PID namespace isolation
 *   desc: The @pid argument is interpreted within the caller's PID namespace.
 *     A thread can only signal threads visible in its PID namespace or
 *     descendant namespaces. PID/TID translation is handled by
 *     find_task_by_vpid(). Cross-namespace signaling requires the target to
 *     be in the caller's namespace or a descendant namespace.
 *
 * constraint: Init process protection
 *   desc: The init process (PID 1) and threads within container init processes
 *     can only receive signals for which they have installed explicit handlers.
 *     SIGKILL and SIGSTOP sent to init threads are silently dropped unless
 *     forced by the kernel or sent from an ancestor PID namespace. Threads
 *     with the SIGNAL_UNKILLABLE flag have similar protection.
 *
 * constraint: TID recycling race condition
 *   desc: CRITICAL: There is an inherent race condition in tkill(). Between
 *     obtaining a TID (e.g., via clone() return value or /proc) and calling
 *     tkill(), the target thread may terminate and its TID may be assigned
 *     to a completely different thread. This can result in signaling an
 *     unintended target. The tgkill() syscall solves this by requiring both
 *     TGID and TID; if they don't match, -ESRCH is returned. Always prefer
 *     tgkill() over tkill() for thread-directed signals.
 *
 * examples:
 *   tkill(12345, SIGTERM);   // Send SIGTERM to thread 12345 (UNSAFE)
 *   tkill(12345, 0);         // Check if thread 12345 exists and is signalable
 *   tkill(gettid(), SIGUSR1); // Send SIGUSR1 to self (safe, same thread)
 *
 * notes:
 *   - OBSOLETE: This syscall has a race condition and should not be used.
 *     Use tgkill(tgid, tid, sig) instead, which verifies both thread group
 *     ID and thread ID before delivering the signal.
 *   - Available since Linux 2.4.19 (2.4 stable) and 2.5.4 (2.5 development).
 *   - No glibc wrapper is provided; must be called via syscall(SYS_tkill, ...).
 *   - Linux-specific; not portable to other Unix systems.
 *   - The pthread_kill() function in glibc internally uses tgkill(), not tkill().
 *   - A kernel memory info leak via tkill/tgkill was fixed in commit
 *     b9e146d8eb3b9 (kernel 3.10): the si_ptr field could leak kernel memory
 *     to compat (32-bit) processes receiving signals from 64-bit processes.
 *   - For kernel threads (PF_KTHREAD), signals are silently ignored unless
 *     the kernel explicitly enables signal handling for that thread.
 *   - When the target thread is in the middle of exec() via de_thread(), the
 *     signal may be delivered to the new thread group leader instead.
 *   - Real-time signals sent via tkill() include full siginfo (unlike kill()
 *     which may drop siginfo under memory pressure for RT signals).
 *
 * since-version: 2.4.19
 */
SYSCALL_DEFINE2(tkill, pid_t, pid, int, sig)
{
	/* This is only valid for single tasks */
	if (pid <= 0)
		return -EINVAL;

	return do_tkill(0, pid, sig);
}

static int do_rt_sigqueueinfo(pid_t pid, int sig, kernel_siginfo_t *info)
{
	/* Not even root can pretend to send signals from the kernel.
	 * Nor can they impersonate a kill()/tgkill(), which adds source info.
	 */
	if ((info->si_code >= 0 || info->si_code == SI_TKILL) &&
	    (task_pid_vnr(current) != pid))
		return -EPERM;

	/* POSIX.1b doesn't mention process groups.  */
	return kill_proc_info(sig, info, pid);
}

/**
 *  sys_rt_sigqueueinfo - send signal information to a signal
 *  @pid: the PID of the thread
 *  @sig: signal to be sent
 *  @uinfo: signal info to be sent
 */
SYSCALL_DEFINE3(rt_sigqueueinfo, pid_t, pid, int, sig,
		siginfo_t __user *, uinfo)
{
	kernel_siginfo_t info;
	int ret = __copy_siginfo_from_user(sig, &info, uinfo);
	if (unlikely(ret))
		return ret;
	return do_rt_sigqueueinfo(pid, sig, &info);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE3(rt_sigqueueinfo,
			compat_pid_t, pid,
			int, sig,
			struct compat_siginfo __user *, uinfo)
{
	kernel_siginfo_t info;
	int ret = __copy_siginfo_from_user32(sig, &info, uinfo);
	if (unlikely(ret))
		return ret;
	return do_rt_sigqueueinfo(pid, sig, &info);
}
#endif

static int do_rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig, kernel_siginfo_t *info)
{
	/* This is only valid for single tasks */
	if (pid <= 0 || tgid <= 0)
		return -EINVAL;

	/* Not even root can pretend to send signals from the kernel.
	 * Nor can they impersonate a kill()/tgkill(), which adds source info.
	 */
	if ((info->si_code >= 0 || info->si_code == SI_TKILL) &&
	    (task_pid_vnr(current) != pid))
		return -EPERM;

	return do_send_specific(tgid, pid, sig, info);
}

SYSCALL_DEFINE4(rt_tgsigqueueinfo, pid_t, tgid, pid_t, pid, int, sig,
		siginfo_t __user *, uinfo)
{
	kernel_siginfo_t info;
	int ret = __copy_siginfo_from_user(sig, &info, uinfo);
	if (unlikely(ret))
		return ret;
	return do_rt_tgsigqueueinfo(tgid, pid, sig, &info);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(rt_tgsigqueueinfo,
			compat_pid_t, tgid,
			compat_pid_t, pid,
			int, sig,
			struct compat_siginfo __user *, uinfo)
{
	kernel_siginfo_t info;
	int ret = __copy_siginfo_from_user32(sig, &info, uinfo);
	if (unlikely(ret))
		return ret;
	return do_rt_tgsigqueueinfo(tgid, pid, sig, &info);
}
#endif

/*
 * For kthreads only, must not be used if cloned with CLONE_SIGHAND
 */
void kernel_sigaction(int sig, __sighandler_t action)
{
	spin_lock_irq(&current->sighand->siglock);
	current->sighand->action[sig - 1].sa.sa_handler = action;
	if (action == SIG_IGN) {
		sigset_t mask;

		sigemptyset(&mask);
		sigaddset(&mask, sig);

		flush_sigqueue_mask(current, &mask, &current->signal->shared_pending);
		flush_sigqueue_mask(current, &mask, &current->pending);
		recalc_sigpending();
	}
	spin_unlock_irq(&current->sighand->siglock);
}
EXPORT_SYMBOL(kernel_sigaction);

void __weak sigaction_compat_abi(struct k_sigaction *act,
		struct k_sigaction *oact)
{
}

int do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact)
{
	struct task_struct *p = current, *t;
	struct k_sigaction *k;
	sigset_t mask;

	if (!valid_signal(sig) || sig < 1 || (act && sig_kernel_only(sig)))
		return -EINVAL;

	k = &p->sighand->action[sig-1];

	spin_lock_irq(&p->sighand->siglock);
	if (k->sa.sa_flags & SA_IMMUTABLE) {
		spin_unlock_irq(&p->sighand->siglock);
		return -EINVAL;
	}
	if (oact)
		*oact = *k;

	/*
	 * Make sure that we never accidentally claim to support SA_UNSUPPORTED,
	 * e.g. by having an architecture use the bit in their uapi.
	 */
	BUILD_BUG_ON(UAPI_SA_FLAGS & SA_UNSUPPORTED);

	/*
	 * Clear unknown flag bits in order to allow userspace to detect missing
	 * support for flag bits and to allow the kernel to use non-uapi bits
	 * internally.
	 */
	if (act)
		act->sa.sa_flags &= UAPI_SA_FLAGS;
	if (oact)
		oact->sa.sa_flags &= UAPI_SA_FLAGS;

	sigaction_compat_abi(act, oact);

	if (act) {
		bool was_ignored = k->sa.sa_handler == SIG_IGN;

		sigdelsetmask(&act->sa.sa_mask,
			      sigmask(SIGKILL) | sigmask(SIGSTOP));
		*k = *act;
		/*
		 * POSIX 3.3.1.3:
		 *  "Setting a signal action to SIG_IGN for a signal that is
		 *   pending shall cause the pending signal to be discarded,
		 *   whether or not it is blocked."
		 *
		 *  "Setting a signal action to SIG_DFL for a signal that is
		 *   pending and whose default action is to ignore the signal
		 *   (for example, SIGCHLD), shall cause the pending signal to
		 *   be discarded, whether or not it is blocked"
		 */
		if (sig_handler_ignored(sig_handler(p, sig), sig)) {
			sigemptyset(&mask);
			sigaddset(&mask, sig);
			flush_sigqueue_mask(p, &mask, &p->signal->shared_pending);
			for_each_thread(p, t)
				flush_sigqueue_mask(p, &mask, &t->pending);
		} else if (was_ignored) {
			posixtimer_sig_unignore(p, sig);
		}
	}

	spin_unlock_irq(&p->sighand->siglock);
	return 0;
}

#ifdef CONFIG_DYNAMIC_SIGFRAME
static inline void sigaltstack_lock(void)
	__acquires(&current->sighand->siglock)
{
	spin_lock_irq(&current->sighand->siglock);
}

static inline void sigaltstack_unlock(void)
	__releases(&current->sighand->siglock)
{
	spin_unlock_irq(&current->sighand->siglock);
}
#else
static inline void sigaltstack_lock(void) { }
static inline void sigaltstack_unlock(void) { }
#endif

static int
do_sigaltstack (const stack_t *ss, stack_t *oss, unsigned long sp,
		size_t min_ss_size)
{
	struct task_struct *t = current;
	int ret = 0;

	if (oss) {
		memset(oss, 0, sizeof(stack_t));
		oss->ss_sp = (void __user *) t->sas_ss_sp;
		oss->ss_size = t->sas_ss_size;
		oss->ss_flags = sas_ss_flags(sp) |
			(current->sas_ss_flags & SS_FLAG_BITS);
	}

	if (ss) {
		void __user *ss_sp = ss->ss_sp;
		size_t ss_size = ss->ss_size;
		unsigned ss_flags = ss->ss_flags;
		int ss_mode;

		if (unlikely(on_sig_stack(sp)))
			return -EPERM;

		ss_mode = ss_flags & ~SS_FLAG_BITS;
		if (unlikely(ss_mode != SS_DISABLE && ss_mode != SS_ONSTACK &&
				ss_mode != 0))
			return -EINVAL;

		/*
		 * Return before taking any locks if no actual
		 * sigaltstack changes were requested.
		 */
		if (t->sas_ss_sp == (unsigned long)ss_sp &&
		    t->sas_ss_size == ss_size &&
		    t->sas_ss_flags == ss_flags)
			return 0;

		sigaltstack_lock();
		if (ss_mode == SS_DISABLE) {
			ss_size = 0;
			ss_sp = NULL;
		} else {
			if (unlikely(ss_size < min_ss_size))
				ret = -ENOMEM;
			if (!sigaltstack_size_valid(ss_size))
				ret = -ENOMEM;
		}
		if (!ret) {
			t->sas_ss_sp = (unsigned long) ss_sp;
			t->sas_ss_size = ss_size;
			t->sas_ss_flags = ss_flags;
		}
		sigaltstack_unlock();
	}
	return ret;
}

/**
 * sys_sigaltstack - set and/or get alternate signal stack context
 * @uss: Pointer to new alternate signal stack configuration, or NULL
 * @uoss: Pointer to buffer for receiving current configuration, or NULL
 *
 * long-desc: Sets and/or retrieves the alternate signal stack for the
 *   calling thread. The alternate signal stack is a specially designated
 *   memory region used for executing signal handlers, separate from the
 *   thread's main stack. This is primarily used to handle SIGSEGV and
 *   other signals that may be generated when the normal stack overflows
 *   or becomes corrupted.
 *
 *   The alternate signal stack is defined by a stack_t structure containing:
 *   - ss_sp: Base address of the stack memory region
 *   - ss_size: Size of the stack in bytes
 *   - ss_flags: Control flags (SS_DISABLE, SS_ONSTACK, SS_AUTODISARM)
 *
 *   When @uss is non-NULL, it specifies the new alternate signal stack
 *   configuration. The ss_flags field controls the operation:
 *   - ss_flags == 0: Enable a new alternate stack with the given ss_sp/ss_size
 *   - ss_flags == SS_DISABLE: Disable the alternate stack (ss_sp/ss_size ignored)
 *   - ss_flags == SS_ONSTACK: Same as 0 on Linux (for compatibility, not portable)
 *   - SS_AUTODISARM flag (OR-ed): Auto-disarm the stack on signal handler entry
 *
 *   The SS_AUTODISARM flag (since Linux 4.7) causes the alternate stack to be
 *   disabled when a signal handler is entered. The previous stack settings are
 *   saved in the signal frame's uc_stack field and automatically restored when
 *   the signal handler returns via sigreturn. This enables safe use of
 *   swapcontext() inside signal handlers, as subsequent signals will not reuse
 *   the same signal stack that the handler has switched away from.
 *
 *   When @uoss is non-NULL, the current alternate signal stack settings are
 *   returned before any changes are applied. The returned ss_flags will indicate:
 *   - SS_DISABLE: No alternate stack is configured
 *   - SS_ONSTACK: Currently executing on the alternate signal stack
 *   - SS_AUTODISARM: Stack has auto-disarm enabled
 *   Multiple flags may be combined in the output.
 *
 *   Attempting to change the alternate stack while currently executing on it
 *   (on_sig_stack() returns true) is not permitted and returns EPERM. However,
 *   if SS_AUTODISARM is set, the stack is considered disabled during signal
 *   handler execution, so modification is permitted.
 *
 *   The stack size must be at least MINSIGSTKSZ (typically 2048 bytes). On
 *   architectures with dynamic signal frames (CONFIG_DYNAMIC_SIGFRAME, e.g.,
 *   x86 with AVX-512/AMX), additional size validation is performed via
 *   sigaltstack_size_valid() which may require larger stacks depending on the
 *   task's FPU/XSTATE feature permissions. The AT_MINSIGSTKSZ auxiliary vector
 *   entry provides the runtime-recommended minimum stack size.
 *
 *   The kernel automatically aligns ss_sp to an appropriate boundary for
 *   the architecture. On most architectures, stacks grow downward, so the
 *   signal handler frame is placed at ss_sp + ss_size.
 *
 *   Fork/clone behavior: The alternate signal stack is inherited by child
 *   processes. However, if CLONE_VM is specified without CLONE_VFORK, the
 *   child's alternate stack is reset to disabled (sas_ss_reset) because the
 *   parent's stack memory is shared.
 *
 *   Execve behavior: The alternate signal stack is cleared (disabled) when a
 *   new program is executed via execve(). The new program starts with no
 *   alternate signal stack configured.
 *
 *   Both @uss and @uoss may be NULL. If both are NULL, the syscall is a no-op
 *   and returns 0. If @uss is NULL, only the current stack is retrieved. If
 *   @uoss is NULL, only the new stack is set.
 *
 *   Optimization: If the new stack settings (@uss) exactly match the current
 *   settings, the syscall returns 0 immediately without acquiring any locks.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: uss
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_OPTIONAL | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Pointer to stack_t structure defining the new alternate signal
 *     stack, or NULL to skip setting. The ss_sp field must point to a valid
 *     user-space memory region of at least ss_size bytes. The ss_size field
 *     must be at least MINSIGSTKSZ (typically 2048), and may need to be larger
 *     on architectures with dynamic signal frames (check AT_MINSIGSTKSZ).
 *     The ss_flags field must be 0, SS_DISABLE, SS_ONSTACK, or a combination
 *     with SS_AUTODISARM. Invalid flag combinations return EINVAL.
 *
 * param: uoss
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_OPTIONAL | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Pointer to stack_t structure to receive the current alternate
 *     signal stack configuration, or NULL to skip retrieval. When provided,
 *     the current ss_sp, ss_size, and ss_flags are written before any changes
 *     are applied. The output ss_flags reflects the current state (SS_DISABLE
 *     if no stack configured, SS_ONSTACK if currently on the stack,
 *     SS_AUTODISARM if auto-disarm is enabled).
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. If both @uss and @uoss are NULL, returns 0
 *     as a no-op. If the new settings match the current settings exactly,
 *     returns 0 without making changes (optimization path).
 *
 * error: EFAULT, Invalid user pointer
 *   desc: Either @uss points outside the accessible address space and could
 *     not be read (copy_from_user failed), or @uoss points outside the
 *     accessible address space and the current stack settings could not be
 *     written (copy_to_user failed). The EFAULT for @uoss is only checked
 *     after successful processing, so partial side effects are possible if
 *     @uss was valid but @uoss is invalid.
 *
 * error: EPERM, Modification while on alternate stack
 *   desc: Attempted to change the alternate signal stack (by providing @uss)
 *     while currently executing on that stack. This check is performed by
 *     on_sig_stack() which compares the current stack pointer against the
 *     configured sas_ss_sp/sas_ss_size range. If SS_AUTODISARM is set, the
 *     stack is considered disabled during handler execution and this error
 *     does not occur.
 *
 * error: EINVAL, Invalid flags
 *   desc: The ss_flags field in @uss contains invalid flags. Valid combinations
 *     are: 0 (enable stack), SS_ONSTACK (same as 0 on Linux), SS_DISABLE
 *     (disable stack), and these may be OR-ed with SS_AUTODISARM. Any other
 *     bits set in ss_flags cause EINVAL. Note that using SS_ONSTACK reduces
 *     portability as other Unix systems may reject it.
 *
 * error: ENOMEM, Stack size too small
 *   desc: The ss_size field in @uss is smaller than the minimum required size.
 *     The minimum is MINSIGSTKSZ (typically 2048 bytes) for basic operation,
 *     but on x86 with CONFIG_DYNAMIC_SIGFRAME, larger stacks may be required
 *     depending on the task's XSTATE feature permissions (AVX-512, AMX, etc.).
 *     The sigaltstack_size_valid() function performs this architecture-specific
 *     validation while holding sighand->siglock. Applications should query
 *     AT_MINSIGSTKSZ from the auxiliary vector for the recommended minimum.
 *
 * lock: current->sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: On architectures with CONFIG_DYNAMIC_SIGFRAME (x86), the signal
 *     handler lock is acquired with IRQs disabled (spin_lock_irq) via
 *     sigaltstack_lock() when modifying the alternate stack settings. This
 *     serializes access with XSTATE permission requests that also check the
 *     signal stack size. On architectures without CONFIG_DYNAMIC_SIGFRAME,
 *     sigaltstack_lock() is a no-op and no lock is acquired. The lock is
 *     only held during the actual modification of sas_ss_sp/sas_ss_size/
 *     sas_ss_flags, not during the copy_from_user/copy_to_user operations.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE | KAPI_EFFECT_PROCESS_STATE
 *   target: Current task's alternate signal stack configuration
 *   desc: Modifies current->sas_ss_sp (stack base address), current->sas_ss_size
 *     (stack size), and current->sas_ss_flags (control flags). These fields in
 *     task_struct control where signal handlers execute when SA_ONSTACK is set
 *     in the sigaction flags. When SS_DISABLE is set, sas_ss_sp is set to NULL
 *     and sas_ss_size is set to 0. The changes persist until modified by another
 *     sigaltstack() call, execve() (which clears them), or certain clone() flags
 *     that reset the stack.
 *   condition: @uss is non-NULL and different from current settings
 *   reversible: yes (by calling sigaltstack with previous settings)
 *
 * state-trans: alternate_signal_stack
 *   from: disabled
 *   to: enabled
 *   condition: @uss->ss_flags is 0 or SS_ONSTACK (not SS_DISABLE) with valid size
 *   desc: Transitions from no alternate stack to an active alternate stack.
 *     Signal handlers registered with SA_ONSTACK will now execute on this stack.
 *
 * state-trans: alternate_signal_stack
 *   from: enabled
 *   to: disabled
 *   condition: @uss->ss_flags includes SS_DISABLE
 *   desc: Disables the alternate signal stack. Signal handlers will execute
 *     on the normal thread stack regardless of SA_ONSTACK flag.
 *
 * state-trans: alternate_signal_stack
 *   from: enabled
 *   to: auto-disarm-enabled
 *   condition: @uss->ss_flags includes SS_AUTODISARM (without SS_DISABLE)
 *   desc: Configures the stack with auto-disarm behavior. On signal handler
 *     entry, the stack settings are saved to the signal frame and the stack
 *     is automatically disabled. Settings are restored on sigreturn.
 *
 * constraint: Minimum stack size
 *   desc: The alternate signal stack must be at least MINSIGSTKSZ bytes
 *     (typically 2048). On architectures with extended state (x86 AVX-512,
 *     AMX), larger sizes may be required. The AT_MINSIGSTKSZ auxiliary vector
 *     entry provides the runtime minimum. Using a stack smaller than required
 *     for the signal frame results in undefined behavior (stack corruption).
 *   expr: ss_size >= MINSIGSTKSZ && sigaltstack_size_valid(ss_size)
 *
 * constraint: Cannot modify while on stack
 *   desc: The alternate signal stack cannot be modified while executing on it.
 *     This prevents corruption of the current signal handler's stack frame.
 *     The SS_AUTODISARM flag provides a workaround by disabling the stack
 *     during handler execution.
 *   expr: !on_sig_stack(current_user_stack_pointer()) || (sas_ss_flags & SS_AUTODISARM)
 *
 * examples: sigaltstack(&new_stack, NULL);  // Set new stack
 *   sigaltstack(NULL, &old_stack);  // Query current stack
 *   sigaltstack(&new_stack, &old_stack);  // Atomically swap
 *   sigaltstack(&(stack_t){.ss_flags = SS_DISABLE}, NULL);  // Disable stack
 *
 * notes: The SIGSTKSZ constant (typically 8192 bytes) is the recommended
 *   stack size for most applications. MINSIGSTKSZ is the absolute minimum.
 *   For robust applications on modern x86 systems, query AT_MINSIGSTKSZ and
 *   add SIGSTKSZ to it for safety.
 *
 *   Using SS_ONSTACK in the input ss_flags is a Linux-specific no-op that may
 *   cause portability problems. POSIX only specifies SS_DISABLE for input;
 *   SS_ONSTACK is defined for output only (to indicate execution on the stack).
 *
 *   The SS_AUTODISARM flag (Linux 4.7+) is essential for applications that use
 *   swapcontext() or similar context-switching functions inside signal handlers.
 *   Without it, a subsequent signal could corrupt the switched-away handler's
 *   state by reusing the same signal stack.
 *
 *   There is no RLIMIT affecting sigaltstack. The memory for the stack must be
 *   allocated by the application (typically via mmap with MAP_STACK flag).
 *
 *   No capability checks are performed. Any process can configure its own
 *   alternate signal stack.
 *
 * since-version: 2.2
 */
SYSCALL_DEFINE2(sigaltstack,const stack_t __user *,uss, stack_t __user *,uoss)
{
	stack_t new, old;
	int err;
	if (uss && copy_from_user(&new, uss, sizeof(stack_t)))
		return -EFAULT;
	err = do_sigaltstack(uss ? &new : NULL, uoss ? &old : NULL,
			      current_user_stack_pointer(),
			      MINSIGSTKSZ);
	if (!err && uoss && copy_to_user(uoss, &old, sizeof(stack_t)))
		err = -EFAULT;
	return err;
}

int restore_altstack(const stack_t __user *uss)
{
	stack_t new;
	if (copy_from_user(&new, uss, sizeof(stack_t)))
		return -EFAULT;
	(void)do_sigaltstack(&new, NULL, current_user_stack_pointer(),
			     MINSIGSTKSZ);
	/* squash all but EFAULT for now */
	return 0;
}

int __save_altstack(stack_t __user *uss, unsigned long sp)
{
	struct task_struct *t = current;
	int err = __put_user((void __user *)t->sas_ss_sp, &uss->ss_sp) |
		__put_user(t->sas_ss_flags, &uss->ss_flags) |
		__put_user(t->sas_ss_size, &uss->ss_size);
	return err;
}

#ifdef CONFIG_COMPAT
static int do_compat_sigaltstack(const compat_stack_t __user *uss_ptr,
				 compat_stack_t __user *uoss_ptr)
{
	stack_t uss, uoss;
	int ret;

	if (uss_ptr) {
		compat_stack_t uss32;
		if (copy_from_user(&uss32, uss_ptr, sizeof(compat_stack_t)))
			return -EFAULT;
		uss.ss_sp = compat_ptr(uss32.ss_sp);
		uss.ss_flags = uss32.ss_flags;
		uss.ss_size = uss32.ss_size;
	}
	ret = do_sigaltstack(uss_ptr ? &uss : NULL, &uoss,
			     compat_user_stack_pointer(),
			     COMPAT_MINSIGSTKSZ);
	if (ret >= 0 && uoss_ptr)  {
		compat_stack_t old;
		memset(&old, 0, sizeof(old));
		old.ss_sp = ptr_to_compat(uoss.ss_sp);
		old.ss_flags = uoss.ss_flags;
		old.ss_size = uoss.ss_size;
		if (copy_to_user(uoss_ptr, &old, sizeof(compat_stack_t)))
			ret = -EFAULT;
	}
	return ret;
}

COMPAT_SYSCALL_DEFINE2(sigaltstack,
			const compat_stack_t __user *, uss_ptr,
			compat_stack_t __user *, uoss_ptr)
{
	return do_compat_sigaltstack(uss_ptr, uoss_ptr);
}

int compat_restore_altstack(const compat_stack_t __user *uss)
{
	int err = do_compat_sigaltstack(uss, NULL);
	/* squash all but -EFAULT for now */
	return err == -EFAULT ? err : 0;
}

int __compat_save_altstack(compat_stack_t __user *uss, unsigned long sp)
{
	int err;
	struct task_struct *t = current;
	err = __put_user(ptr_to_compat((void __user *)t->sas_ss_sp),
			 &uss->ss_sp) |
		__put_user(t->sas_ss_flags, &uss->ss_flags) |
		__put_user(t->sas_ss_size, &uss->ss_size);
	return err;
}
#endif

#ifdef __ARCH_WANT_SYS_SIGPENDING

/**
 *  sys_sigpending - examine pending signals
 *  @uset: where mask of pending signal is returned
 */
SYSCALL_DEFINE1(sigpending, old_sigset_t __user *, uset)
{
	sigset_t set;

	if (sizeof(old_sigset_t) > sizeof(*uset))
		return -EINVAL;

	do_sigpending(&set);

	if (copy_to_user(uset, &set, sizeof(old_sigset_t)))
		return -EFAULT;

	return 0;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE1(sigpending, compat_old_sigset_t __user *, set32)
{
	sigset_t set;

	do_sigpending(&set);

	return put_user(set.sig[0], set32);
}
#endif

#endif

#ifdef __ARCH_WANT_SYS_SIGPROCMASK
/**
 *  sys_sigprocmask - examine and change blocked signals
 *  @how: whether to add, remove, or set signals
 *  @nset: signals to add or remove (if non-null)
 *  @oset: previous value of signal mask if non-null
 *
 * Some platforms have their own version with special arguments;
 * others support only sys_rt_sigprocmask.
 */

SYSCALL_DEFINE3(sigprocmask, int, how, old_sigset_t __user *, nset,
		old_sigset_t __user *, oset)
{
	old_sigset_t old_set, new_set;
	sigset_t new_blocked;

	old_set = current->blocked.sig[0];

	if (nset) {
		if (copy_from_user(&new_set, nset, sizeof(*nset)))
			return -EFAULT;

		new_blocked = current->blocked;

		switch (how) {
		case SIG_BLOCK:
			sigaddsetmask(&new_blocked, new_set);
			break;
		case SIG_UNBLOCK:
			sigdelsetmask(&new_blocked, new_set);
			break;
		case SIG_SETMASK:
			new_blocked.sig[0] = new_set;
			break;
		default:
			return -EINVAL;
		}

		set_current_blocked(&new_blocked);
	}

	if (oset) {
		if (copy_to_user(oset, &old_set, sizeof(*oset)))
			return -EFAULT;
	}

	return 0;
}
#endif /* __ARCH_WANT_SYS_SIGPROCMASK */

#ifndef CONFIG_ODD_RT_SIGACTION
/**
 * sys_rt_sigaction - examine and change a signal action
 * @sig: Signal number to examine or modify (1 to SIGRTMAX)
 * @act: New signal action to install, or NULL to only query
 * @oact: Buffer to receive previous signal action, or NULL if not needed
 * @sigsetsize: Size of the sigset_t type (must equal sizeof(sigset_t))
 *
 * long-desc: Examines and/or changes the action taken by a process on receipt
 *   of a specific signal. This is the real-time signal variant of sigaction(2),
 *   introduced in Linux 2.2 to support enlarged 64-bit signal sets.
 *
 *   The signal action is specified by a struct sigaction containing:
 *   - sa_handler: Signal handler function (SIG_DFL, SIG_IGN, or function pointer)
 *   - sa_sigaction: Alternate handler receiving 3 args (when SA_SIGINFO is set)
 *   - sa_mask: Signals to block during handler execution (sigset_t)
 *   - sa_flags: Behavior modifiers (SA_* flags)
 *   - sa_restorer: Signal trampoline address (internal use, architecture-specific)
 *
 *   If @act is non-NULL, the new action is installed for signal @sig. The previous
 *   action is returned in @oact if non-NULL. If @act is NULL and @oact is non-NULL,
 *   the current action is queried without modification.
 *
 *   The sa_mask field specifies which signals are blocked during execution of
 *   the signal handler. The signal being handled is always blocked unless
 *   SA_NODEFER is specified. SIGKILL and SIGSTOP are automatically removed from
 *   sa_mask as they cannot be blocked.
 *
 *   When setting a signal to SIG_IGN or to SIG_DFL for signals with a default
 *   action of ignore (SIGCHLD, SIGCONT, SIGURG, SIGWINCH), any pending instances
 *   of that signal are discarded from both the thread's pending queue and the
 *   shared pending queue, as required by POSIX.
 *
 *   If the signal handler was previously SIG_IGN and is being changed to catch
 *   the signal, POSIX timers that were ignored are re-armed.
 *
 *   Signals marked with SA_IMMUTABLE (an internal kernel flag) cannot be modified.
 *   This flag is set by the kernel for forced signals from seccomp or similar
 *   security mechanisms to prevent races between signal delivery and sigaction.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: sig
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 1, SIGRTMAX
 *   constraint: Signal number between 1 and SIGRTMAX (typically 64). SIGKILL (9)
 *     and SIGSTOP (19) cannot be caught, blocked, or ignored - attempting to
 *     install a handler for them returns EINVAL. Signal 0 is not valid for this
 *     syscall (unlike kill). Real-time signals range from SIGRTMIN (32) to
 *     SIGRTMAX (64).
 *
 * param: act
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_OPTIONAL | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Pointer to struct sigaction describing the new signal action.
 *     If NULL, the signal action is not changed (query-only mode). The struct
 *     contains: sa_handler/sa_sigaction (handler function or SIG_DFL/SIG_IGN),
 *     sa_mask (sigset_t of signals to block during handling), sa_flags (SA_*
 *     behavior flags), and optionally sa_restorer (signal trampoline). The
 *     sa_flags field is filtered to only include UAPI_SA_FLAGS; unknown flags
 *     are silently cleared (since Linux 5.11 via SA_UNSUPPORTED detection).
 *
 * param: oact
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_OPTIONAL | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Pointer to struct sigaction buffer to receive the previous
 *     signal action. If NULL, the previous action is not returned. This can
 *     be the same pointer as @act for atomic swap operations. The returned
 *     sa_flags field is filtered to only include UAPI_SA_FLAGS, clearing any
 *     internal kernel flags (e.g., SA_IMMUTABLE is never visible to userspace).
 *
 * param: sigsetsize
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must exactly equal sizeof(sigset_t) on the calling architecture
 *     (8 bytes on most 64-bit architectures, 8 bytes on 32-bit with 64 signals).
 *     This parameter allows future expansion to larger signal sets while
 *     maintaining backward compatibility. Returns EINVAL if size mismatch.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success. If @act was non-NULL, the new signal action
 *     is now installed. If @oact was non-NULL, it contains the previous action.
 *     Both operations are performed atomically under siglock.
 *
 * error: EINVAL, Invalid signal number or uncatchable signal
 *   desc: The signal number @sig is invalid (less than 1 or greater than
 *     SIGRTMAX), or an attempt was made to change the action for SIGKILL or
 *     SIGSTOP, which cannot be caught, blocked, or ignored. POSIX requires
 *     that these signals remain uncatchable.
 *
 * error: EINVAL, Signal set size mismatch
 *   desc: The @sigsetsize parameter does not equal sizeof(sigset_t). This
 *     indicates an ABI mismatch between the calling program and the kernel.
 *     The C library normally handles this automatically.
 *
 * error: EINVAL, Signal action is immutable
 *   desc: The signal action has the SA_IMMUTABLE flag set internally, indicating
 *     it was set by the kernel for a forced signal (e.g., from seccomp) and
 *     cannot be changed by userspace. This prevents security-critical signals
 *     from being caught or ignored by the target process.
 *
 * error: EFAULT, Bad address
 *   desc: The @act pointer points to memory that is not readable by the
 *     calling process, or @oact points to memory that is not writable.
 *     For @act, the entire struct sigaction must be readable. For @oact,
 *     the buffer must be writable. Returned via copy_from_user/copy_to_user.
 *
 * lock: sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The per-process signal handler spinlock (sighand->siglock) is acquired
 *     with interrupts disabled via spin_lock_irq() in do_sigaction(). Held during
 *     the entire signal action modification: checking SA_IMMUTABLE, reading the
 *     old action, applying flag filtering, updating the action, and flushing
 *     pending signals if the handler becomes SIG_IGN or default-ignore. Released
 *     with spin_unlock_irq() before return. All threads sharing sighand share
 *     this lock.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process signal handling state (task->sighand->action[sig-1])
 *   desc: Modifies the signal action for signal @sig in the calling process.
 *     The change affects all threads sharing the sighand structure. The new
 *     handler, mask, and flags take effect immediately for subsequent signal
 *     delivery. Child processes inherit the signal actions at fork time.
 *   condition: @act is non-NULL
 *   reversible: yes (by calling rt_sigaction again)
 *
 * side-effect: KAPI_EFFECT_SIGNAL_SEND | KAPI_EFFECT_PROCESS_STATE
 *   target: Pending signal queues (signal->shared_pending and thread pending)
 *   desc: When the signal action is set to SIG_IGN or to SIG_DFL for a signal
 *     whose default action is ignore (SIGCHLD, SIGCONT, SIGURG, SIGWINCH),
 *     all pending instances of that signal are removed from both the shared
 *     pending queue and all per-thread pending queues via flush_sigqueue_mask().
 *     This implements POSIX 3.3.1.3 requirements.
 *   condition: @act non-NULL and handler set to SIG_IGN or default-ignore
 *   reversible: no (discarded signals cannot be recovered)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: POSIX timers (signal->ignored_posix_timers)
 *   desc: When changing a signal handler from SIG_IGN to a catching handler
 *     or SIG_DFL (for non-ignore signals), any POSIX timers that had their
 *     signals ignored are re-armed via posixtimer_sig_unignore(). This ensures
 *     timer signals are not permanently lost when temporarily ignored.
 *   condition: @act non-NULL and previous handler was SIG_IGN
 *   reversible: yes (timers can be disarmed)
 *
 * state-trans: signal_action
 *   from: Any valid action (handler, SIG_DFL, SIG_IGN)
 *   to: New action specified in @act
 *   condition: @act is non-NULL, signal is catchable, not SA_IMMUTABLE
 *   desc: The signal disposition changes atomically from the old action to
 *     the new action. The transition is visible to all threads sharing the
 *     signal handler table. Signal delivery racing with sigaction may see
 *     either the old or new handler depending on timing.
 *
 * constraint: Thread-group shared signal handlers
 *   desc: Signal actions are shared among all threads in a thread group
 *     (threads created with CLONE_SIGHAND). Changing a signal action in one
 *     thread immediately affects all threads in the group. Each thread may
 *     have its own signal mask (blocked signals), but handlers are shared.
 *
 * constraint: SA_MASK filtering
 *   desc: SIGKILL and SIGSTOP are automatically removed from the sa_mask field
 *     via sigdelsetmask() before the action is installed. These signals cannot
 *     be blocked even during signal handler execution.
 *
 * constraint: SA_FLAGS filtering
 *   desc: The kernel only recognizes flags defined in UAPI_SA_FLAGS: SA_NOCLDSTOP,
 *     SA_NOCLDWAIT, SA_SIGINFO, SA_ONSTACK, SA_RESTART, SA_NODEFER, SA_RESETHAND,
 *     SA_EXPOSE_TAGBITS, and architecture-specific SA_RESTORER. Unknown flags are
 *     silently cleared. The SA_UNSUPPORTED flag (0x400) can be used to detect flag
 *     support: set it in sa_flags, call sigaction, and check if it remains set in
 *     oact.sa_flags (it won't, indicating the kernel clears unknown flags).
 *
 * constraint: exec() behavior
 *   desc: On exec(), signals with handlers are reset to SIG_DFL. Signals that are
 *     ignored (SIG_IGN) remain ignored across exec(). The sa_mask and sa_flags
 *     are reset for signals reverting to SIG_DFL.
 *
 * constraint: fork() behavior
 *   desc: Child processes created via fork() inherit the parent's complete signal
 *     disposition table, including all signal handlers, masks, and flags. Pending
 *     signals are NOT inherited by the child.
 *
 * examples:
 *   rt_sigaction(SIGINT, &new_act, &old_act, sizeof(sigset_t));  // Replace handler
 *   rt_sigaction(SIGTERM, &new_act, NULL, sizeof(sigset_t));     // Install, no old
 *   rt_sigaction(SIGHUP, NULL, &old_act, sizeof(sigset_t));      // Query only
 *   rt_sigaction(SIGKILL, &new_act, NULL, sizeof(sigset_t));     // Returns -EINVAL
 *
 * notes:
 *   - This syscall is normally called via the glibc sigaction() wrapper, which
 *     handles the sigsetsize parameter automatically and uses the correct signal
 *     trampoline (sa_restorer) for the architecture.
 *   - The SA_SIGINFO flag determines the handler prototype: without it, the handler
 *     receives only the signal number; with it, the handler receives (int signo,
 *     siginfo_t *info, void *ucontext) providing detailed signal information.
 *   - On x86_64, glibc sets SA_RESTORER and provides sa_restorer pointing to
 *     __restore_rt which calls rt_sigreturn to return from the signal handler.
 *   - SA_RESTART causes interrupted syscalls to be restarted after the signal
 *     handler returns. Without it, syscalls return -EINTR. Some syscalls (like
 *     read/write on slow devices) are always restartable regardless of SA_RESTART.
 *   - SA_RESETHAND causes the signal disposition to reset to SIG_DFL when the
 *     handler is invoked, providing one-shot signal handling.
 *   - SA_NODEFER prevents the signal from being added to the blocked mask during
 *     handler execution, allowing recursive signal handling.
 *   - SA_ONSTACK causes the handler to execute on an alternate signal stack
 *     configured via sigaltstack(). Essential for handling SIGSEGV from stack
 *     overflow.
 *   - SA_NOCLDSTOP and SA_NOCLDWAIT are only meaningful for SIGCHLD: NOCLDSTOP
 *     suppresses SIGCHLD when children stop/continue; NOCLDWAIT causes children
 *     to not become zombies (auto-reaped).
 *   - The compat variant (compat_sys_rt_sigaction) handles 32-bit userspace on
 *     64-bit kernels, translating pointer sizes and sigset_t layout.
 *   - Kernel threads cannot use this syscall; they use kernel_sigaction() which
 *     directly manipulates sighand->action without the userspace interface.
 *   - A race condition fix in SA_IMMUTABLE (kernel 5.16) prevents userspace from
 *     changing signal disposition between when seccomp decides to send a fatal
 *     signal and when the signal is delivered. This closes a security hole.
 *   - Linux 2.6.13 and earlier had a bug where SA_NODEFER incorrectly masked
 *     signals specified in sa_mask instead of just not adding the signal itself;
 *     this was fixed in 2.6.14.
 *
 * since-version: 2.2
 */
SYSCALL_DEFINE4(rt_sigaction, int, sig,
		const struct sigaction __user *, act,
		struct sigaction __user *, oact,
		size_t, sigsetsize)
{
	struct k_sigaction new_sa, old_sa;
	int ret;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (act && copy_from_user(&new_sa.sa, act, sizeof(new_sa.sa)))
		return -EFAULT;

	ret = do_sigaction(sig, act ? &new_sa : NULL, oact ? &old_sa : NULL);
	if (ret)
		return ret;

	if (oact && copy_to_user(oact, &old_sa.sa, sizeof(old_sa.sa)))
		return -EFAULT;

	return 0;
}
#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(rt_sigaction, int, sig,
		const struct compat_sigaction __user *, act,
		struct compat_sigaction __user *, oact,
		compat_size_t, sigsetsize)
{
	struct k_sigaction new_ka, old_ka;
#ifdef __ARCH_HAS_SA_RESTORER
	compat_uptr_t restorer;
#endif
	int ret;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(compat_sigset_t))
		return -EINVAL;

	if (act) {
		compat_uptr_t handler;
		ret = get_user(handler, &act->sa_handler);
		new_ka.sa.sa_handler = compat_ptr(handler);
#ifdef __ARCH_HAS_SA_RESTORER
		ret |= get_user(restorer, &act->sa_restorer);
		new_ka.sa.sa_restorer = compat_ptr(restorer);
#endif
		ret |= get_compat_sigset(&new_ka.sa.sa_mask, &act->sa_mask);
		ret |= get_user(new_ka.sa.sa_flags, &act->sa_flags);
		if (ret)
			return -EFAULT;
	}

	ret = do_sigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);
	if (!ret && oact) {
		ret = put_user(ptr_to_compat(old_ka.sa.sa_handler), 
			       &oact->sa_handler);
		ret |= put_compat_sigset(&oact->sa_mask, &old_ka.sa.sa_mask,
					 sizeof(oact->sa_mask));
		ret |= put_user(old_ka.sa.sa_flags, &oact->sa_flags);
#ifdef __ARCH_HAS_SA_RESTORER
		ret |= put_user(ptr_to_compat(old_ka.sa.sa_restorer),
				&oact->sa_restorer);
#endif
	}
	return ret;
}
#endif
#endif /* !CONFIG_ODD_RT_SIGACTION */

#ifdef CONFIG_OLD_SIGACTION
SYSCALL_DEFINE3(sigaction, int, sig,
		const struct old_sigaction __user *, act,
	        struct old_sigaction __user *, oact)
{
	struct k_sigaction new_ka, old_ka;
	int ret;

	if (act) {
		old_sigset_t mask;
		if (!access_ok(act, sizeof(*act)) ||
		    __get_user(new_ka.sa.sa_handler, &act->sa_handler) ||
		    __get_user(new_ka.sa.sa_restorer, &act->sa_restorer) ||
		    __get_user(new_ka.sa.sa_flags, &act->sa_flags) ||
		    __get_user(mask, &act->sa_mask))
			return -EFAULT;
#ifdef __ARCH_HAS_KA_RESTORER
		new_ka.ka_restorer = NULL;
#endif
		siginitset(&new_ka.sa.sa_mask, mask);
	}

	ret = do_sigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);

	if (!ret && oact) {
		if (!access_ok(oact, sizeof(*oact)) ||
		    __put_user(old_ka.sa.sa_handler, &oact->sa_handler) ||
		    __put_user(old_ka.sa.sa_restorer, &oact->sa_restorer) ||
		    __put_user(old_ka.sa.sa_flags, &oact->sa_flags) ||
		    __put_user(old_ka.sa.sa_mask.sig[0], &oact->sa_mask))
			return -EFAULT;
	}

	return ret;
}
#endif
#ifdef CONFIG_COMPAT_OLD_SIGACTION
COMPAT_SYSCALL_DEFINE3(sigaction, int, sig,
		const struct compat_old_sigaction __user *, act,
	        struct compat_old_sigaction __user *, oact)
{
	struct k_sigaction new_ka, old_ka;
	int ret;
	compat_old_sigset_t mask;
	compat_uptr_t handler, restorer;

	if (act) {
		if (!access_ok(act, sizeof(*act)) ||
		    __get_user(handler, &act->sa_handler) ||
		    __get_user(restorer, &act->sa_restorer) ||
		    __get_user(new_ka.sa.sa_flags, &act->sa_flags) ||
		    __get_user(mask, &act->sa_mask))
			return -EFAULT;

#ifdef __ARCH_HAS_KA_RESTORER
		new_ka.ka_restorer = NULL;
#endif
		new_ka.sa.sa_handler = compat_ptr(handler);
		new_ka.sa.sa_restorer = compat_ptr(restorer);
		siginitset(&new_ka.sa.sa_mask, mask);
	}

	ret = do_sigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);

	if (!ret && oact) {
		if (!access_ok(oact, sizeof(*oact)) ||
		    __put_user(ptr_to_compat(old_ka.sa.sa_handler),
			       &oact->sa_handler) ||
		    __put_user(ptr_to_compat(old_ka.sa.sa_restorer),
			       &oact->sa_restorer) ||
		    __put_user(old_ka.sa.sa_flags, &oact->sa_flags) ||
		    __put_user(old_ka.sa.sa_mask.sig[0], &oact->sa_mask))
			return -EFAULT;
	}
	return ret;
}
#endif

#ifdef CONFIG_SGETMASK_SYSCALL

/*
 * For backwards compatibility.  Functionality superseded by sigprocmask.
 */
SYSCALL_DEFINE0(sgetmask)
{
	/* SMP safe */
	return current->blocked.sig[0];
}

SYSCALL_DEFINE1(ssetmask, int, newmask)
{
	int old = current->blocked.sig[0];
	sigset_t newset;

	siginitset(&newset, newmask);
	set_current_blocked(&newset);

	return old;
}
#endif /* CONFIG_SGETMASK_SYSCALL */

#ifdef __ARCH_WANT_SYS_SIGNAL
/*
 * For backwards compatibility.  Functionality superseded by sigaction.
 */
SYSCALL_DEFINE2(signal, int, sig, __sighandler_t, handler)
{
	struct k_sigaction new_sa, old_sa;
	int ret;

	new_sa.sa.sa_handler = handler;
	new_sa.sa.sa_flags = SA_ONESHOT | SA_NOMASK;
	sigemptyset(&new_sa.sa.sa_mask);

	ret = do_sigaction(sig, &new_sa, &old_sa);

	return ret ? ret : (unsigned long)old_sa.sa.sa_handler;
}
#endif /* __ARCH_WANT_SYS_SIGNAL */

#ifdef __ARCH_WANT_SYS_PAUSE

SYSCALL_DEFINE0(pause)
{
	while (!signal_pending(current)) {
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return -ERESTARTNOHAND;
}

#endif

static int sigsuspend(sigset_t *set)
{
	current->saved_sigmask = current->blocked;
	set_current_blocked(set);

	while (!signal_pending(current)) {
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	set_restore_sigmask();
	return -ERESTARTNOHAND;
}

/**
 * sys_rt_sigsuspend - atomically replace signal mask and wait for a signal
 * @unewset: pointer to new signal mask to install temporarily
 * @sigsetsize: size of the sigset_t structure in bytes
 *
 * long-desc: Atomically replaces the calling thread's signal mask with the
 *   set pointed to by @unewset and suspends execution until delivery of a
 *   signal whose action is to invoke a signal handler or to terminate the
 *   process. This syscall provides the real-time signal extension of the
 *   original sigsuspend(), supporting the full 64-signal sigset_t structure
 *   required for real-time signals (SIGRTMIN to SIGRTMAX).
 *
 *   The atomicity guarantee is critical: it ensures no window exists between
 *   changing the signal mask and entering the wait state where a signal could
 *   be missed. This is essential for reliable signal-based synchronization
 *   patterns.
 *
 *   The typical usage pattern is:
 *   1. Block a set of signals using sigprocmask(SIG_BLOCK, ...)
 *   2. Enter a critical section where the signals should not interrupt
 *   3. Call rt_sigsuspend() with the original (unblocked) mask to atomically
 *      unblock the signals and wait for one to arrive
 *   4. The signal handler executes with the signal temporarily unblocked
 *   5. Upon return, the original signal mask is automatically restored
 *
 *   The signal mask specified by @unewset temporarily replaces the thread's
 *   blocked signal mask. However, SIGKILL and SIGSTOP are always stripped
 *   from this mask - they cannot be blocked and will always be delivered
 *   immediately. Attempting to block them via @unewset has no effect.
 *
 *   When a signal is delivered:
 *   - If the signal has a handler: The handler executes with the original
 *     signal mask (from before rt_sigsuspend) restored. After the handler
 *     returns, rt_sigsuspend() returns -EINTR to the caller.
 *   - If the signal terminates the process: rt_sigsuspend() never returns.
 *   - If the signal is ignored: It does not cause rt_sigsuspend() to return.
 *
 *   The signal mask restoration is handled via the TIF_RESTORE_SIGMASK thread
 *   flag, which causes the arch-specific signal return path to restore
 *   current->saved_sigmask after delivering the signal.
 *
 *   This syscall always returns -1 (error); there is no "successful" return.
 *   The expected return is -EINTR indicating a signal was caught. This is
 *   conformant with POSIX, which specifies that sigsuspend() always returns
 *   -1 with errno set to EINTR.
 *
 *   Historical note: This syscall was introduced in Linux 2.2 as part of the
 *   real-time signal extension. It replaces the original sigsuspend() syscall
 *   which used a 32-bit old_sigset_t that could not represent real-time signals.
 *   The glibc sigsuspend() wrapper transparently calls rt_sigsuspend() when
 *   available. The @sigsetsize parameter was added for future compatibility
 *   with potentially different sigset_t sizes, though currently only
 *   sizeof(sigset_t) is accepted.
 *
 *   Bug fix history: Prior to kernel 4.4, a spurious wakeup (e.g., from a
 *   debugger or spurious interrupt) could cause rt_sigsuspend() to return
 *   prematurely without a signal being pending. This was fixed by adding a
 *   loop that rechecks signal_pending() after each wakeup.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: unewset
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must point to a valid user-space sigset_t structure containing
 *     the signal mask to use while suspended. The structure is copied into
 *     kernel space via copy_from_user(). The pointer must be properly aligned
 *     for a sigset_t (typically 8-byte alignment on 64-bit systems). Any signals
 *     specified in the mask are blocked; signals NOT in the mask are unblocked
 *     and can wake the caller. Note that SIGKILL (9) and SIGSTOP (19) are
 *     automatically removed from the mask - they cannot be blocked.
 *
 * param: sigsetsize
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must exactly equal sizeof(sigset_t), which is 8 bytes on most
 *     64-bit architectures (_NSIG_WORDS * sizeof(unsigned long) = 1 * 8 = 8)
 *     and 16 bytes on 32-bit architectures (_NSIG_WORDS * sizeof(unsigned long)
 *     = 2 * 4 = 8, but often 16 for alignment). Any other value results in
 *     -EINVAL. This parameter exists for forward compatibility with potential
 *     future sigset_t size changes, though such changes have never occurred.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: never succeeds
 *   desc: This syscall never returns successfully. It always returns -1 with
 *     errno set to indicate the condition. The only expected "normal" return
 *     is -EINTR, indicating a signal was caught and its handler has returned.
 *     This behavior is mandated by POSIX. The kernel internally returns
 *     -ERESTARTNOHAND which is converted to -EINTR by the signal delivery
 *     mechanism when a signal handler is invoked.
 *
 * error: EINTR, Signal was caught
 *   desc: A signal was delivered whose action was to invoke a signal handler.
 *     The signal handler has completed execution and returned. This is the
 *     expected "normal" return from rt_sigsuspend() and indicates successful
 *     completion of the wait. The original signal mask has been restored.
 *     Internally, the syscall returns -ERESTARTNOHAND (514), which is converted
 *     to -EINTR by the arch-specific signal handling code when a signal handler
 *     is present for the delivered signal.
 *
 * error: EINVAL, Invalid sigsetsize
 *   desc: The @sigsetsize parameter does not equal sizeof(sigset_t). On x86_64,
 *     sigset_t is 8 bytes; on 32-bit systems it may be 8 or 16 bytes depending
 *     on architecture. The check is performed before any other validation.
 *     This error is returned immediately without accessing @unewset.
 *
 * error: EFAULT, Invalid pointer
 *   desc: The @unewset pointer is invalid or points to memory that is not
 *     readable by the calling process. This is detected by copy_from_user()
 *     failing to read sizeof(sigset_t) bytes from the user-space address.
 *     The pointer may be NULL, point to unmapped memory, or point to a
 *     read-protected page. No partial read is performed; the entire sigset_t
 *     must be readable.
 *
 * lock: current->sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The per-process signal handler spinlock is acquired with interrupts
 *     disabled (spin_lock_irq) in __set_current_blocked() when changing the
 *     signal mask. The lock protects current->blocked and serializes with
 *     signal delivery. The lock is held briefly only during the mask change,
 *     not during the actual sleep. If the new mask equals the current mask
 *     (sigequalsets returns true), the lock is not acquired at all.
 *
 * signal: Any unblocked signal
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: Signal is not blocked by the temporary mask and has a handler
 *   desc: The syscall suspends until any signal not blocked by @unewset is
 *     delivered. When such a signal arrives and has a registered handler, the
 *     handler executes with the original signal mask restored, then the syscall
 *     returns -EINTR. If the signal's disposition is SIG_IGN, it is discarded
 *     and does not wake the syscall. If the signal's disposition is SIG_DFL
 *     and that default terminates the process, the syscall never returns.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: no
 *
 * signal: SIGKILL
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_TERMINATE
 *   condition: SIGKILL delivered (cannot be blocked or caught)
 *   desc: SIGKILL is automatically removed from the temporary mask and will
 *     always terminate the process. The syscall never returns in this case.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * signal: SIGSTOP
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_STOP
 *   condition: SIGSTOP delivered (cannot be blocked or caught)
 *   desc: SIGSTOP is automatically removed from the temporary mask and will
 *     always stop the process. When the process is continued (SIGCONT), the
 *     syscall resumes waiting. SIGSTOP does not cause the syscall to return.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE | KAPI_EFFECT_PROCESS_STATE
 *   target: current->blocked, current->saved_sigmask
 *   desc: Temporarily modifies the calling thread's signal mask (current->blocked)
 *     to the value specified by @unewset (with SIGKILL and SIGSTOP removed).
 *     The original signal mask is saved in current->saved_sigmask before
 *     modification. The TIF_RESTORE_SIGMASK thread flag is set to ensure the
 *     original mask is restored when returning to user space after signal
 *     delivery.
 *   condition: Always, after successful parameter validation
 *   reversible: yes (automatic on signal delivery)
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: calling thread
 *   desc: The calling thread enters TASK_INTERRUPTIBLE state and yields the
 *     CPU via schedule(). The thread remains descheduled until a deliverable
 *     signal arrives, which may be indefinitely if all signals are blocked.
 *     The wait is performed in a loop to handle spurious wakeups (e.g., from
 *     debuggers or spurious interrupts).
 *   reversible: yes (when signal arrives)
 *
 * state-trans: signal_mask
 *   from: original blocked mask
 *   to: @unewset mask (minus SIGKILL/SIGSTOP)
 *   condition: Entering the suspend wait
 *   desc: The thread's signal mask transitions to the temporary mask for the
 *     duration of the wait. This allows signals that were blocked to be
 *     received while suspended.
 *
 * state-trans: signal_mask
 *   from: temporary @unewset mask
 *   to: original blocked mask (from saved_sigmask)
 *   condition: Signal handler invoked
 *   desc: When a signal is delivered and its handler is about to execute, the
 *     original signal mask is restored from saved_sigmask. This ensures the
 *     signal handler runs with the expected signal mask, not the temporary
 *     suspend mask.
 *
 * examples: rt_sigsuspend(&empty_mask, sizeof(sigset_t));  // Wait for any signal
 *   rt_sigsuspend(&block_all_but_sigusr1, sizeof(sigset_t));  // Wait for SIGUSR1
 *
 * notes: The syscall is not restartable - if interrupted by a signal with a
 *   handler, it always returns -EINTR regardless of SA_RESTART. This is because
 *   the purpose of rt_sigsuspend() is specifically to wait for a signal, so
 *   automatic restart would defeat that purpose. The internal -ERESTARTNOHAND
 *   return code ensures this behavior: when a signal handler exists, it is
 *   converted to -EINTR; when no handler exists (signal ignored or default
 *   action), the syscall is restarted internally.
 *
 *   The compat variant (compat_sys_rt_sigsuspend) handles 32-bit processes on
 *   64-bit kernels, using get_compat_sigset() instead of copy_from_user() to
 *   properly convert the 32-bit sigset_t representation.
 *
 * since-version: 2.2
 */
SYSCALL_DEFINE2(rt_sigsuspend, sigset_t __user *, unewset, size_t, sigsetsize)
{
	sigset_t newset;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (copy_from_user(&newset, unewset, sizeof(newset)))
		return -EFAULT;
	return sigsuspend(&newset);
}
 
#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(rt_sigsuspend, compat_sigset_t __user *, unewset, compat_size_t, sigsetsize)
{
	sigset_t newset;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (get_compat_sigset(&newset, unewset))
		return -EFAULT;
	return sigsuspend(&newset);
}
#endif

#ifdef CONFIG_OLD_SIGSUSPEND
SYSCALL_DEFINE1(sigsuspend, old_sigset_t, mask)
{
	sigset_t blocked;
	siginitset(&blocked, mask);
	return sigsuspend(&blocked);
}
#endif
#ifdef CONFIG_OLD_SIGSUSPEND3
SYSCALL_DEFINE3(sigsuspend, int, unused1, int, unused2, old_sigset_t, mask)
{
	sigset_t blocked;
	siginitset(&blocked, mask);
	return sigsuspend(&blocked);
}
#endif

__weak const char *arch_vma_name(struct vm_area_struct *vma)
{
	return NULL;
}

static inline void siginfo_buildtime_checks(void)
{
	BUILD_BUG_ON(sizeof(struct siginfo) != SI_MAX_SIZE);

	/* Verify the offsets in the two siginfos match */
#define CHECK_OFFSET(field) \
	BUILD_BUG_ON(offsetof(siginfo_t, field) != offsetof(kernel_siginfo_t, field))

	/* kill */
	CHECK_OFFSET(si_pid);
	CHECK_OFFSET(si_uid);

	/* timer */
	CHECK_OFFSET(si_tid);
	CHECK_OFFSET(si_overrun);
	CHECK_OFFSET(si_value);

	/* rt */
	CHECK_OFFSET(si_pid);
	CHECK_OFFSET(si_uid);
	CHECK_OFFSET(si_value);

	/* sigchld */
	CHECK_OFFSET(si_pid);
	CHECK_OFFSET(si_uid);
	CHECK_OFFSET(si_status);
	CHECK_OFFSET(si_utime);
	CHECK_OFFSET(si_stime);

	/* sigfault */
	CHECK_OFFSET(si_addr);
	CHECK_OFFSET(si_trapno);
	CHECK_OFFSET(si_addr_lsb);
	CHECK_OFFSET(si_lower);
	CHECK_OFFSET(si_upper);
	CHECK_OFFSET(si_pkey);
	CHECK_OFFSET(si_perf_data);
	CHECK_OFFSET(si_perf_type);
	CHECK_OFFSET(si_perf_flags);

	/* sigpoll */
	CHECK_OFFSET(si_band);
	CHECK_OFFSET(si_fd);

	/* sigsys */
	CHECK_OFFSET(si_call_addr);
	CHECK_OFFSET(si_syscall);
	CHECK_OFFSET(si_arch);
#undef CHECK_OFFSET

	/* usb asyncio */
	BUILD_BUG_ON(offsetof(struct siginfo, si_pid) !=
		     offsetof(struct siginfo, si_addr));
	if (sizeof(int) == sizeof(void __user *)) {
		BUILD_BUG_ON(sizeof_field(struct siginfo, si_pid) !=
			     sizeof(void __user *));
	} else {
		BUILD_BUG_ON((sizeof_field(struct siginfo, si_pid) +
			      sizeof_field(struct siginfo, si_uid)) !=
			     sizeof(void __user *));
		BUILD_BUG_ON(offsetofend(struct siginfo, si_pid) !=
			     offsetof(struct siginfo, si_uid));
	}
#ifdef CONFIG_COMPAT
	BUILD_BUG_ON(offsetof(struct compat_siginfo, si_pid) !=
		     offsetof(struct compat_siginfo, si_addr));
	BUILD_BUG_ON(sizeof_field(struct compat_siginfo, si_pid) !=
		     sizeof(compat_uptr_t));
	BUILD_BUG_ON(sizeof_field(struct compat_siginfo, si_pid) !=
		     sizeof_field(struct siginfo, si_pid));
#endif
}

#if defined(CONFIG_SYSCTL)
static const struct ctl_table signal_debug_table[] = {
#ifdef CONFIG_SYSCTL_EXCEPTION_TRACE
	{
		.procname	= "exception-trace",
		.data		= &show_unhandled_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
#endif
};

static const struct ctl_table signal_table[] = {
	{
		.procname	= "print-fatal-signals",
		.data		= &print_fatal_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
};

static int __init init_signal_sysctls(void)
{
	register_sysctl_init("debug", signal_debug_table);
	register_sysctl_init("kernel", signal_table);
	return 0;
}
early_initcall(init_signal_sysctls);
#endif /* CONFIG_SYSCTL */

void __init signals_init(void)
{
	siginfo_buildtime_checks();

	sigqueue_cachep = KMEM_CACHE(sigqueue, SLAB_PANIC | SLAB_ACCOUNT);
}

#ifdef CONFIG_KGDB_KDB
#include <linux/kdb.h>
/*
 * kdb_send_sig - Allows kdb to send signals without exposing
 * signal internals.  This function checks if the required locks are
 * available before calling the main signal code, to avoid kdb
 * deadlocks.
 */
void kdb_send_sig(struct task_struct *t, int sig)
{
	static struct task_struct *kdb_prev_t;
	int new_t, ret;
	if (!spin_trylock(&t->sighand->siglock)) {
		kdb_printf("Can't do kill command now.\n"
			   "The sigmask lock is held somewhere else in "
			   "kernel, try again later\n");
		return;
	}
	new_t = kdb_prev_t != t;
	kdb_prev_t = t;
	if (!task_is_running(t) && new_t) {
		spin_unlock(&t->sighand->siglock);
		kdb_printf("Process is not RUNNING, sending a signal from "
			   "kdb risks deadlock\n"
			   "on the run queue locks. "
			   "The signal has _not_ been sent.\n"
			   "Reissue the kill command if you want to risk "
			   "the deadlock.\n");
		return;
	}
	ret = send_signal_locked(sig, SEND_SIG_PRIV, t, PIDTYPE_PID);
	spin_unlock(&t->sighand->siglock);
	if (ret)
		kdb_printf("Fail to deliver Signal %d to process %d.\n",
			   sig, t->pid);
	else
		kdb_printf("Signal %d is sent to process %d.\n", sig, t->pid);
}
#endif	/* CONFIG_KGDB_KDB */
