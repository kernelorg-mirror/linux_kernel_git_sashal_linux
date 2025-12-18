// SPDX-License-Identifier: GPL-2.0-only
/*
 *  kernel/sched/syscalls.c
 *
 *  Core kernel scheduler syscalls related code
 *
 *  Copyright (C) 1991-2002  Linus Torvalds
 *  Copyright (C) 1998-2024  Ingo Molnar, Red Hat
 */
#include <linux/sched.h>
#include <linux/cpuset.h>
#include <linux/sched/debug.h>

#include <uapi/linux/sched/types.h>

#include "sched.h"
#include "autogroup.h"

static inline int __normal_prio(int policy, int rt_prio, int nice)
{
	int prio;

	if (dl_policy(policy))
		prio = MAX_DL_PRIO - 1;
	else if (rt_policy(policy))
		prio = MAX_RT_PRIO - 1 - rt_prio;
	else
		prio = NICE_TO_PRIO(nice);

	return prio;
}

/*
 * Calculate the expected normal priority: i.e. priority
 * without taking RT-inheritance into account. Might be
 * boosted by interactivity modifiers. Changes upon fork,
 * setprio syscalls, and whenever the interactivity
 * estimator recalculates.
 */
static inline int normal_prio(struct task_struct *p)
{
	return __normal_prio(p->policy, p->rt_priority, PRIO_TO_NICE(p->static_prio));
}

/*
 * Calculate the current priority, i.e. the priority
 * taken into account by the scheduler. This value might
 * be boosted by RT tasks, or might be boosted by
 * interactivity modifiers. Will be RT if the task got
 * RT-boosted. If not then it returns p->normal_prio.
 */
static int effective_prio(struct task_struct *p)
{
	p->normal_prio = normal_prio(p);
	/*
	 * If we are RT tasks or we were boosted to RT priority,
	 * keep the priority unchanged. Otherwise, update priority
	 * to the normal priority:
	 */
	if (!rt_or_dl_prio(p->prio))
		return p->normal_prio;
	return p->prio;
}

void set_user_nice(struct task_struct *p, long nice)
{
	int old_prio;

	if (task_nice(p) == nice || nice < MIN_NICE || nice > MAX_NICE)
		return;
	/*
	 * We have to be careful, if called from sys_setpriority(),
	 * the task might be in the middle of scheduling on another CPU.
	 */
	guard(task_rq_lock)(p);

	/*
	 * The RT priorities are set via sched_setscheduler(), but we still
	 * allow the 'normal' nice value to be set - but as expected
	 * it won't have any effect on scheduling until the task is
	 * SCHED_DEADLINE, SCHED_FIFO or SCHED_RR:
	 */
	if (task_has_dl_policy(p) || task_has_rt_policy(p)) {
		p->static_prio = NICE_TO_PRIO(nice);
		return;
	}

	scoped_guard (sched_change, p, DEQUEUE_SAVE) {
		p->static_prio = NICE_TO_PRIO(nice);
		set_load_weight(p, true);
		old_prio = p->prio;
		p->prio = effective_prio(p);
	}
}
EXPORT_SYMBOL(set_user_nice);

/*
 * is_nice_reduction - check if nice value is an actual reduction
 *
 * Similar to can_nice() but does not perform a capability check.
 *
 * @p: task
 * @nice: nice value
 */
static bool is_nice_reduction(const struct task_struct *p, const int nice)
{
	/* Convert nice value [19,-20] to rlimit style value [1,40]: */
	int nice_rlim = nice_to_rlimit(nice);

	return (nice_rlim <= task_rlimit(p, RLIMIT_NICE));
}

/*
 * can_nice - check if a task can reduce its nice value
 * @p: task
 * @nice: nice value
 */
int can_nice(const struct task_struct *p, const int nice)
{
	return is_nice_reduction(p, nice) || capable(CAP_SYS_NICE);
}

#ifdef __ARCH_WANT_SYS_NICE

/*
 * sys_nice - change the priority of the current process.
 * @increment: priority increment
 *
 * sys_setpriority is a more generic, but much slower function that
 * does similar things.
 */
SYSCALL_DEFINE1(nice, int, increment)
{
	long nice, retval;

	/*
	 * Setpriority might change our priority at the same moment.
	 * We don't have to worry. Conceptually one call occurs first
	 * and we have a single winner.
	 */
	increment = clamp(increment, -NICE_WIDTH, NICE_WIDTH);
	nice = task_nice(current) + increment;

	nice = clamp_val(nice, MIN_NICE, MAX_NICE);
	if (increment < 0 && !can_nice(current, nice))
		return -EPERM;

	retval = security_task_setnice(current, nice);
	if (retval)
		return retval;

	set_user_nice(current, nice);
	return 0;
}

#endif /* __ARCH_WANT_SYS_NICE */

/**
 * task_prio - return the priority value of a given task.
 * @p: the task in question.
 *
 * Return: The priority value as seen by users in /proc.
 *
 * sched policy         return value   kernel prio    user prio/nice
 *
 * normal, batch, idle     [0 ... 39]  [100 ... 139]          0/[-20 ... 19]
 * fifo, rr             [-2 ... -100]     [98 ... 0]  [1 ... 99]
 * deadline                     -101             -1           0
 */
int task_prio(const struct task_struct *p)
{
	return p->prio - MAX_RT_PRIO;
}

/**
 * idle_cpu - is a given CPU idle currently?
 * @cpu: the processor in question.
 *
 * Return: 1 if the CPU is currently idle. 0 otherwise.
 */
int idle_cpu(int cpu)
{
	struct rq *rq = cpu_rq(cpu);

	if (rq->curr != rq->idle)
		return 0;

	if (rq->nr_running)
		return 0;

	if (rq->ttwu_pending)
		return 0;

	return 1;
}

/**
 * available_idle_cpu - is a given CPU idle for enqueuing work.
 * @cpu: the CPU in question.
 *
 * Return: 1 if the CPU is currently idle. 0 otherwise.
 */
int available_idle_cpu(int cpu)
{
	if (!idle_cpu(cpu))
		return 0;

	if (vcpu_is_preempted(cpu))
		return 0;

	return 1;
}

/**
 * idle_task - return the idle task for a given CPU.
 * @cpu: the processor in question.
 *
 * Return: The idle task for the CPU @cpu.
 */
struct task_struct *idle_task(int cpu)
{
	return cpu_rq(cpu)->idle;
}

#ifdef CONFIG_SCHED_CORE
int sched_core_idle_cpu(int cpu)
{
	struct rq *rq = cpu_rq(cpu);

	if (sched_core_enabled(rq) && rq->curr == rq->idle)
		return 1;

	return idle_cpu(cpu);
}
#endif /* CONFIG_SCHED_CORE */

/**
 * find_process_by_pid - find a process with a matching PID value.
 * @pid: the pid in question.
 *
 * The task of @pid, if found. %NULL otherwise.
 */
static struct task_struct *find_process_by_pid(pid_t pid)
{
	return pid ? find_task_by_vpid(pid) : current;
}

static struct task_struct *find_get_task(pid_t pid)
{
	struct task_struct *p;
	guard(rcu)();

	p = find_process_by_pid(pid);
	if (likely(p))
		get_task_struct(p);

	return p;
}

DEFINE_CLASS(find_get_task, struct task_struct *, if (_T) put_task_struct(_T),
	     find_get_task(pid), pid_t pid)

/*
 * sched_setparam() passes in -1 for its policy, to let the functions
 * it calls know not to change it.
 */
#define SETPARAM_POLICY	-1

static void __setscheduler_params(struct task_struct *p,
		const struct sched_attr *attr)
{
	int policy = attr->sched_policy;

	if (policy == SETPARAM_POLICY)
		policy = p->policy;

	p->policy = policy;

	if (dl_policy(policy))
		__setparam_dl(p, attr);
	else if (fair_policy(policy))
		__setparam_fair(p, attr);

	/* rt-policy tasks do not have a timerslack */
	if (rt_or_dl_task_policy(p)) {
		p->timer_slack_ns = 0;
	} else if (p->timer_slack_ns == 0) {
		/* when switching back to non-rt policy, restore timerslack */
		p->timer_slack_ns = p->default_timer_slack_ns;
	}

	/*
	 * __sched_setscheduler() ensures attr->sched_priority == 0 when
	 * !rt_policy. Always setting this ensures that things like
	 * getparam()/getattr() don't report silly values for !rt tasks.
	 */
	p->rt_priority = attr->sched_priority;
	p->normal_prio = normal_prio(p);
	set_load_weight(p, true);
}

/*
 * Check the target process has a UID that matches the current process's:
 */
static bool check_same_owner(struct task_struct *p)
{
	const struct cred *cred = current_cred(), *pcred;
	guard(rcu)();

	pcred = __task_cred(p);
	return (uid_eq(cred->euid, pcred->euid) ||
		uid_eq(cred->euid, pcred->uid));
}

#ifdef CONFIG_UCLAMP_TASK

static int uclamp_validate(struct task_struct *p,
			   const struct sched_attr *attr)
{
	int util_min = p->uclamp_req[UCLAMP_MIN].value;
	int util_max = p->uclamp_req[UCLAMP_MAX].value;

	if (attr->sched_flags & SCHED_FLAG_UTIL_CLAMP_MIN) {
		util_min = attr->sched_util_min;

		if (util_min + 1 > SCHED_CAPACITY_SCALE + 1)
			return -EINVAL;
	}

	if (attr->sched_flags & SCHED_FLAG_UTIL_CLAMP_MAX) {
		util_max = attr->sched_util_max;

		if (util_max + 1 > SCHED_CAPACITY_SCALE + 1)
			return -EINVAL;
	}

	if (util_min != -1 && util_max != -1 && util_min > util_max)
		return -EINVAL;

	/*
	 * We have valid uclamp attributes; make sure uclamp is enabled.
	 *
	 * We need to do that here, because enabling static branches is a
	 * blocking operation which obviously cannot be done while holding
	 * scheduler locks.
	 */
	sched_uclamp_enable();

	return 0;
}

static bool uclamp_reset(const struct sched_attr *attr,
			 enum uclamp_id clamp_id,
			 struct uclamp_se *uc_se)
{
	/* Reset on sched class change for a non user-defined clamp value. */
	if (likely(!(attr->sched_flags & SCHED_FLAG_UTIL_CLAMP)) &&
	    !uc_se->user_defined)
		return true;

	/* Reset on sched_util_{min,max} == -1. */
	if (clamp_id == UCLAMP_MIN &&
	    attr->sched_flags & SCHED_FLAG_UTIL_CLAMP_MIN &&
	    attr->sched_util_min == -1) {
		return true;
	}

	if (clamp_id == UCLAMP_MAX &&
	    attr->sched_flags & SCHED_FLAG_UTIL_CLAMP_MAX &&
	    attr->sched_util_max == -1) {
		return true;
	}

	return false;
}

static void __setscheduler_uclamp(struct task_struct *p,
				  const struct sched_attr *attr)
{
	enum uclamp_id clamp_id;

	for_each_clamp_id(clamp_id) {
		struct uclamp_se *uc_se = &p->uclamp_req[clamp_id];
		unsigned int value;

		if (!uclamp_reset(attr, clamp_id, uc_se))
			continue;

		/*
		 * RT by default have a 100% boost value that could be modified
		 * at runtime.
		 */
		if (unlikely(rt_task(p) && clamp_id == UCLAMP_MIN))
			value = sysctl_sched_uclamp_util_min_rt_default;
		else
			value = uclamp_none(clamp_id);

		uclamp_se_set(uc_se, value, false);

	}

	if (likely(!(attr->sched_flags & SCHED_FLAG_UTIL_CLAMP)))
		return;

	if (attr->sched_flags & SCHED_FLAG_UTIL_CLAMP_MIN &&
	    attr->sched_util_min != -1) {
		uclamp_se_set(&p->uclamp_req[UCLAMP_MIN],
			      attr->sched_util_min, true);
	}

	if (attr->sched_flags & SCHED_FLAG_UTIL_CLAMP_MAX &&
	    attr->sched_util_max != -1) {
		uclamp_se_set(&p->uclamp_req[UCLAMP_MAX],
			      attr->sched_util_max, true);
	}
}

#else /* !CONFIG_UCLAMP_TASK: */

static inline int uclamp_validate(struct task_struct *p,
				  const struct sched_attr *attr)
{
	return -EOPNOTSUPP;
}
static void __setscheduler_uclamp(struct task_struct *p,
				  const struct sched_attr *attr) { }
#endif /* !CONFIG_UCLAMP_TASK */

/*
 * Allow unprivileged RT tasks to decrease priority.
 * Only issue a capable test if needed and only once to avoid an audit
 * event on permitted non-privileged operations:
 */
static int user_check_sched_setscheduler(struct task_struct *p,
					 const struct sched_attr *attr,
					 int policy, int reset_on_fork)
{
	if (fair_policy(policy)) {
		if (attr->sched_nice < task_nice(p) &&
		    !is_nice_reduction(p, attr->sched_nice))
			goto req_priv;
	}

	if (rt_policy(policy)) {
		unsigned long rlim_rtprio = task_rlimit(p, RLIMIT_RTPRIO);

		/* Can't set/change the rt policy: */
		if (policy != p->policy && !rlim_rtprio)
			goto req_priv;

		/* Can't increase priority: */
		if (attr->sched_priority > p->rt_priority &&
		    attr->sched_priority > rlim_rtprio)
			goto req_priv;
	}

	/*
	 * Can't set/change SCHED_DEADLINE policy at all for now
	 * (safest behavior); in the future we would like to allow
	 * unprivileged DL tasks to increase their relative deadline
	 * or reduce their runtime (both ways reducing utilization)
	 */
	if (dl_policy(policy))
		goto req_priv;

	/*
	 * Treat SCHED_IDLE as nice 20. Only allow a switch to
	 * SCHED_NORMAL if the RLIMIT_NICE would normally permit it.
	 */
	if (task_has_idle_policy(p) && !idle_policy(policy)) {
		if (!is_nice_reduction(p, task_nice(p)))
			goto req_priv;
	}

	/* Can't change other user's priorities: */
	if (!check_same_owner(p))
		goto req_priv;

	/* Normal users shall not reset the sched_reset_on_fork flag: */
	if (p->sched_reset_on_fork && !reset_on_fork)
		goto req_priv;

	return 0;

req_priv:
	if (!capable(CAP_SYS_NICE))
		return -EPERM;

	return 0;
}

int __sched_setscheduler(struct task_struct *p,
			 const struct sched_attr *attr,
			 bool user, bool pi)
{
	int oldpolicy = -1, policy = attr->sched_policy;
	int retval, oldprio, newprio;
	const struct sched_class *prev_class, *next_class;
	struct balance_callback *head;
	struct rq_flags rf;
	int reset_on_fork;
	int queue_flags = DEQUEUE_SAVE | DEQUEUE_MOVE | DEQUEUE_NOCLOCK;
	struct rq *rq;
	bool cpuset_locked = false;

	/* The pi code expects interrupts enabled */
	BUG_ON(pi && in_interrupt());
recheck:
	/* Double check policy once rq lock held: */
	if (policy < 0) {
		reset_on_fork = p->sched_reset_on_fork;
		policy = oldpolicy = p->policy;
	} else {
		reset_on_fork = !!(attr->sched_flags & SCHED_FLAG_RESET_ON_FORK);

		if (!valid_policy(policy))
			return -EINVAL;
	}

	if (attr->sched_flags & ~(SCHED_FLAG_ALL | SCHED_FLAG_SUGOV))
		return -EINVAL;

	/*
	 * Valid priorities for SCHED_FIFO and SCHED_RR are
	 * 1..MAX_RT_PRIO-1, valid priority for SCHED_NORMAL,
	 * SCHED_BATCH and SCHED_IDLE is 0.
	 */
	if (attr->sched_priority > MAX_RT_PRIO-1)
		return -EINVAL;
	if ((dl_policy(policy) && !__checkparam_dl(attr)) ||
	    (rt_policy(policy) != (attr->sched_priority != 0)))
		return -EINVAL;

	if (user) {
		retval = user_check_sched_setscheduler(p, attr, policy, reset_on_fork);
		if (retval)
			return retval;

		if (attr->sched_flags & SCHED_FLAG_SUGOV)
			return -EINVAL;

		retval = security_task_setscheduler(p);
		if (retval)
			return retval;
	}

	/* Update task specific "requested" clamps */
	if (attr->sched_flags & SCHED_FLAG_UTIL_CLAMP) {
		retval = uclamp_validate(p, attr);
		if (retval)
			return retval;
	}

	/*
	 * SCHED_DEADLINE bandwidth accounting relies on stable cpusets
	 * information.
	 */
	if (dl_policy(policy) || dl_policy(p->policy)) {
		cpuset_locked = true;
		cpuset_lock();
	}

	/*
	 * Make sure no PI-waiters arrive (or leave) while we are
	 * changing the priority of the task:
	 *
	 * To be able to change p->policy safely, the appropriate
	 * runqueue lock must be held.
	 */
	rq = task_rq_lock(p, &rf);
	update_rq_clock(rq);

	/*
	 * Changing the policy of the stop threads its a very bad idea:
	 */
	if (p == rq->stop) {
		retval = -EINVAL;
		goto unlock;
	}

	retval = scx_check_setscheduler(p, policy);
	if (retval)
		goto unlock;

	/*
	 * If not changing anything there's no need to proceed further,
	 * but store a possible modification of reset_on_fork.
	 */
	if (unlikely(policy == p->policy)) {
		if (fair_policy(policy) &&
		    (attr->sched_nice != task_nice(p) ||
		     (attr->sched_runtime != p->se.slice)))
			goto change;
		if (rt_policy(policy) && attr->sched_priority != p->rt_priority)
			goto change;
		if (dl_policy(policy) && dl_param_changed(p, attr))
			goto change;
		if (attr->sched_flags & SCHED_FLAG_UTIL_CLAMP)
			goto change;

		p->sched_reset_on_fork = reset_on_fork;
		retval = 0;
		goto unlock;
	}
change:

	if (user) {
#ifdef CONFIG_RT_GROUP_SCHED
		/*
		 * Do not allow real-time tasks into groups that have no runtime
		 * assigned.
		 */
		if (rt_group_sched_enabled() &&
				rt_bandwidth_enabled() && rt_policy(policy) &&
				task_group(p)->rt_bandwidth.rt_runtime == 0 &&
				!task_group_is_autogroup(task_group(p))) {
			retval = -EPERM;
			goto unlock;
		}
#endif /* CONFIG_RT_GROUP_SCHED */
		if (dl_bandwidth_enabled() && dl_policy(policy) &&
				!(attr->sched_flags & SCHED_FLAG_SUGOV)) {
			cpumask_t *span = rq->rd->span;

			/*
			 * Don't allow tasks with an affinity mask smaller than
			 * the entire root_domain to become SCHED_DEADLINE. We
			 * will also fail if there's no bandwidth available.
			 */
			if (!cpumask_subset(span, p->cpus_ptr) ||
			    rq->rd->dl_bw.bw == 0) {
				retval = -EPERM;
				goto unlock;
			}
		}
	}

	/* Re-check policy now with rq lock held: */
	if (unlikely(oldpolicy != -1 && oldpolicy != p->policy)) {
		policy = oldpolicy = -1;
		task_rq_unlock(rq, p, &rf);
		if (cpuset_locked)
			cpuset_unlock();
		goto recheck;
	}

	/*
	 * If setscheduling to SCHED_DEADLINE (or changing the parameters
	 * of a SCHED_DEADLINE task) we need to check if enough bandwidth
	 * is available.
	 */
	if ((dl_policy(policy) || dl_task(p)) && sched_dl_overflow(p, policy, attr)) {
		retval = -EBUSY;
		goto unlock;
	}

	p->sched_reset_on_fork = reset_on_fork;
	oldprio = p->prio;

	newprio = __normal_prio(policy, attr->sched_priority, attr->sched_nice);
	if (pi) {
		/*
		 * Take priority boosted tasks into account. If the new
		 * effective priority is unchanged, we just store the new
		 * normal parameters and do not touch the scheduler class and
		 * the runqueue. This will be done when the task deboost
		 * itself.
		 */
		newprio = rt_effective_prio(p, newprio);
		if (newprio == oldprio)
			queue_flags &= ~DEQUEUE_MOVE;
	}

	prev_class = p->sched_class;
	next_class = __setscheduler_class(policy, newprio);

	if (prev_class != next_class)
		queue_flags |= DEQUEUE_CLASS;

	scoped_guard (sched_change, p, queue_flags) {

		if (!(attr->sched_flags & SCHED_FLAG_KEEP_PARAMS)) {
			__setscheduler_params(p, attr);
			p->sched_class = next_class;
			p->prio = newprio;
		}
		__setscheduler_uclamp(p, attr);

		if (scope->queued) {
			/*
			 * We enqueue to tail when the priority of a task is
			 * increased (user space view).
			 */
			if (oldprio < p->prio)
				scope->flags |= ENQUEUE_HEAD;
		}
	}

	/* Avoid rq from going away on us: */
	preempt_disable();
	head = splice_balance_callbacks(rq);
	task_rq_unlock(rq, p, &rf);

	if (pi) {
		if (cpuset_locked)
			cpuset_unlock();
		rt_mutex_adjust_pi(p);
	}

	/* Run balance callbacks after we've adjusted the PI chain: */
	balance_callbacks(rq, head);
	preempt_enable();

	return 0;

unlock:
	task_rq_unlock(rq, p, &rf);
	if (cpuset_locked)
		cpuset_unlock();
	return retval;
}

static int _sched_setscheduler(struct task_struct *p, int policy,
			       const struct sched_param *param, bool check)
{
	struct sched_attr attr = {
		.sched_policy   = policy,
		.sched_priority = param->sched_priority,
		.sched_nice	= PRIO_TO_NICE(p->static_prio),
	};

	if (p->se.custom_slice)
		attr.sched_runtime = p->se.slice;

	/* Fixup the legacy SCHED_RESET_ON_FORK hack. */
	if ((policy != SETPARAM_POLICY) && (policy & SCHED_RESET_ON_FORK)) {
		attr.sched_flags |= SCHED_FLAG_RESET_ON_FORK;
		policy &= ~SCHED_RESET_ON_FORK;
		attr.sched_policy = policy;
	}

	return __sched_setscheduler(p, &attr, check, true);
}
/**
 * sched_setscheduler - change the scheduling policy and/or RT priority of a thread.
 * @p: the task in question.
 * @policy: new policy.
 * @param: structure containing the new RT priority.
 *
 * Use sched_set_fifo(), read its comment.
 *
 * Return: 0 on success. An error code otherwise.
 *
 * NOTE that the task may be already dead.
 */
int sched_setscheduler(struct task_struct *p, int policy,
		       const struct sched_param *param)
{
	return _sched_setscheduler(p, policy, param, true);
}

int sched_setattr(struct task_struct *p, const struct sched_attr *attr)
{
	return __sched_setscheduler(p, attr, true, true);
}

int sched_setattr_nocheck(struct task_struct *p, const struct sched_attr *attr)
{
	return __sched_setscheduler(p, attr, false, true);
}
EXPORT_SYMBOL_GPL(sched_setattr_nocheck);

/**
 * sched_setscheduler_nocheck - change the scheduling policy and/or RT priority of a thread from kernel-space.
 * @p: the task in question.
 * @policy: new policy.
 * @param: structure containing the new RT priority.
 *
 * Just like sched_setscheduler, only don't bother checking if the
 * current context has permission.  For example, this is needed in
 * stop_machine(): we create temporary high priority worker threads,
 * but our caller might not have that capability.
 *
 * Return: 0 on success. An error code otherwise.
 */
int sched_setscheduler_nocheck(struct task_struct *p, int policy,
			       const struct sched_param *param)
{
	return _sched_setscheduler(p, policy, param, false);
}

/*
 * SCHED_FIFO is a broken scheduler model; that is, it is fundamentally
 * incapable of resource management, which is the one thing an OS really should
 * be doing.
 *
 * This is of course the reason it is limited to privileged users only.
 *
 * Worse still; it is fundamentally impossible to compose static priority
 * workloads. You cannot take two correctly working static prio workloads
 * and smash them together and still expect them to work.
 *
 * For this reason 'all' FIFO tasks the kernel creates are basically at:
 *
 *   MAX_RT_PRIO / 2
 *
 * The administrator _MUST_ configure the system, the kernel simply doesn't
 * know enough information to make a sensible choice.
 */
void sched_set_fifo(struct task_struct *p)
{
	struct sched_param sp = { .sched_priority = MAX_RT_PRIO / 2 };
	WARN_ON_ONCE(sched_setscheduler_nocheck(p, SCHED_FIFO, &sp) != 0);
}
EXPORT_SYMBOL_GPL(sched_set_fifo);

/*
 * For when you don't much care about FIFO, but want to be above SCHED_NORMAL.
 */
void sched_set_fifo_low(struct task_struct *p)
{
	struct sched_param sp = { .sched_priority = 1 };
	WARN_ON_ONCE(sched_setscheduler_nocheck(p, SCHED_FIFO, &sp) != 0);
}
EXPORT_SYMBOL_GPL(sched_set_fifo_low);

/*
 * Used when the primary interrupt handler is forced into a thread, in addition
 * to the (always threaded) secondary handler.  The secondary handler gets a
 * slightly lower priority so that the primary handler can preempt it, thereby
 * emulating the behavior of a non-PREEMPT_RT system where the primary handler
 * runs in hard interrupt context.
 */
void sched_set_fifo_secondary(struct task_struct *p)
{
	struct sched_param sp = { .sched_priority = MAX_RT_PRIO / 2 - 1 };
	WARN_ON_ONCE(sched_setscheduler_nocheck(p, SCHED_FIFO, &sp) != 0);
}

void sched_set_normal(struct task_struct *p, int nice)
{
	struct sched_attr attr = {
		.sched_policy = SCHED_NORMAL,
		.sched_nice = nice,
	};
	WARN_ON_ONCE(sched_setattr_nocheck(p, &attr) != 0);
}
EXPORT_SYMBOL_GPL(sched_set_normal);

static int
do_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param)
{
	struct sched_param lparam;

	if (unlikely(!param || pid < 0))
		return -EINVAL;
	if (copy_from_user(&lparam, param, sizeof(struct sched_param)))
		return -EFAULT;

	CLASS(find_get_task, p)(pid);
	if (!p)
		return -ESRCH;

	return sched_setscheduler(p, policy, &lparam);
}

/*
 * Mimics kernel/events/core.c perf_copy_attr().
 */
static int sched_copy_attr(struct sched_attr __user *uattr, struct sched_attr *attr)
{
	u32 size;
	int ret;

	/* Zero the full structure, so that a short copy will be nice: */
	memset(attr, 0, sizeof(*attr));

	ret = get_user(size, &uattr->size);
	if (ret)
		return ret;

	/* ABI compatibility quirk: */
	if (!size)
		size = SCHED_ATTR_SIZE_VER0;
	if (size < SCHED_ATTR_SIZE_VER0 || size > PAGE_SIZE)
		goto err_size;

	ret = copy_struct_from_user(attr, sizeof(*attr), uattr, size);
	if (ret) {
		if (ret == -E2BIG)
			goto err_size;
		return ret;
	}

	if ((attr->sched_flags & SCHED_FLAG_UTIL_CLAMP) &&
	    size < SCHED_ATTR_SIZE_VER1)
		return -EINVAL;

	/*
	 * XXX: Do we want to be lenient like existing syscalls; or do we want
	 * to be strict and return an error on out-of-bounds values?
	 */
	attr->sched_nice = clamp(attr->sched_nice, MIN_NICE, MAX_NICE);

	return 0;

err_size:
	put_user(sizeof(*attr), &uattr->size);
	return -E2BIG;
}

static void get_params(struct task_struct *p, struct sched_attr *attr)
{
	if (task_has_dl_policy(p)) {
		__getparam_dl(p, attr);
	} else if (task_has_rt_policy(p)) {
		attr->sched_priority = p->rt_priority;
	} else {
		attr->sched_nice = task_nice(p);
		attr->sched_runtime = p->se.slice;
	}
}

/**
 * sys_sched_setscheduler - Set the scheduling policy and priority of a thread
 * @pid: Thread ID to target, or 0 for the calling thread
 * @policy: New scheduling policy (optionally ORed with SCHED_RESET_ON_FORK)
 * @param: User-space pointer to struct sched_param containing the new priority
 *
 * long-desc: Sets both the scheduling policy and priority of a thread in a
 *   single atomic operation. This is the primary interface for changing a
 *   thread's scheduling class and associated parameters.
 *
 *   The @pid parameter identifies the target thread. If @pid is 0, the calling
 *   thread is modified. The thread is looked up via find_task_by_vpid(), which
 *   respects PID namespace boundaries - only threads visible in the caller's
 *   PID namespace can be targeted.
 *
 *   The @policy parameter specifies the scheduling class. Valid policies are:
 *   - SCHED_NORMAL (0): Standard time-sharing policy (CFS scheduler)
 *   - SCHED_FIFO (1): First-in-first-out realtime policy
 *   - SCHED_RR (2): Round-robin realtime policy
 *   - SCHED_BATCH (3): Batch processing policy (longer timeslices)
 *   - SCHED_IDLE (5): Very low priority background tasks
 *   - SCHED_EXT (7): Extensible BPF scheduler (if CONFIG_SCHED_CLASS_EXT)
 *   Note: SCHED_DEADLINE (6) is NOT supported via this syscall; use
 *   sched_setattr() instead as it requires additional parameters.
 *
 *   The policy value may be ORed with SCHED_RESET_ON_FORK (0x40000000) to
 *   ensure that child processes created via fork() will have their scheduling
 *   policy reset to SCHED_NORMAL with priority 0. This flag is preserved
 *   across subsequent sched_setscheduler() calls.
 *
 *   The @param structure contains a single field, sched_priority, which must
 *   be appropriate for the specified policy:
 *   - For SCHED_FIFO and SCHED_RR: sched_priority must be in range 1-99
 *     (MAX_RT_PRIO-1), with higher values meaning higher priority.
 *   - For SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE, SCHED_EXT: sched_priority
 *     must be 0 (these policies do not use RT priority).
 *
 *   The implementation calls do_sched_setscheduler() which copies the param
 *   structure from user space, looks up the target task, and calls
 *   sched_setscheduler() -> _sched_setscheduler() -> __sched_setscheduler()
 *   to perform the actual policy change.
 *
 *   Permission checks are performed by user_check_sched_setscheduler():
 *   - Switching to or modifying RT policies (SCHED_FIFO, SCHED_RR) requires
 *     either CAP_SYS_NICE or RLIMIT_RTPRIO allowance.
 *   - Modifying another user's thread requires CAP_SYS_NICE or matching
 *     real/effective UID.
 *   - Clearing the SCHED_RESET_ON_FORK flag requires CAP_SYS_NICE.
 *   - Switching from SCHED_IDLE to other policies requires CAP_SYS_NICE or
 *     RLIMIT_NICE allowance.
 *   - LSMs may impose additional restrictions via security_task_setscheduler().
 *
 *   When using RT policies under CONFIG_RT_GROUP_SCHED, the task's cgroup must
 *   have allocated RT bandwidth (rt_runtime > 0), otherwise EPERM is returned.
 *
 *   Unlike POSIX which specifies that the previous policy should be returned
 *   on success, Linux returns 0. This is a documented non-conformance.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: pid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid thread ID in the caller's PID namespace, or 0
 *     to target the calling thread. Negative values return EINVAL. Non-existent
 *     or invisible thread IDs return ESRCH.
 *
 * param: policy
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   valid-mask: SCHED_NORMAL | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE | SCHED_EXT | SCHED_RESET_ON_FORK
 *   constraint: Must be a valid scheduling policy (0-3, 5, 7), optionally ORed
 *     with SCHED_RESET_ON_FORK (0x40000000). Negative values return EINVAL.
 *     SCHED_DEADLINE (6) is NOT valid for this syscall. The policy must be
 *     consistent with the sched_priority in @param.
 *
 * param: param
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid user-space pointer to struct sched_param. The
 *     structure must be readable by the kernel (copy_from_user must succeed).
 *     The sched_priority field must be valid for the specified policy: 1-99
 *     for RT policies (SCHED_FIFO, SCHED_RR), or 0 for all other policies.
 *     NULL returns EINVAL. Invalid pointer returns EFAULT.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success, indicating the thread's scheduling policy and
 *     priority have been updated. The change takes effect immediately and may
 *     cause rescheduling. Note: Unlike POSIX, Linux does NOT return the
 *     previous scheduling policy on success.
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned when: (1) @pid is negative, (2) @param is NULL, (3) @policy
 *     is not a recognized scheduling policy (after masking SCHED_RESET_ON_FORK),
 *     (4) sched_priority exceeds MAX_RT_PRIO-1 (99), (5) sched_priority is
 *     inconsistent with the policy (non-zero for non-RT, zero for RT), (6) the
 *     target task is the special per-CPU stop thread (rq->stop). For DEADLINE
 *     tasks being changed, invalid DL parameters also return EINVAL.
 *
 * error: ESRCH, No thread found with specified PID
 *   desc: No thread with the specified @pid exists in the caller's PID
 *     namespace. The lookup uses find_task_by_vpid() which respects PID
 *     namespace isolation.
 *
 * error: EFAULT, Invalid user-space pointer
 *   desc: The @param pointer is invalid and copy_from_user() failed. The
 *     pointer may be unmapped, point to kernel memory, or otherwise be
 *     inaccessible from user space.
 *
 * error: EPERM, Insufficient privileges
 *   desc: Permission denied. Occurs when: (1) Switching to RT policy without
 *     CAP_SYS_NICE and RLIMIT_RTPRIO is 0. (2) Increasing RT priority beyond
 *     both current priority and RLIMIT_RTPRIO without CAP_SYS_NICE.
 *     (3) Modifying another user's thread without CAP_SYS_NICE. (4) Clearing
 *     SCHED_RESET_ON_FORK flag without CAP_SYS_NICE. (5) Switching from
 *     SCHED_IDLE without CAP_SYS_NICE or RLIMIT_NICE allowance. (6) Under
 *     CONFIG_RT_GROUP_SCHED, switching to RT policy when task's cgroup has
 *     no allocated RT bandwidth. (7) cap_safe_nice() check failed - target
 *     has capabilities not in caller's permitted set. (8) Under SCHED_DEADLINE,
 *     task's cpumask doesn't cover entire root_domain or no DL bandwidth.
 *
 * error: EACCES, LSM denied the operation
 *   desc: A Linux Security Module (SELinux, AppArmor, etc.) denied the
 *     scheduling policy change via the security_task_setscheduler() hook.
 *     SELinux requires the PROCESS__SETSCHED permission. Also returned by
 *     scx_check_setscheduler() if transitioning to SCHED_EXT when the task
 *     has the scx.disallow flag set.
 *
 * error: EBUSY, Resource busy
 *   desc: Returned when switching to or modifying SCHED_DEADLINE parameters
 *     would exceed the available deadline bandwidth. The system maintains
 *     admission control to ensure all SCHED_DEADLINE tasks can meet their
 *     deadlines. Checked by sched_dl_overflow().
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is acquired by find_get_task() via guard(rcu)() when
 *     looking up the target thread. This protects the task_struct from being
 *     freed during the lookup. The reference count is incremented before RCU
 *     unlock, and decremented after the operation completes.
 *
 * lock: pi_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The target task's pi_lock (priority inheritance lock) is acquired
 *     as part of task_rq_lock() in __sched_setscheduler(). This lock protects
 *     the task's scheduling-related fields and PI waiter state. Acquired with
 *     interrupts disabled.
 *
 * lock: rq->lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The per-CPU run queue lock is acquired via task_rq_lock() in
 *     __sched_setscheduler(). This lock serializes modifications to the task's
 *     scheduling parameters and ensures atomic updates to run queue data
 *     structures. Held while checking and modifying task state.
 *
 * lock: cpuset_mutex
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: The cpuset mutex is acquired via cpuset_lock() when the operation
 *     involves SCHED_DEADLINE policy (either current or target). This ensures
 *     stable cpuset information during DL bandwidth accounting. This is why
 *     the syscall can sleep.
 *
 * lock: dl_bw->lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The deadline bandwidth lock is acquired in sched_dl_overflow() when
 *     checking or updating SCHED_DEADLINE bandwidth allocation. Protects the
 *     per-root-domain dl_bw structure.
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: Syscall has no interruptible wait points
 *   desc: This syscall does not have explicit signal handling. While it can
 *     acquire the cpuset_mutex (which is a sleeping lock), the mutex is
 *     acquired via mutex_lock() not mutex_lock_interruptible(), so signals
 *     cannot interrupt the wait. The syscall does not return EINTR or
 *     ERESTARTSYS.
 *   timing: KAPI_SIGNAL_TIME_NONE
 *   restartable: n/a
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task scheduling policy and parameters
 *   desc: Modifies the target thread's p->policy, p->rt_priority, p->prio,
 *     p->normal_prio, and p->sched_reset_on_fork fields. For transitions
 *     to/from RT policies, also modifies p->timer_slack_ns (set to 0 for RT,
 *     restored to default for non-RT). The sched_class pointer is updated
 *     to reflect the new scheduling class.
 *   reversible: yes (can be changed with another sched_setscheduler call)
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: CPU run queue ordering
 *   desc: If the policy/priority change affects the task's position in the
 *     run queue, a reschedule may be triggered. When priority increases
 *     (numerically lower prio value), the task is enqueued at the head.
 *     Balance callbacks are invoked after the change to handle potential
 *     migrations. preempt_disable/enable brackets balance callback execution.
 *   condition: Task is runnable and priority changes relative position
 *   reversible: n/a
 *
 * side-effect: KAPI_EFFECT_PROCESS_STATE
 *   target: task reference count and PI chain
 *   desc: The target task's reference count is incremented during the
 *     operation. After the scheduling change, rt_mutex_adjust_pi() is called
 *     to update the priority inheritance chain for any tasks blocked on
 *     mutexes held by the modified task.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: deadline bandwidth allocation
 *   desc: When changing to/from SCHED_DEADLINE, the per-root-domain dl_bw
 *     bandwidth allocation is updated to reflect the task's new bandwidth
 *     requirements. This affects admission control for other DEADLINE tasks.
 *   condition: Policy involves SCHED_DEADLINE
 *   reversible: yes
 *
 * state-trans: task_policy
 *   from: previous scheduling policy (SCHED_NORMAL, SCHED_FIFO, etc.)
 *   to: new scheduling policy from @policy parameter
 *   condition: Successful completion of __sched_setscheduler()
 *   desc: The task's scheduling policy transitions to the specified value.
 *     The SCHED_RESET_ON_FORK flag is handled separately in sched_reset_on_fork.
 *
 * state-trans: task_rt_priority
 *   from: previous sched_priority value (0-99)
 *   to: new sched_priority value from @param
 *   condition: Successful completion and policy accepts RT priority
 *   desc: The task's rt_priority field transitions to the value specified
 *     in param->sched_priority. For RT tasks this is 1-99, for others 0.
 *
 * state-trans: task_sched_class
 *   from: previous sched_class (fair_sched_class, rt_sched_class, etc.)
 *   to: new sched_class matching the policy
 *   condition: Policy change requires different scheduler class
 *   desc: The task's sched_class pointer is updated to point to the
 *     appropriate scheduling class implementation. This changes which
 *     scheduler algorithms handle the task.
 *
 * capability: CAP_SYS_NICE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: (1) Setting any RT policy regardless of RLIMIT_RTPRIO.
 *     (2) Setting any RT priority (1-99) regardless of limits.
 *     (3) Modifying scheduling of threads owned by other users.
 *     (4) Clearing the SCHED_RESET_ON_FORK flag.
 *     (5) Switching from SCHED_IDLE to other policies.
 *     (6) Modifying tasks with higher capability sets.
 *   without: For RT policies, must have RLIMIT_RTPRIO > 0 and priority <=
 *     max(RLIMIT_RTPRIO, current priority). For other users' threads, EPERM.
 *     For SCHED_IDLE escape, must have RLIMIT_NICE allowance. For clearing
 *     SCHED_RESET_ON_FORK, EPERM.
 *   condition: Checked by user_check_sched_setscheduler() and cap_safe_nice()
 *
 * constraint: RLIMIT_RTPRIO resource limit
 *   desc: For RT scheduling policies, the maximum sched_priority that can be
 *     set without CAP_SYS_NICE is limited by RLIMIT_RTPRIO. If RLIMIT_RTPRIO
 *     is 0, the process cannot switch to RT scheduling at all without the
 *     capability. The limit also controls whether the policy can be changed
 *     to RT if currently non-RT.
 *
 * constraint: RLIMIT_NICE resource limit
 *   desc: When switching from SCHED_IDLE to another policy, the process must
 *     have CAP_SYS_NICE or the RLIMIT_NICE must allow nice value 19 (the
 *     effective nice of SCHED_IDLE). This prevents unprivileged escape from
 *     the lowest priority class.
 *
 * constraint: RT group scheduling bandwidth
 *   desc: Under CONFIG_RT_GROUP_SCHED with rt_group_sched_enabled(), a task
 *     can only be switched to RT policy if its cgroup has allocated RT
 *     bandwidth (task_group->rt_bandwidth.rt_runtime > 0). Autogroups are
 *     exempt from this check.
 *   expr: !rt_group_sched_enabled() || task_group(p)->rt_bandwidth.rt_runtime > 0
 *
 * constraint: SCHED_DEADLINE bandwidth
 *   desc: While SCHED_DEADLINE is not directly supported, if a DEADLINE task's
 *     parameters are being modified, the new bandwidth must not cause overflow.
 *     Also, DEADLINE tasks must have affinity covering the entire root_domain.
 *
 * constraint: LSM security hooks
 *   desc: The security_task_setscheduler() LSM hook is called after basic
 *     permission checks pass. LSMs like SELinux may impose additional policy
 *     restrictions. SELinux requires PROCESS__SETSCHED permission.
 *
 * constraint: stop thread protection
 *   desc: The per-CPU stop threads (rq->stop) cannot have their scheduling
 *     policy modified. These are critical kernel threads used for CPU
 *     hotplug and other operations. Attempting to modify them returns EINVAL.
 *
 * examples:
 *   struct sched_param sp = { .sched_priority = 50 };
 *   sched_setscheduler(0, SCHED_FIFO, &sp);  // Set current to FIFO prio 50
 *   sched_setscheduler(pid, SCHED_RR, &sp);  // Set other thread to RR prio 50
 *   sp.sched_priority = 0;
 *   sched_setscheduler(0, SCHED_NORMAL, &sp);  // Switch to CFS
 *   sched_setscheduler(0, SCHED_FIFO | SCHED_RESET_ON_FORK, &sp);  // With reset flag
 *
 * notes:
 *   - POSIX.1-2008 specifies this syscall but Linux does NOT conform to the
 *     requirement that the previous policy be returned on success. Linux
 *     always returns 0 on success. Use sched_getscheduler() to query first.
 *   - This syscall predates sched_setattr() which provides more comprehensive
 *     control including SCHED_DEADLINE parameters and nice values.
 *   - The sched_param structure cannot be extended due to ABI compatibility.
 *     For extended parameters, use sched_setattr() with sched_attr.
 *   - SCHED_DEADLINE (policy 6) is NOT supported by this syscall because it
 *     requires additional parameters (runtime, deadline, period) that cannot
 *     be expressed in struct sched_param.
 *   - SCHED_EXT (policy 7) is only available if CONFIG_SCHED_CLASS_EXT is
 *     enabled and requires sched_priority = 0.
 *   - The call is atomic with respect to the scheduling parameters - either
 *     all changes succeed or none do.
 *   - If the target task is currently running on another CPU and its priority
 *     changes, an IPI may be sent to trigger rescheduling on that CPU.
 *   - Priority changes trigger PI chain updates via rt_mutex_adjust_pi() to
 *     handle tasks blocked on mutexes held by the modified task.
 *   - The SCHED_RESET_ON_FORK flag is useful for preventing child processes
 *     from inheriting elevated RT priorities, which could be a security issue.
 *   - Under PREEMPT_RT kernels, some spinlocks become sleeping locks, but the
 *     core semantics remain the same.
 *
 * since-version: 2.0
 */
SYSCALL_DEFINE3(sched_setscheduler, pid_t, pid, int, policy, struct sched_param __user *, param)
{
	if (policy < 0)
		return -EINVAL;

	return do_sched_setscheduler(pid, policy, param);
}

/**
 * sys_sched_setparam - Set scheduling parameters for a thread
 * @pid: Thread ID to target, or 0 for the calling thread
 * @param: User-space pointer to struct sched_param containing the new priority
 *
 * long-desc: Sets the scheduling parameters (specifically the realtime
 *   priority) of a thread without changing its scheduling policy. This
 *   syscall is a subset of sched_setscheduler() - it can only modify the
 *   sched_priority field within the constraints of the thread's current
 *   scheduling policy.
 *
 *   The @pid parameter identifies the target thread. If @pid is 0, the calling
 *   thread is modified. The thread is looked up via find_task_by_vpid(), which
 *   respects PID namespace boundaries - only threads visible in the caller's
 *   PID namespace can be targeted.
 *
 *   The @param structure contains a single field, sched_priority, which must
 *   be appropriate for the thread's current scheduling policy:
 *   - For SCHED_FIFO and SCHED_RR (realtime policies): sched_priority must
 *     be in the range 1 to 99 (MAX_RT_PRIO-1), with higher values meaning
 *     higher priority.
 *   - For SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE, and SCHED_DEADLINE:
 *     sched_priority must be 0 (these policies do not use RT priority).
 *   - For SCHED_EXT: sched_priority must be 0.
 *
 *   Internally, sched_setparam() calls the same __sched_setscheduler() code
 *   path as sched_setscheduler(), but passes a special SETPARAM_POLICY (-1)
 *   value that instructs the function to preserve the current scheduling
 *   policy while only modifying the priority.
 *
 *   Permission checks are performed by user_check_sched_setscheduler():
 *   - For realtime policies, increasing priority beyond RLIMIT_RTPRIO requires
 *     CAP_SYS_NICE capability.
 *   - Modifying another user's thread requires CAP_SYS_NICE capability or
 *     matching real/effective UID.
 *   - Clearing the SCHED_RESET_ON_FORK flag requires CAP_SYS_NICE.
 *   - LSMs may impose additional restrictions via security_task_setscheduler().
 *
 *   Unlike sched_setattr(), this syscall does not support setting nice values,
 *   SCHED_DEADLINE parameters, or utilization clamp values. For full scheduler
 *   control, use sched_setattr() instead.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: pid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid thread ID in the caller's PID namespace, or 0
 *     to target the calling thread. Negative values return EINVAL. Non-existent
 *     or invisible thread IDs return ESRCH.
 *
 * param: param
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid user-space pointer to struct sched_param. The
 *     structure must be readable by the kernel (copy_from_user must succeed).
 *     The sched_priority field must be valid for the target thread's current
 *     scheduling policy: 1-99 for RT policies (SCHED_FIFO, SCHED_RR), or 0 for
 *     all other policies. NULL returns EINVAL. Invalid pointer returns EFAULT.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success, indicating the thread's scheduling parameters
 *     have been updated. The change takes effect immediately and may cause
 *     rescheduling if the priority change affects the run queue ordering.
 *
 * error: EINVAL, Invalid pid or param argument
 *   desc: Returned when @pid is negative, when @param is NULL, when
 *     sched_priority exceeds MAX_RT_PRIO-1 (99), or when sched_priority is
 *     inconsistent with the thread's scheduling policy (non-zero for non-RT
 *     policy, or zero for RT policy). Also returned if the target thread is
 *     the special per-CPU stop thread (rq->stop), which cannot have its
 *     scheduling parameters modified.
 *
 * error: ESRCH, No thread found with specified PID
 *   desc: No thread with the specified @pid exists in the caller's PID
 *     namespace. The lookup uses find_task_by_vpid() which respects PID
 *     namespace isolation - threads in parent or sibling PID namespaces are
 *     not visible.
 *
 * error: EFAULT, Invalid user-space pointer
 *   desc: The @param pointer is invalid and copy_from_user() failed. The
 *     pointer may be unmapped, point to kernel memory, or otherwise be
 *     inaccessible from user space.
 *
 * error: EPERM, Insufficient privileges
 *   desc: Permission denied. Occurs when: (1) Increasing RT priority beyond
 *     RLIMIT_RTPRIO without CAP_SYS_NICE. (2) Modifying another user's thread
 *     without CAP_SYS_NICE. (3) Clearing SCHED_RESET_ON_FORK without CAP_SYS_NICE.
 *     Check performed by user_check_sched_setscheduler().
 *
 * error: EACCES, LSM denied the operation
 *   desc: A Linux Security Module (SELinux, AppArmor, etc.) denied the
 *     scheduling parameter change via the security_task_setscheduler() hook.
 *     SELinux requires the PROCESS__SETSCHED permission. This error is also
 *     returned by scx_check_setscheduler() if attempting to transition to
 *     SCHED_EXT when the task has the disallow flag set, though this path is
 *     not reachable via sched_setparam() since it preserves the current policy.
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is acquired by find_get_task() via guard(rcu)() when
 *     looking up the target thread. This protects the task_struct from being
 *     freed during the lookup. The reference count is incremented before RCU
 *     unlock, and decremented after the operation completes.
 *
 * lock: pi_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The target task's pi_lock (priority inheritance lock) is acquired
 *     as part of task_rq_lock() in __sched_setscheduler(). This lock protects
 *     the task's scheduling-related fields and is held while modifying priority.
 *     Acquired with interrupts disabled.
 *
 * lock: rq->lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The per-CPU run queue lock is acquired via task_rq_lock() in
 *     __sched_setscheduler(). This lock serializes modifications to the task's
 *     scheduling parameters and ensures atomic updates to run queue data
 *     structures. Held while checking and modifying task state.
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: Syscall has no interruptible wait points
 *   desc: This syscall does not have explicit signal handling. All operations
 *     are performed under spinlocks or with RCU protection, and there are no
 *     interruptible sleep points. The syscall completes quickly and does not
 *     return EINTR or ERESTARTSYS.
 *   timing: KAPI_SIGNAL_TIME_NONE
 *   restartable: n/a
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task scheduling parameters (p->rt_priority, p->prio, p->normal_prio)
 *   desc: Modifies the target thread's realtime priority and effective priority.
 *     For RT policies, p->rt_priority is set to param->sched_priority, and
 *     p->prio and p->normal_prio are recalculated accordingly. The change is
 *     performed atomically under rq->lock protection.
 *   reversible: yes (can be changed with another sched_setparam call)
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: CPU run queue ordering
 *   desc: If the priority change affects the task's position in the run queue,
 *     a reschedule may be triggered. If the task's priority increases, it may
 *     preempt lower-priority tasks. If it decreases, higher-priority tasks may
 *     preempt it. Balance callbacks are invoked after the change to handle
 *     potential migrations.
 *   condition: Task is runnable and priority changes relative position
 *   reversible: n/a
 *
 * side-effect: KAPI_EFFECT_PROCESS_STATE
 *   target: task reference count
 *   desc: The target task's reference count is incremented by find_get_task()
 *     to prevent the task from being freed during the operation. The reference
 *     is decremented automatically when the CLASS(find_get_task) destructor
 *     runs via put_task_struct().
 *   reversible: yes (automatically within syscall)
 *
 * state-trans: task_rt_priority
 *   from: previous sched_priority value (0-99)
 *   to: new sched_priority value from @param
 *   condition: Successful completion of __sched_setscheduler()
 *   desc: The task's rt_priority field transitions to the value specified
 *     in param->sched_priority. For non-RT tasks, this must be 0. For RT
 *     tasks, this must be 1-99.
 *
 * capability: CAP_SYS_NICE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: (1) Increasing RT priority beyond RLIMIT_RTPRIO. (2) Modifying
 *     scheduling parameters of threads owned by other users. (3) Clearing
 *     the SCHED_RESET_ON_FORK flag on any thread.
 *   without: For RT priority increases, the new priority must not exceed
 *     RLIMIT_RTPRIO. For other users' threads, EPERM is returned. For clearing
 *     SCHED_RESET_ON_FORK, EPERM is returned.
 *   condition: Checked by user_check_sched_setscheduler() when escalation or
 *     cross-user modification is attempted
 *
 * constraint: RLIMIT_RTPRIO resource limit
 *   desc: For threads with RT scheduling policies, the maximum sched_priority
 *     that can be set without CAP_SYS_NICE is limited by RLIMIT_RTPRIO. If
 *     RLIMIT_RTPRIO is 0, the thread cannot use RT scheduling at all without
 *     the capability. If the requested priority exceeds both RLIMIT_RTPRIO
 *     and the current priority, EPERM is returned (unless CAP_SYS_NICE is held).
 *
 * constraint: LSM security hooks
 *   desc: The security_task_setscheduler() LSM hook is called after basic
 *     permission checks pass. LSMs like SELinux may impose additional policy
 *     restrictions. SELinux requires the PROCESS__SETSCHED permission on the
 *     target process context.
 *
 * constraint: Policy-priority consistency
 *   desc: The sched_priority value must be consistent with the target thread's
 *     current scheduling policy. RT policies (SCHED_FIFO, SCHED_RR) require
 *     priority 1-99. All other policies (SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE,
 *     SCHED_DEADLINE, SCHED_EXT) require priority 0. Violation returns EINVAL.
 *
 * examples:
 *   struct sched_param sp = { .sched_priority = 50 };
 *   sched_setparam(0, &sp);  // Set current thread RT priority to 50
 *   sp.sched_priority = 0;
 *   sched_setparam(child_pid, &sp);  // Set non-RT thread priority (must be 0)
 *   sp.sched_priority = 99;
 *   sched_setparam(rt_thread, &sp);  // Set max RT priority (requires privilege)
 *
 * notes:
 *   - POSIX.1-2008 conformant. Available on systems defining _POSIX_PRIORITY_SCHEDULING.
 *   - This syscall only modifies priority, not policy. Use sched_setscheduler()
 *     to change both policy and priority, or sched_setattr() for full control.
 *   - The sched_param structure cannot be extended (unlike sched_attr) due to
 *     ABI compatibility - it has no size field for versioning.
 *   - The special SETPARAM_POLICY value (-1) is used internally to signal that
 *     the policy should be preserved. A historical bug (fixed in v3.14, commit
 *     d8d28c8f00e8) caused -1 to incorrectly match SCHED_RESET_ON_FORK masking,
 *     breaking the syscall until the check order was fixed.
 *   - For SCHED_DEADLINE tasks, sched_priority has no effect - deadline parameters
 *     can only be modified via sched_setattr().
 *   - The nice value of a task is preserved across sched_setparam() calls.
 *   - Priority changes trigger PI (priority inheritance) chain updates via
 *     rt_mutex_adjust_pi() to handle any tasks blocked on mutexes held by the
 *     modified task.
 *
 * since-version: 2.0
 */
SYSCALL_DEFINE2(sched_setparam, pid_t, pid, struct sched_param __user *, param)
{
	return do_sched_setscheduler(pid, SETPARAM_POLICY, param);
}

/**
 * sys_sched_setattr - same as above, but with extended sched_attr
 * @pid: the pid in question.
 * @uattr: structure containing the extended parameters.
 * @flags: for future extension.
 */
SYSCALL_DEFINE3(sched_setattr, pid_t, pid, struct sched_attr __user *, uattr,
			       unsigned int, flags)
{
	struct sched_attr attr;
	int retval;

	if (unlikely(!uattr || pid < 0 || flags))
		return -EINVAL;

	retval = sched_copy_attr(uattr, &attr);
	if (retval)
		return retval;

	if ((int)attr.sched_policy < 0)
		return -EINVAL;
	if (attr.sched_flags & SCHED_FLAG_KEEP_POLICY)
		attr.sched_policy = SETPARAM_POLICY;

	CLASS(find_get_task, p)(pid);
	if (!p)
		return -ESRCH;

	if (attr.sched_flags & SCHED_FLAG_KEEP_PARAMS)
		get_params(p, &attr);

	return sched_setattr(p, &attr);
}

/**
 * sys_sched_getscheduler - Get the scheduling policy of a thread
 * @pid: Thread ID to query, or 0 for the calling thread
 *
 * long-desc: Retrieves the current scheduling policy of the specified thread.
 *   This syscall provides a lightweight mechanism to query a thread's
 *   scheduling class without retrieving all scheduling parameters.
 *
 *   The @pid parameter identifies the target thread. If @pid is 0, the calling
 *   thread policy is returned. The thread is looked up via
 *   find_task_by_vpid(), which respects PID namespace boundaries - only threads
 *   visible in the caller's PID namespace can be queried.
 *
 *   On success, the syscall returns the scheduling policy as a non-negative
 *   integer. The base policy value will be one of:
 *   - SCHED_NORMAL (0): Standard time-sharing policy (CFS scheduler)
 *   - SCHED_FIFO (1): First-in-first-out realtime policy
 *   - SCHED_RR (2): Round-robin realtime policy
 *   - SCHED_BATCH (3): Batch processing policy
 *   - SCHED_IDLE (5): Very low priority background tasks
 *   - SCHED_DEADLINE (6): Earliest deadline first realtime policy
 *   - SCHED_EXT (7): Extensible BPF scheduler (if CONFIG_SCHED_CLASS_EXT)
 *
 *   If the thread has the SCHED_RESET_ON_FORK flag set, the return value will
 *   have bit 0x40000000 set in addition to the base policy. This flag indicates
 *   that child processes created via fork() will have their scheduling policy
 *   reset to SCHED_NORMAL with priority 0.
 *
 *   The implementation acquires an RCU read lock to safely look up the thread
 *   and read its policy. Since the policy and sched_reset_on_fork flag are
 *   simple integers, no additional locking is needed - the values read are
 *   guaranteed to be consistent (though they may change immediately after the
 *   syscall returns if another thread modifies the target's policy).
 *
 *   Permission checks are performed by the security_task_getscheduler() LSM
 *   hook. By default, any thread can query any other thread's scheduling
 *   policy. However, LSMs like SELinux may restrict this based on security
 *   policy - SELinux requires the PROCESS__GETSCHED permission on the target
 *   task.
 *
 *   This syscall is the complement to sched_setscheduler(). Together with
 *   sched_getparam(), it allows querying the complete scheduling state of a
 *   thread (though sched_getattr() provides all information in a single call).
 *
 * context-flags: KAPI_CTX_PROCESS
 *
 * param: pid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, PID_MAX_LIMIT
 *   constraint: Must be a valid thread ID in the caller's PID namespace, or 0
 *     to query the calling thread. Negative values return EINVAL. A PID of 0 is
 *     treated specially and always refers to the calling thread via 'current'.
 *     Non-existent or invisible thread IDs return ESRCH.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: scheduling policy value (0-7, possibly OR'd with SCHED_RESET_ON_FORK)
 *   desc: On success, returns the scheduling policy of the target thread as a
 *     non-negative integer. The low bits (0-2) contain the policy value
 *     (SCHED_NORMAL=0, SCHED_FIFO=1, SCHED_RR=2, SCHED_BATCH=3, SCHED_IDLE=5,
 *     SCHED_DEADLINE=6, SCHED_EXT=7). Bit 30 (SCHED_RESET_ON_FORK=0x40000000)
 *     indicates children will reset to SCHED_NORMAL on fork. On failure,
 *     returns a negative error code.
 *
 * error: EINVAL, Invalid pid argument
 *   desc: The @pid argument is negative. Valid PIDs are non-negative integers.
 *     This check is performed before any process lookup occurs. Note that pid 0
 *     is valid and refers to the calling thread.
 *
 * error: ESRCH, No thread found with specified PID
 *   desc: No thread with the specified @pid exists in the caller's PID
 *     namespace. The lookup uses find_task_by_vpid() which respects PID
 *     namespace isolation - threads in parent or sibling PID namespaces are
 *     not visible. This error also occurs if the thread existed but exited
 *     before the lookup completed.
 *
 * error: EACCES, LSM denied the operation
 *   desc: A Linux Security Module (SELinux, etc.) denied permission to query
 *     the target thread's scheduling policy via the security_task_getscheduler()
 *     hook. SELinux requires the PROCESS__GETSCHED permission on the target
 *     task's security context. This error is returned by avc_has_perm() when
 *     the permission check fails. Note: The man page incorrectly documents this
 *     as EPERM; the actual kernel implementation returns EACCES from LSM hooks.
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is acquired via guard(rcu)() to protect the
 *     find_process_by_pid() lookup and subsequent read of the task's policy
 *     and sched_reset_on_fork fields. This prevents the task_struct from being
 *     freed while being accessed. The lock is automatically released when the
 *     function returns (whether success or error).
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: No blocking operations performed
 *   desc: This syscall does not block and completes quickly. The RCU read-side
 *     critical section is non-blocking. There are no interruptible sleep points,
 *     so signals cannot interrupt this syscall. It never returns EINTR or
 *     ERESTARTSYS.
 *   timing: KAPI_SIGNAL_TIME_NONE
 *   restartable: n/a
 *
 * side-effect: KAPI_EFFECT_NONE
 *   target: none
 *   desc: This is a read-only syscall. It does not modify any kernel state,
 *     does not allocate resources, and has no persistent side effects. The
 *     target task's state is not modified in any way.
 *   reversible: n/a
 *
 * capability: none
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: No capabilities are directly checked by this syscall.
 *   without: By default, all processes can query any thread's scheduling policy.
 *   condition: LSMs may impose restrictions based on security policy, not
 *     Linux capabilities. SELinux uses the PROCESS__GETSCHED permission.
 *
 * constraint: PID namespace visibility
 *   desc: The target thread must be visible in the caller's PID namespace.
 *     find_task_by_vpid() performs the lookup in task_active_pid_ns(current),
 *     so processes can only query threads they can "see". Threads in parent
 *     PID namespaces or other containers are not accessible.
 *
 * constraint: LSM policy restrictions
 *   desc: Linux Security Modules may restrict access to scheduling information.
 *     SELinux requires PROCESS__GETSCHED permission. The caller must have
 *     appropriate SELinux policy allowing it to read scheduling information
 *     from the target process's security context.
 *
 * examples:
 *   int policy = sched_getscheduler(0);
 *   int policy = sched_getscheduler(pid);
 *   if (policy & SCHED_RESET_ON_FORK) handle_reset_flag();
 *   int base_policy = policy & ~SCHED_RESET_ON_FORK;
 *
 * notes:
 *   - POSIX.1-2001/2008 conformant. Returns the policy as a non-negative
 *     integer on success, or -1 with errno set on failure.
 *   - The scheduling policy is a per-thread attribute in Linux. The pid
 *     parameter can accept either a process ID from getpid() or a thread ID
 *     from gettid(). When a process ID is used, the main thread policy is
 *     returned.
 *   - The returned value is a snapshot that may become stale immediately if
 *     another thread calls sched_setscheduler() on the target. No locks are
 *     held after the syscall returns to prevent this.
 *   - Unlike sched_getparam() which returns priority via an output parameter,
 *     this syscall uses the return value for the policy. This allows for a
 *     simpler interface when only the policy is needed.
 *   - The SCHED_RESET_ON_FORK flag in the return value was added in Linux
 *     2.6.32. Prior kernels did not report this flag.
 *   - For pthread applications, use pthread_getschedparam(3) which provides
 *     both policy and priority in a single call.
 *   - To get complete scheduling attributes including SCHED_DEADLINE parameters
 *     and nice values, use sched_getattr() instead.
 *   - This syscall is very lightweight - it only acquires RCU read lock and
 *     reads two integer fields. It is suitable for frequent polling if needed.
 *   - The man page documents EPERM as a possible error, but the actual kernel
 *     implementation returns EACCES from LSM hooks. Applications should handle
 *     both error codes for maximum portability.
 *
 * since-version: 2.0
 */
SYSCALL_DEFINE1(sched_getscheduler, pid_t, pid)
{
	struct task_struct *p;
	int retval;

	if (pid < 0)
		return -EINVAL;

	guard(rcu)();
	p = find_process_by_pid(pid);
	if (!p)
		return -ESRCH;

	retval = security_task_getscheduler(p);
	if (!retval) {
		retval = p->policy;
		if (p->sched_reset_on_fork)
			retval |= SCHED_RESET_ON_FORK;
	}
	return retval;
}

/**
 * sys_sched_getparam - Get the scheduling priority of a thread
 * @pid: Thread ID to query, or 0 for the calling thread
 * @param: User-space pointer to struct sched_param to receive the priority
 *
 * long-desc: Retrieves the scheduling parameters (specifically the realtime
 *   priority) of a thread. This syscall is the read-side complement to
 *   sched_setparam() and provides a subset of the information available via
 *   sched_getattr().
 *
 *   The @pid parameter identifies the target thread. If @pid is 0, the calling
 *   thread's parameters are returned. The thread is looked up via
 *   find_task_by_vpid(), which respects PID namespace boundaries - only threads
 *   visible in the caller's PID namespace can be queried.
 *
 *   The @param structure receives a single field, sched_priority, which
 *   contains the thread's realtime priority:
 *   - For SCHED_FIFO and SCHED_RR (realtime policies): sched_priority is the
 *     thread's RT priority in the range 1 to 99 (task->rt_priority), with
 *     higher values meaning higher priority.
 *   - For SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE, SCHED_DEADLINE, and SCHED_EXT:
 *     sched_priority is always 0. These policies do not use RT priority; nice
 *     values or deadline parameters control scheduling instead.
 *
 *   POSIX specifies that sched_getparam() should only be called when
 *   sched_getscheduler() returns SCHED_FIFO or SCHED_RR. The Linux
 *   implementation extends this by returning 0 for all other policies rather
 *   than returning an error, maintaining backwards compatibility.
 *
 *   The implementation acquires an RCU read lock to safely look up the thread
 *   and read its scheduling policy and rt_priority. The RCU lock is released
 *   before calling copy_to_user(), which may sleep. Since the read values are
 *   simple integers, no additional locking is needed - the values are snapshots
 *   that may change immediately after the syscall returns if another thread
 *   modifies the target's scheduling parameters.
 *
 *   Permission checks are performed by the security_task_getscheduler() LSM
 *   hook. By default, any thread can query any other thread's scheduling
 *   parameters. However, LSMs like SELinux or Smack may restrict this based on
 *   security policy.
 *
 *   Historical note: Prior to kernel 3.14 (commit ce5f7f8200ca), calling
 *   sched_getparam() on a SCHED_DEADLINE task returned EINVAL. This was changed
 *   to return sched_priority=0 for consistency with other non-RT policies.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: pid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, PID_MAX_LIMIT
 *   constraint: Must be a valid thread ID in the caller's PID namespace, or 0
 *     to query the calling thread. Negative values return EINVAL. A PID of 0 is
 *     treated specially and always refers to the calling thread via 'current'.
 *     Non-existent or invisible thread IDs return ESRCH.
 *
 * param: param
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid user-space pointer to struct sched_param. The
 *     structure must be writable by the kernel (copy_to_user must succeed).
 *     NULL returns EINVAL. Invalid pointer returns EFAULT. The structure size
 *     is sizeof(struct sched_param) which contains a single int sched_priority.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success, indicating the scheduling parameters have been
 *     written to @param. The sched_priority field will contain the RT priority
 *     (1-99) for SCHED_FIFO/SCHED_RR tasks, or 0 for all other scheduling
 *     policies.
 *
 * error: EINVAL, Invalid pid or param argument
 *   desc: Returned when @pid is negative (pid < 0) or when @param is NULL.
 *     This check is performed first, before any process lookup or permission
 *     checks occur. Note that pid 0 is valid and refers to the calling thread.
 *     The unlikely() hint is used on this check path for branch optimization.
 *
 * error: ESRCH, No thread found with specified PID
 *   desc: No thread with the specified @pid exists in the caller's PID
 *     namespace. The lookup uses find_task_by_vpid() which respects PID
 *     namespace isolation - threads in parent or sibling PID namespaces are
 *     not visible. This error also occurs if the thread existed but exited
 *     before the lookup completed. When pid is 0, this error cannot occur
 *     as find_process_by_pid() returns 'current' directly.
 *
 * error: EACCES, LSM denied the operation
 *   desc: A Linux Security Module denied permission to query the target
 *     thread's scheduling parameters via security_task_getscheduler(). SELinux
 *     requires PROCESS__GETSCHED permission, Smack requires MAY_READ access.
 *     Note: The man page does not document this error, but it is returned by
 *     the actual kernel implementation when LSMs are active.
 *
 * error: EFAULT, Invalid user-space pointer
 *   desc: The @param pointer is invalid and copy_to_user() failed. The pointer
 *     may be unmapped, point to kernel memory, be read-only, or otherwise be
 *     inaccessible for writing from user space. This error is returned after
 *     all permission checks pass and the scheduling parameters have been read
 *     from the target task.
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is acquired via scoped_guard(rcu) to protect the
 *     find_process_by_pid() lookup and subsequent read of the task's policy
 *     and rt_priority fields. This prevents the task_struct from being freed
 *     while being accessed. The lock is released when the scoped_guard block
 *     exits, which happens before the copy_to_user() call since that operation
 *     may sleep. The comment in the source explicitly notes "This one might
 *     sleep, we cannot do it with a spinlock held".
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: No interruptible wait points
 *   desc: This syscall does not block in a signal-interruptible manner. The
 *     RCU read-side critical section is non-blocking. While copy_to_user() may
 *     fault and potentially sleep for page-in, this is not interruptible by
 *     signals in a way that would return EINTR. The syscall never returns
 *     EINTR or ERESTARTSYS.
 *   timing: KAPI_SIGNAL_TIME_NONE
 *   restartable: n/a
 *
 * side-effect: KAPI_EFFECT_NONE
 *   target: none
 *   desc: This is a read-only syscall. It does not modify any kernel state,
 *     does not allocate persistent resources, and has no lasting side effects.
 *     The target task's state is not modified in any way. The only memory
 *     modified is the user-space @param structure, which receives the output.
 *   reversible: n/a
 *
 * capability: none
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: No capabilities are directly checked by this syscall.
 *   without: By default, all processes can query any thread's scheduling
 *     parameters. The kernel imposes no capability-based restrictions.
 *   condition: LSMs may impose restrictions based on security policy, not
 *     Linux capabilities. SELinux uses the PROCESS__GETSCHED permission,
 *     Smack checks MAY_READ access between security labels.
 *
 * constraint: PID namespace visibility
 *   desc: The target thread must be visible in the caller's PID namespace.
 *     find_task_by_vpid() performs the lookup in task_active_pid_ns(current),
 *     so processes can only query threads they can "see". Threads in parent
 *     PID namespaces, sibling namespaces, or other containers are not
 *     accessible and result in ESRCH.
 *
 * constraint: LSM policy restrictions
 *   desc: Linux Security Modules may restrict access to scheduling information.
 *     SELinux: requires PROCESS__GETSCHED permission from the calling process's
 *     security context to the target process's security context.
 *     Smack: requires MAY_READ access from the caller's Smack label to the
 *     target task's Smack label.
 *
 * examples:
 *   struct sched_param sp;
 *   sched_getparam(0, &sp);  // Get own priority
 *   sched_getparam(pid, &sp);  // Get another thread's priority
 *   if (sched_getscheduler(pid) == SCHED_FIFO)
 *       printf("RT priority: %d\n", sp.sched_priority);  // 1-99
 *   else
 *       printf("Not RT, priority: %d\n", sp.sched_priority);  // Always 0
 *
 * notes:
 *   - POSIX.1-2001/2008 conformant. Available on systems defining
 *     _POSIX_PRIORITY_SCHEDULING in <unistd.h>.
 *   - POSIX says sched_getparam() should only be called when sched_getscheduler()
 *     returns SCHED_FIFO or SCHED_RR. Linux extends this by returning 0 for
 *     non-RT policies instead of an error.
 *   - The sched_param structure has only one field: int sched_priority. Unlike
 *     sched_attr, it cannot be extended without breaking ABI compatibility.
 *   - For complete scheduling information including nice values, SCHED_DEADLINE
 *     parameters, and utilization clamp values, use sched_getattr() instead.
 *   - The returned value is a snapshot that may become stale immediately if
 *     another thread calls sched_setscheduler() or sched_setparam() on the
 *     target. No locks are held after the syscall returns.
 *   - The scheduling parameters are per-thread attributes in Linux. The pid
 *     parameter accepts either a process ID from getpid() or a thread ID from
 *     gettid(). When a process ID is used, the main thread's parameters are
 *     returned.
 *   - For pthread applications, use pthread_getschedparam(3) which provides
 *     both policy and priority in a single call.
 *   - Prior to Linux 3.14, calling sched_getparam() on a SCHED_DEADLINE task
 *     returned EINVAL. This was changed for consistency (commit ce5f7f8200ca).
 *   - The man page does not document EACCES, but it can be returned by LSM
 *     hooks (SELinux, Smack). Applications should handle both EACCES and the
 *     documented errors for maximum portability.
 *   - This syscall is very lightweight when the target thread is known to
 *     exist - it only acquires RCU read lock and reads a few integers.
 *
 * since-version: 2.0
 */
SYSCALL_DEFINE2(sched_getparam, pid_t, pid, struct sched_param __user *, param)
{
	struct sched_param lp = { .sched_priority = 0 };
	struct task_struct *p;
	int retval;

	if (unlikely(!param || pid < 0))
		return -EINVAL;

	scoped_guard (rcu) {
		p = find_process_by_pid(pid);
		if (!p)
			return -ESRCH;

		retval = security_task_getscheduler(p);
		if (retval)
			return retval;

		if (task_has_rt_policy(p))
			lp.sched_priority = p->rt_priority;
	}

	/*
	 * This one might sleep, we cannot do it with a spinlock held ...
	 */
	return copy_to_user(param, &lp, sizeof(*param)) ? -EFAULT : 0;
}

/**
 * sys_sched_getattr - similar to sched_getparam, but with sched_attr
 * @pid: the pid in question.
 * @uattr: structure containing the extended parameters.
 * @usize: sizeof(attr) for fwd/bwd comp.
 * @flags: for future extension.
 */
SYSCALL_DEFINE4(sched_getattr, pid_t, pid, struct sched_attr __user *, uattr,
		unsigned int, usize, unsigned int, flags)
{
	struct sched_attr kattr = { };
	struct task_struct *p;
	int retval;

	if (unlikely(!uattr || pid < 0 || usize > PAGE_SIZE ||
		      usize < SCHED_ATTR_SIZE_VER0 || flags))
		return -EINVAL;

	scoped_guard (rcu) {
		p = find_process_by_pid(pid);
		if (!p)
			return -ESRCH;

		retval = security_task_getscheduler(p);
		if (retval)
			return retval;

		kattr.sched_policy = p->policy;
		if (p->sched_reset_on_fork)
			kattr.sched_flags |= SCHED_FLAG_RESET_ON_FORK;
		get_params(p, &kattr);
		kattr.sched_flags &= SCHED_FLAG_ALL;

#ifdef CONFIG_UCLAMP_TASK
		/*
		 * This could race with another potential updater, but this is fine
		 * because it'll correctly read the old or the new value. We don't need
		 * to guarantee who wins the race as long as it doesn't return garbage.
		 */
		kattr.sched_util_min = p->uclamp_req[UCLAMP_MIN].value;
		kattr.sched_util_max = p->uclamp_req[UCLAMP_MAX].value;
#endif
	}

	kattr.size = min(usize, sizeof(kattr));
	return copy_struct_to_user(uattr, usize, &kattr, sizeof(kattr), NULL);
}

int dl_task_check_affinity(struct task_struct *p, const struct cpumask *mask)
{
	/*
	 * If the task isn't a deadline task or admission control is
	 * disabled then we don't care about affinity changes.
	 */
	if (!task_has_dl_policy(p) || !dl_bandwidth_enabled())
		return 0;

	/*
	 * The special/sugov task isn't part of regular bandwidth/admission
	 * control so let userspace change affinities.
	 */
	if (dl_entity_is_special(&p->dl))
		return 0;

	/*
	 * Since bandwidth control happens on root_domain basis,
	 * if admission test is enabled, we only admit -deadline
	 * tasks allowed to run on all the CPUs in the task's
	 * root_domain.
	 */
	guard(rcu)();
	if (!cpumask_subset(task_rq(p)->rd->span, mask))
		return -EBUSY;

	return 0;
}

int __sched_setaffinity(struct task_struct *p, struct affinity_context *ctx)
{
	int retval;
	cpumask_var_t cpus_allowed, new_mask;

	if (!alloc_cpumask_var(&cpus_allowed, GFP_KERNEL))
		return -ENOMEM;

	if (!alloc_cpumask_var(&new_mask, GFP_KERNEL)) {
		retval = -ENOMEM;
		goto out_free_cpus_allowed;
	}

	cpuset_cpus_allowed(p, cpus_allowed);
	cpumask_and(new_mask, ctx->new_mask, cpus_allowed);

	ctx->new_mask = new_mask;
	ctx->flags |= SCA_CHECK;

	retval = dl_task_check_affinity(p, new_mask);
	if (retval)
		goto out_free_new_mask;

	retval = __set_cpus_allowed_ptr(p, ctx);
	if (retval)
		goto out_free_new_mask;

	cpuset_cpus_allowed(p, cpus_allowed);
	if (!cpumask_subset(new_mask, cpus_allowed)) {
		/*
		 * We must have raced with a concurrent cpuset update.
		 * Just reset the cpumask to the cpuset's cpus_allowed.
		 */
		cpumask_copy(new_mask, cpus_allowed);

		/*
		 * If SCA_USER is set, a 2nd call to __set_cpus_allowed_ptr()
		 * will restore the previous user_cpus_ptr value.
		 *
		 * In the unlikely event a previous user_cpus_ptr exists,
		 * we need to further restrict the mask to what is allowed
		 * by that old user_cpus_ptr.
		 */
		if (unlikely((ctx->flags & SCA_USER) && ctx->user_mask)) {
			bool empty = !cpumask_and(new_mask, new_mask,
						  ctx->user_mask);

			if (empty)
				cpumask_copy(new_mask, cpus_allowed);
		}
		__set_cpus_allowed_ptr(p, ctx);
		retval = -EINVAL;
	}

out_free_new_mask:
	free_cpumask_var(new_mask);
out_free_cpus_allowed:
	free_cpumask_var(cpus_allowed);
	return retval;
}

long sched_setaffinity(pid_t pid, const struct cpumask *in_mask)
{
	struct affinity_context ac;
	struct cpumask *user_mask;
	int retval;

	CLASS(find_get_task, p)(pid);
	if (!p)
		return -ESRCH;

	if (p->flags & PF_NO_SETAFFINITY)
		return -EINVAL;

	if (!check_same_owner(p)) {
		guard(rcu)();
		if (!ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE))
			return -EPERM;
	}

	retval = security_task_setscheduler(p);
	if (retval)
		return retval;

	/*
	 * With non-SMP configs, user_cpus_ptr/user_mask isn't used and
	 * alloc_user_cpus_ptr() returns NULL.
	 */
	user_mask = alloc_user_cpus_ptr(NUMA_NO_NODE);
	if (user_mask) {
		cpumask_copy(user_mask, in_mask);
	} else {
		return -ENOMEM;
	}

	ac = (struct affinity_context){
		.new_mask  = in_mask,
		.user_mask = user_mask,
		.flags     = SCA_USER,
	};

	retval = __sched_setaffinity(p, &ac);
	kfree(ac.user_mask);

	return retval;
}

static int get_user_cpu_mask(unsigned long __user *user_mask_ptr, unsigned len,
			     struct cpumask *new_mask)
{
	if (len < cpumask_size())
		cpumask_clear(new_mask);
	else if (len > cpumask_size())
		len = cpumask_size();

	return copy_from_user(new_mask, user_mask_ptr, len) ? -EFAULT : 0;
}

/**
 * sys_sched_setaffinity - set the CPU affinity mask of a thread
 * @pid: thread ID of the target thread (0 means calling thread)
 * @len: length in bytes of the bitmask pointed to by user_mask_ptr
 * @user_mask_ptr: user-space pointer to the new CPU affinity mask
 *
 * long-desc: Sets the CPU affinity mask of the thread specified by @pid to the
 *   value pointed to by @user_mask_ptr. The CPU affinity mask determines which
 *   CPUs the thread is eligible to run on. If the thread is not currently
 *   running on one of the CPUs specified in the new mask, it will be migrated
 *   to an eligible CPU. The @pid argument is a thread ID (the value returned by
 *   gettid() or clone()), not a process ID - to operate on a different thread
 *   in a multi-threaded process, use the specific thread's TID. When @pid is 0,
 *   the calling thread is modified.
 *
 *   The @len parameter specifies the size in bytes of the affinity mask. If
 *   @len is smaller than the kernel's cpumask_size(), the remaining bits are
 *   treated as zero. If @len is larger, only cpumask_size() bytes are copied.
 *   This allows the syscall to work across kernel versions with different
 *   NR_CPUS configurations.
 *
 *   The actual affinity is constrained to the intersection of the requested
 *   mask and the CPUs allowed by the task's cpuset. If this intersection is
 *   empty, the syscall fails with -EINVAL. The kernel preserves the
 *   user-requested mask internally, so if the cpuset later expands to include
 *   more CPUs that match the original request, the task may run on those CPUs.
 *
 *   Child processes created via fork() inherit the parent's CPU affinity mask.
 *   The affinity mask is preserved across execve(). Each thread in a thread
 *   group can have its own affinity mask, adjusted independently.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: pid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, PID_MAX_LIMIT
 *   constraint: Must be either 0 (for the calling thread) or a valid thread ID
 *     in the caller's PID namespace. Negative values are not valid but are
 *     treated as a lookup for a non-existent thread (returns -ESRCH). The value
 *     is interpreted as a TID (thread ID), not a TGID (process ID). Using a
 *     TGID will only affect the main thread of that process, not all threads.
 *
 * param: len
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, UINT_MAX
 *   constraint: Length in bytes of the user-space CPU mask buffer. The kernel
 *     handles variable-sized masks: if @len is less than cpumask_size(), the
 *     kernel clears the mask first then copies @len bytes (remaining bits are
 *     zero). If @len is greater than cpumask_size(), only cpumask_size() bytes
 *     are copied. A @len of 0 results in an empty mask, which will fail with
 *     -EINVAL if it results in no valid CPUs.
 *
 * param: user_mask_ptr
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid user-space pointer to a buffer of at least
 *     @len bytes containing the desired CPU affinity bitmask. The mask is a
 *     bitmap where bit N set indicates CPU N is allowed. If @user_mask_ptr is
 *     NULL or points to inaccessible memory, copy_from_user() fails and the
 *     syscall returns -EFAULT. The buffer does not need to be aligned.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success, indicating the thread's CPU affinity has been
 *     updated. The thread will be migrated to an allowed CPU if necessary.
 *     The user-requested mask is stored internally and will be used to restore
 *     affinity if the cpuset later changes to permit more CPUs.
 *
 * error: ENOMEM, Out of memory
 *   desc: Memory allocation failed. The syscall allocates temporary cpumask
 *     structures (via alloc_cpumask_var() with GFP_KERNEL) and storage for the
 *     user-requested mask (via alloc_user_cpus_ptr()). This error is most
 *     likely under extreme memory pressure. On non-SMP kernels where
 *     alloc_user_cpus_ptr() returns NULL by design, this path is handled
 *     specially and does not trigger ENOMEM.
 *
 * error: EFAULT, Bad address
 *   desc: The @user_mask_ptr pointer is invalid or inaccessible. Returned when
 *     copy_from_user() fails to read @len bytes from @user_mask_ptr. This
 *     occurs when the pointer is NULL, points to unmapped memory, points to
 *     kernel memory, or the buffer is not fully readable.
 *
 * error: ESRCH, No such process
 *   desc: No thread with the specified @pid exists in the caller's PID
 *     namespace. The lookup uses find_task_by_vpid() which respects PID
 *     namespace isolation - threads in parent or sibling PID namespaces are
 *     not visible. This error also occurs if the thread existed but exited
 *     before the lookup completed. When @pid is 0, this error cannot occur
 *     as the calling thread is used directly.
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned in several cases: (1) The target task has the
 *     PF_NO_SETAFFINITY flag set, indicating it is a special kernel thread
 *     (such as per-CPU kthreads, migration threads, or workqueue workers)
 *     whose affinity userspace is not allowed to modify. (2) The effective
 *     CPU mask (intersection of requested mask with cpuset-allowed CPUs)
 *     contains no active CPUs. (3) For non-kthread tasks, the requested mask
 *     is not a subset of task_cpu_possible_mask() (which may be restricted on
 *     asymmetric systems). (4) A race with concurrent cpuset updates caused
 *     the effective mask to become invalid; in this case the kernel attempts
 *     to fall back to the cpuset mask, but if this also fails the syscall
 *     returns -EINVAL. (5) For tasks with migration disabled, if the new mask
 *     does not include the CPU the task is currently running on.
 *
 * error: EPERM, Operation not permitted
 *   desc: Permission denied. The caller does not have permission to modify the
 *     target thread's affinity. This occurs when: (1) The calling process does
 *     not own the target thread (i.e., caller's EUID does not match the target
 *     thread's UID or EUID), AND (2) the caller lacks the CAP_SYS_NICE
 *     capability in the target thread's user namespace. The ownership check
 *     uses check_same_owner() and compares effective UIDs.
 *
 * error: EACCES, Permission denied (LSM)
 *   desc: A Linux Security Module (such as SELinux, AppArmor, Smack, or
 *     another LSM) denied permission to modify the target thread's scheduling
 *     parameters via the security_task_setscheduler() hook. SELinux requires
 *     the PROCESS__SETSCHED permission for this operation. This error is
 *     distinct from EPERM which is returned for capability/ownership checks.
 *
 * error: EBUSY, Device or resource busy
 *   desc: Returned for SCHED_DEADLINE tasks when the requested CPU affinity
 *     mask is not a superset of the root domain's span. SCHED_DEADLINE uses
 *     per-root-domain bandwidth accounting, so a deadline task must be able
 *     to run on all CPUs in its root domain. The check is performed by
 *     dl_task_check_affinity() and only applies when deadline bandwidth
 *     control is enabled. Regular (non-deadline) tasks do not encounter this
 *     error. Also returned if the current task has migration disabled and
 *     the new mask doesn't include the current CPU.
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is acquired via guard(rcu)() in find_get_task() when
 *     looking up the target thread, and in check_same_owner() when comparing
 *     credentials. This protects the task_struct and cred structures from
 *     being freed during access. The task's reference count is incremented
 *     before RCU unlock using get_task_struct(), and decremented after the
 *     operation completes via the CLASS(find_get_task) destructor.
 *
 * lock: pi_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The target task's pi_lock (priority inheritance lock) is acquired
 *     as part of task_rq_lock() in __set_cpus_allowed_ptr(). This spinlock
 *     protects the task's scheduling-related fields including cpus_mask and
 *     user_cpus_ptr. Acquired with interrupts disabled (raw_spin_lock_irqsave).
 *     The lock ordering is: pi_lock -> rq->lock.
 *
 * lock: rq->lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The per-CPU run queue lock is acquired via task_rq_lock() in
 *     __set_cpus_allowed_ptr(). This lock serializes modifications to the
 *     task's CPU affinity and ensures atomic updates to run queue data
 *     structures during potential task migration. Released before the
 *     function returns, but may be temporarily dropped during migration.
 *
 * lock: callback_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The cpuset callback_lock is acquired with spin_lock_irqsave() in
 *     cpuset_cpus_allowed() when reading the task's cpuset-allowed CPUs.
 *     This ensures a consistent view of the cpuset's effective_cpus mask
 *     while determining which CPUs the task may actually use.
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: Syscall has no interruptible wait points
 *   desc: This syscall does not have explicit signal handling. While it uses
 *     GFP_KERNEL allocations which can sleep, these are not interruptible by
 *     signals. The spinlocks used (pi_lock, rq->lock) are not sleeping locks.
 *     The syscall does not return EINTR or ERESTARTSYS. A pending signal will
 *     be delivered after the syscall completes.
 *   timing: KAPI_SIGNAL_TIME_NONE
 *   restartable: n/a
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task CPU affinity mask (cpus_mask and cpus_ptr)
 *   desc: Modifies the target task's cpus_mask field to reflect the new
 *     allowed CPUs (intersection of requested mask and cpuset). Also updates
 *     cpus_ptr which points to the effective mask. The task can only be
 *     scheduled on CPUs in this mask after the syscall returns.
 *   reversible: yes (can be changed with another sched_setaffinity call)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task user_cpus_ptr (user-requested affinity)
 *   desc: Saves a copy of the user-requested affinity mask in the task's
 *     user_cpus_ptr field. This is the original mask requested by userspace,
 *     before intersection with cpuset-allowed CPUs. The kernel preserves this
 *     so that if the cpuset later expands, the task's affinity can be
 *     automatically updated to include more CPUs from the original request.
 *     Memory for this mask is allocated with GFP_KERNEL. On SMP systems, this
 *     is always allocated; on non-SMP it remains NULL.
 *   condition: Always on SMP systems
 *   reversible: yes (replaced by subsequent sched_setaffinity calls)
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: task migration and run queue placement
 *   desc: If the task is not currently running on a CPU in the new affinity
 *     mask, it will be migrated to an eligible CPU. For runnable tasks, this
 *     may involve removing the task from its current run queue and adding it
 *     to another CPU's run queue. The migration uses affine_move_task() which
 *     may use CPU stop machine for synchronous migration. If the task is
 *     currently running on a CPU that is no longer allowed, it will be
 *     migrated when it next enters the scheduler.
 *   condition: Current CPU not in new mask
 *   reversible: n/a (migration is immediate)
 *
 * side-effect: KAPI_EFFECT_PROCESS_STATE
 *   target: task reference count
 *   desc: The target task's reference count is incremented by find_get_task()
 *     (via get_task_struct()) to prevent the task from being freed during
 *     the operation. The reference is automatically decremented when the
 *     CLASS(find_get_task) destructor runs via put_task_struct().
 *   reversible: yes (automatically within syscall)
 *
 * state-trans: task_cpus_mask
 *   from: previous CPU affinity mask
 *   to: intersection of requested mask and cpuset-allowed CPUs
 *   condition: Successful completion of __set_cpus_allowed_ptr()
 *   desc: The task's effective CPU affinity transitions from its previous
 *     value to the new value. If the new mask equals the old mask,
 *     only the user_cpus_ptr is updated (no migration occurs).
 *
 * state-trans: task_user_cpus_ptr
 *   from: previous user-requested mask (or NULL if never set)
 *   to: copy of newly requested mask from userspace
 *   condition: Successful set with SCA_USER flag
 *   desc: The stored user-requested affinity transitions to the new value.
 *     This may differ from the effective cpus_mask if cpuset constraints
 *     apply. The old user_cpus_ptr is freed via kfree() after the new
 *     one is installed.
 *
 * capability: CAP_SYS_NICE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Modifying the CPU affinity of threads owned by other users. When
 *     the caller's EUID does not match the target thread's UID or EUID, this
 *     capability (checked in the target's user namespace via ns_capable())
 *     allows the operation to proceed.
 *   without: The syscall returns -EPERM if the caller does not own the target
 *     thread and lacks this capability. Ownership means the caller's EUID
 *     matches the target's UID or EUID.
 *   condition: Checked only when check_same_owner() returns false
 *
 * constraint: cpuset restrictions
 *   desc: The effective CPU affinity is always constrained to the CPUs allowed
 *     by the task's cpuset (determined by cpuset_cpus_allowed()). The syscall
 *     stores the user-requested mask but the actual schedulable CPUs are the
 *     intersection with cpuset-allowed CPUs. If this intersection is empty,
 *     the syscall fails with -EINVAL.
 *
 * constraint: PF_NO_SETAFFINITY flag
 *   desc: Certain kernel threads have the PF_NO_SETAFFINITY flag set, which
 *     prevents userspace from modifying their CPU affinity. These include
 *     per-CPU kthreads, migration threads, and some workqueue workers. The
 *     check is performed both at the beginning of sched_setaffinity() and
 *     again under locks in __set_cpus_allowed_ptr_locked() to handle races.
 *     Attempting to modify such a task returns -EINVAL.
 *
 * constraint: SCHED_DEADLINE root domain coverage
 *   desc: Tasks using the SCHED_DEADLINE scheduling policy must have an
 *     affinity mask that is a superset of their root domain's CPU span when
 *     deadline bandwidth control is enabled. This ensures proper bandwidth
 *     accounting across the root domain. The check is performed by
 *     dl_task_check_affinity() and returns -EBUSY if violated.
 *
 * constraint: migration_disabled tasks
 *   desc: If a task has migration disabled (via migrate_disable()), its
 *     affinity can only be changed to a mask that includes its current CPU.
 *     Attempting to set an affinity that excludes the current CPU when
 *     migration is disabled returns -EBUSY. This protects tasks that have
 *     explicitly requested to stay on their current CPU.
 *
 * examples: sched_setaffinity(0, sizeof(cpu_set_t), &mask);  // Set calling thread
 *   sched_setaffinity(pid, sizeof(cpu_set_t), &mask);  // Set specific thread
 *   sched_setaffinity(gettid(), 8, &mask);  // 8-byte (64 CPU) mask
 *
 * notes: The glibc wrapper function for sched_setaffinity() differs from
 *   the raw kernel syscall. The glibc version has signature:
 *   int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
 *   and always returns 0 on success or -1 with errno set on failure.
 *
 *   On NUMA systems, binding tasks to specific CPUs can significantly affect
 *   performance due to memory locality. Consider using libnuma or mbind()
 *   in conjunction with CPU affinity for optimal NUMA placement.
 *
 *   The kernel's NR_CPUS configuration determines the maximum number of CPUs
 *   supported. On systems with more than 1024 CPUs, the standard cpu_set_t
 *   (128 bytes, supporting up to 1024 CPUs) is insufficient and dynamic
 *   allocation via CPU_ALLOC() is required.
 *
 *   When using isolcpus= kernel boot parameter to isolate CPUs from the
 *   scheduler, sched_setaffinity() or cpuset cgroups are the only ways to
 *   schedule tasks on those isolated CPUs.
 *
 *   Race condition handling: If a cpuset update races with this syscall,
 *   the kernel handles it gracefully. The syscall may return -EINVAL if the
 *   cpuset changes make the requested affinity impossible, but it will not
 *   leave the task in an inconsistent state. Historical race conditions
 *   between fork() and sched_setaffinity() have been fixed (see commit
 *   87ca4f9efbd7c for use-after-free fix in dup_user_cpus_ptr()).
 *
 * since-version: 2.5.8
 */
SYSCALL_DEFINE3(sched_setaffinity, pid_t, pid, unsigned int, len,
		unsigned long __user *, user_mask_ptr)
{
	cpumask_var_t new_mask;
	int retval;

	if (!alloc_cpumask_var(&new_mask, GFP_KERNEL))
		return -ENOMEM;

	retval = get_user_cpu_mask(user_mask_ptr, len, new_mask);
	if (retval == 0)
		retval = sched_setaffinity(pid, new_mask);
	free_cpumask_var(new_mask);
	return retval;
}

long sched_getaffinity(pid_t pid, struct cpumask *mask)
{
	struct task_struct *p;
	int retval;

	guard(rcu)();
	p = find_process_by_pid(pid);
	if (!p)
		return -ESRCH;

	retval = security_task_getscheduler(p);
	if (retval)
		return retval;

	guard(raw_spinlock_irqsave)(&p->pi_lock);
	cpumask_and(mask, &p->cpus_mask, cpu_active_mask);

	return 0;
}

/**
 * sys_sched_getaffinity - get the CPU affinity mask of a thread
 * @pid: thread ID of the target thread (0 means calling thread)
 * @len: length in bytes of the buffer pointed to by user_mask_ptr
 * @user_mask_ptr: user-space pointer to receive the current CPU affinity mask
 *
 * long-desc: Retrieves the CPU affinity mask of the thread specified by @pid
 *   and writes it to the buffer pointed to by @user_mask_ptr. The CPU affinity
 *   mask indicates which CPUs the thread is currently eligible to run on. The
 *   returned mask is the intersection of the thread's affinity mask and the
 *   currently active CPUs (cpu_active_mask), so it reflects the CPUs on which
 *   the thread can actually be scheduled.
 *
 *   The @pid argument is a thread ID (the value returned by gettid() or
 *   clone()), not a process ID. To query the affinity of a specific thread in
 *   a multi-threaded process, use that thread's TID. Using a TGID returns the
 *   affinity of only the main thread. When @pid is 0, the calling thread's own
 *   affinity is returned.
 *
 *   The @len parameter specifies the size in bytes of the buffer at
 *   @user_mask_ptr. It must be large enough to hold at least nr_cpu_ids bits
 *   (rounded up to bytes), and must be aligned to sizeof(unsigned long). If
 *   these requirements are not met, the syscall returns -EINVAL. If @len is
 *   larger than cpumask_size(), only cpumask_size() bytes are copied to
 *   userspace. The returned value indicates how many bytes were actually
 *   copied.
 *
 *   Unlike sched_setaffinity() which requires privilege to modify another
 *   thread's affinity, sched_getaffinity() only requires permission via the
 *   LSM security_task_getscheduler() hook. In standard DAC (no LSM), any
 *   thread can query any other thread's affinity if it is visible in the
 *   caller's PID namespace.
 *
 *   The mask is zero-filled before being populated, so any bits beyond the
 *   actual number of CPUs will be zero. This was fixed in kernel 6.3 by
 *   commit 6015b1aca1a23 which changed from alloc_cpumask_var() to
 *   zalloc_cpumask_var() to ensure the entire buffer is initialized.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: pid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: 0, PID_MAX_LIMIT
 *   constraint: Must be either 0 (for the calling thread) or a valid thread ID
 *     in the caller's PID namespace. Negative values are treated as a lookup
 *     for a non-existent thread and return -ESRCH. The value is interpreted as
 *     a TID (thread ID), not a TGID. Using a TGID will return only the main
 *     thread's affinity.
 *
 * param: len
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Length in bytes of the user-space buffer. Must satisfy two
 *     requirements: (1) len * 8 >= nr_cpu_ids (buffer must hold enough bits
 *     for all possible CPU IDs), and (2) len must be aligned to
 *     sizeof(unsigned long) (8 bytes on 64-bit, 4 bytes on 32-bit). Failure
 *     to meet either requirement returns -EINVAL. If len > cpumask_size(),
 *     only cpumask_size() bytes are copied. The standard glibc cpu_set_t is
 *     128 bytes (1024 CPUs), which is sufficient for most systems.
 *
 * param: user_mask_ptr
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid user-space pointer to a writable buffer of at
 *     least @len bytes to receive the CPU affinity bitmask. The mask is a
 *     bitmap where bit N set indicates CPU N is in the affinity set. If
 *     @user_mask_ptr is NULL or points to inaccessible memory, copy_to_user()
 *     fails and the syscall returns -EFAULT. The buffer need not be aligned,
 *     though alignment may improve performance.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_RANGE
 *   success: min(len, cpumask_size())
 *   desc: On success, returns the number of bytes copied to user_mask_ptr,
 *     which is min(len, cpumask_size()). This value indicates how many bytes
 *     of the mask are valid. Note that the kernel syscall returns the size on
 *     success, while the glibc wrapper returns 0 on success and -1 on error.
 *     The value returned can be used to determine the kernel's cpumask_size(),
 *     which reflects NR_CPUS configuration.
 *
 * error: EINVAL, Invalid len argument
 *   desc: Returned when the @len argument fails validation. Two checks are
 *     performed: (1) len * BITS_PER_BYTE must be >= nr_cpu_ids, meaning the
 *     buffer must be large enough to hold a bit for each possible CPU. On a
 *     system with 256 possible CPUs, this requires at least 32 bytes. (2) len
 *     must be a multiple of sizeof(unsigned long) (8 on 64-bit, 4 on 32-bit).
 *     For the compat syscall on 64-bit kernels, alignment is to
 *     sizeof(compat_ulong_t) which is 4 bytes.
 *
 * error: ENOMEM, Out of memory
 *   desc: Memory allocation failed. The syscall allocates a temporary cpumask
 *     structure via zalloc_cpumask_var() with GFP_KERNEL. This is a sleepable
 *     allocation that only fails under extreme memory pressure. The cpumask
 *     is freed before the syscall returns regardless of success or failure.
 *
 * error: ESRCH, No such process
 *   desc: No thread with the specified @pid exists in the caller's PID
 *     namespace. The lookup uses find_task_by_vpid() which respects PID
 *     namespace isolation - threads in parent or sibling PID namespaces are
 *     not visible. This error also occurs if the thread existed but exited
 *     before the lookup completed. When @pid is 0, this error cannot occur
 *     since find_process_by_pid() returns 'current' directly.
 *
 * error: EACCES, Permission denied (LSM)
 *   desc: A Linux Security Module denied permission to query the target
 *     thread's scheduling parameters via security_task_getscheduler(). SELinux
 *     requires PROCESS__GETSCHED permission from the caller's security context
 *     to the target's context. Smack requires MAY_READ access from the caller's
 *     Smack label to the target's label. AppArmor does not implement this hook.
 *     Note that unlike sched_setaffinity(), there is no DAC permission check
 *     (CAP_SYS_NICE is not required), only LSM checks apply.
 *
 * error: EFAULT, Bad address
 *   desc: The @user_mask_ptr pointer is invalid or not writable. Returned when
 *     copy_to_user() fails to write to the user buffer. This occurs when the
 *     pointer is NULL, points to unmapped memory, points to kernel memory,
 *     points to read-only memory, or the buffer is not fully writable for the
 *     required length.
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is acquired via guard(rcu)() to protect the
 *     find_process_by_pid() lookup and subsequent access to the task's
 *     cpus_mask. This prevents the task_struct from being freed while being
 *     accessed. The lock is automatically released when the function returns.
 *     The RCU critical section encompasses the task lookup, security check,
 *     and cpumask read.
 *
 * lock: p->pi_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The target task's pi_lock (priority inheritance lock) is acquired
 *     via guard(raw_spinlock_irqsave)(&p->pi_lock) while reading the task's
 *     cpus_mask. This spinlock protects the task's scheduling-related fields
 *     including cpus_mask from concurrent modification by sched_setaffinity().
 *     The lock is held with interrupts disabled and is released before
 *     returning from sched_getaffinity(). Note that copy_to_user() is called
 *     after the lock is released since it may sleep.
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: Syscall has minimal blocking points
 *   desc: This syscall does not have explicit signal handling. The
 *     zalloc_cpumask_var() call uses GFP_KERNEL which may sleep but is not
 *     interruptible. The copy_to_user() may also sleep during page faults
 *     but is not interruptible. The syscall does not return EINTR or
 *     ERESTARTSYS. A pending signal will be delivered after the syscall
 *     completes.
 *   timing: KAPI_SIGNAL_TIME_NONE
 *   restartable: n/a
 *
 * side-effect: KAPI_EFFECT_NONE
 *   target: none
 *   desc: This is a read-only query syscall that does not modify any kernel
 *     state. The target task's affinity mask is only read, never modified.
 *     The only kernel resource used is a temporary cpumask allocation which
 *     is freed before returning.
 *
 * state-trans: none
 *   desc: No state transitions occur. This syscall is purely informational
 *     and does not change any task state.
 *
 * capability: none
 *   desc: Unlike sched_setaffinity(), this syscall does not require any
 *     capabilities for DAC permission. Any process can query any other
 *     process's CPU affinity as long as the target is visible in the caller's
 *     PID namespace. However, LSM policies (SELinux, Smack) may still restrict
 *     access via the security_task_getscheduler() hook.
 *
 * constraint: PID namespace visibility
 *   desc: The target thread must be visible in the caller's PID namespace.
 *     find_task_by_vpid() performs the lookup in task_active_pid_ns(current),
 *     so processes can only query threads they can "see". Threads in parent
 *     PID namespaces, sibling namespaces, or other containers are not
 *     accessible and return -ESRCH.
 *
 * constraint: LSM policy restrictions
 *   desc: Linux Security Modules may restrict access to scheduling information.
 *     SELinux: requires PROCESS__GETSCHED permission (getsched access vector).
 *     Smack: requires MAY_READ access from caller's label to target's label.
 *     The check is performed by security_task_getscheduler() before reading
 *     the affinity mask. Denial returns -EACCES.
 *
 * constraint: Buffer size and alignment
 *   desc: The len parameter must be large enough to hold nr_cpu_ids bits
 *     (divide by 8 and round up for bytes) and must be aligned to
 *     sizeof(unsigned long). These requirements ensure the buffer can hold
 *     the mask and that the copy is efficient. Systems with many CPUs require
 *     larger buffers; use CPU_ALLOC() and CPU_ALLOC_SIZE() from glibc for
 *     dynamic sizing.
 *
 * examples: sched_getaffinity(0, sizeof(cpu_set_t), &mask);  // Get calling thread
 *   sched_getaffinity(pid, sizeof(cpu_set_t), &mask);  // Get specific thread
 *   sched_getaffinity(gettid(), 128, &mask);  // 128-byte (1024 CPU) mask
 *
 * notes: The glibc wrapper function for sched_getaffinity() differs from
 *   the raw kernel syscall. The glibc version has signature:
 *   int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
 *   and returns 0 on success or -1 with errno set on failure. The raw syscall
 *   returns the number of bytes copied on success.
 *
 *   The cpu_set_t data type used by glibc has a fixed size of 128 bytes,
 *   meaning that the maximum CPU number that can be represented is 1023.
 *   For systems with more CPUs, use CPU_ALLOC() to dynamically allocate
 *   larger masks. The reliable method to determine the required size is to
 *   call sched_getaffinity() with increasing mask sizes until it succeeds
 *   without -EINVAL.
 *
 *   The returned mask reflects only currently active CPUs (cpu_active_mask).
 *   CPUs that are offline or not yet brought online will have their bits
 *   cleared even if the task's affinity includes them. This differs from
 *   the user-requested mask stored by sched_setaffinity().
 *
 *   Historical bug (fixed in kernel 6.3): Prior to commit 6015b1aca1a23,
 *   sched_getaffinity() used alloc_cpumask_var() instead of zalloc_cpumask_var(),
 *   which could leave uninitialized data in the mask when cpumask_size() was
 *   larger than the bits actually used (nr_cpu_ids). This could leak kernel
 *   stack data to userspace in edge cases.
 *
 *   Compat syscall: A 32-bit compatible version (compat_sys_sched_getaffinity)
 *   exists for 32-bit processes on 64-bit kernels. It uses compat_ulong_t
 *   for alignment and compat_put_bitmap() for copying. The alignment
 *   requirement is sizeof(compat_ulong_t) (4 bytes) instead of
 *   sizeof(unsigned long) (8 bytes).
 *
 * since-version: 2.5.8
 */
SYSCALL_DEFINE3(sched_getaffinity, pid_t, pid, unsigned int, len,
		unsigned long __user *, user_mask_ptr)
{
	int ret;
	cpumask_var_t mask;

	if ((len * BITS_PER_BYTE) < nr_cpu_ids)
		return -EINVAL;
	if (len & (sizeof(unsigned long)-1))
		return -EINVAL;

	if (!zalloc_cpumask_var(&mask, GFP_KERNEL))
		return -ENOMEM;

	ret = sched_getaffinity(pid, mask);
	if (ret == 0) {
		unsigned int retlen = min(len, cpumask_size());

		if (copy_to_user(user_mask_ptr, cpumask_bits(mask), retlen))
			ret = -EFAULT;
		else
			ret = retlen;
	}
	free_cpumask_var(mask);

	return ret;
}

static void do_sched_yield(void)
{
	struct rq_flags rf;
	struct rq *rq;

	rq = this_rq_lock_irq(&rf);

	schedstat_inc(rq->yld_count);
	rq->donor->sched_class->yield_task(rq);

	preempt_disable();
	rq_unlock_irq(rq, &rf);
	sched_preempt_enable_no_resched();

	schedule();
}

/**
 * sys_sched_yield - yield the current processor to other threads.
 *
 * long-desc: Voluntarily relinquishes the CPU, allowing other runnable
 *   threads to execute. The calling thread remains in the runnable state
 *   but is moved to the end of its scheduling queue or has its virtual
 *   runtime adjusted depending on the scheduling policy. The syscall always
 *   succeeds on Linux.
 *
 *   The behavior varies by scheduling class:
 *   - SCHED_OTHER/SCHED_BATCH (CFS): The task's vruntime is set to its
 *     deadline if the task is eligible, effectively forfeiting its remaining
 *     timeslice. The task will not run again until other eligible tasks have
 *     had a chance to execute.
 *   - SCHED_FIFO/SCHED_RR: The task is moved to the end of the queue for its
 *     static priority level. If it is the only task at that priority, it
 *     continues running immediately.
 *   - SCHED_DEADLINE: Sets the dl_yielded flag, causing the task to sleep
 *     until the start of its next period. This allows other deadline tasks
 *     to run and facilitates bandwidth reclamation.
 *   - SCHED_EXT: Behavior is determined by the loaded BPF scheduler.
 *
 *   This syscall is primarily intended for real-time scheduling policies.
 *   Using sched_yield() with SCHED_OTHER is generally discouraged as it
 *   indicates a design problem. Busy-wait loops using sched_yield() are
 *   particularly problematic and should use proper synchronization
 *   primitives like wait_event() or condition variables instead.
 *
 *   If the calling thread is the only runnable thread at its priority level
 *   (or the highest priority for CFS), the thread continues running after
 *   the syscall returns, though unnecessary context switch overhead is still
 *   incurred.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Always returns 0. On Linux, sched_yield() cannot fail.
 *
 * lock: rq->lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The current CPU's runqueue lock is acquired via this_rq_lock_irq()
 *     with local IRQs disabled. The lock is held while updating scheduler
 *     statistics and calling the scheduling class's yield_task() method.
 *     The lock is released before calling schedule() to allow the scheduler
 *     to select the next task to run.
 *
 * signal: pending signals
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: After schedule() returns
 *   desc: This syscall does not check for pending signals before yielding.
 *     The call to schedule() will handle any pending signals after the task
 *     is rescheduled. The syscall is not interruptible and does not return
 *     EINTR or ERESTARTSYS. Signals are processed in the normal way when the
 *     task resumes execution.
 *   timing: KAPI_SIGNAL_TIME_AFTER
 *   restartable: n/a
 *
 * side-effect: KAPI_EFFECT_SCHEDULE | KAPI_EFFECT_MODIFY_STATE
 *   target: current task scheduling state
 *   desc: Triggers an immediate reschedule by calling schedule(). For CFS
 *     tasks, modifies the task's vruntime to forfeit the remaining timeslice.
 *     For RT tasks, requeues the task at the end of its priority queue. For
 *     deadline tasks, sets the dl_yielded flag. Increments the per-CPU
 *     yld_count scheduler statistic (visible via /proc/schedstat when
 *     CONFIG_SCHEDSTATS is enabled).
 *   reversible: yes (task automatically becomes schedulable again)
 *
 * state-trans: task_runqueue_position
 *   from: front or middle of runqueue
 *   to: end of runqueue or deferred (for deadline)
 *   condition: Always occurs when syscall is invoked
 *   desc: The task transitions from its current position in the scheduling
 *     data structures to a position that defers its next execution. For CFS,
 *     the vruntime adjustment places it behind other eligible tasks. For RT,
 *     it moves to queue tail. For deadline, it is throttled until the next
 *     period.
 *
 * examples:
 *   sched_yield();  // Yield to other threads, always returns 0
 *   // Proper usage in RT task to let equal-priority peers run:
 *   while (work_available()) {
 *       do_work();
 *       sched_yield();  // Let other RT threads at same priority run
 *   }
 *
 * notes:
 *   - POSIX.1-2008 conformant. In POSIX.1-2001, support was optional and
 *     indicated by _POSIX_PRIORITY_SCHEDULING being defined.
 *   - On Linux, this syscall always succeeds and always returns 0. The POSIX
 *     specification allows returning -1 with errno, but Linux never does.
 *   - The semantics changed significantly between Linux 2.4 and 2.5/2.6. In
 *     2.4, yield moved the task to the end of the runqueue. In 2.6+, the
 *     task is moved to the "expired" set, meaning it must wait until all
 *     other runnable tasks have exhausted their timeslices.
 *   - Applications that use sched_yield() in busy-wait loops are considered
 *     broken. Such loops degrade system performance significantly under the
 *     modern semantics. Use proper blocking primitives instead.
 *   - For SCHED_DEADLINE tasks, sched_yield() can be used to signal the end
 *     of the current activation. The task will be awakened by the next
 *     runtime replenishment at the start of its next period.
 *   - Stop tasks (highest priority kernel threads) trigger a BUG() if they
 *     call yield, as this should never happen.
 *   - In proxy execution scenarios (introduced in recent kernels), the yield
 *     is attributed to the donor task rather than the currently executing
 *     proxy task.
 *   - Unnecessary calls to sched_yield() cause context switches that degrade
 *     system performance. Only use when there is a genuine need to give other
 *     threads a chance to run.
 *
 * since-version: 2.0
 */
SYSCALL_DEFINE0(sched_yield)
{
	do_sched_yield();
	return 0;
}

/**
 * yield - yield the current processor to other threads.
 *
 * Do not ever use this function, there's a 99% chance you're doing it wrong.
 *
 * The scheduler is at all times free to pick the calling task as the most
 * eligible task to run, if removing the yield() call from your code breaks
 * it, it's already broken.
 *
 * Typical broken usage is:
 *
 * while (!event)
 *	yield();
 *
 * where one assumes that yield() will let 'the other' process run that will
 * make event true. If the current task is a SCHED_FIFO task that will never
 * happen. Never use yield() as a progress guarantee!!
 *
 * If you want to use yield() to wait for something, use wait_event().
 * If you want to use yield() to be 'nice' for others, use cond_resched().
 * If you still want to use yield(), do not!
 */
void __sched yield(void)
{
	set_current_state(TASK_RUNNING);
	do_sched_yield();
}
EXPORT_SYMBOL(yield);

/**
 * yield_to - yield the current processor to another thread in
 * your thread group, or accelerate that thread toward the
 * processor it's on.
 * @p: target task
 * @preempt: whether task preemption is allowed or not
 *
 * It's the caller's job to ensure that the target task struct
 * can't go away on us before we can do any checks.
 *
 * Return:
 *	true (>0) if we indeed boosted the target task.
 *	false (0) if we failed to boost the target.
 *	-ESRCH if there's no task to yield to.
 */
int __sched yield_to(struct task_struct *p, bool preempt)
{
	struct task_struct *curr;
	struct rq *rq, *p_rq;
	int yielded = 0;

	scoped_guard (raw_spinlock_irqsave, &p->pi_lock) {
		rq = this_rq();
		curr = rq->donor;

again:
		p_rq = task_rq(p);
		/*
		 * If we're the only runnable task on the rq and target rq also
		 * has only one task, there's absolutely no point in yielding.
		 */
		if (rq->nr_running == 1 && p_rq->nr_running == 1)
			return -ESRCH;

		guard(double_rq_lock)(rq, p_rq);
		if (task_rq(p) != p_rq)
			goto again;

		if (!curr->sched_class->yield_to_task)
			return 0;

		if (curr->sched_class != p->sched_class)
			return 0;

		if (task_on_cpu(p_rq, p) || !task_is_running(p))
			return 0;

		yielded = curr->sched_class->yield_to_task(rq, p);
		if (yielded) {
			schedstat_inc(rq->yld_count);
			/*
			 * Make p's CPU reschedule; pick_next_entity
			 * takes care of fairness.
			 */
			if (preempt && rq != p_rq)
				resched_curr(p_rq);
		}
	}

	if (yielded)
		schedule();

	return yielded;
}
EXPORT_SYMBOL_GPL(yield_to);

/**
 * sys_sched_get_priority_max - Return maximum scheduling priority for a policy
 * @policy: Scheduling policy to query (SCHED_FIFO, SCHED_RR, SCHED_NORMAL, etc.)
 *
 * long-desc: Returns the maximum static priority value that can be used with
 *   the specified scheduling policy. This syscall is one half of the pair
 *   (along with sched_get_priority_min) that allows applications to portably
 *   discover the valid priority range for a given scheduling class.
 *
 *   For realtime policies SCHED_FIFO and SCHED_RR, this returns 99 (the value
 *   MAX_RT_PRIO-1), which is the highest static priority available. Realtime
 *   priorities range from 1 to 99, with higher numeric values indicating
 *   higher scheduling priority.
 *
 *   For non-realtime policies (SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE) and
 *   special policies (SCHED_DEADLINE, SCHED_EXT), this returns 0 because
 *   these policies do not use the static priority mechanism. SCHED_NORMAL
 *   and SCHED_BATCH use nice values instead, SCHED_DEADLINE uses explicit
 *   deadline parameters, and SCHED_IDLE runs at the lowest possible priority.
 *
 *   The @policy parameter must be an exact scheduling policy value. Unlike
 *   sched_setscheduler() which masks out the SCHED_RESET_ON_FORK flag, this
 *   syscall treats the policy value literally. Passing SCHED_FIFO |
 *   SCHED_RESET_ON_FORK will return EINVAL because the combined value does
 *   not match any case in the switch statement.
 *
 *   This is a pure query syscall with no side effects. It acquires no locks,
 *   performs no memory allocation, and cannot sleep. It is safe to call from
 *   any process context and will always complete quickly.
 *
 *   Note: The POSIX name SCHED_OTHER corresponds to Linux's SCHED_NORMAL.
 *   Both refer to the same policy (value 0) and return the same result.
 *
 * context-flags: KAPI_CTX_PROCESS
 *
 * param: policy
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_ENUM
 *   constraint: Must be exactly one of the following scheduling policy values:
 *     SCHED_NORMAL (0), SCHED_FIFO (1), SCHED_RR (2), SCHED_BATCH (3),
 *     SCHED_IDLE (5), SCHED_DEADLINE (6), or SCHED_EXT (7). The value must not
 *     include SCHED_RESET_ON_FORK or any other flags - these are not masked
 *     out and will cause EINVAL to be returned.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0 or 99 depending on policy
 *   desc: On success, returns the maximum scheduling priority for the specified
 *     policy. For SCHED_FIFO and SCHED_RR, returns 99 (MAX_RT_PRIO-1). For all
 *     other valid policies (SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE, SCHED_DEADLINE,
 *     SCHED_EXT), returns 0. On error, returns a negative error code.
 *
 * error: EINVAL, Invalid scheduling policy
 *   desc: The @policy argument is not a recognized scheduling policy value.
 *     This occurs when: (1) The value is negative, (2) the value is 4 (which
 *     was reserved for SCHED_ISO but never implemented), (3) the value is 8
 *     or higher, or (4) the value includes the SCHED_RESET_ON_FORK flag
 *     (0x40000000) or any other bits beyond the base policy value. Unlike
 *     sched_setscheduler(), this syscall does NOT mask out SCHED_RESET_ON_FORK.
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: Syscall has no blocking or interruptible operations
 *   desc: This syscall does not interact with signals in any way. It is a
 *     pure lookup operation implemented as a switch statement that completes
 *     in constant time without any blocking, sleeping, or interruptible points.
 *     The syscall cannot return EINTR and does not need to be restarted.
 *   timing: KAPI_SIGNAL_TIME_NONE
 *   restartable: n/a
 *
 * side-effect: KAPI_EFFECT_NONE
 *   target: none
 *   desc: This is a read-only query syscall. It does not modify any kernel
 *     state, acquire any locks, allocate any memory, or produce any observable
 *     side effects. The returned value is a compile-time constant based solely
 *     on the policy argument.
 *   reversible: n/a
 *
 * constraint: Valid policy enumeration
 *   desc: The policy parameter must be an exact match for one of the defined
 *     scheduling policy constants. The implementation uses a switch statement
 *     without a default fallthrough for valid cases, so any unrecognized value
 *     returns the pre-initialized -EINVAL. Policy value 4 (reserved for the
 *     never-implemented SCHED_ISO) is not valid.
 *
 * examples:
 *   sched_get_priority_max(SCHED_FIFO);  // Returns 99
 *   sched_get_priority_max(SCHED_RR);    // Returns 99
 *   sched_get_priority_max(SCHED_NORMAL);  // Returns 0 (SCHED_OTHER in POSIX)
 *   sched_get_priority_max(SCHED_BATCH);   // Returns 0
 *   sched_get_priority_max(SCHED_IDLE);    // Returns 0
 *   sched_get_priority_max(SCHED_DEADLINE);  // Returns 0
 *   sched_get_priority_max(SCHED_FIFO | SCHED_RESET_ON_FORK);  // Returns -EINVAL
 *
 * notes:
 *   - POSIX.1-2001 and POSIX.1-2008 conformant. This interface is part of the
 *     optional Realtime scheduling feature (_POSIX_PRIORITY_SCHEDULING).
 *   - POSIX requires implementations to support at least 32 distinct priority
 *     levels for SCHED_FIFO and SCHED_RR. Linux exceeds this with 99 levels.
 *   - The return value for SCHED_FIFO and SCHED_RR is MAX_RT_PRIO-1, which is
 *     a compile-time constant of 99. This value has been stable since the
 *     introduction of realtime scheduling in Linux.
 *   - Portable applications should always query the priority range dynamically
 *     using this syscall and sched_get_priority_min() rather than hardcoding
 *     values, as the range may vary across POSIX-compliant systems.
 *   - SCHED_DEADLINE priorities are not managed through static priorities at
 *     all; deadline tasks use runtime/deadline/period parameters instead.
 *     Returning 0 indicates static priority is not applicable.
 *   - SCHED_EXT (BPF extensible scheduler, added in Linux 6.12) also returns 0
 *     as it does not use static priorities.
 *   - Unlike sched_setscheduler() and related syscalls, this function does NOT
 *     strip the SCHED_RESET_ON_FORK flag from the policy value. Applications
 *     must pass the bare policy value without any flags.
 *   - The syscall has no privilege requirements and can be called by any process.
 *
 * since-version: 2.0
 */
SYSCALL_DEFINE1(sched_get_priority_max, int, policy)
{
	int ret = -EINVAL;

	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
		ret = MAX_RT_PRIO-1;
		break;
	case SCHED_DEADLINE:
	case SCHED_NORMAL:
	case SCHED_BATCH:
	case SCHED_IDLE:
	case SCHED_EXT:
		ret = 0;
		break;
	}
	return ret;
}

/**
 * sys_sched_get_priority_min - Return minimum scheduling priority for a policy
 * @policy: Scheduling policy to query (SCHED_FIFO, SCHED_RR, SCHED_NORMAL, etc.)
 *
 * long-desc: Returns the minimum static priority value that can be used with
 *   the specified scheduling policy. This syscall is one half of the pair
 *   (along with sched_get_priority_max) that allows applications to portably
 *   discover the valid priority range for a given scheduling class.
 *
 *   For realtime policies SCHED_FIFO and SCHED_RR, this returns 1, which is
 *   the lowest static priority available for realtime tasks. Realtime
 *   priorities range from 1 to 99, with higher numeric values indicating
 *   higher scheduling priority. A realtime task with priority 1 will be
 *   preempted by any realtime task with priority 2 or higher.
 *
 *   For non-realtime policies (SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE) and
 *   special policies (SCHED_DEADLINE, SCHED_EXT), this returns 0 because
 *   these policies do not use the static priority mechanism. SCHED_NORMAL
 *   and SCHED_BATCH use nice values instead, SCHED_DEADLINE uses explicit
 *   deadline parameters, and SCHED_IDLE runs at the lowest possible priority.
 *
 *   The @policy parameter must be an exact scheduling policy value. Unlike
 *   sched_setscheduler() which masks out the SCHED_RESET_ON_FORK flag, this
 *   syscall treats the policy value literally. Passing SCHED_FIFO |
 *   SCHED_RESET_ON_FORK will return EINVAL because the combined value does
 *   not match any case in the switch statement.
 *
 *   This is a pure query syscall with no side effects. It acquires no locks,
 *   performs no memory allocation, and cannot sleep. It is safe to call from
 *   any process context and will always complete quickly.
 *
 *   Note: The POSIX name SCHED_OTHER corresponds to Linux's SCHED_NORMAL.
 *   Both refer to the same policy (value 0) and return the same result.
 *
 * context-flags: KAPI_CTX_PROCESS
 *
 * param: policy
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_ENUM
 *   constraint: Must be exactly one of the following scheduling policy values:
 *     SCHED_NORMAL (0), SCHED_FIFO (1), SCHED_RR (2), SCHED_BATCH (3),
 *     SCHED_IDLE (5), SCHED_DEADLINE (6), or SCHED_EXT (7). The value must not
 *     include SCHED_RESET_ON_FORK or any other flags - these are not masked
 *     out and will cause EINVAL to be returned.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0 or 1 depending on policy
 *   desc: On success, returns the minimum scheduling priority for the specified
 *     policy. For SCHED_FIFO and SCHED_RR, returns 1 (the lowest realtime
 *     priority). For all other valid policies (SCHED_NORMAL, SCHED_BATCH,
 *     SCHED_IDLE, SCHED_DEADLINE, SCHED_EXT), returns 0. On error, returns a
 *     negative error code.
 *
 * error: EINVAL, Invalid scheduling policy
 *   desc: The @policy argument is not a recognized scheduling policy value.
 *     This occurs when: (1) The value is negative, (2) the value is 4 (which
 *     was reserved for SCHED_ISO but never implemented), (3) the value is 8
 *     or higher, or (4) the value includes the SCHED_RESET_ON_FORK flag
 *     (0x40000000) or any other bits beyond the base policy value. Unlike
 *     sched_setscheduler(), this syscall does NOT mask out SCHED_RESET_ON_FORK.
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: Syscall has no blocking or interruptible operations
 *   desc: This syscall does not interact with signals in any way. It is a
 *     pure lookup operation implemented as a switch statement that completes
 *     in constant time without any blocking, sleeping, or interruptible points.
 *     The syscall cannot return EINTR and does not need to be restarted.
 *   timing: KAPI_SIGNAL_TIME_NONE
 *   restartable: n/a
 *
 * side-effect: KAPI_EFFECT_NONE
 *   target: none
 *   desc: This is a read-only query syscall. It does not modify any kernel
 *     state, acquire any locks, allocate any memory, or produce any observable
 *     side effects. The returned value is a compile-time constant based solely
 *     on the policy argument.
 *   reversible: n/a
 *
 * constraint: Valid policy enumeration
 *   desc: The policy parameter must be an exact match for one of the defined
 *     scheduling policy constants. The implementation uses a switch statement
 *     without a default fallthrough for valid cases, so any unrecognized value
 *     returns the pre-initialized -EINVAL. Policy value 4 (reserved for the
 *     never-implemented SCHED_ISO) is not valid.
 *
 * examples:
 *   sched_get_priority_min(SCHED_FIFO);  // Returns 1
 *   sched_get_priority_min(SCHED_RR);    // Returns 1
 *   sched_get_priority_min(SCHED_NORMAL);  // Returns 0 (SCHED_OTHER in POSIX)
 *   sched_get_priority_min(SCHED_BATCH);   // Returns 0
 *   sched_get_priority_min(SCHED_IDLE);    // Returns 0
 *   sched_get_priority_min(SCHED_DEADLINE);  // Returns 0
 *   sched_get_priority_min(SCHED_FIFO | SCHED_RESET_ON_FORK);  // Returns -EINVAL
 *
 * notes:
 *   - POSIX.1-2001 and POSIX.1-2008 conformant. This interface is part of the
 *     optional Realtime scheduling feature (_POSIX_PRIORITY_SCHEDULING).
 *   - POSIX requires implementations to support at least 32 distinct priority
 *     levels for SCHED_FIFO and SCHED_RR. Linux exceeds this with 99 levels
 *     (priorities 1-99), giving a range of sched_get_priority_min() returning
 *     1 and sched_get_priority_max() returning 99.
 *   - The return value for SCHED_FIFO and SCHED_RR is 1, which is the lowest
 *     valid realtime priority. This value has been stable since the
 *     introduction of realtime scheduling in Linux.
 *   - Portable applications should always query the priority range dynamically
 *     using sched_get_priority_max() and this syscall rather than hardcoding
 *     values, as the range may vary across POSIX-compliant systems.
 *   - SCHED_DEADLINE priorities are not managed through static priorities at
 *     all; deadline tasks use runtime/deadline/period parameters instead.
 *     Returning 0 indicates static priority is not applicable.
 *   - SCHED_EXT (BPF extensible scheduler, added in Linux 6.12) also returns 0
 *     as it does not use static priorities.
 *   - Unlike sched_setscheduler() and related syscalls, this function does NOT
 *     strip the SCHED_RESET_ON_FORK flag from the policy value. Applications
 *     must pass the bare policy value without any flags.
 *   - The syscall has no privilege requirements and can be called by any process.
 *
 * since-version: 2.0
 */
SYSCALL_DEFINE1(sched_get_priority_min, int, policy)
{
	int ret = -EINVAL;

	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
		ret = 1;
		break;
	case SCHED_DEADLINE:
	case SCHED_NORMAL:
	case SCHED_BATCH:
	case SCHED_IDLE:
	case SCHED_EXT:
		ret = 0;
	}
	return ret;
}

static int sched_rr_get_interval(pid_t pid, struct timespec64 *t)
{
	unsigned int time_slice = 0;
	int retval;

	if (pid < 0)
		return -EINVAL;

	scoped_guard (rcu) {
		struct task_struct *p = find_process_by_pid(pid);
		if (!p)
			return -ESRCH;

		retval = security_task_getscheduler(p);
		if (retval)
			return retval;

		scoped_guard (task_rq_lock, p) {
			struct rq *rq = scope.rq;
			if (p->sched_class->get_rr_interval)
				time_slice = p->sched_class->get_rr_interval(rq, p);
		}
	}

	jiffies_to_timespec64(time_slice, t);
	return 0;
}

/**
 * sys_sched_rr_get_interval - return the default time-slice of a process.
 * @pid: pid of the process.
 * @interval: userspace pointer to the time-slice value.
 *
 * this syscall writes the default time-slice value of a given process
 * into the user-space timespec buffer. A value of '0' means infinity.
 *
 * Return: On success, 0 and the time-slice is in @interval. Otherwise,
 * an error code.
 */
SYSCALL_DEFINE2(sched_rr_get_interval, pid_t, pid,
		struct __kernel_timespec __user *, interval)
{
	struct timespec64 t;
	int retval = sched_rr_get_interval(pid, &t);

	if (retval == 0)
		retval = put_timespec64(&t, interval);

	return retval;
}

#ifdef CONFIG_COMPAT_32BIT_TIME
SYSCALL_DEFINE2(sched_rr_get_interval_time32, pid_t, pid,
		struct old_timespec32 __user *, interval)
{
	struct timespec64 t;
	int retval = sched_rr_get_interval(pid, &t);

	if (retval == 0)
		retval = put_old_timespec32(&t, interval);
	return retval;
}
#endif
