// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/exit.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/mm.h>
#include <linux/sched/stat.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/cputime.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/tty.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/cpu.h>
#include <linux/acct.h>
#include <linux/tsacct_kern.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/binfmts.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/profile.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/cgroup.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/posix-timers.h>
#include <linux/cn_proc.h>
#include <linux/mutex.h>
#include <linux/futex.h>
#include <linux/pipe_fs_i.h>
#include <linux/audit.h> /* for audit_free() */
#include <linux/resource.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/blkdev.h>
#include <linux/task_work.h>
#include <linux/fs_struct.h>
#include <linux/init_task.h>
#include <linux/perf_event.h>
#include <trace/events/sched.h>
#include <linux/hw_breakpoint.h>
#include <linux/oom.h>
#include <linux/writeback.h>
#include <linux/shm.h>
#include <linux/kcov.h>
#include <linux/kmsan.h>
#include <linux/random.h>
#include <linux/rcuwait.h>
#include <linux/compat.h>
#include <linux/io_uring.h>
#include <linux/kprobes.h>
#include <linux/rethook.h>
#include <linux/sysfs.h>
#include <linux/user_events.h>
#include <linux/unwind_deferred.h>
#include <linux/uaccess.h>
#include <linux/pidfs.h>

#include <uapi/linux/wait.h>

#include <asm/unistd.h>
#include <asm/mmu_context.h>

#include "exit.h"

/*
 * The default value should be high enough to not crash a system that randomly
 * crashes its kernel from time to time, but low enough to at least not permit
 * overflowing 32-bit refcounts or the ldsem writer count.
 */
static unsigned int oops_limit = 10000;

#ifdef CONFIG_SYSCTL
static const struct ctl_table kern_exit_table[] = {
	{
		.procname       = "oops_limit",
		.data           = &oops_limit,
		.maxlen         = sizeof(oops_limit),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
};

static __init int kernel_exit_sysctls_init(void)
{
	register_sysctl_init("kernel", kern_exit_table);
	return 0;
}
late_initcall(kernel_exit_sysctls_init);
#endif

static atomic_t oops_count = ATOMIC_INIT(0);

#ifdef CONFIG_SYSFS
static ssize_t oops_count_show(struct kobject *kobj, struct kobj_attribute *attr,
			       char *page)
{
	return sysfs_emit(page, "%d\n", atomic_read(&oops_count));
}

static struct kobj_attribute oops_count_attr = __ATTR_RO(oops_count);

static __init int kernel_exit_sysfs_init(void)
{
	sysfs_add_file_to_group(kernel_kobj, &oops_count_attr.attr, NULL);
	return 0;
}
late_initcall(kernel_exit_sysfs_init);
#endif

/*
 * For things release_task() would like to do *after* tasklist_lock is released.
 */
struct release_task_post {
	struct pid *pids[PIDTYPE_MAX];
};

static void __unhash_process(struct release_task_post *post, struct task_struct *p,
			     bool group_dead)
{
	struct pid *pid = task_pid(p);

	nr_threads--;

	detach_pid(post->pids, p, PIDTYPE_PID);
	wake_up_all(&pid->wait_pidfd);

	if (group_dead) {
		detach_pid(post->pids, p, PIDTYPE_TGID);
		detach_pid(post->pids, p, PIDTYPE_PGID);
		detach_pid(post->pids, p, PIDTYPE_SID);

		list_del_rcu(&p->tasks);
		list_del_init(&p->sibling);
		__this_cpu_dec(process_counts);
	}
	list_del_rcu(&p->thread_node);
}

/*
 * This function expects the tasklist_lock write-locked.
 */
static void __exit_signal(struct release_task_post *post, struct task_struct *tsk)
{
	struct signal_struct *sig = tsk->signal;
	bool group_dead = thread_group_leader(tsk);
	struct sighand_struct *sighand;
	struct tty_struct *tty;
	u64 utime, stime;

	sighand = rcu_dereference_check(tsk->sighand,
					lockdep_tasklist_lock_is_held());
	spin_lock(&sighand->siglock);

#ifdef CONFIG_POSIX_TIMERS
	posix_cpu_timers_exit(tsk);
	if (group_dead)
		posix_cpu_timers_exit_group(tsk);
#endif

	if (group_dead) {
		tty = sig->tty;
		sig->tty = NULL;
	} else {
		/*
		 * If there is any task waiting for the group exit
		 * then notify it:
		 */
		if (sig->notify_count > 0 && !--sig->notify_count)
			wake_up_process(sig->group_exec_task);

		if (tsk == sig->curr_target)
			sig->curr_target = next_thread(tsk);
	}

	/*
	 * Accumulate here the counters for all threads as they die. We could
	 * skip the group leader because it is the last user of signal_struct,
	 * but we want to avoid the race with thread_group_cputime() which can
	 * see the empty ->thread_head list.
	 */
	task_cputime(tsk, &utime, &stime);
	write_seqlock(&sig->stats_lock);
	sig->utime += utime;
	sig->stime += stime;
	sig->gtime += task_gtime(tsk);
	sig->min_flt += tsk->min_flt;
	sig->maj_flt += tsk->maj_flt;
	sig->nvcsw += tsk->nvcsw;
	sig->nivcsw += tsk->nivcsw;
	sig->inblock += task_io_get_inblock(tsk);
	sig->oublock += task_io_get_oublock(tsk);
	task_io_accounting_add(&sig->ioac, &tsk->ioac);
	sig->sum_sched_runtime += tsk->se.sum_exec_runtime;
	sig->nr_threads--;
	__unhash_process(post, tsk, group_dead);
	write_sequnlock(&sig->stats_lock);

	tsk->sighand = NULL;
	spin_unlock(&sighand->siglock);

	__cleanup_sighand(sighand);
	if (group_dead)
		tty_kref_put(tty);
}

static void delayed_put_task_struct(struct rcu_head *rhp)
{
	struct task_struct *tsk = container_of(rhp, struct task_struct, rcu);

	kprobe_flush_task(tsk);
	rethook_flush_task(tsk);
	perf_event_delayed_put(tsk);
	trace_sched_process_free(tsk);
	put_task_struct(tsk);
}

void put_task_struct_rcu_user(struct task_struct *task)
{
	if (refcount_dec_and_test(&task->rcu_users))
		call_rcu(&task->rcu, delayed_put_task_struct);
}

void __weak release_thread(struct task_struct *dead_task)
{
}

void release_task(struct task_struct *p)
{
	struct release_task_post post;
	struct task_struct *leader;
	struct pid *thread_pid;
	int zap_leader;
repeat:
	memset(&post, 0, sizeof(post));

	/* don't need to get the RCU readlock here - the process is dead and
	 * can't be modifying its own credentials. */
	dec_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);

	pidfs_exit(p);
	cgroup_task_release(p);

	/* Retrieve @thread_pid before __unhash_process() may set it to NULL. */
	thread_pid = task_pid(p);

	write_lock_irq(&tasklist_lock);
	ptrace_release_task(p);
	__exit_signal(&post, p);

	/*
	 * If we are the last non-leader member of the thread
	 * group, and the leader is zombie, then notify the
	 * group leader's parent process. (if it wants notification.)
	 */
	zap_leader = 0;
	leader = p->group_leader;
	if (leader != p && thread_group_empty(leader)
			&& leader->exit_state == EXIT_ZOMBIE) {
		/* for pidfs_exit() and do_notify_parent() */
		if (leader->signal->flags & SIGNAL_GROUP_EXIT)
			leader->exit_code = leader->signal->group_exit_code;
		/*
		 * If we were the last child thread and the leader has
		 * exited already, and the leader's parent ignores SIGCHLD,
		 * then we are the one who should release the leader.
		 */
		zap_leader = do_notify_parent(leader, leader->exit_signal);
		if (zap_leader)
			leader->exit_state = EXIT_DEAD;
	}

	write_unlock_irq(&tasklist_lock);
	/* @thread_pid can't go away until free_pids() below */
	proc_flush_pid(thread_pid);
	exit_cred_namespaces(p);
	add_device_randomness(&p->se.sum_exec_runtime,
			      sizeof(p->se.sum_exec_runtime));
	free_pids(post.pids);
	release_thread(p);
	/*
	 * This task was already removed from the process/thread/pid lists
	 * and lock_task_sighand(p) can't succeed. Nobody else can touch
	 * ->pending or, if group dead, signal->shared_pending. We can call
	 * flush_sigqueue() lockless.
	 */
	flush_sigqueue(&p->pending);
	if (thread_group_leader(p))
		flush_sigqueue(&p->signal->shared_pending);

	put_task_struct_rcu_user(p);

	p = leader;
	if (unlikely(zap_leader))
		goto repeat;
}

int rcuwait_wake_up(struct rcuwait *w)
{
	int ret = 0;
	struct task_struct *task;

	rcu_read_lock();

	/*
	 * Order condition vs @task, such that everything prior to the load
	 * of @task is visible. This is the condition as to why the user called
	 * rcuwait_wake() in the first place. Pairs with set_current_state()
	 * barrier (A) in rcuwait_wait_event().
	 *
	 *    WAIT                WAKE
	 *    [S] tsk = current	  [S] cond = true
	 *        MB (A)	      MB (B)
	 *    [L] cond		  [L] tsk
	 */
	smp_mb(); /* (B) */

	task = rcu_dereference(w->task);
	if (task)
		ret = wake_up_process(task);
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(rcuwait_wake_up);

/*
 * Determine if a process group is "orphaned", according to the POSIX
 * definition in 2.2.2.52.  Orphaned process groups are not to be affected
 * by terminal-generated stop signals.  Newly orphaned process groups are
 * to receive a SIGHUP and a SIGCONT.
 *
 * "I ask you, have you ever known what it is to be an orphan?"
 */
static int will_become_orphaned_pgrp(struct pid *pgrp,
					struct task_struct *ignored_task)
{
	struct task_struct *p;

	do_each_pid_task(pgrp, PIDTYPE_PGID, p) {
		if ((p == ignored_task) ||
		    (p->exit_state && thread_group_empty(p)) ||
		    is_global_init(p->real_parent))
			continue;

		if (task_pgrp(p->real_parent) != pgrp &&
		    task_session(p->real_parent) == task_session(p))
			return 0;
	} while_each_pid_task(pgrp, PIDTYPE_PGID, p);

	return 1;
}

int is_current_pgrp_orphaned(void)
{
	int retval;

	read_lock(&tasklist_lock);
	retval = will_become_orphaned_pgrp(task_pgrp(current), NULL);
	read_unlock(&tasklist_lock);

	return retval;
}

static bool has_stopped_jobs(struct pid *pgrp)
{
	struct task_struct *p;

	do_each_pid_task(pgrp, PIDTYPE_PGID, p) {
		if (p->signal->flags & SIGNAL_STOP_STOPPED)
			return true;
	} while_each_pid_task(pgrp, PIDTYPE_PGID, p);

	return false;
}

/*
 * Check to see if any process groups have become orphaned as
 * a result of our exiting, and if they have any stopped jobs,
 * send them a SIGHUP and then a SIGCONT. (POSIX 3.2.2.2)
 */
static void
kill_orphaned_pgrp(struct task_struct *tsk, struct task_struct *parent)
{
	struct pid *pgrp = task_pgrp(tsk);
	struct task_struct *ignored_task = tsk;

	if (!parent)
		/* exit: our father is in a different pgrp than
		 * we are and we were the only connection outside.
		 */
		parent = tsk->real_parent;
	else
		/* reparent: our child is in a different pgrp than
		 * we are, and it was the only connection outside.
		 */
		ignored_task = NULL;

	if (task_pgrp(parent) != pgrp &&
	    task_session(parent) == task_session(tsk) &&
	    will_become_orphaned_pgrp(pgrp, ignored_task) &&
	    has_stopped_jobs(pgrp)) {
		__kill_pgrp_info(SIGHUP, SEND_SIG_PRIV, pgrp);
		__kill_pgrp_info(SIGCONT, SEND_SIG_PRIV, pgrp);
	}
}

static void coredump_task_exit(struct task_struct *tsk,
			       struct core_state *core_state)
{
	struct core_thread self;

	self.task = tsk;
	if (self.task->flags & PF_SIGNALED)
		self.next = xchg(&core_state->dumper.next, &self);
	else
		self.task = NULL;
	/*
	 * Implies mb(), the result of xchg() must be visible
	 * to core_state->dumper.
	 */
	if (atomic_dec_and_test(&core_state->nr_threads))
		complete(&core_state->startup);

	for (;;) {
		set_current_state(TASK_IDLE|TASK_FREEZABLE);
		if (!self.task) /* see coredump_finish() */
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);
}

#ifdef CONFIG_MEMCG
/* drops tasklist_lock if succeeds */
static bool __try_to_set_owner(struct task_struct *tsk, struct mm_struct *mm)
{
	bool ret = false;

	task_lock(tsk);
	if (likely(tsk->mm == mm)) {
		/* tsk can't pass exit_mm/exec_mmap and exit */
		read_unlock(&tasklist_lock);
		WRITE_ONCE(mm->owner, tsk);
		lru_gen_migrate_mm(mm);
		ret = true;
	}
	task_unlock(tsk);
	return ret;
}

static bool try_to_set_owner(struct task_struct *g, struct mm_struct *mm)
{
	struct task_struct *t;

	for_each_thread(g, t) {
		struct mm_struct *t_mm = READ_ONCE(t->mm);
		if (t_mm == mm) {
			if (__try_to_set_owner(t, mm))
				return true;
		} else if (t_mm)
			break;
	}

	return false;
}

/*
 * A task is exiting.   If it owned this mm, find a new owner for the mm.
 */
void mm_update_next_owner(struct mm_struct *mm)
{
	struct task_struct *g, *p = current;

	/*
	 * If the exiting or execing task is not the owner, it's
	 * someone else's problem.
	 */
	if (mm->owner != p)
		return;
	/*
	 * The current owner is exiting/execing and there are no other
	 * candidates.  Do not leave the mm pointing to a possibly
	 * freed task structure.
	 */
	if (atomic_read(&mm->mm_users) <= 1) {
		WRITE_ONCE(mm->owner, NULL);
		return;
	}

	read_lock(&tasklist_lock);
	/*
	 * Search in the children
	 */
	list_for_each_entry(g, &p->children, sibling) {
		if (try_to_set_owner(g, mm))
			goto ret;
	}
	/*
	 * Search in the siblings
	 */
	list_for_each_entry(g, &p->real_parent->children, sibling) {
		if (try_to_set_owner(g, mm))
			goto ret;
	}
	/*
	 * Search through everything else, we should not get here often.
	 */
	for_each_process(g) {
		if (atomic_read(&mm->mm_users) <= 1)
			break;
		if (g->flags & PF_KTHREAD)
			continue;
		if (try_to_set_owner(g, mm))
			goto ret;
	}
	read_unlock(&tasklist_lock);
	/*
	 * We found no owner yet mm_users > 1: this implies that we are
	 * most likely racing with swapoff (try_to_unuse()) or /proc or
	 * ptrace or page migration (get_task_mm()).  Mark owner as NULL.
	 */
	WRITE_ONCE(mm->owner, NULL);
 ret:
	return;

}
#endif /* CONFIG_MEMCG */

/*
 * Turn us into a lazy TLB process if we
 * aren't already..
 */
static void exit_mm(void)
{
	struct mm_struct *mm = current->mm;

	exit_mm_release(current, mm);
	if (!mm)
		return;
	mmap_read_lock(mm);
	mmgrab_lazy_tlb(mm);
	BUG_ON(mm != current->active_mm);
	/* more a memory barrier than a real lock */
	task_lock(current);
	/*
	 * When a thread stops operating on an address space, the loop
	 * in membarrier_private_expedited() may not observe that
	 * tsk->mm, and the loop in membarrier_global_expedited() may
	 * not observe a MEMBARRIER_STATE_GLOBAL_EXPEDITED
	 * rq->membarrier_state, so those would not issue an IPI.
	 * Membarrier requires a memory barrier after accessing
	 * user-space memory, before clearing tsk->mm or the
	 * rq->membarrier_state.
	 */
	smp_mb__after_spinlock();
	local_irq_disable();
	current->mm = NULL;
	membarrier_update_current_mm(NULL);
	enter_lazy_tlb(mm, current);
	local_irq_enable();
	task_unlock(current);
	mmap_read_unlock(mm);
	mm_update_next_owner(mm);
	mmput(mm);
	if (test_thread_flag(TIF_MEMDIE))
		exit_oom_victim();
}

static struct task_struct *find_alive_thread(struct task_struct *p)
{
	struct task_struct *t;

	for_each_thread(p, t) {
		if (!(t->flags & PF_EXITING))
			return t;
	}
	return NULL;
}

static struct task_struct *find_child_reaper(struct task_struct *father,
						struct list_head *dead)
	__releases(&tasklist_lock)
	__acquires(&tasklist_lock)
{
	struct pid_namespace *pid_ns = task_active_pid_ns(father);
	struct task_struct *reaper = pid_ns->child_reaper;
	struct task_struct *p, *n;

	if (likely(reaper != father))
		return reaper;

	reaper = find_alive_thread(father);
	if (reaper) {
		pid_ns->child_reaper = reaper;
		return reaper;
	}

	write_unlock_irq(&tasklist_lock);

	list_for_each_entry_safe(p, n, dead, ptrace_entry) {
		list_del_init(&p->ptrace_entry);
		release_task(p);
	}

	zap_pid_ns_processes(pid_ns);
	write_lock_irq(&tasklist_lock);

	return father;
}

/*
 * When we die, we re-parent all our children, and try to:
 * 1. give them to another thread in our thread group, if such a member exists
 * 2. give it to the first ancestor process which prctl'd itself as a
 *    child_subreaper for its children (like a service manager)
 * 3. give it to the init process (PID 1) in our pid namespace
 */
static struct task_struct *find_new_reaper(struct task_struct *father,
					   struct task_struct *child_reaper)
{
	struct task_struct *thread, *reaper;

	thread = find_alive_thread(father);
	if (thread)
		return thread;

	if (father->signal->has_child_subreaper) {
		unsigned int ns_level = task_pid(father)->level;
		/*
		 * Find the first ->is_child_subreaper ancestor in our pid_ns.
		 * We can't check reaper != child_reaper to ensure we do not
		 * cross the namespaces, the exiting parent could be injected
		 * by setns() + fork().
		 * We check pid->level, this is slightly more efficient than
		 * task_active_pid_ns(reaper) != task_active_pid_ns(father).
		 */
		for (reaper = father->real_parent;
		     task_pid(reaper)->level == ns_level;
		     reaper = reaper->real_parent) {
			if (reaper == &init_task)
				break;
			if (!reaper->signal->is_child_subreaper)
				continue;
			thread = find_alive_thread(reaper);
			if (thread)
				return thread;
		}
	}

	return child_reaper;
}

/*
* Any that need to be release_task'd are put on the @dead list.
 */
static void reparent_leader(struct task_struct *father, struct task_struct *p,
				struct list_head *dead)
{
	if (unlikely(p->exit_state == EXIT_DEAD))
		return;

	/* We don't want people slaying init. */
	p->exit_signal = SIGCHLD;

	/* If it has exited notify the new parent about this child's death. */
	if (!p->ptrace &&
	    p->exit_state == EXIT_ZOMBIE && thread_group_empty(p)) {
		if (do_notify_parent(p, p->exit_signal)) {
			p->exit_state = EXIT_DEAD;
			list_add(&p->ptrace_entry, dead);
		}
	}

	kill_orphaned_pgrp(p, father);
}

/*
 * Make init inherit all the child processes
 */
static void forget_original_parent(struct task_struct *father,
					struct list_head *dead)
{
	struct task_struct *p, *t, *reaper;

	if (unlikely(!list_empty(&father->ptraced)))
		exit_ptrace(father, dead);

	/* Can drop and reacquire tasklist_lock */
	reaper = find_child_reaper(father, dead);
	if (list_empty(&father->children))
		return;

	reaper = find_new_reaper(father, reaper);
	list_for_each_entry(p, &father->children, sibling) {
		for_each_thread(p, t) {
			RCU_INIT_POINTER(t->real_parent, reaper);
			BUG_ON((!t->ptrace) != (rcu_access_pointer(t->parent) == father));
			if (likely(!t->ptrace))
				t->parent = t->real_parent;
			if (t->pdeath_signal)
				group_send_sig_info(t->pdeath_signal,
						    SEND_SIG_NOINFO, t,
						    PIDTYPE_TGID);
		}
		/*
		 * If this is a threaded reparent there is no need to
		 * notify anyone anything has happened.
		 */
		if (!same_thread_group(reaper, father))
			reparent_leader(father, p, dead);
	}
	list_splice_tail_init(&father->children, &reaper->children);
}

/*
 * Send signals to all our closest relatives so that they know
 * to properly mourn us..
 */
static void exit_notify(struct task_struct *tsk, int group_dead)
{
	bool autoreap;
	struct task_struct *p, *n;
	LIST_HEAD(dead);

	write_lock_irq(&tasklist_lock);
	forget_original_parent(tsk, &dead);

	if (group_dead)
		kill_orphaned_pgrp(tsk->group_leader, NULL);

	tsk->exit_state = EXIT_ZOMBIE;

	if (unlikely(tsk->ptrace)) {
		int sig = thread_group_leader(tsk) &&
				thread_group_empty(tsk) &&
				!ptrace_reparented(tsk) ?
			tsk->exit_signal : SIGCHLD;
		autoreap = do_notify_parent(tsk, sig);
	} else if (thread_group_leader(tsk)) {
		autoreap = thread_group_empty(tsk) &&
			do_notify_parent(tsk, tsk->exit_signal);
	} else {
		autoreap = true;
		/* untraced sub-thread */
		do_notify_pidfd(tsk);
	}

	if (autoreap) {
		tsk->exit_state = EXIT_DEAD;
		list_add(&tsk->ptrace_entry, &dead);
	}

	/* mt-exec, de_thread() is waiting for group leader */
	if (unlikely(tsk->signal->notify_count < 0))
		wake_up_process(tsk->signal->group_exec_task);
	write_unlock_irq(&tasklist_lock);

	list_for_each_entry_safe(p, n, &dead, ptrace_entry) {
		list_del_init(&p->ptrace_entry);
		release_task(p);
	}
}

#ifdef CONFIG_DEBUG_STACK_USAGE
#ifdef CONFIG_STACK_GROWSUP
unsigned long stack_not_used(struct task_struct *p)
{
	unsigned long *n = end_of_stack(p);

	do {	/* Skip over canary */
		n--;
	} while (!*n);

	return (unsigned long)end_of_stack(p) - (unsigned long)n;
}
#else /* !CONFIG_STACK_GROWSUP */
unsigned long stack_not_used(struct task_struct *p)
{
	unsigned long *n = end_of_stack(p);

	do {	/* Skip over canary */
		n++;
	} while (!*n);

	return (unsigned long)n - (unsigned long)end_of_stack(p);
}
#endif /* CONFIG_STACK_GROWSUP */

/* Count the maximum pages reached in kernel stacks */
static inline void kstack_histogram(unsigned long used_stack)
{
#ifdef CONFIG_VM_EVENT_COUNTERS
	if (used_stack <= 1024)
		count_vm_event(KSTACK_1K);
#if THREAD_SIZE > 1024
	else if (used_stack <= 2048)
		count_vm_event(KSTACK_2K);
#endif
#if THREAD_SIZE > 2048
	else if (used_stack <= 4096)
		count_vm_event(KSTACK_4K);
#endif
#if THREAD_SIZE > 4096
	else if (used_stack <= 8192)
		count_vm_event(KSTACK_8K);
#endif
#if THREAD_SIZE > 8192
	else if (used_stack <= 16384)
		count_vm_event(KSTACK_16K);
#endif
#if THREAD_SIZE > 16384
	else if (used_stack <= 32768)
		count_vm_event(KSTACK_32K);
#endif
#if THREAD_SIZE > 32768
	else if (used_stack <= 65536)
		count_vm_event(KSTACK_64K);
#endif
#if THREAD_SIZE > 65536
	else
		count_vm_event(KSTACK_REST);
#endif
#endif /* CONFIG_VM_EVENT_COUNTERS */
}

static void check_stack_usage(void)
{
	static DEFINE_SPINLOCK(low_water_lock);
	static int lowest_to_date = THREAD_SIZE;
	unsigned long free;

	free = stack_not_used(current);
	kstack_histogram(THREAD_SIZE - free);

	if (free >= lowest_to_date)
		return;

	spin_lock(&low_water_lock);
	if (free < lowest_to_date) {
		pr_info("%s (%d) used greatest stack depth: %lu bytes left\n",
			current->comm, task_pid_nr(current), free);
		lowest_to_date = free;
	}
	spin_unlock(&low_water_lock);
}
#else /* !CONFIG_DEBUG_STACK_USAGE */
static inline void check_stack_usage(void) {}
#endif /* CONFIG_DEBUG_STACK_USAGE */

static void synchronize_group_exit(struct task_struct *tsk, long code)
{
	struct sighand_struct *sighand = tsk->sighand;
	struct signal_struct *signal = tsk->signal;
	struct core_state *core_state;

	spin_lock_irq(&sighand->siglock);
	signal->quick_threads--;
	if ((signal->quick_threads == 0) &&
	    !(signal->flags & SIGNAL_GROUP_EXIT)) {
		signal->flags = SIGNAL_GROUP_EXIT;
		signal->group_exit_code = code;
		signal->group_stop_count = 0;
	}
	/*
	 * Serialize with any possible pending coredump.
	 * We must hold siglock around checking core_state
	 * and setting PF_POSTCOREDUMP.  The core-inducing thread
	 * will increment ->nr_threads for each thread in the
	 * group without PF_POSTCOREDUMP set.
	 */
	tsk->flags |= PF_POSTCOREDUMP;
	core_state = signal->core_state;
	spin_unlock_irq(&sighand->siglock);

	if (unlikely(core_state))
		coredump_task_exit(tsk, core_state);
}

void __noreturn do_exit(long code)
{
	struct task_struct *tsk = current;
	int group_dead;

	WARN_ON(irqs_disabled());
	WARN_ON(tsk->plug);

	kcov_task_exit(tsk);
	kmsan_task_exit(tsk);

	synchronize_group_exit(tsk, code);
	ptrace_event(PTRACE_EVENT_EXIT, code);
	user_events_exit(tsk);

	io_uring_files_cancel();
	sched_mm_cid_exit(tsk);
	exit_signals(tsk);  /* sets PF_EXITING */

	seccomp_filter_release(tsk);

	acct_update_integrals(tsk);
	group_dead = atomic_dec_and_test(&tsk->signal->live);
	if (group_dead) {
		/*
		 * If the last thread of global init has exited, panic
		 * immediately to get a useable coredump.
		 */
		if (unlikely(is_global_init(tsk)))
			panic("Attempted to kill init! exitcode=0x%08x\n",
				tsk->signal->group_exit_code ?: (int)code);

#ifdef CONFIG_POSIX_TIMERS
		hrtimer_cancel(&tsk->signal->real_timer);
		exit_itimers(tsk);
#endif
		if (tsk->mm)
			setmax_mm_hiwater_rss(&tsk->signal->maxrss, tsk->mm);
	}
	acct_collect(code, group_dead);
	if (group_dead)
		tty_audit_exit();
	audit_free(tsk);

	tsk->exit_code = code;
	taskstats_exit(tsk, group_dead);
	trace_sched_process_exit(tsk, group_dead);

	/*
	 * Since sampling can touch ->mm, make sure to stop everything before we
	 * tear it down.
	 *
	 * Also flushes inherited counters to the parent - before the parent
	 * gets woken up by child-exit notifications.
	 */
	perf_event_exit_task(tsk);
	/*
	 * PF_EXITING (above) ensures unwind_deferred_request() will no
	 * longer add new unwinds. While exit_mm() (below) will destroy the
	 * abaility to do unwinds. So flush any pending unwinds here.
	 */
	unwind_deferred_task_exit(tsk);

	exit_mm();

	if (group_dead)
		acct_process();

	exit_sem(tsk);
	exit_shm(tsk);
	exit_files(tsk);
	exit_fs(tsk);
	if (group_dead)
		disassociate_ctty(1);
	exit_nsproxy_namespaces(tsk);
	exit_task_work(tsk);
	exit_thread(tsk);

	sched_autogroup_exit_task(tsk);
	cgroup_task_exit(tsk);

	/*
	 * FIXME: do that only when needed, using sched_exit tracepoint
	 */
	flush_ptrace_hw_breakpoint(tsk);

	exit_tasks_rcu_start();
	exit_notify(tsk, group_dead);
	proc_exit_connector(tsk);
	mpol_put_task_policy(tsk);
#ifdef CONFIG_FUTEX
	if (unlikely(current->pi_state_cache))
		kfree(current->pi_state_cache);
#endif
	/*
	 * Make sure we are holding no locks:
	 */
	debug_check_no_locks_held();

	if (tsk->io_context)
		exit_io_context(tsk);

	if (tsk->splice_pipe)
		free_pipe_info(tsk->splice_pipe);

	if (tsk->task_frag.page)
		put_page(tsk->task_frag.page);

	exit_task_stack_account(tsk);

	check_stack_usage();
	preempt_disable();
	if (tsk->nr_dirtied)
		__this_cpu_add(dirty_throttle_leaks, tsk->nr_dirtied);
	exit_rcu();
	exit_tasks_rcu_finish();

	lockdep_free_task(tsk);
	do_task_dead();
}

void __noreturn make_task_dead(int signr)
{
	/*
	 * Take the task off the cpu after something catastrophic has
	 * happened.
	 *
	 * We can get here from a kernel oops, sometimes with preemption off.
	 * Start by checking for critical errors.
	 * Then fix up important state like USER_DS and preemption.
	 * Then do everything else.
	 */
	struct task_struct *tsk = current;
	unsigned int limit;

	if (unlikely(in_interrupt()))
		panic("Aiee, killing interrupt handler!");
	if (unlikely(!tsk->pid))
		panic("Attempted to kill the idle task!");

	if (unlikely(irqs_disabled())) {
		pr_info("note: %s[%d] exited with irqs disabled\n",
			current->comm, task_pid_nr(current));
		local_irq_enable();
	}
	if (unlikely(in_atomic())) {
		pr_info("note: %s[%d] exited with preempt_count %d\n",
			current->comm, task_pid_nr(current),
			preempt_count());
		preempt_count_set(PREEMPT_ENABLED);
	}

	/*
	 * Every time the system oopses, if the oops happens while a reference
	 * to an object was held, the reference leaks.
	 * If the oops doesn't also leak memory, repeated oopsing can cause
	 * reference counters to wrap around (if they're not using refcount_t).
	 * This means that repeated oopsing can make unexploitable-looking bugs
	 * exploitable through repeated oopsing.
	 * To make sure this can't happen, place an upper bound on how often the
	 * kernel may oops without panic().
	 */
	limit = READ_ONCE(oops_limit);
	if (atomic_inc_return(&oops_count) >= limit && limit)
		panic("Oopsed too often (kernel.oops_limit is %d)", limit);

	/*
	 * We're taking recursive faults here in make_task_dead. Safest is to just
	 * leave this task alone and wait for reboot.
	 */
	if (unlikely(tsk->flags & PF_EXITING)) {
		pr_alert("Fixing recursive fault but reboot is needed!\n");
		futex_exit_recursive(tsk);
		tsk->exit_state = EXIT_DEAD;
		refcount_inc(&tsk->rcu_users);
		do_task_dead();
	}

	do_exit(signr);
}

/**
 * sys_exit - Terminate the calling thread
 * @error_code: Exit status code returned to the parent process
 *
 * long-desc: Terminates the calling thread immediately, performing extensive
 *   cleanup of kernel resources. Only the low 8 bits of error_code are used;
 *   these bits are shifted left by 8 and stored as the wait status, making
 *   them retrievable via wait(2), waitpid(2), or waitid(2) by the parent.
 *
 *   This syscall terminates only the calling thread, not the entire process.
 *   In a multi-threaded process, other threads continue executing. To
 *   terminate all threads in the thread group, use exit_group(2) instead.
 *   Modern glibc (since version 2.3) implements _exit() using exit_group(2)
 *   rather than this syscall for exactly this reason.
 *
 *   The exit status encoding follows UNIX conventions: the low 7 bits (0x7f)
 *   of the wait status indicate termination by signal (0 means normal exit),
 *   bit 0x80 indicates core dump, and bits 8-15 contain the exit code passed
 *   to exit(). Since sys_exit shifts error_code left by 8, the value passed
 *   to sys_exit becomes bits 8-15 of the wait status, indicating normal exit.
 *
 *   The cleanup sequence performed by do_exit() includes:
 *   - Synchronizing with group exit (if other threads are exiting)
 *   - Notifying ptrace debuggers via PTRACE_EVENT_EXIT
 *   - Canceling io_uring operations
 *   - Setting PF_EXITING flag to mark thread as exiting
 *   - Releasing seccomp filters
 *   - Recording process accounting data
 *   - Stopping POSIX timers (if last thread in group)
 *   - Releasing the memory address space (mm_struct)
 *   - Releasing SysV semaphore undo structures
 *   - Detaching from shared memory segments
 *   - Closing all open file descriptors
 *   - Releasing filesystem context (cwd, root)
 *   - Disassociating from controlling terminal (if last thread)
 *   - Leaving namespaces
 *   - Executing pending task work
 *   - Releasing thread-specific state
 *   - Leaving cgroups
 *   - Flushing hardware breakpoints
 *   - Reparenting children to init or a subreaper
 *   - Sending SIGCHLD to parent process
 *   - Transitioning to zombie state
 *   - Freeing remaining resources and scheduling final context switch
 *
 *   This syscall does not return - after cleanup completes, the thread
 *   enters TASK_DEAD state and is scheduled away permanently.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: error_code
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: INT_MIN, INT_MAX
 *   constraint: Any integer value is accepted. Only the low 8 bits
 *     (error_code & 0xff) are used; all other bits are masked off. The
 *     resulting value is shifted left by 8 before being stored as the
 *     exit code, producing values in the range 0x0000-0xFF00. Conventionally,
 *     values 0-255 are used, with 0 indicating success and non-zero values
 *     indicating various error conditions defined by the application.
 *     Values 126-128 have special conventional meanings in shells.
 *
 * return:
 *   type: KAPI_TYPE_VOID
 *   check-type: KAPI_RETURN_NO_RETURN
 *   success: never returns
 *   desc: This syscall never returns to the caller. The thread is terminated
 *     and enters TASK_DEAD state. The exit status becomes available to the
 *     parent process via wait(2) family calls. If the parent has set SIGCHLD
 *     to SIG_IGN or used SA_NOCLDWAIT, the thread is automatically reaped
 *     without becoming a zombie.
 *
 * lock: sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The signal handler spinlock is acquired multiple times during exit
 *     processing: in synchronize_group_exit() to coordinate with other exiting
 *     threads and check for pending coredumps, in exit_signals() to set
 *     PF_EXITING and retarget shared pending signals, and in exit_notify()
 *     when notifying the parent. The lock protects signal-related state
 *     including the group exit code and quick_threads counter.
 *
 * lock: tasklist_lock
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: The global task list rwlock is acquired for writing in exit_notify()
 *     to safely reparent children, remove the task from process lists, and
 *     notify the parent. It protects the parent/child relationships and task
 *     list integrity. Also acquired for reading in exit_signals() if group
 *     stop notification is needed.
 *
 * lock: mm->mmap_lock
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: The memory map read-write semaphore is acquired for reading in
 *     exit_mm() during address space teardown. This synchronizes with other
 *     threads accessing the memory map and ensures safe transition to lazy
 *     TLB mode.
 *
 * lock: files->file_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The file descriptor table spinlock is acquired in exit_files()
 *     when closing file descriptors. Protects concurrent access to the
 *     process's file descriptor table.
 *
 * signal: SIGCHLD
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: When exiting thread is the thread group leader or is ptraced
 *   desc: Sends SIGCHLD to the parent process to notify it of the child's
 *     termination. The signal carries information about the exit status
 *     (si_status), termination cause (CLD_EXITED for normal exit), and
 *     resource usage. If parent has SIGCHLD set to SIG_IGN or SA_NOCLDWAIT,
 *     no signal is sent and the task is auto-reaped.
 *   timing: KAPI_SIGNAL_TIME_AFTER
 *
 * signal: SIGHUP
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: When exit orphans a process group with stopped members
 *   desc: Sends SIGHUP followed by SIGCONT to newly orphaned process groups
 *     that have stopped members. This implements POSIX semantics for orphaned
 *     process groups - stopped jobs in orphaned groups receive SIGHUP to
 *     notify them they can no longer be continued by job control.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * signal: SIGCONT
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_CONTINUE
 *   condition: After SIGHUP to orphaned process group
 *   desc: Sent immediately after SIGHUP to orphaned process groups with
 *     stopped members. Allows stopped processes to wake up and handle the
 *     SIGHUP signal rather than remaining stopped indefinitely.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * signal: pdeath_signal
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: When child processes are reparented and have pdeath_signal set
 *   desc: If a child process has set a parent-death signal via prctl(2)
 *     PR_SET_PDEATHSIG, that signal is sent to the child when this process
 *     exits and the child is reparented.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * side-effect: KAPI_EFFECT_PROCESS_STATE | KAPI_EFFECT_IRREVERSIBLE
 *   target: Calling thread
 *   desc: Terminates the calling thread. This is irreversible - once exit()
 *     is called, the thread cannot be resumed or restarted. The thread's
 *     task_struct transitions through EXIT_ZOMBIE state (waiting to be
 *     reaped by parent) and eventually to EXIT_DEAD (fully released).
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_FREE_MEMORY
 *   target: Address space (mm_struct)
 *   desc: Releases the thread's reference to the address space. If this is
 *     the last reference, all virtual memory mappings are unmapped, page
 *     tables are freed, and physical pages are released. Anonymous pages
 *     go to swap or are discarded; file-backed pages are written back if
 *     dirty.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_RESOURCE_DESTROY
 *   target: File descriptors
 *   desc: Closes all open file descriptors. For each fd, this decrements
 *     the file reference count and may trigger close operations including
 *     flushing buffers, releasing locks (flock, fcntl), and freeing
 *     resources. Pending writes may block if O_SYNC or similar is set.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Child processes
 *   desc: All child processes are reparented. The new parent is selected
 *     in order: (1) another thread in the same thread group, (2) the
 *     nearest ancestor marked as child_subreaper via prctl(), or (3)
 *     the init process (PID 1) in the child's PID namespace. Zombie
 *     children are immediately reparented to be reaped by the new parent.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_RESOURCE_DESTROY
 *   target: POSIX timers
 *   desc: If this is the last thread in the thread group, all POSIX timers
 *     created by timer_create(2) are destroyed. The real-time timer is
 *     canceled via hrtimer_cancel().
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_RESOURCE_DESTROY
 *   target: SysV semaphore undo entries
 *   desc: Releases all SysV semaphore undo entries (struct sem_undo).
 *     Pending semaphore adjustments from semop() with SEM_UNDO are applied.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_RESOURCE_DESTROY
 *   target: io_uring instances
 *   desc: Cancels all pending io_uring operations and releases io_uring
 *     state associated with this task.
 *   reversible: no
 *
 * state-trans: task->__state
 *   from: TASK_RUNNING
 *   to: TASK_DEAD
 *   condition: Always, at end of do_exit()
 *   desc: The task's scheduling state transitions from TASK_RUNNING (or
 *     any runnable state) to TASK_DEAD. In TASK_DEAD state, the task is
 *     removed from the run queue and will never be scheduled again. The
 *     final context switch releases the task_struct.
 *
 * state-trans: task->exit_state
 *   from: 0
 *   to: EXIT_ZOMBIE
 *   condition: When entering exit_notify()
 *   desc: The exit_state transitions from 0 (not exiting) to EXIT_ZOMBIE,
 *     indicating the task has exited but its exit status has not yet been
 *     collected by the parent. In zombie state, most resources are freed
 *     but the task_struct remains for status collection.
 *
 * state-trans: task->exit_state
 *   from: EXIT_ZOMBIE
 *   to: EXIT_DEAD
 *   condition: When parent ignores SIGCHLD or performs wait()
 *   desc: If the parent has SIGCHLD set to SIG_IGN or SA_NOCLDWAIT, or
 *     when the parent calls wait() to collect the status, the exit_state
 *     transitions to EXIT_DEAD. In EXIT_DEAD state, release_task() frees
 *     the remaining task_struct memory.
 *
 * state-trans: task->flags PF_EXITING
 *   from: unset
 *   to: set
 *   condition: During exit_signals()
 *   desc: The PF_EXITING flag is set to mark the task as exiting. This
 *     flag prevents the task from receiving new group-wide signals and
 *     is checked by various subsystems to avoid operating on exiting
 *     tasks.
 *
 * constraint: Thread vs Process Termination
 *   desc: This syscall only terminates the calling thread. In multi-threaded
 *     programs, use exit_group(2) to terminate all threads. The C library
 *     _exit() function typically calls exit_group(2), not this syscall.
 *     Direct use of sys_exit in multi-threaded programs leaves other
 *     threads running, which may not be the intended behavior.
 *
 * constraint: Init process protection
 *   desc: If the last thread of the global init process (PID 1) calls exit,
 *     the kernel panics with "Attempted to kill init!" rather than allowing
 *     system shutdown. This is intentional - init must be killed via
 *     reboot(2) or similar mechanisms that properly shut down the system.
 *     Container init processes in PID namespaces can exit normally.
 *
 * constraint: Coredump synchronization
 *   desc: If a coredump is in progress when exit() is called, the exiting
 *     thread waits for the coredump to complete before proceeding with
 *     exit cleanup. This ensures the coredump captures consistent state.
 *     The thread blocks in coredump_task_exit() until the core_state
 *     completion is signaled.
 *
 * examples: exit(0);  // Normal successful exit
 *   exit(1);  // Exit with error status
 *   exit(EXIT_FAILURE);  // Portable error exit (typically 1)
 *   syscall(SYS_exit, 42);  // Direct syscall, terminates only this thread
 *
 * notes: This is the raw kernel syscall that terminates a single thread.
 *   Applications should normally use the C library exit() or _exit()
 *   functions, which handle thread group termination properly.
 *
 *   The difference between exit(3), _exit(2), and sys_exit is critical:
 *   - exit(3): C library function that flushes stdio buffers, calls atexit
 *     handlers, then calls _exit()
 *   - _exit(2): glibc wrapper that calls exit_group(2) to terminate all
 *     threads in the process (since glibc 2.3)
 *   - sys_exit: Raw kernel syscall that terminates only the calling thread
 *
 *   The exit_group(2) syscall was added in Linux 2.5.35 specifically to
 *   support POSIX thread semantics where exit() should terminate all
 *   threads. Before that, terminating a multi-threaded process required
 *   userspace thread libraries to manually signal all threads.
 *
 *   The 8-bit exit code limitation is a historical UNIX constraint.
 *   waitpid(2) and friends encode termination information in a 16-bit
 *   status word where bits 0-7 indicate signal number (0 for exit()),
 *   bit 0x80 indicates core dump, and bits 8-15 contain the exit code.
 *
 *   Zombie processes consume minimal resources (just task_struct and
 *   some accounting structures) but should still be reaped promptly.
 *   A process that ignores SIGCHLD or has SA_NOCLDWAIT set does not
 *   create zombies - children are auto-reaped.
 *
 *   The syscall performs WARN_ON checks at entry to catch callers from
 *   invalid contexts (interrupts disabled, block I/O plug held).
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE1(exit, int, error_code)
{
	do_exit((error_code&0xff)<<8);
}

/*
 * Take down every thread in the group.  This is called by fatal signals
 * as well as by sys_exit_group (below).
 */
void __noreturn
do_group_exit(int exit_code)
{
	struct signal_struct *sig = current->signal;

	if (sig->flags & SIGNAL_GROUP_EXIT)
		exit_code = sig->group_exit_code;
	else if (sig->group_exec_task)
		exit_code = 0;
	else {
		struct sighand_struct *const sighand = current->sighand;

		spin_lock_irq(&sighand->siglock);
		if (sig->flags & SIGNAL_GROUP_EXIT)
			/* Another thread got here before we took the lock.  */
			exit_code = sig->group_exit_code;
		else if (sig->group_exec_task)
			exit_code = 0;
		else {
			sig->group_exit_code = exit_code;
			sig->flags = SIGNAL_GROUP_EXIT;
			zap_other_threads(current);
		}
		spin_unlock_irq(&sighand->siglock);
	}

	do_exit(exit_code);
	/* NOTREACHED */
}

/**
 * sys_exit_group - Terminate all threads in the calling process
 * @error_code: Exit status code returned to the parent process
 *
 * long-desc: Terminates all threads in the calling thread group (i.e., the
 *   entire process) immediately. This is the syscall invoked by glibc's
 *   _exit(2) wrapper since glibc 2.3, making it the standard way for
 *   processes to terminate. Only the low 8 bits of error_code are used;
 *   these bits are shifted left by 8 and stored as the wait status.
 *
 *   Unlike sys_exit which only terminates the calling thread, exit_group
 *   ensures that all threads in the process are terminated atomically.
 *   This is achieved by setting the SIGNAL_GROUP_EXIT flag and sending
 *   SIGKILL to all other threads via zap_other_threads().
 *
 *   The exit code handling follows these rules:
 *   - If SIGNAL_GROUP_EXIT is already set (another thread initiated group
 *     exit first), the existing group_exit_code is used instead
 *   - If an exec is in progress (group_exec_task is set), exit code is 0
 *   - Otherwise, this thread's exit code becomes the group exit code
 *
 *   Any process waiting via wait4() or related calls will receive the
 *   correct exit code regardless of which thread called exit_group, as
 *   the group_exit_code is stored in the shared signal_struct.
 *
 *   The cleanup sequence is the same as sys_exit (via do_exit()) but
 *   affects all threads:
 *   - Send SIGKILL to all other threads in the thread group
 *   - Synchronize with group exit and any pending coredump
 *   - Notify ptrace debuggers via PTRACE_EVENT_EXIT
 *   - Cancel io_uring operations
 *   - Set PF_EXITING flag on each thread
 *   - Release seccomp filters
 *   - Record process accounting data
 *   - Stop POSIX timers (when last thread exits)
 *   - Release memory address space
 *   - Release SysV semaphore undo structures
 *   - Detach from shared memory segments
 *   - Close all open file descriptors
 *   - Release filesystem context
 *   - Disassociate from controlling terminal
 *   - Leave namespaces
 *   - Reparent children to init or subreaper
 *   - Send SIGCHLD to parent
 *   - Transition to zombie state
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: error_code
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: INT_MIN, INT_MAX
 *   constraint: Any integer value is accepted. Only the low 8 bits
 *     (error_code & 0xff) are used; all other bits are masked off. The
 *     resulting value is shifted left by 8 before being stored as the
 *     exit code, producing values in the range 0x0000-0xFF00. Conventionally,
 *     values 0-255 are used, with 0 indicating success and non-zero values
 *     indicating various error conditions defined by the application.
 *
 * return:
 *   type: KAPI_TYPE_VOID
 *   check-type: KAPI_RETURN_NO_RETURN
 *   success: never returns
 *   desc: This syscall never returns to the caller. All threads in the
 *     thread group are terminated. The exit status becomes available to
 *     the parent process via wait(2) family calls. If the parent has set
 *     SIGCHLD to SIG_IGN or used SA_NOCLDWAIT, the process is automatically
 *     reaped without becoming a zombie.
 *
 * lock: sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The signal handler spinlock is acquired in do_group_exit() to
 *     atomically check/set SIGNAL_GROUP_EXIT flag and store the group exit
 *     code. Also acquired multiple times during do_exit() processing for
 *     signal coordination, coredump synchronization, and parent notification.
 *
 * lock: tasklist_lock
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: The global task list rwlock is acquired for writing in exit_notify()
 *     to safely reparent children, remove tasks from process lists, and
 *     notify the parent. Protects parent/child relationships and task
 *     list integrity.
 *
 * lock: mm->mmap_lock
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: The memory map read-write semaphore is acquired for reading in
 *     exit_mm() during address space teardown. Synchronizes with other
 *     threads accessing the memory map.
 *
 * signal: SIGKILL
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_TERMINATE
 *   condition: Always sent to all other threads in the thread group
 *   desc: zap_other_threads() adds SIGKILL to the pending signal set of
 *     every other thread in the thread group and wakes them up. This
 *     ensures all threads terminate regardless of their current state
 *     (blocked, sleeping, etc.). Each thread will process the SIGKILL
 *     and call do_exit() independently.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * signal: SIGCHLD
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: When the thread group leader exits (last thread to exit)
 *   desc: Sends SIGCHLD to the parent process to notify it of the child's
 *     termination. The signal carries information about the exit status
 *     (si_status), termination cause (CLD_EXITED), and resource usage.
 *     If parent has SIGCHLD set to SIG_IGN or SA_NOCLDWAIT, no signal is
 *     sent and the process is auto-reaped.
 *   timing: KAPI_SIGNAL_TIME_AFTER
 *
 * signal: SIGHUP
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: When exit orphans a process group with stopped members
 *   desc: Sends SIGHUP followed by SIGCONT to newly orphaned process groups
 *     that have stopped members. This implements POSIX semantics for orphaned
 *     process groups.
 *   timing: KAPI_SIGNAL_TIME_DURING
 *
 * side-effect: KAPI_EFFECT_PROCESS_STATE | KAPI_EFFECT_IRREVERSIBLE
 *   target: All threads in thread group
 *   desc: Terminates all threads in the calling process. Each thread's
 *     task_struct transitions through EXIT_ZOMBIE state and eventually to
 *     EXIT_DEAD. This is irreversible - the entire process is terminated.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_FREE_MEMORY
 *   target: Address space (mm_struct)
 *   desc: Releases all references to the address space. When the last thread
 *     exits, all virtual memory mappings are unmapped, page tables are freed,
 *     and physical pages are released.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_RESOURCE_DESTROY
 *   target: File descriptors
 *   desc: Closes all open file descriptors for each thread. This may trigger
 *     flush operations, release file locks, and free resources.
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Child processes
 *   desc: All child processes are reparented. The new parent is selected
 *     in order: (1) a thread in the same thread group (but all are exiting),
 *     (2) the nearest ancestor marked as child_subreaper, or (3) init (PID 1).
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_RESOURCE_DESTROY
 *   target: POSIX timers
 *   desc: When the last thread in the thread group exits, all POSIX timers
 *     are destroyed and the real-time timer is canceled.
 *   reversible: no
 *
 * state-trans: signal->flags SIGNAL_GROUP_EXIT
 *   from: unset (or already set)
 *   to: set
 *   condition: First thread to call exit_group or receive fatal signal
 *   desc: The SIGNAL_GROUP_EXIT flag is set atomically under siglock to
 *     coordinate group-wide exit. If already set, the existing group_exit_code
 *     is used. This ensures all threads exit with the same status.
 *
 * state-trans: task->exit_state
 *   from: 0
 *   to: EXIT_ZOMBIE
 *   condition: When each thread enters exit_notify()
 *   desc: Each thread's exit_state transitions to EXIT_ZOMBIE, indicating
 *     it has exited but status has not been collected. The thread group
 *     leader remains zombie until parent reaps it.
 *
 * state-trans: task->__state
 *   from: TASK_RUNNING
 *   to: TASK_DEAD
 *   condition: At end of do_exit() for each thread
 *   desc: Each thread's scheduling state transitions to TASK_DEAD and is
 *     removed from the run queue permanently.
 *
 * constraint: Exec race handling
 *   desc: If an exec() is in progress when exit_group() is called (indicated
 *     by group_exec_task being set), the exit code is forced to 0. This
 *     handles the race between exec and exit_group gracefully.
 *
 * constraint: Multiple exit_group race
 *   desc: If multiple threads call exit_group() simultaneously, only the
 *     first thread's exit code is used. Subsequent threads observe
 *     SIGNAL_GROUP_EXIT already set and use the existing group_exit_code.
 *     The siglock ensures atomicity of this check-and-set operation.
 *
 * constraint: Init process protection
 *   desc: If the last thread of the global init process (PID 1) exits via
 *     exit_group, the kernel panics with "Attempted to kill init!" rather
 *     than allowing an uncontrolled system shutdown.
 *
 * constraint: Coredump synchronization
 *   desc: If a coredump is in progress, exiting threads wait in
 *     coredump_task_exit() until the dump completes. The PF_POSTCOREDUMP
 *     flag is set to mark threads that have passed this synchronization.
 *
 * examples: _exit(0);  // glibc calls exit_group(0) internally
 *   syscall(SYS_exit_group, 1);  // Direct syscall with error status
 *   exit(EXIT_FAILURE);  // C library exit() eventually calls exit_group
 *
 * notes: This syscall is the preferred way to terminate a process. Since
 *   glibc 2.3, the _exit() library function calls exit_group() rather than
 *   the older sys_exit syscall. This ensures proper termination of all
 *   threads in multi-threaded programs.
 *
 *   glibc does not provide a direct wrapper for exit_group(); callers must
 *   use syscall(SYS_exit_group, status) or rely on _exit() which calls it.
 *
 *   The syscall was introduced specifically for NPTL (Native POSIX Thread
 *   Library) to provide efficient thread group termination. Previously,
 *   thread libraries had to manually signal each thread, which was slower
 *   and had race conditions if threads were killed externally.
 *
 *   The return value of 0 in the syscall definition is never reached since
 *   do_group_exit() is marked __noreturn. It exists only to satisfy the
 *   SYSCALL_DEFINE macro requirements.
 *
 *   When a fatal signal (like SIGSEGV) kills a process, the kernel also
 *   uses do_group_exit() to ensure all threads are terminated together.
 *
 * since-version: 2.5.35
 */
SYSCALL_DEFINE1(exit_group, int, error_code)
{
	do_group_exit((error_code & 0xff) << 8);
	/* NOTREACHED */
	return 0;
}

static int eligible_pid(struct wait_opts *wo, struct task_struct *p)
{
	return	wo->wo_type == PIDTYPE_MAX ||
		task_pid_type(p, wo->wo_type) == wo->wo_pid;
}

static int
eligible_child(struct wait_opts *wo, bool ptrace, struct task_struct *p)
{
	if (!eligible_pid(wo, p))
		return 0;

	/*
	 * Wait for all children (clone and not) if __WALL is set or
	 * if it is traced by us.
	 */
	if (ptrace || (wo->wo_flags & __WALL))
		return 1;

	/*
	 * Otherwise, wait for clone children *only* if __WCLONE is set;
	 * otherwise, wait for non-clone children *only*.
	 *
	 * Note: a "clone" child here is one that reports to its parent
	 * using a signal other than SIGCHLD, or a non-leader thread which
	 * we can only see if it is traced by us.
	 */
	if ((p->exit_signal != SIGCHLD) ^ !!(wo->wo_flags & __WCLONE))
		return 0;

	return 1;
}

/*
 * Handle sys_wait4 work for one task in state EXIT_ZOMBIE.  We hold
 * read_lock(&tasklist_lock) on entry.  If we return zero, we still hold
 * the lock and this task is uninteresting.  If we return nonzero, we have
 * released the lock and the system call should return.
 */
static int wait_task_zombie(struct wait_opts *wo, struct task_struct *p)
{
	int state, status;
	pid_t pid = task_pid_vnr(p);
	uid_t uid = from_kuid_munged(current_user_ns(), task_uid(p));
	struct waitid_info *infop;

	if (!likely(wo->wo_flags & WEXITED))
		return 0;

	if (unlikely(wo->wo_flags & WNOWAIT)) {
		status = (p->signal->flags & SIGNAL_GROUP_EXIT)
			? p->signal->group_exit_code : p->exit_code;
		get_task_struct(p);
		read_unlock(&tasklist_lock);
		sched_annotate_sleep();
		if (wo->wo_rusage)
			getrusage(p, RUSAGE_BOTH, wo->wo_rusage);
		put_task_struct(p);
		goto out_info;
	}
	/*
	 * Move the task's state to DEAD/TRACE, only one thread can do this.
	 */
	state = (ptrace_reparented(p) && thread_group_leader(p)) ?
		EXIT_TRACE : EXIT_DEAD;
	if (cmpxchg(&p->exit_state, EXIT_ZOMBIE, state) != EXIT_ZOMBIE)
		return 0;
	/*
	 * We own this thread, nobody else can reap it.
	 */
	read_unlock(&tasklist_lock);
	sched_annotate_sleep();

	/*
	 * Check thread_group_leader() to exclude the traced sub-threads.
	 */
	if (state == EXIT_DEAD && thread_group_leader(p)) {
		struct signal_struct *sig = p->signal;
		struct signal_struct *psig = current->signal;
		unsigned long maxrss;
		u64 tgutime, tgstime;

		/*
		 * The resource counters for the group leader are in its
		 * own task_struct.  Those for dead threads in the group
		 * are in its signal_struct, as are those for the child
		 * processes it has previously reaped.  All these
		 * accumulate in the parent's signal_struct c* fields.
		 *
		 * We don't bother to take a lock here to protect these
		 * p->signal fields because the whole thread group is dead
		 * and nobody can change them.
		 *
		 * psig->stats_lock also protects us from our sub-threads
		 * which can reap other children at the same time.
		 *
		 * We use thread_group_cputime_adjusted() to get times for
		 * the thread group, which consolidates times for all threads
		 * in the group including the group leader.
		 */
		thread_group_cputime_adjusted(p, &tgutime, &tgstime);
		write_seqlock_irq(&psig->stats_lock);
		psig->cutime += tgutime + sig->cutime;
		psig->cstime += tgstime + sig->cstime;
		psig->cgtime += task_gtime(p) + sig->gtime + sig->cgtime;
		psig->cmin_flt +=
			p->min_flt + sig->min_flt + sig->cmin_flt;
		psig->cmaj_flt +=
			p->maj_flt + sig->maj_flt + sig->cmaj_flt;
		psig->cnvcsw +=
			p->nvcsw + sig->nvcsw + sig->cnvcsw;
		psig->cnivcsw +=
			p->nivcsw + sig->nivcsw + sig->cnivcsw;
		psig->cinblock +=
			task_io_get_inblock(p) +
			sig->inblock + sig->cinblock;
		psig->coublock +=
			task_io_get_oublock(p) +
			sig->oublock + sig->coublock;
		maxrss = max(sig->maxrss, sig->cmaxrss);
		if (psig->cmaxrss < maxrss)
			psig->cmaxrss = maxrss;
		task_io_accounting_add(&psig->ioac, &p->ioac);
		task_io_accounting_add(&psig->ioac, &sig->ioac);
		write_sequnlock_irq(&psig->stats_lock);
	}

	if (wo->wo_rusage)
		getrusage(p, RUSAGE_BOTH, wo->wo_rusage);
	status = (p->signal->flags & SIGNAL_GROUP_EXIT)
		? p->signal->group_exit_code : p->exit_code;
	wo->wo_stat = status;

	if (state == EXIT_TRACE) {
		write_lock_irq(&tasklist_lock);
		/* We dropped tasklist, ptracer could die and untrace */
		ptrace_unlink(p);

		/* If parent wants a zombie, don't release it now */
		state = EXIT_ZOMBIE;
		if (do_notify_parent(p, p->exit_signal))
			state = EXIT_DEAD;
		p->exit_state = state;
		write_unlock_irq(&tasklist_lock);
	}
	if (state == EXIT_DEAD)
		release_task(p);

out_info:
	infop = wo->wo_info;
	if (infop) {
		if ((status & 0x7f) == 0) {
			infop->cause = CLD_EXITED;
			infop->status = status >> 8;
		} else {
			infop->cause = (status & 0x80) ? CLD_DUMPED : CLD_KILLED;
			infop->status = status & 0x7f;
		}
		infop->pid = pid;
		infop->uid = uid;
	}

	return pid;
}

static int *task_stopped_code(struct task_struct *p, bool ptrace)
{
	if (ptrace) {
		if (task_is_traced(p) && !(p->jobctl & JOBCTL_LISTENING))
			return &p->exit_code;
	} else {
		if (p->signal->flags & SIGNAL_STOP_STOPPED)
			return &p->signal->group_exit_code;
	}
	return NULL;
}

/**
 * wait_task_stopped - Wait for %TASK_STOPPED or %TASK_TRACED
 * @wo: wait options
 * @ptrace: is the wait for ptrace
 * @p: task to wait for
 *
 * Handle sys_wait4() work for %p in state %TASK_STOPPED or %TASK_TRACED.
 *
 * CONTEXT:
 * read_lock(&tasklist_lock), which is released if return value is
 * non-zero.  Also, grabs and releases @p->sighand->siglock.
 *
 * RETURNS:
 * 0 if wait condition didn't exist and search for other wait conditions
 * should continue.  Non-zero return, -errno on failure and @p's pid on
 * success, implies that tasklist_lock is released and wait condition
 * search should terminate.
 */
static int wait_task_stopped(struct wait_opts *wo,
				int ptrace, struct task_struct *p)
{
	struct waitid_info *infop;
	int exit_code, *p_code, why;
	uid_t uid = 0; /* unneeded, required by compiler */
	pid_t pid;

	/*
	 * Traditionally we see ptrace'd stopped tasks regardless of options.
	 */
	if (!ptrace && !(wo->wo_flags & WUNTRACED))
		return 0;

	if (!task_stopped_code(p, ptrace))
		return 0;

	exit_code = 0;
	spin_lock_irq(&p->sighand->siglock);

	p_code = task_stopped_code(p, ptrace);
	if (unlikely(!p_code))
		goto unlock_sig;

	exit_code = *p_code;
	if (!exit_code)
		goto unlock_sig;

	if (!unlikely(wo->wo_flags & WNOWAIT))
		*p_code = 0;

	uid = from_kuid_munged(current_user_ns(), task_uid(p));
unlock_sig:
	spin_unlock_irq(&p->sighand->siglock);
	if (!exit_code)
		return 0;

	/*
	 * Now we are pretty sure this task is interesting.
	 * Make sure it doesn't get reaped out from under us while we
	 * give up the lock and then examine it below.  We don't want to
	 * keep holding onto the tasklist_lock while we call getrusage and
	 * possibly take page faults for user memory.
	 */
	get_task_struct(p);
	pid = task_pid_vnr(p);
	why = ptrace ? CLD_TRAPPED : CLD_STOPPED;
	read_unlock(&tasklist_lock);
	sched_annotate_sleep();
	if (wo->wo_rusage)
		getrusage(p, RUSAGE_BOTH, wo->wo_rusage);
	put_task_struct(p);

	if (likely(!(wo->wo_flags & WNOWAIT)))
		wo->wo_stat = (exit_code << 8) | 0x7f;

	infop = wo->wo_info;
	if (infop) {
		infop->cause = why;
		infop->status = exit_code;
		infop->pid = pid;
		infop->uid = uid;
	}
	return pid;
}

/*
 * Handle do_wait work for one task in a live, non-stopped state.
 * read_lock(&tasklist_lock) on entry.  If we return zero, we still hold
 * the lock and this task is uninteresting.  If we return nonzero, we have
 * released the lock and the system call should return.
 */
static int wait_task_continued(struct wait_opts *wo, struct task_struct *p)
{
	struct waitid_info *infop;
	pid_t pid;
	uid_t uid;

	if (!unlikely(wo->wo_flags & WCONTINUED))
		return 0;

	if (!(p->signal->flags & SIGNAL_STOP_CONTINUED))
		return 0;

	spin_lock_irq(&p->sighand->siglock);
	/* Re-check with the lock held.  */
	if (!(p->signal->flags & SIGNAL_STOP_CONTINUED)) {
		spin_unlock_irq(&p->sighand->siglock);
		return 0;
	}
	if (!unlikely(wo->wo_flags & WNOWAIT))
		p->signal->flags &= ~SIGNAL_STOP_CONTINUED;
	uid = from_kuid_munged(current_user_ns(), task_uid(p));
	spin_unlock_irq(&p->sighand->siglock);

	pid = task_pid_vnr(p);
	get_task_struct(p);
	read_unlock(&tasklist_lock);
	sched_annotate_sleep();
	if (wo->wo_rusage)
		getrusage(p, RUSAGE_BOTH, wo->wo_rusage);
	put_task_struct(p);

	infop = wo->wo_info;
	if (!infop) {
		wo->wo_stat = 0xffff;
	} else {
		infop->cause = CLD_CONTINUED;
		infop->pid = pid;
		infop->uid = uid;
		infop->status = SIGCONT;
	}
	return pid;
}

/*
 * Consider @p for a wait by @parent.
 *
 * -ECHILD should be in ->notask_error before the first call.
 * Returns nonzero for a final return, when we have unlocked tasklist_lock.
 * Returns zero if the search for a child should continue;
 * then ->notask_error is 0 if @p is an eligible child,
 * or still -ECHILD.
 */
static int wait_consider_task(struct wait_opts *wo, int ptrace,
				struct task_struct *p)
{
	/*
	 * We can race with wait_task_zombie() from another thread.
	 * Ensure that EXIT_ZOMBIE -> EXIT_DEAD/EXIT_TRACE transition
	 * can't confuse the checks below.
	 */
	int exit_state = READ_ONCE(p->exit_state);
	int ret;

	if (unlikely(exit_state == EXIT_DEAD))
		return 0;

	ret = eligible_child(wo, ptrace, p);
	if (!ret)
		return ret;

	if (unlikely(exit_state == EXIT_TRACE)) {
		/*
		 * ptrace == 0 means we are the natural parent. In this case
		 * we should clear notask_error, debugger will notify us.
		 */
		if (likely(!ptrace))
			wo->notask_error = 0;
		return 0;
	}

	if (likely(!ptrace) && unlikely(p->ptrace)) {
		/*
		 * If it is traced by its real parent's group, just pretend
		 * the caller is ptrace_do_wait() and reap this child if it
		 * is zombie.
		 *
		 * This also hides group stop state from real parent; otherwise
		 * a single stop can be reported twice as group and ptrace stop.
		 * If a ptracer wants to distinguish these two events for its
		 * own children it should create a separate process which takes
		 * the role of real parent.
		 */
		if (!ptrace_reparented(p))
			ptrace = 1;
	}

	/* slay zombie? */
	if (exit_state == EXIT_ZOMBIE) {
		/* we don't reap group leaders with subthreads */
		if (!delay_group_leader(p)) {
			/*
			 * A zombie ptracee is only visible to its ptracer.
			 * Notification and reaping will be cascaded to the
			 * real parent when the ptracer detaches.
			 */
			if (unlikely(ptrace) || likely(!p->ptrace))
				return wait_task_zombie(wo, p);
		}

		/*
		 * Allow access to stopped/continued state via zombie by
		 * falling through.  Clearing of notask_error is complex.
		 *
		 * When !@ptrace:
		 *
		 * If WEXITED is set, notask_error should naturally be
		 * cleared.  If not, subset of WSTOPPED|WCONTINUED is set,
		 * so, if there are live subthreads, there are events to
		 * wait for.  If all subthreads are dead, it's still safe
		 * to clear - this function will be called again in finite
		 * amount time once all the subthreads are released and
		 * will then return without clearing.
		 *
		 * When @ptrace:
		 *
		 * Stopped state is per-task and thus can't change once the
		 * target task dies.  Only continued and exited can happen.
		 * Clear notask_error if WCONTINUED | WEXITED.
		 */
		if (likely(!ptrace) || (wo->wo_flags & (WCONTINUED | WEXITED)))
			wo->notask_error = 0;
	} else {
		/*
		 * @p is alive and it's gonna stop, continue or exit, so
		 * there always is something to wait for.
		 */
		wo->notask_error = 0;
	}

	/*
	 * Wait for stopped.  Depending on @ptrace, different stopped state
	 * is used and the two don't interact with each other.
	 */
	ret = wait_task_stopped(wo, ptrace, p);
	if (ret)
		return ret;

	/*
	 * Wait for continued.  There's only one continued state and the
	 * ptracer can consume it which can confuse the real parent.  Don't
	 * use WCONTINUED from ptracer.  You don't need or want it.
	 */
	return wait_task_continued(wo, p);
}

/*
 * Do the work of do_wait() for one thread in the group, @tsk.
 *
 * -ECHILD should be in ->notask_error before the first call.
 * Returns nonzero for a final return, when we have unlocked tasklist_lock.
 * Returns zero if the search for a child should continue; then
 * ->notask_error is 0 if there were any eligible children,
 * or still -ECHILD.
 */
static int do_wait_thread(struct wait_opts *wo, struct task_struct *tsk)
{
	struct task_struct *p;

	list_for_each_entry(p, &tsk->children, sibling) {
		int ret = wait_consider_task(wo, 0, p);

		if (ret)
			return ret;
	}

	return 0;
}

static int ptrace_do_wait(struct wait_opts *wo, struct task_struct *tsk)
{
	struct task_struct *p;

	list_for_each_entry(p, &tsk->ptraced, ptrace_entry) {
		int ret = wait_consider_task(wo, 1, p);

		if (ret)
			return ret;
	}

	return 0;
}

bool pid_child_should_wake(struct wait_opts *wo, struct task_struct *p)
{
	if (!eligible_pid(wo, p))
		return false;

	if ((wo->wo_flags & __WNOTHREAD) && wo->child_wait.private != p->parent)
		return false;

	return true;
}

static int child_wait_callback(wait_queue_entry_t *wait, unsigned mode,
				int sync, void *key)
{
	struct wait_opts *wo = container_of(wait, struct wait_opts,
						child_wait);
	struct task_struct *p = key;

	if (pid_child_should_wake(wo, p))
		return default_wake_function(wait, mode, sync, key);

	return 0;
}

void __wake_up_parent(struct task_struct *p, struct task_struct *parent)
{
	__wake_up_sync_key(&parent->signal->wait_chldexit,
			   TASK_INTERRUPTIBLE, p);
}

static bool is_effectively_child(struct wait_opts *wo, bool ptrace,
				 struct task_struct *target)
{
	struct task_struct *parent =
		!ptrace ? target->real_parent : target->parent;

	return current == parent || (!(wo->wo_flags & __WNOTHREAD) &&
				     same_thread_group(current, parent));
}

/*
 * Optimization for waiting on PIDTYPE_PID. No need to iterate through child
 * and tracee lists to find the target task.
 */
static int do_wait_pid(struct wait_opts *wo)
{
	bool ptrace;
	struct task_struct *target;
	int retval;

	ptrace = false;
	target = pid_task(wo->wo_pid, PIDTYPE_TGID);
	if (target && is_effectively_child(wo, ptrace, target)) {
		retval = wait_consider_task(wo, ptrace, target);
		if (retval)
			return retval;
	}

	ptrace = true;
	target = pid_task(wo->wo_pid, PIDTYPE_PID);
	if (target && target->ptrace &&
	    is_effectively_child(wo, ptrace, target)) {
		retval = wait_consider_task(wo, ptrace, target);
		if (retval)
			return retval;
	}

	return 0;
}

long __do_wait(struct wait_opts *wo)
{
	long retval;

	/*
	 * If there is nothing that can match our criteria, just get out.
	 * We will clear ->notask_error to zero if we see any child that
	 * might later match our criteria, even if we are not able to reap
	 * it yet.
	 */
	wo->notask_error = -ECHILD;
	if ((wo->wo_type < PIDTYPE_MAX) &&
	   (!wo->wo_pid || !pid_has_task(wo->wo_pid, wo->wo_type)))
		goto notask;

	read_lock(&tasklist_lock);

	if (wo->wo_type == PIDTYPE_PID) {
		retval = do_wait_pid(wo);
		if (retval)
			return retval;
	} else {
		struct task_struct *tsk = current;

		do {
			retval = do_wait_thread(wo, tsk);
			if (retval)
				return retval;

			retval = ptrace_do_wait(wo, tsk);
			if (retval)
				return retval;

			if (wo->wo_flags & __WNOTHREAD)
				break;
		} while_each_thread(current, tsk);
	}
	read_unlock(&tasklist_lock);

notask:
	retval = wo->notask_error;
	if (!retval && !(wo->wo_flags & WNOHANG))
		return -ERESTARTSYS;

	return retval;
}

static long do_wait(struct wait_opts *wo)
{
	int retval;

	trace_sched_process_wait(wo->wo_pid);

	init_waitqueue_func_entry(&wo->child_wait, child_wait_callback);
	wo->child_wait.private = current;
	add_wait_queue(&current->signal->wait_chldexit, &wo->child_wait);

	do {
		set_current_state(TASK_INTERRUPTIBLE);
		retval = __do_wait(wo);
		if (retval != -ERESTARTSYS)
			break;
		if (signal_pending(current))
			break;
		schedule();
	} while (1);

	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&current->signal->wait_chldexit, &wo->child_wait);
	return retval;
}

int kernel_waitid_prepare(struct wait_opts *wo, int which, pid_t upid,
			  struct waitid_info *infop, int options,
			  struct rusage *ru)
{
	unsigned int f_flags = 0;
	struct pid *pid = NULL;
	enum pid_type type;

	if (options & ~(WNOHANG|WNOWAIT|WEXITED|WSTOPPED|WCONTINUED|
			__WNOTHREAD|__WCLONE|__WALL))
		return -EINVAL;
	if (!(options & (WEXITED|WSTOPPED|WCONTINUED)))
		return -EINVAL;

	switch (which) {
	case P_ALL:
		type = PIDTYPE_MAX;
		break;
	case P_PID:
		type = PIDTYPE_PID;
		if (upid <= 0)
			return -EINVAL;

		pid = find_get_pid(upid);
		break;
	case P_PGID:
		type = PIDTYPE_PGID;
		if (upid < 0)
			return -EINVAL;

		if (upid)
			pid = find_get_pid(upid);
		else
			pid = get_task_pid(current, PIDTYPE_PGID);
		break;
	case P_PIDFD:
		type = PIDTYPE_PID;
		if (upid < 0)
			return -EINVAL;

		pid = pidfd_get_pid(upid, &f_flags);
		if (IS_ERR(pid))
			return PTR_ERR(pid);

		break;
	default:
		return -EINVAL;
	}

	wo->wo_type	= type;
	wo->wo_pid	= pid;
	wo->wo_flags	= options;
	wo->wo_info	= infop;
	wo->wo_rusage	= ru;
	if (f_flags & O_NONBLOCK)
		wo->wo_flags |= WNOHANG;

	return 0;
}

static long kernel_waitid(int which, pid_t upid, struct waitid_info *infop,
			  int options, struct rusage *ru)
{
	struct wait_opts wo;
	long ret;

	ret = kernel_waitid_prepare(&wo, which, upid, infop, options, ru);
	if (ret)
		return ret;

	ret = do_wait(&wo);
	if (!ret && !(options & WNOHANG) && (wo.wo_flags & WNOHANG))
		ret = -EAGAIN;

	put_pid(wo.wo_pid);
	return ret;
}

SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
		infop, int, options, struct rusage __user *, ru)
{
	struct rusage r;
	struct waitid_info info = {.status = 0};
	long err = kernel_waitid(which, upid, &info, options, ru ? &r : NULL);
	int signo = 0;

	if (err > 0) {
		signo = SIGCHLD;
		err = 0;
		if (ru && copy_to_user(ru, &r, sizeof(struct rusage)))
			return -EFAULT;
	}
	if (!infop)
		return err;

	if (!user_write_access_begin(infop, sizeof(*infop)))
		return -EFAULT;

	unsafe_put_user(signo, &infop->si_signo, Efault);
	unsafe_put_user(0, &infop->si_errno, Efault);
	unsafe_put_user(info.cause, &infop->si_code, Efault);
	unsafe_put_user(info.pid, &infop->si_pid, Efault);
	unsafe_put_user(info.uid, &infop->si_uid, Efault);
	unsafe_put_user(info.status, &infop->si_status, Efault);
	user_write_access_end();
	return err;
Efault:
	user_write_access_end();
	return -EFAULT;
}

long kernel_wait4(pid_t upid, int __user *stat_addr, int options,
		  struct rusage *ru)
{
	struct wait_opts wo;
	struct pid *pid = NULL;
	enum pid_type type;
	long ret;

	if (options & ~(WNOHANG|WUNTRACED|WCONTINUED|
			__WNOTHREAD|__WCLONE|__WALL))
		return -EINVAL;

	/* -INT_MIN is not defined */
	if (upid == INT_MIN)
		return -ESRCH;

	if (upid == -1)
		type = PIDTYPE_MAX;
	else if (upid < 0) {
		type = PIDTYPE_PGID;
		pid = find_get_pid(-upid);
	} else if (upid == 0) {
		type = PIDTYPE_PGID;
		pid = get_task_pid(current, PIDTYPE_PGID);
	} else /* upid > 0 */ {
		type = PIDTYPE_PID;
		pid = find_get_pid(upid);
	}

	wo.wo_type	= type;
	wo.wo_pid	= pid;
	wo.wo_flags	= options | WEXITED;
	wo.wo_info	= NULL;
	wo.wo_stat	= 0;
	wo.wo_rusage	= ru;
	ret = do_wait(&wo);
	put_pid(pid);
	if (ret > 0 && stat_addr && put_user(wo.wo_stat, stat_addr))
		ret = -EFAULT;

	return ret;
}

int kernel_wait(pid_t pid, int *stat)
{
	struct wait_opts wo = {
		.wo_type	= PIDTYPE_PID,
		.wo_pid		= find_get_pid(pid),
		.wo_flags	= WEXITED,
	};
	int ret;

	ret = do_wait(&wo);
	if (ret > 0 && wo.wo_stat)
		*stat = wo.wo_stat;
	put_pid(wo.wo_pid);
	return ret;
}

SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
		int, options, struct rusage __user *, ru)
{
	struct rusage r;
	long err = kernel_wait4(upid, stat_addr, options, ru ? &r : NULL);

	if (err > 0) {
		if (ru && copy_to_user(ru, &r, sizeof(struct rusage)))
			return -EFAULT;
	}
	return err;
}

#ifdef __ARCH_WANT_SYS_WAITPID

/*
 * sys_waitpid() remains for compatibility. waitpid() should be
 * implemented by calling sys_wait4() from libc.a.
 */
SYSCALL_DEFINE3(waitpid, pid_t, pid, int __user *, stat_addr, int, options)
{
	return kernel_wait4(pid, stat_addr, options, NULL);
}

#endif

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(wait4,
	compat_pid_t, pid,
	compat_uint_t __user *, stat_addr,
	int, options,
	struct compat_rusage __user *, ru)
{
	struct rusage r;
	long err = kernel_wait4(pid, stat_addr, options, ru ? &r : NULL);
	if (err > 0) {
		if (ru && put_compat_rusage(&r, ru))
			return -EFAULT;
	}
	return err;
}

COMPAT_SYSCALL_DEFINE5(waitid,
		int, which, compat_pid_t, pid,
		struct compat_siginfo __user *, infop, int, options,
		struct compat_rusage __user *, uru)
{
	struct rusage ru;
	struct waitid_info info = {.status = 0};
	long err = kernel_waitid(which, pid, &info, options, uru ? &ru : NULL);
	int signo = 0;
	if (err > 0) {
		signo = SIGCHLD;
		err = 0;
		if (uru) {
			/* kernel_waitid() overwrites everything in ru */
			if (COMPAT_USE_64BIT_TIME)
				err = copy_to_user(uru, &ru, sizeof(ru));
			else
				err = put_compat_rusage(&ru, uru);
			if (err)
				return -EFAULT;
		}
	}

	if (!infop)
		return err;

	if (!user_write_access_begin(infop, sizeof(*infop)))
		return -EFAULT;

	unsafe_put_user(signo, &infop->si_signo, Efault);
	unsafe_put_user(0, &infop->si_errno, Efault);
	unsafe_put_user(info.cause, &infop->si_code, Efault);
	unsafe_put_user(info.pid, &infop->si_pid, Efault);
	unsafe_put_user(info.uid, &infop->si_uid, Efault);
	unsafe_put_user(info.status, &infop->si_status, Efault);
	user_write_access_end();
	return err;
Efault:
	user_write_access_end();
	return -EFAULT;
}
#endif

/*
 * This needs to be __function_aligned as GCC implicitly makes any
 * implementation of abort() cold and drops alignment specified by
 * -falign-functions=N.
 *
 * See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=88345#c11
 */
__weak __function_aligned void abort(void)
{
	BUG();

	/* if that doesn't kill us, halt */
	panic("Oops failed to kill thread");
}
EXPORT_SYMBOL(abort);
