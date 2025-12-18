// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/kernel/sys.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/utsname.h>
#include <linux/mman.h>
#include <linux/reboot.h>
#include <linux/prctl.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/ksm.h>
#include <linux/perf_event.h>
#include <linux/resource.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/capability.h>
#include <linux/device.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/posix-timers.h>
#include <linux/security.h>
#include <linux/random.h>
#include <linux/suspend.h>
#include <linux/tty.h>
#include <linux/signal.h>
#include <linux/cn_proc.h>
#include <linux/getcpu.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/seccomp.h>
#include <linux/cpu.h>
#include <linux/personality.h>
#include <linux/ptrace.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/gfp.h>
#include <linux/syscore_ops.h>
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/syscall_user_dispatch.h>

#include <linux/compat.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/user_namespace.h>
#include <linux/time_namespace.h>
#include <linux/binfmts.h>
#include <linux/futex.h>

#include <linux/sched.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/stat.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task.h>
#include <linux/sched/cputime.h>
#include <linux/rcupdate.h>
#include <linux/uidgid.h>
#include <linux/cred.h>

#include <linux/nospec.h>

#include <linux/kmsg_dump.h>
/* Move somewhere else to avoid recompiling? */
#include <generated/utsrelease.h>

#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>

#include <trace/events/task.h>

#include "uid16.h"

#ifndef SET_UNALIGN_CTL
# define SET_UNALIGN_CTL(a, b)	(-EINVAL)
#endif
#ifndef GET_UNALIGN_CTL
# define GET_UNALIGN_CTL(a, b)	(-EINVAL)
#endif
#ifndef SET_FPEMU_CTL
# define SET_FPEMU_CTL(a, b)	(-EINVAL)
#endif
#ifndef GET_FPEMU_CTL
# define GET_FPEMU_CTL(a, b)	(-EINVAL)
#endif
#ifndef SET_FPEXC_CTL
# define SET_FPEXC_CTL(a, b)	(-EINVAL)
#endif
#ifndef GET_FPEXC_CTL
# define GET_FPEXC_CTL(a, b)	(-EINVAL)
#endif
#ifndef GET_ENDIAN
# define GET_ENDIAN(a, b)	(-EINVAL)
#endif
#ifndef SET_ENDIAN
# define SET_ENDIAN(a, b)	(-EINVAL)
#endif
#ifndef GET_TSC_CTL
# define GET_TSC_CTL(a)		(-EINVAL)
#endif
#ifndef SET_TSC_CTL
# define SET_TSC_CTL(a)		(-EINVAL)
#endif
#ifndef GET_FP_MODE
# define GET_FP_MODE(a)		(-EINVAL)
#endif
#ifndef SET_FP_MODE
# define SET_FP_MODE(a,b)	(-EINVAL)
#endif
#ifndef SVE_SET_VL
# define SVE_SET_VL(a)		(-EINVAL)
#endif
#ifndef SVE_GET_VL
# define SVE_GET_VL()		(-EINVAL)
#endif
#ifndef SME_SET_VL
# define SME_SET_VL(a)		(-EINVAL)
#endif
#ifndef SME_GET_VL
# define SME_GET_VL()		(-EINVAL)
#endif
#ifndef PAC_RESET_KEYS
# define PAC_RESET_KEYS(a, b)	(-EINVAL)
#endif
#ifndef PAC_SET_ENABLED_KEYS
# define PAC_SET_ENABLED_KEYS(a, b, c)	(-EINVAL)
#endif
#ifndef PAC_GET_ENABLED_KEYS
# define PAC_GET_ENABLED_KEYS(a)	(-EINVAL)
#endif
#ifndef SET_TAGGED_ADDR_CTRL
# define SET_TAGGED_ADDR_CTRL(a)	(-EINVAL)
#endif
#ifndef GET_TAGGED_ADDR_CTRL
# define GET_TAGGED_ADDR_CTRL()		(-EINVAL)
#endif
#ifndef RISCV_V_SET_CONTROL
# define RISCV_V_SET_CONTROL(a)		(-EINVAL)
#endif
#ifndef RISCV_V_GET_CONTROL
# define RISCV_V_GET_CONTROL()		(-EINVAL)
#endif
#ifndef RISCV_SET_ICACHE_FLUSH_CTX
# define RISCV_SET_ICACHE_FLUSH_CTX(a, b)	(-EINVAL)
#endif
#ifndef PPC_GET_DEXCR_ASPECT
# define PPC_GET_DEXCR_ASPECT(a, b)	(-EINVAL)
#endif
#ifndef PPC_SET_DEXCR_ASPECT
# define PPC_SET_DEXCR_ASPECT(a, b, c)	(-EINVAL)
#endif

/*
 * this is where the system-wide overflow UID and GID are defined, for
 * architectures that now have 32-bit UID/GID but didn't in the past
 */

int overflowuid = DEFAULT_OVERFLOWUID;
int overflowgid = DEFAULT_OVERFLOWGID;

EXPORT_SYMBOL(overflowuid);
EXPORT_SYMBOL(overflowgid);

/*
 * the same as above, but for filesystems which can only store a 16-bit
 * UID and GID. as such, this is needed on all architectures
 */

int fs_overflowuid = DEFAULT_FS_OVERFLOWUID;
int fs_overflowgid = DEFAULT_FS_OVERFLOWGID;

EXPORT_SYMBOL(fs_overflowuid);
EXPORT_SYMBOL(fs_overflowgid);

static const struct ctl_table overflow_sysctl_table[] = {
	{
		.procname	= "overflowuid",
		.data		= &overflowuid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_MAXOLDUID,
	},
	{
		.procname	= "overflowgid",
		.data		= &overflowgid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_MAXOLDUID,
	},
};

static int __init init_overflow_sysctl(void)
{
	register_sysctl_init("kernel", overflow_sysctl_table);
	return 0;
}

postcore_initcall(init_overflow_sysctl);

/*
 * Returns true if current's euid is same as p's uid or euid,
 * or has CAP_SYS_NICE to p's user_ns.
 *
 * Called with rcu_read_lock, creds are safe
 */
static bool set_one_prio_perm(struct task_struct *p)
{
	const struct cred *cred = current_cred(), *pcred = __task_cred(p);

	if (uid_eq(pcred->uid,  cred->euid) ||
	    uid_eq(pcred->euid, cred->euid))
		return true;
	if (ns_capable(pcred->user_ns, CAP_SYS_NICE))
		return true;
	return false;
}

/*
 * set the priority of a task
 * - the caller must hold the RCU read lock
 */
static int set_one_prio(struct task_struct *p, int niceval, int error)
{
	int no_nice;

	if (!set_one_prio_perm(p)) {
		error = -EPERM;
		goto out;
	}
	if (niceval < task_nice(p) && !can_nice(p, niceval)) {
		error = -EACCES;
		goto out;
	}
	no_nice = security_task_setnice(p, niceval);
	if (no_nice) {
		error = no_nice;
		goto out;
	}
	if (error == -ESRCH)
		error = 0;
	set_user_nice(p, niceval);
out:
	return error;
}

/**
 * sys_setpriority - Set the scheduling priority (nice value) for processes
 * @which: Target type selector (PRIO_PROCESS, PRIO_PGRP, or PRIO_USER)
 * @who: Target identifier interpreted according to @which
 * @niceval: New nice value to set (range -20 to 19)
 *
 * long-desc: Sets the scheduling nice value for one or more processes. The nice
 *   value affects the relative CPU time allocation: lower nice values mean
 *   higher priority (more CPU time), higher nice values mean lower priority.
 *
 *   The @which parameter determines how @who is interpreted:
 *   - PRIO_PROCESS (0): @who is a process ID. If @who is 0, the calling
 *     process is targeted. Uses find_task_by_vpid() which respects PID
 *     namespace boundaries.
 *   - PRIO_PGRP (1): @who is a process group ID. If @who is 0, the calling
 *     process's process group is targeted. All threads in the process group
 *     are affected, iterated via do_each_pid_thread().
 *   - PRIO_USER (2): @who is a user ID. If @who is 0, the calling process's
 *     real UID is targeted. All processes owned by the specified user are
 *     affected. Only processes visible in the caller's PID namespace are
 *     modified (checked via task_pid_vnr() != 0).
 *
 *   The @niceval is clamped to the valid range [MIN_NICE, MAX_NICE] which is
 *   [-20, 19]. Values outside this range are silently adjusted to the nearest
 *   valid value, so niceval < -20 becomes -20, and niceval > 19 becomes 19.
 *
 *   Permission model: There are two separate permission checks for lowering
 *   nice values (raising priority):
 *   1. UID check: The caller's effective UID must match the target process's
 *      UID or effective UID, OR the caller must have CAP_SYS_NICE in the
 *      target's user namespace.
 *   2. RLIMIT check: The target nice value must be within the process's
 *      RLIMIT_NICE allowance (converted to nice range) OR the caller must
 *      have CAP_SYS_NICE. RLIMIT_NICE uses rlimit-style values (1-40) which
 *      map to nice values 19 to -20.
 *
 *   Raising nice values (lowering priority) has no restrictions beyond the
 *   basic UID check - unprivileged users can always lower their own priority.
 *
 *   LSM hooks: security_task_setnice() is called for each target task,
 *   allowing SELinux (PROCESS__SETSCHED permission) and other LSMs to
 *   impose additional restrictions.
 *
 *   For RT/DL tasks: The nice value is stored in static_prio but does not
 *   affect scheduling until the task returns to a normal scheduling class.
 *
 *   Error aggregation: When targeting multiple processes (PRIO_PGRP or
 *   PRIO_USER), if at least one process is successfully modified, the call
 *   returns 0. If all processes fail (or no processes match), the last error
 *   encountered is returned. ESRCH is only returned if no matching process
 *   was found at all.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: which
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_ENUM
 *   valid-mask: PRIO_PROCESS | PRIO_PGRP | PRIO_USER
 *   constraint: Must be exactly one of PRIO_PROCESS (0), PRIO_PGRP (1), or
 *     PRIO_USER (2). Any other value results in EINVAL.
 *
 * param: who
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Interpretation depends on @which. For PRIO_PROCESS, must be a
 *     valid PID in the caller's PID namespace or 0 (current process). For
 *     PRIO_PGRP, must be a valid process group ID or 0 (current pgrp). For
 *     PRIO_USER, must be a valid UID or 0 (current real UID). When @which is
 *     PRIO_USER, @who is converted to a kuid via make_kuid() using the caller's
 *     user namespace.
 *
 * param: niceval
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   range: -20, 19
 *   constraint: Any integer is accepted; values outside [-20, 19] are clamped.
 *     Lower values mean higher priority; -20 is highest priority (most CPU
 *     time), 19 is lowest priority (least CPU time).
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success, indicating at least one target process had its
 *     nice value updated. When targeting multiple processes, success means at
 *     least one was modified, even if others failed.
 *
 * error: EINVAL, Invalid which parameter
 *   desc: The @which parameter is not one of PRIO_PROCESS (0), PRIO_PGRP (1),
 *     or PRIO_USER (2). Checked at syscall entry before any process lookup.
 *
 * error: ESRCH, No matching process found
 *   desc: No process matched the @which/@who criteria. For PRIO_PROCESS, no
 *     process with the specified PID exists in the caller's PID namespace.
 *     For PRIO_PGRP, no process group with the specified PGID exists or the
 *     group is empty. For PRIO_USER, no processes owned by the specified UID
 *     exist that are visible in the caller's PID namespace. Also returned if
 *     find_user() fails to locate the user structure for the specified UID.
 *
 * error: EPERM, Permission denied (UID check failed)
 *   desc: The caller does not have permission to modify the target process's
 *     priority. Returned by set_one_prio_perm() when the caller's effective
 *     UID does not match either the target's UID or effective UID, AND the
 *     caller lacks CAP_SYS_NICE in the target's user namespace. Also returned
 *     by cap_safe_nice() via security_task_setnice() when the target task has
 *     capabilities not present in the caller's permitted set and the caller
 *     lacks CAP_SYS_NICE.
 *
 * error: EACCES, Permission denied (RLIMIT_NICE check failed)
 *   desc: The caller is attempting to set a nice value lower than the
 *     target's current nice value (raising priority), but the new nice value
 *     exceeds the RLIMIT_NICE allowance and the caller lacks CAP_SYS_NICE.
 *     Returned by can_nice() when the requested nice value would raise
 *     priority beyond what RLIMIT_NICE permits for unprivileged users.
 *
 * error: LSM-specific errors, Security module denied operation
 *   desc: A Linux Security Module (SELinux, AppArmor) denied the nice value
 *     change via security_task_setnice(). SELinux requires PROCESS__SETSCHED
 *     permission. The specific error code depends on the LSM implementation,
 *     but is typically EACCES or EPERM. Checked for each target process.
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is held for the duration of process iteration and
 *     lookup. Protects task structures from being freed during iteration.
 *     Required for find_task_by_vpid(), find_vpid(), and task credential
 *     access via __task_cred().
 *
 * lock: tasklist_lock
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: The global tasklist read lock is acquired only for PRIO_PGRP case
 *     during do_each_pid_thread() iteration to ensure thread group stability.
 *     Not acquired for PRIO_PROCESS or PRIO_USER cases. Acquired as read_lock
 *     inside rcu_read_lock section.
 *
 * lock: p->pi_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Each target task's priority inheritance lock is acquired via
 *     guard(task_rq_lock) in set_user_nice() when actually modifying the
 *     nice value. Protects scheduling-related fields. Acquired with IRQs
 *     disabled.
 *
 * lock: rq->lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The per-CPU run queue lock for each target task is acquired via
 *     guard(task_rq_lock) in set_user_nice(). Serializes modifications to
 *     task scheduling state and ensures atomic priority updates.
 *
 * lock: uidhash_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: For PRIO_USER case only, acquired by find_user() to look up the
 *     user_struct for the target UID. Acquired with IRQs disabled
 *     (spin_lock_irqsave). Also acquired by free_uid() when releasing the
 *     reference.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Target task(s) static_prio field
 *   desc: Updates p->static_prio for each successfully modified task.
 *     For normal scheduling class tasks, this changes p->prio and affects
 *     CPU scheduling weight. For RT/DL tasks, static_prio is stored but
 *     does not affect current scheduling.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: CFS scheduler load weight
 *   desc: For tasks in the fair scheduling class (SCHED_NORMAL, SCHED_BATCH),
 *     set_load_weight() is called to update the task's scheduling weight
 *     based on the new nice value. This affects the vruntime calculation
 *     and CPU time allocation.
 *   condition: Task is in fair scheduling class (not RT or DL)
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_SCHEDULE
 *   target: Run queue ordering
 *   desc: Changing the nice value may cause the task to be dequeued and
 *     re-enqueued on the run queue via the scoped sched_change guard in
 *     set_user_nice(). This can trigger immediate rescheduling if the
 *     priority change affects the current highest-priority runnable task.
 *   condition: Task is currently runnable (on_rq)
 *   reversible: yes
 *
 * state-trans: nice_value
 *   from: current nice value (task_nice(p))
 *   to: @niceval (clamped to [-20, 19])
 *   condition: Permission checks pass and niceval differs from current
 *   desc: The task's nice value is updated from its current value to the
 *     requested value. No change occurs if niceval equals current nice.
 *
 * capability: CAP_SYS_NICE
 *   type: KAPI_CAP_BYPASS_CHECK | KAPI_CAP_OVERRIDE_RESTRICTION
 *   allows: (1) Setting nice values for processes owned by other users.
 *     (2) Lowering nice values (raising priority) regardless of RLIMIT_NICE.
 *     (3) Modifying tasks that have capabilities not in caller's permitted set.
 *   without: Can only modify own processes (matching UID/EUID). Can only lower
 *     nice if current nice >= target nice, or if RLIMIT_NICE permits. Cannot
 *     modify tasks with elevated capabilities.
 *   condition: Checked by set_one_prio_perm() via ns_capable() in target's
 *     user namespace, and by can_nice() via capable(CAP_SYS_NICE), and by
 *     cap_safe_nice() via ns_capable().
 *
 * constraint: RLIMIT_NICE resource limit
 *   desc: For unprivileged users, RLIMIT_NICE determines the minimum nice
 *     value (maximum priority) that can be set. RLIMIT_NICE uses values 1-40
 *     which map to nice values 19 to -20 (conversion: nice = MAX_NICE - rlimit
 *     + 1). A RLIMIT_NICE of 0 allows no priority increases. Default is 0.
 *   expr: niceval >= (MAX_NICE - RLIMIT_NICE + 1) OR CAP_SYS_NICE
 *
 * constraint: PID namespace isolation
 *   desc: Processes are only visible and modifiable if they exist in the
 *     caller's PID namespace hierarchy. For PRIO_PROCESS and PRIO_PGRP, uses
 *     find_task_by_vpid()/find_vpid(). For PRIO_USER, only processes with
 *     task_pid_vnr(p) != 0 are considered (visible in caller's PID namespace).
 *
 * examples: setpriority(PRIO_PROCESS, 0, 10);  // Lower own priority to nice 10
 *   setpriority(PRIO_PROCESS, 1234, -5);  // Set PID 1234 to nice -5 (needs privs)
 *   setpriority(PRIO_PGRP, 0, 5);  // Set all procs in own pgrp to nice 5
 *   setpriority(PRIO_USER, 1000, 15);  // Set all UID 1000 procs to nice 15
 *
 * notes: This syscall originated in 4.2BSD and is specified by POSIX.1-2008.
 *   The kernel normalizes out-of-range nice values rather than returning an
 *   error, which differs from strict POSIX behavior.
 *
 *   The syscall number is 141 on x86-64, 97 on i386, and 140 in the generic
 *   syscall table.
 *
 *   Historical fix (commit 8639b46139b0): Prior to Linux 4.5, PRIO_USER mode
 *   could affect processes outside the caller's PID namespace. This was fixed
 *   by adding task_pid_vnr(p) check.
 *
 *   Historical optimization (commit 7f8ca0edfe07): The tasklist_lock is now
 *   only taken for PRIO_PGRP, not for PRIO_PROCESS or PRIO_USER, improving
 *   scalability.
 *
 *   When multiple processes match (PRIO_PGRP or PRIO_USER), the operation
 *   is not atomic across all of them - some may succeed while others fail.
 *   The syscall returns success if at least one succeeded.
 *
 *   The getpriority() syscall is the counterpart for reading nice values.
 *   Note that getpriority() returns 20 - nice (range 1-40) to avoid negative
 *   return values being confused with errors.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE3(setpriority, int, which, int, who, int, niceval)
{
	struct task_struct *g, *p;
	struct user_struct *user;
	const struct cred *cred = current_cred();
	int error = -EINVAL;
	struct pid *pgrp;
	kuid_t uid;

	if (which > PRIO_USER || which < PRIO_PROCESS)
		goto out;

	/* normalize: avoid signed division (rounding problems) */
	error = -ESRCH;
	if (niceval < MIN_NICE)
		niceval = MIN_NICE;
	if (niceval > MAX_NICE)
		niceval = MAX_NICE;

	rcu_read_lock();
	switch (which) {
	case PRIO_PROCESS:
		if (who)
			p = find_task_by_vpid(who);
		else
			p = current;
		if (p)
			error = set_one_prio(p, niceval, error);
		break;
	case PRIO_PGRP:
		if (who)
			pgrp = find_vpid(who);
		else
			pgrp = task_pgrp(current);
		read_lock(&tasklist_lock);
		do_each_pid_thread(pgrp, PIDTYPE_PGID, p) {
			error = set_one_prio(p, niceval, error);
		} while_each_pid_thread(pgrp, PIDTYPE_PGID, p);
		read_unlock(&tasklist_lock);
		break;
	case PRIO_USER:
		uid = make_kuid(cred->user_ns, who);
		user = cred->user;
		if (!who)
			uid = cred->uid;
		else if (!uid_eq(uid, cred->uid)) {
			user = find_user(uid);
			if (!user)
				goto out_unlock;	/* No processes for this user */
		}
		for_each_process_thread(g, p) {
			if (uid_eq(task_uid(p), uid) && task_pid_vnr(p))
				error = set_one_prio(p, niceval, error);
		}
		if (!uid_eq(uid, cred->uid))
			free_uid(user);		/* For find_user() */
		break;
	}
out_unlock:
	rcu_read_unlock();
out:
	return error;
}

/**
 * sys_getpriority - Get the scheduling priority (nice value) for processes
 * @which: Target type selector (PRIO_PROCESS, PRIO_PGRP, or PRIO_USER)
 * @who: Target identifier interpreted according to @which
 *
 * long-desc: Retrieves the scheduling nice value for one or more processes.
 *   When multiple processes match the criteria (PRIO_PGRP or PRIO_USER),
 *   returns the highest priority (lowest nice value) among all matching
 *   processes.
 *
 *   IMPORTANT: To avoid returning negative values that could be confused with
 *   error codes, the kernel returns an offset value in the range 1-40 instead
 *   of the actual nice value (-20 to 19). The formula is:
 *   returned_value = 20 - nice_value, so nice -20 returns 40, nice 19 returns 1.
 *   User-space wrappers (glibc) convert this back to the actual nice value.
 *
 *   The @which parameter determines how @who is interpreted:
 *   - PRIO_PROCESS (0): @who is a process ID. If @who is 0, the calling
 *     process is targeted. Uses find_task_by_vpid() which respects PID
 *     namespace boundaries.
 *   - PRIO_PGRP (1): @who is a process group ID. If @who is 0, the calling
 *     process's process group is targeted. All threads in the process group
 *     are examined via do_each_pid_thread(). Returns the highest priority
 *     (lowest nice value) found among all threads.
 *   - PRIO_USER (2): @who is a user ID. If @who is 0, the calling process's
 *     real UID is targeted. All processes owned by the specified user are
 *     examined. Only processes visible in the caller's PID namespace are
 *     considered (checked via task_pid_vnr() != 0). Returns the highest
 *     priority (lowest nice value) found.
 *
 *   For PRIO_USER, the @who value is converted to a kuid via make_kuid()
 *   using the caller's user namespace. If @who is 0 or matches the caller's
 *   UID, the current user_struct is used directly. Otherwise, find_user()
 *   is called to locate the user_struct for the target UID.
 *
 *   Unlike setpriority(), no permission checks are required to read process
 *   priorities. Any process can query the nice value of any other visible
 *   process.
 *
 *   POSIX specifies that when multiple processes match, getpriority() should
 *   return the lowest nice value (highest priority). Since the kernel returns
 *   offset values (40..1 maps to nice -20..19), it actually returns the
 *   highest offset value among matching processes.
 *
 *   Per-thread vs per-process: Under Linux/NPTL, nice values are per-thread
 *   attributes, which differs from POSIX semantics that treat nice as
 *   per-process. Different threads in the same process may have different
 *   nice values. This syscall examines individual threads.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: which
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_ENUM
 *   valid-mask: PRIO_PROCESS | PRIO_PGRP | PRIO_USER
 *   constraint: Must be exactly one of PRIO_PROCESS (0), PRIO_PGRP (1), or
 *     PRIO_USER (2). Any other value results in EINVAL.
 *
 * param: who
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Interpretation depends on @which. For PRIO_PROCESS, must be a
 *     valid PID in the caller's PID namespace or 0 (current process). For
 *     PRIO_PGRP, must be a valid process group ID or 0 (current pgrp). For
 *     PRIO_USER, must be a valid UID or 0 (current real UID). When @which is
 *     PRIO_USER, @who is converted to a kuid via make_kuid() using the caller's
 *     user namespace.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_RANGE
 *   success: 1 to 40
 *   desc: Returns an offset nice value in the range 1-40 on success. This maps
 *     to actual nice values 19 to -20 via the formula: nice = 20 - returned.
 *     When multiple processes match, returns the value corresponding to the
 *     highest priority (lowest nice value) among all matching processes.
 *     User-space wrappers convert this to the actual nice value. Since -1 is
 *     never returned on success, callers can distinguish success from error.
 *
 * error: EINVAL, Invalid which parameter
 *   desc: The @which parameter is not one of PRIO_PROCESS (0), PRIO_PGRP (1),
 *     or PRIO_USER (2). Checked at syscall entry before any process lookup.
 *
 * error: ESRCH, No matching process found
 *   desc: No process matched the @which/@who criteria. For PRIO_PROCESS, no
 *     process with the specified PID exists in the caller's PID namespace.
 *     For PRIO_PGRP, no process group with the specified PGID exists or the
 *     group has no threads. For PRIO_USER, no processes owned by the specified
 *     UID exist that are visible in the caller's PID namespace, or find_user()
 *     failed to locate the user_struct for the specified UID (meaning no
 *     processes exist for that user).
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is held for the duration of process iteration and
 *     lookup. Protects task structures from being freed during iteration.
 *     Required for find_task_by_vpid(), find_vpid(), task credential access,
 *     and for_each_process_thread() iteration.
 *
 * lock: tasklist_lock
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: The global tasklist read lock is acquired only for PRIO_PGRP case
 *     during do_each_pid_thread() iteration to ensure thread group stability.
 *     Not acquired for PRIO_PROCESS or PRIO_USER cases. Acquired as read_lock
 *     inside the rcu_read_lock section.
 *
 * lock: uidhash_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: For PRIO_USER case only, acquired by find_user() to look up the
 *     user_struct for the target UID. Acquired with IRQs disabled
 *     (spin_lock_irqsave). Also acquired by free_uid() when releasing the
 *     reference. Only acquired when @who != 0 and differs from caller's UID.
 *
 * constraint: PID namespace isolation
 *   desc: Processes are only visible if they exist in the caller's PID
 *     namespace hierarchy. For PRIO_PROCESS and PRIO_PGRP, uses
 *     find_task_by_vpid()/find_vpid(). For PRIO_USER, only processes with
 *     task_pid_vnr(p) != 0 are considered (visible in caller's PID namespace).
 *
 * examples: getpriority(PRIO_PROCESS, 0);  // Get own nice value (returns 1-40)
 *   getpriority(PRIO_PROCESS, 1234);  // Get nice value of PID 1234
 *   getpriority(PRIO_PGRP, 0);  // Get highest priority in own process group
 *   getpriority(PRIO_USER, 1000);  // Get highest priority among UID 1000 procs
 *
 * notes: This syscall originated in 4.2BSD and is specified by POSIX.1-2008.
 *   The unusual return value encoding (1-40 instead of -20..19) is for
 *   historical compatibility to distinguish success from error returns.
 *
 *   The syscall number is 140 on x86-64, 96 on i386, and 141 in the generic
 *   syscall table.
 *
 *   Historical fix (commit 8639b46139b0): Prior to Linux 4.5, PRIO_USER mode
 *   could examine processes outside the caller's PID namespace. This was fixed
 *   by adding the task_pid_vnr(p) != 0 check.
 *
 *   Historical fix (commit 701188374b6f): In 2.6.33-rc7, RCU protection was
 *   added for sys_setpriority() but was missing for sys_getpriority(). This
 *   was fixed to properly protect find_task_by_vpid() access.
 *
 *   The setpriority() syscall is the counterpart for modifying nice values.
 *   Together they provide the BSD-style priority management interface.
 *
 *   Alpha architecture note: OSF/1 compatibility layer (osf_getpriority)
 *   converts the return value back to the actual nice value (-20..19) and
 *   uses force_successful_syscall_return() to handle the negative values.
 *
 *   The for_each_process_thread() iteration in PRIO_USER case iterates over
 *   all processes and threads in the system, which can be expensive on systems
 *   with many processes.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE2(getpriority, int, which, int, who)
{
	struct task_struct *g, *p;
	struct user_struct *user;
	const struct cred *cred = current_cred();
	long niceval, retval = -ESRCH;
	struct pid *pgrp;
	kuid_t uid;

	if (which > PRIO_USER || which < PRIO_PROCESS)
		return -EINVAL;

	rcu_read_lock();
	switch (which) {
	case PRIO_PROCESS:
		if (who)
			p = find_task_by_vpid(who);
		else
			p = current;
		if (p) {
			niceval = nice_to_rlimit(task_nice(p));
			if (niceval > retval)
				retval = niceval;
		}
		break;
	case PRIO_PGRP:
		if (who)
			pgrp = find_vpid(who);
		else
			pgrp = task_pgrp(current);
		read_lock(&tasklist_lock);
		do_each_pid_thread(pgrp, PIDTYPE_PGID, p) {
			niceval = nice_to_rlimit(task_nice(p));
			if (niceval > retval)
				retval = niceval;
		} while_each_pid_thread(pgrp, PIDTYPE_PGID, p);
		read_unlock(&tasklist_lock);
		break;
	case PRIO_USER:
		uid = make_kuid(cred->user_ns, who);
		user = cred->user;
		if (!who)
			uid = cred->uid;
		else if (!uid_eq(uid, cred->uid)) {
			user = find_user(uid);
			if (!user)
				goto out_unlock;	/* No processes for this user */
		}
		for_each_process_thread(g, p) {
			if (uid_eq(task_uid(p), uid) && task_pid_vnr(p)) {
				niceval = nice_to_rlimit(task_nice(p));
				if (niceval > retval)
					retval = niceval;
			}
		}
		if (!uid_eq(uid, cred->uid))
			free_uid(user);		/* for find_user() */
		break;
	}
out_unlock:
	rcu_read_unlock();

	return retval;
}

/*
 * Unprivileged users may change the real gid to the effective gid
 * or vice versa.  (BSD-style)
 *
 * If you set the real gid at all, or set the effective gid to a value not
 * equal to the real gid, then the saved gid is set to the new effective gid.
 *
 * This makes it possible for a setgid program to completely drop its
 * privileges, which is often a useful assertion to make when you are doing
 * a security audit over a program.
 *
 * The general idea is that a program which uses just setregid() will be
 * 100% compatible with BSD.  A program which uses just setgid() will be
 * 100% compatible with POSIX with saved IDs.
 *
 * SMP: There are not races, the GIDs are checked only by filesystem
 *      operations (as far as semantic preservation is concerned).
 */
#ifdef CONFIG_MULTIUSER
long __sys_setregid(gid_t rgid, gid_t egid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kgid_t krgid, kegid;

	krgid = make_kgid(ns, rgid);
	kegid = make_kgid(ns, egid);

	if ((rgid != (gid_t) -1) && !gid_valid(krgid))
		return -EINVAL;
	if ((egid != (gid_t) -1) && !gid_valid(kegid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (rgid != (gid_t) -1) {
		if (gid_eq(old->gid, krgid) ||
		    gid_eq(old->egid, krgid) ||
		    ns_capable_setid(old->user_ns, CAP_SETGID))
			new->gid = krgid;
		else
			goto error;
	}
	if (egid != (gid_t) -1) {
		if (gid_eq(old->gid, kegid) ||
		    gid_eq(old->egid, kegid) ||
		    gid_eq(old->sgid, kegid) ||
		    ns_capable_setid(old->user_ns, CAP_SETGID))
			new->egid = kegid;
		else
			goto error;
	}

	if (rgid != (gid_t) -1 ||
	    (egid != (gid_t) -1 && !gid_eq(kegid, old->gid)))
		new->sgid = new->egid;
	new->fsgid = new->egid;

	retval = security_task_fix_setgid(new, old, LSM_SETID_RE);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

/**
 * sys_setregid - Set the real and effective group IDs of the calling process
 * @rgid: New real group ID, or (gid_t)-1 to leave unchanged
 * @egid: New effective group ID, or (gid_t)-1 to leave unchanged
 *
 * long-desc: Sets the real and/or effective group IDs of the calling process.
 *   This syscall provides BSD-style credential management where unprivileged
 *   processes may swap their real and effective group IDs or set them to
 *   values they already possess.
 *
 *   The special value (gid_t)-1 (0xFFFFFFFF) for either parameter means that
 *   the corresponding ID should not be changed. Both parameters can be -1,
 *   in which case the syscall succeeds but makes no changes.
 *
 *   Permission rules for setting real GID (@rgid != -1):
 *   - The caller may set rgid to the current real GID (no change)
 *   - The caller may set rgid to the current effective GID
 *   - The caller with CAP_SETGID may set rgid to any valid GID
 *
 *   Permission rules for setting effective GID (@egid != -1):
 *   - The caller may set egid to the current real GID
 *   - The caller may set egid to the current effective GID (no change)
 *   - The caller may set egid to the current saved set-group-ID
 *   - The caller with CAP_SETGID may set egid to any valid GID
 *
 *   Saved set-group-ID (sgid) behavior:
 *   - If rgid is set (rgid != -1), sgid is updated to the new effective GID
 *   - If egid is set to a value different from the original real GID,
 *     sgid is updated to the new effective GID
 *   - Otherwise, sgid remains unchanged
 *
 *   The filesystem group ID (fsgid) is always updated to match the new
 *   effective group ID, regardless of which IDs were changed.
 *
 *   User namespace support: The @rgid and @egid values are interpreted in
 *   the context of the caller's user namespace. They are converted to
 *   kernel-internal kgid_t values using make_kgid(). If a GID has no
 *   mapping in the caller's user namespace, it is considered invalid.
 *
 *   This syscall is only available when CONFIG_MULTIUSER is enabled. On
 *   single-user systems (CONFIG_MULTIUSER=n), this syscall is not defined.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: rgid
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be (gid_t)-1 to leave unchanged, OR a valid GID that
 *     the caller has permission to set. For unprivileged callers, must be
 *     the current real GID or effective GID. For privileged callers (with
 *     CAP_SETGID), may be any GID that has a mapping in the caller's user
 *     namespace.
 *
 * param: egid
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be (gid_t)-1 to leave unchanged, OR a valid GID that
 *     the caller has permission to set. For unprivileged callers, must be
 *     the current real GID, effective GID, or saved set-group-ID. For
 *     privileged callers (with CAP_SETGID), may be any GID that has a
 *     mapping in the caller's user namespace.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. The real and/or effective group IDs have
 *     been updated as requested, along with possible updates to the saved
 *     set-group-ID and filesystem group ID.
 *
 * error: EINVAL, Group ID not valid in user namespace
 *   desc: Either @rgid or @egid (when not -1) does not have a valid mapping
 *     in the caller's user namespace. This occurs when make_kgid() returns
 *     INVALID_GID, which is checked by gid_valid(). This typically happens
 *     when running in a user namespace that doesn't have the target GID
 *     mapped, or when the GID value is out of the mapped range.
 *
 * error: ENOMEM, Cannot allocate credentials structure
 *   desc: The kernel failed to allocate memory for the new credentials
 *     structure via prepare_creds(). This function uses kmem_cache_alloc()
 *     with GFP_KERNEL, which can fail under memory pressure. The syscall
 *     returns early without modifying any credentials.
 *
 * error: EPERM, Permission denied for real GID change
 *   desc: Returned when @rgid is not -1 and the caller does not have
 *     permission to set the real GID to the requested value. Specifically,
 *     the requested @rgid is not equal to the current real GID, not equal
 *     to the current effective GID, AND the caller does not have CAP_SETGID
 *     capability in the target user namespace.
 *
 * error: EPERM, Permission denied for effective GID change
 *   desc: Returned when @egid is not -1 and the caller does not have
 *     permission to set the effective GID to the requested value.
 *     Specifically, the requested @egid is not equal to the current real
 *     GID, not equal to the current effective GID, not equal to the current
 *     saved set-group-ID, AND the caller does not have CAP_SETGID capability
 *     in the target user namespace.
 *
 * error: EACCES, LSM policy denied the operation
 *   desc: A Linux Security Module (such as SafeSetID) denied the group ID
 *     transition via the security_task_fix_setgid() hook. SafeSetID enforces
 *     allowlist-based policies and returns -EACCES when a transition is not
 *     explicitly permitted. When SafeSetID denies the operation, it also
 *     sends SIGKILL to the process to prevent security vulnerabilities from
 *     missing allowlist entries.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process credential group IDs (gid, egid, sgid, fsgid)
 *   desc: Updates the calling process's group ID credentials according to
 *     the parameters. The real GID is set if @rgid != -1. The effective GID
 *     is set if @egid != -1. The saved set-group-ID is updated if the real
 *     GID is changed or if the effective GID is set to differ from the
 *     original real GID. The filesystem GID is always set to the new
 *     effective GID value.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process dumpability flag
 *   desc: If the effective GID or filesystem GID changes, the process's
 *     dumpability may be affected. In commit_creds(), if egid or fsgid
 *     differs from the old values, set_dumpable() is called with the
 *     suid_dumpable sysctl value, potentially making the process
 *     non-dumpable for security reasons.
 *   condition: Effective GID or filesystem GID changes
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process death signal (pdeath_signal)
 *   desc: If the effective GID changes to differ from the original effective
 *     GID, the pdeath_signal field of the task is cleared to 0. This prevents
 *     a process from receiving a death signal from its parent after changing
 *     credentials, which could be a security issue.
 *   condition: Effective GID changes
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Keyring state (via key_fsgid_changed)
 *   desc: If the filesystem GID changes, key_fsgid_changed() is called to
 *     update any keyring state that depends on the process's filesystem GID.
 *     This ensures proper key access control after credential changes.
 *   condition: Filesystem GID changes (always, since fsgid = new egid)
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_NETWORK
 *   target: Process connector notification (PROC_EVENT_GID)
 *   desc: If any of the group ID fields (gid, egid, sgid, fsgid) change,
 *     a PROC_EVENT_GID notification is sent via the process connector
 *     (proc_id_connector). This allows userspace processes monitoring the
 *     connector socket to be notified of credential changes.
 *   condition: Any group ID field changes (CONFIG_PROC_EVENTS enabled)
 *   reversible: no
 *
 * state-trans: credentials
 *   from: original credential state
 *   to: new credential state with updated group IDs
 *   condition: Permission checks pass and at least one GID changes
 *   desc: The process credentials atomically transition from the old state
 *     to the new state via commit_creds(). The old credentials are released
 *     via put_cred_many(). RCU is used to ensure safe concurrent access to
 *     credentials by other kernel code.
 *
 * capability: CAP_SETGID
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Setting the real GID to any valid GID (not just current gid/egid).
 *     Setting the effective GID to any valid GID (not just current gid/egid/sgid).
 *     Essentially allows arbitrary group ID changes within the user namespace.
 *   without: Can only set real GID to current real GID or effective GID. Can
 *     only set effective GID to current real GID, effective GID, or saved
 *     set-group-ID. These restrictions enforce the BSD-style privilege model.
 *   condition: Checked via ns_capable_setid(old->user_ns, CAP_SETGID) which
 *     verifies the capability in the credentials' user namespace and sets
 *     PF_SUPERPRIV flag on the task if capability is used.
 *
 * constraint: User namespace GID mapping
 *   desc: Both @rgid and @egid (when not -1) must have valid mappings in the
 *     caller's user namespace. The conversion via make_kgid() must produce a
 *     valid kgid_t (not INVALID_GID). In the initial user namespace, all
 *     32-bit GID values are valid except (gid_t)-1. In other user namespaces,
 *     only GIDs that have been explicitly mapped via /proc/[pid]/gid_map are
 *     valid.
 *   expr: gid_valid(make_kgid(current_user_ns(), rgid/egid))
 *
 * constraint: CONFIG_MULTIUSER kernel configuration
 *   desc: This syscall is only available when the kernel is built with
 *     CONFIG_MULTIUSER=y. This option is enabled by default and is required
 *     for multi-user systems. Embedded systems may disable it to save space,
 *     in which case all users are treated as root and this syscall is not
 *     available.
 *
 * examples: setregid(-1, 100);  // Set effective GID to 100, keep real GID
 *   setregid(100, -1);  // Set real GID to 100, keep effective GID
 *   setregid(100, 100);  // Set both to 100
 *   setregid(-1, -1);  // No change (always succeeds)
 *   setregid(getegid(), getgid());  // Swap real and effective GIDs
 *
 * notes: This syscall originated in 4.2BSD and is specified by POSIX.1-2001
 *   and POSIX.1-2008. The Linux implementation follows BSD semantics for
 *   compatibility.
 *
 *   The syscall number is 114 on x86-64, 71 (16-bit setregid16) and 204
 *   (32-bit setregid32) on i386.
 *
 *   For programs needing full control over all three group IDs (real,
 *   effective, and saved), use setresgid(2) instead.
 *
 *   Unlike setreuid(2) which has EAGAIN for RLIMIT_NPROC, setregid(2) does
 *   not check RLIMIT_NPROC since group changes don't affect process count
 *   accounting.
 *
 *   The man page warns that setregid() can fail even when called by root,
 *   so applications must always check the return value. This is particularly
 *   important when dropping privileges - a failed call could leave the
 *   process running with elevated privileges.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE2(setregid, gid_t, rgid, gid_t, egid)
{
	return __sys_setregid(rgid, egid);
}

/*
 * setgid() is implemented like SysV w/ SAVED_IDS
 *
 * SMP: Same implicit races as above.
 */
long __sys_setgid(gid_t gid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kgid_t kgid;

	kgid = make_kgid(ns, gid);
	if (!gid_valid(kgid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (ns_capable_setid(old->user_ns, CAP_SETGID))
		new->gid = new->egid = new->sgid = new->fsgid = kgid;
	else if (gid_eq(kgid, old->gid) || gid_eq(kgid, old->sgid))
		new->egid = new->fsgid = kgid;
	else
		goto error;

	retval = security_task_fix_setgid(new, old, LSM_SETID_ID);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

/**
 * sys_setgid - Set the group ID of the calling process
 * @gid: New group ID to set
 *
 * long-desc: Sets the group IDs of the calling process according to the
 *   SysV semantics with saved IDs. This syscall provides a mechanism for
 *   processes to change their group identity, subject to capability and
 *   permission checks.
 *
 *   Behavior with CAP_SETGID capability:
 *   When the caller has CAP_SETGID capability in its user namespace, all
 *   four group ID fields in the credentials are set to @gid:
 *   - Real group ID (gid)
 *   - Effective group ID (egid)
 *   - Saved set-group-ID (sgid)
 *   - Filesystem group ID (fsgid)
 *
 *   Behavior without CAP_SETGID capability:
 *   When the caller lacks CAP_SETGID, the syscall can only succeed if @gid
 *   matches either the current real group ID or the saved set-group-ID. In
 *   this case, only the effective group ID and filesystem group ID are
 *   changed to @gid. The real group ID and saved set-group-ID remain
 *   unchanged.
 *
 *   User namespace support: The @gid value is interpreted in the context
 *   of the caller's user namespace. It is converted to a kernel-internal
 *   kgid_t value using make_kgid(). If the GID has no mapping in the
 *   caller's user namespace (e.g., the namespace's gid_map doesn't include
 *   that value), the syscall fails with EINVAL.
 *
 *   POSIX compliance: This syscall implements POSIX.1-2001 and POSIX.1-2008
 *   semantics for setgid(), which specify saved ID support. The Linux
 *   implementation always has saved IDs enabled (there is no
 *   _POSIX_SAVED_IDS feature test; it is always present).
 *
 *   Threading considerations: At the kernel level, credentials are per-thread.
 *   However, POSIX mandates that all threads in a process share credentials.
 *   The glibc wrapper for setgid() uses a signal-based mechanism (via the
 *   NPTL threading implementation) to synchronize credential changes across
 *   all threads in the process. Direct syscall invocations bypass this
 *   synchronization and only affect the calling thread.
 *
 *   This syscall is only available when CONFIG_MULTIUSER is enabled. On
 *   single-user systems (CONFIG_MULTIUSER=n), this syscall is not defined.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: gid
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid GID that has a mapping in the caller's user
 *     namespace. For unprivileged callers (without CAP_SETGID), must also
 *     equal either the current real group ID or the saved set-group-ID.
 *     The special value (gid_t)-1 (0xFFFFFFFF) is not valid and will return
 *     EINVAL because INVALID_GID is defined as -1.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. The group IDs have been updated according
 *     to the capability-dependent rules described above.
 *
 * error: EINVAL, Group ID not valid in user namespace
 *   desc: The @gid value does not have a valid mapping in the caller's user
 *     namespace. This occurs when make_kgid() returns INVALID_GID (-1),
 *     which is detected by gid_valid(). Common causes include: (1) running
 *     in a user namespace that doesn't have the target GID mapped in
 *     /proc/[pid]/gid_map, (2) specifying (gid_t)-1 which equals INVALID_GID,
 *     or (3) the GID value being outside the mapped range for the namespace.
 *     In the initial user namespace, all 32-bit GID values are valid except
 *     (gid_t)-1.
 *
 * error: ENOMEM, Cannot allocate credentials structure
 *   desc: The kernel failed to allocate memory for the new credentials
 *     structure via prepare_creds(). This function uses kmem_cache_alloc()
 *     with GFP_KERNEL, which can fail under severe memory pressure. The
 *     syscall returns early without modifying any credentials. This error
 *     is rare under normal system operation.
 *
 * error: EPERM, Permission denied
 *   desc: The calling process does not have CAP_SETGID capability in its
 *     user namespace, AND the requested @gid does not match either the
 *     current real group ID (old->gid) or the saved set-group-ID (old->sgid).
 *     The capability check uses ns_capable_setid() which checks within the
 *     credentials' user namespace and sets PF_SUPERPRIV on success.
 *
 * error: EACCES, LSM policy denied the operation
 *   desc: A Linux Security Module denied the group ID transition via the
 *     security_task_fix_setgid() hook with the LSM_SETID_ID flag. The
 *     SafeSetID LSM, for example, enforces allowlist-based policies for
 *     GID transitions and returns -EACCES when a transition is not explicitly
 *     permitted. Note: SafeSetID also sends SIGKILL to the process when
 *     denying a transition to prevent security vulnerabilities from processes
 *     that don't check setgid() return values.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process credential group IDs (gid, egid, sgid, fsgid)
 *   desc: Updates the calling process's group ID credentials. With CAP_SETGID,
 *     all four group IDs (real, effective, saved, filesystem) are set to
 *     @gid. Without CAP_SETGID, only effective and filesystem group IDs are
 *     changed to @gid (when @gid matches real or saved GID).
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process dumpability flag
 *   desc: If the effective GID or filesystem GID changes from their original
 *     values, set_dumpable() is called in commit_creds() with the current
 *     suid_dumpable sysctl value. This may make the process non-dumpable
 *     (preventing core dumps and ptrace attachment) for security reasons,
 *     protecting sensitive data after credential changes.
 *   condition: Effective GID or filesystem GID changes
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process death signal (pdeath_signal)
 *   desc: If the effective GID changes, the task's pdeath_signal field is
 *     cleared to 0 in commit_creds(). This prevents a process from receiving
 *     an arbitrary signal from its parent after changing credentials, which
 *     could otherwise be a privilege escalation vector.
 *   condition: Effective GID changes
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Keyring state (via key_fsgid_changed)
 *   desc: If the filesystem GID changes, key_fsgid_changed() is called to
 *     update any keyring state dependent on the process's filesystem GID.
 *     This ensures proper key access control after credential changes.
 *   condition: Filesystem GID changes
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_NETWORK
 *   target: Process connector notification (PROC_EVENT_GID)
 *   desc: If any group ID field changes, a PROC_EVENT_GID notification is
 *     sent via proc_id_connector(). This allows userspace processes monitoring
 *     the process connector socket (CONFIG_PROC_EVENTS) to receive real-time
 *     notification of credential changes.
 *   condition: Any group ID field changes
 *   reversible: no
 *
 * state-trans: credentials
 *   from: original credential state
 *   to: new credential state with updated group IDs
 *   condition: All permission and LSM checks pass
 *   desc: The process credentials atomically transition from the old state
 *     to the new state via commit_creds(). RCU (rcu_assign_pointer) is used
 *     to ensure safe concurrent access by other kernel code that may be
 *     reading the credentials. The old credentials are released via
 *     put_cred_many() after the RCU grace period.
 *
 * capability: CAP_SETGID
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Setting all four group IDs (real, effective, saved, filesystem)
 *     to any valid GID in the user namespace. Essentially allows arbitrary
 *     group ID changes within the namespace.
 *   without: Can only change effective and filesystem GIDs, and only to a
 *     value that equals either the current real GID or saved set-group-ID.
 *     The real and saved GIDs cannot be changed without the capability.
 *   condition: Checked via ns_capable_setid(old->user_ns, CAP_SETGID) which
 *     verifies the capability in the credentials' user namespace and sets
 *     PF_SUPERPRIV flag on the task if the capability is used.
 *
 * constraint: User namespace GID mapping
 *   desc: The @gid value must have a valid mapping in the caller's user
 *     namespace. The conversion via make_kgid() must produce a valid kgid_t
 *     (not INVALID_GID). In the initial user namespace, all 32-bit GID
 *     values are valid except (gid_t)-1. In other user namespaces, only
 *     GIDs explicitly mapped via /proc/[pid]/gid_map are valid.
 *   expr: gid_valid(make_kgid(current_user_ns(), gid))
 *
 * constraint: CONFIG_MULTIUSER kernel configuration
 *   desc: This syscall is only available when the kernel is built with
 *     CONFIG_MULTIUSER=y (enabled by default). Embedded systems may disable
 *     this option to save space, in which case all users are treated as root
 *     and this syscall is unavailable.
 *
 * examples: setgid(100);  // Set group ID to 100 (if permitted)
 *   setgid(getgid());  // No-op, always succeeds for current real GID
 *   setgid(getegid());  // Only succeeds if egid equals gid or sgid
 *
 * notes: This syscall implements SysV semantics with saved IDs as noted in
 *   the kernel source comment. The "SMP: Same implicit races as above"
 *   comment refers to potential races between concurrent credential changes
 *   (e.g., from different threads calling set*gid syscalls simultaneously).
 *   These races are considered acceptable because the RCU mechanism ensures
 *   memory safety, even if the final credential state depends on timing.
 *
 *   The syscall number is 106 on x86-64, 144 in the generic syscall table,
 *   46 for the 16-bit setgid16 variant, and 214 for 32-bit setgid32 on i386.
 *
 *   Unlike setuid(2) which can return EAGAIN when RLIMIT_NPROC is exceeded,
 *   setgid(2) has no RLIMIT checking because group changes don't affect the
 *   per-user process count accounting.
 *
 *   For full control over all three group IDs independently, use setresgid(2).
 *   For changing only the effective GID without affecting saved GID under
 *   certain conditions, consider setregid(2).
 *
 *   The man page warns that setgid() can fail even when called by root (e.g.,
 *   if an LSM denies the operation). Applications should always check the
 *   return value, especially when dropping privileges, as a failed call
 *   could leave the process running with elevated privileges.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE1(setgid, gid_t, gid)
{
	return __sys_setgid(gid);
}

/*
 * change the user struct in a credentials set to match the new UID
 */
static int set_user(struct cred *new)
{
	struct user_struct *new_user;

	new_user = alloc_uid(new->uid);
	if (!new_user)
		return -EAGAIN;

	free_uid(new->user);
	new->user = new_user;
	return 0;
}

static void flag_nproc_exceeded(struct cred *new)
{
	if (new->ucounts == current_ucounts())
		return;

	/*
	 * We don't fail in case of NPROC limit excess here because too many
	 * poorly written programs don't check set*uid() return code, assuming
	 * it never fails if called by root.  We may still enforce NPROC limit
	 * for programs doing set*uid()+execve() by harmlessly deferring the
	 * failure to the execve() stage.
	 */
	if (is_rlimit_overlimit(new->ucounts, UCOUNT_RLIMIT_NPROC, rlimit(RLIMIT_NPROC)) &&
			new->user != INIT_USER)
		current->flags |= PF_NPROC_EXCEEDED;
	else
		current->flags &= ~PF_NPROC_EXCEEDED;
}

/*
 * Unprivileged users may change the real uid to the effective uid
 * or vice versa.  (BSD-style)
 *
 * If you set the real uid at all, or set the effective uid to a value not
 * equal to the real uid, then the saved uid is set to the new effective uid.
 *
 * This makes it possible for a setuid program to completely drop its
 * privileges, which is often a useful assertion to make when you are doing
 * a security audit over a program.
 *
 * The general idea is that a program which uses just setreuid() will be
 * 100% compatible with BSD.  A program which uses just setuid() will be
 * 100% compatible with POSIX with saved IDs.
 */
long __sys_setreuid(uid_t ruid, uid_t euid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kruid, keuid;

	kruid = make_kuid(ns, ruid);
	keuid = make_kuid(ns, euid);

	if ((ruid != (uid_t) -1) && !uid_valid(kruid))
		return -EINVAL;
	if ((euid != (uid_t) -1) && !uid_valid(keuid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (ruid != (uid_t) -1) {
		new->uid = kruid;
		if (!uid_eq(old->uid, kruid) &&
		    !uid_eq(old->euid, kruid) &&
		    !ns_capable_setid(old->user_ns, CAP_SETUID))
			goto error;
	}

	if (euid != (uid_t) -1) {
		new->euid = keuid;
		if (!uid_eq(old->uid, keuid) &&
		    !uid_eq(old->euid, keuid) &&
		    !uid_eq(old->suid, keuid) &&
		    !ns_capable_setid(old->user_ns, CAP_SETUID))
			goto error;
	}

	if (!uid_eq(new->uid, old->uid)) {
		retval = set_user(new);
		if (retval < 0)
			goto error;
	}
	if (ruid != (uid_t) -1 ||
	    (euid != (uid_t) -1 && !uid_eq(keuid, old->uid)))
		new->suid = new->euid;
	new->fsuid = new->euid;

	retval = security_task_fix_setuid(new, old, LSM_SETID_RE);
	if (retval < 0)
		goto error;

	retval = set_cred_ucounts(new);
	if (retval < 0)
		goto error;

	flag_nproc_exceeded(new);
	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

/**
 * sys_setreuid - Set the real and effective user IDs of the calling process
 * @ruid: New real user ID, or (uid_t)-1 to leave unchanged
 * @euid: New effective user ID, or (uid_t)-1 to leave unchanged
 *
 * long-desc: Sets the real and/or effective user IDs of the calling process.
 *   This syscall provides BSD-style credential management where unprivileged
 *   processes may swap their real and effective user IDs or set them to
 *   values they already possess.
 *
 *   The special value (uid_t)-1 (0xFFFFFFFF) for either parameter means that
 *   the corresponding ID should not be changed. Both parameters can be -1,
 *   in which case the syscall succeeds but makes no changes.
 *
 *   Permission rules for setting real UID (@ruid != -1):
 *   - The caller may set ruid to the current real UID (no change)
 *   - The caller may set ruid to the current effective UID
 *   - The caller with CAP_SETUID may set ruid to any valid UID
 *
 *   Permission rules for setting effective UID (@euid != -1):
 *   - The caller may set euid to the current real UID
 *   - The caller may set euid to the current effective UID (no change)
 *   - The caller may set euid to the current saved set-user-ID
 *   - The caller with CAP_SETUID may set euid to any valid UID
 *
 *   Saved set-user-ID (suid) behavior:
 *   - If ruid is set (ruid != -1), suid is updated to the new effective UID
 *   - If euid is set to a value different from the original real UID,
 *     suid is updated to the new effective UID
 *   - Otherwise, suid remains unchanged
 *
 *   The filesystem user ID (fsuid) is always updated to match the new
 *   effective user ID, regardless of which IDs were changed.
 *
 *   User namespace support: The @ruid and @euid values are interpreted in
 *   the context of the caller's user namespace. They are converted to
 *   kernel-internal kuid_t values using make_kuid(). If a UID has no
 *   mapping in the caller's user namespace, it is considered invalid.
 *
 *   This syscall is only available when CONFIG_MULTIUSER is enabled. On
 *   single-user systems (CONFIG_MULTIUSER=n), this syscall is not defined.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: ruid
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be (uid_t)-1 to leave unchanged, OR a valid UID that
 *     the caller has permission to set. For unprivileged callers, must be
 *     the current real UID or effective UID. For privileged callers (with
 *     CAP_SETUID), may be any UID that has a mapping in the caller's user
 *     namespace.
 *
 * param: euid
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be (uid_t)-1 to leave unchanged, OR a valid UID that
 *     the caller has permission to set. For unprivileged callers, must be
 *     the current real UID, effective UID, or saved set-user-ID. For
 *     privileged callers (with CAP_SETUID), may be any UID that has a
 *     mapping in the caller's user namespace.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. The real and/or effective user IDs have
 *     been updated as requested, along with possible updates to the saved
 *     set-user-ID and filesystem user ID.
 *
 * error: EINVAL, User ID not valid in user namespace
 *   desc: Either @ruid or @euid (when not -1) does not have a valid mapping
 *     in the caller's user namespace. This occurs when make_kuid() returns
 *     INVALID_UID, which is checked by uid_valid(). This typically happens
 *     when running in a user namespace that doesn't have the target UID
 *     mapped, or when the UID value is out of the mapped range.
 *
 * error: ENOMEM, Cannot allocate credentials structure
 *   desc: The kernel failed to allocate memory for the new credentials
 *     structure via prepare_creds(). This function uses kmem_cache_alloc()
 *     with GFP_KERNEL, which can fail under memory pressure. The syscall
 *     returns early without modifying any credentials.
 *
 * error: EPERM, Permission denied for real UID change
 *   desc: Returned when @ruid is not -1 and the caller does not have
 *     permission to set the real UID to the requested value. Specifically,
 *     the requested @ruid is not equal to the current real UID, not equal
 *     to the current effective UID, AND the caller does not have CAP_SETUID
 *     capability in the target user namespace.
 *
 * error: EPERM, Permission denied for effective UID change
 *   desc: Returned when @euid is not -1 and the caller does not have
 *     permission to set the effective UID to the requested value.
 *     Specifically, the requested @euid is not equal to the current real
 *     UID, not equal to the current effective UID, not equal to the current
 *     saved set-user-ID, AND the caller does not have CAP_SETUID capability
 *     in the target user namespace.
 *
 * error: EAGAIN, Cannot allocate user structure
 *   desc: Returned when the kernel fails to allocate a new user_struct in
 *     set_user() via alloc_uid(). This occurs when the real UID is being
 *     changed to a different value and memory allocation fails. The
 *     alloc_uid() function uses kmem_cache_zalloc() with GFP_KERNEL. Note
 *     that unlike older kernel versions, RLIMIT_NPROC is not checked at
 *     setuid time; instead, the PF_NPROC_EXCEEDED flag is set and checked
 *     at execve() time.
 *
 * error: EAGAIN, Cannot allocate ucounts structure
 *   desc: Returned when set_cred_ucounts() fails to allocate a new ucounts
 *     structure via alloc_ucounts(). This happens when changing to a
 *     different UID and the kernel cannot allocate memory for tracking
 *     per-user resource counts. Uses kzalloc() with GFP_KERNEL.
 *
 * error: EACCES, LSM policy denied the operation
 *   desc: A Linux Security Module (such as SafeSetID) denied the user ID
 *     transition via the security_task_fix_setuid() hook. SafeSetID enforces
 *     allowlist-based policies and returns -EACCES when a transition is not
 *     explicitly permitted. When SafeSetID denies the operation, it also
 *     sends SIGKILL to the process to prevent security vulnerabilities from
 *     missing allowlist entries.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process credential user IDs (uid, euid, suid, fsuid)
 *   desc: Updates the calling process's user ID credentials according to
 *     the parameters. The real UID is set if @ruid != -1. The effective UID
 *     is set if @euid != -1. The saved set-user-ID is updated if the real
 *     UID is changed or if the effective UID is set to differ from the
 *     original real UID. The filesystem UID is always set to the new
 *     effective UID value.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process user structure (user_struct)
 *   desc: If the real UID changes, set_user() allocates or finds the
 *     user_struct for the new UID, updates new->user, and releases the
 *     reference to the old user_struct via free_uid(). This affects
 *     per-user resource accounting.
 *   condition: Real UID changes to a different value
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process dumpability flag
 *   desc: If the effective UID or filesystem UID changes, the process's
 *     dumpability may be affected. In commit_creds(), if euid or fsuid
 *     differs from the old values, set_dumpable() is called with the
 *     suid_dumpable sysctl value, potentially making the process
 *     non-dumpable for security reasons.
 *   condition: Effective UID or filesystem UID changes
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process death signal (pdeath_signal)
 *   desc: If the effective UID changes to differ from the original effective
 *     UID, the pdeath_signal field of the task is cleared to 0. This prevents
 *     a process from receiving a death signal from its parent after changing
 *     credentials, which could be a security issue.
 *   condition: Effective UID changes
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Keyring state (via key_fsuid_changed)
 *   desc: If the filesystem UID changes, key_fsuid_changed() is called to
 *     update any keyring state that depends on the process's filesystem UID.
 *     This ensures proper key access control after credential changes.
 *   condition: Filesystem UID changes (always, since fsuid = new euid)
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process flags (PF_NPROC_EXCEEDED)
 *   desc: The flag_nproc_exceeded() function checks if the new credentials
 *     would exceed RLIMIT_NPROC. If so, PF_NPROC_EXCEEDED is set on the
 *     current task, deferring the RLIMIT_NPROC enforcement to execve()
 *     time. This ensures that set*uid() calls succeed even when over limit,
 *     but subsequent execve() calls will fail with EAGAIN.
 *   condition: New ucounts differ from current and RLIMIT_NPROC exceeded
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_NETWORK
 *   target: Process connector notification (PROC_EVENT_UID)
 *   desc: If any of the user ID fields (uid, euid, suid, fsuid) change,
 *     a PROC_EVENT_UID notification is sent via the process connector
 *     (proc_id_connector). This allows userspace processes monitoring the
 *     connector socket to be notified of credential changes.
 *   condition: Any user ID field changes (CONFIG_PROC_EVENTS enabled)
 *   reversible: no
 *
 * state-trans: credentials
 *   from: original credential state
 *   to: new credential state with updated user IDs
 *   condition: Permission checks pass and at least one UID changes
 *   desc: The process credentials atomically transition from the old state
 *     to the new state via commit_creds(). The old credentials are released
 *     via put_cred_many(). RCU is used to ensure safe concurrent access to
 *     credentials by other kernel code.
 *
 * capability: CAP_SETUID
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Setting the real UID to any valid UID (not just current uid/euid).
 *     Setting the effective UID to any valid UID (not just current uid/euid/suid).
 *     Essentially allows arbitrary user ID changes within the user namespace.
 *   without: Can only set real UID to current real UID or effective UID. Can
 *     only set effective UID to current real UID, effective UID, or saved
 *     set-user-ID. These restrictions enforce the BSD-style privilege model.
 *   condition: Checked via ns_capable_setid(old->user_ns, CAP_SETUID) which
 *     verifies the capability in the credentials' user namespace and sets
 *     PF_SUPERPRIV flag on the task if capability is used.
 *
 * constraint: User namespace UID mapping
 *   desc: Both @ruid and @euid (when not -1) must have valid mappings in the
 *     caller's user namespace. The conversion via make_kuid() must produce a
 *     valid kuid_t (not INVALID_UID). In the initial user namespace, all
 *     32-bit UID values are valid except (uid_t)-1. In other user namespaces,
 *     only UIDs that have been explicitly mapped via /proc/[pid]/uid_map are
 *     valid.
 *   expr: uid_valid(make_kuid(current_user_ns(), ruid/euid))
 *
 * constraint: CONFIG_MULTIUSER kernel configuration
 *   desc: This syscall is only available when the kernel is built with
 *     CONFIG_MULTIUSER=y. This option is enabled by default and is required
 *     for multi-user systems. Embedded systems may disable it to save space,
 *     in which case all users are treated as root and this syscall is not
 *     available.
 *
 * examples: setreuid(-1, 100);  // Set effective UID to 100, keep real UID
 *   setreuid(100, -1);  // Set real UID to 100, keep effective UID
 *   setreuid(100, 100);  // Set both to 100
 *   setreuid(-1, -1);  // No change (always succeeds)
 *   setreuid(geteuid(), getuid());  // Swap real and effective UIDs
 *
 * notes: This syscall originated in 4.2BSD and is specified by POSIX.1-2001
 *   and POSIX.1-2008. The Linux implementation follows BSD semantics for
 *   compatibility.
 *
 *   The syscall number is 113 on x86-64, 70 (16-bit setreuid16) and 203
 *   (32-bit setreuid32) on i386.
 *
 *   For programs needing full control over all three user IDs (real,
 *   effective, and saved), use setresuid(2) instead.
 *
 *   Unlike older kernels, RLIMIT_NPROC is not enforced at setreuid() time.
 *   Instead, the PF_NPROC_EXCEEDED flag is set and enforcement is deferred
 *   to execve(). This change was made because many programs don't check
 *   set*uid() return codes, and immediate failure could leave processes
 *   running with elevated privileges.
 *
 *   The man page warns that setreuid() can fail even when called by root,
 *   so applications must always check the return value. This is particularly
 *   important when dropping privileges - a failed call could leave the
 *   process running with elevated privileges.
 *
 *   The commoncap LSM module adjusts process capabilities via
 *   cap_emulate_setxuid() when UIDs change, unless SECURE_NO_SETUID_FIXUP
 *   is set in the securebits.
 *
 *   Threading: At the kernel level, UIDs are per-thread. However, POSIX
 *   requires all threads to share credentials. NPTL uses signal-based
 *   techniques to synchronize credential changes across threads.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE2(setreuid, uid_t, ruid, uid_t, euid)
{
	return __sys_setreuid(ruid, euid);
}

/**
 * sys_setuid - Set the user ID of the calling process
 * @uid: New user ID to set
 *
 * long-desc: Sets the effective user ID of the calling process, and
 *   depending on the caller's privileges, may also set the real UID,
 *   saved set-user-ID, and filesystem UID.
 *
 *   This syscall implements SysV/POSIX semantics with SAVED_IDS. The behavior
 *   differs significantly based on whether the caller has CAP_SETUID:
 *
 *   With CAP_SETUID capability:
 *   - The real UID (uid) is set to @uid
 *   - The saved set-user-ID (suid) is set to @uid
 *   - The effective UID (euid) is set to @uid
 *   - The filesystem UID (fsuid) is set to @uid
 *   - If the new UID differs from the old real UID, the user_struct is
 *     updated via set_user() to point to the new UID's accounting structure
 *
 *   Without CAP_SETUID capability:
 *   - The @uid must equal either the current real UID or the saved set-user-ID
 *   - Only the effective UID (euid) is set to @uid
 *   - The filesystem UID (fsuid) is set to @uid
 *   - The real UID and saved set-user-ID remain unchanged
 *
 *   CRITICAL SECURITY NOTE: Unlike setreuid(2), a privileged process that
 *   calls setuid() to a non-root UID CANNOT regain root privileges afterward.
 *   This is because setuid() sets ALL user IDs (uid, euid, suid) to the
 *   specified value when called with CAP_SETUID. This behavior follows POSIX
 *   SAVED_IDS semantics and is by design. Programs needing to temporarily
 *   drop privileges should use seteuid(2) or setreuid(2) instead.
 *
 *   User namespace support: The @uid value is interpreted in the context of
 *   the caller's user namespace. It is converted to a kernel-internal kuid_t
 *   value using make_kuid(). If @uid has no mapping in the caller's user
 *   namespace, it is considered invalid and EINVAL is returned.
 *
 *   Capability side effects: When UIDs change, the commoncap LSM adjusts
 *   process capabilities via cap_emulate_setxuid():
 *   - If transitioning from any UID == 0 to all UIDs != 0, and
 *     SECURE_KEEP_CAPS is not set, permitted and effective capabilities
 *     are cleared, along with ambient capabilities
 *   - If transitioning from euid == 0 to euid != 0, effective caps are cleared
 *   - If transitioning from euid != 0 to euid == 0, effective caps are set
 *     to permitted caps
 *   These adjustments can be suppressed by setting SECURE_NO_SETUID_FIXUP
 *   in the securebits via prctl(PR_SET_SECUREBITS).
 *
 *   This syscall is only available when CONFIG_MULTIUSER is enabled. On
 *   single-user systems (CONFIG_MULTIUSER=n), this syscall is not defined.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: uid
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid UID that the caller has permission to set.
 *     For unprivileged callers (without CAP_SETUID), must equal the current
 *     real UID or saved set-user-ID. For privileged callers (with CAP_SETUID),
 *     may be any UID that has a mapping in the caller's user namespace.
 *     Unlike setreuid/setresuid, the value (uid_t)-1 is NOT special and is
 *     treated as a literal UID value (which will fail uid_valid() check).
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. The user IDs have been updated as described
 *     above based on the caller's capabilities. The process's capabilities
 *     may also have been adjusted based on the UID transitions.
 *
 * error: EINVAL, User ID not valid in user namespace
 *   desc: The @uid does not have a valid mapping in the caller's user
 *     namespace. This occurs when make_kuid() returns INVALID_UID (internal
 *     value of (uid_t)-1), which is checked by uid_valid(). This typically
 *     happens when running in a user namespace that doesn't have the target
 *     UID mapped, or when the UID value is out of the mapped range. Note
 *     that in the initial user namespace, all 32-bit UID values are valid
 *     except (uid_t)-1.
 *
 * error: ENOMEM, Cannot allocate credentials structure
 *   desc: The kernel failed to allocate memory for the new credentials
 *     structure via prepare_creds(). This function uses kmem_cache_alloc()
 *     with GFP_KERNEL, which can fail under severe memory pressure. The
 *     syscall returns early without modifying any credentials. Also returned
 *     if security_prepare_creds() fails during credential preparation.
 *
 * error: EPERM, Permission denied for UID change
 *   desc: Returned when the caller does not have CAP_SETUID capability and
 *     the requested @uid does not equal either the current real UID or the
 *     current saved set-user-ID. The caller may only set their effective UID
 *     to their real UID or saved set-user-ID without CAP_SETUID. This
 *     implements the unprivileged setuid behavior defined by POSIX.
 *
 * error: EAGAIN, Cannot allocate user structure
 *   desc: Returned when the kernel fails to allocate a new user_struct in
 *     set_user() via alloc_uid(). This occurs when the caller has CAP_SETUID
 *     and the new UID differs from the old real UID, requiring allocation of
 *     a new per-user accounting structure. The alloc_uid() function uses
 *     kmem_cache_zalloc() with GFP_KERNEL. Also can fail if user_epoll_alloc()
 *     fails during user structure initialization. Note that unlike older
 *     kernel versions, RLIMIT_NPROC is not enforced at setuid time.
 *
 * error: EAGAIN, Cannot allocate ucounts structure
 *   desc: Returned when set_cred_ucounts() fails to allocate a new ucounts
 *     structure via alloc_ucounts(). This happens when the new UID differs
 *     from the current UID and the kernel cannot allocate memory for tracking
 *     per-user resource counts. Uses kzalloc() with GFP_KERNEL.
 *
 * error: EACCES, LSM policy denied the operation
 *   desc: A Linux Security Module (such as SafeSetID) denied the user ID
 *     transition via the security_task_fix_setuid() hook. SafeSetID enforces
 *     allowlist-based policies and returns -EACCES when a UID transition is
 *     not explicitly permitted in the policy. When SafeSetID denies the
 *     operation, it also sends SIGKILL to the process to prevent security
 *     vulnerabilities from missing allowlist entries. This error only occurs
 *     when SafeSetID or a similar restrictive LSM is enabled and configured.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process credential user IDs (uid, euid, suid, fsuid)
 *   desc: Updates the calling process's user ID credentials. With CAP_SETUID,
 *     all four user IDs (uid, suid, euid, fsuid) are set to @uid. Without
 *     CAP_SETUID, only euid and fsuid are updated. The credentials are
 *     atomically replaced via RCU in commit_creds().
 *   reversible: Depends on prior state. If setuid was called with CAP_SETUID,
 *     the saved set-user-ID is overwritten, making it impossible to regain
 *     the previous privileges via setuid alone.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process user structure (user_struct)
 *   desc: If the real UID changes (only when caller has CAP_SETUID),
 *     set_user() allocates or finds the user_struct for the new UID, updates
 *     new->user, and releases the reference to the old user_struct via
 *     free_uid(). This affects per-user resource accounting.
 *   condition: Real UID changes to a different value (requires CAP_SETUID)
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process capabilities (cap_permitted, cap_effective, cap_ambient)
 *   desc: The commoncap LSM adjusts capabilities based on UID transitions via
 *     cap_emulate_setxuid(). When dropping from root (any of uid/euid/suid==0)
 *     to non-root (all of uid/euid/suid!=0), capabilities are cleared unless
 *     SECURE_KEEP_CAPS is set. Ambient capabilities are always cleared in this
 *     case. These adjustments implement the traditional Unix behavior where
 *     dropping root loses capabilities.
 *   condition: UID transitions involving root (UID 0) in the user namespace
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process dumpability flag
 *   desc: If the effective UID or filesystem UID changes, the process's
 *     dumpability may be affected. In commit_creds(), if euid or fsuid
 *     differs from the old values (or capabilities are reduced),
 *     set_dumpable() is called with the suid_dumpable sysctl value,
 *     potentially making the process non-dumpable for security reasons.
 *     Also, pdeath_signal is cleared to 0.
 *   condition: Effective UID or filesystem UID changes, or caps reduced
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Keyring state (via key_fsuid_changed)
 *   desc: If the filesystem UID changes, key_fsuid_changed() is called to
 *     update any keyring state that depends on the process's filesystem UID.
 *     This ensures proper key access control after credential changes.
 *   condition: Filesystem UID changes
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process flags (PF_NPROC_EXCEEDED)
 *   desc: The flag_nproc_exceeded() function checks if the new credentials
 *     would exceed RLIMIT_NPROC for the new user. If so, PF_NPROC_EXCEEDED
 *     is set on the current task, deferring the RLIMIT_NPROC enforcement to
 *     execve() time. This ensures that setuid() calls succeed even when over
 *     limit, but subsequent execve() calls will fail with EAGAIN. The flag
 *     is cleared if the limit is not exceeded. This behavior exists because
 *     many programs don't check set*uid() return codes.
 *   condition: New ucounts differ from current and RLIMIT_NPROC exceeded
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_NETWORK
 *   target: Process connector notification (PROC_EVENT_UID)
 *   desc: If any of the user ID fields (uid, euid, suid, fsuid) change,
 *     a PROC_EVENT_UID notification is sent via the process connector
 *     (proc_id_connector). This allows userspace processes monitoring the
 *     connector socket to be notified of credential changes.
 *   condition: Any user ID field changes (CONFIG_PROC_EVENTS enabled)
 *   reversible: no
 *
 * state-trans: credentials
 *   from: original credential state
 *   to: new credential state with updated user IDs
 *   condition: Permission checks pass
 *   desc: The process credentials atomically transition from the old state
 *     to the new state via commit_creds(). The old credentials are released
 *     via put_cred_many(). RCU is used to ensure safe concurrent access to
 *     credentials by other kernel code (via rcu_assign_pointer).
 *
 * capability: CAP_SETUID
 *   type: KAPI_CAP_BYPASS_CHECK | KAPI_CAP_MODIFY_BEHAVIOR
 *   allows: Setting all four user IDs (uid, suid, euid, fsuid) to any valid
 *     UID in the caller's user namespace. Changing the real UID triggers
 *     allocation of a new user_struct for resource accounting.
 *   without: Can only set euid and fsuid to the current real UID or saved
 *     set-user-ID. The real UID and saved set-user-ID remain unchanged.
 *     This is the unprivileged POSIX-compliant behavior.
 *   condition: Checked via ns_capable_setid(old->user_ns, CAP_SETUID) which
 *     verifies the capability in the credentials' user namespace and sets
 *     PF_SUPERPRIV flag on the task if capability is used.
 *
 * constraint: User namespace UID mapping
 *   desc: The @uid parameter must have a valid mapping in the caller's user
 *     namespace. The conversion via make_kuid() must produce a valid kuid_t
 *     (not INVALID_UID). In the initial user namespace, all 32-bit UID values
 *     are valid except (uid_t)-1. In other user namespaces, only UIDs that
 *     have been explicitly mapped via /proc/[pid]/uid_map are valid.
 *   expr: uid_valid(make_kuid(current_user_ns(), uid))
 *
 * constraint: CONFIG_MULTIUSER kernel configuration
 *   desc: This syscall is only available when the kernel is built with
 *     CONFIG_MULTIUSER=y. This option is enabled by default and is required
 *     for multi-user systems. Embedded systems may disable it to save space,
 *     in which case all users are treated as root and this syscall is not
 *     available.
 *
 * examples: setuid(0);  // Become root (requires CAP_SETUID or already root)
 *   setuid(1000);  // Drop to user 1000 (if CAP_SETUID: permanent, else: must match uid or suid)
 *   setuid(getuid());  // Set euid to real uid (always succeeds if valid)
 *   setuid(getsuid());  // Set euid to saved uid (unprivileged allowed)
 *
 * notes: This syscall implements SysV/POSIX semantics, NOT BSD semantics.
 *   The critical difference is that root processes calling setuid() to a
 *   non-zero UID permanently drop all privileges because the saved
 *   set-user-ID is also changed. BSD-style setreuid() preserves the ability
 *   to regain root privileges by leaving suid unchanged.
 *
 *   The syscall number is 105 on x86-64, 23 (16-bit setuid16) and 213
 *   (32-bit setuid32) on i386. The glibc wrapper transparently handles
 *   the kernel version difference.
 *
 *   For programs needing temporary privilege dropping with restoration
 *   capability, use seteuid(2) instead. For full control over all three
 *   user IDs, use setresuid(2).
 *
 *   The man page emphasizes: "it is a grave security error to omit checking
 *   for a failure return from setuid()." Even root can fail this call under
 *   various conditions (memory pressure, LSM denial, namespace issues).
 *
 *   Threading: At the kernel level, UIDs are per-thread. However, POSIX
 *   requires all threads to share credentials. NPTL uses signal-based
 *   techniques (specifically, sending RT signals to all threads) to
 *   synchronize credential changes across threads.
 *
 *   RLIMIT_NPROC is NOT enforced at setuid() time. Instead, PF_NPROC_EXCEEDED
 *   is set and enforcement is deferred to execve(). This was changed because
 *   many programs don't check set*uid() return codes, and immediate failure
 *   could leave processes running with elevated privileges. The commit
 *   c16bdeb5a39ff removed the CAP_SYS_RESOURCE/CAP_SYS_ADMIN bypass for this
 *   check to fix RLIMIT_NPROC enforcement issues.
 *
 * since-version: 1.0
 */
long __sys_setuid(uid_t uid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kuid;

	kuid = make_kuid(ns, uid);
	if (!uid_valid(kuid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (ns_capable_setid(old->user_ns, CAP_SETUID)) {
		new->suid = new->uid = kuid;
		if (!uid_eq(kuid, old->uid)) {
			retval = set_user(new);
			if (retval < 0)
				goto error;
		}
	} else if (!uid_eq(kuid, old->uid) && !uid_eq(kuid, new->suid)) {
		goto error;
	}

	new->fsuid = new->euid = kuid;

	retval = security_task_fix_setuid(new, old, LSM_SETID_ID);
	if (retval < 0)
		goto error;

	retval = set_cred_ucounts(new);
	if (retval < 0)
		goto error;

	flag_nproc_exceeded(new);
	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

SYSCALL_DEFINE1(setuid, uid_t, uid)
{
	return __sys_setuid(uid);
}


/*
 * This function implements a generic ability to update ruid, euid,
 * and suid.  This allows you to implement the 4.4 compatible seteuid().
 */
long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kruid, keuid, ksuid;
	bool ruid_new, euid_new, suid_new;

	kruid = make_kuid(ns, ruid);
	keuid = make_kuid(ns, euid);
	ksuid = make_kuid(ns, suid);

	if ((ruid != (uid_t) -1) && !uid_valid(kruid))
		return -EINVAL;

	if ((euid != (uid_t) -1) && !uid_valid(keuid))
		return -EINVAL;

	if ((suid != (uid_t) -1) && !uid_valid(ksuid))
		return -EINVAL;

	old = current_cred();

	/* check for no-op */
	if ((ruid == (uid_t) -1 || uid_eq(kruid, old->uid)) &&
	    (euid == (uid_t) -1 || (uid_eq(keuid, old->euid) &&
				    uid_eq(keuid, old->fsuid))) &&
	    (suid == (uid_t) -1 || uid_eq(ksuid, old->suid)))
		return 0;

	ruid_new = ruid != (uid_t) -1        && !uid_eq(kruid, old->uid) &&
		   !uid_eq(kruid, old->euid) && !uid_eq(kruid, old->suid);
	euid_new = euid != (uid_t) -1        && !uid_eq(keuid, old->uid) &&
		   !uid_eq(keuid, old->euid) && !uid_eq(keuid, old->suid);
	suid_new = suid != (uid_t) -1        && !uid_eq(ksuid, old->uid) &&
		   !uid_eq(ksuid, old->euid) && !uid_eq(ksuid, old->suid);
	if ((ruid_new || euid_new || suid_new) &&
	    !ns_capable_setid(old->user_ns, CAP_SETUID))
		return -EPERM;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	if (ruid != (uid_t) -1) {
		new->uid = kruid;
		if (!uid_eq(kruid, old->uid)) {
			retval = set_user(new);
			if (retval < 0)
				goto error;
		}
	}
	if (euid != (uid_t) -1)
		new->euid = keuid;
	if (suid != (uid_t) -1)
		new->suid = ksuid;
	new->fsuid = new->euid;

	retval = security_task_fix_setuid(new, old, LSM_SETID_RES);
	if (retval < 0)
		goto error;

	retval = set_cred_ucounts(new);
	if (retval < 0)
		goto error;

	flag_nproc_exceeded(new);
	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

/**
 * sys_setresuid - Set the real, effective, and saved user IDs
 * @ruid: New real user ID, or (uid_t)-1 to leave unchanged
 * @euid: New effective user ID, or (uid_t)-1 to leave unchanged
 * @suid: New saved set-user-ID, or (uid_t)-1 to leave unchanged
 *
 * long-desc: Sets the real, effective, and/or saved set-user-ID of the
 *   calling process. This syscall provides the most flexible and complete
 *   control over user identity credentials, allowing independent control
 *   of all three user IDs. It can be used to implement the 4.4BSD-compatible
 *   seteuid() function.
 *
 *   The special value (uid_t)-1 (0xFFFFFFFF on 32-bit systems) for any
 *   parameter means that the corresponding ID should not be changed. All
 *   three parameters can be -1, in which case the syscall succeeds but
 *   makes no changes.
 *
 *   Permission rules for unprivileged callers (without CAP_SETUID):
 *   - Each specified UID (when not -1) must equal the current real UID,
 *     effective UID, or saved set-user-ID
 *   - This allows swapping between the three existing UIDs or setting any
 *     of them to a value already held
 *
 *   Permission rules for privileged callers (with CAP_SETUID):
 *   - May set any of the three UIDs to any valid UID in the user namespace
 *   - Provides complete control over the process's user identity
 *
 *   Filesystem UID behavior:
 *   - The filesystem UID (fsuid) is always set to the new effective UID value
 *   - This happens regardless of whether euid was explicitly changed
 *   - If euid is -1, fsuid is set to the (unchanged) current euid
 *
 *   No-op optimization:
 *   - The syscall returns immediately with 0 (without allocating credentials
 *     or taking locks) if all of the following are true:
 *     * ruid is -1 OR equals the current real UID
 *     * euid is -1 OR (equals the current effective UID AND equals the
 *       current filesystem UID)
 *     * suid is -1 OR equals the current saved set-user-ID
 *   - This optimization is important for performance when a process calls
 *     setresuid() to verify or maintain its current state
 *
 *   Real UID change effects:
 *   - When the real UID is changed to a different value, set_user() is called
 *     to update the user_struct reference for resource accounting
 *   - This ensures proper tracking of per-user resource limits
 *
 *   Capability side effects:
 *   - When UIDs change, the commoncap LSM adjusts process capabilities via
 *     cap_emulate_setxuid():
 *     * If transitioning from any UID == 0 to all UIDs != 0, and
 *       SECURE_KEEP_CAPS is not set, permitted and effective capabilities
 *       are cleared, along with ambient capabilities
 *     * If transitioning from euid == 0 to euid != 0, effective caps are
 *       cleared
 *     * If transitioning from euid != 0 to euid == 0, effective caps are
 *       set to permitted caps
 *   - These adjustments can be suppressed by setting SECURE_NO_SETUID_FIXUP
 *     in the securebits via prctl(PR_SET_SECUREBITS)
 *
 *   User namespace support:
 *   - All three UID parameters are interpreted in the context of the caller's
 *     user namespace
 *   - They are converted to kernel-internal kuid_t values using make_kuid()
 *   - If a UID has no mapping in the caller's user namespace, it is invalid
 *
 *   This syscall is only available when CONFIG_MULTIUSER is enabled. On
 *   single-user systems (CONFIG_MULTIUSER=n), this syscall is not defined.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: ruid
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be (uid_t)-1 to leave unchanged, OR a valid UID that
 *     the caller has permission to set. For unprivileged callers, must be
 *     the current real UID, effective UID, or saved set-user-ID. For
 *     privileged callers (with CAP_SETUID), may be any UID that has a mapping
 *     in the caller's user namespace.
 *
 * param: euid
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be (uid_t)-1 to leave unchanged, OR a valid UID that
 *     the caller has permission to set. For unprivileged callers, must be
 *     the current real UID, effective UID, or saved set-user-ID. For
 *     privileged callers (with CAP_SETUID), may be any UID that has a mapping
 *     in the caller's user namespace.
 *
 * param: suid
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be (uid_t)-1 to leave unchanged, OR a valid UID that
 *     the caller has permission to set. For unprivileged callers, must be
 *     the current real UID, effective UID, or saved set-user-ID. For
 *     privileged callers (with CAP_SETUID), may be any UID that has a mapping
 *     in the caller's user namespace.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. The user IDs have been updated as specified.
 *     Note that the syscall may return 0 even if no changes were made (when
 *     all parameters are -1 or match current values). The process's
 *     capabilities may also have been adjusted based on the UID transitions.
 *
 * error: EINVAL, User ID not valid in user namespace
 *   desc: One of @ruid, @euid, or @suid (when not -1) does not have a valid
 *     mapping in the caller's user namespace. This occurs when make_kuid()
 *     returns INVALID_UID, which is checked by uid_valid(). This typically
 *     happens when running in a user namespace that doesn't have the target
 *     UID mapped, or when the UID value is out of the mapped range. In the
 *     initial user namespace, all 32-bit UID values are valid except
 *     (uid_t)-1 which is reserved as the "no change" sentinel.
 *
 * error: EPERM, Permission denied for UID change
 *   desc: Returned when the caller does not have permission to set one or
 *     more of the requested UIDs. Specifically, one of the specified UIDs
 *     is not equal to the current real UID, not equal to the current
 *     effective UID, not equal to the current saved set-user-ID, AND the
 *     caller does not have CAP_SETUID capability in the target user
 *     namespace. The check is: if any of (ruid_new || euid_new || suid_new)
 *     is true and the caller lacks CAP_SETUID, EPERM is returned. A UID is
 *     considered "new" if it is specified (!= -1) AND differs from all three
 *     current UIDs (uid, euid, suid).
 *
 * error: ENOMEM, Cannot allocate credentials structure
 *   desc: The kernel failed to allocate memory for the new credentials
 *     structure via prepare_creds(). This function uses kmem_cache_alloc()
 *     with GFP_KERNEL, which can fail under memory pressure. The syscall
 *     returns early without modifying any credentials. Note that this error
 *     only occurs if the syscall passes the no-op check; if all requested
 *     changes match current values, the syscall returns 0 without allocation.
 *
 * error: EAGAIN, Cannot allocate user structure
 *   desc: Returned when the kernel fails to allocate a new user_struct in
 *     set_user() via alloc_uid(). This occurs when the real UID is being
 *     changed to a different value and memory allocation fails. The
 *     alloc_uid() function uses kmem_cache_zalloc() with GFP_KERNEL. It also
 *     allocates an eventpoll structure for the user via user_epoll_alloc().
 *     Unlike older kernel versions, RLIMIT_NPROC is not checked at setresuid
 *     time; instead, the PF_NPROC_EXCEEDED flag is set and checked at
 *     execve() time.
 *
 * error: EAGAIN, Cannot allocate ucounts structure
 *   desc: Returned when set_cred_ucounts() fails to allocate a new ucounts
 *     structure via alloc_ucounts(). This happens when changing to a
 *     different UID and the kernel cannot allocate memory for tracking
 *     per-user resource counts. Uses kzalloc() with GFP_KERNEL. This error
 *     is distinct from the user_struct allocation failure but returns the
 *     same error code.
 *
 * error: EACCES, LSM policy denied the operation
 *   desc: A Linux Security Module (such as SafeSetID) denied the user ID
 *     transition via the security_task_fix_setuid() hook. SafeSetID enforces
 *     allowlist-based policies and returns -EACCES when a transition is not
 *     explicitly permitted. When SafeSetID denies the operation, it also
 *     sends SIGKILL to the process to prevent security vulnerabilities from
 *     missing allowlist entries. This error is only possible when the
 *     SafeSetID LSM is enabled and has a policy for the calling process's
 *     current real UID.
 *
 * lock: uidhash_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The uid hash table spinlock is acquired (with IRQs disabled) in
 *     alloc_uid() when changing the real UID to a different value. This lock
 *     protects the global UID hash table used for user_struct lookups. It is
 *     briefly held during hash table lookup and insertion, then released
 *     before the function returns.
 *
 * lock: ucounts_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The ucounts spinlock is acquired (with IRQs disabled) in
 *     alloc_ucounts() when setting up per-user resource counting for the new
 *     credentials. This lock protects the global ucounts hash table. It is
 *     briefly held during hash table lookup and insertion.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process credential user IDs (uid, euid, suid, fsuid)
 *   desc: Updates the calling process's user ID credentials according to
 *     the parameters. The real UID is set if @ruid != -1. The effective UID
 *     is set if @euid != -1. The saved set-user-ID is set if @suid != -1.
 *     The filesystem UID is always set to the (possibly new) effective UID
 *     value, even if euid was specified as -1.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process user structure (user_struct)
 *   desc: If the real UID changes to a different value, set_user() allocates
 *     or finds the user_struct for the new UID, updates new->user, and
 *     releases the reference to the old user_struct via free_uid(). This
 *     affects per-user resource accounting including the RLIMIT_NPROC
 *     process count.
 *   condition: Real UID changes to a different value (ruid != -1 and
 *     ruid != current uid)
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process capabilities
 *   desc: The commoncap LSM module adjusts process capabilities when UIDs
 *     change via cap_emulate_setxuid(). If transitioning from any UID == 0
 *     to all UIDs != 0 (and SECURE_KEEP_CAPS is not set), permitted,
 *     effective, and ambient capabilities are cleared. If euid transitions
 *     from 0 to non-0, effective caps are cleared. If euid transitions from
 *     non-0 to 0, effective caps are set to permitted caps. This is the
 *     traditional Unix behavior for capability handling during setuid
 *     transitions.
 *   condition: UID transitions involving root (UID 0) in the user namespace
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process dumpability flag
 *   desc: If the effective UID or filesystem UID changes, the process's
 *     dumpability may be affected. In commit_creds(), if euid or fsuid
 *     differs from the old values (or capabilities are reduced),
 *     set_dumpable() is called with the suid_dumpable sysctl value,
 *     potentially making the process non-dumpable for security reasons.
 *     The pdeath_signal field is also cleared to 0.
 *   condition: Effective UID or filesystem UID changes, or caps reduced
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Keyring state (via key_fsuid_changed)
 *   desc: If the filesystem UID changes, key_fsuid_changed() is called to
 *     update any keyring state that depends on the process's filesystem UID.
 *     This ensures proper key access control after credential changes.
 *   condition: Filesystem UID changes (since fsuid is always set to new euid,
 *     this happens whenever euid changes or fsuid differs from new euid)
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process flags (PF_NPROC_EXCEEDED)
 *   desc: The flag_nproc_exceeded() function checks if the new credentials
 *     would exceed RLIMIT_NPROC for the new user. If so, PF_NPROC_EXCEEDED
 *     is set on the current task, deferring the RLIMIT_NPROC enforcement to
 *     execve() time. This ensures that setresuid() calls succeed even when
 *     over limit, but subsequent execve() calls will fail with EAGAIN. The
 *     flag is cleared if the limit is not exceeded. This behavior exists
 *     because many programs don't check set*uid() return codes.
 *   condition: New ucounts differ from current and RLIMIT_NPROC exceeded
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_NETWORK
 *   target: Process connector notification (PROC_EVENT_UID)
 *   desc: If any of the user ID fields (uid, euid, suid, fsuid) change,
 *     a PROC_EVENT_UID notification is sent via the process connector
 *     (proc_id_connector). This allows userspace processes monitoring the
 *     connector socket to be notified of credential changes.
 *   condition: Any user ID field changes (CONFIG_PROC_EVENTS enabled)
 *   reversible: no
 *
 * state-trans: credentials
 *   from: original credential state
 *   to: new credential state with updated user IDs
 *   condition: Permission checks pass and at least one UID changes
 *   desc: The process credentials atomically transition from the old state
 *     to the new state via commit_creds(). The old credentials are released
 *     via put_cred_many(). RCU is used (via rcu_assign_pointer) to ensure
 *     safe concurrent access to credentials by other kernel code.
 *
 * capability: CAP_SETUID
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Setting any or all of the three user IDs (real, effective, saved)
 *     to any valid UID in the caller's user namespace. This provides complete
 *     control over the process's user identity. When the real UID changes,
 *     this triggers allocation of a new user_struct for resource accounting.
 *   without: Can only set each UID to a value already held as the current
 *     real UID, effective UID, or saved set-user-ID. Any attempt to set a
 *     UID to a "new" value (one not matching any of the three current UIDs)
 *     will fail with EPERM.
 *   condition: Checked via ns_capable_setid(old->user_ns, CAP_SETUID) which
 *     verifies the capability in the credentials' user namespace and sets
 *     PF_SUPERPRIV flag on the task if capability is used.
 *
 * constraint: User namespace UID mapping
 *   desc: Each of @ruid, @euid, and @suid (when not -1) must have a valid
 *     mapping in the caller's user namespace. The conversion via make_kuid()
 *     must produce a valid kuid_t (not INVALID_UID). In the initial user
 *     namespace, all 32-bit UID values are valid except (uid_t)-1. In other
 *     user namespaces, only UIDs that have been explicitly mapped via
 *     /proc/[pid]/uid_map are valid.
 *   expr: uid_valid(make_kuid(current_user_ns(), uid)) for each uid != -1
 *
 * constraint: CONFIG_MULTIUSER kernel configuration
 *   desc: This syscall is only available when the kernel is built with
 *     CONFIG_MULTIUSER=y. This option is enabled by default and is required
 *     for multi-user systems. Embedded systems may disable it to save space,
 *     in which case all users are treated as root and this syscall is not
 *     available.
 *
 * examples: setresuid(-1, -1, -1);  // No change (always succeeds)
 *   setresuid(0, 0, 0);  // Become root completely (requires CAP_SETUID)
 *   setresuid(-1, 0, -1);  // Set only effective UID to root
 *   setresuid(-1, getuid(), -1);  // Set effective UID to real UID
 *   setresuid(1000, 1000, 1000);  // Drop all privileges to user 1000
 *   setresuid(-1, 1000, -1);  // Temporarily drop privileges (can restore via saved UID)
 *   setresuid(getuid(), getuid(), getuid());  // Ensure all UIDs match real UID
 *
 * notes: This syscall provides more control than setreuid(2) or setuid(2).
 *   Unlike setreuid(), it allows explicitly setting the saved set-user-ID
 *   independently. Unlike setuid(), privileged processes can set the three
 *   UIDs to different values.
 *
 *   This syscall originated in Linux 2.1.44 and is also available in HP-UX
 *   and FreeBSD (since 4.2). It is NOT part of any POSIX standard, though
 *   POSIX.1-2001 describes a similar interface.
 *
 *   The syscall number is 117 on x86-64, 164 (16-bit setresuid16) and 208
 *   (32-bit setresuid32) on i386, and 147 in the generic syscall table.
 *
 *   The man page emphasizes: "it is a grave security error to omit checking
 *   for a failure return from setresuid()." Even root can fail this call
 *   under various conditions (memory pressure, LSM denial, namespace issues).
 *
 *   Unlike older kernels, RLIMIT_NPROC is not enforced at setresuid() time.
 *   Instead, the PF_NPROC_EXCEEDED flag is set and enforcement is deferred
 *   to execve(). This change was made because many programs don't check
 *   set*uid() return codes, and immediate failure could leave processes
 *   running with elevated privileges.
 *
 *   Threading: At the kernel level, UIDs are per-thread. However, POSIX
 *   requires all threads to share credentials. NPTL uses signal-based
 *   techniques (specifically, sending RT signals to all threads) to
 *   synchronize credential changes across threads. The glibc wrapper handles
 *   this synchronization transparently.
 *
 *   The SafeSetID LSM module can enforce additional restrictions on UID
 *   transitions based on a configured allowlist policy. If a transition is
 *   denied by SafeSetID, the process receives SIGKILL in addition to the
 *   EACCES return value.
 *
 * since-version: 2.1.44
 */
SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
{
	return __sys_setresuid(ruid, euid, suid);
}

/**
 * sys_getresuid - Get the real, effective, and saved user IDs
 * @ruidp: Pointer to store the real user ID
 * @euidp: Pointer to store the effective user ID
 * @suidp: Pointer to store the saved set-user-ID
 *
 * long-desc: Retrieves the real user ID, effective user ID, and saved
 *   set-user-ID of the calling process, storing them in the locations
 *   pointed to by @ruidp, @euidp, and @suidp respectively. The UIDs are
 *   translated from the kernel's internal representation to the caller's
 *   user namespace. This syscall is the counterpart to setresuid(2).
 *
 *   The real UID identifies the user who owns the process and is used for
 *   resource accounting. The effective UID determines the process's access
 *   permissions and is used for most permission checks. The saved set-user-ID
 *   allows a set-user-ID program to temporarily drop privileges and later
 *   regain them.
 *
 *   If a UID has no mapping in the caller's user namespace (which can happen
 *   when a process enters a user namespace where its UIDs are not mapped),
 *   the overflow UID (typically 65534, configured via /proc/sys/kernel/overflowuid)
 *   is returned instead. This "munging" ensures the syscall never fails due
 *   to unmapped UIDs.
 *
 * context-flags: KAPI_CTX_PROCESS
 *
 * param: ruidp
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Must be a valid user-space pointer to a uid_t (4 bytes). Cannot
 *     be NULL. The memory must be writable by the calling process.
 *
 * param: euidp
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Must be a valid user-space pointer to a uid_t (4 bytes). Cannot
 *     be NULL. The memory must be writable by the calling process.
 *
 * param: suidp
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Must be a valid user-space pointer to a uid_t (4 bytes). Cannot
 *     be NULL. The memory must be writable by the calling process.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. The real, effective, and saved UIDs are written
 *     to the locations pointed to by @ruidp, @euidp, and @suidp respectively.
 *
 * error: EFAULT, Invalid user-space pointer
 *   desc: One of @ruidp, @euidp, or @suidp points to an address outside the
 *     process's accessible address space, or the memory is not writable. The
 *     pointers are validated sequentially (ruidp first, then euidp, then suidp),
 *     so if EFAULT is returned, some values may have been written while others
 *     were not. Specifically, if @euidp fails, @ruidp has already been written;
 *     if @suidp fails, both @ruidp and @euidp have been written.
 *
 * examples: uid_t ruid, euid, suid;
 *   getresuid(&ruid, &euid, &suid);  // Retrieve all three UIDs
 *   if (euid != ruid) { ... }  // Running with elevated privileges
 *   if (suid == 0) { ... }  // Can regain root privileges via setresuid
 *
 * notes: This syscall requires no special capabilities; any process can read
 *   its own user IDs.
 *
 *   The syscall originated in Linux 2.1.44 and is also available on HP-UX
 *   and FreeBSD (since 4.2). It is NOT part of any POSIX standard.
 *
 *   The syscall number is 118 on x86-64, 165 (16-bit getresuid16) and 209
 *   (32-bit getresuid32) on i386, and 148 in the generic syscall table.
 *
 *   On 32-bit platforms with 16-bit UID support (CONFIG_UID16), a separate
 *   getresuid16 syscall exists. UIDs larger than 65535 are truncated to the
 *   overflow UID (65534) by the high2lowuid() macro.
 *
 *   This syscall does not acquire any locks. The credentials are accessed via
 *   current_cred() which uses RCU-protected access to the current task
 *   credentials. Since a task can only modify its own credentials (via
 *   set*uid syscalls), this access is inherently safe without additional
 *   synchronization.
 *
 *   Unlike setresuid(2), this syscall has no interaction with LSM modules,
 *   capability checks, or user namespace restrictions (beyond UID mapping).
 *
 *   Threading: At the kernel level, UIDs are per-thread. However, POSIX
 *   requires all threads to share credentials. The glibc wrapper for
 *   setresuid(2) uses signal-based synchronization to ensure all threads
 *   see consistent credentials. Since getresuid only reads, no such
 *   synchronization is needed for this syscall.
 *
 * since-version: 2.1.44
 */
SYSCALL_DEFINE3(getresuid, uid_t __user *, ruidp, uid_t __user *, euidp, uid_t __user *, suidp)
{
	const struct cred *cred = current_cred();
	int retval;
	uid_t ruid, euid, suid;

	ruid = from_kuid_munged(cred->user_ns, cred->uid);
	euid = from_kuid_munged(cred->user_ns, cred->euid);
	suid = from_kuid_munged(cred->user_ns, cred->suid);

	retval = put_user(ruid, ruidp);
	if (!retval) {
		retval = put_user(euid, euidp);
		if (!retval)
			return put_user(suid, suidp);
	}
	return retval;
}

/*
 * Same as above, but for rgid, egid, sgid.
 */
long __sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kgid_t krgid, kegid, ksgid;
	bool rgid_new, egid_new, sgid_new;

	krgid = make_kgid(ns, rgid);
	kegid = make_kgid(ns, egid);
	ksgid = make_kgid(ns, sgid);

	if ((rgid != (gid_t) -1) && !gid_valid(krgid))
		return -EINVAL;
	if ((egid != (gid_t) -1) && !gid_valid(kegid))
		return -EINVAL;
	if ((sgid != (gid_t) -1) && !gid_valid(ksgid))
		return -EINVAL;

	old = current_cred();

	/* check for no-op */
	if ((rgid == (gid_t) -1 || gid_eq(krgid, old->gid)) &&
	    (egid == (gid_t) -1 || (gid_eq(kegid, old->egid) &&
				    gid_eq(kegid, old->fsgid))) &&
	    (sgid == (gid_t) -1 || gid_eq(ksgid, old->sgid)))
		return 0;

	rgid_new = rgid != (gid_t) -1        && !gid_eq(krgid, old->gid) &&
		   !gid_eq(krgid, old->egid) && !gid_eq(krgid, old->sgid);
	egid_new = egid != (gid_t) -1        && !gid_eq(kegid, old->gid) &&
		   !gid_eq(kegid, old->egid) && !gid_eq(kegid, old->sgid);
	sgid_new = sgid != (gid_t) -1        && !gid_eq(ksgid, old->gid) &&
		   !gid_eq(ksgid, old->egid) && !gid_eq(ksgid, old->sgid);
	if ((rgid_new || egid_new || sgid_new) &&
	    !ns_capable_setid(old->user_ns, CAP_SETGID))
		return -EPERM;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	if (rgid != (gid_t) -1)
		new->gid = krgid;
	if (egid != (gid_t) -1)
		new->egid = kegid;
	if (sgid != (gid_t) -1)
		new->sgid = ksgid;
	new->fsgid = new->egid;

	retval = security_task_fix_setgid(new, old, LSM_SETID_RES);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

SYSCALL_DEFINE3(setresgid, gid_t, rgid, gid_t, egid, gid_t, sgid)
{
	return __sys_setresgid(rgid, egid, sgid);
}

SYSCALL_DEFINE3(getresgid, gid_t __user *, rgidp, gid_t __user *, egidp, gid_t __user *, sgidp)
{
	const struct cred *cred = current_cred();
	int retval;
	gid_t rgid, egid, sgid;

	rgid = from_kgid_munged(cred->user_ns, cred->gid);
	egid = from_kgid_munged(cred->user_ns, cred->egid);
	sgid = from_kgid_munged(cred->user_ns, cred->sgid);

	retval = put_user(rgid, rgidp);
	if (!retval) {
		retval = put_user(egid, egidp);
		if (!retval)
			retval = put_user(sgid, sgidp);
	}

	return retval;
}


/*
 * "setfsuid()" sets the fsuid - the uid used for filesystem checks. This
 * is used for "access()" and for the NFS daemon (letting nfsd stay at
 * whatever uid it wants to). It normally shadows "euid", except when
 * explicitly set by setfsuid() or for access..
 */
long __sys_setfsuid(uid_t uid)
{
	const struct cred *old;
	struct cred *new;
	uid_t old_fsuid;
	kuid_t kuid;

	old = current_cred();
	old_fsuid = from_kuid_munged(old->user_ns, old->fsuid);

	kuid = make_kuid(old->user_ns, uid);
	if (!uid_valid(kuid))
		return old_fsuid;

	new = prepare_creds();
	if (!new)
		return old_fsuid;

	if (uid_eq(kuid, old->uid)  || uid_eq(kuid, old->euid)  ||
	    uid_eq(kuid, old->suid) || uid_eq(kuid, old->fsuid) ||
	    ns_capable_setid(old->user_ns, CAP_SETUID)) {
		if (!uid_eq(kuid, old->fsuid)) {
			new->fsuid = kuid;
			if (security_task_fix_setuid(new, old, LSM_SETID_FS) == 0)
				goto change_okay;
		}
	}

	abort_creds(new);
	return old_fsuid;

change_okay:
	commit_creds(new);
	return old_fsuid;
}

SYSCALL_DEFINE1(setfsuid, uid_t, uid)
{
	return __sys_setfsuid(uid);
}

/*
 * Samma på svenska..
 */
long __sys_setfsgid(gid_t gid)
{
	const struct cred *old;
	struct cred *new;
	gid_t old_fsgid;
	kgid_t kgid;

	old = current_cred();
	old_fsgid = from_kgid_munged(old->user_ns, old->fsgid);

	kgid = make_kgid(old->user_ns, gid);
	if (!gid_valid(kgid))
		return old_fsgid;

	new = prepare_creds();
	if (!new)
		return old_fsgid;

	if (gid_eq(kgid, old->gid)  || gid_eq(kgid, old->egid)  ||
	    gid_eq(kgid, old->sgid) || gid_eq(kgid, old->fsgid) ||
	    ns_capable_setid(old->user_ns, CAP_SETGID)) {
		if (!gid_eq(kgid, old->fsgid)) {
			new->fsgid = kgid;
			if (security_task_fix_setgid(new,old,LSM_SETID_FS) == 0)
				goto change_okay;
		}
	}

	abort_creds(new);
	return old_fsgid;

change_okay:
	commit_creds(new);
	return old_fsgid;
}

SYSCALL_DEFINE1(setfsgid, gid_t, gid)
{
	return __sys_setfsgid(gid);
}
#endif /* CONFIG_MULTIUSER */

/**
 * sys_getpid - return the thread group id of the current process
 *
 * Note, despite the name, this returns the tgid not the pid.  The tgid and
 * the pid are identical unless CLONE_THREAD was specified on clone() in
 * which case the tgid is the same in all threads of the same group.
 *
 * This is SMP safe as current->tgid does not change.
 */
SYSCALL_DEFINE0(getpid)
{
	return task_tgid_vnr(current);
}

/* Thread ID - the internal kernel "pid" */
SYSCALL_DEFINE0(gettid)
{
	return task_pid_vnr(current);
}

/*
 * Accessing ->real_parent is not SMP-safe, it could
 * change from under us. However, we can use a stale
 * value of ->real_parent under rcu_read_lock(), see
 * release_task()->call_rcu(delayed_put_task_struct).
 */
SYSCALL_DEFINE0(getppid)
{
	int pid;

	rcu_read_lock();
	pid = task_tgid_vnr(rcu_dereference(current->real_parent));
	rcu_read_unlock();

	return pid;
}

SYSCALL_DEFINE0(getuid)
{
	/* Only we change this so SMP safe */
	return from_kuid_munged(current_user_ns(), current_uid());
}

SYSCALL_DEFINE0(geteuid)
{
	/* Only we change this so SMP safe */
	return from_kuid_munged(current_user_ns(), current_euid());
}

SYSCALL_DEFINE0(getgid)
{
	/* Only we change this so SMP safe */
	return from_kgid_munged(current_user_ns(), current_gid());
}

SYSCALL_DEFINE0(getegid)
{
	/* Only we change this so SMP safe */
	return from_kgid_munged(current_user_ns(), current_egid());
}

static void do_sys_times(struct tms *tms)
{
	u64 tgutime, tgstime, cutime, cstime;

	thread_group_cputime_adjusted(current, &tgutime, &tgstime);
	cutime = current->signal->cutime;
	cstime = current->signal->cstime;
	tms->tms_utime = nsec_to_clock_t(tgutime);
	tms->tms_stime = nsec_to_clock_t(tgstime);
	tms->tms_cutime = nsec_to_clock_t(cutime);
	tms->tms_cstime = nsec_to_clock_t(cstime);
}

SYSCALL_DEFINE1(times, struct tms __user *, tbuf)
{
	if (tbuf) {
		struct tms tmp;

		do_sys_times(&tmp);
		if (copy_to_user(tbuf, &tmp, sizeof(struct tms)))
			return -EFAULT;
	}
	force_successful_syscall_return();
	return (long) jiffies_64_to_clock_t(get_jiffies_64());
}

#ifdef CONFIG_COMPAT
static compat_clock_t clock_t_to_compat_clock_t(clock_t x)
{
	return compat_jiffies_to_clock_t(clock_t_to_jiffies(x));
}

COMPAT_SYSCALL_DEFINE1(times, struct compat_tms __user *, tbuf)
{
	if (tbuf) {
		struct tms tms;
		struct compat_tms tmp;

		do_sys_times(&tms);
		/* Convert our struct tms to the compat version. */
		tmp.tms_utime = clock_t_to_compat_clock_t(tms.tms_utime);
		tmp.tms_stime = clock_t_to_compat_clock_t(tms.tms_stime);
		tmp.tms_cutime = clock_t_to_compat_clock_t(tms.tms_cutime);
		tmp.tms_cstime = clock_t_to_compat_clock_t(tms.tms_cstime);
		if (copy_to_user(tbuf, &tmp, sizeof(tmp)))
			return -EFAULT;
	}
	force_successful_syscall_return();
	return compat_jiffies_to_clock_t(jiffies);
}
#endif

/*
 * This needs some heavy checking ...
 * I just haven't the stomach for it. I also don't fully
 * understand sessions/pgrp etc. Let somebody who does explain it.
 *
 * OK, I think I have the protection semantics right.... this is really
 * only important on a multi-user system anyway, to make sure one user
 * can't send a signal to a process owned by another.  -TYT, 12/12/91
 *
 * !PF_FORKNOEXEC check to conform completely to POSIX.
 */
SYSCALL_DEFINE2(setpgid, pid_t, pid, pid_t, pgid)
{
	struct task_struct *p;
	struct task_struct *group_leader = current->group_leader;
	struct pid *pids[PIDTYPE_MAX] = { 0 };
	struct pid *pgrp;
	int err;

	if (!pid)
		pid = task_pid_vnr(group_leader);
	if (!pgid)
		pgid = pid;
	if (pgid < 0)
		return -EINVAL;
	rcu_read_lock();

	/* From this point forward we keep holding onto the tasklist lock
	 * so that our parent does not change from under us. -DaveM
	 */
	write_lock_irq(&tasklist_lock);

	err = -ESRCH;
	p = find_task_by_vpid(pid);
	if (!p)
		goto out;

	err = -EINVAL;
	if (!thread_group_leader(p))
		goto out;

	if (same_thread_group(p->real_parent, group_leader)) {
		err = -EPERM;
		if (task_session(p) != task_session(group_leader))
			goto out;
		err = -EACCES;
		if (!(p->flags & PF_FORKNOEXEC))
			goto out;
	} else {
		err = -ESRCH;
		if (p != group_leader)
			goto out;
	}

	err = -EPERM;
	if (p->signal->leader)
		goto out;

	pgrp = task_pid(p);
	if (pgid != pid) {
		struct task_struct *g;

		pgrp = find_vpid(pgid);
		g = pid_task(pgrp, PIDTYPE_PGID);
		if (!g || task_session(g) != task_session(group_leader))
			goto out;
	}

	err = security_task_setpgid(p, pgid);
	if (err)
		goto out;

	if (task_pgrp(p) != pgrp)
		change_pid(pids, p, PIDTYPE_PGID, pgrp);

	err = 0;
out:
	/* All paths lead to here, thus we are safe. -DaveM */
	write_unlock_irq(&tasklist_lock);
	rcu_read_unlock();
	free_pids(pids);
	return err;
}

static int do_getpgid(pid_t pid)
{
	struct task_struct *p;
	struct pid *grp;
	int retval;

	rcu_read_lock();
	if (!pid)
		grp = task_pgrp(current);
	else {
		retval = -ESRCH;
		p = find_task_by_vpid(pid);
		if (!p)
			goto out;
		grp = task_pgrp(p);
		if (!grp)
			goto out;

		retval = security_task_getpgid(p);
		if (retval)
			goto out;
	}
	retval = pid_vnr(grp);
out:
	rcu_read_unlock();
	return retval;
}

SYSCALL_DEFINE1(getpgid, pid_t, pid)
{
	return do_getpgid(pid);
}

#ifdef __ARCH_WANT_SYS_GETPGRP

SYSCALL_DEFINE0(getpgrp)
{
	return do_getpgid(0);
}

#endif

SYSCALL_DEFINE1(getsid, pid_t, pid)
{
	struct task_struct *p;
	struct pid *sid;
	int retval;

	rcu_read_lock();
	if (!pid)
		sid = task_session(current);
	else {
		retval = -ESRCH;
		p = find_task_by_vpid(pid);
		if (!p)
			goto out;
		sid = task_session(p);
		if (!sid)
			goto out;

		retval = security_task_getsid(p);
		if (retval)
			goto out;
	}
	retval = pid_vnr(sid);
out:
	rcu_read_unlock();
	return retval;
}

static void set_special_pids(struct pid **pids, struct pid *pid)
{
	struct task_struct *curr = current->group_leader;

	if (task_session(curr) != pid)
		change_pid(pids, curr, PIDTYPE_SID, pid);

	if (task_pgrp(curr) != pid)
		change_pid(pids, curr, PIDTYPE_PGID, pid);
}

int ksys_setsid(void)
{
	struct task_struct *group_leader = current->group_leader;
	struct pid *sid = task_pid(group_leader);
	struct pid *pids[PIDTYPE_MAX] = { 0 };
	pid_t session = pid_vnr(sid);
	int err = -EPERM;

	write_lock_irq(&tasklist_lock);
	/* Fail if I am already a session leader */
	if (group_leader->signal->leader)
		goto out;

	/* Fail if a process group id already exists that equals the
	 * proposed session id.
	 */
	if (pid_task(sid, PIDTYPE_PGID))
		goto out;

	group_leader->signal->leader = 1;
	set_special_pids(pids, sid);

	proc_clear_tty(group_leader);

	err = session;
out:
	write_unlock_irq(&tasklist_lock);
	free_pids(pids);
	if (err > 0) {
		proc_sid_connector(group_leader);
		sched_autogroup_create_attach(group_leader);
	}
	return err;
}

SYSCALL_DEFINE0(setsid)
{
	return ksys_setsid();
}

DECLARE_RWSEM(uts_sem);

#ifdef COMPAT_UTS_MACHINE
#define override_architecture(name) \
	(personality(current->personality) == PER_LINUX32 && \
	 copy_to_user(name->machine, COMPAT_UTS_MACHINE, \
		      sizeof(COMPAT_UTS_MACHINE)))
#else
#define override_architecture(name)	0
#endif

/*
 * Work around broken programs that cannot handle "Linux 3.0".
 * Instead we map 3.x to 2.6.40+x, so e.g. 3.0 would be 2.6.40
 * And we map 4.x and later versions to 2.6.60+x, so 4.0/5.0/6.0/... would be
 * 2.6.60.
 */
static int override_release(char __user *release, size_t len)
{
	int ret = 0;

	if (current->personality & UNAME26) {
		const char *rest = UTS_RELEASE;
		char buf[65] = { 0 };
		int ndots = 0;
		unsigned v;
		size_t copy;

		while (*rest) {
			if (*rest == '.' && ++ndots >= 3)
				break;
			if (!isdigit(*rest) && *rest != '.')
				break;
			rest++;
		}
		v = LINUX_VERSION_PATCHLEVEL + 60;
		copy = clamp_t(size_t, len, 1, sizeof(buf));
		copy = scnprintf(buf, copy, "2.6.%u%s", v, rest);
		ret = copy_to_user(release, buf, copy + 1);
	}
	return ret;
}

SYSCALL_DEFINE1(newuname, struct new_utsname __user *, name)
{
	struct new_utsname tmp;

	down_read(&uts_sem);
	memcpy(&tmp, utsname(), sizeof(tmp));
	up_read(&uts_sem);
	if (copy_to_user(name, &tmp, sizeof(tmp)))
		return -EFAULT;

	if (override_release(name->release, sizeof(name->release)))
		return -EFAULT;
	if (override_architecture(name))
		return -EFAULT;
	return 0;
}

#ifdef __ARCH_WANT_SYS_OLD_UNAME
/*
 * Old cruft
 */
SYSCALL_DEFINE1(uname, struct old_utsname __user *, name)
{
	struct old_utsname tmp;

	if (!name)
		return -EFAULT;

	down_read(&uts_sem);
	memcpy(&tmp, utsname(), sizeof(tmp));
	up_read(&uts_sem);
	if (copy_to_user(name, &tmp, sizeof(tmp)))
		return -EFAULT;

	if (override_release(name->release, sizeof(name->release)))
		return -EFAULT;
	if (override_architecture(name))
		return -EFAULT;
	return 0;
}

SYSCALL_DEFINE1(olduname, struct oldold_utsname __user *, name)
{
	struct oldold_utsname tmp;

	if (!name)
		return -EFAULT;

	memset(&tmp, 0, sizeof(tmp));

	down_read(&uts_sem);
	memcpy(&tmp.sysname, &utsname()->sysname, __OLD_UTS_LEN);
	memcpy(&tmp.nodename, &utsname()->nodename, __OLD_UTS_LEN);
	memcpy(&tmp.release, &utsname()->release, __OLD_UTS_LEN);
	memcpy(&tmp.version, &utsname()->version, __OLD_UTS_LEN);
	memcpy(&tmp.machine, &utsname()->machine, __OLD_UTS_LEN);
	up_read(&uts_sem);
	if (copy_to_user(name, &tmp, sizeof(tmp)))
		return -EFAULT;

	if (override_architecture(name))
		return -EFAULT;
	if (override_release(name->release, sizeof(name->release)))
		return -EFAULT;
	return 0;
}
#endif

SYSCALL_DEFINE2(sethostname, char __user *, name, int, len)
{
	int errno;
	char tmp[__NEW_UTS_LEN];

	if (!ns_capable(current->nsproxy->uts_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	if (len < 0 || len > __NEW_UTS_LEN)
		return -EINVAL;
	errno = -EFAULT;
	if (!copy_from_user(tmp, name, len)) {
		struct new_utsname *u;

		add_device_randomness(tmp, len);
		down_write(&uts_sem);
		u = utsname();
		memcpy(u->nodename, tmp, len);
		memset(u->nodename + len, 0, sizeof(u->nodename) - len);
		errno = 0;
		uts_proc_notify(UTS_PROC_HOSTNAME);
		up_write(&uts_sem);
	}
	return errno;
}

#ifdef __ARCH_WANT_SYS_GETHOSTNAME

SYSCALL_DEFINE2(gethostname, char __user *, name, int, len)
{
	int i;
	struct new_utsname *u;
	char tmp[__NEW_UTS_LEN + 1];

	if (len < 0)
		return -EINVAL;
	down_read(&uts_sem);
	u = utsname();
	i = 1 + strlen(u->nodename);
	if (i > len)
		i = len;
	memcpy(tmp, u->nodename, i);
	up_read(&uts_sem);
	if (copy_to_user(name, tmp, i))
		return -EFAULT;
	return 0;
}

#endif

/*
 * Only setdomainname; getdomainname can be implemented by calling
 * uname()
 */
SYSCALL_DEFINE2(setdomainname, char __user *, name, int, len)
{
	int errno;
	char tmp[__NEW_UTS_LEN];

	if (!ns_capable(current->nsproxy->uts_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (len < 0 || len > __NEW_UTS_LEN)
		return -EINVAL;

	errno = -EFAULT;
	if (!copy_from_user(tmp, name, len)) {
		struct new_utsname *u;

		add_device_randomness(tmp, len);
		down_write(&uts_sem);
		u = utsname();
		memcpy(u->domainname, tmp, len);
		memset(u->domainname + len, 0, sizeof(u->domainname) - len);
		errno = 0;
		uts_proc_notify(UTS_PROC_DOMAINNAME);
		up_write(&uts_sem);
	}
	return errno;
}

/* make sure you are allowed to change @tsk limits before calling this */
static int do_prlimit(struct task_struct *tsk, unsigned int resource,
		      struct rlimit *new_rlim, struct rlimit *old_rlim)
{
	struct rlimit *rlim;
	int retval = 0;

	if (resource >= RLIM_NLIMITS)
		return -EINVAL;
	resource = array_index_nospec(resource, RLIM_NLIMITS);

	if (new_rlim) {
		if (new_rlim->rlim_cur > new_rlim->rlim_max)
			return -EINVAL;
		if (resource == RLIMIT_NOFILE &&
				new_rlim->rlim_max > sysctl_nr_open)
			return -EPERM;
	}

	/* Holding a refcount on tsk protects tsk->signal from disappearing. */
	rlim = tsk->signal->rlim + resource;
	task_lock(tsk->group_leader);
	if (new_rlim) {
		/*
		 * Keep the capable check against init_user_ns until cgroups can
		 * contain all limits.
		 */
		if (new_rlim->rlim_max > rlim->rlim_max &&
				!capable(CAP_SYS_RESOURCE))
			retval = -EPERM;
		if (!retval)
			retval = security_task_setrlimit(tsk, resource, new_rlim);
	}
	if (!retval) {
		if (old_rlim)
			*old_rlim = *rlim;
		if (new_rlim)
			*rlim = *new_rlim;
	}
	task_unlock(tsk->group_leader);

	/*
	 * RLIMIT_CPU handling. Arm the posix CPU timer if the limit is not
	 * infinite. In case of RLIM_INFINITY the posix CPU timer code
	 * ignores the rlimit.
	 */
	if (!retval && new_rlim && resource == RLIMIT_CPU &&
	    new_rlim->rlim_cur != RLIM_INFINITY &&
	    IS_ENABLED(CONFIG_POSIX_TIMERS)) {
		/*
		 * update_rlimit_cpu can fail if the task is exiting, but there
		 * may be other tasks in the thread group that are not exiting,
		 * and they need their cpu timers adjusted.
		 *
		 * The group_leader is the last task to be released, so if we
		 * cannot update_rlimit_cpu on it, then the entire process is
		 * exiting and we do not need to update at all.
		 */
		update_rlimit_cpu(tsk->group_leader, new_rlim->rlim_cur);
	}

	return retval;
}

SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit value;
	int ret;

	ret = do_prlimit(current, resource, NULL, &value);
	if (!ret)
		ret = copy_to_user(rlim, &value, sizeof(*rlim)) ? -EFAULT : 0;

	return ret;
}

#ifdef CONFIG_COMPAT

COMPAT_SYSCALL_DEFINE2(setrlimit, unsigned int, resource,
		       struct compat_rlimit __user *, rlim)
{
	struct rlimit r;
	struct compat_rlimit r32;

	if (copy_from_user(&r32, rlim, sizeof(struct compat_rlimit)))
		return -EFAULT;

	if (r32.rlim_cur == COMPAT_RLIM_INFINITY)
		r.rlim_cur = RLIM_INFINITY;
	else
		r.rlim_cur = r32.rlim_cur;
	if (r32.rlim_max == COMPAT_RLIM_INFINITY)
		r.rlim_max = RLIM_INFINITY;
	else
		r.rlim_max = r32.rlim_max;
	return do_prlimit(current, resource, &r, NULL);
}

COMPAT_SYSCALL_DEFINE2(getrlimit, unsigned int, resource,
		       struct compat_rlimit __user *, rlim)
{
	struct rlimit r;
	int ret;

	ret = do_prlimit(current, resource, NULL, &r);
	if (!ret) {
		struct compat_rlimit r32;
		if (r.rlim_cur > COMPAT_RLIM_INFINITY)
			r32.rlim_cur = COMPAT_RLIM_INFINITY;
		else
			r32.rlim_cur = r.rlim_cur;
		if (r.rlim_max > COMPAT_RLIM_INFINITY)
			r32.rlim_max = COMPAT_RLIM_INFINITY;
		else
			r32.rlim_max = r.rlim_max;

		if (copy_to_user(rlim, &r32, sizeof(struct compat_rlimit)))
			return -EFAULT;
	}
	return ret;
}

#endif

#ifdef __ARCH_WANT_SYS_OLD_GETRLIMIT

/*
 *	Back compatibility for getrlimit. Needed for some apps.
 */
SYSCALL_DEFINE2(old_getrlimit, unsigned int, resource,
		struct rlimit __user *, rlim)
{
	struct rlimit x;
	if (resource >= RLIM_NLIMITS)
		return -EINVAL;

	resource = array_index_nospec(resource, RLIM_NLIMITS);
	task_lock(current->group_leader);
	x = current->signal->rlim[resource];
	task_unlock(current->group_leader);
	if (x.rlim_cur > 0x7FFFFFFF)
		x.rlim_cur = 0x7FFFFFFF;
	if (x.rlim_max > 0x7FFFFFFF)
		x.rlim_max = 0x7FFFFFFF;
	return copy_to_user(rlim, &x, sizeof(x)) ? -EFAULT : 0;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(old_getrlimit, unsigned int, resource,
		       struct compat_rlimit __user *, rlim)
{
	struct rlimit r;

	if (resource >= RLIM_NLIMITS)
		return -EINVAL;

	resource = array_index_nospec(resource, RLIM_NLIMITS);
	task_lock(current->group_leader);
	r = current->signal->rlim[resource];
	task_unlock(current->group_leader);
	if (r.rlim_cur > 0x7FFFFFFF)
		r.rlim_cur = 0x7FFFFFFF;
	if (r.rlim_max > 0x7FFFFFFF)
		r.rlim_max = 0x7FFFFFFF;

	if (put_user(r.rlim_cur, &rlim->rlim_cur) ||
	    put_user(r.rlim_max, &rlim->rlim_max))
		return -EFAULT;
	return 0;
}
#endif

#endif

static inline bool rlim64_is_infinity(__u64 rlim64)
{
#if BITS_PER_LONG < 64
	return rlim64 >= ULONG_MAX;
#else
	return rlim64 == RLIM64_INFINITY;
#endif
}

static void rlim_to_rlim64(const struct rlimit *rlim, struct rlimit64 *rlim64)
{
	if (rlim->rlim_cur == RLIM_INFINITY)
		rlim64->rlim_cur = RLIM64_INFINITY;
	else
		rlim64->rlim_cur = rlim->rlim_cur;
	if (rlim->rlim_max == RLIM_INFINITY)
		rlim64->rlim_max = RLIM64_INFINITY;
	else
		rlim64->rlim_max = rlim->rlim_max;
}

static void rlim64_to_rlim(const struct rlimit64 *rlim64, struct rlimit *rlim)
{
	if (rlim64_is_infinity(rlim64->rlim_cur))
		rlim->rlim_cur = RLIM_INFINITY;
	else
		rlim->rlim_cur = (unsigned long)rlim64->rlim_cur;
	if (rlim64_is_infinity(rlim64->rlim_max))
		rlim->rlim_max = RLIM_INFINITY;
	else
		rlim->rlim_max = (unsigned long)rlim64->rlim_max;
}

/* rcu lock must be held */
static int check_prlimit_permission(struct task_struct *task,
				    unsigned int flags)
{
	const struct cred *cred = current_cred(), *tcred;
	bool id_match;

	if (current == task)
		return 0;

	tcred = __task_cred(task);
	id_match = (uid_eq(cred->uid, tcred->euid) &&
		    uid_eq(cred->uid, tcred->suid) &&
		    uid_eq(cred->uid, tcred->uid)  &&
		    gid_eq(cred->gid, tcred->egid) &&
		    gid_eq(cred->gid, tcred->sgid) &&
		    gid_eq(cred->gid, tcred->gid));
	if (!id_match && !ns_capable(tcred->user_ns, CAP_SYS_RESOURCE))
		return -EPERM;

	return security_task_prlimit(cred, tcred, flags);
}

SYSCALL_DEFINE4(prlimit64, pid_t, pid, unsigned int, resource,
		const struct rlimit64 __user *, new_rlim,
		struct rlimit64 __user *, old_rlim)
{
	struct rlimit64 old64, new64;
	struct rlimit old, new;
	struct task_struct *tsk;
	unsigned int checkflags = 0;
	bool need_tasklist;
	int ret;

	if (old_rlim)
		checkflags |= LSM_PRLIMIT_READ;

	if (new_rlim) {
		if (copy_from_user(&new64, new_rlim, sizeof(new64)))
			return -EFAULT;
		rlim64_to_rlim(&new64, &new);
		checkflags |= LSM_PRLIMIT_WRITE;
	}

	rcu_read_lock();
	tsk = pid ? find_task_by_vpid(pid) : current;
	if (!tsk) {
		rcu_read_unlock();
		return -ESRCH;
	}
	ret = check_prlimit_permission(tsk, checkflags);
	if (ret) {
		rcu_read_unlock();
		return ret;
	}
	get_task_struct(tsk);
	rcu_read_unlock();

	need_tasklist = !same_thread_group(tsk, current);
	if (need_tasklist) {
		/*
		 * Ensure we can't race with group exit or de_thread(),
		 * so tsk->group_leader can't be freed or changed until
		 * read_unlock(tasklist_lock) below.
		 */
		read_lock(&tasklist_lock);
		if (!pid_alive(tsk))
			ret = -ESRCH;
	}

	if (!ret) {
		ret = do_prlimit(tsk, resource, new_rlim ? &new : NULL,
				old_rlim ? &old : NULL);
	}

	if (need_tasklist)
		read_unlock(&tasklist_lock);

	if (!ret && old_rlim) {
		rlim_to_rlim64(&old, &old64);
		if (copy_to_user(old_rlim, &old64, sizeof(old64)))
			ret = -EFAULT;
	}

	put_task_struct(tsk);
	return ret;
}

SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit new_rlim;

	if (copy_from_user(&new_rlim, rlim, sizeof(*rlim)))
		return -EFAULT;
	return do_prlimit(current, resource, &new_rlim, NULL);
}

/*
 * It would make sense to put struct rusage in the task_struct,
 * except that would make the task_struct be *really big*.  After
 * task_struct gets moved into malloc'ed memory, it would
 * make sense to do this.  It will make moving the rest of the information
 * a lot simpler!  (Which we're not doing right now because we're not
 * measuring them yet).
 *
 * When sampling multiple threads for RUSAGE_SELF, under SMP we might have
 * races with threads incrementing their own counters.  But since word
 * reads are atomic, we either get new values or old values and we don't
 * care which for the sums.  We always take the siglock to protect reading
 * the c* fields from p->signal from races with exit.c updating those
 * fields when reaping, so a sample either gets all the additions of a
 * given child after it's reaped, or none so this sample is before reaping.
 *
 * Locking:
 * We need to take the siglock for CHILDEREN, SELF and BOTH
 * for  the cases current multithreaded, non-current single threaded
 * non-current multithreaded.  Thread traversal is now safe with
 * the siglock held.
 * Strictly speaking, we donot need to take the siglock if we are current and
 * single threaded,  as no one else can take our signal_struct away, no one
 * else can  reap the  children to update signal->c* counters, and no one else
 * can race with the signal-> fields. If we do not take any lock, the
 * signal-> fields could be read out of order while another thread was just
 * exiting. So we should  place a read memory barrier when we avoid the lock.
 * On the writer side,  write memory barrier is implied in  __exit_signal
 * as __exit_signal releases  the siglock spinlock after updating the signal->
 * fields. But we don't do this yet to keep things simple.
 *
 */

static void accumulate_thread_rusage(struct task_struct *t, struct rusage *r)
{
	r->ru_nvcsw += t->nvcsw;
	r->ru_nivcsw += t->nivcsw;
	r->ru_minflt += t->min_flt;
	r->ru_majflt += t->maj_flt;
	r->ru_inblock += task_io_get_inblock(t);
	r->ru_oublock += task_io_get_oublock(t);
}

void getrusage(struct task_struct *p, int who, struct rusage *r)
{
	struct task_struct *t;
	unsigned long flags;
	u64 tgutime, tgstime, utime, stime;
	unsigned long maxrss;
	struct mm_struct *mm;
	struct signal_struct *sig = p->signal;
	unsigned int seq = 0;

retry:
	memset(r, 0, sizeof(*r));
	utime = stime = 0;
	maxrss = 0;

	if (who == RUSAGE_THREAD) {
		task_cputime_adjusted(current, &utime, &stime);
		accumulate_thread_rusage(p, r);
		maxrss = sig->maxrss;
		goto out_thread;
	}

	flags = read_seqbegin_or_lock_irqsave(&sig->stats_lock, &seq);

	switch (who) {
	case RUSAGE_BOTH:
	case RUSAGE_CHILDREN:
		utime = sig->cutime;
		stime = sig->cstime;
		r->ru_nvcsw = sig->cnvcsw;
		r->ru_nivcsw = sig->cnivcsw;
		r->ru_minflt = sig->cmin_flt;
		r->ru_majflt = sig->cmaj_flt;
		r->ru_inblock = sig->cinblock;
		r->ru_oublock = sig->coublock;
		maxrss = sig->cmaxrss;

		if (who == RUSAGE_CHILDREN)
			break;
		fallthrough;

	case RUSAGE_SELF:
		r->ru_nvcsw += sig->nvcsw;
		r->ru_nivcsw += sig->nivcsw;
		r->ru_minflt += sig->min_flt;
		r->ru_majflt += sig->maj_flt;
		r->ru_inblock += sig->inblock;
		r->ru_oublock += sig->oublock;
		if (maxrss < sig->maxrss)
			maxrss = sig->maxrss;

		rcu_read_lock();
		__for_each_thread(sig, t)
			accumulate_thread_rusage(t, r);
		rcu_read_unlock();

		break;

	default:
		BUG();
	}

	if (need_seqretry(&sig->stats_lock, seq)) {
		seq = 1;
		goto retry;
	}
	done_seqretry_irqrestore(&sig->stats_lock, seq, flags);

	if (who == RUSAGE_CHILDREN)
		goto out_children;

	thread_group_cputime_adjusted(p, &tgutime, &tgstime);
	utime += tgutime;
	stime += tgstime;

out_thread:
	mm = get_task_mm(p);
	if (mm) {
		setmax_mm_hiwater_rss(&maxrss, mm);
		mmput(mm);
	}

out_children:
	r->ru_maxrss = maxrss * (PAGE_SIZE / 1024); /* convert pages to KBs */
	r->ru_utime = ns_to_kernel_old_timeval(utime);
	r->ru_stime = ns_to_kernel_old_timeval(stime);
}

SYSCALL_DEFINE2(getrusage, int, who, struct rusage __user *, ru)
{
	struct rusage r;

	if (who != RUSAGE_SELF && who != RUSAGE_CHILDREN &&
	    who != RUSAGE_THREAD)
		return -EINVAL;

	getrusage(current, who, &r);
	return copy_to_user(ru, &r, sizeof(r)) ? -EFAULT : 0;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(getrusage, int, who, struct compat_rusage __user *, ru)
{
	struct rusage r;

	if (who != RUSAGE_SELF && who != RUSAGE_CHILDREN &&
	    who != RUSAGE_THREAD)
		return -EINVAL;

	getrusage(current, who, &r);
	return put_compat_rusage(&r, ru);
}
#endif

SYSCALL_DEFINE1(umask, int, mask)
{
	mask = xchg(&current->fs->umask, mask & S_IRWXUGO);
	return mask;
}

static int prctl_set_mm_exe_file(struct mm_struct *mm, unsigned int fd)
{
	CLASS(fd, exe)(fd);
	struct inode *inode;
	int err;

	if (fd_empty(exe))
		return -EBADF;

	inode = file_inode(fd_file(exe));

	/*
	 * Because the original mm->exe_file points to executable file, make
	 * sure that this one is executable as well, to avoid breaking an
	 * overall picture.
	 */
	if (!S_ISREG(inode->i_mode) || path_noexec(&fd_file(exe)->f_path))
		return -EACCES;

	err = file_permission(fd_file(exe), MAY_EXEC);
	if (err)
		return err;

	return replace_mm_exe_file(mm, fd_file(exe));
}

/*
 * Check arithmetic relations of passed addresses.
 *
 * WARNING: we don't require any capability here so be very careful
 * in what is allowed for modification from userspace.
 */
static int validate_prctl_map_addr(struct prctl_mm_map *prctl_map)
{
	unsigned long mmap_max_addr = TASK_SIZE;
	int error = -EINVAL, i;

	static const unsigned char offsets[] = {
		offsetof(struct prctl_mm_map, start_code),
		offsetof(struct prctl_mm_map, end_code),
		offsetof(struct prctl_mm_map, start_data),
		offsetof(struct prctl_mm_map, end_data),
		offsetof(struct prctl_mm_map, start_brk),
		offsetof(struct prctl_mm_map, brk),
		offsetof(struct prctl_mm_map, start_stack),
		offsetof(struct prctl_mm_map, arg_start),
		offsetof(struct prctl_mm_map, arg_end),
		offsetof(struct prctl_mm_map, env_start),
		offsetof(struct prctl_mm_map, env_end),
	};

	/*
	 * Make sure the members are not somewhere outside
	 * of allowed address space.
	 */
	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		u64 val = *(u64 *)((char *)prctl_map + offsets[i]);

		if ((unsigned long)val >= mmap_max_addr ||
		    (unsigned long)val < mmap_min_addr)
			goto out;
	}

	/*
	 * Make sure the pairs are ordered.
	 */
#define __prctl_check_order(__m1, __op, __m2)				\
	((unsigned long)prctl_map->__m1 __op				\
	 (unsigned long)prctl_map->__m2) ? 0 : -EINVAL
	error  = __prctl_check_order(start_code, <, end_code);
	error |= __prctl_check_order(start_data,<=, end_data);
	error |= __prctl_check_order(start_brk, <=, brk);
	error |= __prctl_check_order(arg_start, <=, arg_end);
	error |= __prctl_check_order(env_start, <=, env_end);
	if (error)
		goto out;
#undef __prctl_check_order

	error = -EINVAL;

	/*
	 * Neither we should allow to override limits if they set.
	 */
	if (check_data_rlimit(rlimit(RLIMIT_DATA), prctl_map->brk,
			      prctl_map->start_brk, prctl_map->end_data,
			      prctl_map->start_data))
			goto out;

	error = 0;
out:
	return error;
}

#ifdef CONFIG_CHECKPOINT_RESTORE
static int prctl_set_mm_map(int opt, const void __user *addr, unsigned long data_size)
{
	struct prctl_mm_map prctl_map = { .exe_fd = (u32)-1, };
	unsigned long user_auxv[AT_VECTOR_SIZE];
	struct mm_struct *mm = current->mm;
	int error;

	BUILD_BUG_ON(sizeof(user_auxv) != sizeof(mm->saved_auxv));
	BUILD_BUG_ON(sizeof(struct prctl_mm_map) > 256);

	if (opt == PR_SET_MM_MAP_SIZE)
		return put_user((unsigned int)sizeof(prctl_map),
				(unsigned int __user *)addr);

	if (data_size != sizeof(prctl_map))
		return -EINVAL;

	if (copy_from_user(&prctl_map, addr, sizeof(prctl_map)))
		return -EFAULT;

	error = validate_prctl_map_addr(&prctl_map);
	if (error)
		return error;

	if (prctl_map.auxv_size) {
		/*
		 * Someone is trying to cheat the auxv vector.
		 */
		if (!prctl_map.auxv ||
				prctl_map.auxv_size > sizeof(mm->saved_auxv))
			return -EINVAL;

		memset(user_auxv, 0, sizeof(user_auxv));
		if (copy_from_user(user_auxv,
				   (const void __user *)prctl_map.auxv,
				   prctl_map.auxv_size))
			return -EFAULT;

		/* Last entry must be AT_NULL as specification requires */
		user_auxv[AT_VECTOR_SIZE - 2] = AT_NULL;
		user_auxv[AT_VECTOR_SIZE - 1] = AT_NULL;
	}

	if (prctl_map.exe_fd != (u32)-1) {
		/*
		 * Check if the current user is checkpoint/restore capable.
		 * At the time of this writing, it checks for CAP_SYS_ADMIN
		 * or CAP_CHECKPOINT_RESTORE.
		 * Note that a user with access to ptrace can masquerade an
		 * arbitrary program as any executable, even setuid ones.
		 * This may have implications in the tomoyo subsystem.
		 */
		if (!checkpoint_restore_ns_capable(current_user_ns()))
			return -EPERM;

		error = prctl_set_mm_exe_file(mm, prctl_map.exe_fd);
		if (error)
			return error;
	}

	/*
	 * arg_lock protects concurrent updates but we still need mmap_lock for
	 * read to exclude races with sys_brk.
	 */
	mmap_read_lock(mm);

	/*
	 * We don't validate if these members are pointing to
	 * real present VMAs because application may have correspond
	 * VMAs already unmapped and kernel uses these members for statistics
	 * output in procfs mostly, except
	 *
	 *  - @start_brk/@brk which are used in do_brk_flags but kernel lookups
	 *    for VMAs when updating these members so anything wrong written
	 *    here cause kernel to swear at userspace program but won't lead
	 *    to any problem in kernel itself
	 */

	spin_lock(&mm->arg_lock);
	mm->start_code	= prctl_map.start_code;
	mm->end_code	= prctl_map.end_code;
	mm->start_data	= prctl_map.start_data;
	mm->end_data	= prctl_map.end_data;
	mm->start_brk	= prctl_map.start_brk;
	mm->brk		= prctl_map.brk;
	mm->start_stack	= prctl_map.start_stack;
	mm->arg_start	= prctl_map.arg_start;
	mm->arg_end	= prctl_map.arg_end;
	mm->env_start	= prctl_map.env_start;
	mm->env_end	= prctl_map.env_end;
	spin_unlock(&mm->arg_lock);

	/*
	 * Note this update of @saved_auxv is lockless thus
	 * if someone reads this member in procfs while we're
	 * updating -- it may get partly updated results. It's
	 * known and acceptable trade off: we leave it as is to
	 * not introduce additional locks here making the kernel
	 * more complex.
	 */
	if (prctl_map.auxv_size)
		memcpy(mm->saved_auxv, user_auxv, sizeof(user_auxv));

	mmap_read_unlock(mm);
	return 0;
}
#endif /* CONFIG_CHECKPOINT_RESTORE */

static int prctl_set_auxv(struct mm_struct *mm, unsigned long addr,
			  unsigned long len)
{
	/*
	 * This doesn't move the auxiliary vector itself since it's pinned to
	 * mm_struct, but it permits filling the vector with new values.  It's
	 * up to the caller to provide sane values here, otherwise userspace
	 * tools which use this vector might be unhappy.
	 */
	unsigned long user_auxv[AT_VECTOR_SIZE] = {};

	if (len > sizeof(user_auxv))
		return -EINVAL;

	if (copy_from_user(user_auxv, (const void __user *)addr, len))
		return -EFAULT;

	/* Make sure the last entry is always AT_NULL */
	user_auxv[AT_VECTOR_SIZE - 2] = 0;
	user_auxv[AT_VECTOR_SIZE - 1] = 0;

	BUILD_BUG_ON(sizeof(user_auxv) != sizeof(mm->saved_auxv));

	task_lock(current);
	memcpy(mm->saved_auxv, user_auxv, len);
	task_unlock(current);

	return 0;
}

static int prctl_set_mm(int opt, unsigned long addr,
			unsigned long arg4, unsigned long arg5)
{
	struct mm_struct *mm = current->mm;
	struct prctl_mm_map prctl_map = {
		.auxv = NULL,
		.auxv_size = 0,
		.exe_fd = -1,
	};
	struct vm_area_struct *vma;
	int error;

	if (arg5 || (arg4 && (opt != PR_SET_MM_AUXV &&
			      opt != PR_SET_MM_MAP &&
			      opt != PR_SET_MM_MAP_SIZE)))
		return -EINVAL;

#ifdef CONFIG_CHECKPOINT_RESTORE
	if (opt == PR_SET_MM_MAP || opt == PR_SET_MM_MAP_SIZE)
		return prctl_set_mm_map(opt, (const void __user *)addr, arg4);
#endif

	if (!capable(CAP_SYS_RESOURCE))
		return -EPERM;

	if (opt == PR_SET_MM_EXE_FILE)
		return prctl_set_mm_exe_file(mm, (unsigned int)addr);

	if (opt == PR_SET_MM_AUXV)
		return prctl_set_auxv(mm, addr, arg4);

	if (addr >= TASK_SIZE || addr < mmap_min_addr)
		return -EINVAL;

	error = -EINVAL;

	/*
	 * arg_lock protects concurrent updates of arg boundaries, we need
	 * mmap_lock for a) concurrent sys_brk, b) finding VMA for addr
	 * validation.
	 */
	mmap_read_lock(mm);
	vma = find_vma(mm, addr);

	spin_lock(&mm->arg_lock);
	prctl_map.start_code	= mm->start_code;
	prctl_map.end_code	= mm->end_code;
	prctl_map.start_data	= mm->start_data;
	prctl_map.end_data	= mm->end_data;
	prctl_map.start_brk	= mm->start_brk;
	prctl_map.brk		= mm->brk;
	prctl_map.start_stack	= mm->start_stack;
	prctl_map.arg_start	= mm->arg_start;
	prctl_map.arg_end	= mm->arg_end;
	prctl_map.env_start	= mm->env_start;
	prctl_map.env_end	= mm->env_end;

	switch (opt) {
	case PR_SET_MM_START_CODE:
		prctl_map.start_code = addr;
		break;
	case PR_SET_MM_END_CODE:
		prctl_map.end_code = addr;
		break;
	case PR_SET_MM_START_DATA:
		prctl_map.start_data = addr;
		break;
	case PR_SET_MM_END_DATA:
		prctl_map.end_data = addr;
		break;
	case PR_SET_MM_START_STACK:
		prctl_map.start_stack = addr;
		break;
	case PR_SET_MM_START_BRK:
		prctl_map.start_brk = addr;
		break;
	case PR_SET_MM_BRK:
		prctl_map.brk = addr;
		break;
	case PR_SET_MM_ARG_START:
		prctl_map.arg_start = addr;
		break;
	case PR_SET_MM_ARG_END:
		prctl_map.arg_end = addr;
		break;
	case PR_SET_MM_ENV_START:
		prctl_map.env_start = addr;
		break;
	case PR_SET_MM_ENV_END:
		prctl_map.env_end = addr;
		break;
	default:
		goto out;
	}

	error = validate_prctl_map_addr(&prctl_map);
	if (error)
		goto out;

	switch (opt) {
	/*
	 * If command line arguments and environment
	 * are placed somewhere else on stack, we can
	 * set them up here, ARG_START/END to setup
	 * command line arguments and ENV_START/END
	 * for environment.
	 */
	case PR_SET_MM_START_STACK:
	case PR_SET_MM_ARG_START:
	case PR_SET_MM_ARG_END:
	case PR_SET_MM_ENV_START:
	case PR_SET_MM_ENV_END:
		if (!vma) {
			error = -EFAULT;
			goto out;
		}
	}

	mm->start_code	= prctl_map.start_code;
	mm->end_code	= prctl_map.end_code;
	mm->start_data	= prctl_map.start_data;
	mm->end_data	= prctl_map.end_data;
	mm->start_brk	= prctl_map.start_brk;
	mm->brk		= prctl_map.brk;
	mm->start_stack	= prctl_map.start_stack;
	mm->arg_start	= prctl_map.arg_start;
	mm->arg_end	= prctl_map.arg_end;
	mm->env_start	= prctl_map.env_start;
	mm->env_end	= prctl_map.env_end;

	error = 0;
out:
	spin_unlock(&mm->arg_lock);
	mmap_read_unlock(mm);
	return error;
}

#ifdef CONFIG_CHECKPOINT_RESTORE
static int prctl_get_tid_address(struct task_struct *me, int __user * __user *tid_addr)
{
	return put_user(me->clear_child_tid, tid_addr);
}
#else
static int prctl_get_tid_address(struct task_struct *me, int __user * __user *tid_addr)
{
	return -EINVAL;
}
#endif

static int propagate_has_child_subreaper(struct task_struct *p, void *data)
{
	/*
	 * If task has has_child_subreaper - all its descendants
	 * already have these flag too and new descendants will
	 * inherit it on fork, skip them.
	 *
	 * If we've found child_reaper - skip descendants in
	 * it's subtree as they will never get out pidns.
	 */
	if (p->signal->has_child_subreaper ||
	    is_child_reaper(task_pid(p)))
		return 0;

	p->signal->has_child_subreaper = 1;
	return 1;
}

int __weak arch_prctl_spec_ctrl_get(struct task_struct *t, unsigned long which)
{
	return -EINVAL;
}

int __weak arch_prctl_spec_ctrl_set(struct task_struct *t, unsigned long which,
				    unsigned long ctrl)
{
	return -EINVAL;
}

int __weak arch_get_shadow_stack_status(struct task_struct *t, unsigned long __user *status)
{
	return -EINVAL;
}

int __weak arch_set_shadow_stack_status(struct task_struct *t, unsigned long status)
{
	return -EINVAL;
}

int __weak arch_lock_shadow_stack_status(struct task_struct *t, unsigned long status)
{
	return -EINVAL;
}

#define PR_IO_FLUSHER (PF_MEMALLOC_NOIO | PF_LOCAL_THROTTLE)

static int prctl_set_vma(unsigned long opt, unsigned long addr,
			 unsigned long size, unsigned long arg)
{
	int error;

	switch (opt) {
	case PR_SET_VMA_ANON_NAME:
		error = set_anon_vma_name(addr, size, (const char __user *)arg);
		break;
	default:
		error = -EINVAL;
	}

	return error;
}

static inline unsigned long get_current_mdwe(void)
{
	unsigned long ret = 0;

	if (mm_flags_test(MMF_HAS_MDWE, current->mm))
		ret |= PR_MDWE_REFUSE_EXEC_GAIN;
	if (mm_flags_test(MMF_HAS_MDWE_NO_INHERIT, current->mm))
		ret |= PR_MDWE_NO_INHERIT;

	return ret;
}

static inline int prctl_set_mdwe(unsigned long bits, unsigned long arg3,
				 unsigned long arg4, unsigned long arg5)
{
	unsigned long current_bits;

	if (arg3 || arg4 || arg5)
		return -EINVAL;

	if (bits & ~(PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT))
		return -EINVAL;

	/* NO_INHERIT only makes sense with REFUSE_EXEC_GAIN */
	if (bits & PR_MDWE_NO_INHERIT && !(bits & PR_MDWE_REFUSE_EXEC_GAIN))
		return -EINVAL;

	/*
	 * EOPNOTSUPP might be more appropriate here in principle, but
	 * existing userspace depends on EINVAL specifically.
	 */
	if (!arch_memory_deny_write_exec_supported())
		return -EINVAL;

	current_bits = get_current_mdwe();
	if (current_bits && current_bits != bits)
		return -EPERM; /* Cannot unset the flags */

	if (bits & PR_MDWE_NO_INHERIT)
		mm_flags_set(MMF_HAS_MDWE_NO_INHERIT, current->mm);
	if (bits & PR_MDWE_REFUSE_EXEC_GAIN)
		mm_flags_set(MMF_HAS_MDWE, current->mm);

	return 0;
}

static inline int prctl_get_mdwe(unsigned long arg2, unsigned long arg3,
				 unsigned long arg4, unsigned long arg5)
{
	if (arg2 || arg3 || arg4 || arg5)
		return -EINVAL;
	return get_current_mdwe();
}

static int prctl_get_auxv(void __user *addr, unsigned long len)
{
	struct mm_struct *mm = current->mm;
	unsigned long size = min_t(unsigned long, sizeof(mm->saved_auxv), len);

	if (size && copy_to_user(addr, mm->saved_auxv, size))
		return -EFAULT;
	return sizeof(mm->saved_auxv);
}

static int prctl_get_thp_disable(unsigned long arg2, unsigned long arg3,
				 unsigned long arg4, unsigned long arg5)
{
	struct mm_struct *mm = current->mm;

	if (arg2 || arg3 || arg4 || arg5)
		return -EINVAL;

	/* If disabled, we return "1 | flags", otherwise 0. */
	if (mm_flags_test(MMF_DISABLE_THP_COMPLETELY, mm))
		return 1;
	else if (mm_flags_test(MMF_DISABLE_THP_EXCEPT_ADVISED, mm))
		return 1 | PR_THP_DISABLE_EXCEPT_ADVISED;
	return 0;
}

static int prctl_set_thp_disable(bool thp_disable, unsigned long flags,
				 unsigned long arg4, unsigned long arg5)
{
	struct mm_struct *mm = current->mm;

	if (arg4 || arg5)
		return -EINVAL;

	/* Flags are only allowed when disabling. */
	if ((!thp_disable && flags) || (flags & ~PR_THP_DISABLE_EXCEPT_ADVISED))
		return -EINVAL;
	if (mmap_write_lock_killable(current->mm))
		return -EINTR;
	if (thp_disable) {
		if (flags & PR_THP_DISABLE_EXCEPT_ADVISED) {
			mm_flags_clear(MMF_DISABLE_THP_COMPLETELY, mm);
			mm_flags_set(MMF_DISABLE_THP_EXCEPT_ADVISED, mm);
		} else {
			mm_flags_set(MMF_DISABLE_THP_COMPLETELY, mm);
			mm_flags_clear(MMF_DISABLE_THP_EXCEPT_ADVISED, mm);
		}
	} else {
		mm_flags_clear(MMF_DISABLE_THP_COMPLETELY, mm);
		mm_flags_clear(MMF_DISABLE_THP_EXCEPT_ADVISED, mm);
	}
	mmap_write_unlock(current->mm);
	return 0;
}

SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
		unsigned long, arg4, unsigned long, arg5)
{
	struct task_struct *me = current;
	unsigned char comm[sizeof(me->comm)];
	long error;

	error = security_task_prctl(option, arg2, arg3, arg4, arg5);
	if (error != -ENOSYS)
		return error;

	error = 0;
	switch (option) {
	case PR_SET_PDEATHSIG:
		if (!valid_signal(arg2)) {
			error = -EINVAL;
			break;
		}
		/*
		 * Ensure that either:
		 *
		 * 1. Subsequent getppid() calls reflect the parent process having died.
		 * 2. forget_original_parent() will send the new me->pdeath_signal.
		 *
		 * Also prevent the read of me->pdeath_signal from being a data race.
		 */
		read_lock(&tasklist_lock);
		me->pdeath_signal = arg2;
		read_unlock(&tasklist_lock);
		break;
	case PR_GET_PDEATHSIG:
		error = put_user(me->pdeath_signal, (int __user *)arg2);
		break;
	case PR_GET_DUMPABLE:
		error = get_dumpable(me->mm);
		break;
	case PR_SET_DUMPABLE:
		if (arg2 != SUID_DUMP_DISABLE && arg2 != SUID_DUMP_USER) {
			error = -EINVAL;
			break;
		}
		set_dumpable(me->mm, arg2);
		break;

	case PR_SET_UNALIGN:
		error = SET_UNALIGN_CTL(me, arg2);
		break;
	case PR_GET_UNALIGN:
		error = GET_UNALIGN_CTL(me, arg2);
		break;
	case PR_SET_FPEMU:
		error = SET_FPEMU_CTL(me, arg2);
		break;
	case PR_GET_FPEMU:
		error = GET_FPEMU_CTL(me, arg2);
		break;
	case PR_SET_FPEXC:
		error = SET_FPEXC_CTL(me, arg2);
		break;
	case PR_GET_FPEXC:
		error = GET_FPEXC_CTL(me, arg2);
		break;
	case PR_GET_TIMING:
		error = PR_TIMING_STATISTICAL;
		break;
	case PR_SET_TIMING:
		if (arg2 != PR_TIMING_STATISTICAL)
			error = -EINVAL;
		break;
	case PR_SET_NAME:
		comm[sizeof(me->comm) - 1] = 0;
		if (strncpy_from_user(comm, (char __user *)arg2,
				      sizeof(me->comm) - 1) < 0)
			return -EFAULT;
		set_task_comm(me, comm);
		proc_comm_connector(me);
		break;
	case PR_GET_NAME:
		get_task_comm(comm, me);
		if (copy_to_user((char __user *)arg2, comm, sizeof(comm)))
			return -EFAULT;
		break;
	case PR_GET_ENDIAN:
		error = GET_ENDIAN(me, arg2);
		break;
	case PR_SET_ENDIAN:
		error = SET_ENDIAN(me, arg2);
		break;
	case PR_GET_SECCOMP:
		error = prctl_get_seccomp();
		break;
	case PR_SET_SECCOMP:
		error = prctl_set_seccomp(arg2, (char __user *)arg3);
		break;
	case PR_GET_TSC:
		error = GET_TSC_CTL(arg2);
		break;
	case PR_SET_TSC:
		error = SET_TSC_CTL(arg2);
		break;
	case PR_TASK_PERF_EVENTS_DISABLE:
		error = perf_event_task_disable();
		break;
	case PR_TASK_PERF_EVENTS_ENABLE:
		error = perf_event_task_enable();
		break;
	case PR_GET_TIMERSLACK:
		if (current->timer_slack_ns > ULONG_MAX)
			error = ULONG_MAX;
		else
			error = current->timer_slack_ns;
		break;
	case PR_SET_TIMERSLACK:
		if (rt_or_dl_task_policy(current))
			break;
		if (arg2 <= 0)
			current->timer_slack_ns =
					current->default_timer_slack_ns;
		else
			current->timer_slack_ns = arg2;
		break;
	case PR_MCE_KILL:
		if (arg4 | arg5)
			return -EINVAL;
		switch (arg2) {
		case PR_MCE_KILL_CLEAR:
			if (arg3 != 0)
				return -EINVAL;
			current->flags &= ~PF_MCE_PROCESS;
			break;
		case PR_MCE_KILL_SET:
			current->flags |= PF_MCE_PROCESS;
			if (arg3 == PR_MCE_KILL_EARLY)
				current->flags |= PF_MCE_EARLY;
			else if (arg3 == PR_MCE_KILL_LATE)
				current->flags &= ~PF_MCE_EARLY;
			else if (arg3 == PR_MCE_KILL_DEFAULT)
				current->flags &=
						~(PF_MCE_EARLY|PF_MCE_PROCESS);
			else
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
		break;
	case PR_MCE_KILL_GET:
		if (arg2 | arg3 | arg4 | arg5)
			return -EINVAL;
		if (current->flags & PF_MCE_PROCESS)
			error = (current->flags & PF_MCE_EARLY) ?
				PR_MCE_KILL_EARLY : PR_MCE_KILL_LATE;
		else
			error = PR_MCE_KILL_DEFAULT;
		break;
	case PR_SET_MM:
		error = prctl_set_mm(arg2, arg3, arg4, arg5);
		break;
	case PR_GET_TID_ADDRESS:
		error = prctl_get_tid_address(me, (int __user * __user *)arg2);
		break;
	case PR_SET_CHILD_SUBREAPER:
		me->signal->is_child_subreaper = !!arg2;
		if (!arg2)
			break;

		walk_process_tree(me, propagate_has_child_subreaper, NULL);
		break;
	case PR_GET_CHILD_SUBREAPER:
		error = put_user(me->signal->is_child_subreaper,
				 (int __user *)arg2);
		break;
	case PR_SET_NO_NEW_PRIVS:
		if (arg2 != 1 || arg3 || arg4 || arg5)
			return -EINVAL;

		task_set_no_new_privs(current);
		break;
	case PR_GET_NO_NEW_PRIVS:
		if (arg2 || arg3 || arg4 || arg5)
			return -EINVAL;
		return task_no_new_privs(current) ? 1 : 0;
	case PR_GET_THP_DISABLE:
		error = prctl_get_thp_disable(arg2, arg3, arg4, arg5);
		break;
	case PR_SET_THP_DISABLE:
		error = prctl_set_thp_disable(arg2, arg3, arg4, arg5);
		break;
	case PR_MPX_ENABLE_MANAGEMENT:
	case PR_MPX_DISABLE_MANAGEMENT:
		/* No longer implemented: */
		return -EINVAL;
	case PR_SET_FP_MODE:
		error = SET_FP_MODE(me, arg2);
		break;
	case PR_GET_FP_MODE:
		error = GET_FP_MODE(me);
		break;
	case PR_SVE_SET_VL:
		error = SVE_SET_VL(arg2);
		break;
	case PR_SVE_GET_VL:
		error = SVE_GET_VL();
		break;
	case PR_SME_SET_VL:
		error = SME_SET_VL(arg2);
		break;
	case PR_SME_GET_VL:
		error = SME_GET_VL();
		break;
	case PR_GET_SPECULATION_CTRL:
		if (arg3 || arg4 || arg5)
			return -EINVAL;
		error = arch_prctl_spec_ctrl_get(me, arg2);
		break;
	case PR_SET_SPECULATION_CTRL:
		if (arg4 || arg5)
			return -EINVAL;
		error = arch_prctl_spec_ctrl_set(me, arg2, arg3);
		break;
	case PR_PAC_RESET_KEYS:
		if (arg3 || arg4 || arg5)
			return -EINVAL;
		error = PAC_RESET_KEYS(me, arg2);
		break;
	case PR_PAC_SET_ENABLED_KEYS:
		if (arg4 || arg5)
			return -EINVAL;
		error = PAC_SET_ENABLED_KEYS(me, arg2, arg3);
		break;
	case PR_PAC_GET_ENABLED_KEYS:
		if (arg2 || arg3 || arg4 || arg5)
			return -EINVAL;
		error = PAC_GET_ENABLED_KEYS(me);
		break;
	case PR_SET_TAGGED_ADDR_CTRL:
		if (arg3 || arg4 || arg5)
			return -EINVAL;
		error = SET_TAGGED_ADDR_CTRL(arg2);
		break;
	case PR_GET_TAGGED_ADDR_CTRL:
		if (arg2 || arg3 || arg4 || arg5)
			return -EINVAL;
		error = GET_TAGGED_ADDR_CTRL();
		break;
	case PR_SET_IO_FLUSHER:
		if (!capable(CAP_SYS_RESOURCE))
			return -EPERM;

		if (arg3 || arg4 || arg5)
			return -EINVAL;

		if (arg2 == 1)
			current->flags |= PR_IO_FLUSHER;
		else if (!arg2)
			current->flags &= ~PR_IO_FLUSHER;
		else
			return -EINVAL;
		break;
	case PR_GET_IO_FLUSHER:
		if (!capable(CAP_SYS_RESOURCE))
			return -EPERM;

		if (arg2 || arg3 || arg4 || arg5)
			return -EINVAL;

		error = (current->flags & PR_IO_FLUSHER) == PR_IO_FLUSHER;
		break;
	case PR_SET_SYSCALL_USER_DISPATCH:
		error = set_syscall_user_dispatch(arg2, arg3, arg4,
						  (char __user *) arg5);
		break;
#ifdef CONFIG_SCHED_CORE
	case PR_SCHED_CORE:
		error = sched_core_share_pid(arg2, arg3, arg4, arg5);
		break;
#endif
	case PR_SET_MDWE:
		error = prctl_set_mdwe(arg2, arg3, arg4, arg5);
		break;
	case PR_GET_MDWE:
		error = prctl_get_mdwe(arg2, arg3, arg4, arg5);
		break;
	case PR_PPC_GET_DEXCR:
		if (arg3 || arg4 || arg5)
			return -EINVAL;
		error = PPC_GET_DEXCR_ASPECT(me, arg2);
		break;
	case PR_PPC_SET_DEXCR:
		if (arg4 || arg5)
			return -EINVAL;
		error = PPC_SET_DEXCR_ASPECT(me, arg2, arg3);
		break;
	case PR_SET_VMA:
		error = prctl_set_vma(arg2, arg3, arg4, arg5);
		break;
	case PR_GET_AUXV:
		if (arg4 || arg5)
			return -EINVAL;
		error = prctl_get_auxv((void __user *)arg2, arg3);
		break;
#ifdef CONFIG_KSM
	case PR_SET_MEMORY_MERGE:
		if (arg3 || arg4 || arg5)
			return -EINVAL;
		if (mmap_write_lock_killable(me->mm))
			return -EINTR;

		if (arg2)
			error = ksm_enable_merge_any(me->mm);
		else
			error = ksm_disable_merge_any(me->mm);
		mmap_write_unlock(me->mm);
		break;
	case PR_GET_MEMORY_MERGE:
		if (arg2 || arg3 || arg4 || arg5)
			return -EINVAL;

		error = !!mm_flags_test(MMF_VM_MERGE_ANY, me->mm);
		break;
#endif
	case PR_RISCV_V_SET_CONTROL:
		error = RISCV_V_SET_CONTROL(arg2);
		break;
	case PR_RISCV_V_GET_CONTROL:
		error = RISCV_V_GET_CONTROL();
		break;
	case PR_RISCV_SET_ICACHE_FLUSH_CTX:
		error = RISCV_SET_ICACHE_FLUSH_CTX(arg2, arg3);
		break;
	case PR_GET_SHADOW_STACK_STATUS:
		if (arg3 || arg4 || arg5)
			return -EINVAL;
		error = arch_get_shadow_stack_status(me, (unsigned long __user *) arg2);
		break;
	case PR_SET_SHADOW_STACK_STATUS:
		if (arg3 || arg4 || arg5)
			return -EINVAL;
		error = arch_set_shadow_stack_status(me, arg2);
		break;
	case PR_LOCK_SHADOW_STACK_STATUS:
		if (arg3 || arg4 || arg5)
			return -EINVAL;
		error = arch_lock_shadow_stack_status(me, arg2);
		break;
	case PR_TIMER_CREATE_RESTORE_IDS:
		if (arg3 || arg4 || arg5)
			return -EINVAL;
		error = posixtimer_create_prctl(arg2);
		break;
	case PR_FUTEX_HASH:
		error = futex_hash_prctl(arg2, arg3, arg4);
		break;
	default:
		trace_task_prctl_unknown(option, arg2, arg3, arg4, arg5);
		error = -EINVAL;
		break;
	}
	return error;
}

SYSCALL_DEFINE3(getcpu, unsigned __user *, cpup, unsigned __user *, nodep,
		struct getcpu_cache __user *, unused)
{
	int err = 0;
	int cpu = raw_smp_processor_id();

	if (cpup)
		err |= put_user(cpu, cpup);
	if (nodep)
		err |= put_user(cpu_to_node(cpu), nodep);
	return err ? -EFAULT : 0;
}

/**
 * do_sysinfo - fill in sysinfo struct
 * @info: pointer to buffer to fill
 */
static int do_sysinfo(struct sysinfo *info)
{
	unsigned long mem_total, sav_total;
	unsigned int mem_unit, bitcount;
	struct timespec64 tp;

	memset(info, 0, sizeof(struct sysinfo));

	ktime_get_boottime_ts64(&tp);
	timens_add_boottime(&tp);
	info->uptime = tp.tv_sec + (tp.tv_nsec ? 1 : 0);

	get_avenrun(info->loads, 0, SI_LOAD_SHIFT - FSHIFT);

	info->procs = nr_threads;

	si_meminfo(info);
	si_swapinfo(info);

	/*
	 * If the sum of all the available memory (i.e. ram + swap)
	 * is less than can be stored in a 32 bit unsigned long then
	 * we can be binary compatible with 2.2.x kernels.  If not,
	 * well, in that case 2.2.x was broken anyways...
	 *
	 *  -Erik Andersen <andersee@debian.org>
	 */

	mem_total = info->totalram + info->totalswap;
	if (mem_total < info->totalram || mem_total < info->totalswap)
		goto out;
	bitcount = 0;
	mem_unit = info->mem_unit;
	while (mem_unit > 1) {
		bitcount++;
		mem_unit >>= 1;
		sav_total = mem_total;
		mem_total <<= 1;
		if (mem_total < sav_total)
			goto out;
	}

	/*
	 * If mem_total did not overflow, multiply all memory values by
	 * info->mem_unit and set it to 1.  This leaves things compatible
	 * with 2.2.x, and also retains compatibility with earlier 2.4.x
	 * kernels...
	 */

	info->mem_unit = 1;
	info->totalram <<= bitcount;
	info->freeram <<= bitcount;
	info->sharedram <<= bitcount;
	info->bufferram <<= bitcount;
	info->totalswap <<= bitcount;
	info->freeswap <<= bitcount;
	info->totalhigh <<= bitcount;
	info->freehigh <<= bitcount;

out:
	return 0;
}

SYSCALL_DEFINE1(sysinfo, struct sysinfo __user *, info)
{
	struct sysinfo val;

	do_sysinfo(&val);

	if (copy_to_user(info, &val, sizeof(struct sysinfo)))
		return -EFAULT;

	return 0;
}

#ifdef CONFIG_COMPAT
struct compat_sysinfo {
	s32 uptime;
	u32 loads[3];
	u32 totalram;
	u32 freeram;
	u32 sharedram;
	u32 bufferram;
	u32 totalswap;
	u32 freeswap;
	u16 procs;
	u16 pad;
	u32 totalhigh;
	u32 freehigh;
	u32 mem_unit;
	char _f[20-2*sizeof(u32)-sizeof(int)];
};

COMPAT_SYSCALL_DEFINE1(sysinfo, struct compat_sysinfo __user *, info)
{
	struct sysinfo s;
	struct compat_sysinfo s_32;

	do_sysinfo(&s);

	/* Check to see if any memory value is too large for 32-bit and scale
	 *  down if needed
	 */
	if (upper_32_bits(s.totalram) || upper_32_bits(s.totalswap)) {
		int bitcount = 0;

		while (s.mem_unit < PAGE_SIZE) {
			s.mem_unit <<= 1;
			bitcount++;
		}

		s.totalram >>= bitcount;
		s.freeram >>= bitcount;
		s.sharedram >>= bitcount;
		s.bufferram >>= bitcount;
		s.totalswap >>= bitcount;
		s.freeswap >>= bitcount;
		s.totalhigh >>= bitcount;
		s.freehigh >>= bitcount;
	}

	memset(&s_32, 0, sizeof(s_32));
	s_32.uptime = s.uptime;
	s_32.loads[0] = s.loads[0];
	s_32.loads[1] = s.loads[1];
	s_32.loads[2] = s.loads[2];
	s_32.totalram = s.totalram;
	s_32.freeram = s.freeram;
	s_32.sharedram = s.sharedram;
	s_32.bufferram = s.bufferram;
	s_32.totalswap = s.totalswap;
	s_32.freeswap = s.freeswap;
	s_32.procs = s.procs;
	s_32.totalhigh = s.totalhigh;
	s_32.freehigh = s.freehigh;
	s_32.mem_unit = s.mem_unit;
	if (copy_to_user(info, &s_32, sizeof(s_32)))
		return -EFAULT;
	return 0;
}
#endif /* CONFIG_COMPAT */
