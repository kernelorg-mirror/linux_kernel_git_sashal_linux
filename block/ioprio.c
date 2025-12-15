// SPDX-License-Identifier: GPL-2.0
/*
 * fs/ioprio.c
 *
 * Copyright (C) 2004 Jens Axboe <axboe@kernel.dk>
 *
 * Helper functions for setting/querying io priorities of processes. The
 * system calls closely mimmick getpriority/setpriority, see the man page for
 * those. The prio argument is a composite of prio class and prio data, where
 * the data argument has meaning within that class. The standard scheduling
 * classes have 8 distinct prio levels, with 0 being the highest prio and 7
 * being the lowest.
 *
 * IOW, setting BE scheduling class with prio 2 is done ala:
 *
 * unsigned int prio = (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 2;
 *
 * ioprio_set(PRIO_PROCESS, pid, prio);
 *
 * See also Documentation/block/ioprio.rst
 *
 */
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/ioprio.h>
#include <linux/cred.h>
#include <linux/blkdev.h>
#include <linux/capability.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/pid_namespace.h>

int ioprio_check_cap(int ioprio)
{
	int class = IOPRIO_PRIO_CLASS(ioprio);
	int level = IOPRIO_PRIO_LEVEL(ioprio);

	switch (class) {
		case IOPRIO_CLASS_RT:
			/*
			 * Originally this only checked for CAP_SYS_ADMIN,
			 * which was implicitly allowed for pid 0 by security
			 * modules such as SELinux. Make sure we check
			 * CAP_SYS_ADMIN first to avoid a denial/avc for
			 * possibly missing CAP_SYS_NICE permission.
			 */
			if (!capable(CAP_SYS_ADMIN) && !capable(CAP_SYS_NICE))
				return -EPERM;
			break;
		case IOPRIO_CLASS_BE:
		case IOPRIO_CLASS_IDLE:
			break;
		case IOPRIO_CLASS_NONE:
			if (level)
				return -EINVAL;
			break;
		case IOPRIO_CLASS_INVALID:
		default:
			return -EINVAL;
	}

	return 0;
}

/**
 * sys_ioprio_set - Set I/O scheduling class and priority
 * @which: Type of target to set priority for (process, pgrp, or user)
 * @who: Identifier of target (PID, PGID, or UID), or 0 for current/self
 * @ioprio: I/O priority value combining scheduling class and priority level
 *
 * long-desc: Sets the I/O scheduling class and priority for one or more
 *   processes. The I/O priority affects how the block I/O schedulers (bfq
 *   and mq-deadline) order requests from different processes. This syscall
 *   closely mimics getpriority/setpriority semantics.
 *
 *   The @which parameter determines how @who is interpreted:
 *   - IOPRIO_WHO_PROCESS (1): @who is a thread/process ID. If @who is 0,
 *     the calling thread is targeted. Despite the name, this operates on
 *     individual threads, not entire thread groups.
 *   - IOPRIO_WHO_PGRP (2): @who is a process group ID. If @who is 0, the
 *     calling process's process group is used. All threads in all processes
 *     in the process group are affected.
 *   - IOPRIO_WHO_USER (3): @who is a user ID (interpreted in the caller's
 *     user namespace). All processes with that real UID and a visible PID
 *     in the caller's PID namespace are affected. Note: @who of 0 means
 *     UID 0 (root), NOT the caller's UID.
 *
 *   The @ioprio parameter is a composite value created using the
 *   IOPRIO_PRIO_VALUE(class, level) macro. The class occupies bits 13-15,
 *   an optional hint occupies bits 3-12, and the priority level occupies
 *   bits 0-2.
 *
 *   I/O scheduling classes:
 *   - IOPRIO_CLASS_NONE (0): No explicit I/O priority. The effective priority
 *     is derived from the process's CPU nice value: io_nice = (nice + 20) / 5.
 *     The level field must be 0 for this class.
 *   - IOPRIO_CLASS_RT (1): Realtime I/O class. Processes get first access to
 *     the disk. Requires CAP_SYS_ADMIN or CAP_SYS_NICE capability. WARNING:
 *     A single RT I/O process can starve all other I/O in the system. Priority
 *     levels 0-7 are valid, with 0 being highest priority.
 *   - IOPRIO_CLASS_BE (2): Best-effort I/O class, the default. Priority levels
 *     0-7 are valid, with 0 being highest priority.
 *   - IOPRIO_CLASS_IDLE (3): Idle I/O class. Processes only get disk time when
 *     no other process needs the disk. The priority level is ignored.
 *
 *   When targeting multiple processes (IOPRIO_WHO_PGRP or IOPRIO_WHO_USER),
 *   the operation proceeds through all matching processes. If any individual
 *   set_task_ioprio() call fails, the syscall returns immediately with that
 *   error, potentially leaving some processes with the new priority and
 *   others unchanged (non-atomic behavior).
 *
 *   I/O priority is stored in the task's io_context structure. If a task
 *   does not have an io_context, one is allocated using GFP_ATOMIC when
 *   this syscall is called. I/O priority settings are inherited by child
 *   processes via fork() if the priority is explicitly set (ioprio_valid()
 *   returns true), otherwise children start without an io_context.
 *
 *   The I/O priority only affects block I/O schedulers that support it
 *   (bfq and mq-deadline). Other schedulers ignore the priority. The
 *   priority affects reads and synchronous writes (O_DIRECT, O_SYNC),
 *   but asynchronous writeback (page cache) may not honor the priority
 *   since the identity of the originating process is not known.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: which
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_ENUM
 *   constraint: Must be one of IOPRIO_WHO_PROCESS (1), IOPRIO_WHO_PGRP (2),
 *     or IOPRIO_WHO_USER (3). Any other value returns EINVAL.
 *
 * param: who
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Interpretation depends on @which. For IOPRIO_WHO_PROCESS, this
 *     is a PID (thread ID) where 0 means the calling thread. For IOPRIO_WHO_PGRP,
 *     this is a process group ID where 0 means the caller's process group. For
 *     IOPRIO_WHO_USER, this is a UID in the caller's user namespace (0 means
 *     UID 0, not the caller's UID). Negative values are treated as large
 *     positive values and will likely result in ESRCH. Invalid or non-existent
 *     identifiers return ESRCH.
 *
 * param: ioprio
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: A composite I/O priority value. Use IOPRIO_PRIO_VALUE(class, level)
 *     to construct. Class (bits 13-15) must be 0-3; class 7 (IOPRIO_CLASS_INVALID)
 *     or 4-6 return EINVAL. For IOPRIO_CLASS_NONE, level must be 0. For
 *     IOPRIO_CLASS_RT and IOPRIO_CLASS_BE, level should be 0-7. For
 *     IOPRIO_CLASS_IDLE, level is ignored. Optional hints (bits 3-12) can be
 *     set using IOPRIO_PRIO_VALUE_HINT(). Setting ioprio to 0 (IOPRIO_CLASS_NONE
 *     with level 0) resets to default nice-based priority derivation.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. When targeting multiple processes, success
 *     means all targeted processes were updated. On error, returns a negative
 *     errno value. Note that some processes may have been updated before an
 *     error occurred when targeting process groups or users.
 *
 * error: EINVAL, Invalid which value or ioprio class/level
 *   desc: Returned when @which is not IOPRIO_WHO_PROCESS (1), IOPRIO_WHO_PGRP
 *     (2), or IOPRIO_WHO_USER (3). Also returned when the @ioprio class is
 *     IOPRIO_CLASS_INVALID (7), an undefined class (4-6), or when
 *     IOPRIO_CLASS_NONE is specified with a non-zero level. The validation
 *     is performed by ioprio_check_cap() before any process lookup.
 *
 * error: EPERM, Insufficient privileges for operation
 *   desc: Returned in two situations: (1) Attempting to set IOPRIO_CLASS_RT
 *     without having either CAP_SYS_ADMIN or CAP_SYS_NICE capability.
 *     CAP_SYS_ADMIN is checked first for SELinux compatibility (commit
 *     94c4b4fd25e6). (2) Attempting to set I/O priority of a process not
 *     owned by the caller (target's UID does not match caller's real or
 *     effective UID) without CAP_SYS_NICE capability. The ownership check
 *     is performed in set_task_ioprio() via __task_cred() comparison.
 *
 * error: ESRCH, No matching process found
 *   desc: No process matching the @which/@who criteria was found. For
 *     IOPRIO_WHO_PROCESS, the specified PID does not exist or is not visible
 *     in the caller's PID namespace (find_task_by_vpid returns NULL). For
 *     IOPRIO_WHO_PGRP, the process group is empty or does not exist. For
 *     IOPRIO_WHO_USER, no processes with the specified real UID exist, the
 *     UID is not valid in the caller's user namespace (uid_valid returns
 *     false), or the user_struct for that UID could not be found.
 *
 * error: ENOMEM, Cannot allocate io_context
 *   desc: Memory allocation failed when trying to create an io_context for
 *     a target process that did not already have one. The allocation uses
 *     GFP_ATOMIC from the iocontext_cachep kmem_cache, which may fail under
 *     memory pressure or when called from atomic context. This error is more
 *     likely when setting priority for many processes simultaneously.
 *
 * error: EACCES, LSM denied the operation
 *   desc: The Linux Security Module (e.g., SELinux, AppArmor, Smack) denied
 *     the I/O priority change via the security_task_setioprio() hook. SELinux
 *     requires the PROCESS__SETSCHED permission on the target process. Smack
 *     requires MAY_WRITE access to the target task.
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: RCU read lock is held around the entire process/pgrp/user lookup
 *     and iteration to protect against task_struct being freed during access.
 *     Acquired at syscall entry and released before return. Required for
 *     find_task_by_vpid(), find_vpid(), task_pgrp(), and __task_cred().
 *
 * lock: tasklist_lock
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: The tasklist read lock is acquired for IOPRIO_WHO_PGRP to safely
 *     iterate over all threads in the process group using do_each_pid_thread().
 *     This prevents races with change_pid() that could move tasks between
 *     hash lists during iteration (fix from commit 40c7fd3fdfba9). Released
 *     on error or after completing iteration.
 *
 * lock: task->alloc_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The per-task allocation lock (task_lock/task_unlock) is acquired
 *     in set_task_ioprio() when accessing or creating the task's io_context.
 *     Protects task->io_context from concurrent modification. May be released
 *     and re-acquired during io_context allocation.
 *
 * lock: uidhash_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: The UID hash table lock is briefly acquired by find_user() when
 *     looking up a user_struct for IOPRIO_WHO_USER with non-zero @who.
 *     Acquired with IRQs disabled (spin_lock_irqsave).
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DEFAULT
 *   condition: Syscall does not have interruptible waits
 *   desc: This syscall does not have explicit signal handling. Memory
 *     allocation uses GFP_ATOMIC which does not sleep interruptibly, and
 *     the syscall completes quickly under the various locks. No ERESTARTSYS
 *     or EINTR returns are possible from this syscall.
 *   timing: KAPI_SIGNAL_TIME_NONE
 *   restartable: n/a
 *
 * side-effect: KAPI_EFFECT_ALLOC_MEMORY
 *   target: task io_context structure
 *   desc: If a target task does not have an io_context, one is allocated
 *     from the blkdev_ioc kmem_cache using GFP_ATOMIC. The io_context stores
 *     the I/O priority and persists until the task exits. Allocation uses
 *     kmem_cache_alloc_node() with NUMA_NO_NODE. Race conditions during
 *     allocation are handled by re-checking under task_lock.
 *   condition: Target task has no io_context (task->io_context is NULL)
 *   reversible: no (io_context is freed only on task exit via exit_io_context)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: task I/O priority (task->io_context->ioprio)
 *   desc: Modifies the I/O priority stored in the task's io_context. This
 *     affects how the block I/O scheduler prioritizes requests from this
 *     task. The change takes effect immediately for new I/O requests.
 *     Pending I/O requests may still be processed at the old priority.
 *   reversible: yes (can be changed back with another ioprio_set call)
 *
 * side-effect: KAPI_EFFECT_PROCESS_STATE
 *   target: user_struct reference count
 *   desc: For IOPRIO_WHO_USER with non-zero @who, find_user() increments
 *     the reference count on the user_struct. This is decremented by
 *     free_uid() before the syscall returns. This side effect is temporary
 *     and internal to the syscall.
 *   condition: IOPRIO_WHO_USER with non-zero @who
 *   reversible: yes (automatically within syscall)
 *
 * state-trans: task_io_priority
 *   from: any I/O priority or none (IOPRIO_DEFAULT)
 *   to: specified @ioprio value
 *   condition: Successful set_task_ioprio() call for the task
 *   desc: The task's I/O scheduling class and priority level transition
 *     to the value specified in @ioprio. If the task had no io_context,
 *     one is created with the new priority. If the task had an existing
 *     priority, it is overwritten.
 *
 * capability: CAP_SYS_ADMIN
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Setting I/O priority to IOPRIO_CLASS_RT (realtime class)
 *   without: IOPRIO_CLASS_RT returns EPERM unless CAP_SYS_NICE is also held
 *   condition: Checked first in ioprio_check_cap() when @ioprio class is
 *     IOPRIO_CLASS_RT, for SELinux compatibility
 *
 * capability: CAP_SYS_NICE
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: (1) Setting IOPRIO_CLASS_RT when CAP_SYS_ADMIN is not held.
 *     (2) Setting I/O priority of processes not owned by the caller.
 *   without: For RT class, EPERM if CAP_SYS_ADMIN also not held. For other
 *     processes, EPERM if target's UID doesn't match caller's real/effective
 *     UID. The ownership check compares tcred->uid with cred->euid and
 *     cred->uid.
 *   condition: Checked in ioprio_check_cap() for RT class, and in
 *     set_task_ioprio() for ownership bypass
 *
 * constraint: LSM security check
 *   desc: The security_task_setioprio() hook is called for each target task
 *     before modifying its I/O priority. LSMs like SELinux may deny the
 *     operation based on security policy (requiring PROCESS__SETSCHED
 *     permission). This check occurs after capability and ownership checks
 *     in set_task_ioprio().
 *
 * constraint: Process visibility (PID namespace)
 *   desc: For IOPRIO_WHO_PROCESS and IOPRIO_WHO_PGRP, processes are looked
 *     up using find_task_by_vpid() and find_vpid() which respect PID namespace
 *     boundaries. Only processes visible in the caller's PID namespace can
 *     be targeted. For IOPRIO_WHO_USER, task_pid_vnr() must return non-zero
 *     for a process to be affected.
 *
 * constraint: User namespace UID mapping
 *   desc: For IOPRIO_WHO_USER, the @who parameter is interpreted as a UID
 *     in the caller's user namespace via make_kuid(current_user_ns(), who).
 *     If the UID is not valid in that namespace (uid_valid() returns false),
 *     the syscall returns ESRCH.
 *
 * examples:
 *   ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4));
 *     // Set current thread to best-effort class, priority 4 (middle)
 *   ioprio_set(IOPRIO_WHO_PROCESS, pid, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 0));
 *     // Set thread 'pid' to realtime class, highest priority (requires cap)
 *   ioprio_set(IOPRIO_WHO_PGRP, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));
 *     // Set all threads in caller's process group to idle class
 *   ioprio_set(IOPRIO_WHO_PROCESS, 0, 0);
 *     // Reset to default (nice-derived) priority
 *   ioprio_set(IOPRIO_WHO_USER, 1000, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 7));
 *     // Set all processes of UID 1000 to lowest best-effort priority
 *
 * notes:
 *   - Introduced in Linux 2.6.13 by Jens Axboe as part of the CFQ I/O
 *     scheduler work.
 *   - glibc does not provide a wrapper; use syscall(SYS_ioprio_set, ...).
 *   - Despite IOPRIO_WHO_PROCESS's name, it targets individual threads, not
 *     entire thread groups. To set priority for all threads in a process,
 *     iterate through /proc/PID/task/ or use IOPRIO_WHO_PGRP.
 *   - The PF_EXITING check in set_task_ioprio() means that if a task is in
 *     the process of exiting, the ioprio is silently not set but 0 (success)
 *     is returned. This is intentional to avoid errors for racing exits
 *     (restored in commit 15583a563cd5a after temporary change to ESRCH).
 *   - For IOPRIO_WHO_PGRP and IOPRIO_WHO_USER, multiple processes may be
 *     updated. The operation is not atomic - some may succeed before an
 *     error (EPERM/EACCES/ENOMEM) occurs on another process.
 *   - I/O hints (IOPRIO_HINT_DEV_DURATION_LIMIT_*) were added in later
 *     kernels for storage devices supporting NCQ command duration limits.
 *   - The interaction with cgroups v2 I/O controller: cgroup-level I/O
 *     weights may override or interact with per-task priorities depending
 *     on kernel configuration and cgroup policy.
 *   - Historical change: Prior to 2.6.25, IOPRIO_CLASS_IDLE required
 *     CAP_SYS_ADMIN. This restriction was removed.
 *   - Historical change: CAP_SYS_NICE was added as an alternative to
 *     CAP_SYS_ADMIN for IOPRIO_CLASS_RT in kernel 5.9 (commit 9d3a39a5f1e4).
 *   - Race condition fixes: commit 40c7fd3fdfba9 added tasklist_lock for
 *     PGRP iteration; commit 8ba8682107ee2 added task_lock for io_context
 *     access to prevent use-after-free.
 *
 * since-version: 2.6.13
 */
SYSCALL_DEFINE3(ioprio_set, int, which, int, who, int, ioprio)
{
	struct task_struct *p, *g;
	struct user_struct *user;
	struct pid *pgrp;
	kuid_t uid;
	int ret;

	ret = ioprio_check_cap(ioprio);
	if (ret)
		return ret;

	ret = -ESRCH;
	rcu_read_lock();
	switch (which) {
		case IOPRIO_WHO_PROCESS:
			if (!who)
				p = current;
			else
				p = find_task_by_vpid(who);
			if (p)
				ret = set_task_ioprio(p, ioprio);
			break;
		case IOPRIO_WHO_PGRP:
			if (!who)
				pgrp = task_pgrp(current);
			else
				pgrp = find_vpid(who);

			read_lock(&tasklist_lock);
			do_each_pid_thread(pgrp, PIDTYPE_PGID, p) {
				ret = set_task_ioprio(p, ioprio);
				if (ret) {
					read_unlock(&tasklist_lock);
					goto out;
				}
			} while_each_pid_thread(pgrp, PIDTYPE_PGID, p);
			read_unlock(&tasklist_lock);

			break;
		case IOPRIO_WHO_USER:
			uid = make_kuid(current_user_ns(), who);
			if (!uid_valid(uid))
				break;
			if (!who)
				user = current_user();
			else
				user = find_user(uid);

			if (!user)
				break;

			for_each_process_thread(g, p) {
				if (!uid_eq(task_uid(p), uid) ||
				    !task_pid_vnr(p))
					continue;
				ret = set_task_ioprio(p, ioprio);
				if (ret)
					goto free_uid;
			}
free_uid:
			if (who)
				free_uid(user);
			break;
		default:
			ret = -EINVAL;
	}

out:
	rcu_read_unlock();
	return ret;
}

static int get_task_ioprio(struct task_struct *p)
{
	int ret;

	ret = security_task_getioprio(p);
	if (ret)
		goto out;
	task_lock(p);
	ret = __get_task_ioprio(p);
	task_unlock(p);
out:
	return ret;
}

/*
 * Return raw IO priority value as set by userspace. We use this for
 * ioprio_get(pid, IOPRIO_WHO_PROCESS) so that we keep historical behavior and
 * also so that userspace can distinguish unset IO priority (which just gets
 * overriden based on task's nice value) from IO priority set to some value.
 */
static int get_task_raw_ioprio(struct task_struct *p)
{
	int ret;

	ret = security_task_getioprio(p);
	if (ret)
		goto out;
	task_lock(p);
	if (p->io_context)
		ret = p->io_context->ioprio;
	else
		ret = IOPRIO_DEFAULT;
	task_unlock(p);
out:
	return ret;
}

static int ioprio_best(unsigned short aprio, unsigned short bprio)
{
	return min(aprio, bprio);
}

SYSCALL_DEFINE2(ioprio_get, int, which, int, who)
{
	struct task_struct *g, *p;
	struct user_struct *user;
	struct pid *pgrp;
	kuid_t uid;
	int ret = -ESRCH;
	int tmpio;

	rcu_read_lock();
	switch (which) {
		case IOPRIO_WHO_PROCESS:
			if (!who)
				p = current;
			else
				p = find_task_by_vpid(who);
			if (p)
				ret = get_task_raw_ioprio(p);
			break;
		case IOPRIO_WHO_PGRP:
			if (!who)
				pgrp = task_pgrp(current);
			else
				pgrp = find_vpid(who);
			read_lock(&tasklist_lock);
			do_each_pid_thread(pgrp, PIDTYPE_PGID, p) {
				tmpio = get_task_ioprio(p);
				if (tmpio < 0)
					continue;
				if (ret == -ESRCH)
					ret = tmpio;
				else
					ret = ioprio_best(ret, tmpio);
			} while_each_pid_thread(pgrp, PIDTYPE_PGID, p);
			read_unlock(&tasklist_lock);

			break;
		case IOPRIO_WHO_USER:
			uid = make_kuid(current_user_ns(), who);
			if (!who)
				user = current_user();
			else
				user = find_user(uid);

			if (!user)
				break;

			for_each_process_thread(g, p) {
				if (!uid_eq(task_uid(p), user->uid) ||
				    !task_pid_vnr(p))
					continue;
				tmpio = get_task_ioprio(p);
				if (tmpio < 0)
					continue;
				if (ret == -ESRCH)
					ret = tmpio;
				else
					ret = ioprio_best(ret, tmpio);
			}

			if (who)
				free_uid(user);
			break;
		default:
			ret = -EINVAL;
	}

	rcu_read_unlock();
	return ret;
}
