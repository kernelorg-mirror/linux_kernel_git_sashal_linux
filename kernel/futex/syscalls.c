// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/syscalls.h>
#include <linux/time_namespace.h>

#include "futex.h"

/*
 * Support for robust futexes: the kernel cleans up held futexes at
 * thread exit time.
 *
 * Implementation: user-space maintains a per-thread list of locks it
 * is holding. Upon do_exit(), the kernel carefully walks this list,
 * and marks all locks that are owned by this thread with the
 * FUTEX_OWNER_DIED bit, and wakes up a waiter (if any). The list is
 * always manipulated with the lock held, so the list is private and
 * per-thread. Userspace also maintains a per-thread 'list_op_pending'
 * field, to allow the kernel to clean up if the thread dies after
 * acquiring the lock, but just before it could have added itself to
 * the list. There can only be one such pending lock.
 */

/**
 * sys_set_robust_list - Register the robust futex list head for the calling thread
 * @head: User-space pointer to the robust list head structure
 * @len: Size of the robust_list_head structure (must equal sizeof(*head))
 *
 * long-desc: Registers a per-thread robust futex list with the kernel. This
 *   mechanism enables automatic cleanup of futex-based locks when a thread
 *   terminates abnormally (e.g., killed by a signal, segmentation fault, or
 *   explicit exit without unlocking). Without this mechanism, other threads
 *   waiting on locks held by the deceased thread would block forever.
 *
 *   The robust futex list is a user-space linked list that threads use to
 *   track which futex locks they currently hold. The kernel does not modify
 *   this list during normal operation - it only reads and processes the list
 *   when the thread exits.
 *
 *   The robust_list_head structure contains three fields:
 *   1. list.next: Pointer to the first robust_list entry (or back to itself
 *      if empty). The low bit indicates PI futex when set.
 *   2. futex_offset: Byte offset from each list entry to its futex word
 *   3. list_op_pending: Transient pointer to lock being acquired/released
 *
 *   When a thread exits (via do_exit()), the kernel walks the robust list
 *   and for each entry where the futex word's TID matches the dying thread:
 *   1. Sets the FUTEX_OWNER_DIED bit (0x40000000) in the futex word
 *   2. If FUTEX_WAITERS bit (0x80000000) is set, wakes one waiting thread
 *   3. Also processes list_op_pending to catch in-flight lock acquisitions
 *
 *   The kernel limits processing to ROBUST_LIST_LIMIT (2048) entries to
 *   prevent infinite loops on circular or maliciously crafted lists. This
 *   limit protects against denial-of-service attacks.
 *
 *   User-space protocol for lock acquisition:
 *   1. Set list_op_pending to the lock entry address
 *   2. Acquire the futex lock (set futex word to TID)
 *   3. Add the entry to the linked list
 *   4. Clear list_op_pending
 *
 *   User-space protocol for lock release:
 *   1. Set list_op_pending to the lock entry address
 *   2. Remove the entry from the linked list
 *   3. Release the futex lock (clear futex word)
 *   4. Clear list_op_pending
 *
 *   This syscall only stores the pointer; the actual list processing
 *   happens at thread exit time in exit_robust_list(). The pointer is not
 *   validated during this syscall - invalid pointers will cause the list
 *   walk to abort silently at exit time.
 *
 *   A compat version exists for 32-bit processes on 64-bit kernels, storing
 *   the pointer in current->compat_robust_list instead.
 *
 * context-flags: KAPI_CTX_PROCESS
 *
 * param: head
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: User-space pointer to a struct robust_list_head, or NULL
 *     to disable robust futex handling for this thread. The pointer is
 *     stored without validation. If NULL, the robust list mechanism is
 *     effectively disabled (exit_robust_list returns early). The structure
 *     must remain valid and accessible in user memory until thread exit.
 *     Invalid pointers cause silent failures during exit processing.
 *
 * param: len
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must exactly equal sizeof(struct robust_list_head). On
 *     64-bit systems this is typically 24 bytes (3 x 8-byte words). On
 *     32-bit systems this is 12 bytes (3 x 4-byte words). This size check
 *     provides versioning - if the structure size changes in future kernel
 *     versions, old binaries will fail gracefully with EINVAL rather than
 *     causing memory corruption.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success, indicating the robust list head pointer
 *     has been stored in the calling thread's task_struct. The previously
 *     registered head (if any) is silently replaced.
 *
 * error: EINVAL, Invalid structure size
 *   desc: The len parameter does not match sizeof(struct robust_list_head).
 *     This indicates a version mismatch between user-space and the kernel,
 *     or an incorrect size value passed by the application. The robust list
 *     head is not modified when this error occurs.
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: current->robust_list
 *   desc: Stores the head pointer in the calling thread's task_struct. The
 *     previous value is overwritten without any cleanup or notification.
 *     This pointer is read during thread exit to process the robust list.
 *   reversible: yes
 *   condition: When len == sizeof(struct robust_list_head)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: User memory futex words (deferred)
 *   desc: At thread exit time (not during this syscall), the kernel walks
 *     the robust list and modifies futex words for locks held by the dying
 *     thread. For each held lock, FUTEX_OWNER_DIED (0x40000000) is set in
 *     the 32-bit futex word via atomic cmpxchg. This is a deferred side
 *     effect occurring in exit_robust_list() during do_exit().
 *   reversible: no
 *   condition: Thread exits with non-empty robust list
 *
 * side-effect: KAPI_EFFECT_SIGNAL_SEND
 *   target: Futex waiters (deferred)
 *   desc: At thread exit time, for each robust futex that had the
 *     FUTEX_WAITERS bit set, the kernel performs futex_wake() to wake one
 *     waiting thread. The woken thread sees FUTEX_OWNER_DIED set and can
 *     take appropriate action (typically acquire the lock and recover).
 *   reversible: no
 *   condition: Thread exits holding futexes with waiters
 *
 * state-trans: current->robust_list
 *   from: previous value (NULL or valid pointer)
 *   to: head parameter value
 *   condition: When len == sizeof(struct robust_list_head)
 *   desc: The robust_list field is unconditionally set to the new value.
 *     Setting NULL effectively disables robust futex handling for the
 *     thread. There is no reference counting or cleanup of old values.
 *
 * constraint: Structure size versioning
 *   desc: The len parameter provides ABI versioning. If the kernel's
 *     robust_list_head structure changes size in future versions, older
 *     binaries compiled against the previous size will fail with EINVAL.
 *     This prevents memory corruption from mismatched structures.
 *   expr: len == sizeof(struct robust_list_head)
 *
 * constraint: List entry limit
 *   desc: The kernel processes at most ROBUST_LIST_LIMIT (2048) entries
 *     from the robust list at exit time. This limit protects against
 *     infinite loops caused by circular lists (malicious or accidental)
 *     and denial-of-service attacks. Excess entries are silently ignored.
 *
 * constraint: Memory validity at exit
 *   desc: The head pointer and all list entries must point to valid,
 *     readable user memory at thread exit time. If any pointer is invalid,
 *     the kernel silently aborts list processing at that point. The
 *     futex_offset must also produce valid addresses when added to list
 *     entry addresses.
 *
 * constraint: Futex word alignment
 *   desc: The futex word (32-bit integer at list_entry + futex_offset)
 *     must be naturally aligned (4-byte aligned). Unaligned accesses cause
 *     handle_futex_death() to return early, skipping that entry.
 *
 * examples: struct robust_list_head head;
 *   head.list.next = &head.list;  // Empty list points to self
 *   head.futex_offset = offsetof(struct my_lock, futex) -
 *                       offsetof(struct my_lock, list);
 *   head.list_op_pending = NULL;
 *   syscall(SYS_set_robust_list, &head, sizeof(head));  // Register
 *   syscall(SYS_set_robust_list, NULL, sizeof(head));  // Disable
 *
 * notes: This syscall is not intended for direct application use. Instead,
 *   applications should use glibc's robust mutex implementation via
 *   pthread_mutexattr_setrobust(). glibc provides no wrapper function for
 *   this syscall; direct invocation requires syscall(2).
 *
 *   A thread can have only one robust futex list at a time. Each call to
 *   set_robust_list() replaces any previously registered list head.
 *
 *   The robust list mechanism was introduced to solve a long-standing
 *   problem with futex-based locks: if a thread holding a lock terminates
 *   unexpectedly (SIGKILL, segfault, etc.), other threads waiting for that
 *   lock would hang indefinitely. Prior to robust futexes, a system reboot
 *   was often required to recover from such situations (famously affecting
 *   package managers like yum).
 *
 *   During execve(), the robust_list pointer is NOT cleared by default.
 *   A security fix (commit 6b54082c3ed4d) added exec_update_lock protection
 *   to get_robust_list() to prevent leaking the pointer across privilege
 *   boundaries during exec races.
 *
 *   The kernel silently ignores errors during exit-time list processing:
 *   - Invalid user pointers cause immediate abort of list walking
 *   - Unaligned futex words are skipped
 *   - Futex words not owned by the dying thread are skipped
 *   - cmpxchg failures are retried; persistent failures cause abort
 *
 *   PI (Priority Inheritance) futexes are indicated by setting bit 0 in
 *   the list entry's next pointer. The kernel handles PI futexes specially
 *   during exit, coordinating with the PI state cleanup in exit_pi_state_list().
 *
 *   Corner cases:
 *   - NULL head: Valid, disables robust futex handling
 *   - Zero len: Returns -EINVAL
 *   - Wrong len: Returns -EINVAL (ABI protection)
 *   - Invalid head pointer: Stored anyway; fails silently at exit
 *   - Empty list (head->list.next == &head->list): No locks processed
 *   - Circular list: Kernel stops after 2048 iterations
 *   - Thread exits before adding lock to list: list_op_pending catches it
 *
 * since-version: 2.6.17
 */
SYSCALL_DEFINE2(set_robust_list, struct robust_list_head __user *, head,
		size_t, len)
{
	/*
	 * The kernel knows only one size for now:
	 */
	if (unlikely(len != sizeof(*head)))
		return -EINVAL;

	current->robust_list = head;

	return 0;
}

static inline void __user *futex_task_robust_list(struct task_struct *p, bool compat)
{
#ifdef CONFIG_COMPAT
	if (compat)
		return p->compat_robust_list;
#endif
	return p->robust_list;
}

static void __user *futex_get_robust_list_common(int pid, bool compat)
{
	struct task_struct *p = current;
	void __user *head;
	int ret;

	scoped_guard(rcu) {
		if (pid) {
			p = find_task_by_vpid(pid);
			if (!p)
				return (void __user *)ERR_PTR(-ESRCH);
		}
		get_task_struct(p);
	}

	/*
	 * Hold exec_update_lock to serialize with concurrent exec()
	 * so ptrace_may_access() is checked against stable credentials
	 */
	ret = down_read_killable(&p->signal->exec_update_lock);
	if (ret)
		goto err_put;

	ret = -EPERM;
	if (!ptrace_may_access(p, PTRACE_MODE_READ_REALCREDS))
		goto err_unlock;

	head = futex_task_robust_list(p, compat);

	up_read(&p->signal->exec_update_lock);
	put_task_struct(p);

	return head;

err_unlock:
	up_read(&p->signal->exec_update_lock);
err_put:
	put_task_struct(p);
	return (void __user *)ERR_PTR(ret);
}

/**
 * sys_get_robust_list - Retrieve the robust futex list head of a thread
 * @pid: Thread ID to query, or 0 for the calling thread
 * @head_ptr: User pointer where the list head address will be stored
 * @len_ptr: User pointer where the list head structure size will be stored
 *
 * long-desc: Retrieves the robust futex list head pointer previously
 *   registered by a thread via set_robust_list(). This syscall is primarily
 *   used for debugging, inspection, and process introspection tools.
 *
 *   When pid is 0, returns the calling thread's own robust list head. When
 *   pid is non-zero, it specifies the thread ID (TID) of the target thread.
 *   Thread IDs are kernel thread IDs as returned by clone(2) or gettid(2),
 *   not process IDs (PIDs).
 *
 *   On success, two values are written to user space:
 *   1. The robust list head pointer is written to *head_ptr. This may be
 *      NULL if the thread never called set_robust_list() or explicitly
 *      registered NULL.
 *   2. The size of the robust_list_head structure is written to *len_ptr.
 *      This is always sizeof(struct robust_list_head) for the kernel version,
 *      providing ABI versioning information.
 *
 *   Access to another thread's robust list requires passing a ptrace access
 *   check with PTRACE_MODE_READ_REALCREDS. This means:
 *   1. The caller must have matching real UID/GID credentials with the target
 *      (comparing real UID against target's real, effective, and saved UIDs,
 *      and similarly for GIDs), OR
 *   2. The caller must have CAP_SYS_PTRACE capability in the target's user
 *      namespace, OR
 *   3. The target process must be dumpable (SUID_DUMP_USER) and the caller
 *      must have CAP_SYS_PTRACE in the target's mm user namespace.
 *
 *   Additionally, Linux Security Modules (AppArmor, SELinux, Landlock) may
 *   impose further restrictions on ptrace access.
 *
 *   The syscall holds signal->exec_update_lock during the permission check
 *   and pointer retrieval to prevent race conditions with concurrent exec()
 *   operations that might change the target's credentials.
 *
 *   A compat version exists for 32-bit processes on 64-bit kernels. The
 *   compat version retrieves compat_robust_list (12 bytes) instead of
 *   robust_list (24 bytes on 64-bit), and writes a compat pointer.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: pid
 *   type: KAPI_TYPE_INT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Thread ID of the target thread. Use 0 to query the calling
 *     thread's own robust list (no permission check required). Non-zero
 *     values specify a kernel thread ID (TID) as returned by clone(2) or
 *     gettid(2). The TID must refer to an existing thread visible in the
 *     caller's PID namespace; otherwise ESRCH is returned. Negative values
 *     are treated as invalid TIDs and will return ESRCH.
 *
 * param: head_ptr
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Must point to valid, writable user memory capable of storing
 *     a pointer (8 bytes on 64-bit, 4 bytes on 32-bit systems). The kernel
 *     writes the target thread's robust_list head pointer to this location.
 *     The written value may be NULL if the target never registered a robust
 *     list. Cannot be NULL; passing NULL causes EFAULT.
 *
 * param: len_ptr
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_NONE
 *   constraint: Must point to valid, writable user memory capable of storing
 *     a size_t (8 bytes on 64-bit, 4 bytes on 32-bit systems). The kernel
 *     writes sizeof(struct robust_list_head) to this location, providing
 *     ABI version information. Cannot be NULL; passing NULL causes EFAULT.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: 0
 *   desc: Returns 0 on success, indicating that *head_ptr contains the
 *     target thread's robust list head pointer and *len_ptr contains the
 *     structure size. The head pointer may be NULL if no robust list was
 *     registered.
 *
 * error: ESRCH, No such thread
 *   desc: No thread with the specified pid exists in the caller's PID
 *     namespace. This includes the case where pid refers to a process that
 *     has already exited, a TID that never existed, or a TID in a different
 *     PID namespace not visible to the caller.
 *
 * error: EPERM, Permission denied
 *   desc: The caller lacks permission to access the target thread's robust
 *     list. This occurs when pid is non-zero (querying another thread) and
 *     the ptrace access check fails. Permission is denied if: (1) the
 *     caller's real UID/GID credentials do not match the target's real,
 *     effective, and saved UID/GID, AND (2) the caller lacks CAP_SYS_PTRACE
 *     capability, AND (3) either the target is not dumpable or the caller
 *     lacks CAP_SYS_PTRACE in the target mm's user namespace. LSM modules
 *     (SELinux, AppArmor, Landlock) may also deny access based on their
 *     policies.
 *
 * error: EFAULT, Bad address
 *   desc: Either head_ptr or len_ptr points to memory that cannot be
 *     written. This can occur if the pointers are NULL, point to unmapped
 *     memory, or point to read-only memory. The put_user() operation fails
 *     and the syscall returns immediately.
 *
 * error: EINTR, Interrupted by signal
 *   desc: A fatal signal (SIGKILL or SIGSTOP) was received while waiting
 *     to acquire the exec_update_lock semaphore. This can occur when pid
 *     is non-zero and the target thread is concurrently executing exec().
 *     The syscall should not be automatically restarted as the operation
 *     was not started.
 *
 * lock: RCU read lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: Held briefly while looking up the target task by PID via
 *     find_task_by_vpid() and incrementing its reference count. The lock
 *     is acquired and released using scoped_guard(rcu).
 *
 * lock: signal->exec_update_lock
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: Read semaphore acquired on the target task's signal structure
 *     before performing the ptrace access check and reading robust_list.
 *     This serializes with concurrent exec() operations to prevent race
 *     conditions where credentials change during the access check. Acquired
 *     via down_read_killable(), which can return -EINTR on fatal signals.
 *     Always released before returning, even on error paths.
 *
 * lock: task->alloc_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Spinlock acquired indirectly via task_lock() inside
 *     ptrace_may_access() when checking credentials. Protects reading of
 *     task credentials during the permission check.
 *
 * signal: SIGKILL
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_RETURN
 *   condition: While blocked on exec_update_lock acquisition
 *   desc: If a fatal signal (SIGKILL or SIGSTOP) arrives while waiting
 *     for the exec_update_lock, the syscall aborts and returns -EINTR.
 *     The down_read_killable() function uses TASK_KILLABLE state, making
 *     it interruptible only by fatal signals, not by normal signals.
 *   error: -EINTR
 *   timing: KAPI_SIGNAL_TIME_DURING
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_NONE
 *   target: User memory at head_ptr and len_ptr
 *   desc: On success, writes two values to user memory: the robust list
 *     head pointer to *head_ptr and sizeof(struct robust_list_head) to
 *     *len_ptr. These are read-only operations on kernel state with
 *     write-only effects on user space. No kernel state is modified.
 *   reversible: yes
 *   condition: Always on success
 *
 * capability: CAP_SYS_PTRACE
 *   type: KAPI_CAP_BYPASS_CHECK
 *   allows: Access to any thread's robust list regardless of credential
 *     matching or dumpability status
 *   without: Must have matching credentials with target (real UID/GID
 *     must match target's real/effective/saved UID/GID) and target must
 *     be dumpable
 *   condition: Checked when pid is non-zero (querying another thread)
 *
 * constraint: PID namespace visibility
 *   desc: The pid parameter is interpreted within the caller's PID
 *     namespace. Threads in child or sibling PID namespaces may have
 *     different apparent PIDs. A pid value valid in one namespace may
 *     refer to a different thread or no thread in another namespace.
 *
 * constraint: Credential stability
 *   desc: The exec_update_lock ensures that the target's credentials are
 *     stable during the permission check. Without this lock, a race with
 *     exec() could allow access based on pre-exec credentials to a
 *     post-exec privileged process, potentially leaking sensitive
 *     information.
 *
 * constraint: LSM policy
 *   desc: Linux Security Modules may impose additional restrictions
 *     beyond standard credential checks. AppArmor, SELinux, and Landlock
 *     all implement ptrace_access_check hooks that can deny access based
 *     on their configured policies, returning -EPERM.
 *
 * examples: struct robust_list_head *head;
 *   size_t len;
 *   int ret;
 *   // Get own robust list
 *   ret = syscall(SYS_get_robust_list, 0, &head, &len);
 *   if (ret == 0) printf("head=%p, len=%zu\n", head, len);
 *   // Get another thread's robust list (requires permission)
 *   ret = syscall(SYS_get_robust_list, tid, &head, &len);
 *   if (ret == -1 && errno == EPERM) printf("access denied\n");
 *
 * notes: This syscall is not intended for normal application use.
 *   Applications should use glibc's robust mutex implementation via
 *   pthread_mutexattr_setrobust(). glibc does not provide a wrapper
 *   function; direct invocation requires syscall(2).
 *
 *   The returned pointer may be stale if the target thread concurrently
 *   calls set_robust_list() after this syscall retrieves the value. There
 *   is no atomic "get and lock" operation.
 *
 *   For 32-bit processes on 64-bit kernels, the compat syscall version
 *   (compat_sys_get_robust_list) retrieves compat_robust_list instead,
 *   which is 12 bytes vs 24 bytes. The len_ptr value reflects this.
 *
 *   A security fix in kernel 6.x added exec_update_lock protection to
 *   prevent leaking robust_list pointers across privilege boundaries
 *   during exec() races. Prior kernels had a TOCTOU vulnerability where
 *   an attacker could read post-exec addresses from a setuid process.
 *
 *   The syscall was briefly deprecated in 2012 (marked for removal) due
 *   to security concerns, but the deprecation was reverted because the
 *   syscall was in active use and the security issues were addressed by
 *   the permission checks.
 *
 *   Corner cases:
 *   - pid=0: Returns caller's own list, no permission check needed
 *   - pid=caller's own TID: Treated same as pid=0 functionally, but does
 *     go through find_task_by_vpid and permission check (which passes)
 *   - head_ptr/len_ptr=NULL: Returns -EFAULT
 *   - Target never called set_robust_list: Returns NULL in *head_ptr
 *   - Target thread exiting: Returns -ESRCH if already reaped
 *   - Target execing: May block on exec_update_lock, returns -EINTR if
 *     killed while waiting
 *
 * since-version: 2.6.17
 */
SYSCALL_DEFINE3(get_robust_list, int, pid,
		struct robust_list_head __user * __user *, head_ptr,
		size_t __user *, len_ptr)
{
	struct robust_list_head __user *head = futex_get_robust_list_common(pid, false);

	if (IS_ERR(head))
		return PTR_ERR(head);

	if (put_user(sizeof(*head), len_ptr))
		return -EFAULT;
	return put_user(head, head_ptr);
}

long do_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
		u32 __user *uaddr2, u32 val2, u32 val3)
{
	unsigned int flags = futex_to_flags(op);
	int cmd = op & FUTEX_CMD_MASK;

	if (flags & FLAGS_CLOCKRT) {
		if (cmd != FUTEX_WAIT_BITSET &&
		    cmd != FUTEX_WAIT_REQUEUE_PI &&
		    cmd != FUTEX_LOCK_PI2)
			return -ENOSYS;
	}

	switch (cmd) {
	case FUTEX_WAIT:
		val3 = FUTEX_BITSET_MATCH_ANY;
		fallthrough;
	case FUTEX_WAIT_BITSET:
		return futex_wait(uaddr, flags, val, timeout, val3);
	case FUTEX_WAKE:
		val3 = FUTEX_BITSET_MATCH_ANY;
		fallthrough;
	case FUTEX_WAKE_BITSET:
		return futex_wake(uaddr, flags, val, val3);
	case FUTEX_REQUEUE:
		return futex_requeue(uaddr, flags, uaddr2, flags, val, val2, NULL, 0);
	case FUTEX_CMP_REQUEUE:
		return futex_requeue(uaddr, flags, uaddr2, flags, val, val2, &val3, 0);
	case FUTEX_WAKE_OP:
		return futex_wake_op(uaddr, flags, uaddr2, val, val2, val3);
	case FUTEX_LOCK_PI:
		flags |= FLAGS_CLOCKRT;
		fallthrough;
	case FUTEX_LOCK_PI2:
		return futex_lock_pi(uaddr, flags, timeout, 0);
	case FUTEX_UNLOCK_PI:
		return futex_unlock_pi(uaddr, flags);
	case FUTEX_TRYLOCK_PI:
		return futex_lock_pi(uaddr, flags, NULL, 1);
	case FUTEX_WAIT_REQUEUE_PI:
		val3 = FUTEX_BITSET_MATCH_ANY;
		return futex_wait_requeue_pi(uaddr, flags, val, timeout, val3,
					     uaddr2);
	case FUTEX_CMP_REQUEUE_PI:
		return futex_requeue(uaddr, flags, uaddr2, flags, val, val2, &val3, 1);
	}
	return -ENOSYS;
}

static __always_inline bool futex_cmd_has_timeout(u32 cmd)
{
	switch (cmd) {
	case FUTEX_WAIT:
	case FUTEX_LOCK_PI:
	case FUTEX_LOCK_PI2:
	case FUTEX_WAIT_BITSET:
	case FUTEX_WAIT_REQUEUE_PI:
		return true;
	}
	return false;
}

static __always_inline int
futex_init_timeout(u32 cmd, u32 op, struct timespec64 *ts, ktime_t *t)
{
	if (!timespec64_valid(ts))
		return -EINVAL;

	*t = timespec64_to_ktime(*ts);
	if (cmd == FUTEX_WAIT)
		*t = ktime_add_safe(ktime_get(), *t);
	else if (cmd != FUTEX_LOCK_PI && !(op & FUTEX_CLOCK_REALTIME))
		*t = timens_ktime_to_host(CLOCK_MONOTONIC, *t);
	return 0;
}

SYSCALL_DEFINE6(futex, u32 __user *, uaddr, int, op, u32, val,
		const struct __kernel_timespec __user *, utime,
		u32 __user *, uaddr2, u32, val3)
{
	int ret, cmd = op & FUTEX_CMD_MASK;
	ktime_t t, *tp = NULL;
	struct timespec64 ts;

	if (utime && futex_cmd_has_timeout(cmd)) {
		if (unlikely(should_fail_futex(!(op & FUTEX_PRIVATE_FLAG))))
			return -EFAULT;
		if (get_timespec64(&ts, utime))
			return -EFAULT;
		ret = futex_init_timeout(cmd, op, &ts, &t);
		if (ret)
			return ret;
		tp = &t;
	}

	return do_futex(uaddr, op, val, tp, uaddr2, (unsigned long)utime, val3);
}

/**
 * futex_parse_waitv - Parse a waitv array from userspace
 * @futexv:	Kernel side list of waiters to be filled
 * @uwaitv:     Userspace list to be parsed
 * @nr_futexes: Length of futexv
 * @wake:	Wake to call when futex is woken
 * @wake_data:	Data for the wake handler
 *
 * Return: Error code on failure, 0 on success
 */
int futex_parse_waitv(struct futex_vector *futexv,
		      struct futex_waitv __user *uwaitv,
		      unsigned int nr_futexes, futex_wake_fn *wake,
		      void *wake_data)
{
	struct futex_waitv aux;
	unsigned int i;

	for (i = 0; i < nr_futexes; i++) {
		unsigned int flags;

		if (copy_from_user(&aux, &uwaitv[i], sizeof(aux)))
			return -EFAULT;

		if ((aux.flags & ~FUTEX2_VALID_MASK) || aux.__reserved)
			return -EINVAL;

		flags = futex2_to_flags(aux.flags);
		if (!futex_flags_valid(flags))
			return -EINVAL;

		if (!futex_validate_input(flags, aux.val))
			return -EINVAL;

		futexv[i].w.flags = flags;
		futexv[i].w.val = aux.val;
		futexv[i].w.uaddr = aux.uaddr;
		futexv[i].q = futex_q_init;
		futexv[i].q.wake = wake;
		futexv[i].q.wake_data = wake_data;
	}

	return 0;
}

static int futex2_setup_timeout(struct __kernel_timespec __user *timeout,
				clockid_t clockid, struct hrtimer_sleeper *to)
{
	int flag_clkid = 0, flag_init = 0;
	struct timespec64 ts;
	ktime_t time;
	int ret;

	if (!timeout)
		return 0;

	if (clockid == CLOCK_REALTIME) {
		flag_clkid = FLAGS_CLOCKRT;
		flag_init = FUTEX_CLOCK_REALTIME;
	}

	if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
		return -EINVAL;

	if (get_timespec64(&ts, timeout))
		return -EFAULT;

	/*
	 * Since there's no opcode for futex_waitv, use
	 * FUTEX_WAIT_BITSET that uses absolute timeout as well
	 */
	ret = futex_init_timeout(FUTEX_WAIT_BITSET, flag_init, &ts, &time);
	if (ret)
		return ret;

	futex_setup_timer(&time, to, flag_clkid, 0);
	return 0;
}

static inline void futex2_destroy_timeout(struct hrtimer_sleeper *to)
{
	hrtimer_cancel(&to->timer);
	destroy_hrtimer_on_stack(&to->timer);
}

/**
 * sys_futex_waitv - Wait on a list of futexes
 * @waiters:    List of futexes to wait on
 * @nr_futexes: Length of futexv
 * @flags:      Flag for timeout (monotonic/realtime)
 * @timeout:	Optional absolute timeout.
 * @clockid:	Clock to be used for the timeout, realtime or monotonic.
 *
 * Given an array of `struct futex_waitv`, wait on each uaddr. The thread wakes
 * if a futex_wake() is performed at any uaddr. The syscall returns immediately
 * if any waiter has *uaddr != val. *timeout is an optional timeout value for
 * the operation. Each waiter has individual flags. The `flags` argument for
 * the syscall should be used solely for specifying the timeout as realtime, if
 * needed. Flags for private futexes, sizes, etc. should be used on the
 * individual flags of each waiter.
 *
 * Returns the array index of one of the woken futexes. No further information
 * is provided: any number of other futexes may also have been woken by the
 * same event, and if more than one futex was woken, the retrned index may
 * refer to any one of them. (It is not necessaryily the futex with the
 * smallest index, nor the one most recently woken, nor...)
 */

SYSCALL_DEFINE5(futex_waitv, struct futex_waitv __user *, waiters,
		unsigned int, nr_futexes, unsigned int, flags,
		struct __kernel_timespec __user *, timeout, clockid_t, clockid)
{
	struct hrtimer_sleeper to;
	struct futex_vector *futexv;
	int ret;

	/* This syscall supports no flags for now */
	if (flags)
		return -EINVAL;

	if (!nr_futexes || nr_futexes > FUTEX_WAITV_MAX || !waiters)
		return -EINVAL;

	if (timeout && (ret = futex2_setup_timeout(timeout, clockid, &to)))
		return ret;

	futexv = kcalloc(nr_futexes, sizeof(*futexv), GFP_KERNEL);
	if (!futexv) {
		ret = -ENOMEM;
		goto destroy_timer;
	}

	ret = futex_parse_waitv(futexv, waiters, nr_futexes, futex_wake_mark,
				NULL);
	if (!ret)
		ret = futex_wait_multiple(futexv, nr_futexes, timeout ? &to : NULL);

	kfree(futexv);

destroy_timer:
	if (timeout)
		futex2_destroy_timeout(&to);
	return ret;
}

/*
 * sys_futex_wake - Wake a number of futexes
 * @uaddr:	Address of the futex(es) to wake
 * @mask:	bitmask
 * @nr:		Number of the futexes to wake
 * @flags:	FUTEX2 flags
 *
 * Identical to the traditional FUTEX_WAKE_BITSET op, except it is part of the
 * futex2 family of calls.
 */

SYSCALL_DEFINE4(futex_wake,
		void __user *, uaddr,
		unsigned long, mask,
		int, nr,
		unsigned int, flags)
{
	if (flags & ~FUTEX2_VALID_MASK)
		return -EINVAL;

	flags = futex2_to_flags(flags);
	if (!futex_flags_valid(flags))
		return -EINVAL;

	if (!futex_validate_input(flags, mask))
		return -EINVAL;

	return futex_wake(uaddr, FLAGS_STRICT | flags, nr, mask);
}

/*
 * sys_futex_wait - Wait on a futex
 * @uaddr:	Address of the futex to wait on
 * @val:	Value of @uaddr
 * @mask:	bitmask
 * @flags:	FUTEX2 flags
 * @timeout:	Optional absolute timeout
 * @clockid:	Clock to be used for the timeout, realtime or monotonic
 *
 * Identical to the traditional FUTEX_WAIT_BITSET op, except it is part of the
 * futex2 familiy of calls.
 */

SYSCALL_DEFINE6(futex_wait,
		void __user *, uaddr,
		unsigned long, val,
		unsigned long, mask,
		unsigned int, flags,
		struct __kernel_timespec __user *, timeout,
		clockid_t, clockid)
{
	struct hrtimer_sleeper to;
	int ret;

	if (flags & ~FUTEX2_VALID_MASK)
		return -EINVAL;

	flags = futex2_to_flags(flags);
	if (!futex_flags_valid(flags))
		return -EINVAL;

	if (!futex_validate_input(flags, val) ||
	    !futex_validate_input(flags, mask))
		return -EINVAL;

	if (timeout && (ret = futex2_setup_timeout(timeout, clockid, &to)))
		return ret;

	ret = __futex_wait(uaddr, flags, val, timeout ? &to : NULL, mask);

	if (timeout)
		futex2_destroy_timeout(&to);

	return ret;
}

/*
 * sys_futex_requeue - Requeue a waiter from one futex to another
 * @waiters:	array describing the source and destination futex
 * @flags:	unused
 * @nr_wake:	number of futexes to wake
 * @nr_requeue:	number of futexes to requeue
 *
 * Identical to the traditional FUTEX_CMP_REQUEUE op, except it is part of the
 * futex2 family of calls.
 */

SYSCALL_DEFINE4(futex_requeue,
		struct futex_waitv __user *, waiters,
		unsigned int, flags,
		int, nr_wake,
		int, nr_requeue)
{
	struct futex_vector futexes[2];
	u32 cmpval;
	int ret;

	if (flags)
		return -EINVAL;

	if (!waiters)
		return -EINVAL;

	ret = futex_parse_waitv(futexes, waiters, 2, futex_wake_mark, NULL);
	if (ret)
		return ret;

	cmpval = futexes[0].w.val;

	return futex_requeue(u64_to_user_ptr(futexes[0].w.uaddr), futexes[0].w.flags,
			     u64_to_user_ptr(futexes[1].w.uaddr), futexes[1].w.flags,
			     nr_wake, nr_requeue, &cmpval, 0);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(set_robust_list,
		struct compat_robust_list_head __user *, head,
		compat_size_t, len)
{
	if (unlikely(len != sizeof(*head)))
		return -EINVAL;

	current->compat_robust_list = head;

	return 0;
}

COMPAT_SYSCALL_DEFINE3(get_robust_list, int, pid,
			compat_uptr_t __user *, head_ptr,
			compat_size_t __user *, len_ptr)
{
	struct compat_robust_list_head __user *head = futex_get_robust_list_common(pid, true);

	if (IS_ERR(head))
		return PTR_ERR(head);

	if (put_user(sizeof(*head), len_ptr))
		return -EFAULT;
	return put_user(ptr_to_compat(head), head_ptr);
}
#endif /* CONFIG_COMPAT */

#ifdef CONFIG_COMPAT_32BIT_TIME
SYSCALL_DEFINE6(futex_time32, u32 __user *, uaddr, int, op, u32, val,
		const struct old_timespec32 __user *, utime, u32 __user *, uaddr2,
		u32, val3)
{
	int ret, cmd = op & FUTEX_CMD_MASK;
	ktime_t t, *tp = NULL;
	struct timespec64 ts;

	if (utime && futex_cmd_has_timeout(cmd)) {
		if (get_old_timespec32(&ts, utime))
			return -EFAULT;
		ret = futex_init_timeout(cmd, op, &ts, &t);
		if (ret)
			return ret;
		tp = &t;
	}

	return do_futex(uaddr, op, val, tp, uaddr2, (unsigned long)utime, val3);
}
#endif /* CONFIG_COMPAT_32BIT_TIME */

