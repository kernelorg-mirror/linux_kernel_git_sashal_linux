// SPDX-License-Identifier: GPL-2.0
/*
 * linux/kernel/capability.c
 *
 * Copyright (C) 1997  Andrew Main <zefram@fysh.org>
 *
 * Integrated into 2.1.97+,  Andrew G. Morgan <morgan@kernel.org>
 * 30 May 2002:	Cleanup, Robert M. Love <rml@tech9.net>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/uaccess.h>

int file_caps_enabled = 1;

static int __init file_caps_disable(char *str)
{
	file_caps_enabled = 0;
	return 1;
}
__setup("no_file_caps", file_caps_disable);

#ifdef CONFIG_MULTIUSER
/*
 * More recent versions of libcap are available from:
 *
 *   http://www.kernel.org/pub/linux/libs/security/linux-privs/
 */

static void warn_legacy_capability_use(void)
{
	pr_info_once("warning: `%s' uses 32-bit capabilities (legacy support in use)\n",
		     current->comm);
}

/*
 * Version 2 capabilities worked fine, but the linux/capability.h file
 * that accompanied their introduction encouraged their use without
 * the necessary user-space source code changes. As such, we have
 * created a version 3 with equivalent functionality to version 2, but
 * with a header change to protect legacy source code from using
 * version 2 when it wanted to use version 1. If your system has code
 * that trips the following warning, it is using version 2 specific
 * capabilities and may be doing so insecurely.
 *
 * The remedy is to either upgrade your version of libcap (to 2.10+,
 * if the application is linked against it), or recompile your
 * application with modern kernel headers and this warning will go
 * away.
 */

static void warn_deprecated_v2(void)
{
	pr_info_once("warning: `%s' uses deprecated v2 capabilities in a way that may be insecure\n",
		     current->comm);
}

/*
 * Version check. Return the number of u32s in each capability flag
 * array, or a negative value on error.
 */
static int cap_validate_magic(cap_user_header_t header, unsigned *tocopy)
{
	__u32 version;

	if (get_user(version, &header->version))
		return -EFAULT;

	switch (version) {
	case _LINUX_CAPABILITY_VERSION_1:
		warn_legacy_capability_use();
		*tocopy = _LINUX_CAPABILITY_U32S_1;
		break;
	case _LINUX_CAPABILITY_VERSION_2:
		warn_deprecated_v2();
		fallthrough;	/* v3 is otherwise equivalent to v2 */
	case _LINUX_CAPABILITY_VERSION_3:
		*tocopy = _LINUX_CAPABILITY_U32S_3;
		break;
	default:
		if (put_user((u32)_KERNEL_CAPABILITY_VERSION, &header->version))
			return -EFAULT;
		return -EINVAL;
	}

	return 0;
}

/*
 * The only thing that can change the capabilities of the current
 * process is the current process. As such, we can't be in this code
 * at the same time as we are in the process of setting capabilities
 * in this process. The net result is that we can limit our use of
 * locks to when we are reading the caps of another process.
 */
static inline int cap_get_target_pid(pid_t pid, kernel_cap_t *pEp,
				     kernel_cap_t *pIp, kernel_cap_t *pPp)
{
	int ret;

	if (pid && (pid != task_pid_vnr(current))) {
		const struct task_struct *target;

		rcu_read_lock();

		target = find_task_by_vpid(pid);
		if (!target)
			ret = -ESRCH;
		else
			ret = security_capget(target, pEp, pIp, pPp);

		rcu_read_unlock();
	} else
		ret = security_capget(current, pEp, pIp, pPp);

	return ret;
}

/**
 * sys_capget - Get the capability sets of a process
 * @header: Pointer to user-space structure containing protocol version
 *	and target process ID
 * @dataptr: Pointer to user-space structure(s) to receive capability data
 *
 * long-desc: Retrieves the effective, permitted, and inheritable capability
 *   sets of a specified process. Linux capabilities provide a mechanism for
 *   partitioning the privileges traditionally associated with superuser (root)
 *   into distinct units that can be independently enabled and disabled.
 *
 *   The @header parameter points to a cap_user_header_t structure that
 *   contains:
 *   - version: A magic number indicating the capability protocol version.
 *     Must be _LINUX_CAPABILITY_VERSION_1 (0x19980330),
 *     _LINUX_CAPABILITY_VERSION_2 (0x20071026, deprecated), or
 *     _LINUX_CAPABILITY_VERSION_3 (0x20080522, preferred).
 *   - pid: The process ID whose capabilities are to be retrieved, or 0
 *     to query the calling thread's own capabilities.
 *
 *   The @dataptr parameter points to one or two cap_user_data_t structures
 *   (depending on the protocol version) that receive the capability sets:
 *   - effective: Capabilities currently in effect for the process
 *   - permitted: Capabilities the process is allowed to assume
 *   - inheritable: Capabilities preserved across execve()
 *
 *   Version 1 supports only the first 32 capabilities and requires a single
 *   __user_cap_data_struct. Versions 2 and 3 support 64 capabilities and
 *   require an array of two __user_cap_data_struct elements. Version 2 is
 *   deprecated; version 3 is functionally identical but with a different
 *   magic number to avoid source compatibility issues with version 1.
 *
 *   This syscall can be used to query the kernel's preferred capability
 *   version by passing an invalid version in header->version with @dataptr
 *   set to NULL. The kernel will return 0 and update header->version to
 *   _LINUX_CAPABILITY_VERSION_3.
 *
 *   When querying another process (pid != 0 and pid != current), the syscall
 *   uses RCU to safely access the target process's credentials. The operation
 *   is atomic with respect to capability changes made by the target process.
 *
 *   Note: Any process can read any other process's capabilities without
 *   requiring special privileges. This is by design, as capability information
 *   is not considered sensitive.
 *
 *   For version 1, upper 32 bits of 64-bit capabilities are silently dropped.
 *   This provides backwards compatibility but means older applications cannot
 *   see capabilities beyond CAP_AUDIT_CONTROL (30). The recommended approach
 *   is to always use version 3.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: header
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_INOUT | KAPI_PARAM_USER
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be a valid pointer to a cap_user_header_t structure
 *     in user space. The version field is read to determine protocol version
 *     and may be written to indicate the kernel's preferred version on error.
 *     The pid field is read to determine the target process. Cannot be NULL.
 *
 * param: dataptr
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER | KAPI_PARAM_OPTIONAL
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: May be NULL for version query, otherwise must point to valid
 *     user-space memory. For version 1, must point to a single
 *     __user_cap_data_struct (12 bytes). For versions 2 and 3, must point
 *     to an array of two __user_cap_data_struct elements (24 bytes total).
 *     Memory must be writable.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. The capability sets have been written to
 *     the memory pointed to by @dataptr (if non-NULL). For a version query
 *     (invalid version with NULL dataptr), header->version is updated to
 *     indicate the kernel's preferred version.
 *
 * error: EFAULT, Invalid user-space pointer
 *   desc: The @header pointer is invalid or points to unmapped memory,
 *     preventing the kernel from reading the version or pid fields.
 *     Also returned if @dataptr is non-NULL but points to invalid or
 *     read-only memory where capability data cannot be written. This error
 *     can originate from get_user() reading header fields, put_user()
 *     updating header->version, or copy_to_user() writing capability data.
 *
 * error: EINVAL, Invalid argument
 *   desc: Returned in two cases: (1) The header->version field contains an
 *     unrecognized capability protocol version and @dataptr is non-NULL.
 *     When version is invalid, the kernel updates header->version to
 *     _LINUX_CAPABILITY_VERSION_3 before returning this error. (2) The
 *     header->pid field contains a negative value. Process IDs must be
 *     non-negative; use 0 to query the calling thread's own capabilities.
 *
 * error: ESRCH, No such process
 *   desc: The process specified by header->pid does not exist in the
 *     caller's PID namespace. This includes the case where the process
 *     has already terminated. When pid is 0 or matches the caller's own
 *     PID, this error cannot occur. The lookup is performed using
 *     find_task_by_vpid() which respects PID namespace boundaries.
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: Acquired when querying another process's capabilities (pid != 0
 *     and pid != current). Protects the task lookup via find_task_by_vpid()
 *     and the subsequent credential access in security_capget(). Also
 *     acquired by cap_capget() when reading the target task's credentials
 *     via __task_cred(). The RCU read lock ensures the target task and its
 *     credentials remain valid during the operation.
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DISCARD
 *   condition: During user-space memory access
 *   desc: The syscall may block during get_user(), put_user(), or
 *     copy_to_user() operations if pages need to be faulted in. These
 *     operations use TASK_UNINTERRUPTIBLE state and cannot be interrupted
 *     by signals. Any signals delivered during the syscall remain pending
 *     and are handled after the syscall returns.
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: header->version in user space
 *   desc: When an unrecognized capability version is provided in
 *     header->version, the kernel writes _LINUX_CAPABILITY_VERSION_3
 *     (0x20080522) to header->version before returning. This allows
 *     applications to discover the kernel's preferred capability version
 *     by calling capget() with an invalid version and @dataptr set to NULL.
 *   condition: header->version is not a recognized capability version
 *   reversible: yes
 *
 * examples: struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
 *   struct __user_cap_data_struct data[2];
 *   syscall(__NR_capget, &hdr, data);  // Get own capabilities
 *
 * notes: The glibc library does not provide a wrapper for this syscall.
 *   Applications should use syscall(__NR_capget, ...) directly or use the
 *   libcap library functions cap_get_proc() and cap_get_pid() for a more
 *   portable interface.
 *
 *   Capability version 2 was introduced in Linux 2.6.25 but had API issues
 *   with backwards compatibility. Version 3, introduced in Linux 2.6.26,
 *   is identical to version 2 but uses a different magic number to prevent
 *   source code compiled against old headers from accidentally using the
 *   wrong version. Always use version 3 for new code.
 *
 *   The CONFIG_MULTIUSER kernel configuration option affects this syscall.
 *   When disabled (embedded systems), the syscall infrastructure still exists
 *   but the underlying implementation is simplified.
 *
 *   Unlike capset(), this syscall does not require any capabilities. Any
 *   process can read any other process's capabilities.
 *
 * since-version: 2.2
 */
SYSCALL_DEFINE2(capget, cap_user_header_t, header, cap_user_data_t, dataptr)
{
	int ret = 0;
	pid_t pid;
	unsigned tocopy;
	kernel_cap_t pE, pI, pP;
	struct __user_cap_data_struct kdata[2];

	ret = cap_validate_magic(header, &tocopy);
	if ((dataptr == NULL) || (ret != 0))
		return ((dataptr == NULL) && (ret == -EINVAL)) ? 0 : ret;

	if (get_user(pid, &header->pid))
		return -EFAULT;

	if (pid < 0)
		return -EINVAL;

	ret = cap_get_target_pid(pid, &pE, &pI, &pP);
	if (ret)
		return ret;

	/*
	 * Annoying legacy format with 64-bit capabilities exposed
	 * as two sets of 32-bit fields, so we need to split the
	 * capability values up.
	 */
	kdata[0].effective   = pE.val; kdata[1].effective   = pE.val >> 32;
	kdata[0].permitted   = pP.val; kdata[1].permitted   = pP.val >> 32;
	kdata[0].inheritable = pI.val; kdata[1].inheritable = pI.val >> 32;

	/*
	 * Note, in the case, tocopy < _KERNEL_CAPABILITY_U32S,
	 * we silently drop the upper capabilities here. This
	 * has the effect of making older libcap
	 * implementations implicitly drop upper capability
	 * bits when they perform a: capget/modify/capset
	 * sequence.
	 *
	 * This behavior is considered fail-safe
	 * behavior. Upgrading the application to a newer
	 * version of libcap will enable access to the newer
	 * capabilities.
	 *
	 * An alternative would be to return an error here
	 * (-ERANGE), but that causes legacy applications to
	 * unexpectedly fail; the capget/modify/capset aborts
	 * before modification is attempted and the application
	 * fails.
	 */
	if (copy_to_user(dataptr, kdata, tocopy * sizeof(kdata[0])))
		return -EFAULT;

	return 0;
}

static kernel_cap_t mk_kernel_cap(u32 low, u32 high)
{
	return (kernel_cap_t) { (low | ((u64)high << 32)) & CAP_VALID_MASK };
}

/**
 * sys_capset - set capabilities for a process or (*) a group of processes
 * @header: pointer to struct that contains capability version and
 *	target pid data
 * @data: pointer to struct that contains the effective, permitted,
 *	and inheritable capabilities
 *
 * Set capabilities for the current process only.  The ability to any other
 * process(es) has been deprecated and removed.
 *
 * The restrictions on setting capabilities are specified as:
 *
 * I: any raised capabilities must be a subset of the old permitted
 * P: any raised capabilities must be a subset of the old permitted
 * E: must be set to a subset of new permitted
 *
 * Returns 0 on success and < 0 on error.
 */
SYSCALL_DEFINE2(capset, cap_user_header_t, header, const cap_user_data_t, data)
{
	struct __user_cap_data_struct kdata[2] = { { 0, }, };
	unsigned tocopy, copybytes;
	kernel_cap_t inheritable, permitted, effective;
	struct cred *new;
	int ret;
	pid_t pid;

	ret = cap_validate_magic(header, &tocopy);
	if (ret != 0)
		return ret;

	if (get_user(pid, &header->pid))
		return -EFAULT;

	/* may only affect current now */
	if (pid != 0 && pid != task_pid_vnr(current))
		return -EPERM;

	copybytes = tocopy * sizeof(struct __user_cap_data_struct);
	if (copybytes > sizeof(kdata))
		return -EFAULT;

	if (copy_from_user(&kdata, data, copybytes))
		return -EFAULT;

	effective   = mk_kernel_cap(kdata[0].effective,   kdata[1].effective);
	permitted   = mk_kernel_cap(kdata[0].permitted,   kdata[1].permitted);
	inheritable = mk_kernel_cap(kdata[0].inheritable, kdata[1].inheritable);

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	ret = security_capset(new, current_cred(),
			      &effective, &inheritable, &permitted);
	if (ret < 0)
		goto error;

	audit_log_capset(new, current_cred());

	return commit_creds(new);

error:
	abort_creds(new);
	return ret;
}

/**
 * has_ns_capability - Does a task have a capability in a specific user ns
 * @t: The task in question
 * @ns: target user namespace
 * @cap: The capability to be tested for
 *
 * Return true if the specified task has the given superior capability
 * currently in effect to the specified user namespace, false if not.
 *
 * Note that this does not set PF_SUPERPRIV on the task.
 */
bool has_ns_capability(struct task_struct *t,
		       struct user_namespace *ns, int cap)
{
	int ret;

	rcu_read_lock();
	ret = security_capable(__task_cred(t), ns, cap, CAP_OPT_NONE);
	rcu_read_unlock();

	return (ret == 0);
}

/**
 * has_ns_capability_noaudit - Does a task have a capability (unaudited)
 * in a specific user ns.
 * @t: The task in question
 * @ns: target user namespace
 * @cap: The capability to be tested for
 *
 * Return true if the specified task has the given superior capability
 * currently in effect to the specified user namespace, false if not.
 * Do not write an audit message for the check.
 *
 * Note that this does not set PF_SUPERPRIV on the task.
 */
bool has_ns_capability_noaudit(struct task_struct *t,
			       struct user_namespace *ns, int cap)
{
	int ret;

	rcu_read_lock();
	ret = security_capable(__task_cred(t), ns, cap, CAP_OPT_NOAUDIT);
	rcu_read_unlock();

	return (ret == 0);
}

/**
 * has_capability_noaudit - Does a task have a capability (unaudited) in the
 * initial user ns
 * @t: The task in question
 * @cap: The capability to be tested for
 *
 * Return true if the specified task has the given superior capability
 * currently in effect to init_user_ns, false if not.  Don't write an
 * audit message for the check.
 *
 * Note that this does not set PF_SUPERPRIV on the task.
 */
bool has_capability_noaudit(struct task_struct *t, int cap)
{
	return has_ns_capability_noaudit(t, &init_user_ns, cap);
}
EXPORT_SYMBOL(has_capability_noaudit);

static bool ns_capable_common(struct user_namespace *ns,
			      int cap,
			      unsigned int opts)
{
	int capable;

	if (unlikely(!cap_valid(cap))) {
		pr_crit("capable() called with invalid cap=%u\n", cap);
		BUG();
	}

	capable = security_capable(current_cred(), ns, cap, opts);
	if (capable == 0) {
		current->flags |= PF_SUPERPRIV;
		return true;
	}
	return false;
}

/**
 * ns_capable - Determine if the current task has a superior capability in effect
 * @ns:  The usernamespace we want the capability in
 * @cap: The capability to be tested for
 *
 * Return true if the current task has the given superior capability currently
 * available for use, false if not.
 *
 * This sets PF_SUPERPRIV on the task if the capability is available on the
 * assumption that it's about to be used.
 */
bool ns_capable(struct user_namespace *ns, int cap)
{
	return ns_capable_common(ns, cap, CAP_OPT_NONE);
}
EXPORT_SYMBOL(ns_capable);

/**
 * ns_capable_noaudit - Determine if the current task has a superior capability
 * (unaudited) in effect
 * @ns:  The usernamespace we want the capability in
 * @cap: The capability to be tested for
 *
 * Return true if the current task has the given superior capability currently
 * available for use, false if not.
 *
 * This sets PF_SUPERPRIV on the task if the capability is available on the
 * assumption that it's about to be used.
 */
bool ns_capable_noaudit(struct user_namespace *ns, int cap)
{
	return ns_capable_common(ns, cap, CAP_OPT_NOAUDIT);
}
EXPORT_SYMBOL(ns_capable_noaudit);

/**
 * ns_capable_setid - Determine if the current task has a superior capability
 * in effect, while signalling that this check is being done from within a
 * setid or setgroups syscall.
 * @ns:  The usernamespace we want the capability in
 * @cap: The capability to be tested for
 *
 * Return true if the current task has the given superior capability currently
 * available for use, false if not.
 *
 * This sets PF_SUPERPRIV on the task if the capability is available on the
 * assumption that it's about to be used.
 */
bool ns_capable_setid(struct user_namespace *ns, int cap)
{
	return ns_capable_common(ns, cap, CAP_OPT_INSETID);
}
EXPORT_SYMBOL(ns_capable_setid);

/**
 * capable - Determine if the current task has a superior capability in effect
 * @cap: The capability to be tested for
 *
 * Return true if the current task has the given superior capability currently
 * available for use, false if not.
 *
 * This sets PF_SUPERPRIV on the task if the capability is available on the
 * assumption that it's about to be used.
 */
bool capable(int cap)
{
	return ns_capable(&init_user_ns, cap);
}
EXPORT_SYMBOL(capable);
#endif /* CONFIG_MULTIUSER */

/**
 * file_ns_capable - Determine if the file's opener had a capability in effect
 * @file:  The file we want to check
 * @ns:  The usernamespace we want the capability in
 * @cap: The capability to be tested for
 *
 * Return true if task that opened the file had a capability in effect
 * when the file was opened.
 *
 * This does not set PF_SUPERPRIV because the caller may not
 * actually be privileged.
 */
bool file_ns_capable(const struct file *file, struct user_namespace *ns,
		     int cap)
{

	if (WARN_ON_ONCE(!cap_valid(cap)))
		return false;

	if (security_capable(file->f_cred, ns, cap, CAP_OPT_NONE) == 0)
		return true;

	return false;
}
EXPORT_SYMBOL(file_ns_capable);

/**
 * privileged_wrt_inode_uidgid - Do capabilities in the namespace work over the inode?
 * @ns: The user namespace in question
 * @idmap: idmap of the mount @inode was found from
 * @inode: The inode in question
 *
 * Return true if the inode uid and gid are within the namespace.
 */
bool privileged_wrt_inode_uidgid(struct user_namespace *ns,
				 struct mnt_idmap *idmap,
				 const struct inode *inode)
{
	return vfsuid_has_mapping(ns, i_uid_into_vfsuid(idmap, inode)) &&
	       vfsgid_has_mapping(ns, i_gid_into_vfsgid(idmap, inode));
}

/**
 * capable_wrt_inode_uidgid - Check nsown_capable and uid and gid mapped
 * @idmap: idmap of the mount @inode was found from
 * @inode: The inode in question
 * @cap: The capability in question
 *
 * Return true if the current task has the given capability targeted at
 * its own user namespace and that the given inode's uid and gid are
 * mapped into the current user namespace.
 */
bool capable_wrt_inode_uidgid(struct mnt_idmap *idmap,
			      const struct inode *inode, int cap)
{
	struct user_namespace *ns = current_user_ns();

	return ns_capable(ns, cap) &&
	       privileged_wrt_inode_uidgid(ns, idmap, inode);
}
EXPORT_SYMBOL(capable_wrt_inode_uidgid);

/**
 * ptracer_capable - Determine if the ptracer holds CAP_SYS_PTRACE in the namespace
 * @tsk: The task that may be ptraced
 * @ns: The user namespace to search for CAP_SYS_PTRACE in
 *
 * Return true if the task that is ptracing the current task had CAP_SYS_PTRACE
 * in the specified user namespace.
 */
bool ptracer_capable(struct task_struct *tsk, struct user_namespace *ns)
{
	int ret = 0;  /* An absent tracer adds no restrictions */
	const struct cred *cred;

	rcu_read_lock();
	cred = rcu_dereference(tsk->ptracer_cred);
	if (cred)
		ret = security_capable(cred, ns, CAP_SYS_PTRACE,
				       CAP_OPT_NOAUDIT);
	rcu_read_unlock();
	return (ret == 0);
}
