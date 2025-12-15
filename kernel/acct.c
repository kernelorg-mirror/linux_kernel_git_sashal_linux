// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/kernel/acct.c
 *
 *  BSD Process Accounting for Linux
 *
 *  Author: Marco van Wieringen <mvw@planets.elm.net>
 *
 *  Some code based on ideas and code from:
 *  Thomas K. Dyas <tdyas@eden.rutgers.edu>
 *
 *  This file implements BSD-style process accounting. Whenever any
 *  process exits, an accounting record of type "struct acct" is
 *  written to the file specified with the acct() system call. It is
 *  up to user-level programs to do useful things with the accounting
 *  log. The kernel just provides the raw accounting information.
 *
 * (C) Copyright 1995 - 1997 Marco van Wieringen - ELM Consultancy B.V.
 *
 *  Plugged two leaks. 1) It didn't return acct_file into the free_filps if
 *  the file happened to be read-only. 2) If the accounting was suspended
 *  due to the lack of space it happily allowed to reopen it and completely
 *  lost the old acct_file. 3/10/98, Al Viro.
 *
 *  Now we silently close acct_file on attempt to reopen. Cleaned sys_acct().
 *  XTerms and EMACS are manifestations of pure evil. 21/10/98, AV.
 *
 *  Fixed a nasty interaction with sys_umount(). If the accounting
 *  was suspeneded we failed to stop it on umount(). Messy.
 *  Another one: remount to readonly didn't stop accounting.
 *	Question: what should we do if we have CAP_SYS_ADMIN but not
 *  CAP_SYS_PACCT? Current code does the following: umount returns -EBUSY
 *  unless we are messing with the root. In that case we are getting a
 *  real mess with do_remount_sb(). 9/11/98, AV.
 *
 *  Fixed a bunch of races (and pair of leaks). Probably not the best way,
 *  but this one obviously doesn't introduce deadlocks. Later. BTW, found
 *  one race (and leak) in BSD implementation.
 *  OK, that's better. ANOTHER race and leak in BSD variant. There always
 *  is one more bug... 10/11/98, AV.
 *
 *	Oh, fsck... Oopsable SMP race in do_process_acct() - we must hold
 * ->mmap_lock to walk the vma list of current->mm. Nasty, since it leaks
 * a struct file opened for write. Fixed. 2/6/2000, AV.
 */

#include <linux/slab.h>
#include <linux/acct.h>
#include <linux/capability.h>
#include <linux/tty.h>
#include <linux/statfs.h>
#include <linux/jiffies.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/sched/cputime.h>

#include <asm/div64.h>
#include <linux/pid_namespace.h>
#include <linux/fs_pin.h>

/*
 * These constants control the amount of freespace that suspend and
 * resume the process accounting system, and the time delay between
 * each check.
 * Turned into sysctl-controllable parameters. AV, 12/11/98
 */

static int acct_parm[3] = {4, 2, 30};
#define RESUME		(acct_parm[0])	/* >foo% free space - resume */
#define SUSPEND		(acct_parm[1])	/* <foo% free space - suspend */
#define ACCT_TIMEOUT	(acct_parm[2])	/* foo second timeout between checks */

#ifdef CONFIG_SYSCTL
static const struct ctl_table kern_acct_table[] = {
	{
		.procname       = "acct",
		.data           = &acct_parm,
		.maxlen         = 3*sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
};

static __init int kernel_acct_sysctls_init(void)
{
	register_sysctl_init("kernel", kern_acct_table);
	return 0;
}
late_initcall(kernel_acct_sysctls_init);
#endif /* CONFIG_SYSCTL */

/*
 * External references and all of the globals.
 */

struct bsd_acct_struct {
	struct fs_pin		pin;
	atomic_long_t		count;
	struct rcu_head		rcu;
	struct mutex		lock;
	bool			active;
	bool			check_space;
	unsigned long		needcheck;
	struct file		*file;
	struct pid_namespace	*ns;
	struct work_struct	work;
	struct completion	done;
	acct_t			ac;
};

static void fill_ac(struct bsd_acct_struct *acct);
static void acct_write_process(struct bsd_acct_struct *acct);

/*
 * Check the amount of free space and suspend/resume accordingly.
 */
static bool check_free_space(struct bsd_acct_struct *acct)
{
	struct kstatfs sbuf;

	if (!acct->check_space)
		return acct->active;

	/* May block */
	if (vfs_statfs(&acct->file->f_path, &sbuf))
		return acct->active;

	if (acct->active) {
		u64 suspend = sbuf.f_blocks * SUSPEND;
		do_div(suspend, 100);
		if (sbuf.f_bavail <= suspend) {
			acct->active = false;
			pr_info("Process accounting paused\n");
		}
	} else {
		u64 resume = sbuf.f_blocks * RESUME;
		do_div(resume, 100);
		if (sbuf.f_bavail >= resume) {
			acct->active = true;
			pr_info("Process accounting resumed\n");
		}
	}

	acct->needcheck = jiffies + ACCT_TIMEOUT*HZ;
	return acct->active;
}

static void acct_put(struct bsd_acct_struct *p)
{
	if (atomic_long_dec_and_test(&p->count))
		kfree_rcu(p, rcu);
}

static inline struct bsd_acct_struct *to_acct(struct fs_pin *p)
{
	return p ? container_of(p, struct bsd_acct_struct, pin) : NULL;
}

static struct bsd_acct_struct *acct_get(struct pid_namespace *ns)
{
	struct bsd_acct_struct *res;
again:
	smp_rmb();
	rcu_read_lock();
	res = to_acct(READ_ONCE(ns->bacct));
	if (!res) {
		rcu_read_unlock();
		return NULL;
	}
	if (!atomic_long_inc_not_zero(&res->count)) {
		rcu_read_unlock();
		cpu_relax();
		goto again;
	}
	rcu_read_unlock();
	mutex_lock(&res->lock);
	if (res != to_acct(READ_ONCE(ns->bacct))) {
		mutex_unlock(&res->lock);
		acct_put(res);
		goto again;
	}
	return res;
}

static void acct_pin_kill(struct fs_pin *pin)
{
	struct bsd_acct_struct *acct = to_acct(pin);
	mutex_lock(&acct->lock);
	/*
	 * Fill the accounting struct with the exiting task's info
	 * before punting to the workqueue.
	 */
	fill_ac(acct);
	schedule_work(&acct->work);
	wait_for_completion(&acct->done);
	cmpxchg(&acct->ns->bacct, pin, NULL);
	mutex_unlock(&acct->lock);
	pin_remove(pin);
	acct_put(acct);
}

static void close_work(struct work_struct *work)
{
	struct bsd_acct_struct *acct = container_of(work, struct bsd_acct_struct, work);
	struct file *file = acct->file;

	/* We were fired by acct_pin_kill() which holds acct->lock. */
	acct_write_process(acct);
	if (file->f_op->flush)
		file->f_op->flush(file, NULL);
	__fput_sync(file);
	complete(&acct->done);
}

DEFINE_FREE(fput_sync, struct file *, if (!IS_ERR_OR_NULL(_T)) __fput_sync(_T))
static int acct_on(const char __user *name)
{
	/* Difference from BSD - they don't do O_APPEND */
	const int open_flags = O_WRONLY|O_APPEND|O_LARGEFILE;
	struct pid_namespace *ns = task_active_pid_ns(current);
	struct filename *pathname __free(putname) = getname(name);
	struct file *original_file __free(fput) = NULL;	// in that order
	struct path internal __free(path_put) = {};	// in that order
	struct file *file __free(fput_sync) = NULL;	// in that order
	struct bsd_acct_struct *acct;
	struct vfsmount *mnt;
	struct fs_pin *old;

	if (IS_ERR(pathname))
		return PTR_ERR(pathname);
	original_file = file_open_name(pathname, open_flags, 0);
	if (IS_ERR(original_file))
		return PTR_ERR(original_file);

	mnt = mnt_clone_internal(&original_file->f_path);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	internal.mnt = mnt;
	internal.dentry = dget(mnt->mnt_root);

	file = dentry_open(&internal, open_flags, current_cred());
	if (IS_ERR(file))
		return PTR_ERR(file);

	if (!S_ISREG(file_inode(file)->i_mode))
		return -EACCES;

	/* Exclude kernel kernel internal filesystems. */
	if (file_inode(file)->i_sb->s_flags & (SB_NOUSER | SB_KERNMOUNT))
		return -EINVAL;

	/* Exclude procfs and sysfs. */
	if (file_inode(file)->i_sb->s_iflags & SB_I_USERNS_VISIBLE)
		return -EINVAL;

	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EIO;

	acct = kzalloc(sizeof(struct bsd_acct_struct), GFP_KERNEL);
	if (!acct)
		return -ENOMEM;

	atomic_long_set(&acct->count, 1);
	init_fs_pin(&acct->pin, acct_pin_kill);
	acct->file = no_free_ptr(file);
	acct->needcheck = jiffies;
	acct->ns = ns;
	mutex_init(&acct->lock);
	INIT_WORK(&acct->work, close_work);
	init_completion(&acct->done);
	mutex_lock_nested(&acct->lock, 1);	/* nobody has seen it yet */
	pin_insert(&acct->pin, original_file->f_path.mnt);

	rcu_read_lock();
	old = xchg(&ns->bacct, &acct->pin);
	mutex_unlock(&acct->lock);
	pin_kill(old);
	return 0;
}

static DEFINE_MUTEX(acct_on_mutex);

/**
 * sys_acct - Enable or disable BSD-style process accounting
 * @name: Pathname to the accounting file, or NULL to disable accounting
 *
 * long-desc: Controls BSD-style process accounting for the current PID
 *   namespace. When enabled, the kernel writes an accounting record to
 *   the specified file each time a process terminates. When disabled,
 *   accounting records are no longer written.
 *
 *   Process accounting provides a record of resource consumption for each
 *   terminated process, including CPU time (user and system), elapsed time,
 *   memory usage, page faults, controlling terminal, exit status, and the
 *   command name. This information is useful for system administration,
 *   resource tracking, and capacity planning.
 *
 *   The @name parameter specifies the pathname to the accounting file:
 *   - If @name is non-NULL, process accounting is enabled. The file must
 *     already exist and be a regular file on a filesystem that supports
 *     normal file operations (not procfs, sysfs, or kernel internal mounts).
 *     If accounting was already enabled, the old accounting file is closed
 *     and replaced with the new one. Records are appended to the file
 *     using O_APPEND semantics.
 *   - If @name is NULL, process accounting is disabled for the current
 *     PID namespace. Any pending accounting record for the current process
 *     is written before closing the accounting file.
 *
 *   The kernel automatically manages accounting based on available disk space.
 *   Accounting is suspended when free space drops below 2% (configurable via
 *   /proc/sys/kernel/acct[1]) and resumed when free space exceeds 4%
 *   (configurable via /proc/sys/kernel/acct[0]). The check interval is
 *   controlled by /proc/sys/kernel/acct[2] (default 30 seconds).
 *
 *   Process accounting is per-PID namespace. Each PID namespace maintains
 *   its own accounting file and state. When a PID namespace is destroyed,
 *   its accounting is automatically disabled.
 *
 *   The accounting file format is defined by struct acct or struct acct_v3
 *   depending on the CONFIG_BSD_PROCESS_ACCT_V3 kernel configuration option.
 *   The v3 format includes additional fields such as PID and PPID.
 *
 *   Write operations to the accounting file are performed using the
 *   credentials of the process that enabled accounting, not the credentials
 *   of the exiting process. This prevents privilege escalation through
 *   accounting file manipulation.
 *
 *   Unlike BSD systems, Linux opens the accounting file with O_APPEND,
 *   ensuring atomic appends and preventing record interleaving even when
 *   multiple processes exit simultaneously.
 *
 *   Note: Processes that are running when the system crashes are never
 *   accounted for. Only processes that terminate normally (via exit() or
 *   signal) generate accounting records.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: name
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_OPTIONAL
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Must be NULL to disable accounting, or a valid user-space
 *     pointer to a null-terminated pathname string. When non-NULL, the path
 *     must refer to an existing regular file on a writable filesystem. The
 *     path length must not exceed PATH_MAX (4096 bytes including the null
 *     terminator). The path cannot refer to files on procfs, sysfs, or
 *     kernel-internal filesystems (those with SB_NOUSER, SB_KERNMOUNT, or
 *     SB_I_USERNS_VISIBLE flags).
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. Process accounting is now enabled (if @name
 *     was non-NULL) or disabled (if @name was NULL) for the current PID
 *     namespace. If accounting was previously enabled with a different file,
 *     that file has been closed and any pending records flushed.
 *
 * error: EPERM, Insufficient privileges
 *   desc: The calling process does not have the CAP_SYS_PACCT capability.
 *     This capability is required for both enabling and disabling process
 *     accounting. In user namespaces, the process must have CAP_SYS_PACCT
 *     in the initial user namespace, not just in its own user namespace.
 *
 * error: EFAULT, Invalid user pointer
 *   desc: The @name pointer refers to memory outside the accessible address
 *     space of the calling process. This error is returned by the
 *     strncpy_from_user() operation during pathname copying from user space.
 *
 * error: ENOENT, File does not exist
 *   desc: A component of the @name pathname does not exist, or @name is an
 *     empty string (and LOOKUP_EMPTY is not set). The accounting file must
 *     exist before calling acct(); the syscall does not create the file.
 *
 * error: ENAMETOOLONG, Pathname too long
 *   desc: The @name pathname exceeds PATH_MAX (4096) bytes, or a pathname
 *     component exceeds NAME_MAX (255) bytes on most filesystems.
 *
 * error: EACCES, Permission denied or not a regular file
 *   desc: The calling process lacks permission to open the file for writing,
 *     lacks search permission for a directory component of the path, or the
 *     target file is not a regular file (e.g., it is a directory, device,
 *     socket, or FIFO). Only regular files can be used for accounting.
 *
 * error: ENOTDIR, Not a directory
 *   desc: A component of the @name pathname prefix is not a directory. For
 *     example, if the path is "/foo/bar/acct" but "/foo/bar" is a regular
 *     file rather than a directory.
 *
 * error: ELOOP, Too many symbolic links
 *   desc: Too many symbolic links were encountered while resolving @name.
 *     The kernel limits symbolic link traversal to prevent infinite loops
 *     (typically 40 links maximum).
 *
 * error: EROFS, Read-only filesystem
 *   desc: The @name pathname refers to a file on a read-only filesystem.
 *     The accounting file must be on a writable filesystem since records
 *     are appended during process termination.
 *
 * error: EINVAL, Invalid filesystem type
 *   desc: The @name refers to a file on a kernel-internal filesystem
 *     (SB_NOUSER or SB_KERNMOUNT flags set), or on procfs/sysfs (filesystem
 *     with SB_I_USERNS_VISIBLE flag). These filesystems cannot be used for
 *     process accounting as they are not suitable for persistent storage
 *     or may have special semantics that conflict with accounting writes.
 *
 * error: EIO, File not writable
 *   desc: The file was opened but does not support write operations
 *     (FMODE_CAN_WRITE not set). This can occur for special files or files
 *     on filesystems that do not implement write operations.
 *
 * error: ENOMEM, Kernel memory allocation failed
 *   desc: Insufficient kernel memory to allocate the pathname buffer
 *     (struct filename), the bsd_acct_struct structure for accounting state,
 *     the mount clone for the internal mount reference, or the file
 *     structure for the opened file. Each of these allocations uses
 *     GFP_KERNEL and may fail under memory pressure.
 *
 * error: ENFILE, System file table full
 *   desc: The system-wide limit on the number of open files has been reached.
 *     This limit is controlled by /proc/sys/fs/file-max. This error is rare
 *     but possible on systems with extreme file descriptor usage.
 *
 * error: EMFILE, Per-process file descriptor limit reached
 *   desc: The calling process has reached its RLIMIT_NOFILE limit on open
 *     file descriptors. While the file descriptor is internal and not
 *     returned to user space, it still counts against system limits during
 *     the file open operation.
 *
 * error: ETXTBSY, File is being executed
 *   desc: The target file is currently open for execution by some process.
 *     A file cannot be opened for writing while it is being executed.
 *
 * lock: acct_on_mutex
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: Serializes acct_on() operations when @name is non-NULL. This mutex
 *     ensures that only one process can enable or reconfigure accounting
 *     at a time, preventing races between concurrent acct() calls. The lock
 *     is held while opening the file, validating it, creating the accounting
 *     structure, and installing it in the PID namespace. Not acquired when
 *     @name is NULL (disabling accounting uses RCU and atomic operations).
 *
 * lock: acct->lock
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: Protects the bsd_acct_struct fields during setup and operations.
 *     Acquired with mutex_lock_nested() after creating the structure to
 *     protect against concurrent access during the brief window between
 *     structure creation and installation. Released after the accounting
 *     structure is installed in the namespace.
 *
 * lock: rcu_read_lock
 *   type: KAPI_LOCK_RCU
 *   acquired: true
 *   released: true
 *   desc: When @name is NULL, rcu_read_lock() is acquired to safely access
 *     the PID namespace's bacct pointer before calling pin_kill(). RCU
 *     protection ensures the namespace and its accounting structure remain
 *     valid during the lookup. The lock is released by pin_kill() after
 *     initiating the kill sequence.
 *
 * lock: pin_lock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Global spinlock protecting the fs_pin lists (m_list and s_list).
 *     Acquired during pin_insert() to add the new accounting pin to the
 *     mount and superblock pin lists. Also acquired during pin_remove()
 *     when closing accounting.
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DISCARD
 *   condition: During blocking operations
 *   desc: The syscall uses mutex_lock() which is not interruptible by signals.
 *     Memory allocations use GFP_KERNEL which sleeps in TASK_UNINTERRUPTIBLE.
 *     When disabling accounting, pin_kill() may use TASK_UNINTERRUPTIBLE
 *     waits. Signals delivered during the syscall remain pending and are
 *     handled after the syscall returns. The syscall does not return EINTR.
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_FILESYSTEM
 *   target: Accounting file
 *   desc: When @name is non-NULL, opens the specified file for writing with
 *     O_WRONLY | O_APPEND | O_LARGEFILE flags. The file remains open until
 *     accounting is disabled or replaced. The kernel writes struct acct or
 *     struct acct_v3 records to this file each time a process terminates.
 *     Records are written atomically using the credentials of the process
 *     that called acct(), not the exiting process.
 *   condition: @name is non-NULL
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_CREATE
 *   target: bsd_acct_struct
 *   desc: Allocates a bsd_acct_struct structure to track accounting state
 *     for the PID namespace. This structure contains the file pointer,
 *     mutex, workqueue work item, completion structure, and cached accounting
 *     record. The structure is reference-counted and freed via RCU when
 *     the last reference is dropped.
 *   condition: @name is non-NULL and file opens successfully
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_RESOURCE_DESTROY
 *   target: Previous accounting state
 *   desc: If accounting was previously enabled for this PID namespace, the
 *     old bsd_acct_struct is killed via pin_kill(). This triggers the
 *     acct_pin_kill() callback which writes any pending accounting record,
 *     flushes and closes the old file, and frees the old structure. This
 *     ensures a clean transition between accounting files.
 *   condition: Accounting was previously enabled
 *   reversible: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: PID namespace accounting pointer
 *   desc: Updates ns->bacct (the PID namespace's accounting pointer) to
 *     point to the new fs_pin structure (or NULL when disabling). This
 *     change is performed atomically using xchg() to ensure consistency
 *     with concurrent readers using RCU.
 *   reversible: yes
 *
 * state-trans: process_accounting
 *   from: disabled
 *   to: enabled
 *   condition: @name is non-NULL, file opens successfully, capability check passes
 *   desc: Process accounting transitions from disabled to enabled for the
 *     current PID namespace. All processes terminating in this namespace
 *     (and child namespaces unless they have their own accounting) will
 *     have records written to the accounting file.
 *
 * state-trans: process_accounting
 *   from: enabled
 *   to: enabled (different file)
 *   condition: @name is non-NULL, accounting was already enabled
 *   desc: The accounting file is switched to a new file. The old file is
 *     flushed and closed. Any accounting record for the calling process
 *     is written to the old file before the switch.
 *
 * state-trans: process_accounting
 *   from: enabled
 *   to: disabled
 *   condition: @name is NULL
 *   desc: Process accounting is disabled for the current PID namespace.
 *     Any pending accounting record is written, the file is flushed and
 *     closed, and resources are released.
 *
 * capability: CAP_SYS_PACCT
 *   type: KAPI_CAP_GRANT_PERMISSION
 *   allows: Enables or disables process accounting for the current PID
 *     namespace. Without this capability, the syscall immediately returns
 *     EPERM without examining the @name argument.
 *   without: Returns -EPERM. Unprivileged processes cannot control process
 *     accounting regardless of file permissions on the accounting file.
 *   condition: Always checked as the first operation in the syscall
 *
 * constraint: Filesystem Type
 *   desc: The accounting file cannot be on procfs, sysfs, or kernel-internal
 *     filesystems. This restriction prevents accounting to pseudo-files that
 *     may have special semantics, and to filesystems that are not intended
 *     for persistent data storage.
 *
 * constraint: Regular File
 *   desc: The accounting file must be a regular file (S_ISREG). Directories,
 *     device files, sockets, FIFOs, and symbolic links cannot be used for
 *     accounting.
 *
 * constraint: Writable File
 *   desc: The accounting file must support write operations. The kernel
 *     verifies FMODE_CAN_WRITE is set after opening the file. Files that
 *     were opened successfully but do not support writes (unusual case)
 *     will cause an EIO error.
 *
 * examples: acct("/var/log/pacct");  // Enable accounting to /var/log/pacct
 *   acct(NULL);  // Disable accounting
 *   // Check if accounting is enabled (read /proc/sys/kernel/acct)
 *
 * notes: This syscall does not conform to any standard. It originated in
 *   4.3BSD and is available on most Unix-like systems, but the details
 *   (record format, sysctl parameters, error conditions) vary by system.
 *   Linux implements a subset of BSD functionality with some extensions.
 *
 *   The accounting file format is architecture-dependent due to structure
 *   padding differences. Tools reading accounting files must be aware of
 *   the format version (stored in ac_version) and byte order (ACCT_BYTEORDER
 *   bit in ac_version).
 *
 *   CONFIG_BSD_PROCESS_ACCT must be enabled in the kernel for this syscall
 *   to function. If disabled, the syscall returns -ENOSYS (though this is
 *   actually handled by having a stub that returns -ENOSYS when the config
 *   is disabled, rather than in this function).
 *
 *   CONFIG_BSD_PROCESS_ACCT_V3 selects the v3 accounting format which
 *   includes PID and PPID fields but is incompatible with older tools.
 *
 *   The sysctl parameters in /proc/sys/kernel/acct control automatic
 *   suspend/resume based on disk space: [0]=resume threshold (%), [1]=suspend
 *   threshold (%), [2]=check interval (seconds). Default values are 4, 2, 30.
 *
 *   When multiple PID namespaces have accounting enabled, a terminating
 *   process may generate multiple accounting records - one for each ancestor
 *   namespace that has accounting enabled.
 *
 * since-version: 1.0
 */
SYSCALL_DEFINE1(acct, const char __user *, name)
{
	int error = 0;

	if (!capable(CAP_SYS_PACCT))
		return -EPERM;

	if (name) {
		mutex_lock(&acct_on_mutex);
		error = acct_on(name);
		mutex_unlock(&acct_on_mutex);
	} else {
		rcu_read_lock();
		pin_kill(task_active_pid_ns(current)->bacct);
	}

	return error;
}

void acct_exit_ns(struct pid_namespace *ns)
{
	rcu_read_lock();
	pin_kill(ns->bacct);
}

/*
 *  encode an u64 into a comp_t
 *
 *  This routine has been adopted from the encode_comp_t() function in
 *  the kern_acct.c file of the FreeBSD operating system. The encoding
 *  is a 13-bit fraction with a 3-bit (base 8) exponent.
 */

#define	MANTSIZE	13			/* 13 bit mantissa. */
#define	EXPSIZE		3			/* Base 8 (3 bit) exponent. */
#define	MAXFRACT	((1 << MANTSIZE) - 1)	/* Maximum fractional value. */

static comp_t encode_comp_t(u64 value)
{
	int exp, rnd;

	exp = rnd = 0;
	while (value > MAXFRACT) {
		rnd = value & (1 << (EXPSIZE - 1));	/* Round up? */
		value >>= EXPSIZE;	/* Base 8 exponent == 3 bit shift. */
		exp++;
	}

	/*
	 * If we need to round up, do it (and handle overflow correctly).
	 */
	if (rnd && (++value > MAXFRACT)) {
		value >>= EXPSIZE;
		exp++;
	}

	if (exp > (((comp_t) ~0U) >> MANTSIZE))
		return (comp_t) ~0U;
	/*
	 * Clean it up and polish it off.
	 */
	exp <<= MANTSIZE;		/* Shift the exponent into place */
	exp += value;			/* and add on the mantissa. */
	return exp;
}

#if ACCT_VERSION == 1 || ACCT_VERSION == 2
/*
 * encode an u64 into a comp2_t (24 bits)
 *
 * Format: 5 bit base 2 exponent, 20 bits mantissa.
 * The leading bit of the mantissa is not stored, but implied for
 * non-zero exponents.
 * Largest encodable value is 50 bits.
 */

#define MANTSIZE2       20                      /* 20 bit mantissa. */
#define EXPSIZE2        5                       /* 5 bit base 2 exponent. */
#define MAXFRACT2       ((1ul << MANTSIZE2) - 1) /* Maximum fractional value. */
#define MAXEXP2         ((1 << EXPSIZE2) - 1)    /* Maximum exponent. */

static comp2_t encode_comp2_t(u64 value)
{
	int exp, rnd;

	exp = (value > (MAXFRACT2>>1));
	rnd = 0;
	while (value > MAXFRACT2) {
		rnd = value & 1;
		value >>= 1;
		exp++;
	}

	/*
	 * If we need to round up, do it (and handle overflow correctly).
	 */
	if (rnd && (++value > MAXFRACT2)) {
		value >>= 1;
		exp++;
	}

	if (exp > MAXEXP2) {
		/* Overflow. Return largest representable number instead. */
		return (1ul << (MANTSIZE2+EXPSIZE2-1)) - 1;
	} else {
		return (value & (MAXFRACT2>>1)) | (exp << (MANTSIZE2-1));
	}
}
#elif ACCT_VERSION == 3
/*
 * encode an u64 into a 32 bit IEEE float
 */
static u32 encode_float(u64 value)
{
	unsigned exp = 190;
	unsigned u;

	if (value == 0)
		return 0;
	while ((s64)value > 0) {
		value <<= 1;
		exp--;
	}
	u = (u32)(value >> 40) & 0x7fffffu;
	return u | (exp << 23);
}
#endif

/*
 *  Write an accounting entry for an exiting process
 *
 *  The acct_process() call is the workhorse of the process
 *  accounting system. The struct acct is built here and then written
 *  into the accounting file. This function should only be called from
 *  do_exit() or when switching to a different output file.
 */

static void fill_ac(struct bsd_acct_struct *acct)
{
	struct pacct_struct *pacct = &current->signal->pacct;
	struct file *file = acct->file;
	acct_t *ac = &acct->ac;
	u64 elapsed, run_time;
	time64_t btime;
	struct tty_struct *tty;

	lockdep_assert_held(&acct->lock);

	if (time_is_after_jiffies(acct->needcheck)) {
		acct->check_space = false;

		/* Don't fill in @ac if nothing will be written. */
		if (!acct->active)
			return;
	} else {
		acct->check_space = true;
	}

	/*
	 * Fill the accounting struct with the needed info as recorded
	 * by the different kernel functions.
	 */
	memset(ac, 0, sizeof(acct_t));

	ac->ac_version = ACCT_VERSION | ACCT_BYTEORDER;
	strscpy(ac->ac_comm, current->comm, sizeof(ac->ac_comm));

	/* calculate run_time in nsec*/
	run_time = ktime_get_ns();
	run_time -= current->group_leader->start_time;
	/* convert nsec -> AHZ */
	elapsed = nsec_to_AHZ(run_time);
#if ACCT_VERSION == 3
	ac->ac_etime = encode_float(elapsed);
#else
	ac->ac_etime = encode_comp_t(elapsed < (unsigned long) -1l ?
				(unsigned long) elapsed : (unsigned long) -1l);
#endif
#if ACCT_VERSION == 1 || ACCT_VERSION == 2
	{
		/* new enlarged etime field */
		comp2_t etime = encode_comp2_t(elapsed);

		ac->ac_etime_hi = etime >> 16;
		ac->ac_etime_lo = (u16) etime;
	}
#endif
	do_div(elapsed, AHZ);
	btime = ktime_get_real_seconds() - elapsed;
	ac->ac_btime = clamp_t(time64_t, btime, 0, U32_MAX);
#if ACCT_VERSION == 2
	ac->ac_ahz = AHZ;
#endif

	spin_lock_irq(&current->sighand->siglock);
	tty = current->signal->tty;	/* Safe as we hold the siglock */
	ac->ac_tty = tty ? old_encode_dev(tty_devnum(tty)) : 0;
	ac->ac_utime = encode_comp_t(nsec_to_AHZ(pacct->ac_utime));
	ac->ac_stime = encode_comp_t(nsec_to_AHZ(pacct->ac_stime));
	ac->ac_flag = pacct->ac_flag;
	ac->ac_mem = encode_comp_t(pacct->ac_mem);
	ac->ac_minflt = encode_comp_t(pacct->ac_minflt);
	ac->ac_majflt = encode_comp_t(pacct->ac_majflt);
	ac->ac_exitcode = pacct->ac_exitcode;
	spin_unlock_irq(&current->sighand->siglock);

	/* we really need to bite the bullet and change layout */
	ac->ac_uid = from_kuid_munged(file->f_cred->user_ns, current_uid());
	ac->ac_gid = from_kgid_munged(file->f_cred->user_ns, current_gid());
#if ACCT_VERSION == 1 || ACCT_VERSION == 2
	/* backward-compatible 16 bit fields */
	ac->ac_uid16 = ac->ac_uid;
	ac->ac_gid16 = ac->ac_gid;
#elif ACCT_VERSION == 3
	{
		struct pid_namespace *ns = acct->ns;

		ac->ac_pid = task_tgid_nr_ns(current, ns);
		rcu_read_lock();
		ac->ac_ppid = task_tgid_nr_ns(rcu_dereference(current->real_parent), ns);
		rcu_read_unlock();
	}
#endif
}

static void acct_write_process(struct bsd_acct_struct *acct)
{
	struct file *file = acct->file;
	acct_t *ac = &acct->ac;

	/* Perform file operations on behalf of whoever enabled accounting */
	scoped_with_creds(file->f_cred) {
		/*
		 * First check to see if there is enough free_space to continue
		 * the process accounting system. Then get freeze protection. If
		 * the fs is frozen, just skip the write as we could deadlock
		 * the system otherwise.
		 */
		if (check_free_space(acct) && file_start_write_trylock(file)) {
			/* it's been opened O_APPEND, so position is irrelevant */
			loff_t pos = 0;
			__kernel_write(file, ac, sizeof(acct_t), &pos);
			file_end_write(file);
		}
	}
}

static void do_acct_process(struct bsd_acct_struct *acct)
{
	unsigned long flim;

	/* Accounting records are not subject to resource limits. */
	flim = rlimit(RLIMIT_FSIZE);
	current->signal->rlim[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
	fill_ac(acct);
	acct_write_process(acct);
	current->signal->rlim[RLIMIT_FSIZE].rlim_cur = flim;
}

/**
 * acct_collect - collect accounting information into pacct_struct
 * @exitcode: task exit code
 * @group_dead: not 0, if this thread is the last one in the process.
 */
void acct_collect(long exitcode, int group_dead)
{
	struct pacct_struct *pacct = &current->signal->pacct;
	u64 utime, stime;
	unsigned long vsize = 0;

	if (group_dead && current->mm) {
		struct mm_struct *mm = current->mm;
		VMA_ITERATOR(vmi, mm, 0);
		struct vm_area_struct *vma;

		mmap_read_lock(mm);
		for_each_vma(vmi, vma)
			vsize += vma->vm_end - vma->vm_start;
		mmap_read_unlock(mm);
	}

	spin_lock_irq(&current->sighand->siglock);
	if (group_dead)
		pacct->ac_mem = vsize / 1024;
	if (thread_group_leader(current)) {
		pacct->ac_exitcode = exitcode;
		if (current->flags & PF_FORKNOEXEC)
			pacct->ac_flag |= AFORK;
	}
	if (current->flags & PF_SUPERPRIV)
		pacct->ac_flag |= ASU;
	if (current->flags & PF_DUMPCORE)
		pacct->ac_flag |= ACORE;
	if (current->flags & PF_SIGNALED)
		pacct->ac_flag |= AXSIG;

	task_cputime(current, &utime, &stime);
	pacct->ac_utime += utime;
	pacct->ac_stime += stime;
	pacct->ac_minflt += current->min_flt;
	pacct->ac_majflt += current->maj_flt;
	spin_unlock_irq(&current->sighand->siglock);
}

static void slow_acct_process(struct pid_namespace *ns)
{
	for ( ; ns; ns = ns->parent) {
		struct bsd_acct_struct *acct = acct_get(ns);
		if (acct) {
			do_acct_process(acct);
			mutex_unlock(&acct->lock);
			acct_put(acct);
		}
	}
}

/**
 * acct_process - handles process accounting for an exiting task
 */
void acct_process(void)
{
	struct pid_namespace *ns;

	/*
	 * This loop is safe lockless, since current is still
	 * alive and holds its namespace, which in turn holds
	 * its parent.
	 */
	for (ns = task_active_pid_ns(current); ns != NULL; ns = ns->parent) {
		if (ns->bacct)
			break;
	}
	if (unlikely(ns))
		slow_acct_process(ns);
}
