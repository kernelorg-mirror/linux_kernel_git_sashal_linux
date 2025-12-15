// SPDX-License-Identifier: GPL-2.0

#include <linux/linkage.h>
#include <linux/errno.h>

#include <asm/unistd.h>

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
/* Architectures may override COND_SYSCALL and COND_SYSCALL_COMPAT */
#include <asm/syscall_wrapper.h>
#endif /* CONFIG_ARCH_HAS_SYSCALL_WRAPPER */

/*  we can't #include <linux/syscalls.h> here,
    but tell gcc to not warn with -Wmissing-prototypes  */
asmlinkage long sys_ni_syscall(void);

/**
 * sys_ni_syscall - Stub for non-implemented system calls
 *
 * long-desc: This is the universal fallback handler for system calls that are
 *   not implemented in the running kernel. The syscall entry code redirects
 *   all invalid or unimplemented syscall numbers to this function, which
 *   unconditionally returns -ENOSYS to indicate the operation is not supported.
 *
 *   This function serves several critical roles in the syscall infrastructure:
 *
 *   1. Default handler for invalid syscall numbers: When userspace invokes a
 *      syscall number that falls outside the valid range or corresponds to an
 *      unassigned slot in the syscall table, the entry code dispatches to this
 *      function via the sys_call_table's default case.
 *
 *   2. Placeholder for conditionally compiled syscalls: Many syscalls are only
 *      available when specific kernel configuration options are enabled (e.g.,
 *      CONFIG_AIO for io_setup, CONFIG_FUTEX for futex). The COND_SYSCALL macro
 *      creates weak symbols that resolve to sys_ni_syscall when the actual
 *      implementation is not compiled in. This allows userspace to probe for
 *      feature availability at runtime by checking for ENOSYS.
 *
 *   3. Stub for deprecated or removed syscalls: Syscall numbers are never
 *      reused once assigned, even after the syscall is removed. The syscall
 *      table entry is pointed to sys_ni_syscall to maintain ABI stability
 *      while clearly indicating the syscall is no longer available.
 *
 *   4. Architecture-specific syscall fallback: Some syscalls only make sense
 *      on specific architectures (e.g., vm86 on x86-32, subpage_prot on
 *      PowerPC). On other architectures, these slots point to sys_ni_syscall.
 *
 *   The ENOSYS error code is specifically reserved for this purpose. According
 *   to POSIX and the kernel's errno header, syscall implementations should
 *   refrain from returning -ENOSYS for any other reason, as userspace relies
 *   on this error to distinguish "syscall does not exist" from "syscall failed
 *   for other reasons". This allows robust feature detection patterns like:
 *
 *     ret = syscall(__NR_new_feature, ...);
 *     if (ret == -1 && errno == ENOSYS) {
 *         // Fall back to older API
 *     }
 *
 *   Note that seccomp filters may also cause ENOSYS (or EPERM) to be returned
 *   for syscalls that do exist, which can confuse feature detection. Container
 *   runtimes using OCI's default seccomp profile return EPERM for blocked
 *   syscalls rather than ENOSYS to preserve this distinction.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_ATOMIC
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_EXACT
 *   success: (none)
 *   desc: Always returns -ENOSYS (errno 38, "Invalid system call number" or
 *     "Function not implemented"). This function never succeeds; its sole
 *     purpose is to report that the requested syscall is not available.
 *
 * error: ENOSYS, Function not implemented
 *   desc: Always returned. Indicates that the syscall number used to invoke
 *     this function does not correspond to an implemented system call in the
 *     running kernel. This may be because: (1) the syscall number is invalid
 *     or out of range, (2) the syscall was never implemented, (3) the syscall
 *     requires a kernel config option that is disabled (e.g., CONFIG_AIO,
 *     CONFIG_FUTEX, CONFIG_NET), (4) the syscall is deprecated or removed,
 *     (5) the syscall is architecture-specific and not available on the
 *     current architecture, or (6) the syscall table entry was explicitly
 *     set to sys_ni_syscall. Userspace should interpret this error as a
 *     definitive "this syscall does not exist" response and use fallback
 *     mechanisms if available.
 *
 * notes: This function takes no parameters, acquires no locks, allocates no
 *   memory, and has no side effects beyond returning an error code. It is
 *   designed to be as simple and fast as possible since it may be called
 *   frequently during syscall probing or when running binaries compiled for
 *   newer kernel versions.
 *
 *   The function is declared with 'asmlinkage' to ensure the correct calling
 *   convention for syscall entry points, even though it takes no arguments.
 *   On architectures with syscall wrappers (CONFIG_ARCH_HAS_SYSCALL_WRAPPER),
 *   there are also __x64_sys_ni_syscall and __ia32_sys_ni_syscall variants
 *   that accept pt_regs but ignore them.
 *
 *   The cond_syscall() macro in include/linux/linkage.h creates weak symbol
 *   aliases that point to sys_ni_syscall. This mechanism allows the syscall
 *   table to reference syscall implementations that may or may not exist at
 *   link time, with missing implementations automatically falling back to
 *   this stub.
 *
 * since-version: 1.0
 */
asmlinkage long sys_ni_syscall(void)
{
	return -ENOSYS;
}

#ifndef COND_SYSCALL
#define COND_SYSCALL(name) cond_syscall(sys_##name)
#endif /* COND_SYSCALL */

#ifndef COND_SYSCALL_COMPAT
#define COND_SYSCALL_COMPAT(name) cond_syscall(compat_sys_##name)
#endif /* COND_SYSCALL_COMPAT */

/*
 * This list is kept in the same order as include/uapi/asm-generic/unistd.h.
 * Architecture specific entries go below, followed by deprecated or obsolete
 * system calls.
 */

COND_SYSCALL(io_setup);
COND_SYSCALL_COMPAT(io_setup);
COND_SYSCALL(io_destroy);
COND_SYSCALL(io_submit);
COND_SYSCALL_COMPAT(io_submit);
COND_SYSCALL(io_cancel);
COND_SYSCALL(io_getevents_time32);
COND_SYSCALL(io_getevents);
COND_SYSCALL(io_pgetevents_time32);
COND_SYSCALL(io_pgetevents);
COND_SYSCALL_COMPAT(io_pgetevents);
COND_SYSCALL_COMPAT(io_pgetevents_time64);
COND_SYSCALL(io_uring_setup);
COND_SYSCALL(io_uring_enter);
COND_SYSCALL(io_uring_register);
COND_SYSCALL(eventfd2);
COND_SYSCALL(epoll_create1);
COND_SYSCALL(epoll_ctl);
COND_SYSCALL(epoll_pwait);
COND_SYSCALL_COMPAT(epoll_pwait);
COND_SYSCALL(epoll_pwait2);
COND_SYSCALL_COMPAT(epoll_pwait2);
COND_SYSCALL(inotify_init1);
COND_SYSCALL(inotify_add_watch);
COND_SYSCALL(inotify_rm_watch);
COND_SYSCALL(ioprio_set);
COND_SYSCALL(ioprio_get);
COND_SYSCALL(flock);
COND_SYSCALL(quotactl);
COND_SYSCALL(quotactl_fd);
COND_SYSCALL(signalfd4);
COND_SYSCALL_COMPAT(signalfd4);
COND_SYSCALL(timerfd_create);
COND_SYSCALL(timerfd_settime);
COND_SYSCALL(timerfd_settime32);
COND_SYSCALL(timerfd_gettime);
COND_SYSCALL(timerfd_gettime32);
COND_SYSCALL(acct);
COND_SYSCALL(capget);
COND_SYSCALL(capset);
COND_SYSCALL(futex);
COND_SYSCALL(futex_time32);
COND_SYSCALL(set_robust_list);
COND_SYSCALL_COMPAT(set_robust_list);
COND_SYSCALL(get_robust_list);
COND_SYSCALL_COMPAT(get_robust_list);
COND_SYSCALL(futex_waitv);
COND_SYSCALL(futex_wake);
COND_SYSCALL(futex_wait);
COND_SYSCALL(futex_requeue);
COND_SYSCALL(kexec_load);
COND_SYSCALL_COMPAT(kexec_load);
COND_SYSCALL(init_module);
COND_SYSCALL(delete_module);
COND_SYSCALL(syslog);
COND_SYSCALL(setregid);
COND_SYSCALL(setgid);
COND_SYSCALL(setreuid);
COND_SYSCALL(setuid);
COND_SYSCALL(setresuid);
COND_SYSCALL(getresuid);
COND_SYSCALL(setresgid);
COND_SYSCALL(getresgid);
COND_SYSCALL(setfsuid);
COND_SYSCALL(setfsgid);
COND_SYSCALL(setgroups);
COND_SYSCALL(getgroups);
COND_SYSCALL(mq_open);
COND_SYSCALL_COMPAT(mq_open);
COND_SYSCALL(mq_unlink);
COND_SYSCALL(mq_timedsend);
COND_SYSCALL(mq_timedsend_time32);
COND_SYSCALL(mq_timedreceive);
COND_SYSCALL(mq_timedreceive_time32);
COND_SYSCALL(mq_notify);
COND_SYSCALL_COMPAT(mq_notify);
COND_SYSCALL(mq_getsetattr);
COND_SYSCALL_COMPAT(mq_getsetattr);
COND_SYSCALL(msgget);
COND_SYSCALL(old_msgctl);
COND_SYSCALL(msgctl);
COND_SYSCALL_COMPAT(msgctl);
COND_SYSCALL_COMPAT(old_msgctl);
COND_SYSCALL(msgrcv);
COND_SYSCALL_COMPAT(msgrcv);
COND_SYSCALL(msgsnd);
COND_SYSCALL_COMPAT(msgsnd);
COND_SYSCALL(semget);
COND_SYSCALL(old_semctl);
COND_SYSCALL(semctl);
COND_SYSCALL_COMPAT(semctl);
COND_SYSCALL_COMPAT(old_semctl);
COND_SYSCALL(semtimedop);
COND_SYSCALL(semtimedop_time32);
COND_SYSCALL(semop);
COND_SYSCALL(shmget);
COND_SYSCALL(old_shmctl);
COND_SYSCALL(shmctl);
COND_SYSCALL_COMPAT(shmctl);
COND_SYSCALL_COMPAT(old_shmctl);
COND_SYSCALL(shmat);
COND_SYSCALL_COMPAT(shmat);
COND_SYSCALL(shmdt);
COND_SYSCALL(socket);
COND_SYSCALL(socketpair);
COND_SYSCALL(bind);
COND_SYSCALL(listen);
COND_SYSCALL(accept);
COND_SYSCALL(connect);
COND_SYSCALL(getsockname);
COND_SYSCALL(getpeername);
COND_SYSCALL(setsockopt);
COND_SYSCALL_COMPAT(setsockopt);
COND_SYSCALL(getsockopt);
COND_SYSCALL_COMPAT(getsockopt);
COND_SYSCALL(sendto);
COND_SYSCALL(shutdown);
COND_SYSCALL(recvfrom);
COND_SYSCALL_COMPAT(recvfrom);
COND_SYSCALL(sendmsg);
COND_SYSCALL_COMPAT(sendmsg);
COND_SYSCALL(recvmsg);
COND_SYSCALL_COMPAT(recvmsg);
COND_SYSCALL(mremap);
COND_SYSCALL(add_key);
COND_SYSCALL(request_key);
COND_SYSCALL(keyctl);
COND_SYSCALL_COMPAT(keyctl);
COND_SYSCALL(landlock_create_ruleset);
COND_SYSCALL(landlock_add_rule);
COND_SYSCALL(landlock_restrict_self);
COND_SYSCALL(fadvise64_64);
COND_SYSCALL_COMPAT(fadvise64_64);
COND_SYSCALL(lsm_get_self_attr);
COND_SYSCALL(lsm_set_self_attr);
COND_SYSCALL(lsm_list_modules);

/* CONFIG_MMU only */
COND_SYSCALL(swapon);
COND_SYSCALL(swapoff);
COND_SYSCALL(mprotect);
COND_SYSCALL(msync);
COND_SYSCALL(mlock);
COND_SYSCALL(munlock);
COND_SYSCALL(mlockall);
COND_SYSCALL(munlockall);
COND_SYSCALL(mincore);
COND_SYSCALL(madvise);
COND_SYSCALL(process_madvise);
COND_SYSCALL(process_mrelease);
COND_SYSCALL(remap_file_pages);
COND_SYSCALL(mbind);
COND_SYSCALL(get_mempolicy);
COND_SYSCALL(set_mempolicy);
COND_SYSCALL(migrate_pages);
COND_SYSCALL(move_pages);
COND_SYSCALL(set_mempolicy_home_node);
COND_SYSCALL(cachestat);
COND_SYSCALL(mseal);

COND_SYSCALL(perf_event_open);
COND_SYSCALL(accept4);
COND_SYSCALL(recvmmsg);
COND_SYSCALL(recvmmsg_time32);
COND_SYSCALL_COMPAT(recvmmsg_time32);
COND_SYSCALL_COMPAT(recvmmsg_time64);

/* Posix timer syscalls may be configured out */
COND_SYSCALL(timer_create);
COND_SYSCALL(timer_gettime);
COND_SYSCALL(timer_getoverrun);
COND_SYSCALL(timer_settime);
COND_SYSCALL(timer_delete);
COND_SYSCALL(clock_adjtime);
COND_SYSCALL(getitimer);
COND_SYSCALL(setitimer);
COND_SYSCALL(alarm);
COND_SYSCALL_COMPAT(timer_create);
COND_SYSCALL_COMPAT(getitimer);
COND_SYSCALL_COMPAT(setitimer);

/*
 * Architecture specific syscalls: see further below
 */

/* fanotify */
COND_SYSCALL(fanotify_init);
COND_SYSCALL(fanotify_mark);

/* open by handle */
COND_SYSCALL(name_to_handle_at);
COND_SYSCALL(open_by_handle_at);
COND_SYSCALL_COMPAT(open_by_handle_at);

COND_SYSCALL(sendmmsg);
COND_SYSCALL_COMPAT(sendmmsg);
COND_SYSCALL(process_vm_readv);
COND_SYSCALL_COMPAT(process_vm_readv);
COND_SYSCALL(process_vm_writev);
COND_SYSCALL_COMPAT(process_vm_writev);

/* compare kernel pointers */
COND_SYSCALL(kcmp);

COND_SYSCALL(finit_module);

/* operate on Secure Computing state */
COND_SYSCALL(seccomp);

COND_SYSCALL(memfd_create);

/* access BPF programs and maps */
COND_SYSCALL(bpf);

/* execveat */
COND_SYSCALL(execveat);

COND_SYSCALL(userfaultfd);

/* membarrier */
COND_SYSCALL(membarrier);

COND_SYSCALL(mlock2);

COND_SYSCALL(copy_file_range);

/* memory protection keys */
COND_SYSCALL(pkey_mprotect);
COND_SYSCALL(pkey_alloc);
COND_SYSCALL(pkey_free);

/* memfd_secret */
COND_SYSCALL(memfd_secret);

/*
 * Architecture specific weak syscall entries.
 */

/* pciconfig: alpha, arm, arm64, ia64, sparc */
COND_SYSCALL(pciconfig_read);
COND_SYSCALL(pciconfig_write);
COND_SYSCALL(pciconfig_iobase);

/* sys_socketcall: arm, mips, x86, ... */
COND_SYSCALL(socketcall);
COND_SYSCALL_COMPAT(socketcall);

/* compat syscalls for arm64, x86, ... */
COND_SYSCALL_COMPAT(fanotify_mark);

/* x86 */
COND_SYSCALL(vm86old);
COND_SYSCALL(modify_ldt);
COND_SYSCALL(vm86);
COND_SYSCALL(kexec_file_load);
COND_SYSCALL(map_shadow_stack);

/* s390 */
COND_SYSCALL(s390_pci_mmio_read);
COND_SYSCALL(s390_pci_mmio_write);
COND_SYSCALL(s390_ipc);
COND_SYSCALL_COMPAT(s390_ipc);

/* powerpc */
COND_SYSCALL(rtas);
COND_SYSCALL(spu_run);
COND_SYSCALL(spu_create);
COND_SYSCALL(subpage_prot);


/*
 * Deprecated system calls which are still defined in
 * include/uapi/asm-generic/unistd.h and wanted by >= 1 arch
 */

/* __ARCH_WANT_SYSCALL_NO_FLAGS */
COND_SYSCALL(epoll_create);
COND_SYSCALL(inotify_init);
COND_SYSCALL(eventfd);
COND_SYSCALL(signalfd);
COND_SYSCALL_COMPAT(signalfd);

/* __ARCH_WANT_SYSCALL_OFF_T */
COND_SYSCALL(fadvise64);

/* __ARCH_WANT_SYSCALL_DEPRECATED */
COND_SYSCALL(epoll_wait);
COND_SYSCALL(recv);
COND_SYSCALL_COMPAT(recv);
COND_SYSCALL(send);
COND_SYSCALL(uselib);

/* optional: time32 */
COND_SYSCALL(time32);
COND_SYSCALL(stime32);
COND_SYSCALL(utime32);
COND_SYSCALL(adjtimex_time32);
COND_SYSCALL(sched_rr_get_interval_time32);
COND_SYSCALL(nanosleep_time32);
COND_SYSCALL(rt_sigtimedwait_time32);
COND_SYSCALL_COMPAT(rt_sigtimedwait_time32);
COND_SYSCALL(timer_settime32);
COND_SYSCALL(timer_gettime32);
COND_SYSCALL(clock_settime32);
COND_SYSCALL(clock_gettime32);
COND_SYSCALL(clock_getres_time32);
COND_SYSCALL(clock_nanosleep_time32);
COND_SYSCALL(utimes_time32);
COND_SYSCALL(futimesat_time32);
COND_SYSCALL(pselect6_time32);
COND_SYSCALL_COMPAT(pselect6_time32);
COND_SYSCALL(ppoll_time32);
COND_SYSCALL_COMPAT(ppoll_time32);
COND_SYSCALL(utimensat_time32);
COND_SYSCALL(clock_adjtime32);

/*
 * The syscalls below are not found in include/uapi/asm-generic/unistd.h
 */

/* obsolete: SGETMASK_SYSCALL */
COND_SYSCALL(sgetmask);
COND_SYSCALL(ssetmask);

/* obsolete: SYSFS_SYSCALL */
COND_SYSCALL(sysfs);

/* obsolete: __ARCH_WANT_SYS_IPC */
COND_SYSCALL(ipc);
COND_SYSCALL_COMPAT(ipc);

/* obsolete: UID16 */
COND_SYSCALL(chown16);
COND_SYSCALL(fchown16);
COND_SYSCALL(getegid16);
COND_SYSCALL(geteuid16);
COND_SYSCALL(getgid16);
COND_SYSCALL(getgroups16);
COND_SYSCALL(getresgid16);
COND_SYSCALL(getresuid16);
COND_SYSCALL(getuid16);
COND_SYSCALL(lchown16);
COND_SYSCALL(setfsgid16);
COND_SYSCALL(setfsuid16);
COND_SYSCALL(setgid16);
COND_SYSCALL(setgroups16);
COND_SYSCALL(setregid16);
COND_SYSCALL(setresgid16);
COND_SYSCALL(setresuid16);
COND_SYSCALL(setreuid16);
COND_SYSCALL(setuid16);

/* restartable sequence */
COND_SYSCALL(rseq);

COND_SYSCALL(uretprobe);
COND_SYSCALL(uprobe);
