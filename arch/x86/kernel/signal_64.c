// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2000, 2001, 2002 Andi Kleen SuSE Labs
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>

#include <asm/ucontext.h>
#include <asm/fpu/signal.h>
#include <asm/sighandling.h>

#include <asm/syscall.h>
#include <asm/sigframe.h>
#include <asm/signal.h>

/*
 * If regs->ss will cause an IRET fault, change it.  Otherwise leave it
 * alone.  Using this generally makes no sense unless
 * user_64bit_mode(regs) would return true.
 */
static void force_valid_ss(struct pt_regs *regs)
{
	u32 ar;
	asm volatile ("lar %[old_ss], %[ar]\n\t"
		      "jz 1f\n\t"		/* If invalid: */
		      "xorl %[ar], %[ar]\n\t"	/* set ar = 0 */
		      "1:"
		      : [ar] "=r" (ar)
		      : [old_ss] "rm" ((u16)regs->ss));

	/*
	 * For a valid 64-bit user context, we need DPL 3, type
	 * read-write data or read-write exp-down data, and S and P
	 * set.  We can't use VERW because VERW doesn't check the
	 * P bit.
	 */
	ar &= AR_DPL_MASK | AR_S | AR_P | AR_TYPE_MASK;
	if (ar != (AR_DPL3 | AR_S | AR_P | AR_TYPE_RWDATA) &&
	    ar != (AR_DPL3 | AR_S | AR_P | AR_TYPE_RWDATA_EXPDOWN))
		regs->ss = __USER_DS;
}

static bool restore_sigcontext(struct pt_regs *regs,
			       struct sigcontext __user *usc,
			       unsigned long uc_flags)
{
	struct sigcontext sc;

	/* Always make any pending restarted system calls return -EINTR */
	current->restart_block.fn = do_no_restart_syscall;

	if (copy_from_user(&sc, usc, offsetof(struct sigcontext, reserved1)))
		return false;

	regs->bx = sc.bx;
	regs->cx = sc.cx;
	regs->dx = sc.dx;
	regs->si = sc.si;
	regs->di = sc.di;
	regs->bp = sc.bp;
	regs->ax = sc.ax;
	regs->sp = sc.sp;
	regs->ip = sc.ip;
	regs->r8 = sc.r8;
	regs->r9 = sc.r9;
	regs->r10 = sc.r10;
	regs->r11 = sc.r11;
	regs->r12 = sc.r12;
	regs->r13 = sc.r13;
	regs->r14 = sc.r14;
	regs->r15 = sc.r15;

	/* Get CS/SS and force CPL3 */
	regs->cs = sc.cs | 0x03;
	regs->ss = sc.ss | 0x03;

	regs->flags = (regs->flags & ~FIX_EFLAGS) | (sc.flags & FIX_EFLAGS);
	/* disable syscall checks */
	regs->orig_ax = -1;

	/*
	 * Fix up SS if needed for the benefit of old DOSEMU and
	 * CRIU.
	 */
	if (unlikely(!(uc_flags & UC_STRICT_RESTORE_SS) && user_64bit_mode(regs)))
		force_valid_ss(regs);

	return fpu__restore_sig((void __user *)sc.fpstate, 0);
}

static __always_inline int
__unsafe_setup_sigcontext(struct sigcontext __user *sc, void __user *fpstate,
		     struct pt_regs *regs, unsigned long mask)
{
	unsafe_put_user(regs->di, &sc->di, Efault);
	unsafe_put_user(regs->si, &sc->si, Efault);
	unsafe_put_user(regs->bp, &sc->bp, Efault);
	unsafe_put_user(regs->sp, &sc->sp, Efault);
	unsafe_put_user(regs->bx, &sc->bx, Efault);
	unsafe_put_user(regs->dx, &sc->dx, Efault);
	unsafe_put_user(regs->cx, &sc->cx, Efault);
	unsafe_put_user(regs->ax, &sc->ax, Efault);
	unsafe_put_user(regs->r8, &sc->r8, Efault);
	unsafe_put_user(regs->r9, &sc->r9, Efault);
	unsafe_put_user(regs->r10, &sc->r10, Efault);
	unsafe_put_user(regs->r11, &sc->r11, Efault);
	unsafe_put_user(regs->r12, &sc->r12, Efault);
	unsafe_put_user(regs->r13, &sc->r13, Efault);
	unsafe_put_user(regs->r14, &sc->r14, Efault);
	unsafe_put_user(regs->r15, &sc->r15, Efault);

	unsafe_put_user(current->thread.trap_nr, &sc->trapno, Efault);
	unsafe_put_user(current->thread.error_code, &sc->err, Efault);
	unsafe_put_user(regs->ip, &sc->ip, Efault);
	unsafe_put_user(regs->flags, &sc->flags, Efault);
	unsafe_put_user(regs->cs, &sc->cs, Efault);
	unsafe_put_user(0, &sc->gs, Efault);
	unsafe_put_user(0, &sc->fs, Efault);
	unsafe_put_user(regs->ss, &sc->ss, Efault);

	unsafe_put_user(fpstate, (unsigned long __user *)&sc->fpstate, Efault);

	/* non-iBCS2 extensions.. */
	unsafe_put_user(mask, &sc->oldmask, Efault);
	unsafe_put_user(current->thread.cr2, &sc->cr2, Efault);
	return 0;
Efault:
	return -EFAULT;
}

#define unsafe_put_sigcontext(sc, fp, regs, set, label)			\
do {									\
	if (__unsafe_setup_sigcontext(sc, fp, regs, set->sig[0]))	\
		goto label;						\
} while(0);

#define unsafe_put_sigmask(set, frame, label) \
	unsafe_put_user(*(__u64 *)(set), \
			(__u64 __user *)&(frame)->uc.uc_sigmask, \
			label)

static unsigned long frame_uc_flags(struct pt_regs *regs)
{
	unsigned long flags;

	if (boot_cpu_has(X86_FEATURE_XSAVE))
		flags = UC_FP_XSTATE | UC_SIGCONTEXT_SS;
	else
		flags = UC_SIGCONTEXT_SS;

	if (likely(user_64bit_mode(regs)))
		flags |= UC_STRICT_RESTORE_SS;

	return flags;
}

int x64_setup_rt_frame(struct ksignal *ksig, struct pt_regs *regs)
{
	sigset_t *set = sigmask_to_save();
	struct rt_sigframe __user *frame;
	void __user *fp = NULL;
	unsigned long uc_flags;

	/* x86-64 should always use SA_RESTORER. */
	if (!(ksig->ka.sa.sa_flags & SA_RESTORER))
		return -EFAULT;

	frame = get_sigframe(ksig, regs, sizeof(struct rt_sigframe), &fp);
	uc_flags = frame_uc_flags(regs);

	if (!user_access_begin(frame, sizeof(*frame)))
		return -EFAULT;

	/* Create the ucontext.  */
	unsafe_put_user(uc_flags, &frame->uc.uc_flags, Efault);
	unsafe_put_user(0, &frame->uc.uc_link, Efault);
	unsafe_save_altstack(&frame->uc.uc_stack, regs->sp, Efault);

	/* Set up to return from userspace.  If provided, use a stub
	   already in userspace.  */
	unsafe_put_user(ksig->ka.sa.sa_restorer, &frame->pretcode, Efault);
	unsafe_put_sigcontext(&frame->uc.uc_mcontext, fp, regs, set, Efault);
	unsafe_put_sigmask(set, frame, Efault);
	user_access_end();

	if (ksig->ka.sa.sa_flags & SA_SIGINFO) {
		if (copy_siginfo_to_user(&frame->info, &ksig->info))
			return -EFAULT;
	}

	if (setup_signal_shadow_stack(ksig))
		return -EFAULT;

	/* Set up registers for signal handler */
	regs->di = ksig->sig;
	/* In case the signal handler was declared without prototypes */
	regs->ax = 0;

	/* This also works for non SA_SIGINFO handlers because they expect the
	   next argument after the signal number on the stack. */
	regs->si = (unsigned long)&frame->info;
	regs->dx = (unsigned long)&frame->uc;
	regs->ip = (unsigned long) ksig->ka.sa.sa_handler;

	regs->sp = (unsigned long)frame;

	/*
	 * Set up the CS and SS registers to run signal handlers in
	 * 64-bit mode, even if the handler happens to be interrupting
	 * 32-bit or 16-bit code.
	 *
	 * SS is subtle.  In 64-bit mode, we don't need any particular
	 * SS descriptor, but we do need SS to be valid.  It's possible
	 * that the old SS is entirely bogus -- this can happen if the
	 * signal we're trying to deliver is #GP or #SS caused by a bad
	 * SS value.  We also have a compatibility issue here: DOSEMU
	 * relies on the contents of the SS register indicating the
	 * SS value at the time of the signal, even though that code in
	 * DOSEMU predates sigreturn's ability to restore SS.  (DOSEMU
	 * avoids relying on sigreturn to restore SS; instead it uses
	 * a trampoline.)  So we do our best: if the old SS was valid,
	 * we keep it.  Otherwise we replace it.
	 */
	regs->cs = __USER_CS;

	if (unlikely(regs->ss != __USER_DS))
		force_valid_ss(regs);

	return 0;

Efault:
	user_access_end();
	return -EFAULT;
}

/**
 * sys_rt_sigreturn - return from signal handler and restore process context
 *
 * long-desc: Restores the process context saved on the user stack during signal
 *   delivery, allowing execution to resume at the point where the signal
 *   interrupted the process. This syscall is called implicitly by the signal
 *   trampoline when a signal handler returns; it should NEVER be called
 *   directly by user programs.
 *
 *   When a signal is delivered, the kernel creates a signal frame on the user
 *   stack containing the complete CPU state (registers, flags, instruction
 *   pointer, stack pointer), FPU/SIMD state, blocked signal mask, and alternate
 *   signal stack configuration. The signal handler executes with a modified
 *   context, and when it returns, the signal trampoline (typically in vdso or
 *   libc) invokes this syscall to restore the original context.
 *
 *   The syscall reads the signal frame from the stack at (sp - 8) on x86-64,
 *   validates it, and restores: (1) the blocked signal mask, (2) alternate
 *   signal stack settings, (3) CPU register context including segment registers,
 *   (4) FPU/SIMD state, and (5) shadow stack pointer (on CET-enabled systems).
 *   Execution then resumes at the restored instruction pointer, not at the
 *   caller of sigreturn.
 *
 *   On x86-64, special handling exists for the SS segment selector to maintain
 *   compatibility with legacy programs like DOSEMU and CRIU. If the saved SS is
 *   invalid and UC_STRICT_RESTORE_SS is not set, the kernel substitutes a valid
 *   flat data segment instead of failing. This allows programs that construct
 *   signal frames from scratch without proper SS values to continue working.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_NO_RETURN
 *   success: restored_ax
 *   desc: This syscall does not return in the conventional sense. On success,
 *     execution resumes at the instruction pointer stored in the signal frame,
 *     with all registers restored to their saved values. The apparent "return
 *     value" seen by the resumed code is the value of RAX/EAX from the signal
 *     frame. On failure, the kernel sends SIGSEGV to the process and returns 0,
 *     but this return value is never seen as the process handles the signal.
 *
 * error: SIGSEGV, Invalid signal frame
 *   desc: If the signal frame cannot be read (address not accessible, unmapped
 *     memory, or copy_from_user fails), or if any component restoration fails
 *     (sigcontext, FPU state, alternate stack, shadow stack), the kernel sends
 *     SIGSEGV via force_sig(). The process does not see an error return code;
 *     instead it receives a SIGSEGV signal. Common causes include: corrupted
 *     stack pointer, signal frame overwritten by handler, invalid frame address
 *     not satisfying access_ok(), or deliberately malformed frame in sigreturn-
 *     oriented programming (SROP) attacks. On systems with CET shadow stack
 *     enabled, mismatched or corrupted shadow stack tokens also trigger this.
 *
 * lock: sighand->siglock
 *   type: KAPI_LOCK_SPINLOCK
 *   acquired: true
 *   released: true
 *   desc: Acquired by set_current_blocked() when restoring the signal mask.
 *     The lock is held briefly while updating current->blocked and potentially
 *     recalculating pending signals. Released before the syscall continues
 *     with other restorations.
 *
 * lock: mm->mmap_lock
 *   type: KAPI_LOCK_RWLOCK
 *   acquired: true
 *   released: true
 *   desc: On systems with shadow stack (CET) enabled, shstk_pop_sigframe() may
 *     briefly acquire the mmap_lock in read mode via mmap_read_lock_killable()
 *     to verify the shadow stack VMA when the SSP is at a page boundary. This
 *     is only acquired when the SSP is exactly page-aligned, which is uncommon.
 *     The lock is released before the function returns.
 *
 * signal: SIGSEGV
 *   direction: KAPI_SIGNAL_SEND
 *   action: KAPI_SIGNAL_ACTION_TERMINATE
 *   condition: Signal frame validation or restoration fails
 *   desc: When any step of the context restoration fails, the kernel sends
 *     SIGSEGV to the process via force_sig(SIGSEGV) in signal_fault(). This is
 *     a synchronous fault signal that cannot be blocked or ignored. If the
 *     process has a SIGSEGV handler, it will be invoked, but the original
 *     sigreturn operation has failed and cannot be retried. Causes include
 *     invalid frame address, unreadable memory, corrupt sigcontext, invalid
 *     FPU state, corrupt alternate stack data, or shadow stack token mismatch.
 *   timing: KAPI_SIGNAL_TIME_AFTER
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: CPU registers (all general purpose, RIP, RSP, RFLAGS, CS, SS)
 *   desc: All CPU general-purpose registers are restored from the sigcontext
 *     structure in the signal frame. This includes RAX-R15, RIP (instruction
 *     pointer), RSP (stack pointer), and RFLAGS. The CS and SS segment
 *     selectors are also restored, with their RPL bits forced to ring 3 for
 *     security. On success, execution continues at the restored RIP with the
 *     restored register values.
 *   reversible: no (process state is overwritten)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: FPU/SIMD state
 *   desc: The complete floating-point unit state is restored from the fpstate
 *     area in the signal frame via fpu__restore_sig(). This includes x87 FPU
 *     registers, SSE registers (XMM0-XMM15), and any extended state like AVX
 *     (YMM registers), AVX-512, or AMX state depending on CPU capabilities.
 *     If FPU state restoration fails, the FPU state is cleared to the initial
 *     state to prevent information leakage.
 *   condition: Signal frame contains FPU state (fpstate pointer non-NULL)
 *   reversible: no (FPU state is overwritten)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: current->blocked (signal mask)
 *   desc: The blocked signal mask is restored from uc_sigmask in the signal
 *     frame via set_current_blocked(). SIGKILL and SIGSTOP are automatically
 *     removed from the mask as they cannot be blocked. This may trigger
 *     immediate delivery of previously blocked signals that became unblocked.
 *   reversible: yes (via subsequent sigprocmask or signal handler)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Alternate signal stack (sas_ss_sp, sas_ss_size, sas_ss_flags)
 *   desc: The alternate signal stack settings are restored from uc_stack in
 *     the signal frame via restore_altstack(). This includes the stack base
 *     address, size, and flags (including SS_AUTODISARM if it was set).
 *     Errors from restore_altstack() are silently ignored except for EFAULT.
 *   reversible: yes (via subsequent sigaltstack syscall)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Shadow stack pointer (SSP)
 *   desc: On Intel processors with Control-flow Enforcement Technology (CET)
 *     enabled, the shadow stack pointer is restored from a token saved during
 *     signal delivery via restore_signal_shadow_stack(). The token contains
 *     the SSP value XORed with its stack address for validation. An invalid
 *     or mismatched token causes the syscall to fail with SIGSEGV.
 *   condition: CET shadow stack is enabled (X86_FEATURE_USER_SHSTK)
 *   reversible: no (shadow stack state is overwritten)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: current->restart_block.fn
 *   desc: The restart block function pointer is set to do_no_restart_syscall
 *     by restore_sigcontext(). This invalidates any pending syscall restart
 *     that was in progress when the signal was delivered, ensuring that a
 *     subsequent erroneous restart_syscall invocation returns -EINTR instead
 *     of attempting to restart a stale operation.
 *   reversible: no (restart block is invalidated)
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: FRED software event flag (on FRED-enabled systems)
 *   desc: On systems with Intel Flexible Return and Event Delivery (FRED),
 *     the software event flag in the augmented SS is cleared via
 *     prevent_single_step_upon_eretu() to prevent immediate repeat of a
 *     single-step trap when the trap flag (TF) is set. This only occurs
 *     when TF is clear in the current context (not being actively debugged).
 *   condition: FRED is enabled and TF is not set
 *   reversible: no
 *
 * state-trans: process_execution_context
 *   from: signal handler execution context
 *   to: pre-signal interrupted context
 *   condition: Successful sigreturn completion
 *   desc: The process transitions from executing in the signal handler context
 *     (with potentially different register values, signal mask, and stack) back
 *     to the context that existed when the signal was delivered. All register
 *     values, the signal mask, and the alternate signal stack configuration are
 *     restored to their pre-signal state.
 *
 * constraint: Signal frame must be valid and accessible
 *   desc: The signal frame must be located at a valid user-space address that
 *     passes access_ok() verification. The frame address is computed as
 *     (sp - 8) on x86-64. The frame must contain valid data written by the
 *     kernel during signal delivery. User modification of the frame is
 *     supported (this is how handlers like DOSEMU work), but invalid data
 *     causes SIGSEGV.
 *
 * constraint: Must be called from signal trampoline only
 *   desc: This syscall is intended to be called only from the signal
 *     trampoline code that the kernel arranges to execute when a signal
 *     handler returns. The trampoline is typically located in the vdso
 *     (vdso_image.sym___kernel_rt_sigreturn) or in glibc. Direct calls
 *     from application code will fail because the stack does not contain
 *     a valid signal frame at the expected location.
 *
 * constraint: Segment selectors forced to ring 3
 *   desc: For security, the restored CS and SS segment selectors have their
 *     RPL (Requested Privilege Level) bits forced to 3 (user mode) via
 *     OR with 0x03. This prevents privilege escalation by manipulating the
 *     signal frame to contain kernel segment selectors.
 *
 * constraint: EFLAGS sanitization
 *   desc: Only certain EFLAGS bits are restored from the signal frame
 *     (defined by FIX_EFLAGS mask: AC, OF, DF, TF, SF, ZF, AF, PF, CF, RF).
 *     System flags like IOPL and IF are not restored from user-controlled
 *     data for security.
 *
 * examples:
 *   // This syscall should NEVER be called directly. It is invoked by the
 *   // signal trampoline. The following shows the kernel-internal flow:
 *   // 1. Signal delivered: kernel creates signal frame on user stack
 *   // 2. Signal handler executes
 *   // 3. Handler returns to trampoline (in vdso or libc)
 *   // 4. Trampoline: mov $15, %rax; syscall  // NR_rt_sigreturn
 *   // 5. Kernel restores context, execution resumes at interrupted location
 *   //
 *   // Direct syscall (will fail without proper frame):
 *   // syscall(SYS_rt_sigreturn);  // DON'T DO THIS - causes SIGSEGV
 *
 * notes:
 *   This syscall is architecture-specific. Each architecture implements its own
 *   version to handle its unique register set and calling conventions. On x86,
 *   there are multiple variants: rt_sigreturn for 64-bit, sys32_rt_sigreturn
 *   for 32-bit compatibility, and x32_rt_sigreturn for the x32 ABI.
 *
 *   SECURITY: This syscall is the target of sigreturn-oriented programming
 *   (SROP) attacks where an attacker crafts a fake signal frame on the stack
 *   to gain arbitrary control of register values via a single gadget. While
 *   the kernel cannot prevent SROP attacks entirely (as the frame must be
 *   modifiable for legitimate use cases), it does validate frame addresses
 *   and sanitizes security-critical values like segment selectors and EFLAGS.
 *   Some kernels implement additional mitigations like frame cookies, though
 *   this is not universal. See LWN.net article on "Sigreturn-oriented
 *   programming and its mitigation" for details.
 *
 *   The UC_SIGCONTEXT_SS and UC_STRICT_RESTORE_SS flags in uc_flags control SS
 *   restoration behavior for compatibility with legacy programs. When
 *   UC_STRICT_RESTORE_SS is set (for signals from 64-bit code), the saved SS
 *   is restored exactly. When clear (for signals from segmented 16/32-bit code
 *   or legacy sigframes), an invalid SS is silently replaced with __USER_DS.
 *   This is needed for DOSEMU and old CRIU versions.
 *
 *   The syscall number is 15 on x86-64 and 173 on i386. The signal trampoline
 *   code that invokes this syscall is typically in the vdso, making it subject
 *   to ASLR. However, the syscall itself requires no arguments since all
 *   necessary information is on the stack.
 *
 *   glibc does not provide a wrapper for this syscall. The glibc "sigreturn"
 *   function simply returns -1 with errno set to ENOSYS because direct calls
 *   are never correct.
 *
 * since-version: 2.2
 */
SYSCALL_DEFINE0(rt_sigreturn)
{
	struct pt_regs *regs = current_pt_regs();
	struct rt_sigframe __user *frame;
	sigset_t set;
	unsigned long uc_flags;

	prevent_single_step_upon_eretu(regs);

	frame = (struct rt_sigframe __user *)(regs->sp - sizeof(long));
	if (!access_ok(frame, sizeof(*frame)))
		goto badframe;
	if (__get_user(*(__u64 *)&set, (__u64 __user *)&frame->uc.uc_sigmask))
		goto badframe;
	if (__get_user(uc_flags, &frame->uc.uc_flags))
		goto badframe;

	set_current_blocked(&set);

	if (restore_altstack(&frame->uc.uc_stack))
		goto badframe;

	if (!restore_sigcontext(regs, &frame->uc.uc_mcontext, uc_flags))
		goto badframe;

	if (restore_signal_shadow_stack())
		goto badframe;

	return regs->ax;

badframe:
	signal_fault(regs, frame, "rt_sigreturn");
	return 0;
}

#ifdef CONFIG_X86_X32_ABI
static int x32_copy_siginfo_to_user(struct compat_siginfo __user *to,
		const struct kernel_siginfo *from)
{
	struct compat_siginfo new;

	copy_siginfo_to_external32(&new, from);
	if (from->si_signo == SIGCHLD) {
		new._sifields._sigchld_x32._utime = from->si_utime;
		new._sifields._sigchld_x32._stime = from->si_stime;
	}
	if (copy_to_user(to, &new, sizeof(struct compat_siginfo)))
		return -EFAULT;
	return 0;
}

int copy_siginfo_to_user32(struct compat_siginfo __user *to,
			   const struct kernel_siginfo *from)
{
	if (in_x32_syscall())
		return x32_copy_siginfo_to_user(to, from);
	return __copy_siginfo_to_user32(to, from);
}

int x32_setup_rt_frame(struct ksignal *ksig, struct pt_regs *regs)
{
	compat_sigset_t *set = (compat_sigset_t *) sigmask_to_save();
	struct rt_sigframe_x32 __user *frame;
	unsigned long uc_flags;
	void __user *restorer;
	void __user *fp = NULL;

	if (!(ksig->ka.sa.sa_flags & SA_RESTORER))
		return -EFAULT;

	frame = get_sigframe(ksig, regs, sizeof(*frame), &fp);

	uc_flags = frame_uc_flags(regs);

	if (setup_signal_shadow_stack(ksig))
		return -EFAULT;

	if (!user_access_begin(frame, sizeof(*frame)))
		return -EFAULT;

	/* Create the ucontext.  */
	unsafe_put_user(uc_flags, &frame->uc.uc_flags, Efault);
	unsafe_put_user(0, &frame->uc.uc_link, Efault);
	unsafe_compat_save_altstack(&frame->uc.uc_stack, regs->sp, Efault);
	unsafe_put_user(0, &frame->uc.uc__pad0, Efault);
	restorer = ksig->ka.sa.sa_restorer;
	unsafe_put_user(restorer, (unsigned long __user *)&frame->pretcode, Efault);
	unsafe_put_sigcontext(&frame->uc.uc_mcontext, fp, regs, set, Efault);
	unsafe_put_sigmask(set, frame, Efault);
	user_access_end();

	if (ksig->ka.sa.sa_flags & SA_SIGINFO) {
		if (x32_copy_siginfo_to_user(&frame->info, &ksig->info))
			return -EFAULT;
	}

	/* Set up registers for signal handler */
	regs->sp = (unsigned long) frame;
	regs->ip = (unsigned long) ksig->ka.sa.sa_handler;

	/* We use the x32 calling convention here... */
	regs->di = ksig->sig;
	regs->si = (unsigned long) &frame->info;
	regs->dx = (unsigned long) &frame->uc;

	loadsegment(ds, __USER_DS);
	loadsegment(es, __USER_DS);

	regs->cs = __USER_CS;
	regs->ss = __USER_DS;

	return 0;

Efault:
	user_access_end();
	return -EFAULT;
}

COMPAT_SYSCALL_DEFINE0(x32_rt_sigreturn)
{
	struct pt_regs *regs = current_pt_regs();
	struct rt_sigframe_x32 __user *frame;
	sigset_t set;
	unsigned long uc_flags;

	prevent_single_step_upon_eretu(regs);

	frame = (struct rt_sigframe_x32 __user *)(regs->sp - 8);

	if (!access_ok(frame, sizeof(*frame)))
		goto badframe;
	if (__get_user(set.sig[0], (__u64 __user *)&frame->uc.uc_sigmask))
		goto badframe;
	if (__get_user(uc_flags, &frame->uc.uc_flags))
		goto badframe;

	set_current_blocked(&set);

	if (!restore_sigcontext(regs, &frame->uc.uc_mcontext, uc_flags))
		goto badframe;

	if (restore_signal_shadow_stack())
		goto badframe;

	if (compat_restore_altstack(&frame->uc.uc_stack))
		goto badframe;

	return regs->ax;

badframe:
	signal_fault(regs, frame, "x32 rt_sigreturn");
	return 0;
}
#endif /* CONFIG_X86_X32_ABI */

#ifdef CONFIG_COMPAT
void sigaction_compat_abi(struct k_sigaction *act, struct k_sigaction *oact)
{
	if (!act)
		return;

	if (in_ia32_syscall())
		act->sa.sa_flags |= SA_IA32_ABI;
	if (in_x32_syscall())
		act->sa.sa_flags |= SA_X32_ABI;
}
#endif /* CONFIG_COMPAT */

/*
* If adding a new si_code, there is probably new data in
* the siginfo.  Make sure folks bumping the si_code
* limits also have to look at this code.  Make sure any
* new fields are handled in copy_siginfo_to_user32()!
*/
static_assert(NSIGILL  == 11);
static_assert(NSIGFPE  == 15);
static_assert(NSIGSEGV == 10);
static_assert(NSIGBUS  == 5);
static_assert(NSIGTRAP == 6);
static_assert(NSIGCHLD == 6);
static_assert(NSIGSYS  == 2);

/* This is part of the ABI and can never change in size: */
static_assert(sizeof(siginfo_t) == 128);

/* This is a part of the ABI and can never change in alignment */
static_assert(__alignof__(siginfo_t) == 8);

/*
* The offsets of all the (unioned) si_fields are fixed
* in the ABI, of course.  Make sure none of them ever
* move and are always at the beginning:
*/
static_assert(offsetof(siginfo_t, si_signo) == 0);
static_assert(offsetof(siginfo_t, si_errno) == 4);
static_assert(offsetof(siginfo_t, si_code)  == 8);

/*
* Ensure that the size of each si_field never changes.
* If it does, it is a sign that the
* copy_siginfo_to_user32() code below needs to updated
* along with the size in the CHECK_SI_SIZE().
*
* We repeat this check for both the generic and compat
* siginfos.
*
* Note: it is OK for these to grow as long as the whole
* structure stays within the padding size (checked
* above).
*/

#define CHECK_SI_OFFSET(name)						\
	static_assert(offsetof(siginfo_t, _sifields) == 		\
		      offsetof(siginfo_t, _sifields.name))
#define CHECK_SI_SIZE(name, size)					\
	static_assert(sizeof_field(siginfo_t, _sifields.name) == size)

CHECK_SI_OFFSET(_kill);
CHECK_SI_SIZE  (_kill, 2*sizeof(int));
static_assert(offsetof(siginfo_t, si_pid) == 0x10);
static_assert(offsetof(siginfo_t, si_uid) == 0x14);

CHECK_SI_OFFSET(_timer);
CHECK_SI_SIZE  (_timer, 6*sizeof(int));
static_assert(offsetof(siginfo_t, si_tid)     == 0x10);
static_assert(offsetof(siginfo_t, si_overrun) == 0x14);
static_assert(offsetof(siginfo_t, si_value)   == 0x18);

CHECK_SI_OFFSET(_rt);
CHECK_SI_SIZE  (_rt, 4*sizeof(int));
static_assert(offsetof(siginfo_t, si_pid)   == 0x10);
static_assert(offsetof(siginfo_t, si_uid)   == 0x14);
static_assert(offsetof(siginfo_t, si_value) == 0x18);

CHECK_SI_OFFSET(_sigchld);
CHECK_SI_SIZE  (_sigchld, 8*sizeof(int));
static_assert(offsetof(siginfo_t, si_pid)    == 0x10);
static_assert(offsetof(siginfo_t, si_uid)    == 0x14);
static_assert(offsetof(siginfo_t, si_status) == 0x18);
static_assert(offsetof(siginfo_t, si_utime)  == 0x20);
static_assert(offsetof(siginfo_t, si_stime)  == 0x28);

#ifdef CONFIG_X86_X32_ABI
/* no _sigchld_x32 in the generic siginfo_t */
static_assert(sizeof_field(compat_siginfo_t, _sifields._sigchld_x32) ==
	      7*sizeof(int));
static_assert(offsetof(compat_siginfo_t, _sifields) ==
	      offsetof(compat_siginfo_t, _sifields._sigchld_x32));
static_assert(offsetof(compat_siginfo_t, _sifields._sigchld_x32._utime)  == 0x18);
static_assert(offsetof(compat_siginfo_t, _sifields._sigchld_x32._stime)  == 0x20);
#endif

CHECK_SI_OFFSET(_sigfault);
CHECK_SI_SIZE  (_sigfault, 8*sizeof(int));
static_assert(offsetof(siginfo_t, si_addr)	== 0x10);

static_assert(offsetof(siginfo_t, si_trapno)	== 0x18);

static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x18);

static_assert(offsetof(siginfo_t, si_lower)	== 0x20);
static_assert(offsetof(siginfo_t, si_upper)	== 0x28);

static_assert(offsetof(siginfo_t, si_pkey)	== 0x20);

static_assert(offsetof(siginfo_t, si_perf_data)	 == 0x18);
static_assert(offsetof(siginfo_t, si_perf_type)	 == 0x20);
static_assert(offsetof(siginfo_t, si_perf_flags) == 0x24);

CHECK_SI_OFFSET(_sigpoll);
CHECK_SI_SIZE  (_sigpoll, 4*sizeof(int));
static_assert(offsetof(siginfo_t, si_band) == 0x10);
static_assert(offsetof(siginfo_t, si_fd)   == 0x18);

CHECK_SI_OFFSET(_sigsys);
CHECK_SI_SIZE  (_sigsys, 4*sizeof(int));
static_assert(offsetof(siginfo_t, si_call_addr) == 0x10);
static_assert(offsetof(siginfo_t, si_syscall)   == 0x18);
static_assert(offsetof(siginfo_t, si_arch)      == 0x1C);

/* any new si_fields should be added here */
