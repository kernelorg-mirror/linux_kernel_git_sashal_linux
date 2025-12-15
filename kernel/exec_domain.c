// SPDX-License-Identifier: GPL-2.0
/*
 * Handling of different ABIs (personalities).
 *
 * We group personalities into execution domains which have their
 * own handlers for kernel entry points, signal mapping, etc...
 *
 * 2001-05-06	Complete rewrite,  Christoph Hellwig (hch@infradead.org)
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/personality.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/sysctl.h>
#include <linux/types.h>

#ifdef CONFIG_PROC_FS
static int execdomains_proc_show(struct seq_file *m, void *v)
{
	seq_puts(m, "0-0\tLinux           \t[kernel]\n");
	return 0;
}

static int __init proc_execdomains_init(void)
{
	proc_create_single("execdomains", 0, NULL, execdomains_proc_show);
	return 0;
}
module_init(proc_execdomains_init);
#endif

/**
 * sys_personality - Set or retrieve the process execution domain (personality)
 * @personality: New personality value to set, or 0xffffffff to query only
 *
 * long-desc: Sets the process execution domain (personality) for the calling
 *   process, which controls various aspects of system call behavior and
 *   binary compatibility. The personality mechanism was originally designed
 *   to allow Linux to emulate the behavior of other UNIX-like operating
 *   systems (SVR4, BSD, etc.) by modifying signal numbering and system call
 *   semantics. While the execution domain module support has been removed
 *   from the kernel (as of Linux 4.0), the personality flags remain useful
 *   for controlling process behavior such as address space layout
 *   randomization and memory protection.
 *
 *   The @personality parameter is a 32-bit value divided into two parts:
 *   - Low byte (bits 0-7): Personality type identifier (PER_MASK = 0xff)
 *   - Upper bytes (bits 8-31): Behavioral flags
 *
 *   The special value 0xffffffff queries the current personality without
 *   modifying it. Any other value sets the new personality unconditionally.
 *
 *   Supported personality types (low byte):
 *   - PER_LINUX (0x00): Standard Linux behavior
 *   - PER_LINUX_32BIT (0x00 | ADDR_LIMIT_32BIT): 32-bit address space limit
 *   - PER_LINUX_FDPIC (0x00 | FDPIC_FUNCPTRS): FDPIC function pointer ABI
 *   - PER_LINUX32 (0x08): 32-bit personality for 64-bit kernels
 *   - PER_SVR4 (0x01): SVR4 compatibility (mostly obsolete)
 *   - PER_SVR3 (0x02): SVR3 compatibility (mostly obsolete)
 *   - PER_BSD (0x06): BSD compatibility (mostly obsolete)
 *   - And others for historical UNIX variant compatibility
 *
 *   Supported behavioral flags (upper bytes):
 *   - UNAME26 (0x0020000): Report kernel version as 2.6.x in uname(2)
 *   - ADDR_NO_RANDOMIZE (0x0040000): Disable address space layout
 *     randomization (ASLR) for this process. Affects stack, mmap, heap,
 *     and VDSO placement.
 *   - FDPIC_FUNCPTRS (0x0080000): Function pointers point to descriptors
 *     rather than code addresses (used for FDPIC ELF binaries)
 *   - MMAP_PAGE_ZERO (0x0100000): Map the first page of memory (address 0)
 *     to allow dereferencing NULL pointers without SIGSEGV. Required for
 *     some legacy binaries.
 *   - ADDR_COMPAT_LAYOUT (0x0200000): Use legacy (pre-2.6.7) memory layout
 *     with libraries loaded at low addresses. Significantly reduces ASLR
 *     effectiveness.
 *   - READ_IMPLIES_EXEC (0x0400000): Make readable memory pages also
 *     executable. Provides compatibility for older programs that rely on
 *     this behavior but weakens security (W^X protection).
 *   - ADDR_LIMIT_32BIT (0x0800000): Limit virtual address space to 32 bits
 *   - SHORT_INODE (0x1000000): Report short inode numbers (legacy)
 *   - WHOLE_SECONDS (0x2000000): Report only whole seconds in stat times
 *   - STICKY_TIMEOUTS (0x4000000): Do not modify timeout arguments to
 *     select(2), pselect(2), ppoll(2) to reflect remaining time after
 *     signal interruption. Normally these syscalls update the timeout
 *     struct; this flag preserves the original values.
 *   - ADDR_LIMIT_3GB (0x8000000): Limit user address space to 3GB (x86)
 *
 *   Security considerations:
 *   Certain personality flags (READ_IMPLIES_EXEC, ADDR_NO_RANDOMIZE,
 *   ADDR_COMPAT_LAYOUT, MMAP_PAGE_ZERO) are security-sensitive and are
 *   automatically cleared when executing setuid or setgid binaries. This
 *   is enforced through PER_CLEAR_ON_SETID processing in the exec path
 *   and prevents privilege escalation attacks that exploit these flags.
 *   See CVE-2009-1895 for historical context.
 *
 *   Architecture-specific behavior:
 *   On arm64 systems without 32-bit EL0 support (CONFIG_COMPAT not enabled
 *   or hardware lacks aarch32 support), attempting to set PER_LINUX32
 *   returns -EINVAL. On 64-bit systems with 32-bit emulation (x86_64,
 *   powerpc64, s390x, sparc64, mips64), the kernel transparently translates
 *   between PER_LINUX and PER_LINUX32 for 32-bit processes to maintain
 *   consistent behavior across architectures.
 *
 *   The syscall is unprivileged and has no capability requirements. Any
 *   process can modify its own personality. The personality setting is
 *   inherited by child processes across fork(2) and preserved across
 *   execve(2), subject to PER_CLEAR_ON_SETID processing for privileged
 *   binaries.
 *
 * context-flags: KAPI_CTX_PROCESS
 *
 * param: personality
 *   type: KAPI_TYPE_UINT
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Any 32-bit unsigned integer is accepted. The special value
 *     0xffffffff queries the current personality without modification. All
 *     other values set the personality unconditionally. Unknown flags in
 *     the upper bytes are stored but may not have any effect. Unknown
 *     personality types in the low byte are stored but result in default
 *     Linux behavior.
 *
 * return:
 *   type: KAPI_TYPE_UINT
 *   check-type: KAPI_RETURN_EXACT
 *   success: previous personality value
 *   desc: Always returns the personality value that was in effect before
 *     this call. When called with 0xffffffff, this is the current personality.
 *     When called with any other value, this is the previous personality
 *     that was just replaced. The return value can be used to restore the
 *     original personality later if needed.
 *
 * signal: none
 *   direction: KAPI_SIGNAL_RECEIVE
 *   action: KAPI_SIGNAL_ACTION_DISCARD
 *   condition: Never - syscall cannot be interrupted
 *   desc: This syscall performs no blocking operations and cannot be
 *     interrupted by signals. It executes entirely in process context
 *     without sleeping or waiting. Any pending signals remain pending
 *     and are handled after the syscall returns.
 *   restartable: no
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: current->personality (process execution domain)
 *   desc: Directly modifies the personality field of the current task's
 *     task_struct when the parameter is not 0xffffffff. This affects all
 *     subsequent system calls and memory operations for the process. The
 *     change takes effect immediately and persists until modified again
 *     or the process terminates.
 *   condition: personality parameter is not 0xffffffff
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Process address space layout behavior
 *   desc: Setting ADDR_NO_RANDOMIZE disables ASLR for subsequent memory
 *     mappings. Setting ADDR_COMPAT_LAYOUT uses legacy memory layout.
 *     Setting ADDR_LIMIT_32BIT or ADDR_LIMIT_3GB restricts the address
 *     space. These changes affect future mmap(), brk(), and stack placement.
 *   condition: Relevant address space flags are set
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Memory protection semantics
 *   desc: Setting READ_IMPLIES_EXEC causes future mmap() and mprotect()
 *     calls with PROT_READ to also grant PROT_EXEC. This affects both
 *     explicit mappings and implicit ones created by the ELF loader.
 *   condition: READ_IMPLIES_EXEC flag is set
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: select/poll timeout handling
 *   desc: Setting STICKY_TIMEOUTS causes select(2), pselect(2), and ppoll(2)
 *     to not update their timeout arguments to reflect remaining time when
 *     interrupted by signals. Without this flag, these syscalls modify the
 *     timeout structure to show how much time remained.
 *   condition: STICKY_TIMEOUTS flag is set
 *   reversible: yes
 *
 * state-trans: process_personality
 *   from: old personality value
 *   to: new personality value
 *   condition: personality parameter is not 0xffffffff
 *   desc: The process transitions from its previous execution domain to
 *     the newly specified one. This is a simple value replacement with no
 *     validation beyond arm64's PER_LINUX32 check on systems without 32-bit
 *     support.
 *
 * constraint: Process Context
 *   desc: Must be called from process context. This syscall operates on
 *     current task data and cannot be called from interrupt context.
 *
 * constraint: Self-modification Only
 *   desc: A process can only modify its own personality. There is no
 *     mechanism to modify another process's personality.
 *
 * examples: old = personality(0xffffffff);  // Query current personality
 *   personality(PER_LINUX | ADDR_NO_RANDOMIZE);  // Disable ASLR
 *   personality(old);  // Restore original personality
 *
 * notes: The generic syscall cannot fail - it always succeeds and returns
 *   the previous personality. However, some architectures (arm64) may return
 *   -EINVAL for unsupported personality types. Callers should check for
 *   negative return values on architectures with restricted personality
 *   support.
 *
 *   The setarch(8) command provides a user-friendly wrapper around this
 *   syscall for running programs with modified personalities.
 *
 *   While the personality mechanism originally supported loadable execution
 *   domain modules for non-Linux binary compatibility, this support was
 *   removed in Linux 4.0 (commit 973f911f55a0e). The personality syscall
 *   and flags remain for backward compatibility and legitimate uses like
 *   ASLR control.
 *
 *   The PER_CLEAR_ON_SETID flags (READ_IMPLIES_EXEC, ADDR_NO_RANDOMIZE,
 *   ADDR_COMPAT_LAYOUT, MMAP_PAGE_ZERO) cannot be preserved across setuid
 *   or setgid exec, as this would create security vulnerabilities. This was
 *   addressed in CVE-2009-1895.
 *
 * since-version: 1.1.20
 */
SYSCALL_DEFINE1(personality, unsigned int, personality)
{
	unsigned int old = current->personality;

	if (personality != 0xffffffff)
		set_personality(personality);

	return old;
}
