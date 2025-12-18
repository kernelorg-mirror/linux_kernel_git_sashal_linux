// SPDX-License-Identifier: GPL-2.0-only
/*
 * kexec.c - kexec_load system call
 * Copyright (C) 2002-2004 Eric Biederman  <ebiederm@xmission.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/security.h>
#include <linux/kexec.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include "kexec_internal.h"

static int kimage_alloc_init(struct kimage **rimage, unsigned long entry,
			     unsigned long nr_segments,
			     struct kexec_segment *segments,
			     unsigned long flags)
{
	int ret;
	struct kimage *image;
	bool kexec_on_panic = flags & KEXEC_ON_CRASH;

#ifdef CONFIG_CRASH_DUMP
	if (kexec_on_panic) {
		/* Verify we have a valid entry point */
		if ((entry < phys_to_boot_phys(crashk_res.start)) ||
		    (entry > phys_to_boot_phys(crashk_res.end)))
			return -EADDRNOTAVAIL;
	}
#endif

	/* Allocate and initialize a controlling structure */
	image = do_kimage_alloc_init();
	if (!image)
		return -ENOMEM;

	image->start = entry;
	image->nr_segments = nr_segments;
	memcpy(image->segment, segments, nr_segments * sizeof(*segments));

#ifdef CONFIG_CRASH_DUMP
	if (kexec_on_panic) {
		/* Enable special crash kernel control page alloc policy. */
		image->control_page = crashk_res.start;
		image->type = KEXEC_TYPE_CRASH;
	}
#endif

	ret = sanity_check_segment_list(image);
	if (ret)
		goto out_free_image;

	/*
	 * Find a location for the control code buffer, and add it
	 * the vector of segments so that it's pages will also be
	 * counted as destination pages.
	 */
	ret = -ENOMEM;
	image->control_code_page = kimage_alloc_control_pages(image,
					   get_order(KEXEC_CONTROL_PAGE_SIZE));
	if (!image->control_code_page) {
		pr_err("Could not allocate control_code_buffer\n");
		goto out_free_image;
	}

	if (!kexec_on_panic) {
		image->swap_page = kimage_alloc_control_pages(image, 0);
		if (!image->swap_page) {
			pr_err("Could not allocate swap buffer\n");
			goto out_free_control_pages;
		}
	}

	*rimage = image;
	return 0;
out_free_control_pages:
	kimage_free_page_list(&image->control_pages);
out_free_image:
	kfree(image);
	return ret;
}

static int do_kexec_load(unsigned long entry, unsigned long nr_segments,
		struct kexec_segment *segments, unsigned long flags)
{
	struct kimage **dest_image, *image;
	unsigned long i;
	int ret;

	/*
	 * Because we write directly to the reserved memory region when loading
	 * crash kernels we need a serialization here to prevent multiple crash
	 * kernels from attempting to load simultaneously.
	 */
	if (!kexec_trylock())
		return -EBUSY;

#ifdef CONFIG_CRASH_DUMP
	if (flags & KEXEC_ON_CRASH) {
		dest_image = &kexec_crash_image;
		if (kexec_crash_image)
			arch_kexec_unprotect_crashkres();
	} else
#endif
		dest_image = &kexec_image;

	if (nr_segments == 0) {
		/* Uninstall image */
		kimage_free(xchg(dest_image, NULL));
		ret = 0;
		goto out_unlock;
	}
	if (flags & KEXEC_ON_CRASH) {
		/*
		 * Loading another kernel to switch to if this one
		 * crashes.  Free any current crash dump kernel before
		 * we corrupt it.
		 */
		kimage_free(xchg(&kexec_crash_image, NULL));
	}

	ret = kimage_alloc_init(&image, entry, nr_segments, segments, flags);
	if (ret)
		goto out_unlock;

	if (flags & KEXEC_PRESERVE_CONTEXT)
		image->preserve_context = 1;

#ifdef CONFIG_CRASH_HOTPLUG
	if ((flags & KEXEC_ON_CRASH) && arch_crash_hotplug_support(image, flags))
		image->hotplug_support = 1;
#endif

	ret = machine_kexec_prepare(image);
	if (ret)
		goto out;

	/*
	 * Some architecture(like S390) may touch the crash memory before
	 * machine_kexec_prepare(), we must copy vmcoreinfo data after it.
	 */
	ret = kimage_crash_copy_vmcoreinfo(image);
	if (ret)
		goto out;

	for (i = 0; i < nr_segments; i++) {
		ret = kimage_load_segment(image, i);
		if (ret)
			goto out;
	}

	kimage_terminate(image);

	ret = machine_kexec_post_load(image);
	if (ret)
		goto out;

	/* Install the new kernel and uninstall the old */
	image = xchg(dest_image, image);

out:
#ifdef CONFIG_CRASH_DUMP
	if ((flags & KEXEC_ON_CRASH) && kexec_crash_image)
		arch_kexec_protect_crashkres();
#endif

	kimage_free(image);
out_unlock:
	kexec_unlock();
	return ret;
}

/*
 * Exec Kernel system call: for obvious reasons only root may call it.
 *
 * This call breaks up into three pieces.
 * - A generic part which loads the new kernel from the current
 *   address space, and very carefully places the data in the
 *   allocated pages.
 *
 * - A generic part that interacts with the kernel and tells all of
 *   the devices to shut down.  Preventing on-going dmas, and placing
 *   the devices in a consistent state so a later kernel can
 *   reinitialize them.
 *
 * - A machine specific part that includes the syscall number
 *   and then copies the image to it's final destination.  And
 *   jumps into the image at entry.
 *
 * kexec does not sync, or unmount filesystems so if you need
 * that to happen you need to do that yourself.
 */

static inline int kexec_load_check(unsigned long nr_segments,
				   unsigned long flags)
{
	int image_type = (flags & KEXEC_ON_CRASH) ?
			 KEXEC_TYPE_CRASH : KEXEC_TYPE_DEFAULT;
	int result;

	/* We only trust the superuser with rebooting the system. */
	if (!kexec_load_permitted(image_type))
		return -EPERM;

	/* Permit LSMs and IMA to fail the kexec */
	result = security_kernel_load_data(LOADING_KEXEC_IMAGE, false);
	if (result < 0)
		return result;

	/*
	 * kexec can be used to circumvent module loading restrictions, so
	 * prevent loading in that case
	 */
	result = security_locked_down(LOCKDOWN_KEXEC);
	if (result)
		return result;

	/*
	 * Verify we have a legal set of flags
	 * This leaves us room for future extensions.
	 */
	if ((flags & KEXEC_FLAGS) != (flags & ~KEXEC_ARCH_MASK))
		return -EINVAL;

	/* Put an artificial cap on the number
	 * of segments passed to kexec_load.
	 */
	if (nr_segments > KEXEC_SEGMENT_MAX)
		return -EINVAL;

	return 0;
}

/**
 * sys_kexec_load - Load a new kernel image for later execution via kexec
 * @entry: Kernel entry point address for the new kernel image
 * @nr_segments: Number of segments in the @segments array (0 to unload)
 * @segments: User pointer to array of kexec_segment structures
 * @flags: Flags controlling the type of kexec operation
 *
 * long-desc: Loads a new kernel image into memory that can later be booted
 *   using the reboot() syscall with LINUX_REBOOT_CMD_KEXEC. This enables
 *   fast system reboots by bypassing the BIOS/firmware initialization,
 *   and is also used to load crash dump kernels that execute after a panic.
 *
 *   The kexec mechanism works by loading the new kernel's segments into
 *   memory regions that will survive the transition. When kexec is triggered,
 *   the currently running kernel shuts down, and control transfers directly
 *   to the entry point of the loaded kernel.
 *
 *   Two types of kernel images can be loaded, selected by the KEXEC_ON_CRASH
 *   flag:
 *
 *   - Normal kexec (KEXEC_ON_CRASH not set): The kernel is loaded into
 *     standard memory and will be executed during a planned reboot via
 *     reboot(LINUX_REBOOT_CMD_KEXEC). Only one normal kexec image can be
 *     loaded at a time.
 *
 *   - Crash kernel (KEXEC_ON_CRASH set): The kernel is loaded into a
 *     reserved memory region (crashkernel=) and will be automatically
 *     executed if the running kernel panics. This is used for kdump to
 *     capture crash dumps. The crash kernel memory must be reserved at
 *     boot time via the crashkernel= kernel parameter.
 *
 *   Each segment in the @segments array describes a contiguous piece of
 *   the new kernel image:
 *   - buf: User-space buffer containing the segment data
 *   - bufsz: Size of the data in the user-space buffer
 *   - mem: Physical memory address where segment should be loaded
 *   - memsz: Size of the memory region (>= bufsz, excess is zeroed)
 *
 *   Segments must not overlap with each other or with critical memory
 *   regions. For crash kernels, segments must fit within the reserved
 *   crashkernel memory region. The kernel performs extensive validation
 *   of segment addresses and sizes.
 *
 *   To unload a previously loaded kernel image, call with @nr_segments
 *   set to 0 and @segments set to NULL. The @entry value is ignored when
 *   unloading. This frees all memory associated with the loaded image.
 *
 *   The KEXEC_PRESERVE_CONTEXT flag is used for software suspend (S4)
 *   scenarios where the current kernel state needs to be preserved so
 *   it can be resumed after the kexec'd kernel runs. This is incompatible
 *   with KEXEC_ON_CRASH.
 *
 *   This syscall has largely been superseded by kexec_file_load() which
 *   provides better security by accepting file descriptors and verifying
 *   kernel signatures. However, kexec_load() remains necessary for loading
 *   kernels with custom modifications or when kexec_file_load() is not
 *   supported for the target architecture.
 *
 * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE
 *
 * param: entry
 *   type: KAPI_TYPE_ULONG
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Physical address of the kernel entry point. This is where
 *     execution will begin when the kexec is triggered. Ignored when
 *     @nr_segments is 0 (unload operation). For crash kernels, must be
 *     within the reserved crashkernel memory region.
 *
 * param: nr_segments
 *   type: KAPI_TYPE_ULONG
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_RANGE
 *   constraint: Must be between 0 and KEXEC_SEGMENT_MAX (16) inclusive.
 *     A value of 0 indicates an unload operation - any previously loaded
 *     kernel image of the type specified by @flags is freed.
 *
 * param: segments
 *   type: KAPI_TYPE_USER_PTR
 *   flags: KAPI_PARAM_IN | KAPI_PARAM_USER | KAPI_PARAM_OPTIONAL
 *   constraint-type: KAPI_CONSTRAINT_CUSTOM
 *   constraint: Pointer to an array of struct kexec_segment with
 *     @nr_segments elements. May be NULL only if @nr_segments is 0.
 *     Each segment describes a piece of the kernel image to load:
 *     buf (user buffer), bufsz (buffer size), mem (target physical
 *     address), memsz (memory region size >= bufsz). Segments must not
 *     overlap. For crash kernels, all segments must be within the
 *     crashkernel reserved region. Invalid pointers return EFAULT.
 *     Multiplication overflow in array size returns EOVERFLOW.
 *
 * param: flags
 *   type: KAPI_TYPE_ULONG
 *   flags: KAPI_PARAM_IN
 *   constraint-type: KAPI_CONSTRAINT_MASK
 *   constraint: Combination of KEXEC_ON_CRASH, KEXEC_PRESERVE_CONTEXT,
 *     KEXEC_UPDATE_ELFCOREHDR, KEXEC_CRASH_HOTPLUG_SUPPORT, and
 *     architecture selector in KEXEC_ARCH_MASK. KEXEC_ON_CRASH and
 *     KEXEC_PRESERVE_CONTEXT are mutually exclusive. The architecture
 *     in KEXEC_ARCH_MASK must be either 0 (KEXEC_ARCH_DEFAULT, use
 *     current architecture) or match the running kernel's architecture
 *     (KEXEC_ARCH). KEXEC_UPDATE_ELFCOREHDR is only valid when
 *     KEXEC_ON_CRASH is also set. Invalid flag combinations return
 *     EINVAL.
 *
 * return:
 *   type: KAPI_TYPE_INT
 *   check-type: KAPI_RETURN_ERROR_CHECK
 *   success: 0
 *   desc: Returns 0 on success. The kernel image is loaded and ready for
 *     later execution via reboot(LINUX_REBOOT_CMD_KEXEC), or in case of
 *     crash kernels, ready for automatic execution on panic. On error,
 *     returns a negative errno value and no image is loaded/unloaded.
 *
 * error: EPERM, Missing CAP_SYS_BOOT capability
 *   desc: The calling process does not have the CAP_SYS_BOOT capability
 *     required to load kernel images. This capability is typically held
 *     only by root or processes with elevated privileges.
 *
 * error: EPERM, kexec_load_disabled sysctl is set
 *   desc: The /proc/sys/kernel/kexec_load_disabled sysctl has been set to
 *     a non-zero value, permanently disabling kexec_load for security.
 *     Once set, this sysctl cannot be reset without rebooting. This is
 *     checked by kexec_load_permitted() before any other validation.
 *
 * error: EPERM, Kernel lockdown is enabled
 *   desc: Kernel lockdown (security_locked_down(LOCKDOWN_KEXEC)) prevents
 *     loading unsigned kernel images. This can occur when Secure Boot is
 *     active or lockdown is manually enabled. Use kexec_file_load() with
 *     signed kernels instead.
 *
 * error: EPERM, LSM security_kernel_load_data() denied
 *   desc: A Linux Security Module (LSM) such as SELinux or LoadPin denied
 *     the kernel data load operation. The LSM hook
 *     security_kernel_load_data(LOADING_KEXEC_IMAGE) returned an error.
 *
 * error: EINVAL, Too many segments
 *   desc: The @nr_segments value exceeds KEXEC_SEGMENT_MAX (16). The
 *     kernel limits the number of segments to prevent excessive resource
 *     consumption and simplify segment management.
 *
 * error: EINVAL, Invalid flags
 *   desc: The @flags parameter contains undefined flag bits or invalid
 *     combinations. Only KEXEC_ON_CRASH, KEXEC_PRESERVE_CONTEXT,
 *     KEXEC_UPDATE_ELFCOREHDR, KEXEC_CRASH_HOTPLUG_SUPPORT, and valid
 *     KEXEC_ARCH_MASK values are permitted. KEXEC_PRESERVE_CONTEXT is
 *     invalid with KEXEC_ON_CRASH. KEXEC_UPDATE_ELFCOREHDR requires
 *     KEXEC_ON_CRASH to be set.
 *
 * error: EINVAL, Architecture mismatch
 *   desc: The architecture specified in KEXEC_ARCH_MASK does not match
 *     the running kernel's architecture and is not KEXEC_ARCH_DEFAULT (0).
 *     Cross-architecture kexec is not supported.
 *
 * error: EINVAL, Overlapping segments
 *   desc: Two or more segments in the @segments array have overlapping
 *     physical memory regions (mem to mem+memsz). Detected by
 *     sanity_check_segment_list() in kimage_alloc_init().
 *
 * error: EINVAL, Segment bufsz exceeds memsz
 *   desc: A segment has bufsz greater than memsz. The buffer size cannot
 *     exceed the destination memory region size.
 *
 * error: EINVAL, Segment address alignment error
 *   desc: A segment's physical memory address (mem) or size (memsz) is
 *     not properly aligned to page boundaries, or the segment extends
 *     beyond valid physical memory limits.
 *
 * error: EINVAL, Crash kernel without reserved memory
 *   desc: KEXEC_ON_CRASH was specified but no crashkernel memory has been
 *     reserved (crashkernel= boot parameter was not provided or failed).
 *
 * error: EFAULT, Cannot read segments array from userspace
 *   desc: The @segments pointer is invalid or points to unmapped memory.
 *     The memdup_array_user() call failed to copy the segments array.
 *
 * error: EFAULT, Cannot read segment data from userspace
 *   desc: A segment's buf pointer is invalid or points to unmapped memory.
 *     The copy_from_user() call failed while loading segment contents
 *     in kimage_load_segment().
 *
 * error: EOVERFLOW, Segments array size overflow
 *   desc: The multiplication of @nr_segments * sizeof(struct kexec_segment)
 *     overflowed. This prevents integer overflow attacks. Detected by
 *     memdup_array_user()'s internal overflow check.
 *
 * error: ENOMEM, Failed to allocate kernel image structure
 *   desc: Memory allocation for the internal kimage structure or related
 *     data structures failed. This includes allocations in
 *     do_kimage_alloc_init() for the kimage, control pages, page tables,
 *     or segment page arrays.
 *
 * error: ENOMEM, Failed to allocate memory for segment
 *   desc: Memory allocation failed while loading segment data. This can
 *     occur in kimage_alloc_page() when allocating pages for segment
 *     contents or control pages.
 *
 * error: EBUSY, Another kexec operation is in progress
 *   desc: The kexec_lock mutex could not be acquired because another
 *     kexec_load, kexec_file_load, or kexec execution is in progress.
 *     The syscall uses mutex_trylock() for non-blocking behavior - it
 *     immediately fails rather than waiting.
 *
 * error: EADDRNOTAVAIL, Segment address outside permitted range
 *   desc: For crash kernels, a segment's physical address range falls
 *     outside the reserved crashkernel memory region. All crash kernel
 *     segments must fit entirely within the crashkernel= reserved area.
 *
 * error: EOPNOTSUPP, Hardware or configuration does not support kexec
 *   desc: Architecture-specific machine_kexec_prepare() determined that
 *     kexec is not supported in the current configuration. On x86, this
 *     can occur with Intel TDX due to the TDX_PW_MCE silicon bug that
 *     prevents kexec from working reliably. Other architectures may have
 *     different restrictions.
 *
 * capability: CAP_SYS_BOOT
 *   type: KAPI_CAP_REQUIRED
 *   desc: Required capability to load or unload kexec kernel images.
 *     Without this capability, the syscall immediately returns EPERM.
 *     This is checked first by kexec_load_permitted() before any other
 *     validation.
 *
 * lock: kexec_lock
 *   type: KAPI_LOCK_MUTEX
 *   acquired: true
 *   released: true
 *   desc: Global kexec mutex protecting access to the kexec_image and
 *     kexec_crash_image global pointers. Acquired with mutex_trylock()
 *     at the start of do_kexec_load() - if the lock cannot be acquired
 *     immediately, EBUSY is returned. This provides serialization without
 *     blocking, preventing long waits if another kexec operation is in
 *     progress. The lock is released before returning, after all image
 *     modifications are complete.
 *
 * side-effect: KAPI_EFFECT_MEMORY_MAP
 *   target: Physical memory pages for kernel image
 *   desc: Allocates physical memory pages to hold the kernel image segments.
 *     For crash kernels (KEXEC_ON_CRASH), pages are allocated from the
 *     reserved crashkernel memory region. For normal kexec, pages are
 *     allocated from the general page allocator. The number and size of
 *     pages depends on the total size of all segments. Memory is freed
 *     when the image is unloaded or replaced.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_MODIFY_STATE
 *   target: Global kexec_image or kexec_crash_image pointer
 *   desc: On successful load, updates the global kexec_image pointer
 *     (for normal kexec) or kexec_crash_image pointer (for crash kernels)
 *     to point to the newly loaded kernel image. Any previously loaded
 *     image of the same type is freed. On unload (nr_segments=0), the
 *     pointer is set to NULL.
 *   reversible: yes
 *
 * side-effect: KAPI_EFFECT_PROCESS
 *   target: System reboot behavior
 *   desc: After loading a normal kexec image, reboot(LINUX_REBOOT_CMD_KEXEC)
 *     will boot into the loaded kernel instead of performing a normal
 *     reboot. After loading a crash kernel, a kernel panic will trigger
 *     automatic boot into the crash kernel for dump collection.
 *   condition: Kernel image successfully loaded
 *   reversible: yes
 *
 * state-trans: kexec_image
 *   from: NULL (no image loaded)
 *   to: loaded
 *   condition: @nr_segments > 0 and KEXEC_ON_CRASH not set
 *   desc: A normal kexec kernel image is loaded and ready for execution
 *     via reboot(LINUX_REBOOT_CMD_KEXEC).
 *
 * state-trans: kexec_image
 *   from: loaded
 *   to: NULL (unloaded)
 *   condition: @nr_segments == 0 and KEXEC_ON_CRASH not set
 *   desc: The previously loaded normal kexec kernel image is freed and
 *     unloaded. reboot(LINUX_REBOOT_CMD_KEXEC) will fail until a new
 *     image is loaded.
 *
 * state-trans: kexec_crash_image
 *   from: NULL (no image loaded)
 *   to: loaded
 *   condition: @nr_segments > 0 and KEXEC_ON_CRASH set
 *   desc: A crash kernel image is loaded into reserved memory and will
 *     automatically execute if the kernel panics, enabling kdump.
 *
 * state-trans: kexec_crash_image
 *   from: loaded
 *   to: NULL (unloaded)
 *   condition: @nr_segments == 0 and KEXEC_ON_CRASH set
 *   desc: The previously loaded crash kernel image is freed. No automatic
 *     kdump will occur on panic until a new crash image is loaded.
 *
 * examples: kexec_load(entry, 4, segs, KEXEC_ARCH_DEFAULT);  // Load normal kexec
 *   kexec_load(entry, 3, segs, KEXEC_ON_CRASH);  // Load crash kernel
 *   kexec_load(0, 0, NULL, KEXEC_ON_CRASH);  // Unload crash kernel
 *   kexec_load(0, 0, NULL, 0);  // Unload normal kexec kernel
 *
 * notes: The kexec_load syscall was added in Linux 2.6.13. For better
 *   security, especially with Secure Boot, consider using kexec_file_load()
 *   (added in Linux 3.17) which accepts file descriptors and can verify
 *   kernel signatures. The KEXEC_PRESERVE_CONTEXT flag is primarily used
 *   by hibernation (suspend-to-disk) implementations. On x86_64, this
 *   syscall is number 246; on i386, it is 283. A compat syscall is provided
 *   for 32-bit userspace on 64-bit kernels. The kexec-tools userspace
 *   package provides the kexec(8) utility which is the standard interface
 *   for using this functionality. Intel TDX guests cannot use kexec due
 *   to the TDX_PW_MCE silicon bug. The kexec_load_disabled sysctl, once
 *   set, cannot be cleared without a reboot, providing a one-way security
 *   lock. This syscall requires CONFIG_KEXEC=y in the kernel configuration.
 *
 * related: kexec_file_load(2), reboot(2)
 * see-also: kexec(8), Documentation/admin-guide/kdump/kdump.rst
 * since-version: 2.6.13
 */
SYSCALL_DEFINE4(kexec_load, unsigned long, entry, unsigned long, nr_segments,
		struct kexec_segment __user *, segments, unsigned long, flags)
{
	struct kexec_segment *ksegments;
	unsigned long result;

	result = kexec_load_check(nr_segments, flags);
	if (result)
		return result;

	/* Verify we are on the appropriate architecture */
	if (((flags & KEXEC_ARCH_MASK) != KEXEC_ARCH) &&
		((flags & KEXEC_ARCH_MASK) != KEXEC_ARCH_DEFAULT))
		return -EINVAL;

	ksegments = memdup_array_user(segments, nr_segments, sizeof(ksegments[0]));
	if (IS_ERR(ksegments))
		return PTR_ERR(ksegments);

	result = do_kexec_load(entry, nr_segments, ksegments, flags);
	kfree(ksegments);

	return result;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(kexec_load, compat_ulong_t, entry,
		       compat_ulong_t, nr_segments,
		       struct compat_kexec_segment __user *, segments,
		       compat_ulong_t, flags)
{
	struct compat_kexec_segment in;
	struct kexec_segment *ksegments;
	unsigned long i, result;

	result = kexec_load_check(nr_segments, flags);
	if (result)
		return result;

	/* Don't allow clients that don't understand the native
	 * architecture to do anything.
	 */
	if ((flags & KEXEC_ARCH_MASK) == KEXEC_ARCH_DEFAULT)
		return -EINVAL;

	ksegments = kmalloc_array(nr_segments, sizeof(ksegments[0]),
			GFP_KERNEL);
	if (!ksegments)
		return -ENOMEM;

	for (i = 0; i < nr_segments; i++) {
		result = copy_from_user(&in, &segments[i], sizeof(in));
		if (result)
			goto fail;

		ksegments[i].buf   = compat_ptr(in.buf);
		ksegments[i].bufsz = in.bufsz;
		ksegments[i].mem   = in.mem;
		ksegments[i].memsz = in.memsz;
	}

	result = do_kexec_load(entry, nr_segments, ksegments, flags);

fail:
	kfree(ksegments);
	return result;
}
#endif
