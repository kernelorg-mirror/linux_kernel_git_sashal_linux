// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 * Copyright (c) 2016 Facebook
 * Copyright (c) 2018 Covalent IO, Inc. http://covalent.io
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

bool stacksafe(struct bpf_verifier_env *env, struct bpf_func_state *old,
	      struct bpf_func_state *cur, struct bpf_idmap *idmap, bool exact)
{
	int i, spi;

	/* walk slots of the explored stack and ignore any additional
	 * slots in the current stack, since explored(safe) state
	 * didn't use them
	 */
	for (i = 0; i < old->allocated_stack; i++) {
		struct bpf_reg_state *old_reg, *cur_reg;

		spi = i / BPF_REG_SIZE;

		if (exact) {
			u8 old_type = old->stack[spi].slot_type[i % BPF_REG_SIZE];
			u8 cur_type = i < cur->allocated_stack ?
				      cur->stack[spi].slot_type[i % BPF_REG_SIZE] : STACK_INVALID;

			/* STACK_INVALID and STACK_POISON are equivalent for pruning */
			if (old_type == STACK_POISON)
				old_type = STACK_INVALID;
			if (cur_type == STACK_POISON)
				cur_type = STACK_INVALID;
			if (i >= cur->allocated_stack || old_type != cur_type)
				return false;
		}

		if (!(old->stack[spi].spilled_ptr.live & REG_LIVE_READ) && !exact) {
			i += BPF_REG_SIZE - 1;
			/* explored state didn't use this */
			continue;
		}

		if (old->stack[spi].slot_type[i % BPF_REG_SIZE] == STACK_INVALID ||
		    old->stack[spi].slot_type[i % BPF_REG_SIZE] == STACK_POISON)
			continue;

		if (env->allow_uninit_stack &&
		    old->stack[spi].slot_type[i % BPF_REG_SIZE] == STACK_MISC)
			continue;

		/* explored stack has more populated slots than current stack
		 * and these slots were used
		 */
		if (i >= cur->allocated_stack)
			return false;

		/* if old state was safe with misc data in the stack
		 * it will be safe with zero-initialized stack.
		 * The opposite is not true
		 */
		if (old->stack[spi].slot_type[i % BPF_REG_SIZE] == STACK_MISC &&
		    cur->stack[spi].slot_type[i % BPF_REG_SIZE] == STACK_ZERO)
			continue;
		if (old->stack[spi].slot_type[i % BPF_REG_SIZE] !=
		    cur->stack[spi].slot_type[i % BPF_REG_SIZE])
			/* Ex: old explored (safe) state has STACK_SPILL in
			 * this stack slot, but current has STACK_MISC ->
			 * this verifier states are not equivalent,
			 * return false to continue verification of this path
			 */
			return false;
		if (i % BPF_REG_SIZE != BPF_REG_SIZE - 1)
			continue;
		/* Both old and cur are having same slot_type */
		switch (old->stack[spi].slot_type[BPF_REG_SIZE - 1]) {
		case STACK_SPILL:
			/* when explored and current stack slot are both storing
			 * spilled registers, check that stored pointers types
			 * are the same as well.
			 * Ex: explored safe path could have stored
			 * (bpf_reg_state) {.type = PTR_TO_STACK, .off = -8}
			 * but current path has stored:
			 * (bpf_reg_state) {.type = PTR_TO_STACK, .off = -16}
			 * such verifier states are not equivalent.
			 * return false to continue verification of this path
			 */
			if (!regsafe(env, &old->stack[spi].spilled_ptr,
				     &cur->stack[spi].spilled_ptr, idmap, exact))
				return false;
			break;
		case STACK_DYNPTR:
			old_reg = &old->stack[spi].spilled_ptr;
			cur_reg = &cur->stack[spi].spilled_ptr;
			if (old_reg->dynptr.type != cur_reg->dynptr.type ||
			    old_reg->dynptr.first_slot != cur_reg->dynptr.first_slot ||
			    !check_ids(old_reg->ref_obj_id, cur_reg->ref_obj_id, idmap))
				return false;
			break;
		case STACK_ITER:
			old_reg = &old->stack[spi].spilled_ptr;
			cur_reg = &cur->stack[spi].spilled_ptr;
			/* iter.depth is not compared between states as it
			 * doesn't matter for correctness and would otherwise
			 * prevent convergence; we maintain it only to prevent
			 * infinite loop check triggering, see
			 * iter_active_depths_differ()
			 */
			if (old_reg->iter.btf != cur_reg->iter.btf ||
			    old_reg->iter.btf_id != cur_reg->iter.btf_id ||
			    old_reg->iter.state != cur_reg->iter.state ||
			    /* ignore {old_reg,cur_reg}->iter.depth, see above */
			    !check_ids(old_reg->ref_obj_id, cur_reg->ref_obj_id, idmap))
				return false;
			break;
		case STACK_MISC:
		case STACK_ZERO:
		case STACK_INVALID:
		case STACK_POISON:
			continue;
		/* Ensure that new unhandled slot types return false by default */
		default:
			return false;
		}
	}
	return true;
}
