/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mod_lineinfo.h - Binary format for per-module source line information
 *
 * This header defines the layout of the .mod_lineinfo section embedded
 * in loadable kernel modules.  It is dual-use: included from both the
 * kernel and the userspace gen_lineinfo tool.
 *
 * Section layout (all values in target-native endianness):
 *
 *   struct mod_lineinfo_header     (24 bytes)
 *   u32 block_addrs[num_blocks]    -- first addr per block, for binary search
 *   u32 block_offsets[num_blocks]  -- byte offset into compressed data stream
 *   u8  data[data_size]            -- ULEB128 delta-compressed entries
 *   u32 file_offsets[num_files]    -- byte offset into filenames[]
 *   char filenames[filenames_size] -- concatenated NUL-terminated strings
 *
 * Compressed stream format (per block of LINEINFO_BLOCK_ENTRIES entries):
 *   Entry 0: file_id (ULEB128), line (ULEB128)
 *            addr is in block_addrs[]
 *   Entry 1..N: addr_delta (ULEB128),
 *               file_id_delta (zigzag-encoded ULEB128),
 *               line_delta (zigzag-encoded ULEB128)
 */
#ifndef _LINUX_MOD_LINEINFO_H
#define _LINUX_MOD_LINEINFO_H

#ifdef __KERNEL__
#include <linux/leb128.h>
#else
#include "leb128.h"
#endif

#define LINEINFO_BLOCK_ENTRIES 64

struct mod_lineinfo_header {
	u32 num_entries;
	u32 num_files;
	u32 filenames_size;	/* total bytes of concatenated filenames */
	u32 num_blocks;
	u32 data_size;		/* total bytes of compressed data stream */
	u32 reserved;		/* padding, must be 0 */
};

/* Offset helpers: compute byte offset from start of section to each array */

static inline u32 mod_lineinfo_block_addrs_off(void)
{
	return sizeof(struct mod_lineinfo_header);
}

static inline u32 mod_lineinfo_block_offsets_off(u32 num_blocks)
{
	return mod_lineinfo_block_addrs_off() + num_blocks * sizeof(u32);
}

static inline u32 mod_lineinfo_data_off(u32 num_blocks)
{
	return mod_lineinfo_block_offsets_off(num_blocks) +
	       num_blocks * sizeof(u32);
}

static inline u32 mod_lineinfo_file_offsets_off(u32 num_blocks, u32 data_size)
{
	return mod_lineinfo_data_off(num_blocks) + data_size;
}

static inline u32 mod_lineinfo_filenames_off(u32 num_blocks, u32 data_size,
					     u32 num_files)
{
	return mod_lineinfo_file_offsets_off(num_blocks, data_size) +
	       num_files * sizeof(u32);
}


#endif /* _LINUX_MOD_LINEINFO_H */
