/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LEB128_H
#define _LINUX_LEB128_H

/*
 * leb128.h - LEB128 (Little-Endian Base 128) varint encoding/decoding
 *
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 *
 * LEB128 is a standard variable-length integer encoding used in DWARF,
 * ELF, and other binary formats.  This header provides shared helpers
 * so that every subsystem doesn't have to open-code the same logic.
 *
 * All functions are small enough for static inline -- no .c file needed.
 */

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint64_t u64;
typedef int64_t  s64;
typedef uint32_t u32;
typedef int32_t  s32;
typedef uint16_t u16;
typedef uint8_t  u8;
#endif

/* Maximum bytes needed to encode a u64/u32 in ULEB128 */
#define LEB128_U64_MAX_BYTES	10	/* ceil(64/7) */
#define LEB128_U32_MAX_BYTES	5	/* ceil(32/7) */

/*
 * Decode an unsigned LEB128 value.
 * Advances *p past the encoded bytes.  Stops at *end (returns partial
 * result rather than over-reading -- safe for NMI/panic context).
 */
static inline u64 leb128_read_u64(const u8 **p, const u8 *end)
{
	const u8 *cur = *p;
	u64 value = 0;
	unsigned int shift = 0;

	while (cur < end) {
		u8 byte = *cur++;

		value |= (u64)(byte & 0x7f) << shift;
		if (!(byte & 0x80)) {
			*p = cur;
			return value;
		}
		shift += 7;
		if (shift >= 64) {
			/* Malformed: skip remaining continuation bytes */
			while (cur < end && (*cur & 0x80))
				cur++;
			if (cur < end)
				cur++;
			*p = cur;
			return value;
		}
	}
	*p = cur;
	return value;
}

/*
 * Decode a signed LEB128 (SLEB128) value.
 * Advances *p past the encoded bytes.
 */
static inline s64 leb128_read_s64(const u8 **p, const u8 *end)
{
	const u8 *cur = *p;
	s64 value = 0;
	unsigned int shift = 0;
	u8 byte = 0;

	while (cur < end) {
		byte = *cur++;
		value |= (s64)(byte & 0x7f) << shift;
		shift += 7;
		if (!(byte & 0x80))
			break;
		if (shift >= 64) {
			while (cur < end && (*cur & 0x80))
				cur++;
			if (cur < end)
				cur++;
			*p = cur;
			return value;
		}
	}

	/* Sign-extend if the high bit of the last byte was set */
	if (shift < 64 && (byte & 0x40))
		value |= -(1ULL << shift);

	*p = cur;
	return value;
}

/* Convenience: decode unsigned LEB128, truncated to 32 bits */
static inline u32 leb128_read_u32(const u8 **p, const u8 *end)
{
	return (u32)leb128_read_u64(p, end);
}

/* Convenience: decode signed LEB128, truncated to 32 bits */
static inline s32 leb128_read_s32(const u8 **p, const u8 *end)
{
	return (s32)leb128_read_s64(p, end);
}

/*
 * Encode an unsigned value as ULEB128.
 * Writes to *buf (caller must ensure LEB128_U64_MAX_BYTES available).
 * Returns the number of bytes written.
 */
static inline unsigned int leb128_write_u64(u8 *buf, u64 value)
{
	unsigned int len = 0;

	do {
		u8 byte = value & 0x7f;

		value >>= 7;
		if (value)
			byte |= 0x80;
		buf[len++] = byte;
	} while (value);
	return len;
}

/* Convenience: encode a u32 as ULEB128 */
static inline unsigned int leb128_write_u32(u8 *buf, u32 value)
{
	return leb128_write_u64(buf, value);
}

/*
 * Skip past one LEB128-encoded value without decoding it.
 * Advances *p past the encoded bytes.
 */
static inline void leb128_skip(const u8 **p, const u8 *end)
{
	const u8 *cur = *p;

	while (cur < end) {
		if (!(*cur++ & 0x80))
			break;
	}
	*p = cur;
}

/* Zigzag encoding: map signed to unsigned so small magnitudes stay small */
static inline u32 leb128_zigzag_encode(s32 v)
{
	return ((u32)v << 1) ^ (u32)(v >> 31);
}

static inline s32 leb128_zigzag_decode(u32 v)
{
	return (s32)((v >> 1) ^ -(v & 1));
}

static inline u64 leb128_zigzag_encode64(s64 v)
{
	return ((u64)v << 1) ^ (u64)(v >> 63);
}

static inline s64 leb128_zigzag_decode64(u64 v)
{
	return (s64)((v >> 1) ^ -(v & 1));
}

#endif /* _LINUX_LEB128_H */
