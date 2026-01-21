/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

   SPDX-License-Identifier: GPL-2.0-or-later OR Apache-2.0
*/
#define _GNU_SOURCE

#include "config.h"

#include "lcfs-internal.h"
#include "lcfs-utils.h"
#include "lcfs-writer.h"
#include "lcfs-fsverity.h"
#include "lcfs-erofs-internal.h"
#include "lcfs-utils.h"
#include "hash.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <assert.h>
#include <linux/fsverity.h>

/* The xxh32 hash function is copied from the linux kernel at:
 *  https://github.com/torvalds/linux/blob/d89775fc929c5a1d91ed518a71b456da0865e5ff/lib/xxhash.c
 *
 * The original copyright is:
 *
 * xxHash - Extremely Fast Hash algorithm
 * Copyright (C) 2012-2016, Yann Collet.
 *
 * BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other materials provided with the
 *     distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation. This program is dual-licensed; you may select
 * either version 2 of the GNU General Public License ("GPL") or BSD license
 * ("BSD").
 *
 * You can contact the author at:
 * - xxHash homepage: https://cyan4973.github.io/xxHash/
 * - xxHash source repository: https://github.com/Cyan4973/xxHash
 */

static const uint32_t PRIME32_1 = 2654435761U;
static const uint32_t PRIME32_2 = 2246822519U;
static const uint32_t PRIME32_3 = 3266489917U;
static const uint32_t PRIME32_4 = 668265263U;
static const uint32_t PRIME32_5 = 374761393U;

static inline uint32_t get_unaligned_le32(const uint8_t *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

#define xxh_rotl32(x, r) ((x << r) | (x >> (32 - r)))

static uint32_t xxh32_round(uint32_t seed, const uint32_t input)
{
	seed += input * PRIME32_2;
	seed = xxh_rotl32(seed, 13);
	seed *= PRIME32_1;
	return seed;
}

static uint32_t xxh32(const void *input, const size_t len, const uint32_t seed)
{
	const uint8_t *p = (const uint8_t *)input;
	const uint8_t *b_end = p + len;
	uint32_t h32;

	if (len >= 16) {
		const uint8_t *const limit = b_end - 16;
		uint32_t v1 = seed + PRIME32_1 + PRIME32_2;
		uint32_t v2 = seed + PRIME32_2;
		uint32_t v3 = seed + 0;
		uint32_t v4 = seed - PRIME32_1;

		do {
			v1 = xxh32_round(v1, get_unaligned_le32(p));
			p += 4;
			v2 = xxh32_round(v2, get_unaligned_le32(p));
			p += 4;
			v3 = xxh32_round(v3, get_unaligned_le32(p));
			p += 4;
			v4 = xxh32_round(v4, get_unaligned_le32(p));
			p += 4;
		} while (p <= limit);

		h32 = xxh_rotl32(v1, 1) + xxh_rotl32(v2, 7) +
		      xxh_rotl32(v3, 12) + xxh_rotl32(v4, 18);
	} else {
		h32 = seed + PRIME32_5;
	}

	h32 += (uint32_t)len;

	while (p + 4 <= b_end) {
		h32 += get_unaligned_le32(p) * PRIME32_3;
		h32 = xxh_rotl32(h32, 17) * PRIME32_4;
		p += 4;
	}

	while (p < b_end) {
		h32 += (*p) * PRIME32_5;
		h32 = xxh_rotl32(h32, 11) * PRIME32_1;
		p++;
	}

	h32 ^= h32 >> 15;
	h32 *= PRIME32_2;
	h32 ^= h32 >> 13;
	h32 *= PRIME32_3;
	h32 ^= h32 >> 16;

	return h32;
}

struct lcfs_ctx_erofs_s {
	struct lcfs_ctx_s base;

	uint64_t inodes_end; /* start of xattrs */
	uint64_t shared_xattr_size;
	uint64_t n_data_blocks;
	uint64_t current_end;
	struct lcfs_xattr_s **shared_xattrs;
	size_t n_shared_xattrs;
};

static void lcfs_ctx_erofs_finalize(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;

	free(ctx_erofs->shared_xattrs);
}

struct lcfs_ctx_s *lcfs_ctx_erofs_new(void)
{
	struct lcfs_ctx_erofs_s *ret = calloc(1, sizeof(struct lcfs_ctx_erofs_s));
	if (ret == NULL) {
		return NULL;
	}

	ret->base.finalize = lcfs_ctx_erofs_finalize;

	return &ret->base;
}

static int erofs_make_file_type(int regular)
{
	switch (regular) {
	case DT_LNK:
		return EROFS_FT_SYMLINK;
	case DT_DIR:
		return EROFS_FT_DIR;
	case DT_REG:
		return EROFS_FT_REG_FILE;
	case DT_BLK:
		return EROFS_FT_BLKDEV;
	case DT_CHR:
		return EROFS_FT_CHRDEV;
	case DT_SOCK:
		return EROFS_FT_SOCK;
	case DT_FIFO:
		return EROFS_FT_FIFO;
	default:
		return EROFS_FT_UNKNOWN;
	}
}

struct hasher_xattr_s {
	struct lcfs_xattr_s *xattr;
	uint32_t count;

	bool shared;
	uint64_t shared_offset; /* offset in bytes from start of shared xattrs */
};

static size_t xattrs_ht_hasher(const void *d, size_t n)
{
	const struct hasher_xattr_s *v = d;
	return (hash_string(v->xattr->key, n) ^
		hash_memory(v->xattr->value, v->xattr->value_len, n)) %
	       n;
}

static bool xattrs_ht_comparator(const void *d1, const void *d2)
{
	const struct hasher_xattr_s *v1 = d1;
	const struct hasher_xattr_s *v2 = d2;

	if (v1->xattr->value_len != v2->xattr->value_len)
		return false;

	if (memcmp(v1->xattr->value, v2->xattr->value, v1->xattr->value_len) != 0)
		return false;

	return strcmp(v1->xattr->key, v2->xattr->key) == 0;
}

/* Sort alphabetically by key and value to get some canonical order */
static int xattrs_ht_sort(const void *d1, const void *d2)
{
	const struct hasher_xattr_s *v1 = *(const struct hasher_xattr_s **)d1;
	const struct hasher_xattr_s *v2 = *(const struct hasher_xattr_s **)d2;
	int r;

	r = strcmp(v2->xattr->key, v1->xattr->key);
	if (r != 0)
		return r;

	if (v1->xattr->value_len != v2->xattr->value_len)
		return (int)v2->xattr->value_len - (int)v1->xattr->value_len;

	return memcmp(v2->xattr->value, v1->xattr->value, v1->xattr->value_len);
}

static uint8_t xattr_erofs_entry_index(struct lcfs_xattr_s *xattr, char **rest)
{
	char *key = xattr->key;
	struct {
		const char *prefix;
		uint8_t index;
	} keys[] = { { "user.", EROFS_XATTR_INDEX_USER },
		     { "system.posix_acl_access", EROFS_XATTR_INDEX_POSIX_ACL_ACCESS },
		     { "system.posix_acl_default", EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT },
		     { "trusted.", EROFS_XATTR_INDEX_TRUSTED },
		     { "security.", EROFS_XATTR_INDEX_SECURITY },
		     { NULL } };
	for (size_t i = 0; keys[i].prefix != NULL; i++) {
		if (str_has_prefix(key, keys[i].prefix)) {
			*rest = key + strlen(keys[i].prefix);
			return keys[i].index;
		}
	}

	*rest = key;
	return 0;
}

static size_t xattr_erofs_entry_size(struct lcfs_xattr_s *xattr)
{
	char *key_suffix;
	xattr_erofs_entry_index(xattr, &key_suffix);

	return round_up(sizeof(struct erofs_xattr_entry) + strlen(key_suffix) +
				xattr->value_len,
			sizeof(uint32_t));
}

static size_t xattr_erofs_icount(size_t xattr_size)
{
	if (xattr_size == 0)
		return 0;
	return (xattr_size - sizeof(struct erofs_xattr_ibody_header)) /
		       sizeof(uint32_t) +
	       1;
}

static size_t xattr_erofs_inode_size(size_t n_shared_xattrs, size_t unshared_xattrs_size)
{
	if (n_shared_xattrs == 0 && unshared_xattrs_size == 0) {
		return 0;
	}

	return round_up(sizeof(struct erofs_xattr_ibody_header) +
				n_shared_xattrs * sizeof(struct erofs_xattr_entry) +
				unshared_xattrs_size,
			sizeof(uint32_t));
}

static bool erofs_xattr_should_be_shared(struct hasher_xattr_s *ent)
{
	/* Share multi-use xattrs */
	if (ent->count > 1)
		return true;

	return false;
}

static int compute_erofs_shared_xattrs(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;
	struct lcfs_node_s *node;
	Hash_table *xattr_hash;
	struct hasher_xattr_s **sorted = NULL;
	size_t n_xattrs;
	uint64_t xattr_offset;

	size_t n_files = 0;
	for (node = ctx->root; node != NULL; node = node->next)
		n_files++;

	/* Find the use count for each xattr key/value in use */
	xattr_hash = hash_initialize(n_files, NULL, xattrs_ht_hasher,
				     xattrs_ht_comparator, free);
	if (xattr_hash == NULL) {
		errno = ENOMEM;
		return -1;
	}

	for (node = ctx->root; node != NULL; node = node->next) {
		for (size_t i = 0; i < node->n_xattrs; i++) {
			struct hasher_xattr_s hkey = { .xattr = &node->xattrs[i] };
			struct hasher_xattr_s *ent;

			ent = hash_lookup(xattr_hash, &hkey);
			if (ent == NULL) {
				cleanup_free struct hasher_xattr_s *new_ent =
					calloc(1, sizeof(struct hasher_xattr_s));
				if (new_ent == NULL) {
					goto fail;
				}
				new_ent->xattr = &node->xattrs[i];
				ent = hash_insert(xattr_hash, new_ent);
				if (ent == NULL)
					goto fail;
				assert(ent == new_ent); /* Due to result from previously run hash_lookup() */
				new_ent = NULL;
			}
			ent->count++;
		}
	}

	/* Compute the xattr list in canonical order */

	n_xattrs = hash_get_n_entries(xattr_hash);
	sorted = calloc(n_xattrs, sizeof(struct hasher_xattr_s *));
	if (sorted == NULL)
		goto fail;
	n_xattrs = hash_get_entries(xattr_hash, (void **)sorted, n_xattrs);
	qsort(sorted, n_xattrs, sizeof(struct hasher_xattr_s *), xattrs_ht_sort);

	/* Compute the list of shared (multi-use) xattrs and their offsets */
	ctx_erofs->shared_xattrs = calloc(n_xattrs, sizeof(struct lcfs_xattr_s *));
	if (ctx_erofs->shared_xattrs == NULL)
		goto fail;
	ctx_erofs->n_shared_xattrs = 0;

	xattr_offset = 0;
	for (size_t i = 0; i < n_xattrs; i++) {
		struct hasher_xattr_s *ent = sorted[i];
		if (erofs_xattr_should_be_shared(ent)) {
			ent->shared = true;
			ent->shared_offset = xattr_offset;

			ctx_erofs->shared_xattrs[ctx_erofs->n_shared_xattrs] =
				ent->xattr;
			ctx_erofs->n_shared_xattrs++;

			xattr_offset += xattr_erofs_entry_size(ent->xattr);
		}
	}

	ctx_erofs->shared_xattr_size = xattr_offset;

	/* Assign shared xattr offsets for all inodes */

	for (node = ctx->root; node != NULL; node = node->next) {
		int n_shared = 0;
		for (size_t i = 0; i < node->n_xattrs; i++) {
			struct lcfs_xattr_s *xattr = &node->xattrs[i];
			struct hasher_xattr_s hkey = { .xattr = xattr };
			struct hasher_xattr_s *ent;

			ent = hash_lookup(xattr_hash, &hkey);
			assert(ent != NULL);
			if (ent->shared && n_shared < EROFS_XATTR_LONG_PREFIX) {
				xattr->erofs_shared_xattr_offset = ent->shared_offset;
				n_shared++;
			} else {
				xattr->erofs_shared_xattr_offset = -1;
			}
		}
	}

	free(sorted);
	hash_free(xattr_hash);
	return 0;

fail:
	errno = ENOMEM;
	free(sorted);
	hash_free(xattr_hash);
	return -1;
}

static bool lcfs_fits_in_erofs_compact(struct lcfs_ctx_s *ctx,
				       struct lcfs_node_s *node)
{
	int type = node->inode.st_mode & S_IFMT;
	uint64_t size;

	if (node->inode.st_mtim_sec != ctx->min_mtim_sec ||
	    node->inode.st_mtim_nsec != ctx->min_mtim_nsec) {
		return false;
	}

	if (node->inode.st_nlink > UINT16_MAX ||
	    node->inode.st_uid > UINT16_MAX || node->inode.st_gid > UINT16_MAX) {
		return false;
	}

	if (type == S_IFDIR) {
		size = (uint64_t)node->erofs_n_blocks * EROFS_BLKSIZ +
		       node->erofs_tailsize;
	} else {
		size = node->inode.st_size;
	}
	if (size > UINT32_MAX) {
		return false;
	}

	return true;
}

static void compute_erofs_dir_size(struct lcfs_node_s *node)
{
	uint32_t n_blocks = 0;
	size_t block_size = 0;

	for (size_t i = 0; i < node->children_size; i++) {
		struct lcfs_node_s *child = node->children[i];
		size_t len = sizeof(struct erofs_dirent) + strlen(child->name);
		if (block_size + len > EROFS_BLKSIZ) {
			n_blocks++;
			block_size = 0;
		}
		block_size += len;
	}

	/* As a heuristic, we never inline more than half a block */
	if (block_size > EROFS_BLKSIZ / 2) {
		n_blocks++;
		block_size = 0;
	}

	node->erofs_n_blocks = n_blocks;
	node->erofs_tailsize = block_size;
}

static uint32_t erofs_compute_chunk_bitsize(uint64_t file_size)
{
	// Compute the chunksize to use for the file size
	// We want as few chunks as possible, but not an
	// unnecessary large chunk.
	uint32_t chunkbits = ilog2(file_size - 1) + 1;

	// At least one logical block
	if (chunkbits < EROFS_BLKSIZ_BITS)
		chunkbits = EROFS_BLKSIZ_BITS;

	// Not larger chunks than max possible
	if (chunkbits - EROFS_BLKSIZ_BITS > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
		chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + EROFS_BLKSIZ_BITS;

	return chunkbits;
}

// Determine how many "chunks" we'd need to represent a file of this
// size using EROFS_INODE_CHUNK_BASED.
// See https://erofs.docs.kernel.org/en/latest/core_ondisk.html
static void erofs_compute_chunking(struct lcfs_ctx_s *ctx,
				   uint64_t file_size, uint32_t *chunkbits,
				   uint32_t *chunk_count)
{
	if (ctx->options->version < 2) {
		*chunkbits = erofs_compute_chunk_bitsize(file_size);
	} else {
		*chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + EROFS_BLKSIZ_BITS;
	}
	uint64_t chunksize = 1ULL << *chunkbits;
	*chunk_count = DIV_ROUND_UP(file_size, chunksize);
}

static void compute_erofs_inode_size(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node)
{
	int type = node->inode.st_mode & S_IFMT;
	uint64_t file_size = node->inode.st_size;

	if (type == S_IFDIR) {
		compute_erofs_dir_size(node);
	} else if (type == S_IFLNK) {
		// Note this may be overridden later if the symlink target + inode + xattrs
		// overflows a block.
		node->erofs_n_blocks = 0;
		assert(node->payload);
		node->erofs_tailsize = strlen(node->payload);
	} else if (type == S_IFREG && file_size > 0) {
		if (node->content != NULL) {
			node->erofs_n_blocks = file_size / EROFS_BLKSIZ;
			node->erofs_tailsize = file_size % EROFS_BLKSIZ;
			if (node->erofs_tailsize > EROFS_BLKSIZ / 2) {
				node->erofs_n_blocks++;
				node->erofs_tailsize = 0;
			}
		} else {
			uint32_t chunkbits;
			uint32_t chunk_count;
			erofs_compute_chunking(ctx, node->inode.st_size, &chunkbits,
					       &chunk_count);
			// Currently only support single blocks.
			assert(chunk_count <= LCFS_MAX_NONINLINE_CHUNKS);

			node->erofs_n_blocks = 0;
			node->erofs_tailsize = chunk_count * sizeof(uint32_t);
		}
	} else {
		node->erofs_n_blocks = 0;
		node->erofs_tailsize = 0;
	}
	// Just double check
	assert(node->erofs_tailsize <= EROFS_BLKSIZ);
}

static void compute_erofs_xattr_counts(struct lcfs_node_s *node,
				       size_t *n_shared_xattrs_out,
				       size_t *unshared_xattrs_size_out)
{
	size_t n_shared_xattrs = 0;
	size_t unshared_xattrs_size = 0;

	for (size_t i = 0; i < node->n_xattrs; i++) {
		struct lcfs_xattr_s *xattr = &node->xattrs[i];
		if (xattr->erofs_shared_xattr_offset >= 0) {
			n_shared_xattrs++;
		} else {
			unshared_xattrs_size += xattr_erofs_entry_size(xattr);
		}
	}

	*n_shared_xattrs_out = n_shared_xattrs;
	*unshared_xattrs_size_out = unshared_xattrs_size;
}

static uint32_t compute_erofs_xattr_filter(struct lcfs_node_s *node)
{
	uint32_t name_filter = 0;

	for (size_t i = 0; i < node->n_xattrs; i++) {
		struct lcfs_xattr_s *xattr = &node->xattrs[i];
		uint32_t name_filter_bit;
		uint8_t index;
		char *key;

		index = xattr_erofs_entry_index(xattr, &key);
		name_filter_bit =
			xxh32(key, strlen(key), EROFS_XATTR_FILTER_SEED + index) &
			(EROFS_XATTR_FILTER_BITS - 1);
		name_filter |= 1UL << name_filter_bit;
	}

	return EROFS_XATTR_FILTER_DEFAULT & ~name_filter;
}

static uint64_t compute_erofs_inode_padding_for_tail(struct lcfs_node_s *node,
						     uint64_t pos, size_t inode_size,
						     size_t xattr_size)
{
	int type = node->inode.st_mode & S_IFMT;
	uint64_t block_remainder;
	size_t non_tail_size = inode_size + xattr_size;
	size_t total_size = inode_size + xattr_size + node->erofs_tailsize;

	/* This adds extra padding in front of an inode to ensure that
	 * the tail data doesn't cross a block boundary.
	 */

	if (type == S_IFLNK) {
		/* By default we want both the inode data and the symlink tail
		 * data in the same block, wheras for a regular file normally just the
		 * tail data itself need to be inside a block. However
		 * if that would overflow a block, then the symlink data needs
		 * to follow.
		 */
		uint64_t pos_block = pos / EROFS_BLKSIZ;
		uint64_t end_block = (pos + total_size - 1) / EROFS_BLKSIZ;
		uint64_t extra_block = total_size / EROFS_BLKSIZ;
		if (extra_block > 0) {
			node->erofs_n_blocks++;
			node->erofs_tailsize = 0;
		}
		if (pos_block != end_block) {
			return round_up(pos, EROFS_BLKSIZ) - pos;
		}
		return 0;
	}

	block_remainder = EROFS_BLKSIZ - ((pos + non_tail_size) % EROFS_BLKSIZ);
	if (block_remainder < node->erofs_tailsize) {
		/* Add (aligned) padding so that tail starts in new block */
		uint64_t extra_pad = round_up(block_remainder, EROFS_SLOTSIZE);

		/* Due to the extra_pad round up it is possible the tail does not fit anyway */
		block_remainder = EROFS_BLKSIZ -
				  ((pos + non_tail_size + extra_pad) % EROFS_BLKSIZ);
		if (node->erofs_tailsize <= block_remainder) {
			/* It fit! */
			return extra_pad;
		}
		/* Didn't fit, don't inline the tail. */
		node->erofs_n_blocks++;
		node->erofs_tailsize = 0;
		return round_up(pos, EROFS_BLKSIZ) - pos;
	}

	return 0;
}

static int compute_erofs_inodes(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;
	struct lcfs_node_s *node;
	uint64_t pos, ppos;
	uint64_t meta_start, extra_pad;

	// Start inode data directly after superblock
	pos = EROFS_SUPER_OFFSET + sizeof(struct erofs_super_block);

	// But inode offsets (nids) are relative to start of block
	meta_start = round_down(pos, EROFS_BLKSIZ);

	for (node = ctx->root; node != NULL; node = node->next) {
		size_t n_shared_xattrs, unshared_xattrs_size;
		size_t inode_size, xattr_size;

		compute_erofs_inode_size(ctx, node);
		node->erofs_compact = ctx->options->version < 2 &&
			lcfs_fits_in_erofs_compact(ctx, node);
		inode_size = node->erofs_compact ?
				     sizeof(struct erofs_inode_compact) :
				     sizeof(struct erofs_inode_extended);

		compute_erofs_xattr_counts(node, &n_shared_xattrs,
					   &unshared_xattrs_size);
		node->erofs_xattr_size = xattr_size =
			xattr_erofs_inode_size(n_shared_xattrs, unshared_xattrs_size);

		/* Align inode start to next slot */
		ppos = pos;
		pos = round_up(pos, EROFS_SLOTSIZE);
		node->erofs_ipad = pos - ppos;

		/* Ensure tail does not straddle block boundaries */
		extra_pad = compute_erofs_inode_padding_for_tail(
			node, pos, inode_size, xattr_size);
		node->erofs_ipad += extra_pad;
		assert(node->erofs_ipad < EROFS_BLKSIZ);
		pos += extra_pad;
		assert(pos % EROFS_SLOTSIZE == 0);

		node->erofs_isize = inode_size + xattr_size + node->erofs_tailsize;
		ctx_erofs->n_data_blocks += node->erofs_n_blocks;
		node->erofs_nid = (pos - meta_start) / EROFS_SLOTSIZE;

		/* Assert that tails never span multiple blocks */
		assert(node->erofs_tailsize == 0 ||
		       ((pos + inode_size + xattr_size) / EROFS_BLKSIZ) ==
			       ((pos + node->erofs_isize - 1) / EROFS_BLKSIZ));

		pos += node->erofs_isize;
	}

	ctx_erofs->inodes_end = round_up(pos, EROFS_SLOTSIZE);

	return 0;
}

static int write_erofs_xattr(struct lcfs_ctx_s *ctx, struct lcfs_xattr_s *xattr)
{
	struct erofs_xattr_entry e = { 0 };
	int ret;
	char *key_suffix;
	uint8_t index = xattr_erofs_entry_index(xattr, &key_suffix);

	e.e_name_len = strlen(key_suffix);
	e.e_name_index = index;
	e.e_value_size = lcfs_u16_to_file(xattr->value_len);

	ret = lcfs_write(ctx, &e, sizeof(e));
	if (ret < 0)
		return ret;

	ret = lcfs_write(ctx, key_suffix, strlen(key_suffix));
	if (ret < 0)
		return ret;

	ret = lcfs_write(ctx, xattr->value, xattr->value_len);
	if (ret < 0)
		return ret;

	return lcfs_write_align(ctx, sizeof(uint32_t));
}

static int write_erofs_dentries_chunk(struct lcfs_ctx_s *ctx,
				      struct lcfs_node_s *node, int first_child,
				      int n_children, int alignment)
{
	uint16_t nameoff = n_children * sizeof(struct erofs_dirent);
	int ret;

	for (int i = first_child; i < first_child + n_children; i++) {
		struct lcfs_node_s *dirent_child = node->children[i];
		struct lcfs_node_s *target_child;
		if (follow_links(dirent_child, &target_child) < 0) {
			return -1;
		}

		struct erofs_dirent dirent = { 0 };
		dirent.nid = lcfs_u64_to_file(target_child->erofs_nid);
		dirent.nameoff = lcfs_u16_to_file(nameoff);
		dirent.file_type =
			erofs_make_file_type(node_get_dtype(target_child));

		nameoff += strlen(dirent_child->name);

		ret = lcfs_write(ctx, &dirent, sizeof(dirent));
		if (ret < 0)
			return ret;
	}

	for (int i = first_child; i < first_child + n_children; i++) {
		struct lcfs_node_s *dirent_child = node->children[i];

		ret = lcfs_write(ctx, dirent_child->name, strlen(dirent_child->name));
		if (ret < 0)
			return ret;
	}

	return lcfs_write_align(ctx, alignment);
}

static int write_erofs_dentries(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node,
				bool write_blocks, bool write_tail)
{
	size_t block_size = 0;
	size_t block_written = 0;
	size_t first = 0;
	int ret;

	for (size_t i = 0; i < node->children_size; i++) {
		struct lcfs_node_s *child = node->children[i];
		size_t len = sizeof(struct erofs_dirent) + strlen(child->name);
		if (block_size + len > EROFS_BLKSIZ) {
			if (write_blocks) {
				ret = write_erofs_dentries_chunk(
					ctx, node, first, i - first, EROFS_BLKSIZ);
				if (ret < 0)
					return ret;
			}

			block_written++;
			block_size = 0;
			first = i;
		}
		block_size += len;
	}

	/* Handle the remaining block which is either tailpacked or block as decided before */

	if (block_written < node->erofs_n_blocks) {
		if (write_blocks) {
			ret = write_erofs_dentries_chunk(ctx, node, first,
							 node->children_size - first,
							 EROFS_BLKSIZ);
			if (ret < 0)
				return ret;
		}

		block_written++;
		block_size = 0;
		first = node->children_size;
	}

	if (write_tail && block_size > 0) {
		ret = write_erofs_dentries_chunk(ctx, node, first,
						 node->children_size - first, 1);
		if (ret < 0)
			return ret;
	}

	return 0;
}

// Each chunk pointer appears as if it's filled with zeros using the dedicated
// EROFS_NULL_ADDR.
static int write_nullptr_chunks(struct lcfs_ctx_s *ctx, uint32_t chunk_count)
{
	for (size_t i = 0; i < chunk_count; i++) {
		uint32_t empty_chunk = EROFS_NULL_ADDR;
		int ret = lcfs_write(ctx, &empty_chunk, sizeof(empty_chunk));
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int write_erofs_inode_data(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;
	int type = node->inode.st_mode & S_IFMT;
	size_t xattr_icount;
	uint64_t size;
	int ret;
	uint16_t format;
	uint16_t version;
	uint16_t datalayout;
	off_t orig_bytes_written = ctx->bytes_written;
	size_t n_shared_xattrs;
	size_t unshared_xattrs_size;
	size_t xattr_size;
	uint32_t chunk_count = 0;
	uint16_t chunk_format = 0;

	// Unfortunately lcfs_node_set_mode doesn't validate today, so let's ensure we do
	// it at this last ditch moment if we haven't managed to do it earlier.
	if (lcfs_validate_mode(node->inode.st_mode) < 0) {
		return -1;
	}

	ret = lcfs_write_pad(ctx, node->erofs_ipad);
	if (ret < 0)
		return ret;

	/* All inodes start on slot boundary */
	assert(ctx->bytes_written % EROFS_SLOTSIZE == 0);

	/* compute xattr details */

	compute_erofs_xattr_counts(node, &n_shared_xattrs, &unshared_xattrs_size);
	xattr_size = xattr_erofs_inode_size(n_shared_xattrs, unshared_xattrs_size);
	xattr_icount = xattr_erofs_icount(xattr_size);
	if (xattr_icount > UINT16_MAX) {
		errno = EINVAL;
		return -1;
	}

	version = node->erofs_compact ? 0 : 1;
	datalayout = (node->erofs_tailsize > 0) ? EROFS_INODE_FLAT_INLINE :
						  EROFS_INODE_FLAT_PLAIN;

	if (type == S_IFDIR) {
		size = (uint64_t)node->erofs_n_blocks * EROFS_BLKSIZ +
		       node->erofs_tailsize;
	} else if (type == S_IFREG) {
		size = node->inode.st_size;

		if (size > 0 && node->content == NULL) {
			uint32_t chunkbits;
			erofs_compute_chunking(ctx, node->inode.st_size, &chunkbits,
						       &chunk_count);
			assert(chunk_count <= LCFS_MAX_NONINLINE_CHUNKS);
			datalayout = EROFS_INODE_CHUNK_BASED;
			chunk_format = chunkbits - EROFS_BLKSIZ_BITS;
		}
	} else if (type == S_IFLNK) {
		if (node->erofs_n_blocks == 0) {
			size = node->erofs_tailsize;
		} else {
			assert(node->erofs_n_blocks == 1);
			size = node->inode.st_size;
		}
	} else {
		size = 0;
	}

	format = datalayout << EROFS_I_DATALAYOUT_BIT | version << EROFS_I_VERSION_BIT;

	uint32_t ino = ctx->options->version < 2 ? node->inode_num : node->erofs_nid;

	if (node->erofs_compact) {
		struct erofs_inode_compact i = { 0 };
		i.i_format = lcfs_u16_to_file(format);
		i.i_xattr_icount = lcfs_u16_to_file((uint16_t)xattr_icount);
		i.i_mode = lcfs_u16_to_file((uint16_t)node->inode.st_mode);
		i.i_nlink = lcfs_u16_to_file((uint16_t)node->inode.st_nlink);
		i.i_size = lcfs_u32_to_file((uint32_t)size);
		i.i_ino = lcfs_u32_to_file(ino);
		i.i_uid = lcfs_u16_to_file((uint16_t)node->inode.st_uid);
		i.i_gid = lcfs_u16_to_file((uint16_t)node->inode.st_gid);

		if (type == S_IFDIR) {
			if (node->erofs_n_blocks > 0) {
				i.i_u.raw_blkaddr = lcfs_u32_to_file(
					(uint32_t)(ctx_erofs->current_end /
						   EROFS_BLKSIZ));
				ctx_erofs->current_end +=
					EROFS_BLKSIZ * node->erofs_n_blocks;
			}
		} else if (type == S_IFCHR || type == S_IFBLK) {
			i.i_u.rdev = lcfs_u32_to_file(node->inode.st_rdev);
		} else if (type == S_IFREG || type == S_IFLNK) {
			if (node->erofs_n_blocks > 0) {
				i.i_u.raw_blkaddr = lcfs_u32_to_file(
					(uint32_t)(ctx_erofs->current_end /
						   EROFS_BLKSIZ));
				ctx_erofs->current_end +=
					EROFS_BLKSIZ * node->erofs_n_blocks;
			}
			if (datalayout == EROFS_INODE_CHUNK_BASED) {
				i.i_u.c.format = lcfs_u16_to_file(chunk_format);
			}
		}

		ret = lcfs_write(ctx, &i, sizeof(i));
		if (ret < 0)
			return ret;
	} else {
		struct erofs_inode_extended i = { 0 };
		i.i_format = lcfs_u16_to_file(format);
		i.i_xattr_icount = lcfs_u16_to_file((uint16_t)xattr_icount);
		i.i_mode = lcfs_u16_to_file((uint16_t)node->inode.st_mode);
		i.i_nlink = lcfs_u32_to_file(node->inode.st_nlink);
		i.i_size = lcfs_u64_to_file(size);
		i.i_ino = lcfs_u32_to_file(ino);
		i.i_uid = lcfs_u32_to_file(node->inode.st_uid);
		i.i_gid = lcfs_u32_to_file(node->inode.st_gid);
		i.i_mtime = lcfs_u64_to_file((uint64_t)node->inode.st_mtim_sec);
		i.i_mtime_nsec = lcfs_u32_to_file(node->inode.st_mtim_nsec);

		if (type == S_IFDIR) {
			if (node->erofs_n_blocks > 0) {
				i.i_u.raw_blkaddr = lcfs_u32_to_file(
					(uint32_t)(ctx_erofs->current_end /
						   EROFS_BLKSIZ));
				ctx_erofs->current_end +=
					EROFS_BLKSIZ * node->erofs_n_blocks;
			}
		} else if (type == S_IFCHR || type == S_IFBLK) {
			i.i_u.rdev = lcfs_u32_to_file(node->inode.st_rdev);
		} else if (type == S_IFREG || type == S_IFLNK) {
			if (node->erofs_n_blocks > 0) {
				i.i_u.raw_blkaddr = lcfs_u32_to_file(
					(uint32_t)(ctx_erofs->current_end /
						   EROFS_BLKSIZ));
				ctx_erofs->current_end +=
					EROFS_BLKSIZ * node->erofs_n_blocks;
			}
			if (datalayout == EROFS_INODE_CHUNK_BASED) {
				i.i_u.c.format = lcfs_u16_to_file(chunk_format);
			}
		}

		ret = lcfs_write(ctx, &i, sizeof(i));
		if (ret < 0)
			return ret;
	}

	/* write xattrs */
	if (xattr_size) {
		const size_t pre_xattr_bytes_written = ctx->bytes_written;
		struct erofs_xattr_ibody_header xattr_header = { 0 };
		xattr_header.h_shared_count = n_shared_xattrs;
		xattr_header.h_name_filter =
			lcfs_u32_to_file(compute_erofs_xattr_filter(node));

		ret = lcfs_write(ctx, &xattr_header, sizeof(xattr_header));
		if (ret < 0)
			return ret;

		/* shared */
		for (size_t i = 0; i < node->n_xattrs; i++) {
			struct lcfs_xattr_s *xattr = &node->xattrs[i];
			if (xattr->erofs_shared_xattr_offset >= 0) {
				uint64_t offset = ctx_erofs->inodes_end;
				if (ctx->options->version < 2)
					offset %= EROFS_BLKSIZ;
				offset += xattr->erofs_shared_xattr_offset;
				uint32_t v = lcfs_u32_to_file(
					(uint32_t)(offset / sizeof(uint32_t)));
				ret = lcfs_write(ctx, &v, sizeof(v));
				if (ret < 0)
					return ret;
			}
		}
		/* unshared */
		for (size_t i = 0; i < node->n_xattrs; i++) {
			struct lcfs_xattr_s *xattr = &node->xattrs[i];
			if (xattr->erofs_shared_xattr_offset < 0) {
				ret = write_erofs_xattr(ctx, xattr);
				if (ret < 0)
					return ret;
			}
		}
		assert(ctx->bytes_written - pre_xattr_bytes_written ==
		       node->erofs_xattr_size);
	}

	if (type == S_IFDIR) {
		ret = write_erofs_dentries(ctx, node, false, true);
		if (ret < 0)
			return ret;
	} else if (type == S_IFLNK) {
		if (node->erofs_n_blocks == 0) {
			ret = lcfs_write(ctx, node->payload, strlen(node->payload));
			if (ret < 0)
				return ret;
		}
	} else if (type == S_IFREG && node->erofs_tailsize > 0) {
		if (node->content != NULL) {
			uint64_t file_size = node->inode.st_size;
			ret = lcfs_write(ctx, node->content + file_size - node->erofs_tailsize,
					 node->erofs_tailsize);
			if (ret < 0)
				return ret;
		} else {
			// Currently we assume this fits within a single block
			assert(chunk_count <= LCFS_MAX_NONINLINE_CHUNKS);
			assert(node->erofs_n_blocks == 0 ||
			       node->erofs_n_blocks == 1);
			ret = write_nullptr_chunks(ctx, chunk_count);
			if (ret < 0) {
				return ret;
			}
		}
	}

	assert(ctx->bytes_written - orig_bytes_written ==
	       node->erofs_isize + node->erofs_ipad);

	return 0;
}

static int write_erofs_inodes(struct lcfs_ctx_s *ctx)
{
	struct lcfs_node_s *node;
	int ret;

	for (node = ctx->root; node != NULL; node = node->next) {
		ret = write_erofs_inode_data(ctx, node);
		if (ret < 0)
			return ret;
	}

	ret = lcfs_write_align(ctx, EROFS_SLOTSIZE);
	if (ret < 0)
		return ret;

	return 0;
}

/* Writes the non-tailpacked file data, if any */
static int write_erofs_file_content(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node)
{
	int type = node->inode.st_mode & S_IFMT;
	off_t size = node->inode.st_size;

	uint8_t *target;
	bool has_blocks = node->erofs_n_blocks > 0;
	if (type == S_IFREG && has_blocks) {
		// If this is a non-inline file, then we need to write at most
		// a single block-sized chunk.
		if (node->content == NULL) {
			assert(node->erofs_tailsize == 0);
			// Currently we assume this fits within a single block
			assert(node->erofs_n_blocks == 1);
			// Note early return here
			return write_nullptr_chunks(ctx, 1024);
		}
		// If it's an inline file, provide the content to write
		target = node->content;
	} else if (type == S_IFLNK && has_blocks) {
		assert(node->payload != NULL);
		target = (uint8_t *)node->payload;
	} else {
		return 0;
	}

	for (size_t i = 0; i < node->erofs_n_blocks; i++) {
		off_t offset = i * EROFS_BLKSIZ;
		off_t len = min(size - offset, EROFS_BLKSIZ);
		int ret;

		ret = lcfs_write(ctx, target + offset, len);
		if (ret < 0)
			return ret;
		return lcfs_write_align(ctx, EROFS_BLKSIZ);
	}
	return 0;
}

static int write_erofs_data_blocks(struct lcfs_ctx_s *ctx)
{
	struct lcfs_node_s *node;
	int ret;

	for (node = ctx->root; node != NULL; node = node->next) {
		ret = write_erofs_dentries(ctx, node, true, false);
		if (ret < 0)
			return ret;
		ret = write_erofs_file_content(ctx, node);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int write_erofs_shared_xattrs(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;
	int ret;

	for (size_t i = 0; i < ctx_erofs->n_shared_xattrs; i++) {
		struct lcfs_xattr_s *xattr = ctx_erofs->shared_xattrs[i];
		ret = write_erofs_xattr(ctx, xattr);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int add_overlayfs_xattrs(struct lcfs_ctx_s *ctx, struct lcfs_node_s *node)
{
	int type = node->inode.st_mode & S_IFMT;
	int ret;

	/* First escape all existing "trusted.overlay.*" xattrs */
	for (size_t i = 0; i < lcfs_node_get_n_xattr(node); i++) {
		const char *name = lcfs_node_get_xattr_name(node, i);

		if (str_has_prefix(name, OVERLAY_XATTR_PREFIX)) {
			cleanup_free char *renamed =
				str_join(OVERLAY_XATTR_ESCAPE_PREFIX,
					 name + strlen(OVERLAY_XATTR_PREFIX));
			if (renamed == NULL) {
				errno = ENOMEM;
				return -1;
			}
			/* We rename in-place, this is safe from
			   collisions because we also rename any
			   colliding xattr */
			if (lcfs_node_rename_xattr(node, i, renamed) < 0)
				return -1;
		}
	}

	if (type == S_IFREG && node->inode.st_size > 0 && node->content == NULL) {
		uint8_t xattr_data[4 + LCFS_DIGEST_SIZE];
		size_t xattr_len = 0;

		if (node->digest_set) {
			xattr_len = sizeof(xattr_data);
			xattr_data[0] = 0; /* version */
			xattr_data[1] = xattr_len;
			xattr_data[2] = 0; /* flags */
			xattr_data[3] = FS_VERITY_HASH_ALG_SHA256;
			memcpy(xattr_data + 4, node->digest, LCFS_DIGEST_SIZE);
		}

		ret = lcfs_node_set_xattr(node, OVERLAY_XATTR_METACOPY,
					  (const char *)xattr_data, xattr_len);
		if (ret < 0)
			return ret;

		if (node->payload && strlen(node->payload) > 0) {
			char *path = maybe_join_path("/", node->payload);
			if (path == NULL) {
				errno = ENOMEM;
				return -1;
			}
			ret = lcfs_node_set_xattr(node, OVERLAY_XATTR_REDIRECT,
						  path, strlen(path));
			free(path);
			if (ret < 0)
				return ret;
		}
	}

	/* escape whiteouts */
	if (type == S_IFCHR && node->inode.st_rdev == makedev(0, 0)) {
		struct lcfs_node_s *parent = lcfs_node_get_parent(node);

		// The input may have nonsensically been a chardev with nonzero size
		// but we need to discard that.
		node->inode.st_size = 0;
		lcfs_node_set_mode(node,
				   S_IFREG | (lcfs_node_get_mode(node) & ~S_IFMT));
		ret = lcfs_node_set_xattr(node, OVERLAY_XATTR_ESCAPED_WHITEOUT,
					  "", 0);
		if (ret < 0)
			return ret;
		ret = lcfs_node_set_xattr(node, OVERLAY_XATTR_USERXATTR_WHITEOUT,
					  "", 0);
		if (ret < 0)
			return ret;

		/* Mark parent dir containing whiteouts */
		ret = lcfs_node_set_xattr(parent,
					  OVERLAY_XATTR_ESCAPED_WHITEOUTS, "", 0);
		if (ret < 0)
			return ret;
		ret = lcfs_node_set_xattr(parent, OVERLAY_XATTR_USERXATTR_WHITEOUTS,
					  "", 0);
		if (ret < 0)
			return ret;

		/* Mark dir containing whiteouts with new format as of version 1 */
		if (ctx->options->version >= 1) {
			ret = lcfs_node_set_xattr(
				parent, OVERLAY_XATTR_ESCAPED_OPAQUE, "x", 1);
			if (ret < 0)
				return ret;
			ret = lcfs_node_set_xattr(
				parent, OVERLAY_XATTR_USERXATTR_OPAQUE, "x", 1);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

static int add_overlay_whiteouts(struct lcfs_node_s *root)
{
	static const char hexchars[] = "0123456789abcdef";
	const char *selinux;
	size_t selinux_len;
	int res;

	selinux = lcfs_node_get_xattr(root, "security.selinux", &selinux_len);

	for (int i = 0; i <= 255; i++) {
		struct lcfs_node_s *child;
		char name[3];

		name[0] = hexchars[(i >> 4) % 16];
		name[1] = hexchars[i % 16];
		name[2] = 0;

		child = lcfs_node_lookup_child(root, name);
		if (child != NULL)
			continue;

		child = lcfs_node_new();
		if (child == NULL) {
			return -1;
		}

		lcfs_node_set_mode(child, S_IFCHR | 0644);
		lcfs_node_set_rdev64(child, 0);

		child->inode.st_uid = root->inode.st_uid;
		child->inode.st_gid = root->inode.st_gid;
		child->inode.st_mtim_sec = root->inode.st_mtim_sec;
		child->inode.st_mtim_nsec = root->inode.st_mtim_nsec;

		/* Inherit selinux context from root dir */
		if (selinux != NULL) {
			res = lcfs_node_set_xattr(child, "security.selinux",
						  selinux, selinux_len);
			if (res < 0) {
				lcfs_node_unref(child);
				return res;
			}
		}

		res = lcfs_node_add_child(root, child, name);
		if (res < 0) {
			lcfs_node_unref(child);
			return res;
		}
	}

	return 0;
}

static int rewrite_tree_node_for_erofs(struct lcfs_ctx_s *ctx,
				       struct lcfs_node_s *node,
				       struct lcfs_node_s *parent)
{
	int ret;

	// This is one of the first walks of the tree we do, so validate
	// everything here.
	ret = lcfs_node_validate(node);
	if (ret < 0)
		return ret;

	ret = add_overlayfs_xattrs(ctx, node);
	if (ret < 0)
		return ret;

	if (lcfs_node_dirp(node)) {
		struct lcfs_node_s *existing;

		/* Ensure we have . and .. */
		existing = lcfs_node_lookup_child(node, ".");
		if (existing == NULL) {
			struct lcfs_node_s *link = lcfs_node_new();
			if (link == NULL) {
				return -1;
			}
			lcfs_node_make_hardlink(link, node);
			ret = lcfs_node_add_child(node, link, ".");
			if (ret < 0) {
				lcfs_node_unref(link);
				return -1;
			}
		}

		existing = lcfs_node_lookup_child(node, "..");
		if (existing == NULL) {
			struct lcfs_node_s *link = lcfs_node_new();
			if (link == NULL) {
				return -1;
			}
			lcfs_node_make_hardlink(link, parent);
			ret = lcfs_node_add_child(node, link, "..");
			if (ret < 0) {
				lcfs_node_unref(link);
				return -1;
			}
		}

		for (size_t i = 0; i < node->children_size; ++i) {
			struct lcfs_node_s *child = node->children[i];

			if (child->link_to != NULL) {
				continue;
			}

			ret = rewrite_tree_node_for_erofs(ctx, child, node);
			if (ret < 0) {
				return -1;
			}
		}
	}

	return 0;
}

static int set_overlay_opaque(struct lcfs_node_s *node)
{
	int ret;

	ret = lcfs_node_set_xattr(node, OVERLAY_XATTR_OPAQUE, "y", 1);
	if (ret < 0)
		return ret;

	return 0;
}

static int rewrite_tree_for_erofs(struct lcfs_ctx_s *ctx, struct lcfs_node_s *root)
{
	int res;

	res = rewrite_tree_node_for_erofs(ctx, root, root);
	if (res < 0)
		return res;

        if (ctx->options->version < 2) {
		res = set_overlay_opaque(root);
		if (res < 0)
			return res;

		res = add_overlay_whiteouts(root);
		if (res < 0)
			return res;
	}

	return 0;
}

int lcfs_write_erofs_to(struct lcfs_ctx_s *ctx)
{
	struct lcfs_ctx_erofs_s *ctx_erofs = (struct lcfs_ctx_erofs_s *)ctx;
	struct lcfs_node_s *root;
	struct lcfs_erofs_header_s header = {
		.magic = lcfs_u32_to_file(((uint32_t)LCFS_EROFS_MAGIC)),
		.version = lcfs_u32_to_file(((uint32_t)LCFS_EROFS_VERSION)),
		.composefs_version = lcfs_u32_to_file(ctx->options->version),
	};
	uint32_t header_flags;
	struct erofs_super_block superblock = {
		.magic = lcfs_u32_to_file(((uint32_t)EROFS_SUPER_MAGIC_V1)),
		.blkszbits = EROFS_BLKSIZ_BITS,
	};
	int ret = 0;
	uint64_t data_block_start;

	/* Clone root so we can make required modifications to it */
	ret = lcfs_clone_root(ctx);
	if (ret < 0)
		return ret;

	root = ctx->root; /* After we cloned it */

	/* Rewrite cloned tree as needed for erofs */
	ret = rewrite_tree_for_erofs(ctx, root);
	if (ret < 0)
		return ret;

	ret = lcfs_compute_tree(ctx, root);
	if (ret < 0)
		return ret;

	ret = compute_erofs_shared_xattrs(ctx);
	if (ret < 0)
		return ret;

	ret = compute_erofs_inodes(ctx);
	if (ret < 0)
		return ret;

	header_flags = 0;
	if (ctx->has_acl)
		header_flags |= LCFS_EROFS_FLAGS_HAS_ACL;
	header.flags = lcfs_u32_to_file(header_flags);

	ret = lcfs_write(ctx, &header, sizeof(header));
	if (ret < 0)
		return ret;

	ret = lcfs_write_pad(ctx, EROFS_SUPER_OFFSET - sizeof(header));
	if (ret < 0)
		return ret;

	superblock.feature_compat =
		lcfs_u32_to_file((uint32_t)(EROFS_FEATURE_COMPAT_MTIME |
					    EROFS_FEATURE_COMPAT_XATTR_FILTER));
	superblock.inos = lcfs_u64_to_file(ctx->num_inodes);

	if (ctx->options->version < 2) {
		superblock.build_time = lcfs_u64_to_file((uint64_t)ctx->min_mtim_sec);
		superblock.build_time_nsec = lcfs_u32_to_file(ctx->min_mtim_nsec);

		/* metadata is stored directly after superblock */
		superblock.meta_blkaddr = lcfs_u32_to_file(
			(uint32_t)((EROFS_SUPER_OFFSET + sizeof(superblock)) / EROFS_BLKSIZ));

		/* shared xattrs is directly after metadata */
		superblock.xattr_blkaddr = lcfs_u32_to_file((uint32_t)(ctx_erofs->inodes_end / EROFS_BLKSIZ));
	}

	assert(root->erofs_nid < UINT16_MAX);
	superblock.root_nid = lcfs_u16_to_file((uint16_t)root->erofs_nid);

	data_block_start =
		round_up(ctx_erofs->inodes_end + ctx_erofs->shared_xattr_size,
			 EROFS_BLKSIZ);

	superblock.blocks =
		lcfs_u32_to_file((uint32_t)(data_block_start / EROFS_BLKSIZ +
					    ctx_erofs->n_data_blocks));

	/* TODO: More superblock fields:
	 *  uuid?
	 *  volume_name?
	 */

	ret = lcfs_write(ctx, &superblock, sizeof(superblock));
	if (ret < 0)
		return ret;

	ctx_erofs->current_end = data_block_start;

	ret = write_erofs_inodes(ctx);
	if (ret < 0)
		return ret;

	assert(ctx_erofs->inodes_end == (uint64_t)ctx->bytes_written);

	ret = write_erofs_shared_xattrs(ctx);
	if (ret < 0)
		return ret;

	assert(ctx_erofs->inodes_end + ctx_erofs->shared_xattr_size ==
	       (uint64_t)ctx->bytes_written);

	/* Following are full blocks and must be block-aligned */
	ret = lcfs_write_align(ctx, EROFS_BLKSIZ);
	if (ret < 0)
		return ret;

	assert(data_block_start == (uint64_t)ctx->bytes_written);

	ret = write_erofs_data_blocks(ctx);
	if (ret < 0)
		return ret;

	assert(ctx_erofs->current_end == (uint64_t)ctx->bytes_written);
	assert(data_block_start + ctx_erofs->n_data_blocks * EROFS_BLKSIZ ==
	       (uint64_t)ctx->bytes_written);

	return 0;
}

struct hasher_node_s {
	uint64_t nid;
	struct lcfs_node_s *node;
};

struct lcfs_image_data {
	const uint8_t *erofs_data;
	size_t erofs_data_size;
	const uint8_t *erofs_metadata;
	const uint8_t *erofs_metadata_end;
	const uint8_t *erofs_xattrdata;
	const uint8_t *erofs_xattrdata_end;
	uint64_t erofs_build_time;
	uint32_t erofs_build_time_nsec;
	Hash_table *node_hash;
};

static const erofs_inode *lcfs_image_get_erofs_inode(struct lcfs_image_data *data,
						     uint64_t nid)
{
	const uint8_t *inode_data = data->erofs_metadata + (nid << EROFS_ISLOTBITS);

	if (inode_data >= data->erofs_metadata_end) {
		errno = EINVAL;
		return NULL;
	}

	return (const erofs_inode *)inode_data;
}

static struct lcfs_node_s *lcfs_build_node_from_image(struct lcfs_image_data *data,
						      uint64_t nid,
						      Hash_table *filter);

static int erofs_readdir_block(struct lcfs_image_data *data,
			       struct lcfs_node_s *parent, const uint8_t *block,
			       size_t block_size, Hash_table *filter)
{
	const struct erofs_dirent *dirents = (struct erofs_dirent *)block;
	size_t dirents_size = lcfs_u16_from_file(dirents[0].nameoff);
	size_t n_dirents, i;

	if (dirents_size % sizeof(struct erofs_dirent) != 0) {
		/* This should not happen for valid filesystems */
		errno = EINVAL;
		return -1;
	}

	n_dirents = dirents_size / sizeof(struct erofs_dirent);

	for (i = 0; i < n_dirents; i++) {
		char name_buf[PATH_MAX];
		uint64_t nid = lcfs_u64_from_file(dirents[i].nid);
		uint16_t nameoff = lcfs_u16_from_file(dirents[i].nameoff);
		const char *child_name;
		uint16_t child_name_len;
		cleanup_node struct lcfs_node_s *child = NULL;

		/* Compute length of the name, which is a bit weird for the last dirent */
		child_name = (char *)(block + nameoff);
		if (i + 1 < n_dirents)
			child_name_len =
				lcfs_u16_from_file(dirents[i + 1].nameoff) - nameoff;
		else
			child_name_len = strnlen(child_name, block_size - nameoff);

		if ((child_name_len == 1 && child_name[0] == '.') ||
		    (child_name_len == 2 && child_name[0] == '.' &&
		     child_name[1] == '.'))
			continue;

		/* Copy to null terminate */
		child_name_len = min(child_name_len, PATH_MAX - 1);
		memcpy(name_buf, child_name, child_name_len);
		name_buf[child_name_len] = 0;

		if (filter != NULL && hash_lookup(filter, name_buf) == NULL) {
			continue;
		}

		child = lcfs_build_node_from_image(data, nid, NULL);
		if (child == NULL) {
			if (errno == ENOTSUP)
				continue; /* Skip real whiteouts (00-ff) */
			else
				return -1;
		}

		if (lcfs_node_add_child(parent, child, /* Takes ownership on success */
					name_buf) < 0)
			return -1;
		steal_pointer(&child);
	}

	return 0;
}

static int lcfs_build_node_erofs_xattr(struct lcfs_node_s *node, uint8_t name_index,
				       const char *entry_name, uint8_t name_len,
				       const char *value, uint16_t value_size)
{
	static_assert((sizeof(struct erofs_xattr_ibody_header) == LCFS_XATTR_HEADER_SIZE),
		      "Verifying sizeof xattr header entry");
	static_assert((sizeof(struct erofs_xattr_entry) == LCFS_INODE_XATTRMETA_SIZE),
		      "Verifying sizeof xattr entry");

	cleanup_free char *name =
		erofs_get_xattr_name(name_index, entry_name, name_len);
	if (name == NULL)
		return -1;

	if (strcmp(name, OVERLAY_XATTR_REDIRECT) == 0) {
		if ((node->inode.st_mode & S_IFMT) == S_IFREG) {
			if (value_size > 1 && value[0] == '/') {
				value_size++;
				value++;
			}
			node->payload = strndup(value, value_size);
			if (node->payload == NULL) {
				errno = ENOMEM;
				return -1;
			}
		}
		return 0;
	}

	if (strcmp(name, OVERLAY_XATTR_METACOPY) == 0) {
		if ((node->inode.st_mode & S_IFMT) == S_IFREG &&
		    value_size == 4 + LCFS_DIGEST_SIZE)
			lcfs_node_set_fsverity_digest(node, (uint8_t *)value + 4);
		return 0;
	}

	if (strcmp(name, OVERLAY_XATTR_ESCAPED_WHITEOUT) == 0 &&
	    (node->inode.st_mode & S_IFMT) == S_IFREG) {
		/* Rewrite to regular whiteout */
		node->inode.st_mode = (node->inode.st_mode & ~S_IFMT) | S_IFCHR;
		node->inode.st_rdev = makedev(0, 0);
		node->inode.st_size = 0;
		return 0;
	}
	if (strcmp(name, OVERLAY_XATTR_ESCAPED_WHITEOUTS) == 0 ||
	    strcmp(name, OVERLAY_XATTR_USERXATTR_WHITEOUT) == 0 ||
	    strcmp(name, OVERLAY_XATTR_USERXATTR_WHITEOUTS) == 0) {
		/* skip */
		return 0;
	}

	if (str_has_prefix(name, OVERLAY_XATTR_PREFIX)) {
		if (str_has_prefix(name, OVERLAY_XATTR_ESCAPE_PREFIX)) {
			/* Unescape */
			memmove(name + strlen(OVERLAY_XATTR_TRUSTED_PREFIX),
				name + strlen(OVERLAY_XATTR_PREFIX),
				strlen(name) - strlen(OVERLAY_XATTR_PREFIX) + 1);
		} else {
			/* skip */
			return 0;
		}
	}

	if (lcfs_node_set_xattr_internal(node, name, value, value_size, false) < 0)
		return -1;

	return 0;
}

static struct lcfs_node_s *lcfs_build_node_from_image(struct lcfs_image_data *data,
						      uint64_t nid, Hash_table *filter)
{
	const erofs_inode *cino;
	cleanup_node struct lcfs_node_s *node = NULL;
	uint64_t file_size;
	uint16_t xattr_icount;
	uint32_t raw_blkaddr;
	int type;
	size_t isize;
	bool tailpacked;
	size_t xattr_size;
	struct hasher_node_s ht_entry = { nid };
	cleanup_free struct hasher_node_s *new_ht_entry = NULL;
	struct hasher_node_s *existing;
	uint64_t n_blocks;
	uint64_t last_oob_block;
	size_t tail_size;
	const uint8_t *tail_data;
	const uint8_t *oob_data;
	int ret;

	cino = lcfs_image_get_erofs_inode(data, nid);
	if (cino == NULL)
		return NULL;

	node = lcfs_node_new();
	if (node == NULL) {
		return NULL;
	}

	existing = hash_lookup(data->node_hash, &ht_entry);
	if (existing) {
		node->link_to = lcfs_node_ref(existing->node);
		return steal_pointer(&node);
	}

	new_ht_entry = malloc(sizeof(struct hasher_node_s));
	if (new_ht_entry == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	new_ht_entry->nid = nid;
	new_ht_entry->node = node;
	if (hash_insert(data->node_hash, new_ht_entry) == NULL) {
		lcfs_node_unref(node);
		errno = ENOMEM;
		return NULL;
	}
	new_ht_entry = NULL;

	if (erofs_inode_is_compact(cino)) {
		const struct erofs_inode_compact *c = &cino->compact;

		node->inode.st_mode = lcfs_u16_from_file(c->i_mode);
		node->inode.st_nlink = lcfs_u16_from_file(c->i_nlink);
		node->inode.st_size = lcfs_u32_from_file(c->i_size);
		node->inode.st_uid = lcfs_u16_from_file(c->i_uid);
		node->inode.st_gid = lcfs_u16_from_file(c->i_gid);

		node->inode.st_mtim_sec = data->erofs_build_time;
		node->inode.st_mtim_nsec = data->erofs_build_time_nsec;

		type = node->inode.st_mode & S_IFMT;

		if (type == S_IFCHR || type == S_IFBLK)
			node->inode.st_rdev = lcfs_u32_from_file(c->i_u.rdev);

		file_size = lcfs_u32_from_file(c->i_size);
		xattr_icount = lcfs_u16_from_file(c->i_xattr_icount);
		raw_blkaddr = lcfs_u32_from_file(c->i_u.raw_blkaddr);
		isize = sizeof(struct erofs_inode_compact);

	} else {
		const struct erofs_inode_extended *e = &cino->extended;

		node->inode.st_mode = lcfs_u16_from_file(e->i_mode);
		node->inode.st_size = lcfs_u64_from_file(e->i_size);
		node->inode.st_uid = lcfs_u32_from_file(e->i_uid);
		node->inode.st_gid = lcfs_u32_from_file(e->i_gid);
		node->inode.st_mtim_sec = lcfs_u64_from_file(e->i_mtime);
		node->inode.st_mtim_nsec = lcfs_u32_from_file(e->i_mtime_nsec);
		node->inode.st_nlink = lcfs_u32_from_file(e->i_nlink);

		type = node->inode.st_mode & S_IFMT;

		if (type == S_IFCHR || type == S_IFBLK)
			node->inode.st_rdev = lcfs_u32_from_file(e->i_u.rdev);

		file_size = lcfs_u64_from_file(e->i_size);
		xattr_icount = lcfs_u16_from_file(e->i_xattr_icount);
		raw_blkaddr = lcfs_u32_from_file(e->i_u.raw_blkaddr);
		isize = sizeof(struct erofs_inode_extended);
	}

	if (type == S_IFCHR && node->inode.st_rdev == 0) {
		errno = ENOTSUP; /* Use this to signal that we found a whiteout */
		return NULL;
	}

	xattr_size = erofs_xattr_inode_size(xattr_icount);

	tailpacked = erofs_inode_is_tailpacked(cino);
	tail_size = tailpacked ? file_size % EROFS_BLKSIZ : 0;
	tail_data = ((uint8_t *)cino) + isize + xattr_size;
	oob_data = data->erofs_data + raw_blkaddr * EROFS_BLKSIZ;

	n_blocks = round_up(file_size, EROFS_BLKSIZ) / EROFS_BLKSIZ;
	last_oob_block = tailpacked ? n_blocks - 1 : n_blocks;

	if (type == S_IFDIR) {
		/* First read the out-of-band blocks */
		for (uint64_t block = 0; block < last_oob_block; block++) {
			const uint8_t *block_data = oob_data + block * EROFS_BLKSIZ;
			size_t block_size = EROFS_BLKSIZ;

			if (!tailpacked && block + 1 == last_oob_block) {
				block_size = file_size % EROFS_BLKSIZ;
				if (block_size == 0) {
					block_size = EROFS_BLKSIZ;
				}
			}

			if (erofs_readdir_block(data, node, block_data,
						block_size, filter) < 0)
				return NULL;
		}

		/* Then inline */
		if (tailpacked) {
			if (erofs_readdir_block(data, node, tail_data,
						tail_size, filter) < 0)
				return NULL;
		}

	} else if (type == S_IFLNK) {
		char name_buf[PATH_MAX];

		// Filter only applies to toplevel
		assert(filter == NULL);

		if (file_size >= PATH_MAX) {
			errno = EINVAL;
			return NULL;
		}

		if (tailpacked) {
			memcpy(name_buf, tail_data, file_size);
		} else {
			memcpy(name_buf, data->erofs_data + raw_blkaddr * EROFS_BLKSIZ,
			       file_size);
		}
		name_buf[file_size] = 0;
		if (lcfs_node_set_symlink_payload(node, name_buf) < 0)
			return NULL;
	} else if (type == S_IFREG && file_size != 0 && erofs_inode_is_flat(cino)) {
		cleanup_free uint8_t *content = NULL;
		size_t oob_size;

		// Filter only applies to toplevel
		assert(filter == NULL);

		// Strictly limit to our max size, and for good measure
		// the size of the file (which should always be larger than 4k
		// in reality).
		if (file_size > min(LCFS_INLINE_CONTENT_MAX, data->erofs_data_size)) {
			errno = EINVAL;
			return NULL;
		}

		content = malloc(file_size);
		if (content == NULL) {
			errno = ENOMEM;
			return NULL;
		}

		oob_size = tailpacked ? last_oob_block * EROFS_BLKSIZ : file_size;
		memcpy(content, data->erofs_data + raw_blkaddr * EROFS_BLKSIZ,
		       oob_size);
		if (tailpacked)
			memcpy(content + oob_size, tail_data, tail_size);

		ret = lcfs_node_set_content(node, content, file_size);
		if (ret < 0) {
			return NULL;
		}
	} else if (type == S_IFREG && file_size != 0) {
		// If it's not an inline file, then it must be chunk based.
		uint16_t layout = erofs_inode_datalayout(cino);
		if (layout != EROFS_INODE_CHUNK_BASED) {
			errno = EINVAL;
			return NULL;
		}
		// In an extended "fsck" mode we could verify that we have
		// EROFS_NULL_ADDR blocks here.
	}

	if (xattr_icount > 0) {
		const struct erofs_xattr_ibody_header *xattr_header;
		const uint8_t *xattrs_inline;
		const uint8_t *xattrs_start;
		const uint8_t *xattrs_end;
		uint8_t shared_count;

		xattrs_start = ((uint8_t *)cino) + isize;
		xattrs_end = ((uint8_t *)cino) + isize + xattr_size;
		xattr_header = (struct erofs_xattr_ibody_header *)xattrs_start;
		shared_count = xattr_header->h_shared_count;

		xattrs_inline = xattrs_start +
				sizeof(struct erofs_xattr_ibody_header) +
				shared_count * 4;

		/* Inline xattrs */
		while (xattrs_inline + sizeof(struct erofs_xattr_entry) < xattrs_end) {
			const struct erofs_xattr_entry *entry =
				(const struct erofs_xattr_entry *)xattrs_inline;
			const char *entry_data = (const char *)entry +
						 sizeof(struct erofs_xattr_entry);
			const char *entry_name = entry_data;
			uint8_t name_len = entry->e_name_len;
			uint8_t name_index = entry->e_name_index;
			const char *value = entry_data + name_len;
			uint16_t value_size =
				lcfs_u16_from_file(entry->e_value_size);
			size_t el_size = round_up(sizeof(struct erofs_xattr_entry) +
							  name_len + value_size,
						  4);

			if (lcfs_build_node_erofs_xattr(node, name_index,
							entry_name, name_len,
							value, value_size) < 0)
				return NULL;

			xattrs_inline += el_size;
		}

		/* Shared xattrs */
		for (int i = 0; i < shared_count; i++) {
			uint32_t idx = lcfs_u32_from_file(
				xattr_header->h_shared_xattrs[i]);
			const struct erofs_xattr_entry *entry =
				(const struct erofs_xattr_entry *)(data->erofs_xattrdata +
								   idx * 4);
			const char *entry_data = (const char *)entry +
						 sizeof(struct erofs_xattr_entry);
			const char *entry_name = entry_data;
			uint8_t name_len = entry->e_name_len;
			uint8_t name_index = entry->e_name_index;
			const char *value = entry_data + name_len;
			uint16_t value_size =
				lcfs_u16_from_file(entry->e_value_size);

			if (lcfs_build_node_erofs_xattr(node, name_index,
							entry_name, name_len,
							value, value_size) < 0)
				return NULL;
		}
	}

	return steal_pointer(&node);
}

static size_t node_ht_hasher(const void *d, size_t n)
{
	const struct hasher_node_s *v = d;
	return v->nid % n;
}

static bool node_ht_comparator(const void *d1, const void *d2)
{
	const struct hasher_node_s *v1 = d1;
	const struct hasher_node_s *v2 = d2;

	return v1->nid == v2->nid;
}

static size_t str_ht_hash(const void *entry, size_t table_size)
{
	return hash_string(entry, table_size);
}

static bool str_ht_eq(const void *entry1, const void *entry2)
{
	return strcmp(entry1, entry2) == 0;
}

struct lcfs_node_s *
lcfs_load_node_from_image_ext(const uint8_t *image_data, size_t image_data_size,
			      const struct lcfs_read_options_s *opts)
{
	const uint8_t *image_data_end;
	struct lcfs_image_data data = { image_data, image_data_size };
	const struct lcfs_erofs_header_s *cfs_header;
	const struct erofs_super_block *erofs_super;
	uint64_t erofs_root_nid;
	struct lcfs_node_s *root;

	assert(opts);

	if (image_data_size < EROFS_BLKSIZ) {
		errno = EINVAL;
		return NULL;
	}

	/* Avoid wrapping */
	image_data_end = image_data + image_data_size;
	if (image_data_end < image_data) {
		errno = EINVAL;
		return NULL;
	}

	cfs_header = (struct lcfs_erofs_header_s *)(image_data);
	if (lcfs_u32_from_file(cfs_header->magic) != LCFS_EROFS_MAGIC) {
		errno = EINVAL; /* Wrong cfs magic */
		return NULL;
	}

	if (lcfs_u32_from_file(cfs_header->version) != LCFS_EROFS_VERSION) {
		errno = ENOTSUP; /* Wrong cfs version */
		return NULL;
	}

	erofs_super = (struct erofs_super_block *)(image_data + EROFS_SUPER_OFFSET);

	if (lcfs_u32_from_file(erofs_super->magic) != EROFS_SUPER_MAGIC_V1) {
		errno = EINVAL; /* Wrong erofs magic */
		return NULL;
	}

	data.erofs_metadata =
		image_data +
		lcfs_u32_from_file(erofs_super->meta_blkaddr) * EROFS_BLKSIZ;
	data.erofs_xattrdata =
		image_data +
		lcfs_u32_from_file(erofs_super->xattr_blkaddr) * EROFS_BLKSIZ;

	if (data.erofs_metadata >= image_data_end ||
	    data.erofs_xattrdata >= image_data_end) {
		errno = EINVAL;
		return NULL;
	}

	data.erofs_metadata_end = image_data_end;
	data.erofs_xattrdata_end = image_data_end;

	data.erofs_build_time = lcfs_u64_from_file(erofs_super->build_time);
	data.erofs_build_time_nsec =
		lcfs_u32_from_file(erofs_super->build_time_nsec);

	erofs_root_nid = lcfs_u16_from_file(erofs_super->root_nid);

	data.node_hash =
		hash_initialize(0, NULL, node_ht_hasher, node_ht_comparator, free);
	if (data.node_hash == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	Hash_table *toplevel_entries_hash = NULL;
	if (opts->toplevel_entries) {
		toplevel_entries_hash =
			hash_initialize(0, NULL, str_ht_hash, str_ht_eq, NULL);
		if (toplevel_entries_hash == NULL) {
			errno = ENOMEM;
			return NULL;
		}
		for (const char *const *it = opts->toplevel_entries; it && *it; it++) {
			const char *name = *it;
			if (hash_insert_if_absent(toplevel_entries_hash, name,
						  NULL) < 0) {
				errno = ENOMEM;
				return NULL;
			}
		}
	}

	root = lcfs_build_node_from_image(&data, erofs_root_nid,
					  toplevel_entries_hash);

	if (toplevel_entries_hash != NULL)
		hash_free(toplevel_entries_hash);
	hash_free(data.node_hash);

	return root;
}

struct lcfs_node_s *lcfs_load_node_from_image(const uint8_t *image_data,
					      size_t image_data_size)
{
	struct lcfs_read_options_s opts = {
		0,
	};
	return lcfs_load_node_from_image_ext(image_data, image_data_size, &opts);
}