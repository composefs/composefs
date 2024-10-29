/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

   SPDX-License-Identifier: GPL-2.0-or-later OR Apache-2.0
*/
#ifndef _LCFS_INTERNAL_H
#define _LCFS_INTERNAL_H

#ifdef HAVE_MACHINE_ENDIAN_H
#include <machine/endian.h>
#endif

#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif

#include "lcfs-writer.h"
#include "lcfs-fsverity.h"
#include "hash.h"

/* This is used for (internal) functions that return zero or -errno, functions that set errno return int */
typedef int errint_t;

// Should match sizeof(struct erofs_xattr_ibody_header)
#define LCFS_XATTR_HEADER_SIZE 12

/* What may be returned by the kernel for digests */
#define MAX_DIGEST_SIZE 64
/* We picked this default block size */
#define FSVERITY_BLOCK_SIZE 4096

#define OVERLAY_XATTR_USER_PREFIX "user."
#define OVERLAY_XATTR_TRUSTED_PREFIX "trusted."
#define OVERLAY_XATTR_PARTIAL_PREFIX "overlay."
#define OVERLAY_XATTR_PREFIX                                                   \
	OVERLAY_XATTR_TRUSTED_PREFIX OVERLAY_XATTR_PARTIAL_PREFIX
#define OVERLAY_XATTR_USERXATTR_PREFIX                                         \
	OVERLAY_XATTR_USER_PREFIX OVERLAY_XATTR_PARTIAL_PREFIX
#define OVERLAY_XATTR_ESCAPE_PREFIX OVERLAY_XATTR_PREFIX "overlay."
#define OVERLAY_XATTR_METACOPY OVERLAY_XATTR_PREFIX "metacopy"
#define OVERLAY_XATTR_REDIRECT OVERLAY_XATTR_PREFIX "redirect"
#define OVERLAY_XATTR_WHITEOUT OVERLAY_XATTR_PREFIX "whiteout"
#define OVERLAY_XATTR_WHITEOUTS OVERLAY_XATTR_PREFIX "whiteouts"
#define OVERLAY_XATTR_OPAQUE OVERLAY_XATTR_PREFIX "opaque"

#define OVERLAY_XATTR_ESCAPED_WHITEOUT OVERLAY_XATTR_ESCAPE_PREFIX "whiteout"
#define OVERLAY_XATTR_ESCAPED_WHITEOUTS OVERLAY_XATTR_ESCAPE_PREFIX "whiteouts"
#define OVERLAY_XATTR_ESCAPED_OPAQUE OVERLAY_XATTR_ESCAPE_PREFIX "opaque"

#define OVERLAY_XATTR_USERXATTR_WHITEOUT                                       \
	OVERLAY_XATTR_USERXATTR_PREFIX "whiteout"
#define OVERLAY_XATTR_USERXATTR_WHITEOUTS                                      \
	OVERLAY_XATTR_USERXATTR_PREFIX "whiteouts"
#define OVERLAY_XATTR_USERXATTR_OPAQUE OVERLAY_XATTR_USERXATTR_PREFIX "opaque"

#define ALIGN_TO(_offset, _align_size)                                         \
	(((_offset) + _align_size - 1) & ~(_align_size - 1))

#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define LCFS_MAX_NAME_LENGTH 255 /* max len of file name excluding NULL */

/* Alias macros for the generic conversions; we can drop these at some point */
#define lcfs_u16_to_file(v) (htole16(v))
#define lcfs_u32_to_file(v) (htole32(v))
#define lcfs_u64_to_file(v) (htole64(v))
#define lcfs_u16_from_file(v) (le16toh(v))
#define lcfs_u32_from_file(v) (le32toh(v))
#define lcfs_u64_from_file(v) (le64toh(v))

/* In memory representation used to build the file.  */

struct lcfs_xattr_s {
	char *key;
	char *value;
	uint16_t value_len;

	/* Used during writing */
	int64_t erofs_shared_xattr_offset; /* shared offset, or -1 if not shared */
};

struct lcfs_inode_s {
	uint32_t st_mode; /* File type and mode.  */
	uint32_t st_nlink; /* Number of hard links, only for regular files.  */
	uint32_t st_uid; /* User ID of owner.  */
	uint32_t st_gid; /* Group ID of owner.  */
	uint32_t st_rdev; /* Device ID (if special file).  */
	uint64_t st_size; /* Size of file, only used for regular files */
	int64_t st_mtim_sec;
	uint32_t st_mtim_nsec;
};

struct lcfs_node_s {
	int ref_count;

	struct lcfs_node_s *parent;

	struct lcfs_node_s **children; /* Owns refs */
	size_t children_capacity;
	size_t children_size;

	/* Used to create hard links.  */
	struct lcfs_node_s *link_to; /* Owns refs */
	bool link_to_invalid; /* We detected a cycle */

	char *name;
	char *payload; /* backing file or symlink target */

	uint8_t *content;

	struct lcfs_xattr_s *xattrs;
	size_t n_xattrs;
	/* Must not exceeded UINT16_max; the max size here is determined
	 * by sizeof(erofs_xattr_ibody_header) + n_xattrs * sizeof(erofs_xattr_entry).
	 */
	size_t xattr_size;

	bool digest_set;
	uint8_t digest[LCFS_DIGEST_SIZE]; /* sha256 fs-verity digest */

	struct lcfs_inode_s inode;

	/* Used during compute_tree */
	struct lcfs_node_s *next; /* Use for the queue in compute_tree */
	bool in_tree;
	uint32_t inode_num;

	/* These fields are set by compute_erofs_inodes */
	bool erofs_compact;
	uint32_t erofs_ipad; /* padding before inode data */
	uint32_t erofs_xattr_size;
	uint32_t erofs_isize;
	uint64_t erofs_nid;
	uint32_t erofs_n_blocks;
	uint32_t erofs_tailsize;
};

struct lcfs_ctx_s {
	struct lcfs_write_options_s *options;
	struct lcfs_node_s *root;
	bool destroy_root;

	/* Used by compute_tree.  */
	struct lcfs_node_s *queue_end;
	uint64_t num_inodes;
	int64_t min_mtim_sec;
	uint32_t min_mtim_nsec;
	bool has_acl;

	void *file;
	lcfs_write_cb write_cb;
	off_t bytes_written;
	FsVerityContext *fsverity_ctx;

	void (*finalize)(struct lcfs_ctx_s *ctx);
};

static inline void lcfs_node_unrefp(struct lcfs_node_s **nodep)
{
	if (*nodep != NULL) {
		lcfs_node_unref(*nodep);
		*nodep = NULL;
	}
}
#define cleanup_node __attribute__((cleanup(lcfs_node_unrefp)))

/* lcfs-writer.c */
size_t hash_memory(const char *string, size_t len, size_t n_buckets);
int lcfs_write(struct lcfs_ctx_s *ctx, void *_data, size_t data_len);
int lcfs_write_align(struct lcfs_ctx_s *ctx, size_t align_size);
int lcfs_write_pad(struct lcfs_ctx_s *ctx, size_t data_len);
int lcfs_compute_tree(struct lcfs_ctx_s *ctx, struct lcfs_node_s *root);
int lcfs_clone_root(struct lcfs_ctx_s *ctx);
char *maybe_join_path(const char *a, const char *b);
int follow_links(struct lcfs_node_s *node, struct lcfs_node_s **out_node);
int node_get_dtype(struct lcfs_node_s *node);

int lcfs_node_rename_xattr(struct lcfs_node_s *node, size_t index,
			   const char *new_name);
int lcfs_node_set_xattr_internal(struct lcfs_node_s *node, const char *name,
				 const char *value, size_t value_len,
				 bool from_external_input);

int lcfs_validate_mode(mode_t mode);
int lcfs_node_validate(struct lcfs_node_s *node);

/* lcfs-writer-erofs.c */

int lcfs_write_erofs_to(struct lcfs_ctx_s *ctx);
struct lcfs_ctx_s *lcfs_ctx_erofs_new(void);

/* lcfs-writer-cfs.c */

int lcfs_write_cfs_to(struct lcfs_ctx_s *ctx);
struct lcfs_ctx_s *lcfs_ctx_cfs_new(void);

#endif
