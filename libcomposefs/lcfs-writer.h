/* lcfs
   Copyright (C) 2021 Giuseppe Scrivano <giuseppe@scrivano.org>

   SPDX-License-Identifier: GPL-2.0-or-later OR Apache-2.0
*/
#ifndef _LCFS_OPS_H
#define _LCFS_OPS_H

#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef LCFS_EXTERN
#define LCFS_EXTERN extern
#endif

#define LCFS_DIGEST_SIZE 32

enum {
	LCFS_BUILD_SKIP_XATTRS = (1 << 0),
	LCFS_BUILD_USE_EPOCH = (1 << 1),
	LCFS_BUILD_SKIP_DEVICES = (1 << 2),
	LCFS_BUILD_COMPUTE_DIGEST = (1 << 3), /* Store expected fs-verity digest */
	LCFS_BUILD_NO_INLINE = (1 << 4),
	LCFS_BUILD_USER_XATTRS = (1 << 5), /* Only read user.* xattrs */
	LCFS_BUILD_BY_DIGEST = (1 << 6), /* Refer to basedir files by fs-verity digest */
};

enum lcfs_format_t {
	LCFS_FORMAT_EROFS,
};

enum lcfs_flags_t {
	LCFS_FLAGS_NONE = 0,
	LCFS_FLAGS_MASK = 0,
};

#define LCFS_VERSION_MAX 2
/* Version history:
 * 0 - Initial version
 * 1 - Mark xwhitouts using the opaque=x format (1.0.3)
 * 2 - https://github.com/containers/composefs/issues/198
 */

/* Default value used by tooling, update with care */
#define LCFS_DEFAULT_VERSION_MIN 0
#define LCFS_DEFAULT_VERSION_MAX 1

// The extra space required for metadata per xattr.
// Should match sizeof(struct erofs_xattr_entry)
#define LCFS_INODE_XATTRMETA_SIZE 4
// Maximum size of key+value data (excluding trailing NUL for key)
// that can be allocated to an individual inode from external input.
// The EROFS limits this to basically UINT16_MAX -
// space for our internal xattrs. Out of conservatism we reserve
// fully half the xattr storage.
//
#define LCFS_INODE_EXTERNAL_XATTR_MAX (UINT16_MAX / 2)

// The maximum size in bytes of file content which can be inlined
// into a composefs. It's generally recommended to stay far below
// this - use LCFS_RECOMMENDED_INLINE_CONTENT_MAX.
#define LCFS_INLINE_CONTENT_MAX 5000
// The maximum recommended size for content to be inlined;
// We pick 64 which is the size of a sha256 digest that would otherwise be used as a redirect
// xattr, so the inlined file is smaller.
#define LCFS_RECOMMENDED_INLINE_CONTENT_MAX 64

typedef ssize_t (*lcfs_read_cb)(void *file, void *buf, size_t count);
typedef ssize_t (*lcfs_write_cb)(void *file, void *buf, size_t count);

struct lcfs_write_options_s {
	uint32_t format;
	uint32_t version;
	uint32_t flags;
	uint8_t *digest_out;
	void *file;
	lcfs_write_cb file_write_cb;
	uint32_t max_version;
	uint32_t reserved[3];
	void *reserved2[4];
};

LCFS_EXTERN struct lcfs_node_s *lcfs_node_new(void);
LCFS_EXTERN struct lcfs_node_s *lcfs_node_ref(struct lcfs_node_s *node);
LCFS_EXTERN void lcfs_node_unref(struct lcfs_node_s *node);
LCFS_EXTERN struct lcfs_node_s *lcfs_node_clone(struct lcfs_node_s *node);
LCFS_EXTERN struct lcfs_node_s *lcfs_node_clone_deep(struct lcfs_node_s *node);
LCFS_EXTERN struct lcfs_node_s *lcfs_load_node_from_file(int dirfd, const char *fname,
							 int buildflags);
LCFS_EXTERN struct lcfs_node_s *lcfs_load_node_from_image(const uint8_t *image_data,
							  size_t image_data_size);
struct lcfs_read_options_s {
	// If non-NULL, this is a NULL terminated array of filenames; only entries
	// for these files will be loaded. At the current time only filenames (not full paths)
	// are supported.
	const char *const *toplevel_entries;
	uint32_t reserved[3];
	void *reserved2[4];
};
LCFS_EXTERN struct lcfs_node_s *
lcfs_load_node_from_image_ext(const uint8_t *image_data, size_t image_data_size,
			      const struct lcfs_read_options_s *opts);
LCFS_EXTERN struct lcfs_node_s *lcfs_load_node_from_fd(int fd);
LCFS_EXTERN struct lcfs_node_s *
lcfs_load_node_from_fd_ext(int fd, const struct lcfs_read_options_s *opts);
LCFS_EXTERN int lcfs_version_from_fd(int fd);

LCFS_EXTERN const char *lcfs_node_get_xattr(struct lcfs_node_s *node,
					    const char *name, size_t *length);
LCFS_EXTERN int lcfs_node_set_xattr(struct lcfs_node_s *node, const char *name,
				    const char *value, size_t value_len);
LCFS_EXTERN int lcfs_node_unset_xattr(struct lcfs_node_s *node, const char *name);
LCFS_EXTERN size_t lcfs_node_get_n_xattr(struct lcfs_node_s *node);
LCFS_EXTERN const char *lcfs_node_get_xattr_name(struct lcfs_node_s *node,
						 size_t index);

LCFS_EXTERN int lcfs_node_set_payload(struct lcfs_node_s *node, const char *payload);
LCFS_EXTERN int lcfs_node_set_symlink_payload(struct lcfs_node_s *node,
					      const char *payload);
LCFS_EXTERN const char *lcfs_node_get_payload(struct lcfs_node_s *node);

LCFS_EXTERN int lcfs_node_set_content(struct lcfs_node_s *node,
				      const uint8_t *data, size_t data_size);
LCFS_EXTERN const uint8_t *lcfs_node_get_content(struct lcfs_node_s *node);

LCFS_EXTERN struct lcfs_node_s *lcfs_node_lookup_child(struct lcfs_node_s *node,
						       const char *name);
LCFS_EXTERN struct lcfs_node_s *lcfs_node_get_parent(struct lcfs_node_s *node);
LCFS_EXTERN int lcfs_node_add_child(struct lcfs_node_s *parent,
				    struct lcfs_node_s *child, /* Takes ownership on success */
				    const char *name);
LCFS_EXTERN const char *lcfs_node_get_name(struct lcfs_node_s *node);
LCFS_EXTERN size_t lcfs_node_get_n_children(struct lcfs_node_s *node);
LCFS_EXTERN struct lcfs_node_s *lcfs_node_get_child(struct lcfs_node_s *node,
						    size_t i);
LCFS_EXTERN void lcfs_node_make_hardlink(struct lcfs_node_s *node,
					 struct lcfs_node_s *target);
LCFS_EXTERN struct lcfs_node_s *lcfs_node_get_hardlink_target(struct lcfs_node_s *node);

LCFS_EXTERN bool lcfs_node_dirp(struct lcfs_node_s *node);
LCFS_EXTERN uint32_t lcfs_node_get_mode(struct lcfs_node_s *node);
LCFS_EXTERN void lcfs_node_set_mode(struct lcfs_node_s *node, uint32_t mode);
LCFS_EXTERN int lcfs_node_try_set_mode(struct lcfs_node_s *node, uint32_t mode);
LCFS_EXTERN uint32_t lcfs_node_get_uid(struct lcfs_node_s *node);
LCFS_EXTERN void lcfs_node_set_uid(struct lcfs_node_s *node, uint32_t uid);
LCFS_EXTERN uint32_t lcfs_node_get_gid(struct lcfs_node_s *node);
LCFS_EXTERN void lcfs_node_set_gid(struct lcfs_node_s *node, uint32_t gid);
LCFS_EXTERN uint32_t lcfs_node_get_rdev(struct lcfs_node_s *node)
	__attribute__((deprecated));
LCFS_EXTERN uint64_t lcfs_node_get_rdev64(struct lcfs_node_s *node);
LCFS_EXTERN void lcfs_node_set_rdev(struct lcfs_node_s *node, uint32_t rdev)
	__attribute__((deprecated));
LCFS_EXTERN void lcfs_node_set_rdev64(struct lcfs_node_s *node, uint64_t rdev);
LCFS_EXTERN uint32_t lcfs_node_get_nlink(struct lcfs_node_s *node);
LCFS_EXTERN void lcfs_node_set_nlink(struct lcfs_node_s *node, uint32_t nlink);
LCFS_EXTERN uint64_t lcfs_node_get_size(struct lcfs_node_s *node);
LCFS_EXTERN void lcfs_node_set_size(struct lcfs_node_s *node, uint64_t size);
LCFS_EXTERN void lcfs_node_set_mtime(struct lcfs_node_s *node, struct timespec *time);
LCFS_EXTERN void lcfs_node_get_mtime(struct lcfs_node_s *node, struct timespec *time);

LCFS_EXTERN const uint8_t *lcfs_node_get_fsverity_digest(struct lcfs_node_s *node);
LCFS_EXTERN void lcfs_node_set_fsverity_digest(struct lcfs_node_s *node,
					       uint8_t digest[LCFS_DIGEST_SIZE]);

LCFS_EXTERN int lcfs_node_set_fsverity_from_content(struct lcfs_node_s *node,
						    void *file,
						    lcfs_read_cb read_cb);

LCFS_EXTERN int lcfs_node_set_fsverity_from_fd(struct lcfs_node_s *node, int fd);

LCFS_EXTERN struct lcfs_node_s *lcfs_build(int dirfd, const char *fname,
					   int buildflags, char **failed_path_out);

LCFS_EXTERN int lcfs_write_to(struct lcfs_node_s *root,
			      struct lcfs_write_options_s *options);

/* fsverity helpers */
LCFS_EXTERN int lcfs_compute_fsverity_from_content(uint8_t *digest, void *file,
						   lcfs_read_cb read_cb);
LCFS_EXTERN int lcfs_compute_fsverity_from_fd(uint8_t *digest, int fd);
LCFS_EXTERN int lcfs_compute_fsverity_from_data(uint8_t *digest, uint8_t *data,
						size_t data_len);
LCFS_EXTERN int lcfs_fd_measure_fsverity(uint8_t *digest, int fd);
LCFS_EXTERN int lcfs_fd_get_fsverity(uint8_t *digest, int fd);

LCFS_EXTERN int lcfs_node_set_from_content(struct lcfs_node_s *node, int dirfd,
					   const char *fname, int buildflags);
LCFS_EXTERN int lcfs_fd_enable_fsverity(int fd);

#endif
