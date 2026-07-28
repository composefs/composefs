/* SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0 */
#define _GNU_SOURCE

#include "lcfs-writer.h"
#include "lcfs-mount.h"
#include "lcfs-erofs.h"
#include "erofs_fs_wrapper.h"
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <stdlib.h>
#include <limits.h>

static inline void lcfs_node_unrefp(struct lcfs_node_s **nodep)
{
	if (*nodep != NULL) {
		lcfs_node_unref(*nodep);
		*nodep = NULL;
	}
}
#define cleanup_node __attribute__((cleanup(lcfs_node_unrefp)))

static ssize_t write_cb(void *_file, void *buf, size_t count)
{
	FILE *file = _file;

	return fwrite(buf, 1, count, file);
}

static int testwrite_node(struct lcfs_node_s *node)
{
	char *bufp = NULL;
	size_t bufsz = 0;
	FILE *buf = open_memstream(&bufp, &bufsz);

	struct lcfs_write_options_s options = { 0 };
	options.format = LCFS_FORMAT_EROFS;
	options.version = 1;
	options.max_version = 1;
	options.file = buf;
	options.file_write_cb = write_cb;

	int r = lcfs_write_to(node, &options);
	int saved_errno = errno;
	fclose(buf);
	free(bufp);
	errno = saved_errno;
	return r;
}

static void test_basic(void)
{
	cleanup_node struct lcfs_node_s *node = lcfs_node_new();
	lcfs_node_set_mode(node, S_IFDIR | 0755);
	cleanup_node struct lcfs_node_s *child = lcfs_node_new();
	lcfs_node_set_mode(child, S_IFDIR | 0700);
	int r = lcfs_node_add_child(node, child, "somechild");
	assert(r == 0);
	// Adding child took ownership
	child = NULL;
	r = testwrite_node(node);
	assert(r == 0);
}

static void test_xattr_addremove(void)
{
	cleanup_node struct lcfs_node_s *node = lcfs_node_new();
	lcfs_node_set_mode(node, S_IFDIR | 0755);
	cleanup_node struct lcfs_node_s *child = lcfs_node_new();
	lcfs_node_set_mode(child, S_IFDIR | 0700);
	int r = lcfs_node_unset_xattr(child, "user.foo");
	int errsv = errno;
	assert(r == -1);
	assert(errsv == ENODATA);
	r = lcfs_node_set_xattr(child, "user.foo", "bar", 3);
	assert(r == 0);
	r = lcfs_node_unset_xattr(child, "user.foo");
	assert(r == 0);
	r = lcfs_node_add_child(node, child, "somechild");
	assert(r == 0);
	child = NULL;
}

// Test that calling lcfs_node_set_xattr multiple times
// with the same key has last-one-wins semantics.
static void test_xattr_doubleadd(void)
{
	cleanup_node struct lcfs_node_s *node = lcfs_node_new();
	lcfs_node_set_mode(node, S_IFDIR | 0755);
	cleanup_node struct lcfs_node_s *child = lcfs_node_new();
	lcfs_node_set_mode(child, S_IFDIR | 0700);
	int r = lcfs_node_set_xattr(child, "user.foo", "bar", 3);
	assert(r == 0);
	// Should successfully silently overwrite.
	r = lcfs_node_set_xattr(child, "user.foo", "baz", 3);
	assert(r == 0);

	size_t found_len;
	const char *found_value = lcfs_node_get_xattr(child, "user.foo", &found_len);
	assert(found_value);
	assert(found_len == 3);
	assert(memcmp(found_value, "baz", found_len) == 0);
	r = lcfs_node_add_child(node, child, "somechild");
	assert(r == 0);
	child = NULL;
}

static void test_add_uninitialized_child(void)
{
	cleanup_node struct lcfs_node_s *node = lcfs_node_new();
	lcfs_node_set_mode(node, S_IFDIR | 0755);
	// libostree today does this pattern of creating an empty (uninitialized)
	// child and passing it to lcfs_node_add_child first. Verify this
	// continues to work for the forseeable future.
	cleanup_node struct lcfs_node_s *child = lcfs_node_new();
	int r = lcfs_node_add_child(node, child, "somechild");
	assert(r == 0);
	// Adding child took ownership
	child = NULL;

	// But we should fail to write an EROFS with this
	r = testwrite_node(node);
	assert(r == -1);
	assert(errno == EINVAL);
}

/* Regression test for heap-use-after-free when loading an EROFS image that
 * contains a hardlinked whiteout (chardev with rdev=0, nlink>1).
 *
 * A whiteout represents the absence of a file, so nlink>1 is semantically
 * invalid.  The loader must reject such images with EINVAL rather than
 * silently processing them (which previously caused a use-after-free via a
 * stale node_hash entry when the alias dirent appeared before the canonical
 * one in the directory block).
 *
 * We construct a minimal EROFS image in memory rather than loading a binary
 * fixture, so the test is self-contained.
 */
static void test_hardlinked_whiteout_load(void)
{
	/*
	 * Image layout (2 blocks = 8192 bytes, all in block 0's metadata area):
	 *
	 *   0x000  lcfs_erofs_header_s        (composefs header, 32 bytes)
	 *   0x400  erofs_super_block           (EROFS superblock, 128 bytes)
	 *   0x480  erofs_inode_compact          root dir, nid=36, 32 bytes
	 *   0x4A0  inline dir data             3 dirents + names, 41 bytes
	 *   0x4E0  erofs_inode_compact          whiteout, nid=39, 32 bytes
	 */
	uint8_t image[2 * EROFS_BLKSIZ];
	memset(image, 0, sizeof(image));

	/* Composefs header at offset 0 */
	struct lcfs_erofs_header_s *cfs = (struct lcfs_erofs_header_s *)image;
	cfs->magic = htole32(LCFS_EROFS_MAGIC);
	cfs->version = htole32(LCFS_EROFS_VERSION);

	/* EROFS superblock at offset 1024 */
	struct erofs_super_block *sb =
		(struct erofs_super_block *)(image + EROFS_SUPER_OFFSET);
	sb->magic = htole32(EROFS_SUPER_MAGIC_V1);
	sb->blkszbits = EROFS_BLKSIZ_BITS;
	sb->root_nid = htole16(36); /* nid=36 → offset 36*32 = 0x480 */
	sb->inos = htole64(2);
	sb->blocks = htole32(2);
	sb->meta_blkaddr = htole32(0);
	sb->xattr_blkaddr = htole32(0);

	/* Root directory inode (compact, 32 bytes) at offset 0x480, nid=36.
	 * Data layout = FLAT_INLINE (tailpacked dir entries follow the inode). */
	const uint16_t root_nid = 36;
	const uint16_t wh_nid = 39; /* offset 39*32 = 0x4E0 */
	struct erofs_inode_compact *root_ino =
		(struct erofs_inode_compact *)(image + root_nid * EROFS_SLOTSIZE);
	root_ino->i_format =
		htole16((EROFS_INODE_FLAT_INLINE << EROFS_I_DATALAYOUT_BIT) |
			(EROFS_INODE_LAYOUT_COMPACT << EROFS_I_VERSION_BIT));
	root_ino->i_mode = htole16(S_IFDIR | 0755);
	root_ino->i_nlink = htole16(2);

	/* Build inline directory data right after the root inode (offset 0x4A0).
	 * 3 entries: "." (self), ".." (parent), "wh" (whiteout child).
	 * Each dirent is 12 bytes; names start at offset 3*12 = 36. */
	uint8_t *dir = image + root_nid * EROFS_SLOTSIZE +
		       sizeof(struct erofs_inode_compact);
	const uint16_t names_off = 3 * sizeof(struct erofs_dirent); /* 36 */
	/* "." at offset 36, ".." at 37, "wh" at 39 → total = 41 bytes */
	const uint32_t dir_size = names_off + 1 + 2 + 2; /* 41 */
	root_ino->i_size = htole32(dir_size);

	struct erofs_dirent *de = (struct erofs_dirent *)dir;
	/* dirent[0]: "." */
	de[0].nid = htole64(root_nid);
	de[0].nameoff = htole16(names_off);
	de[0].file_type = EROFS_FT_DIR;
	/* dirent[1]: ".." */
	de[1].nid = htole64(root_nid);
	de[1].nameoff = htole16(names_off + 1);
	de[1].file_type = EROFS_FT_DIR;
	/* dirent[2]: "wh" */
	de[2].nid = htole64(wh_nid);
	de[2].nameoff = htole16(names_off + 3);
	de[2].file_type = EROFS_FT_CHRDEV;

	memcpy(dir + names_off, ".", 1);
	memcpy(dir + names_off + 1, "..", 2);
	memcpy(dir + names_off + 3, "wh", 2);

	/* Whiteout inode (compact, 32 bytes) at offset 0x4E0, nid=39.
	 * chardev with rdev=0 and nlink=252 (>1 triggers EINVAL). */
	struct erofs_inode_compact *wh_ino =
		(struct erofs_inode_compact *)(image + wh_nid * EROFS_SLOTSIZE);
	wh_ino->i_format =
		htole16((EROFS_INODE_FLAT_PLAIN << EROFS_I_DATALAYOUT_BIT) |
			(EROFS_INODE_LAYOUT_COMPACT << EROFS_I_VERSION_BIT));
	wh_ino->i_mode = htole16(S_IFCHR);
	wh_ino->i_nlink = htole16(252);
	wh_ino->i_u.rdev = htole32(0); /* rdev=0 makes it a whiteout */

	/* The loader must reject this image with EINVAL (hardlinked whiteout)
	 * and must not crash (the original bug was a use-after-free). */
	cleanup_node struct lcfs_node_s *root =
		lcfs_load_node_from_image(image, sizeof(image));
	int errsv = errno;
	assert(root == NULL);
	assert(errsv == EINVAL);
}

static void create_regular_file(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	assert(fd >= 0);
	assert(write(fd, "hello", 5) == 5);
	close(fd);
}

static void create_symlink(const char *path)
{
	assert(symlink("target-does-not-need-to-exist", path) == 0);
}

// Verifies that lcfs_build() only detects hardlinked files of a given type
// when scanning a directory tree if LCFS_BUILD_TRACK_HARDLINKS is passed; by
// default (matching historical behavior) every path gets its own
// independent inode with nlink == 1. Parameterized over the node type being
// hardlinked, since any non-directory type (regular files, symlinks, FIFOs,
// device nodes, sockets) can be hardlinked, not just regular files.
static void test_build_hardlinks_for(void (*create)(const char *path))
{
	char tmpdir[] = "/tmp/test-build-hardlinks.XXXXXX";
	assert(mkdtemp(tmpdir) != NULL);

	char path1[PATH_MAX], path2[PATH_MAX];
	snprintf(path1, sizeof(path1), "%s/file1", tmpdir);
	snprintf(path2, sizeof(path2), "%s/file2", tmpdir);

	create(path1);

	assert(link(path1, path2) == 0);

	int dirfd = open(tmpdir, O_RDONLY | O_DIRECTORY);
	assert(dirfd >= 0);

	/* Without LCFS_BUILD_TRACK_HARDLINKS: today's default behavior is
	 * that every path becomes an independent inode with nlink == 1. */
	{
		char *failed_path = NULL;
		cleanup_node struct lcfs_node_s *root =
			lcfs_build(dirfd, ".", 0, &failed_path);
		assert(root != NULL);

		struct lcfs_node_s *n1 = lcfs_node_lookup_child(root, "file1");
		struct lcfs_node_s *n2 = lcfs_node_lookup_child(root, "file2");
		assert(n1 != NULL);
		assert(n2 != NULL);
		assert(lcfs_node_get_hardlink_target(n1) == NULL);
		assert(lcfs_node_get_hardlink_target(n2) == NULL);
		assert(lcfs_node_get_nlink(n1) == 1);
		assert(lcfs_node_get_nlink(n2) == 1);

		assert(testwrite_node(root) == 0);
	}

	/* With LCFS_BUILD_TRACK_HARDLINKS: one of the two paths becomes a
	 * hardlink to the other, and the target's nlink is bumped to 2. */
	{
		char *failed_path = NULL;
		cleanup_node struct lcfs_node_s *root = lcfs_build(
			dirfd, ".", LCFS_BUILD_TRACK_HARDLINKS, &failed_path);
		assert(root != NULL);

		struct lcfs_node_s *n1 = lcfs_node_lookup_child(root, "file1");
		struct lcfs_node_s *n2 = lcfs_node_lookup_child(root, "file2");
		assert(n1 != NULL);
		assert(n2 != NULL);

		/* Whichever of the two is visited first by readdir() becomes
		 * the canonical inode; the other becomes a hardlink to it. */
		struct lcfs_node_s *target1 = lcfs_node_get_hardlink_target(n1);
		struct lcfs_node_s *target2 = lcfs_node_get_hardlink_target(n2);
		assert((target1 == NULL) != (target2 == NULL));

		struct lcfs_node_s *link_node = target1 != NULL ? n1 : n2;
		struct lcfs_node_s *target_node = target1 != NULL ? n2 : n1;
		assert(lcfs_node_get_hardlink_target(link_node) == target_node);
		assert(lcfs_node_get_nlink(target_node) == 2);

		assert(testwrite_node(root) == 0);
	}

	close(dirfd);
	unlink(path1);
	unlink(path2);
	rmdir(tmpdir);
}

// A chardev with rdev=0 is how composefs represents an overlayfs whiteout;
// nlink>1 on one is semantically invalid (a whiteout marks the absence of a
// file) and rejected outright by the EROFS writer. Verify that
// LCFS_BUILD_TRACK_HARDLINKS deliberately leaves such inodes untracked, so
// two hardlinked rdev=0 chardevs on disk still build (each as its own
// independent inode) instead of failing.
static void test_build_hardlinks_whiteout_exception(void)
{
	char tmpdir[] = "/tmp/test-build-hardlinks.XXXXXX";
	assert(mkdtemp(tmpdir) != NULL);

	char path1[PATH_MAX], path2[PATH_MAX];
	snprintf(path1, sizeof(path1), "%s/wh1", tmpdir);
	snprintf(path2, sizeof(path2), "%s/wh2", tmpdir);

	if (mknod(path1, S_IFCHR | 0644, makedev(0, 0)) < 0) {
		/* Creating device nodes may be disallowed in some sandboxed
		 * or unprivileged test environments; skip rather than fail. */
		assert(errno == EPERM || errno == EACCES);
		rmdir(tmpdir);
		return;
	}
	assert(link(path1, path2) == 0);

	int dirfd = open(tmpdir, O_RDONLY | O_DIRECTORY);
	assert(dirfd >= 0);

	char *failed_path = NULL;
	cleanup_node struct lcfs_node_s *root =
		lcfs_build(dirfd, ".", LCFS_BUILD_TRACK_HARDLINKS, &failed_path);
	assert(root != NULL);

	struct lcfs_node_s *n1 = lcfs_node_lookup_child(root, "wh1");
	struct lcfs_node_s *n2 = lcfs_node_lookup_child(root, "wh2");
	assert(n1 != NULL);
	assert(n2 != NULL);
	assert(lcfs_node_get_hardlink_target(n1) == NULL);
	assert(lcfs_node_get_hardlink_target(n2) == NULL);
	assert(lcfs_node_get_nlink(n1) == 1);
	assert(lcfs_node_get_nlink(n2) == 1);

	assert(testwrite_node(root) == 0);

	close(dirfd);
	unlink(path1);
	unlink(path2);
	rmdir(tmpdir);
}

static void test_build_hardlinks(void)
{
	test_build_hardlinks_for(create_regular_file);
	test_build_hardlinks_for(create_symlink);
	test_build_hardlinks_whiteout_exception();
}

// Verifies that lcfs_fd_measure_fsverity fails on a fd without fsverity
static void test_no_verity(void)
{
	char buf[] = "/tmp/test-verity.XXXXXX";
	int tmpfd = mkstemp(buf);
	assert(tmpfd > 0);

	uint8_t digest[LCFS_DIGEST_SIZE];
	int r = lcfs_fd_measure_fsverity(digest, tmpfd);
	int errsv = errno;
	assert(r != 0);
	// We may get ENOSYS from qemu userspace emulation not implementing the ioctl
	if (getenv("CFS_TEST_ARCH_EMULATION") == NULL)
		assert(errsv == ENOVERITY);
	close(tmpfd);
}

// Regression test for https://github.com/composefs/composefs/issues/442.
//
// A zero-length file has no Merkle tree blocks, so the root_hash field
// inside the fsverity_descriptor must be all-zero. The final digest
// below is *not* that root_hash: it's SHA256(descriptor), i.e. what
// lcfs_compute_fsverity_from_data() / `composefs-info measure-file`
// actually returns, and what the kernel reports via `fsverity measure`
// for a real empty file with fs-verity enabled.
static void test_fsverity_empty_file(void)
{
	static const uint8_t expected[LCFS_DIGEST_SIZE] = {
		0x3d, 0x24, 0x8c, 0xa5, 0x42, 0xa2, 0x4f, 0xc6,
		0x2d, 0x1c, 0x43, 0xb9, 0x16, 0xea, 0xe5, 0x01,
		0x68, 0x78, 0xe2, 0x53, 0x3c, 0x88, 0x23, 0x84,
		0x80, 0xb2, 0x61, 0x28, 0xa1, 0xf1, 0xaf, 0x95,
	};
	uint8_t digest[LCFS_DIGEST_SIZE];

	int r = lcfs_compute_fsverity_from_data(digest, NULL, 0);
	assert(r == 0);
	assert(memcmp(digest, expected, LCFS_DIGEST_SIZE) == 0);
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	test_basic();
	test_no_verity();
	test_add_uninitialized_child();
	test_xattr_addremove();
	test_xattr_doubleadd();
	test_hardlinked_whiteout_load();
	test_fsverity_empty_file();
	test_build_hardlinks();
}
