/* SPDX-License-Identifier: GPL-2.0-or-later OR Apache-2.0 */
#define _GNU_SOURCE

#define FUSE_USE_VERSION 34

#include "config.h"

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <linux/loop.h>
#include <linux/mount.h>
#include <linux/fsverity.h>
#include <fuse_lowlevel.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>

#include "libcomposefs/lcfs-erofs-internal.h"
#include "libcomposefs/lcfs-internal.h"
#include "libcomposefs/lcfs-utils.h"

/* TODO:
 *  Do we want to user ther negative_timeout=T option?
 */

#define CFS_ENTRY_TIMEOUT 3600.0
#define CFS_ATTR_TIMEOUT 3600.0

const uint8_t *erofs_data;
size_t erofs_data_size;
uint64_t erofs_root_nid;
bool erofs_use_acl;
const struct erofs_super_block *erofs_super;
const struct lcfs_erofs_header_s *cfs_header;
const uint8_t *erofs_metadata;
const uint8_t *erofs_xattrdata;
uint64_t erofs_build_time;
uint32_t erofs_build_time_nsec;
int basedir_fd;

struct cfs_data {
	char *source;
	char *basedir;
	bool noacl;
};

static const struct fuse_opt cfs_opts[] = {
	{ "source=%s", offsetof(struct cfs_data, source), 0 },
	{ "basedir=%s", offsetof(struct cfs_data, basedir), 0 },
	{ "noacl", offsetof(struct cfs_data, noacl), 1 },
	FUSE_OPT_END
};

static uint64_t cfs_nid_from_ino(fuse_ino_t ino)
{
	if (ino == FUSE_ROOT_ID) {
		return erofs_root_nid;
	}
	return ino;
}

static fuse_ino_t cfs_ino_from_nid(uint64_t nid)
{
	if (nid == erofs_root_nid) {
		return FUSE_ROOT_ID;
	}
	return nid;
}

static const erofs_inode *cfs_get_erofs_inode(fuse_ino_t ino)
{
	uint64_t nid = cfs_nid_from_ino(ino);

	/* TODO: Add bounds check */

	return (const erofs_inode *)(erofs_metadata + (nid << EROFS_ISLOTBITS));
}

static int erofs_inode_is_whiteout(const erofs_inode *cino)
{
	mode_t mode;
	dev_t rdev;
	if (erofs_inode_is_compact(cino)) {
		const struct erofs_inode_compact *c = &cino->compact;
		mode = lcfs_u16_from_file(c->i_mode);
		rdev = lcfs_u32_from_file(c->i_u.rdev);
	} else {
		const struct erofs_inode_extended *e = &cino->extended;
		mode = lcfs_u16_from_file(e->i_mode);
		rdev = lcfs_u32_from_file(e->i_u.rdev);
	}

	int type = mode & S_IFMT;
	return (type == S_IFCHR || type == S_IFBLK) && rdev == makedev(0, 0);
}

static int cfs_stat(fuse_ino_t ino, const erofs_inode *cino, struct stat *stbuf)
{
	stbuf->st_ino = ino;

	if (erofs_inode_is_compact(cino)) {
		const struct erofs_inode_compact *c = &cino->compact;

		stbuf->st_mode = lcfs_u16_from_file(c->i_mode);
		stbuf->st_nlink = lcfs_u16_from_file(c->i_nlink);
		stbuf->st_size = lcfs_u32_from_file(c->i_size);
		stbuf->st_uid = lcfs_u16_from_file(c->i_uid);
		stbuf->st_gid = lcfs_u16_from_file(c->i_gid);

		stbuf->st_mtim.tv_sec = erofs_build_time;
		stbuf->st_mtim.tv_nsec = erofs_build_time_nsec;

		int type = stbuf->st_mode & S_IFMT;
		if (type == S_IFCHR || type == S_IFBLK)
			stbuf->st_rdev = lcfs_u32_from_file(c->i_u.rdev);

	} else {
		const struct erofs_inode_extended *e = &cino->extended;

		stbuf->st_mode = lcfs_u16_from_file(e->i_mode);
		stbuf->st_size = lcfs_u64_from_file(e->i_size);
		stbuf->st_uid = lcfs_u32_from_file(e->i_uid);
		stbuf->st_gid = lcfs_u32_from_file(e->i_gid);
		stbuf->st_mtim.tv_sec = lcfs_u64_from_file(e->i_mtime);
		stbuf->st_mtim.tv_nsec = lcfs_u32_from_file(e->i_mtime_nsec);
		stbuf->st_nlink = lcfs_u32_from_file(e->i_nlink);

		int type = stbuf->st_mode & S_IFMT;
		if (type == S_IFCHR || type == S_IFBLK)
			stbuf->st_rdev = lcfs_u32_from_file(e->i_u.rdev);
	}

	stbuf->st_atim.tv_sec = stbuf->st_mtim.tv_sec;
	stbuf->st_atim.tv_nsec = stbuf->st_mtim.tv_nsec;
	stbuf->st_ctim.tv_sec = stbuf->st_mtim.tv_sec;
	stbuf->st_ctim.tv_nsec = stbuf->st_mtim.tv_nsec;

	return 0;
}

static void cfs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	const erofs_inode *cino = cfs_get_erofs_inode(ino);
	struct stat stbuf;

	(void)fi;

	memset(&stbuf, 0, sizeof(stbuf));
	if (cino == NULL || cfs_stat(ino, cino, &stbuf) == -1)
		fuse_reply_err(req, ENOENT);
	else
		fuse_reply_attr(req, &stbuf, CFS_ATTR_TIMEOUT);
}

static mode_t erofs_inode_get_mode(const erofs_inode *cino)
{
	if (erofs_inode_is_compact(cino)) {
		const struct erofs_inode_compact *c = &cino->compact;
		return lcfs_u16_from_file(c->i_mode);
	} else {
		const struct erofs_inode_extended *e = &cino->extended;
		return lcfs_u16_from_file(e->i_mode);
	}
}

static void erofs_inode_get_info(const erofs_inode *cino, uint32_t *mode,
				 uint64_t *file_size, uint16_t *xattr_icount,
				 uint32_t *raw_blkaddr, size_t *isize)
{
	if (erofs_inode_is_compact(cino)) {
		const struct erofs_inode_compact *c = &cino->compact;

		*mode = lcfs_u16_from_file(c->i_mode);
		*file_size = lcfs_u32_from_file(c->i_size);
		*xattr_icount = lcfs_u16_from_file(c->i_xattr_icount);
		*raw_blkaddr = lcfs_u32_from_file(c->i_u.raw_blkaddr);
		*isize = sizeof(struct erofs_inode_compact);
	} else {
		const struct erofs_inode_extended *e = &cino->extended;
		*mode = lcfs_u16_from_file(e->i_mode);
		*file_size = lcfs_u64_from_file(e->i_size);
		*xattr_icount = lcfs_u16_from_file(e->i_xattr_icount);
		*raw_blkaddr = lcfs_u32_from_file(e->i_u.raw_blkaddr);
		*isize = sizeof(struct erofs_inode_extended);
	}
}

/* This is essentially strcmp() for non-null-terminated strings */
static inline int memcmp2(const void *a, const size_t a_size, const void *b,
			  size_t b_size)
{
	size_t common_size = min(a_size, b_size);
	int res;

	res = memcmp(a, b, common_size);
	if (res != 0 || a_size == b_size)
		return res;

	return a_size < b_size ? -1 : 1;
}

static bool cfs_lookup_block(fuse_req_t req, const uint8_t *block,
			     size_t block_size, const char *name, int *cmp_out)
{
	const struct erofs_dirent *dirents = (struct erofs_dirent *)block;
	size_t n_dirents;
	size_t name_len = strlen(name);
	ssize_t start_dirent, end_dirent;
	int cmp = -1;

	n_dirents = lcfs_u16_from_file(dirents[0].nameoff) /
		    sizeof(struct erofs_dirent);

	start_dirent = 0;
	end_dirent = n_dirents - 1;
	while (start_dirent <= end_dirent) {
		ssize_t mid_dirent = start_dirent + (end_dirent - start_dirent) / 2;
		uint16_t nameoff = lcfs_u16_from_file(dirents[mid_dirent].nameoff);
		const char *child_name = (const char *)(block + nameoff);
		uint16_t child_name_len;

		if (mid_dirent + 1 < n_dirents)
			child_name_len =
				lcfs_u16_from_file(dirents[mid_dirent + 1].nameoff) -
				nameoff;
		else
			child_name_len = strnlen(child_name, block_size - nameoff);

		cmp = memcmp2(name, name_len, child_name, child_name_len);
		if (cmp == 0) {
			uint64_t nid = lcfs_u64_from_file(dirents[mid_dirent].nid);
			const erofs_inode *child_cino = cfs_get_erofs_inode(nid);
			struct fuse_entry_param e;

			if (erofs_inode_is_whiteout(child_cino)) {
				fuse_reply_err(req, ENOENT);
			} else {
				memset(&e, 0, sizeof(e));
				e.ino = cfs_ino_from_nid(nid);
				e.attr_timeout = CFS_ATTR_TIMEOUT;
				e.entry_timeout = CFS_ENTRY_TIMEOUT;
				cfs_stat(e.ino, child_cino, &e.attr);

				fuse_reply_entry(req, &e);
			}

			return true;
		} else {
			if (cmp > 0)
				start_dirent = mid_dirent + 1;
			else
				end_dirent = mid_dirent - 1;
		}
	}

	if (end_dirent < 0) {
		*cmp_out = -1;
	} else if (start_dirent >= n_dirents) {
		*cmp_out = 1;
	} else {
		*cmp_out = 0; /* inside the block */
	}

	return false;
}

static void cfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	const erofs_inode *parent_cino = cfs_get_erofs_inode(parent);
	uint32_t mode;
	uint64_t file_size;
	uint16_t xattr_icount;
	uint32_t raw_blkaddr;
	size_t xattr_size;
	size_t isize;
	uint64_t n_blocks;
	uint64_t last_oob_block;
	bool tailpacked;
	size_t tail_size;
	const uint8_t *tail_data;
	const uint8_t *oob_data;
	int start_block, end_block;

	if (parent_cino == NULL) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	erofs_inode_get_info(parent_cino, &mode, &file_size, &xattr_icount,
			     &raw_blkaddr, &isize);

	if ((mode & S_IFMT) != S_IFDIR) {
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	xattr_size = erofs_xattr_inode_size(xattr_icount);

	tailpacked = erofs_inode_is_tailpacked(parent_cino);
	tail_size = tailpacked ? file_size % EROFS_BLKSIZ : 0;
	tail_data = ((uint8_t *)parent_cino) + isize + xattr_size;
	n_blocks = round_up(file_size, EROFS_BLKSIZ) / EROFS_BLKSIZ;
	last_oob_block = tailpacked ? n_blocks - 1 : n_blocks;
	oob_data = erofs_data + raw_blkaddr * EROFS_BLKSIZ;

	/* First read the out-of-band blocks */
	start_block = 0;
	end_block = last_oob_block - 1;
	while (start_block <= end_block) {
		int mid_block = start_block + (end_block - start_block) / 2;
		const uint8_t *block_data = oob_data + mid_block * EROFS_BLKSIZ;
		size_t block_size = EROFS_BLKSIZ;
		int cmp;

		if (!tailpacked && mid_block + 1 == last_oob_block) {
			block_size = file_size % EROFS_BLKSIZ;
			if (block_size == 0) {
				block_size = EROFS_BLKSIZ;
			}
		}

		if (cfs_lookup_block(req, block_data, block_size, name, &cmp)) {
			return; /* Found a match */
		}

		if (cmp == 0)
			/* The name should have been in this block,
			   but wasn't */
			goto noent;
		else if (cmp > 0)
			start_block = mid_block + 1;
		else if (mid_block > 0)
			end_block = mid_block - 1;
	}

	if (tailpacked && start_block > end_block) {
		int cmp;
		if (cfs_lookup_block(req, tail_data, tail_size, name, &cmp))
			return;
	}

noent:
	fuse_reply_err(req, ENOENT);
}

static mode_t erofs_file_type_to_mode(int file_type)
{
	switch (file_type) {
	case EROFS_FT_SYMLINK:
		return S_IFLNK;
	case EROFS_FT_DIR:
		return S_IFDIR;
	case EROFS_FT_REG_FILE:
		return S_IFREG;
	case EROFS_FT_BLKDEV:
		return S_IFBLK;
	case EROFS_FT_CHRDEV:
		return S_IFCHR;
	case EROFS_FT_SOCK:
		return S_IFSOCK;
	case EROFS_FT_FIFO:
		return S_IFIFO;
	default:
		return 0;
	}
}

struct dirbuf {
	uint8_t *buf;
	size_t current_size;
	size_t max_size;

	off_t offset;
};

static bool cfs_readdir_block(fuse_req_t req, struct dirbuf *buf,
			      const uint8_t *block, size_t block_size,
			      size_t block_start, bool use_plus)
{
	const struct erofs_dirent *dirents = (struct erofs_dirent *)block;
	size_t dirents_size = lcfs_u16_from_file(dirents[0].nameoff);
	size_t n_dirents, i;
	size_t start_dirent;

	if (dirents_size % sizeof(struct erofs_dirent) != 0) {
		/* This should not happen for valid filesystems */
		return false;
	}

	assert(buf->offset >= block_start);

	n_dirents = dirents_size / sizeof(struct erofs_dirent);
	/* Round up to ensure we start looking at even dirent position, if the user passed some weird offset. */
	start_dirent =
		(buf->offset - block_start + sizeof(struct erofs_dirent) - 1) /
		sizeof(struct erofs_dirent);
	if (start_dirent >= n_dirents) {
		return false;
	}

	buf->offset = block_start + sizeof(struct erofs_dirent) * start_dirent;

	/* Check if it outside the dirents part */
	if (buf->offset - block_start >= dirents_size) {
		/* Move to next block */
		buf->offset = block_start + EROFS_BLKSIZ;
		return false;
	}

	for (i = start_dirent; i < n_dirents; i++) {
		char name_buf[PATH_MAX];
		uint64_t nid = lcfs_u64_from_file(dirents[i].nid);
		uint16_t nameoff = lcfs_u16_from_file(dirents[i].nameoff);
		const char *child_name;
		uint16_t child_name_len;
		struct stat stbuf;
		size_t res;
		size_t remaining_size;
		off_t next_offset;

		assert(buf->offset == block_start + i * sizeof(struct erofs_dirent));

		/* After last dirent, we go directly to next block */
		if (i < n_dirents - 1) {
			next_offset = buf->offset + sizeof(struct erofs_dirent);
		} else {
			next_offset = block_start + EROFS_BLKSIZ;
		}

		/* Compute length of the name, which is a bit weird for the last dirent */
		child_name = (char *)(block + nameoff);
		if (i + 1 < n_dirents)
			child_name_len =
				lcfs_u16_from_file(dirents[i + 1].nameoff) - nameoff;
		else
			child_name_len = strnlen(child_name, block_size - nameoff);

		/* We have to copy to be able to null terminate for fuse_add_direntry, lame */
		child_name_len = min(child_name_len, PATH_MAX - 1);
		memcpy(name_buf, child_name, child_name_len);
		name_buf[child_name_len] = 0;

		remaining_size = buf->max_size - buf->current_size;

		const erofs_inode *child_cino = cfs_get_erofs_inode(nid);
		uint8_t type = dirents[i].file_type;
		if (type == EROFS_FT_CHRDEV && erofs_inode_is_whiteout(child_cino)) {
			/* Filtered */
			res = 0;
		} else if (use_plus) {
			struct fuse_entry_param e;

			memset(&e, 0, sizeof(e));
			e.ino = cfs_ino_from_nid(nid);
			e.attr_timeout = CFS_ATTR_TIMEOUT;
			e.entry_timeout = CFS_ENTRY_TIMEOUT;
			cfs_stat(e.ino, child_cino, &e.attr);

			res = fuse_add_direntry_plus(
				req, (char *)(buf->buf + buf->current_size),
				remaining_size, name_buf, &e, next_offset);
		} else {
			memset(&stbuf, 0, sizeof(stbuf));
			stbuf.st_ino = cfs_ino_from_nid(nid);
			stbuf.st_mode = erofs_file_type_to_mode(type);
			res = fuse_add_direntry(
				req, (char *)(buf->buf + buf->current_size),
				remaining_size, name_buf, &stbuf, next_offset);
		}
		if (res <= remaining_size) {
			buf->current_size += res;
		} else {
			/* didn't fit, stop */
			return true;
		}
		buf->offset = next_offset;
	}

	return false;
}

static void _cfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t max_size,
			 off_t off, struct fuse_file_info *fi, bool use_plus)
{
	const erofs_inode *cino = (const erofs_inode *)(uintptr_t)fi->fh;
	uint32_t mode;
	uint64_t file_size;
	uint16_t xattr_icount;
	size_t xattr_size;
	size_t isize;
	uint64_t n_blocks;
	uint64_t last_oob_block;
	size_t first_block;
	bool tailpacked;
	size_t tail_size;
	const uint8_t *tail_data;
	const uint8_t *oob_data;
	uint32_t raw_blkaddr;
	uint8_t bufdata[max_size];
	bool done;
	struct dirbuf buf = {
		.buf = bufdata,
		.current_size = 0,
		.max_size = max_size,
		.offset = off,
	};

	erofs_inode_get_info(cino, &mode, &file_size, &xattr_icount,
			     &raw_blkaddr, &isize);

	xattr_size = erofs_xattr_inode_size(xattr_icount);

	tailpacked = erofs_inode_is_tailpacked(cino);
	tail_size = tailpacked ? file_size % EROFS_BLKSIZ : 0;
	tail_data = ((uint8_t *)cino) + isize + xattr_size;
	n_blocks = round_up(file_size, EROFS_BLKSIZ) / EROFS_BLKSIZ;
	last_oob_block = tailpacked ? n_blocks - 1 : n_blocks;
	first_block = buf.offset / EROFS_BLKSIZ;
	oob_data = erofs_data + raw_blkaddr * EROFS_BLKSIZ;

	if (first_block >= n_blocks) {
		goto out;
	}

	/* First read the out-of-band blocks */
	done = false;
	for (uint64_t block = first_block; block < last_oob_block; block++) {
		size_t block_start = block * EROFS_BLKSIZ;
		size_t block_size = EROFS_BLKSIZ;

		if (!tailpacked && block + 1 == last_oob_block) {
			block_size = file_size % EROFS_BLKSIZ;
			if (block_size == 0) {
				block_size = EROFS_BLKSIZ;
			}
		}

		if (buf.offset >= block_start &&
		    buf.offset < block_start + block_size) {
			const uint8_t *block_data = oob_data + block_start;
			if (cfs_readdir_block(req, &buf, block_data, block_size,
					      block_start, use_plus)) {
				done = true;
				break;
			}
		}
	}

	if (!done && tailpacked) {
		size_t block_start = last_oob_block * EROFS_BLKSIZ;

		if (buf.offset >= block_start && buf.offset < block_start + tail_size) {
			cfs_readdir_block(req, &buf, tail_data, tail_size,
					  block_start, use_plus);
		}
	}

out:
	fuse_reply_buf(req, (char *)bufdata, buf.current_size);
}

static void cfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t max_size,
			off_t off, struct fuse_file_info *fi)
{
	_cfs_readdir(req, ino, max_size, off, fi, false);
}

static void cfs_readdir_plus(fuse_req_t req, fuse_ino_t ino, size_t max_size,
			     off_t off, struct fuse_file_info *fi)
{
	_cfs_readdir(req, ino, max_size, off, fi, true);
}

static void cfs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	const erofs_inode *cino = cfs_get_erofs_inode(ino);
	mode_t mode;

	if (cino == NULL) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	mode = erofs_inode_get_mode(cino);

	if ((mode & S_IFMT) != S_IFDIR) {
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	fi->keep_cache = 1;
	fi->cache_readdir = 1;
	fi->fh = (uintptr_t)cino;
	fuse_reply_open(req, fi);
}

static void cfs_readlink(fuse_req_t req, fuse_ino_t ino)
{
	const erofs_inode *cino = cfs_get_erofs_inode(ino);
	uint32_t mode;
	uint64_t file_size;
	uint16_t xattr_icount;
	uint32_t raw_blkaddr;
	size_t isize;
	size_t xattr_size;
	bool tailpacked;
	char name_buf[PATH_MAX];

	if (cino == NULL) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	erofs_inode_get_info(cino, &mode, &file_size, &xattr_icount,
			     &raw_blkaddr, &isize);

	if ((mode & S_IFMT) != S_IFLNK) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	/* Avoid overwriting name_buf below */
	if (file_size >= PATH_MAX) {
		fuse_reply_err(req, EIO);
		return;
	}

	xattr_size = erofs_xattr_inode_size(xattr_icount);

	tailpacked = erofs_inode_is_tailpacked(cino);
	if (!tailpacked) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	const uint8_t *inline_data = ((uint8_t *)cino) + isize + xattr_size;

	memcpy(name_buf, inline_data, file_size);
	name_buf[file_size] = 0;

	fuse_reply_readlink(req, name_buf);
}

static void cfs_init(void *userdata, struct fuse_conn_info *conn)
{
	if (conn->capable & FUSE_CAP_CACHE_SYMLINKS)
		conn->want |= FUSE_CAP_CACHE_SYMLINKS;

	if (conn->capable & FUSE_CAP_EXPORT_SUPPORT)
		conn->want |= FUSE_CAP_EXPORT_SUPPORT;

	if (erofs_use_acl && conn->capable & FUSE_CAP_POSIX_ACL)
		conn->want |= FUSE_CAP_POSIX_ACL;

	if (conn->capable & FUSE_CAP_SPLICE_WRITE)
		conn->want |= FUSE_CAP_SPLICE_WRITE;
	if (conn->capable & FUSE_CAP_SPLICE_READ)
		conn->want |= FUSE_CAP_SPLICE_READ;
}

#define OVERLAY_XATTR_PARTIAL_PREFIX "overlay."

static const char *cfs_xattr_rewrite(int name_index, const char *name,
				     uint8_t *_name_len)
{
	uint8_t name_len = *_name_len;

	if (name_index == EROFS_XATTR_INDEX_TRUSTED &&
	    name_len > strlen(OVERLAY_XATTR_PARTIAL_PREFIX) &&
	    memcmp(name, OVERLAY_XATTR_PARTIAL_PREFIX,
		   strlen(OVERLAY_XATTR_PARTIAL_PREFIX)) == 0) {
		name += strlen(OVERLAY_XATTR_PARTIAL_PREFIX);
		name_len -= strlen(OVERLAY_XATTR_PARTIAL_PREFIX);
		/* Check for escapes */
		if (name_len > strlen(OVERLAY_XATTR_PARTIAL_PREFIX) &&
		    memcmp(name, OVERLAY_XATTR_PARTIAL_PREFIX,
			   strlen(OVERLAY_XATTR_PARTIAL_PREFIX)) == 0) {
			*_name_len = name_len;
			return name;
		}
		return NULL;
	}

	return name;
}

static errint_t cfs_listxattr_element(const struct erofs_xattr_entry *entry,
				      char *buf, size_t *buf_size, size_t max_buf_size)
{
	const char *name = (const char *)entry + sizeof(struct erofs_xattr_entry);
	uint8_t name_len = entry->e_name_len;
	uint8_t name_index = entry->e_name_index;
	size_t full_name_len;
	const char *prefix;

	name = cfs_xattr_rewrite(name_index, name, &name_len);
	if (name == NULL)
		return 0;

	/* Until we support mount option to use all xattrs, only support user.* */
	if (name_index != EROFS_XATTR_INDEX_USER)
		return 0;

	prefix = erofs_xattr_prefixes[name_index];
	full_name_len = name_len + strlen(prefix);

	if (max_buf_size != 0 && max_buf_size - *buf_size < full_name_len + 1)
		return -ERANGE;

	if (max_buf_size != 0)
		memcpy(buf + *buf_size, prefix, strlen(prefix));
	*buf_size += strlen(prefix);
	if (max_buf_size != 0)
		memcpy(buf + *buf_size, name, name_len);
	*buf_size += name_len;
	if (max_buf_size != 0)
		buf[*buf_size] = 0;
	*buf_size += 1;

	return 0;
}

static void cfs_listxattr(fuse_req_t req, fuse_ino_t ino, size_t max_size)
{
	const erofs_inode *cino = cfs_get_erofs_inode(ino);
	uint32_t mode;
	uint64_t file_size;
	uint16_t xattr_icount;
	uint32_t raw_blkaddr;
	size_t isize;
	size_t xattr_size;
	char buf[max_size];
	size_t buf_size;
	uint8_t shared_count;
	const struct erofs_xattr_ibody_header *xattr_header;
	const uint8_t *xattrs_inline;
	const uint8_t *xattrs_start;
	const uint8_t *xattrs_end;
	errint_t err;

	if (cino == NULL) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	erofs_inode_get_info(cino, &mode, &file_size, &xattr_icount,
			     &raw_blkaddr, &isize);

	if (xattr_icount == 0) {
		/* No xattrs */

		if (max_size == 0) {
			fuse_reply_xattr(req, 0);
		} else {
			fuse_reply_buf(req, NULL, 0);
		}
		return;
	}

	xattr_size = erofs_xattr_inode_size(xattr_icount);

	xattrs_start = ((uint8_t *)cino) + isize;
	xattrs_end = ((uint8_t *)cino) + isize + xattr_size;
	xattr_header = (struct erofs_xattr_ibody_header *)xattrs_start;
	shared_count = xattr_header->h_shared_count;

	buf_size = 0;
	xattrs_inline = xattrs_start + sizeof(struct erofs_xattr_ibody_header) +
			shared_count * 4;

	/* Inline xattrs */
	while (xattrs_inline + sizeof(struct erofs_xattr_entry) < xattrs_end) {
		const struct erofs_xattr_entry *entry =
			(const struct erofs_xattr_entry *)xattrs_inline;
		uint8_t name_len = entry->e_name_len;
		uint16_t value_size = lcfs_u16_from_file(entry->e_value_size);
		size_t el_size = round_up(
			sizeof(struct erofs_xattr_entry) + name_len + value_size, 4);

		err = cfs_listxattr_element(entry, buf, &buf_size, max_size);
		if (err < 0) {
			fuse_reply_err(req, -err);
			return;
		}
		xattrs_inline += el_size;
	}

	/* Shared xattrs */
	for (int i = 0; i < shared_count; i++) {
		uint32_t idx = lcfs_u32_from_file(xattr_header->h_shared_xattrs[i]);
		const struct erofs_xattr_entry *entry =
			(const struct erofs_xattr_entry *)(erofs_xattrdata + idx * 4);

		err = cfs_listxattr_element(entry, buf, &buf_size, max_size);
		if (err < 0) {
			fuse_reply_err(req, -err);
			return;
		}
	}

	if (max_size == 0) {
		fuse_reply_xattr(req, buf_size);
	} else {
		fuse_reply_buf(req, buf, buf_size);
	}
}

static int match_xattr_entry(const struct erofs_xattr_entry *entry, int name_prefix,
			     const char *name, size_t name_len, bool filter)
{
	uint8_t e_name_len = entry->e_name_len;
	uint8_t e_name_prefix = entry->e_name_index;
	const char *e_name = (const char *)entry + sizeof(struct erofs_xattr_entry);

	if (filter)
		e_name = cfs_xattr_rewrite(e_name_prefix, e_name, &e_name_len);

	return e_name != NULL && e_name_prefix == name_prefix &&
	       e_name_len == name_len && memcmp(name, e_name, name_len) == 0;
}

static const char *do_getxattr(const erofs_inode *cino, int name_prefix,
			       const char *name, uint16_t *value_size_out, bool filter)
{
	size_t name_len = strlen(name);
	uint32_t mode;
	uint64_t file_size;
	uint16_t xattr_icount;
	uint32_t raw_blkaddr;
	size_t isize;
	size_t xattr_size;
	uint8_t shared_count;
	const struct erofs_xattr_ibody_header *xattr_header;
	const uint8_t *xattrs_inline;
	const uint8_t *xattrs_start;
	const uint8_t *xattrs_end;

	/* Until we support mount option to use all xattrs, only support user.* */
	if (filter && name_prefix != EROFS_XATTR_INDEX_USER)
		return NULL;

	erofs_inode_get_info(cino, &mode, &file_size, &xattr_icount,
			     &raw_blkaddr, &isize);

	if (xattr_icount == 0) {
		return NULL;
	}

	xattr_size = erofs_xattr_inode_size(xattr_icount);

	xattrs_start = ((uint8_t *)cino) + isize;
	xattrs_end = ((uint8_t *)cino) + isize + xattr_size;
	xattr_header = (struct erofs_xattr_ibody_header *)xattrs_start;
	shared_count = xattr_header->h_shared_count;

	xattrs_inline = xattrs_start + sizeof(struct erofs_xattr_ibody_header) +
			shared_count * 4;

	/* Inline xattrs */
	while (xattrs_inline + sizeof(struct erofs_xattr_entry) < xattrs_end) {
		const struct erofs_xattr_entry *entry =
			(const struct erofs_xattr_entry *)xattrs_inline;
		uint8_t e_name_len = entry->e_name_len;
		uint16_t value_size = lcfs_u16_from_file(entry->e_value_size);
		size_t el_size = round_up(sizeof(struct erofs_xattr_entry) +
						  e_name_len + value_size,
					  4);

		if (match_xattr_entry(entry, name_prefix, name, name_len, filter)) {
			const char *value = (const char *)entry +
					    sizeof(struct erofs_xattr_entry) +
					    e_name_len;
			*value_size_out = value_size;
			return value;
		}

		xattrs_inline += el_size;
	}

	/* Shared xattrs */
	for (int i = 0; i < shared_count; i++) {
		uint32_t idx = lcfs_u32_from_file(xattr_header->h_shared_xattrs[i]);
		const struct erofs_xattr_entry *entry =
			(const struct erofs_xattr_entry *)(erofs_xattrdata + idx * 4);

		if (match_xattr_entry(entry, name_prefix, name, name_len, filter)) {
			uint16_t value_size =
				lcfs_u16_from_file(entry->e_value_size);
			uint8_t e_name_len = entry->e_name_len;
			const char *value = (const char *)entry +
					    sizeof(struct erofs_xattr_entry) +
					    e_name_len;
			*value_size_out = value_size;
			return value;
		}
	}

	return NULL;
}

static void cfs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			 size_t max_size)
{
	const erofs_inode *cino = cfs_get_erofs_inode(ino);
	int name_prefix;
	size_t name_len;
	const char *value;
	uint16_t value_size;

	if (cino == NULL) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	/* Handle prefix part */
	name_prefix = erofs_get_xattr_prefix(name);
	name += strlen(erofs_xattr_prefixes[name_prefix]);
	name_len = strlen(name);

	/* When acls are not used, send EOPTNOTSUPP, as this informs
	   userspace to stop constantly looking for acls */
	if (!erofs_use_acl && erofs_is_acl_xattr(name_prefix, name, name_len)) {
		fuse_reply_err(req, EOPNOTSUPP);
		return;
	}

	value = do_getxattr(cino, name_prefix, name, &value_size, true);
	if (value == NULL) {
		fuse_reply_err(req, ENODATA);
		return;
	}

	if (max_size == 0) {
		fuse_reply_xattr(req, value_size);
	} else if (max_size < value_size) {
		fuse_reply_err(req, ERANGE);
	} else {
		fuse_reply_buf(req, (const char *)value, value_size);
	}
}

static void cfs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	const erofs_inode *cino = cfs_get_erofs_inode(ino);
	int fd;
	const char *redirect;
	uint16_t value_size;

	if ((fi->flags & O_ACCMODE) == O_WRONLY || (fi->flags & O_ACCMODE) == O_RDWR)
		return (void)fuse_reply_err(req, EROFS);

	if (cino == NULL) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	redirect = do_getxattr(cino, EROFS_XATTR_INDEX_TRUSTED,
			       "overlay.redirect", &value_size, false);

	if (redirect == NULL) {
		/* Empty files have no redirect */
		fd = -1;
	} else {
		while (*redirect == '/')
			redirect++;

		fd = openat(basedir_fd, redirect,
			    O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_RDONLY, 0);
		if (fd < 0) {
			fuse_reply_err(req, errno);
			return;
		}

		/* TODO: Verify fs-verity */
	}

	fi->fh = fd;
	fi->keep_cache = 1;

	return (void)fuse_reply_open(req, fi);
}

static void cfs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	int fd = fi->fh;

	if (fd >= 0)
		close(fd);
	fuse_reply_err(req, 0);
}

static void cfs_read_inline(fuse_req_t req, fuse_ino_t ino, size_t size,
			    off_t offset, struct fuse_file_info *fi)
{
	const erofs_inode *cino = cfs_get_erofs_inode(ino);
	uint32_t mode;
	uint64_t file_size;
	uint16_t xattr_icount;
	size_t xattr_size;
	size_t isize;
	uint64_t n_blocks;
	uint64_t last_oob_block;
	bool tailpacked;
	size_t tail_size;
	uint32_t raw_blkaddr;
	off_t oob_size;
	const uint8_t *tail_data;
	const uint8_t *oob_data;
	struct iovec iov[2];
	int i;

	if (!erofs_inode_is_flat(cino)) {
		fuse_reply_err(req, ENXIO);
		return;
	}

	erofs_inode_get_info(cino, &mode, &file_size, &xattr_icount,
			     &raw_blkaddr, &isize);

	xattr_size = erofs_xattr_inode_size(xattr_icount);

	tailpacked = erofs_inode_is_tailpacked(cino);
	tail_size = tailpacked ? file_size % EROFS_BLKSIZ : 0;
	tail_data = ((uint8_t *)cino) + isize + xattr_size;

	n_blocks = round_up(file_size, EROFS_BLKSIZ) / EROFS_BLKSIZ;
	last_oob_block = tailpacked ? n_blocks - 1 : n_blocks;

	oob_data = erofs_data + raw_blkaddr * EROFS_BLKSIZ;
	oob_size = tailpacked ? last_oob_block * EROFS_BLKSIZ : file_size;

	i = 0;
	if (offset < oob_size) {
		size_t oob_send = min(size, oob_size);
		iov[i].iov_base = (uint8_t *)oob_data;
		iov[i++].iov_len = oob_send;
		size -= oob_send;
	}

	if (size > 0 && tail_size > 0) {
		size_t tail_send = min(size, tail_size);
		iov[i].iov_base = (uint8_t *)tail_data;
		iov[i++].iov_len = tail_send;
		size -= tail_send;
	}

	fuse_reply_iov(req, iov, i);
}

static void cfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
		     struct fuse_file_info *fi)
{
	struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
	int fd = fi->fh;

	if (fd < 0) {
		cfs_read_inline(req, ino, size, offset, fi);
	} else {
		buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
		buf.buf[0].fd = fd;
		buf.buf[0].pos = offset;

		fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
	}
}

static void cfs_lseek(fuse_req_t req, fuse_ino_t ino, off_t off, int whence,
		      struct fuse_file_info *fi)
{
	int fd = fi->fh;
	off_t res;

	(void)ino;

	if (fd < 0) {
		if (off > 0 || (whence == SEEK_DATA)) {
			fuse_reply_err(req, ENXIO);
		} else {
			fuse_reply_lseek(req, 0);
		}
		return;
	}

	res = lseek(fd, off, whence);
	if (res != -1)
		fuse_reply_lseek(req, res);
	else
		fuse_reply_err(req, errno);
}

static const struct fuse_lowlevel_ops cfs_oper = {
	.init = cfs_init,
	.lookup = cfs_lookup,
	.getattr = cfs_getattr,
	.opendir = cfs_opendir,
	.readdir = cfs_readdir,
	.readdirplus = cfs_readdir_plus,
	.readlink = cfs_readlink,
	.listxattr = cfs_listxattr,
	.getxattr = cfs_getxattr,
	.open = cfs_open,
	.release = cfs_release,
	.read = cfs_read,
	.lseek = cfs_lseek,
};

static void cleanup_cfs_data(struct cfs_data *data)
{
	free(data->source);
	free(data->basedir);
}

int main(int argc, char *argv[])
{
	__attribute__((cleanup(fuse_opt_free_args))) struct fuse_args args =
		FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts opts;
	struct fuse_loop_config config;
	__attribute__((cleanup(cleanup_cfs_data))) struct cfs_data data = {
		.source = NULL, .basedir = NULL
	};
	int fd;
	struct stat s;
	int r;
	uint32_t cfs_flags;

	int ret = -1;

	if (fuse_parse_cmdline(&args, &opts) != 0) {
		ret = 1;
		goto err_out1;
	}
	if (opts.show_help) {
		printf("usage: %s [options] <file> <mountpoint>\n\n", argv[0]);
		fuse_cmdline_help();
		fuse_lowlevel_help();
		ret = 0;
		goto err_out1;
	} else if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		ret = 0;
		goto err_out1;
	}

	if (opts.mountpoint == NULL) {
		printf("usage: %s [options] <mountpoint>\n", argv[0]);
		printf("       %s --help\n", argv[0]);
		ret = 1;
		goto err_out1;
	}

	/* We always want the kernel to handle the permissions */
	fuse_opt_add_arg(&args, "-o");
	fuse_opt_add_arg(&args, "ro,default_permissions");

	if (fuse_opt_parse(&args, &data, cfs_opts, NULL) == -1) {
		ret = 1;
		goto err_out1;
	}

	fd = open(data.source, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		errx(EXIT_FAILURE, "Failed to open %s\n", data.source);
	}

	r = fstat(fd, &s);
	if (r < 0) {
		errx(EXIT_FAILURE, "Failed to stat %s\n", data.source);
	}
	erofs_data_size = s.st_size;

	if (erofs_data_size < EROFS_BLKSIZ) {
		errx(EXIT_FAILURE, "Too small image\n");
	}

	/* Memory-map the file. */
	erofs_data = mmap(0, erofs_data_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (erofs_data == MAP_FAILED) {
		errx(EXIT_FAILURE, "Failed to mmap %s\n", data.source);
	}
	close(fd);

	basedir_fd = open(data.basedir, O_RDONLY | O_PATH);
	if (basedir_fd < 0) {
		errx(EXIT_FAILURE, "Failed to open basedir  %s\n", data.basedir);
	}

	cfs_header = (struct lcfs_erofs_header_s *)(erofs_data);
	if (lcfs_u32_from_file(cfs_header->magic) != LCFS_EROFS_MAGIC) {
		errx(EXIT_FAILURE, "Wrong cfs magic");
	}

	cfs_flags = lcfs_u32_from_file(cfs_header->flags);
	if (cfs_flags & LCFS_EROFS_FLAGS_HAS_ACL && !data.noacl)
		erofs_use_acl = true;

	erofs_super = (struct erofs_super_block *)(erofs_data + EROFS_SUPER_OFFSET);

	if (lcfs_u32_from_file(erofs_super->magic) != EROFS_SUPER_MAGIC_V1) {
		errx(EXIT_FAILURE, "Wrong erofs magic");
	}

	erofs_metadata = erofs_data + lcfs_u32_from_file(erofs_super->meta_blkaddr) *
					      EROFS_BLKSIZ;
	erofs_xattrdata =
		erofs_data +
		lcfs_u32_from_file(erofs_super->xattr_blkaddr) * EROFS_BLKSIZ;

	erofs_root_nid = lcfs_u16_from_file(erofs_super->root_nid);
	erofs_build_time = lcfs_u64_from_file(erofs_super->build_time);
	erofs_build_time_nsec = lcfs_u32_from_file(erofs_super->build_time_nsec);

	se = fuse_session_new(&args, &cfs_oper, sizeof(cfs_oper), NULL);
	if (se == NULL)
		goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
		goto err_out2;

	if (fuse_session_mount(se, opts.mountpoint) != 0)
		goto err_out3;

	fuse_daemonize(opts.foreground);

	/* Block until ctrl+c or fusermount -u */
	if (opts.singlethread)
		ret = fuse_session_loop(se);
	else {
		config.clone_fd = true;
		config.max_idle_threads = opts.max_idle_threads;
		ret = fuse_session_loop_mt(se, &config);
	}

	fuse_session_unmount(se);
err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	free(opts.mountpoint);

	return ret ? 1 : 0;
}
