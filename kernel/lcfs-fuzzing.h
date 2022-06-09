#ifdef FUZZING
#define GFP_KERNEL 0
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <endian.h>

#define SHA512_DIGEST_SIZE 64

#define kfree free
#define vfree free
#define min(a, b) ((a) < (b) ? (a) : (b))
#define check_add_overflow(a, b, d) __builtin_add_overflow(a, b, d)
#define ENOTSUPP ENOTSUP
#define pr_err(x, ...)

#define d_inode(d) (&d)

#define DT_DIR 4

struct inode {};

struct path {
	struct inode dentry;
};

struct file {
	int fd;
	struct path f_path;
};

static inline char *kstrndup(const char *str, size_t len, int ignored)
{
	return strndup(str, len);
}

static inline void *kzalloc(size_t len, int ignored)
{
	return calloc(1, len);
}

static inline void *kmalloc(size_t len, int ignored)
{
	return malloc(len);
}

static inline struct file *filp_open(const char *path, int flags, int mode)
{
	struct file *r;
	int fd;

	fd = open(path, flags, mode);
	if (fd < 0)
		return ERR_PTR(-errno);

	r = malloc(sizeof(struct file));
	if (r == NULL) {
		close(fd);
		return ERR_PTR(-ENOMEM);
	}

	r->fd = fd;
	return r;
}

static inline ssize_t kernel_read(struct file *f, void *buf, size_t count,
				  loff_t *off)
{
	ssize_t bytes;
	do {
		bytes = pread(f->fd, buf, count, *off);
	} while (bytes < 0 && errno == EINTR);
	if (bytes > 0)
		*off += bytes;
	return bytes;
}

static inline struct file *file_inode(struct file *f)
{
	return f;
}

static inline loff_t i_size_read(struct file *f)
{
	struct stat st;
	int r;

	r = fstat(f->fd, &st);
	if (r < 0)
		return -errno;

	return st.st_size;
}

static inline void fput(struct file *f)
{
	close(f->fd);
	free(f);
}

struct __una_u32 {
	u32 x;
} __attribute__((packed));

static inline u32 __get_unaligned_cpu32(const void *p)
{
	const struct __una_u32 *ptr = (const struct __una_u32 *)p;
	return ptr->x;
}

struct __una_u64 {
	u64 x;
} __attribute__((packed));

static inline u64 __get_unaligned_cpu64(const void *p)
{
	const struct __una_u64 *ptr = (const struct __una_u64 *)p;
	return ptr->x;
}

static inline struct fsverity_info *fsverity_get_info(const struct inode *inode)
{
	return NULL;
}

#endif
