/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

   SPDX-License-Identifier: GPL-2.0-or-later OR Apache-2.0
*/

#define _GNU_SOURCE

#include "config.h"

#include "libcomposefs/lcfs-writer.h"
#include "libcomposefs/lcfs-utils.h"
#include "libcomposefs/lcfs-internal.h"
#include "libcomposefs/hash.h"

#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <ctype.h>
#include <getopt.h>
#include <locale.h>

#define ESCAPE_STANDARD 0
#define NOESCAPE_SPACE (1 << 0)
#define ESCAPE_EQUAL (1 << 1)
#define ESCAPE_LONE_DASH (1 << 2)

const char *opt_basedir_path;
// Counting for a NULL terminated char array...so painful to reimplement each time in C
static size_t n_filters;
static size_t filter_capacity = 1;
static char **opt_filter;
int opt_basedir_fd;

static locale_t c_locale;

typedef void *(*command_handler_init)(void);
typedef void (*command_handler)(struct lcfs_node_s *node, void *handler_data);
typedef void (*command_handler_end)(void *handler_data);

static void oom(void)
{
	errx(EXIT_FAILURE, "Out of memory");
}

static void print_escaped(const char *val, ssize_t len, int escape)
{
	bool noescape_space = (escape & NOESCAPE_SPACE) != 0;
	bool escape_equal = (escape & ESCAPE_EQUAL) != 0;
	bool escape_lone_dash = (escape & ESCAPE_LONE_DASH) != 0;

	if (len < 0)
		len = strlen(val);

	if (escape_lone_dash && len == 1 && val[0] == '-') {
		printf("\\x%.2x", val[0]);
		return;
	}

	for (size_t i = 0; i < len; i++) {
		uint8_t c = val[i];
		bool hex_escape = false;
		const char *special = NULL;
		switch (c) {
		case '\\':
			special = "\\\\";
			break;
		case '\n':
			special = "\\n";
			break;
		case '\r':
			special = "\\r";
			break;
		case '\t':
			special = "\\t";
			break;
		case '=':
			hex_escape = escape_equal;
			break;
		default:
			if (noescape_space)
				hex_escape = !isprint_l(c, c_locale);
			else
				hex_escape = !isgraph_l(c, c_locale);
			break;
		}

		if (special != NULL)
			printf("%s", special);
		else if (hex_escape)
			printf("\\x%.2x", c);
		else
			printf("%c", c);
	}
}

static void print_escaped_optional(const char *val, ssize_t len, int escape)
{
	if (val == NULL) {
		printf("-");
	} else {
		print_escaped(val, len, escape);
	}
}

static void print_node(struct lcfs_node_s *node, char *parent_path)
{
	for (size_t i = 0; i < lcfs_node_get_n_children(node); i++) {
		struct lcfs_node_s *child = lcfs_node_get_child(node, i);
		cleanup_free char *path = NULL;
		int r;

		r = asprintf(&path, "%s/%s", parent_path, lcfs_node_get_name(child));
		if (r < 0)
			oom();

		uint32_t mode = lcfs_node_get_mode(child);
		uint32_t type = mode & S_IFMT;
		const char *payload = lcfs_node_get_payload(child);

		print_escaped(path, -1, NOESCAPE_SPACE);

		if (type == S_IFDIR) {
			printf("/\t");
		} else if (type == S_IFLNK) {
			printf("\t-> ");
			print_escaped(payload, -1, ESCAPE_STANDARD);
		} else if (type == S_IFREG && payload) {
			printf("\t@ ");
			print_escaped(payload, -1, ESCAPE_STANDARD);
		}
		printf("\n");

		print_node(child, path);
	}
}

static void print_node_handler(struct lcfs_node_s *node, void *data)
{
	print_node(node, "");
}

static char *node_build_path(struct lcfs_node_s *node)
{
	size_t pathlen = 0;
	for (struct lcfs_node_s *n = node; n != NULL; n = lcfs_node_get_parent(n)) {
		const char *name = lcfs_node_get_name(n);

		/* separator after all but final element */
		if (n != node)
			pathlen += 1;

		/* Root has no name */
		if (name)
			pathlen += strlen(name);
	}

	char *path = malloc(pathlen + 1);
	if (path == NULL)
		oom();
	char *p = path + pathlen;
	*p = 0;

	for (struct lcfs_node_s *n = node; n != NULL; n = lcfs_node_get_parent(n)) {
		const char *name = lcfs_node_get_name(n);
		if (n != node) {
			p--;
			*p = '/';
		}
		if (name) {
			size_t len = strlen(name);
			p -= len;
			memcpy(p, name, len);
		}
	}

	return path;
}

static void dump_node(struct lcfs_node_s *node, char *path)
{
	struct lcfs_node_s *target = lcfs_node_get_hardlink_target(node);
	cleanup_free char *hardlink_path = NULL;
	if (target == NULL)
		target = node;
	else
		hardlink_path = node_build_path(target);

	struct timespec mtime;
	lcfs_node_get_mtime(target, &mtime);
	const char *payload = lcfs_node_get_payload(target);
	const uint8_t *digest = lcfs_node_get_fsverity_digest(target);
	const uint8_t *content = lcfs_node_get_content(target);
	uint64_t size = lcfs_node_get_size(target);

	print_escaped(*path == 0 ? "/" : path, -1, ESCAPE_STANDARD);
	printf(" %" PRIu64 " %s%o %u %u %u %" PRIu64 " %" PRIi64 ".%u ", size,
	       hardlink_path != NULL ? "@" : "", lcfs_node_get_mode(target),
	       lcfs_node_get_nlink(target), lcfs_node_get_uid(target),
	       lcfs_node_get_gid(target), lcfs_node_get_rdev64(target),
	       (int64_t)mtime.tv_sec, (unsigned int)mtime.tv_nsec);
	print_escaped_optional(hardlink_path ? hardlink_path : payload, -1,
			       ESCAPE_LONE_DASH);
	printf(" ");
	print_escaped_optional((char *)content, size, ESCAPE_LONE_DASH);

	if (digest) {
		char digest_str[LCFS_DIGEST_SIZE * 2 + 1] = { 0 };
		digest_to_string(digest, digest_str);
		printf(" %s", digest_str);
	} else {
		printf(" -");
	}

	size_t n_xattr = lcfs_node_get_n_xattr(target);
	for (size_t i = 0; i < n_xattr; i++) {
		const char *name = lcfs_node_get_xattr_name(target, i);
		size_t value_len;
		const char *value = lcfs_node_get_xattr(target, name, &value_len);

		printf(" ");
		print_escaped(name, -1, ESCAPE_EQUAL);
		printf("=");
		print_escaped(value, value_len, ESCAPE_EQUAL);
	}

	printf("\n");

	for (size_t i = 0; i < lcfs_node_get_n_children(node); i++) {
		struct lcfs_node_s *child = lcfs_node_get_child(node, i);
		cleanup_free char *child_path = NULL;
		int r;

		r = asprintf(&child_path, "%s/%s", path, lcfs_node_get_name(child));
		if (r < 0)
			oom();

		dump_node(child, child_path);
	}
}

static void dump_node_handler(struct lcfs_node_s *node, void *data)
{
	dump_node(node, "");
}

typedef struct {
	Hash_table *ht;
} PrintData;

static const char *abs_to_rel_path(const char *path)
{
	while (*path == '/')
		path++;
	return path;
}

static void get_objects(struct lcfs_node_s *node, PrintData *data, int basedir_fd)
{
	uint32_t mode = lcfs_node_get_mode(node);
	uint32_t type = mode & S_IFMT;
	const char *payload = lcfs_node_get_payload(node);

	if (type == S_IFREG && payload && hash_lookup(data->ht, payload) == NULL) {
		struct stat st;
		if (basedir_fd == -1 || fstatat(basedir_fd, abs_to_rel_path(payload),
						&st, AT_EMPTY_PATH) < 0) {
			char *dup = strdup(payload);
			if (dup == NULL || hash_insert(data->ht, dup) == NULL)
				oom();
		}
	}

	for (size_t i = 0; i < lcfs_node_get_n_children(node); i++) {
		struct lcfs_node_s *child = lcfs_node_get_child(node, i);
		get_objects(child, data, basedir_fd);
	}
}

static size_t str_ht_hash(const void *entry, size_t table_size)
{
	return hash_string(entry, table_size);
}

static bool str_ht_eq(const void *entry1, const void *entry2)
{
	return strcmp(entry1, entry2) == 0;
}

static int cmp_obj(const void *_a, const void *_b)
{
	const char *const *a = _a;
	const char *const *b = _b;
	return strcmp(*a, *b);
}

static void *print_objects_handler_init(void)
{
	PrintData *data = calloc(1, sizeof(PrintData));

	if (data == NULL)
		oom();

	data->ht = hash_initialize(0, NULL, str_ht_hash, str_ht_eq, free);
	if (data->ht == NULL)
		oom();

	return data;
}

static void print_objects_handler(struct lcfs_node_s *node, void *_data)
{
	PrintData *data = _data;
	get_objects(node, data, -1);
}

static void print_missing_objects_handler(struct lcfs_node_s *node, void *_data)
{
	PrintData *data = _data;
	get_objects(node, data, opt_basedir_fd);
}

static void print_objects_handler_end(void *_data)
{
	PrintData *data = _data;

	size_t n_objects = hash_get_n_entries(data->ht);
	cleanup_free char **objects = calloc(n_objects, sizeof(char *));
	if (objects == NULL)
		oom();

	hash_get_entries(data->ht, (void **)objects, n_objects);

	qsort(objects, n_objects, sizeof(char *), cmp_obj);

	for (size_t i = 0; i < n_objects; i++)
		printf("%s\n", objects[i]);

	hash_free(data->ht);
	free(data);
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [--basedir=path] [ls|objects|dump|missing-objects|measure-file] IMAGES...\n",
		argv0);
}

#define OPT_BASEDIR 100
#define OPT_FILTER 101

// Most of the rest of this code operates on composefs superblocks.  This function
// just prints the fsverity digest of the provided files.
static int measure_files(const char *bin, int argc, char **argv)
{
	if (argc <= 2) {
		fprintf(stderr, "No files specified\n");
		usage(bin);
		exit(1);
	}

	for (int i = 2; i < argc; i++) {
		const char *path = argv[i];
		uint8_t digest[LCFS_DIGEST_SIZE];

		cleanup_fd int fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			err(EXIT_FAILURE, "Failed to open '%s'", path);
		}

		int r = lcfs_fd_get_fsverity(digest, fd);
		if (r != 0) {
			const char *errmsg = strerror(errno);
			fprintf(stderr, "failed to measure '%s': %s", path, errmsg);
			exit(1);
		}
		char digest_str[LCFS_DIGEST_SIZE * 2 + 1] = { 0 };
		digest_to_string(digest, digest_str);
		printf("%s\n", digest_str);
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *bin = argv[0];
	int opt;
	const struct option longopts[] = {
		{ .name = "basedir",
		  .has_arg = required_argument,
		  .flag = NULL,
		  .val = OPT_BASEDIR },
		{ .name = "filter",
		  .has_arg = required_argument,
		  .flag = NULL,
		  .val = OPT_FILTER },
		{},
	};

	while ((opt = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (opt) {
		case OPT_BASEDIR:
			opt_basedir_path = optarg;
			break;
		case OPT_FILTER:
			// Ensure we have space for the NULL terminator
			if (opt_filter == NULL || (n_filters + 1) >= filter_capacity) {
				filter_capacity *= 2;
				opt_filter = reallocarray(opt_filter, filter_capacity,
							  sizeof(char *));
				if (opt_filter == NULL)
					oom();
			}
			if (strchr(optarg, '/') != NULL) {
				err(EXIT_FAILURE,
				    "Filter must be a single name: %s", optarg);
			}
			opt_filter[n_filters] = strdup(optarg);
			if (opt_filter[n_filters] == NULL)
				oom();
			n_filters++;
			break;
		case ':':
			fprintf(stderr, "option needs a value\n");
			exit(EXIT_FAILURE);
		default:
			printf("Def\n");
			usage(bin);
			exit(1);
		}
	}

	argv += optind - 1;
	argc -= optind - 1;

	if (argc <= 1) {
		fprintf(stderr, "No command specified\n");
		usage(bin);
		exit(1);
	}

	c_locale = newlocale(LC_CTYPE, "C", (locale_t)0);
	if (c_locale == (locale_t)0)
		err(EXIT_FAILURE, "Failed to get C locale");
	const char *command = argv[1];

	command_handler_init handler_init = NULL;
	command_handler handler = NULL;
	command_handler_end handler_end = NULL;
	void *handler_data = NULL;

	if (strcmp(command, "ls") == 0) {
		handler = print_node_handler;
	} else if (strcmp(command, "dump") == 0) {
		handler = dump_node_handler;
	} else if (strcmp(command, "objects") == 0) {
		handler = print_objects_handler;
		handler_init = print_objects_handler_init;
		handler_end = print_objects_handler_end;
	} else if (strcmp(command, "missing-objects") == 0) {
		handler = print_missing_objects_handler;
		handler_init = print_objects_handler_init;
		handler_end = print_objects_handler_end;
	} else if (strcmp(command, "measure-file") == 0) {
		return measure_files(bin, argc, argv);
	} else {
		errx(EXIT_FAILURE, "Unknown command '%s'\n", command);
	}

	if (opt_basedir_path) {
		opt_basedir_fd = open(opt_basedir_path,
				      O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_PATH);
		if (opt_basedir_fd < 0)
			err(EXIT_FAILURE, "Can't open basedir `%s`\n",
			    opt_basedir_path);
	}

	if (argc <= 2) {
		fprintf(stderr, "No image path specified\n");
		usage(bin);
		exit(1);
	}

	if (handler_init)
		handler_data = handler_init();

	// Ensure filters are NULL terminated
	if (opt_filter)
		opt_filter[n_filters] = NULL;

	for (int i = 2; i < argc; i++) {
		const char *image_path = image_path = argv[i];

		cleanup_fd int fd = open(image_path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			err(EXIT_FAILURE, "Failed to open '%s'", image_path);
		}

		const char *const *toplevel_entries = (const char *const *)opt_filter;
		struct lcfs_read_options_s opts = { .toplevel_entries =
							    toplevel_entries };
		cleanup_node struct lcfs_node_s *root =
			lcfs_load_node_from_fd_ext(fd, &opts);
		if (root == NULL) {
			err(EXIT_FAILURE, "Failed to load '%s'", image_path);
		}

		handler(root, handler_data);
	}

	if (handler_end)
		handler_end(handler_data);

	freelocale(c_locale);
	return 0;
}
