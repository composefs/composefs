/* lcfs
   Copyright (C) 2023 Alexander Larsson <alexl@redhat.com>

   SPDX-License-Identifier: GPL-2.0-or-later OR Apache-2.0
*/
#define _GNU_SOURCE

#include "config.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <sys/param.h>

#define SHA256_DATASIZE 64

#ifdef HAVE_OPENSSL
/* For sha256 computation */
#include <openssl/evp.h>

#else /* SHA256 fallback implementation */

typedef struct {
	uint32_t buf[8];
	uint32_t bits[2];

	uint8_t data[SHA256_DATASIZE];
} Sha256sum;

/*
 * SHA-256 Checksum
 */

/* adapted from the SHA256 implementation in glib, which is originally:
 *
 * Copyright (C) 2006 Dave Benson
 * Released under the terms of the GNU Lesser General Public License
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

static void sha256_sum_init(Sha256sum *sha256)
{
	sha256->buf[0] = 0x6a09e667;
	sha256->buf[1] = 0xbb67ae85;
	sha256->buf[2] = 0x3c6ef372;
	sha256->buf[3] = 0xa54ff53a;
	sha256->buf[4] = 0x510e527f;
	sha256->buf[5] = 0x9b05688c;
	sha256->buf[6] = 0x1f83d9ab;
	sha256->buf[7] = 0x5be0cd19;

	sha256->bits[0] = sha256->bits[1] = 0;
}

#define GET_UINT32(n, b, i)                                                     \
	do {                                                                    \
		(n) = ((uint32_t)(b)[(i)] << 24) |                              \
		      ((uint32_t)(b)[(i) + 1] << 16) |                          \
		      ((uint32_t)(b)[(i) + 2] << 8) | ((uint32_t)(b)[(i) + 3]); \
	} while (0)

#define PUT_UINT32(n, b, i)                                                    \
	do {                                                                   \
		(b)[(i)] = (uint8_t)((n) >> 24);                               \
		(b)[(i) + 1] = (uint8_t)((n) >> 16);                           \
		(b)[(i) + 2] = (uint8_t)((n) >> 8);                            \
		(b)[(i) + 3] = (uint8_t)((n));                                 \
	} while (0)

static void sha256_transform(uint32_t buf[8], uint8_t const data[64])
{
	uint32_t temp1, temp2, W[64];
	uint32_t A, B, C, D, E, F, G, H;

	GET_UINT32(W[0], data, 0);
	GET_UINT32(W[1], data, 4);
	GET_UINT32(W[2], data, 8);
	GET_UINT32(W[3], data, 12);
	GET_UINT32(W[4], data, 16);
	GET_UINT32(W[5], data, 20);
	GET_UINT32(W[6], data, 24);
	GET_UINT32(W[7], data, 28);
	GET_UINT32(W[8], data, 32);
	GET_UINT32(W[9], data, 36);
	GET_UINT32(W[10], data, 40);
	GET_UINT32(W[11], data, 44);
	GET_UINT32(W[12], data, 48);
	GET_UINT32(W[13], data, 52);
	GET_UINT32(W[14], data, 56);
	GET_UINT32(W[15], data, 60);

#define SHR(x, n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x, n) (SHR(x, n) | (x << (32 - n)))

#define S0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define S1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))
#define S2(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

#define F0(x, y, z) ((x & y) | (z & (x | y)))
#define F1(x, y, z) (z ^ (x & (y ^ z)))

#define R(t) (W[t] = S1(W[t - 2]) + W[t - 7] + S0(W[t - 15]) + W[t - 16])

#define P(a, b, c, d, e, f, g, h, x, K)                                        \
	do {                                                                   \
		temp1 = h + S3(e) + F1(e, f, g) + K + x;                       \
		temp2 = S2(a) + F0(a, b, c);                                   \
		d += temp1;                                                    \
		h = temp1 + temp2;                                             \
	} while (0)

	A = buf[0];
	B = buf[1];
	C = buf[2];
	D = buf[3];
	E = buf[4];
	F = buf[5];
	G = buf[6];
	H = buf[7];

	P(A, B, C, D, E, F, G, H, W[0], 0x428A2F98);
	P(H, A, B, C, D, E, F, G, W[1], 0x71374491);
	P(G, H, A, B, C, D, E, F, W[2], 0xB5C0FBCF);
	P(F, G, H, A, B, C, D, E, W[3], 0xE9B5DBA5);
	P(E, F, G, H, A, B, C, D, W[4], 0x3956C25B);
	P(D, E, F, G, H, A, B, C, W[5], 0x59F111F1);
	P(C, D, E, F, G, H, A, B, W[6], 0x923F82A4);
	P(B, C, D, E, F, G, H, A, W[7], 0xAB1C5ED5);
	P(A, B, C, D, E, F, G, H, W[8], 0xD807AA98);
	P(H, A, B, C, D, E, F, G, W[9], 0x12835B01);
	P(G, H, A, B, C, D, E, F, W[10], 0x243185BE);
	P(F, G, H, A, B, C, D, E, W[11], 0x550C7DC3);
	P(E, F, G, H, A, B, C, D, W[12], 0x72BE5D74);
	P(D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE);
	P(C, D, E, F, G, H, A, B, W[14], 0x9BDC06A7);
	P(B, C, D, E, F, G, H, A, W[15], 0xC19BF174);
	P(A, B, C, D, E, F, G, H, R(16), 0xE49B69C1);
	P(H, A, B, C, D, E, F, G, R(17), 0xEFBE4786);
	P(G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6);
	P(F, G, H, A, B, C, D, E, R(19), 0x240CA1CC);
	P(E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F);
	P(D, E, F, G, H, A, B, C, R(21), 0x4A7484AA);
	P(C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC);
	P(B, C, D, E, F, G, H, A, R(23), 0x76F988DA);
	P(A, B, C, D, E, F, G, H, R(24), 0x983E5152);
	P(H, A, B, C, D, E, F, G, R(25), 0xA831C66D);
	P(G, H, A, B, C, D, E, F, R(26), 0xB00327C8);
	P(F, G, H, A, B, C, D, E, R(27), 0xBF597FC7);
	P(E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3);
	P(D, E, F, G, H, A, B, C, R(29), 0xD5A79147);
	P(C, D, E, F, G, H, A, B, R(30), 0x06CA6351);
	P(B, C, D, E, F, G, H, A, R(31), 0x14292967);
	P(A, B, C, D, E, F, G, H, R(32), 0x27B70A85);
	P(H, A, B, C, D, E, F, G, R(33), 0x2E1B2138);
	P(G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC);
	P(F, G, H, A, B, C, D, E, R(35), 0x53380D13);
	P(E, F, G, H, A, B, C, D, R(36), 0x650A7354);
	P(D, E, F, G, H, A, B, C, R(37), 0x766A0ABB);
	P(C, D, E, F, G, H, A, B, R(38), 0x81C2C92E);
	P(B, C, D, E, F, G, H, A, R(39), 0x92722C85);
	P(A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1);
	P(H, A, B, C, D, E, F, G, R(41), 0xA81A664B);
	P(G, H, A, B, C, D, E, F, R(42), 0xC24B8B70);
	P(F, G, H, A, B, C, D, E, R(43), 0xC76C51A3);
	P(E, F, G, H, A, B, C, D, R(44), 0xD192E819);
	P(D, E, F, G, H, A, B, C, R(45), 0xD6990624);
	P(C, D, E, F, G, H, A, B, R(46), 0xF40E3585);
	P(B, C, D, E, F, G, H, A, R(47), 0x106AA070);
	P(A, B, C, D, E, F, G, H, R(48), 0x19A4C116);
	P(H, A, B, C, D, E, F, G, R(49), 0x1E376C08);
	P(G, H, A, B, C, D, E, F, R(50), 0x2748774C);
	P(F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5);
	P(E, F, G, H, A, B, C, D, R(52), 0x391C0CB3);
	P(D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A);
	P(C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F);
	P(B, C, D, E, F, G, H, A, R(55), 0x682E6FF3);
	P(A, B, C, D, E, F, G, H, R(56), 0x748F82EE);
	P(H, A, B, C, D, E, F, G, R(57), 0x78A5636F);
	P(G, H, A, B, C, D, E, F, R(58), 0x84C87814);
	P(F, G, H, A, B, C, D, E, R(59), 0x8CC70208);
	P(E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA);
	P(D, E, F, G, H, A, B, C, R(61), 0xA4506CEB);
	P(C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7);
	P(B, C, D, E, F, G, H, A, R(63), 0xC67178F2);

#undef SHR
#undef ROTR
#undef S0
#undef S1
#undef S2
#undef S3
#undef F0
#undef F1
#undef R
#undef P

	buf[0] += A;
	buf[1] += B;
	buf[2] += C;
	buf[3] += D;
	buf[4] += E;
	buf[5] += F;
	buf[6] += G;
	buf[7] += H;
}

static void sha256_sum_update(Sha256sum *sha256, const uint8_t *buffer, size_t length)
{
	uint32_t left, fill;
	const uint8_t *input = buffer;

	if (length == 0)
		return;

	left = sha256->bits[0] & 0x3F;
	fill = 64 - left;

	sha256->bits[0] += length;
	sha256->bits[0] &= 0xFFFFFFFF;

	if (sha256->bits[0] < length)
		sha256->bits[1]++;

	if (left > 0 && length >= fill) {
		memcpy((sha256->data + left), input, fill);

		sha256_transform(sha256->buf, sha256->data);
		length -= fill;
		input += fill;

		left = 0;
	}

	while (length >= SHA256_DATASIZE) {
		sha256_transform(sha256->buf, input);

		length -= 64;
		input += 64;
	}

	if (length)
		memcpy(sha256->data + left, input, length);
}

static uint8_t sha256_padding[64] = { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

static void sha256_sum_close(Sha256sum *sha256, uint8_t *digest)
{
	uint32_t last, padn;
	uint32_t high, low;
	uint8_t msglen[8];

	high = (sha256->bits[0] >> 29) | (sha256->bits[1] << 3);
	low = (sha256->bits[0] << 3);

	PUT_UINT32(high, msglen, 0);
	PUT_UINT32(low, msglen, 4);

	last = sha256->bits[0] & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	sha256_sum_update(sha256, sha256_padding, padn);
	sha256_sum_update(sha256, msglen, 8);

	PUT_UINT32(sha256->buf[0], digest, 0);
	PUT_UINT32(sha256->buf[1], digest, 4);
	PUT_UINT32(sha256->buf[2], digest, 8);
	PUT_UINT32(sha256->buf[3], digest, 12);
	PUT_UINT32(sha256->buf[4], digest, 16);
	PUT_UINT32(sha256->buf[5], digest, 20);
	PUT_UINT32(sha256->buf[6], digest, 24);
	PUT_UINT32(sha256->buf[7], digest, 28);
}

#undef PUT_UINT32
#undef GET_UINT32

#endif /* SHA256 fallback implementation */

#include "lcfs-internal.h" /* for endian.h */
#include "lcfs-fsverity.h"

struct fsverity_descriptor {
	uint8_t version;
	uint8_t hash_algorithm;
	uint8_t log_blocksize;
	uint8_t salt_size;
	uint32_t reserved1;
	uint64_t data_size_le;
	uint8_t root_hash[64];
	uint8_t salt[32];
	uint8_t reserved2[144];
};

#define FSVERITY_MAX_LEVELS 8 /* enough for 64bit file size */

struct FsVerityContext {
	uint8_t buffer[FSVERITY_MAX_LEVELS][FSVERITY_BLOCK_SIZE];
	uint32_t buffer_pos[FSVERITY_MAX_LEVELS];
	uint32_t max_level;
	uint64_t file_size;
#ifdef HAVE_OPENSSL
	EVP_MD_CTX *md_ctx;
#endif
};

FsVerityContext *lcfs_fsverity_context_new(void)
{
	FsVerityContext *ctx;

	ctx = calloc(1, sizeof(FsVerityContext));
	if (ctx == NULL)
		return NULL;

#ifdef HAVE_OPENSSL
	ctx->md_ctx = EVP_MD_CTX_create();
	if (ctx->md_ctx == NULL) {
		free(ctx);
		return NULL;
	}
#endif

	return ctx;
}

void lcfs_fsverity_context_free(FsVerityContext *ctx)
{
#ifdef HAVE_OPENSSL
	EVP_MD_CTX_destroy(ctx->md_ctx);
#endif
	free(ctx);
}

static void do_sha256(FsVerityContext *ctx, const uint8_t *data,
		      size_t data_len, uint8_t *digest)
{
#ifdef HAVE_OPENSSL
	const EVP_MD *md = EVP_sha256();
	int ret;

	assert(md != NULL);

	ret = EVP_DigestInit_ex(ctx->md_ctx, md, NULL);
	assert(ret == 1);

	ret = EVP_DigestUpdate(ctx->md_ctx, data, data_len);
	assert(ret == 1);

	ret = EVP_DigestFinal_ex(ctx->md_ctx, digest, NULL);
	assert(ret == 1);
#else
	Sha256sum sha256;

	sha256_sum_init(&sha256);
	sha256_sum_update(&sha256, data, data_len);
	sha256_sum_close(&sha256, digest);
#endif
}

static void lcfs_fsverity_context_update_level(FsVerityContext *ctx, uint8_t *data,
					       size_t data_len, uint32_t level)
{
	assert(level < FSVERITY_MAX_LEVELS);

	if (level > ctx->max_level)
		ctx->max_level = level;

	while (data_len > 0) {
		/* First check if block is already full, we want to do this lazyly
		   so we only flush to the next level if there is more data after
		   the block is full */
		if (ctx->buffer_pos[level] == FSVERITY_BLOCK_SIZE) {
			uint8_t digest[LCFS_SHA256_DIGEST_LEN];
			do_sha256(ctx, ctx->buffer[level], FSVERITY_BLOCK_SIZE,
				  digest);
			lcfs_fsverity_context_update_level(ctx, digest, 32,
							   level + 1);
			ctx->buffer_pos[level] = 0;
		}

		size_t to_copy =
			MIN(FSVERITY_BLOCK_SIZE - ctx->buffer_pos[level], data_len);

		memcpy(ctx->buffer[level] + ctx->buffer_pos[level], data, to_copy);
		ctx->buffer_pos[level] += to_copy;

		data += to_copy;
		data_len -= to_copy;
	}
}

void lcfs_fsverity_context_update(FsVerityContext *ctx, void *data, size_t data_len)
{
	lcfs_fsverity_context_update_level(ctx, data, data_len, 0);
	ctx->file_size += data_len;
}

static void lcfs_fsverity_context_flush_level(FsVerityContext *ctx, uint32_t level)
{
	uint8_t digest[LCFS_SHA256_DIGEST_LEN];

	if (ctx->buffer_pos[level] < FSVERITY_BLOCK_SIZE) {
		memset(ctx->buffer[level] + ctx->buffer_pos[level], 0,
		       FSVERITY_BLOCK_SIZE - ctx->buffer_pos[level]);
		ctx->buffer_pos[level] = FSVERITY_BLOCK_SIZE;
	}

	if (level == ctx->max_level)
		return;

	do_sha256(ctx, ctx->buffer[level], FSVERITY_BLOCK_SIZE, digest);
	lcfs_fsverity_context_update_level(ctx, digest, LCFS_SHA256_DIGEST_LEN,
					   level + 1);

	lcfs_fsverity_context_flush_level(ctx, level + 1);
}

void lcfs_fsverity_context_get_digest(FsVerityContext *ctx,
				      uint8_t digest[LCFS_SHA256_DIGEST_LEN])
{
	struct fsverity_descriptor descriptor;

	memset(&descriptor, 0, sizeof(descriptor));
	descriptor.version = 1;
	descriptor.hash_algorithm = 1;
	descriptor.log_blocksize = 12;
	descriptor.salt_size = 0;
	descriptor.data_size_le = htole64(ctx->file_size);

	/* An empty file has zero Merkle tree blocks, so per the fs-verity
	 * on-disk format root_hash stays all-zero (as set by the memset
	 * above). There is nothing to flush or hash in that case. */
	if (ctx->file_size > 0) {
		lcfs_fsverity_context_flush_level(ctx, 0);

		do_sha256(ctx, ctx->buffer[ctx->max_level], FSVERITY_BLOCK_SIZE,
			  descriptor.root_hash);
	}

	do_sha256(ctx, (uint8_t *)&descriptor, sizeof(descriptor), digest);
}
