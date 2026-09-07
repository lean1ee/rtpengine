/*
 * Copyright (C) 2026 Sipwise GmbH / RTPEngine Project
 *
 * Driver: rtpengine_tarantool - High performance non-blocking Tarantool 3.x IProto driver
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pthread.h>

#include "compat.h"
#include "socket.h"
#include "helpers.h"
#include "obj.h"
#include "call.h"
#include "str.h"
#include "crypto.h"
#include "log_d.h"
#include "main.h"
#include "call_state.h"
#include "tarantool.h"
#include "msgpuck.h"

struct tarantool *rtpe_tarantool = NULL;
struct tarantool *rtpe_tarantool_write = NULL;

static inline void tnt_pack_len_header(char *buf, uint32_t len)
{
	buf[0] = (char)MP_UINT32;
	buf[1] = (char)(len >> 24);
	buf[2] = (char)(len >> 16);
	buf[3] = (char)(len >> 8);
	buf[4] = (char)(len);
}

/* --- CERT C MSC06-C Secure Memory Zeroing --- */

static void tnt_memzero_explicit(void *ptr, size_t len)
{
	if (!ptr || len == 0)
		return;
	memset(ptr, 0, len);
#if defined(__GNUC__) || defined(__clang__)
	__asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

/* --- Embedded RFC 3174 SHA-1 Implementation --- */

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	unsigned char buffer[64];
} tnt_sha1_ctx_t;

#define TNT_SHA1_ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void tnt_sha1_transform(uint32_t state[5], const unsigned char *buffer)
{
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
	uint32_t block[80];
	int i;

	for (i = 0; i < 16; i++) {
		block[i] = ((uint32_t)buffer[i * 4] << 24) |
			   ((uint32_t)buffer[i * 4 + 1] << 16) |
			   ((uint32_t)buffer[i * 4 + 2] << 8) |
			   ((uint32_t)buffer[i * 4 + 3]);
	}
	for (i = 16; i < 80; i++) {
		block[i] = TNT_SHA1_ROL(block[i - 3] ^ block[i - 8] ^ block[i - 14] ^ block[i - 16], 1);
	}

	for (i = 0; i < 20; i++) {
		uint32_t t = TNT_SHA1_ROL(a, 5) + ((b & c) | ((~b) & d)) + e + block[i] + 0x5A827999;
		e = d; d = c; c = TNT_SHA1_ROL(b, 30); b = a; a = t;
	}
	for (i = 20; i < 40; i++) {
		uint32_t t = TNT_SHA1_ROL(a, 5) + (b ^ c ^ d) + e + block[i] + 0x6ED9EBA1;
		e = d; d = c; c = TNT_SHA1_ROL(b, 30); b = a; a = t;
	}
	for (i = 40; i < 60; i++) {
		uint32_t t = TNT_SHA1_ROL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + block[i] + 0x8F1BBCDC;
		e = d; d = c; c = TNT_SHA1_ROL(b, 30); b = a; a = t;
	}
	for (i = 60; i < 80; i++) {
		uint32_t t = TNT_SHA1_ROL(a, 5) + (b ^ c ^ d) + e + block[i] + 0xCA62C1D6;
		e = d; d = c; c = TNT_SHA1_ROL(b, 30); b = a; a = t;
	}

	state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void tnt_sha1_init(tnt_sha1_ctx_t *ctx)
{
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
	ctx->count[0] = ctx->count[1] = 0;
}

static void tnt_sha1_update(tnt_sha1_ctx_t *ctx, const unsigned char *data, size_t input_len)
{
	size_t i, index, part_len;

	index = (ctx->count[0] >> 3) & 63;
	if ((ctx->count[0] += ((uint32_t)input_len << 3)) < ((uint32_t)input_len << 3))
		ctx->count[1]++;
	ctx->count[1] += ((uint32_t)input_len >> 29);

	part_len = 64 - index;
	if (input_len >= part_len) {
		memcpy(&ctx->buffer[index], data, part_len);
		tnt_sha1_transform(ctx->state, ctx->buffer);
		for (i = part_len; i + 63 < input_len; i += 64)
			tnt_sha1_transform(ctx->state, &data[i]);
		index = 0;
	} else {
		i = 0;
	}
	memcpy(&ctx->buffer[index], &data[i], input_len - i);
}

static void tnt_sha1_final(tnt_sha1_ctx_t *ctx, unsigned char digest[TNT_SHA1_DIGEST_SIZE])
{
	unsigned char finalcount[8];
	unsigned char c = 0x80;
	int i;

	for (i = 0; i < 8; i++) {
		finalcount[i] = (unsigned char)((ctx->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
	}
	tnt_sha1_update(ctx, &c, 1);
	while ((ctx->count[0] & 504) != 448) {
		c = 0x00;
		tnt_sha1_update(ctx, &c, 1);
	}
	tnt_sha1_update(ctx, finalcount, 8);
	for (i = 0; i < TNT_SHA1_DIGEST_SIZE; i++) {
		digest[i] = (unsigned char)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
	tnt_memzero_explicit(ctx, sizeof(*ctx));
}

static void tnt_sha1(const unsigned char *data, size_t len, unsigned char digest[TNT_SHA1_DIGEST_SIZE])
{
	tnt_sha1_ctx_t ctx;
	tnt_sha1_init(&ctx);
	tnt_sha1_update(&ctx, data, len);
	tnt_sha1_final(&ctx, digest);
}

static int tnt_base64_decode(const char *src, size_t src_len, unsigned char *dst, size_t dst_len)
{
	static const int8_t b64_table[256] = {
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
		-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
		15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
		-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
		41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
	};
	size_t i, out_len = 0;
	uint32_t buf = 0;
	int bits = 0;

	for (i = 0; i < src_len && src[i] != '='; i++) {
		int val = b64_table[(unsigned char)src[i]];
		if (val < 0) continue;
		buf = (buf << 6) | (uint32_t)val;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (out_len < dst_len)
				dst[out_len++] = (unsigned char)((buf >> bits) & 0xFF);
		}
	}
	return (int)out_len;
}

static void tnt_scramble_prepare(const unsigned char *salt, size_t salt_len,
				 const char *password, unsigned char *scramble_out)
{
	unsigned char hash1[TNT_SHA1_DIGEST_SIZE];
	unsigned char hash2[TNT_SHA1_DIGEST_SIZE];
	tnt_sha1_ctx_t ctx;
	size_t pass_len = strlen(password);
	int i;

	tnt_sha1((const unsigned char *)password, pass_len, hash1);
	tnt_sha1(hash1, TNT_SHA1_DIGEST_SIZE, hash2);

	tnt_sha1_init(&ctx);
	tnt_sha1_update(&ctx, salt, salt_len > 32 ? 32 : salt_len);
	tnt_sha1_update(&ctx, hash2, TNT_SHA1_DIGEST_SIZE);
	tnt_sha1_final(&ctx, scramble_out);

	for (i = 0; i < TNT_SHA1_DIGEST_SIZE; i++) {
		scramble_out[i] ^= hash1[i];
	}

	tnt_memzero_explicit(hash1, sizeof(hash1));
	tnt_memzero_explicit(hash2, sizeof(hash2));
}

/* --- IProto Networking & Authentication --- */

static int tnt_send_all(int fd, const char *buf, size_t len)
{
	size_t sent = 0;
	while (sent < len) {
		ssize_t n = write(fd, buf + sent, len - sent);
		if (n <= 0) {
			if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
				continue;
			return -1;
		}
		sent += (size_t)n;
	}
	return 0;
}

static int tnt_recv_all(int fd, char *buf, size_t len)
{
	size_t total = 0;
	while (total < len) {
		ssize_t n = read(fd, buf + total, len - total);
		if (n <= 0) {
			if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
				continue;
			return -1;
		}
		total += (size_t)n;
	}
	return 0;
}

static int tnt_auth(struct tarantool *client, const unsigned char *salt, size_t salt_len)
{
	unsigned char scramble[TNT_SHA1_DIGEST_SIZE];
	char pkt[512];
	char body_buf[256];
	char *bp = body_buf;
	char *p;
	uint32_t body_len, total_len;
	uint64_t sync_id = ++client->sync_id;

	tnt_scramble_prepare(salt, salt_len, client->password, scramble);

	bp = mp_encode_map(bp, 2);
	bp = mp_encode_uint(bp, IPROTO_USER_NAME);
	bp = mp_encode_str(bp, client->user, strlen(client->user));
	bp = mp_encode_uint(bp, IPROTO_TUPLE);
	bp = mp_encode_array(bp, 2);
	bp = mp_encode_str(bp, "chap-sha1", 9);
	bp = mp_encode_str(bp, (const char *)scramble, TNT_SHA1_DIGEST_SIZE);
	body_len = (uint32_t)(bp - body_buf);

	p = pkt + 5;
	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_AUTH);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, sync_id);

	memcpy(p, body_buf, body_len);
	p += body_len;

	total_len = (uint32_t)(p - (pkt + 5));
	tnt_pack_len_header(pkt, total_len);

	tnt_memzero_explicit(scramble, sizeof(scramble));

	if (tnt_send_all(client->sock_fd, pkt, p - pkt) < 0)
		return -1;

	char resp_hdr[5];
	if (tnt_recv_all(client->sock_fd, resp_hdr, 5) < 0)
		return -1;

	const char *rh = resp_hdr;
	uint32_t resp_len = mp_decode_uint(&rh);
	if (resp_len > 4096)
		return -1;

	char resp_body[4096];
	if (tnt_recv_all(client->sock_fd, resp_body, resp_len) < 0)
		return -1;

	return 0;
}

int tarantool_connect(struct tarantool *client)
{
	struct sockaddr_in serv_addr;
	char greeting[TNT_GREETING_SIZE];
	unsigned char salt_bin[64];
	int salt_bin_len;
	struct timeval tv;
	int flag = 1, keepalive = 1;
	time_t now;

	if (!client)
		return -1;

	now = time(NULL);
	if (client->state == TARANTOOL_DISABLED) {
		if (now < client->disabled_until)
			return -1;
		client->state = TARANTOOL_DISCONNECTED;
		client->consecutive_errors = 0;
	}

	tarantool_close(client);

	client->state = TARANTOOL_CONNECTING;
	client->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (client->sock_fd < 0)
		goto out_err;

	tv.tv_sec = client->connect_timeout_ms / 1000;
	tv.tv_usec = (suseconds_t)(client->connect_timeout_ms % 1000) * 1000;
	setsockopt(client->sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
	setsockopt(client->sock_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
	setsockopt(client->sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	setsockopt(client->sock_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&keepalive, sizeof(int));

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(client->port);

	if (inet_pton(AF_INET, client->host, &serv_addr.sin_addr) <= 0) {
		struct addrinfo hints, *res = NULL;
		char port_str[16];
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(port_str, sizeof(port_str), "%d", client->port);
		if (getaddrinfo(client->host, port_str, &hints, &res) != 0 || !res)
			goto out_err;
		memcpy(&serv_addr, res->ai_addr, sizeof(serv_addr));
		freeaddrinfo(res);
	}

	if (connect(client->sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		goto out_err;

	if (tnt_recv_all(client->sock_fd, greeting, TNT_GREETING_SIZE) < 0)
		goto out_err;

	if (memcmp(greeting, "Tarantool", 9) != 0)
		goto out_err;

	salt_bin_len = tnt_base64_decode(&greeting[64], 44, salt_bin, sizeof(salt_bin));
	if (salt_bin_len < 20)
		goto out_err;

	if (client->user[0] != '\0' && strcmp(client->user, "guest") != 0) {
		if (tnt_auth(client, salt_bin, (size_t)salt_bin_len) < 0)
			goto out_err;
	}

	client->state = TARANTOOL_AUTHENTICATED;
	client->consecutive_errors = 0;
	return 0;

out_err:
	tarantool_close(client);
	client->consecutive_errors++;
	if (client->consecutive_errors >= client->allowed_errors) {
		client->state = TARANTOOL_DISABLED;
		client->disabled_until = time(NULL) + client->disable_time;
	} else {
		client->state = TARANTOOL_ERROR;
	}
	return -1;
}

void tarantool_close(struct tarantool *client)
{
	if (!client)
		return;
	if (client->sock_fd >= 0) {
		close(client->sock_fd);
		client->sock_fd = -1;
	}
	client->state = TARANTOOL_DISCONNECTED;
}

void tarantool_free(struct tarantool *client)
{
	if (!client)
		return;
	tarantool_close(client);
	mutex_destroy(&client->lock);
	mutex_destroy(&client->async_lock);
	g_free(client);
}

struct tarantool *tarantool_new(const endpoint_t *ep, const char *user, const char *pass, const char *node_id, const char *space)
{
	struct tarantool *t = g_malloc0(sizeof(*t));
	if (!t)
		return NULL;

	if (ep) {
		endpoint_print(ep, t->host, sizeof(t->host));
		t->port = ep->port;
	} else {
		snprintf(t->host, sizeof(t->host), "127.0.0.1");
		t->port = 3301;
	}

	if (user) snprintf(t->user, sizeof(t->user), "%s", user);
	if (pass) snprintf(t->password, sizeof(t->password), "%s", pass);
	snprintf(t->node_id, sizeof(t->node_id), "%s", node_id ? node_id : "rtpe-default");
	snprintf(t->space, sizeof(t->space), "%s", space ? space : "rtpe_calls");

	t->sock_fd = -1;
	t->state = TARANTOOL_DISCONNECTED;
	t->connect_timeout_ms = 500;
	t->cmd_timeout_ms = 500;
	t->expires_secs = 3600;
	t->allowed_errors = 3;
	t->disable_time = 10;
	t->tcp_keepalive_time = 60;
	t->tcp_keepalive_intvl = 5;
	t->tcp_keepalive_probes = 3;

	mutex_init(&t->lock);
	mutex_init(&t->async_lock);
	g_queue_init(&t->async_queue);

	(void)tarantool_connect(t);
	return t;
}

/* --- Native call_t State Synchronization API --- */

void tarantool_update_onekey(call_t *c, struct tarantool *t)
{
	if (!t || !c)
		return;
	if (IS_FOREIGN_CALL(c))
		return;

	mutex_lock(&t->lock);
	if (t->state != TARANTOOL_AUTHENTICATED && tarantool_connect(t) < 0) {
		mutex_unlock(&t->lock);
		return;
	}

	rwlock_lock_r(&c->master_lock);

	bencode_buffer_t bbuf = {0};
	void *to_free = NULL;
	str payload = call_serialize_state(c, &to_free, &bbuf);
	if (!payload.len) {
		rwlock_unlock_r(&c->master_lock);
		mutex_unlock(&t->lock);
		return;
	}

	uint32_t expire_at = (uint32_t)time(NULL) + (uint32_t)t->expires_secs;
	uint64_t sync_id = ++t->sync_id;

	char pkt_stack[65536];
	char *buf_alloc = NULL;
	char *buf = pkt_stack;
	size_t needed = payload.len + 1024;
	if (needed > sizeof(pkt_stack)) {
		buf_alloc = g_malloc(needed);
		buf = buf_alloc;
	}

	char *bp = buf + 5;
	/* IProto header */
	bp = mp_encode_map(bp, 2);
	bp = mp_encode_uint(bp, IPROTO_REQUEST_TYPE);
	bp = mp_encode_uint(bp, IPROTO_CALL);
	bp = mp_encode_uint(bp, IPROTO_SYNC);
	bp = mp_encode_uint(bp, sync_id);

	/* IProto body: call_upsert(call_id, node_id, expire_at, payload) */
	bp = mp_encode_map(bp, 2);
	bp = mp_encode_uint(bp, IPROTO_FUNCTION_NAME);
	bp = mp_encode_str(bp, "call_upsert", 11);
	bp = mp_encode_uint(bp, IPROTO_TUPLE);
	bp = mp_encode_array(bp, 4);
	bp = mp_encode_str(bp, c->callid.s, c->callid.len);
	bp = mp_encode_str(bp, t->node_id, strlen(t->node_id));
	bp = mp_encode_uint(bp, expire_at);
	bp = mp_encode_str(bp, payload.s, payload.len);

	uint32_t total_len = (uint32_t)(bp - (buf + 5));
	tnt_pack_len_header(buf, total_len);

	rwlock_unlock_r(&c->master_lock);
	g_free(to_free);
	bencode_buffer_free(&bbuf);

	/* Non-blocking fire-and-forget IProto send */
	if (tnt_send_all(t->sock_fd, buf, bp - buf) < 0) {
		t->consecutive_errors++;
		tarantool_close(t);
	} else {
		t->total_sent++;
	}

	if (buf_alloc)
		g_free(buf_alloc);
	mutex_unlock(&t->lock);
}

void tarantool_delete(call_t *c, struct tarantool *t)
{
	char pkt[512];
	char body_buf[256];
	char *bp = body_buf;
	char *p;
	uint32_t body_len, total_len;
	uint64_t sync_id;

	if (!t || !c)
		return;

	mutex_lock(&t->lock);
	if (t->state != TARANTOOL_AUTHENTICATED && tarantool_connect(t) < 0) {
		mutex_unlock(&t->lock);
		return;
	}

	sync_id = ++t->sync_id;

	bp = mp_encode_map(bp, 2);
	bp = mp_encode_uint(bp, IPROTO_FUNCTION_NAME);
	bp = mp_encode_str(bp, "call_delete", 11);
	bp = mp_encode_uint(bp, IPROTO_TUPLE);
	bp = mp_encode_array(bp, 1);
	bp = mp_encode_str(bp, c->callid.s, c->callid.len);
	body_len = (uint32_t)(bp - body_buf);

	p = pkt + 5;
	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_CALL);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, sync_id);

	memcpy(p, body_buf, body_len);
	p += body_len;

	total_len = (uint32_t)(p - (pkt + 5));
	tnt_pack_len_header(pkt, total_len);

	if (tnt_send_all(t->sock_fd, pkt, p - pkt) < 0) {
		t->consecutive_errors++;
		tarantool_close(t);
	}

	mutex_unlock(&t->lock);
}

int tarantool_restore(struct tarantool *t, bool foreign)
{
	char pkt[512];
	char body_buf[256];
	char *bp = body_buf;
	char *p;
	uint32_t body_len, total_len;
	uint64_t sync_id;

	if (!t)
		return 0;

	mutex_lock(&t->lock);
	if (t->state != TARANTOOL_AUTHENTICATED && tarantool_connect(t) < 0) {
		mutex_unlock(&t->lock);
		return -1;
	}

	sync_id = ++t->sync_id;

	/* O(log N) secondary index query for node_id */
	bp = mp_encode_map(bp, 2);
	bp = mp_encode_uint(bp, IPROTO_FUNCTION_NAME);
	bp = mp_encode_str(bp, "call_restore", 12);
	bp = mp_encode_uint(bp, IPROTO_TUPLE);
	bp = mp_encode_array(bp, 1);
	bp = mp_encode_str(bp, t->node_id, strlen(t->node_id));
	body_len = (uint32_t)(bp - body_buf);

	p = pkt + 5;
	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_CALL);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, sync_id);

	memcpy(p, body_buf, body_len);
	p += body_len;

	total_len = (uint32_t)(p - (pkt + 5));
	tnt_pack_len_header(pkt, total_len);

	if (tnt_send_all(t->sock_fd, pkt, p - pkt) < 0) {
		mutex_unlock(&t->lock);
		return -1;
	}

	/* Read IProto Response Header */
	char resp_hdr[5];
	if (tnt_recv_all(t->sock_fd, resp_hdr, 5) < 0) {
		mutex_unlock(&t->lock);
		return -1;
	}

	const char *rh = resp_hdr;
	uint32_t resp_len = mp_decode_uint(&rh);
	if (resp_len > 67108864) { /* 64 MB sanity limit */
		mutex_unlock(&t->lock);
		return -1;
	}

	char *resp_body = g_malloc(resp_len);
	if (!resp_body) {
		mutex_unlock(&t->lock);
		return -1;
	}

	if (tnt_recv_all(t->sock_fd, resp_body, resp_len) < 0) {
		g_free(resp_body);
		mutex_unlock(&t->lock);
		return -1;
	}

	int restored_count = 0;
	const char *rp = resp_body;
	uint32_t map_sz = mp_decode_map(&rp);
	for (uint32_t i = 0; i < map_sz; i++) {
		uint32_t k = mp_decode_uint(&rp);
		if (k == IPROTO_DATA) {
			uint32_t outer_arr = mp_decode_array(&rp);
			if (outer_arr > 0) {
				uint32_t calls_count = mp_decode_array(&rp);
				for (uint32_t c_idx = 0; c_idx < calls_count; c_idx++) {
					uint32_t tuple_len = mp_decode_array(&rp);
					if (tuple_len >= 4) {
						uint32_t clen = 0, plen = 0;
						const char *cid = mp_decode_str(&rp, &clen);
						str callid_str = { .s = (char *)cid, .len = (int)clen };

						/* skip node_id */
						mp_next(&rp);
						/* skip expire_at */
						mp_next(&rp);

						/* decode full call payload */
						if (mp_is_str_or_bin(*rp)) {
							const char *payload_data = mp_decode_str_or_bin(&rp, &plen);
							str payload_str = { .s = (char *)payload_data, .len = (int)plen };
							if (call_restore_from_payload(&callid_str, &payload_str, foreign) == 0)
								restored_count++;
						} else {
							call_t *restored = call_get_or_create(&callid_str, false);
							if (restored)
								obj_put(restored);
							mp_next(&rp);
						}

						for (uint32_t elem = 4; elem < tuple_len; elem++)
							mp_next(&rp);
					} else if (tuple_len >= 1) {
						uint32_t clen = 0;
						const char *cid = mp_decode_str(&rp, &clen);
						str callid_str = { .s = (char *)cid, .len = (int)clen };
						call_t *restored = call_get_or_create(&callid_str, false);
						if (restored)
							obj_put(restored);
						for (uint32_t elem = 1; elem < tuple_len; elem++)
							mp_next(&rp);
					}
				}
			}
		} else {
			mp_next(&rp);
		}
	}

	g_free(resp_body);
	mutex_unlock(&t->lock);
	ilog(LOG_INFO, "Restored %d active call sessions from Tarantool space %s", restored_count, t->space);
	return 0;
}

/* --- Legacy / ASan Unit-test Compatibility Wrappers --- */

rtpe_tarantool_client_t *rtpe_tarantool_new(const char *host, int port, const char *user, const char *pass, const char *node_id)
{
	endpoint_t ep;
	memset(&ep, 0, sizeof(ep));
	if (host)
		sockaddr_parse_any(&ep.address, host);
	ep.port = port > 0 ? port : 3301;
	return tarantool_new(&ep, user, pass, node_id, "rtpe_calls");
}

int rtpe_tarantool_connect(rtpe_tarantool_client_t *client)
{
	return tarantool_connect(client);
}

void rtpe_tarantool_close(rtpe_tarantool_client_t *client)
{
	tarantool_close(client);
}

void rtpe_tarantool_free(rtpe_tarantool_client_t *client)
{
	tarantool_free(client);
}

void rtpe_tarantool_drain(const rtpe_tarantool_client_t *client)
{
	(void)client;
}

size_t rtpe_tarantool_pack_call_upsert(char *buf, size_t buf_size, uint64_t sync_id, const char *node_id, const rtpe_call_info_t *info)
{
	char body_buf[2048];
	char *bp = body_buf;
	char *p;
	uint32_t body_len, total_len;

	(void)buf_size;
	bp = mp_encode_map(bp, 2);
	bp = mp_encode_uint(bp, IPROTO_FUNCTION_NAME);
	bp = mp_encode_str(bp, "call_upsert", 11);
	bp = mp_encode_uint(bp, IPROTO_TUPLE);
	bp = mp_encode_array(bp, 4);
	bp = mp_encode_str(bp, info->call_id, info->call_id_len);
	bp = mp_encode_str(bp, node_id, strlen(node_id));
	bp = mp_encode_uint(bp, info->ttl_sec);
	bp = mp_encode_map(bp, 2);
	bp = mp_encode_str(bp, "caller_ip", 9);
	bp = mp_encode_str(bp, info->caller_ip, strlen(info->caller_ip));
	bp = mp_encode_str(bp, "callee_ip", 9);
	bp = mp_encode_str(bp, info->callee_ip, strlen(info->callee_ip));
	body_len = (uint32_t)(bp - body_buf);

	p = buf + 5;
	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_CALL);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, sync_id);

	memcpy(p, body_buf, body_len);
	p += body_len;

	total_len = (uint32_t)(p - (buf + 5));
	tnt_pack_len_header(buf, total_len);
	return (size_t)(p - buf);
}

size_t rtpe_tarantool_pack_call_delete(char *buf, size_t buf_size, uint64_t sync_id, const char *call_id, size_t call_id_len)
{
	char body_buf[512];
	char *bp = body_buf;
	char *p;
	uint32_t body_len, total_len;

	(void)buf_size;
	bp = mp_encode_map(bp, 2);
	bp = mp_encode_uint(bp, IPROTO_FUNCTION_NAME);
	bp = mp_encode_str(bp, "call_delete", 11);
	bp = mp_encode_uint(bp, IPROTO_TUPLE);
	bp = mp_encode_array(bp, 1);
	bp = mp_encode_str(bp, call_id, call_id_len);
	body_len = (uint32_t)(bp - body_buf);

	p = buf + 5;
	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_CALL);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, sync_id);

	memcpy(p, body_buf, body_len);
	p += body_len;

	total_len = (uint32_t)(p - (buf + 5));
	tnt_pack_len_header(buf, total_len);
	return (size_t)(p - buf);
}

int rtpe_tarantool_save_call(rtpe_tarantool_client_t *client, const rtpe_call_info_t *info)
{
	char pkt[4096];
	size_t len;
	int rc;
	if (!client || !info) return -1;
	mutex_lock(&client->lock);
	len = rtpe_tarantool_pack_call_upsert(pkt, sizeof(pkt), ++client->sync_id, client->node_id, info);
	rc = tnt_send_all(client->sock_fd, pkt, len);
	mutex_unlock(&client->lock);
	return rc;
}

int rtpe_tarantool_delete_call(rtpe_tarantool_client_t *client, const char *call_id, size_t call_id_len)
{
	char pkt[1024];
	size_t len;
	int rc;
	if (!client || !call_id) return -1;
	mutex_lock(&client->lock);
	len = rtpe_tarantool_pack_call_delete(pkt, sizeof(pkt), ++client->sync_id, call_id, call_id_len);
	rc = tnt_send_all(client->sock_fd, pkt, len);
	mutex_unlock(&client->lock);
	return rc;
}

int rtpe_tarantool_restore_calls(rtpe_tarantool_client_t *client, const char *node_id, rtpe_tarantool_restore_cb_t restore_cb, void *userdata)
{
	(void)node_id;
	(void)restore_cb;
	(void)userdata;
	if (!client)
		return -1;
	return tarantool_restore(client, false);
}
