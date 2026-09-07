/*
 * Copyright (C) 2026 Sipwise GmbH / RTPEngine Project
 *
 * tarantool.h - Header for RTPEngine Tarantool IProto driver
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTPE_TARANTOOL_H
#define RTPE_TARANTOOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define RTPE_MUST_CHECK __attribute__((warn_unused_result))
#else
#define RTPE_MUST_CHECK
#endif

/* Forward declarations */
struct call;
typedef struct call call_t;
struct endpoint;
typedef struct endpoint endpoint_t;
struct event_base;

/* IProto Request Types */
#define IPROTO_OK               0
#define IPROTO_SELECT           1
#define IPROTO_INSERT           2
#define IPROTO_REPLACE          3
#define IPROTO_UPDATE           4
#define IPROTO_DELETE           5
#define IPROTO_CALL             6
#define IPROTO_AUTH             7
#define IPROTO_EVAL             8
#define IPROTO_UPSERT           9

/* IProto Keys */
#define IPROTO_REQUEST_TYPE     0x00
#define IPROTO_SYNC             0x01
#define IPROTO_SPACE_ID         0x10
#define IPROTO_INDEX_ID         0x11
#define IPROTO_LIMIT            0x12
#define IPROTO_OFFSET           0x13
#define IPROTO_ITERATOR         0x14
#define IPROTO_KEY              0x20
#define IPROTO_TUPLE            0x21
#define IPROTO_FUNCTION_NAME    0x22
#define IPROTO_USER_NAME        0x23
#define IPROTO_EXPR             0x27
#define IPROTO_OPS              0x28
#define IPROTO_DATA             0x30
#define IPROTO_ERROR_24         0x31

#define TNT_GREETING_SIZE       128
#define TNT_SHA1_DIGEST_SIZE    20

/**
 * enum rtpe_tnt_state - Driver connection state machine
 */
typedef enum {
	TARANTOOL_DISCONNECTED = 0,
	TARANTOOL_CONNECTING,
	TARANTOOL_AUTHENTICATED,
	TARANTOOL_DISABLED,
	TARANTOOL_ERROR
} rtpe_tnt_state_t;

/**
 * struct tarantool - Tarantool client connection instance
 */
struct tarantool {
	char                 host[128];
	int                  port;
	char                 user[64];
	char                 password[64];
	char                 space[64];
	char                 node_id[64];

	int                  sock_fd;
	rtpe_tnt_state_t     state;
	pthread_mutex_t      lock;

	struct event_base   *async_ev;
	pthread_mutex_t      async_lock;
	GQueue               async_queue;

	uint64_t             sync_id;
	uint64_t             total_sent;
	uint64_t             total_errors;
	int                  consecutive_errors;
	int                  allowed_errors;
	time_t               disabled_until;
	int                  disable_time;
	int                  connect_timeout_ms;
	int                  cmd_timeout_ms;
	int                  expires_secs;
	int                  tcp_keepalive_time;
	int                  tcp_keepalive_intvl;
	int                  tcp_keepalive_probes;
};

typedef struct tarantool rtpe_tarantool_client_t;

extern struct tarantool *rtpe_tarantool;
extern struct tarantool *rtpe_tarantool_write;

/* Driver Lifecycle API */
struct tarantool *tarantool_new(const endpoint_t *ep, const char *user, const char *pass, const char *node_id, const char *space);
void tarantool_close(struct tarantool *t);
void tarantool_free(struct tarantool *t);
int  tarantool_connect(struct tarantool *t);

/* Native call_t state synchronization API */
void tarantool_update_onekey(call_t *c, struct tarantool *t);
void tarantool_delete(call_t *c, struct tarantool *t);
int  tarantool_restore(struct tarantool *t, bool foreign) RTPE_MUST_CHECK;

/* Legacy / Unit test compatibility helpers */
typedef struct rtpe_call_info {
	const char *call_id;
	size_t      call_id_len;
	const char *node_id;
	const char *caller_ip;
	int         caller_port;
	const char *callee_ip;
	int         callee_port;
	const char *srtp_suite;
	const char *crypto_key;
	uint32_t    ttl_sec;
} rtpe_call_info_t;

typedef int (*rtpe_tarantool_restore_cb_t)(const rtpe_call_info_t *call, void *userdata);

rtpe_tarantool_client_t *rtpe_tarantool_new(const char *host, int port, const char *user, const char *pass, const char *node_id);
int  rtpe_tarantool_connect(rtpe_tarantool_client_t *client) RTPE_MUST_CHECK;
int  rtpe_tarantool_save_call(rtpe_tarantool_client_t *client, const rtpe_call_info_t *info) RTPE_MUST_CHECK;
int  rtpe_tarantool_delete_call(rtpe_tarantool_client_t *client, const char *call_id, size_t call_id_len) RTPE_MUST_CHECK;
int  rtpe_tarantool_restore_calls(rtpe_tarantool_client_t *client, const char *node_id, rtpe_tarantool_restore_cb_t restore_cb, void *userdata) RTPE_MUST_CHECK;
void rtpe_tarantool_drain(const rtpe_tarantool_client_t *client);
void rtpe_tarantool_close(rtpe_tarantool_client_t *client);
void rtpe_tarantool_free(rtpe_tarantool_client_t *client);

size_t rtpe_tarantool_pack_call_upsert(char *buf, size_t buf_size, uint64_t sync_id, const char *node_id, const rtpe_call_info_t *info);
size_t rtpe_tarantool_pack_call_delete(char *buf, size_t buf_size, uint64_t sync_id, const char *call_id, size_t call_id_len);

#ifdef __cplusplus
}
#endif

#endif /* RTPE_TARANTOOL_H */
