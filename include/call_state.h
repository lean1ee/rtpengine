/*
 * Copyright (C) 2026 Sipwise GmbH / RTPEngine Project
 *
 * call_state.h - Core Call State Serialization, Restoration, and Snapshots
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTPE_CALL_STATE_H
#define RTPE_CALL_STATE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <glib.h>

#include "str.h"
#include "bencode.h"
#include "crypto.h"
#include "control_ng.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct call;
typedef struct call call_t;
struct call_monologue;
struct dtls_fingerprint;
struct codec_store;

struct call_state_hash {
	GHashTable *ht;
};

struct call_state_list {
	unsigned int len;
	struct call_state_hash *rh;
	void **ptrs;
};

#ifndef redis_hash
#define redis_hash call_state_hash
#endif
#ifndef redis_list
#define redis_list call_state_list
#endif

/* Serialization & Restoration of Call State */
str call_serialize_state(call_t *c, void **to_free, bencode_buffer_t *bbuf);
int call_restore_from_payload(const str *callid, const str *payload, bool foreign);

/* Port release coordination between restore and allocation */
void call_ports_release_push(bool inc);
void call_ports_release_pop(bool inc);

#ifndef redis_ports_release_push
#define redis_ports_release_push call_ports_release_push
#endif
#ifndef redis_ports_release_pop
#define redis_ports_release_pop call_ports_release_pop
#endif

/* In-memory Call State Snapshots & Rollback */
str call_snapshot_encode(call_t *c, struct call_monologue *ml);
void call_snapshot_free(str *snap);
bool call_snapshot_apply(call_t *c, struct call_monologue *a, struct call_monologue *b);

#ifndef redis_snapshot_encode
#define redis_snapshot_encode call_snapshot_encode
#endif
#ifndef redis_snapshot_free
#define redis_snapshot_free call_snapshot_free
#endif
#ifndef redis_snapshot_apply
#define redis_snapshot_apply call_snapshot_apply
#endif

/* Core parser decoders */
int redis_decode_sdes_params(sdes_q *, const struct redis_hash *, const char *);
int redis_decode_dtls_fingerprint(struct dtls_fingerprint *, const struct redis_hash *);
int redis_hash_from_parser(struct redis_hash *, const ng_parser_t *, parser_arg);
void redis_hash_destroy(struct redis_hash *);
void redis_encode_codec_store(const ng_parser_t *, parser_arg, const struct codec_store *);
int redis_decode_codec_store(const ng_parser_t *, parser_arg, struct codec_store *);

#ifdef __cplusplus
}
#endif

#endif /* RTPE_CALL_STATE_H */
