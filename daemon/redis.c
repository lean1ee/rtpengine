#include "call_state.h"
#include "redis.h"
#include <stdio.h>
#include <hiredis/hiredis.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <glib.h>
#include <stdarg.h>
#include <ctype.h>
#include <glib.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libevent.h>
#include <event2/thread.h>
#include <stdlib.h>
#include <glib-object.h>
#include <json-glib/json-glib.h>
#include <inttypes.h>
#include <stdbool.h>

#include "compat.h"
#include "helpers.h"
#include "call.h"
#include "ice.h"
#include "log_d.h"
#include "str.h"
#include "crypto.h"
#include "dtls.h"
#include "recording.h"
#include "rtplib.h"
#include "str.h"
#include "ssrc.h"
#include "main.h"
#include "codec.h"
#include "sdp.h"

typedef union {
	GQueue *q;
	stream_fd_q *sfds_q;
	medias_arr *ma;
	sfd_intf_list_q *siq;
	packet_stream_q *psq;
	endpoint_map_q *emq;
} callback_arg_t __attribute__ ((__transparent_union__));


struct redis		*rtpe_redis;
struct redis		*rtpe_redis_write;
struct redis		*rtpe_redis_write_disabled;
struct redis		*rtpe_redis_notify;





INLINE redisReply *redis_expect(int type, redisReply *r) {
	if (!r)
		return NULL;
	if (r->type != type) {
		freeReplyObject(r);
		return NULL;
	}
	return r;
}

#if __YCM

/* format checking in YCM editor */

INLINE void redis_pipe(struct redis *r, const char *fmt, ...)
	__attribute__((format(printf,2,3)));
INLINE redisReply *redis_get(struct redis *r, int type, const char *fmt, ...)
	__attribute__((format(printf,3,4)));
static int redisCommandNR(redisContext *r, const char *fmt, ...)
	__attribute__((format(printf,2,3)));

#define PB "%.*s"
#define PBSTR(x) (int) (x)->len, (x)->s
#define STR_R(x) (int) (x)->len, (x)->str
#define S_LEN(s,l) (int) (l), (s)

#else

#define PB "%b"
#define PBSTR(x) (x)->s, (size_t) (x)->len
#define STR_R(x) (x)->str, (size_t) (x)->len
#define S_LEN(s,l) (s), (size_t) (l)

#endif

#define REDIS_FMT(x) (int) (x)->len, (x)->str

#define rlog(l, x...) ilog(l | LOG_FLAG_RESTORE, x)



// To protect against a restore race condition: Keyspace notifications are set up
// before existing calls are restored (restore_thread). Therefore the following
// scenario is possible:
// NOTIF THREAD:   receives SET, creates call
// RESTORE THREAD: executes KEYS *
// NOTIF THREAD:   receives another SET:
// NOTIF THREAD:      does call_destroy(), which:
//                       adds ports to late-release list
// RESTORE THREAD: comes across call ID, does GET
// RESTORE THREAD: creates new call
// RESTORE THREAD: wants to allocate ports, but they're still in use
// NOTIF THREAD:   now does release_closed_sockets()
/* Port release coordination now provided by call_state.h */
static int redis_check_conn(struct redis *r);
static void json_restore_call(struct redis *r, const str *id, bool foreign);
static int redis_connect(struct redis *r, int wait, bool resolve);
static void redis_do_delete(call_t *c, struct redis *r);

static void redis_pipe(struct redis *r, const char *fmt, ...) {
	va_list ap;

	if (!r->ctx) {
		ilog(LOG_ERROR, "Unable to pipe redis command. No redis context");
		return;
	}
	va_start(ap, fmt);
	redisvAppendCommand(r->ctx, fmt, ap);
	va_end(ap);
	r->pipeline++;
}
static redisReply *redis_get(struct redis *r, int type, const char *fmt, ...) {
	va_list ap;
	redisReply *ret;

	if (!r->ctx) {
		ilog(LOG_ERROR, "Unable to get redis reply. No redis context");
		return NULL;
	}
	va_start(ap, fmt);
	ret = redis_expect(type, redisvCommand(r->ctx, fmt, ap));
	va_end(ap);

	return ret;
}
static int redisCommandNR(redisContext *r, const char *fmt, ...) {
	va_list ap;
	redisReply *ret;
	int i = 0;

	if (!r) {
		ilog(LOG_ERROR, "Unable to send redis command. No redis context");
		return -1;
	}
	va_start(ap, fmt);
	ret = redisvCommand(r, fmt, ap);
	va_end(ap);

	if (!ret)
		return -1;

	if (ret->type == REDIS_REPLY_ERROR) {
		i = -1;
		ilog(LOG_WARNING, "Redis returned error to command '%s': %s", fmt, ret->str);
	}

	freeReplyObject(ret);
	return i;
}


/* called with r->lock held */
static int redis_check_type(struct redis *r, char *key, char *suffix, char *type) {
	redisReply *rp;

	if (!r->ctx) {
		ilog(LOG_ERROR, "Unable to check redis reply type. No redis context");
		return -1;
	}

	rp = redisCommand(r->ctx, "TYPE %s%s", key, suffix ? : "");
	if (!rp)
		return -1;
	if (rp->type != REDIS_REPLY_STATUS) {
		freeReplyObject(rp);
		return -1;
	}
	if (strcmp(rp->str, type) && strcmp(rp->str, "none"))
		redisCommandNR(r->ctx, "DEL %s%s", key, suffix ? : "");
	freeReplyObject(rp);
	return 0;
}


/* called with r->lock held */
static void redis_consume(struct redis *r) {
	redisReply *rp;

	if (!r->ctx) {
		ilog(LOG_ERROR, "Unable to consume pipelined replies. No redis context");
		r->pipeline = 0;
		return;
	}
	while (r->pipeline) {
		if (redisGetReply(r->ctx, (void **) &rp) == REDIS_OK)
			freeReplyObject(rp);
		r->pipeline--;
	}
}

int redis_set_timeout(struct redis* r, int64_t timeout) {
	struct timeval tv_cmd;

	if (!timeout)
		return 0;
	tv_cmd = timeval_from_us(timeout);
	if (redisSetTimeout(r->ctx, tv_cmd))
		return -1;
	ilog(LOG_INFO, "Setting timeout for Redis commands to %" PRId64 " milliseconds", timeout);
	return 0;
}

int redis_reconnect(struct redis* r) {
	int rval;
	LOCK(&r->lock);

	rval = redis_connect(r, 1, r->update_resolve);
	if (rval)
		r->state = REDIS_STATE_DISCONNECTED;
	return rval;
}

// struct must be locked or single thread
static int redis_select_db(struct redis *r, int db) {
	if (db == r->current_db)
		return 0;
	if (redisCommandNR(r->ctx, "SELECT %i", db))
		return -1;
	r->current_db = db;
	return 0;
}

void redis_set_keepalive(int fd) {
	if (rtpe_config.redis_tcp_keepalive_time > 0) {
		int keepalive_en = 1;
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive_en, sizeof(keepalive_en));

		setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &rtpe_config.redis_tcp_keepalive_time,
				sizeof(rtpe_config.redis_tcp_keepalive_time));
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &rtpe_config.redis_tcp_keepalive_intvl,
				sizeof(rtpe_config.redis_tcp_keepalive_intvl));
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &rtpe_config.redis_tcp_keepalive_probes,
				sizeof(rtpe_config.redis_tcp_keepalive_probes));
	}
}


/* called with r->lock held if necessary */
static int redis_connect(struct redis *r, int wait, bool resolve) {
	struct timeval tv;
	redisReply *rp;
	char *s;
	int64_t cmd_timeout, connect_timeout;
	sockaddr_t a;

	if (r->ctx)
		redisFree(r->ctx);
	r->ctx = NULL;
	r->current_db = -1;

	connect_timeout = atomic_get_na(&rtpe_config.redis_connect_timeout) * 1000LL;
	cmd_timeout = atomic_get_na(&rtpe_config.redis_cmd_timeout) * 1000LL;

	tv = timeval_from_us(connect_timeout);

	/* re-resolve if asked */
	if (resolve && r->hostname) {
		if (!sockaddr_getaddrinfo(&a, r->hostname))
			ilog(LOG_WARN, "Failed to re-resolve remote server hostname: '%s'. Just use older one: '%s'.",
					r->hostname, r->host);
		else {
			sockaddr_print(&a, r->host, sizeof(r->host));
			r->endpoint.address = a;
		}
	}

	r->ctx = redisConnectWithTimeout(r->host, r->endpoint.port, tv);

	if (!r->ctx)
		goto err;
	if (r->ctx->err)
		goto err2;

	redis_set_keepalive(r->ctx->fd);

	if (redis_set_timeout(r, cmd_timeout))
		goto err2;

	if (r->auth) {
		if (redisCommandNR(r->ctx, "AUTH %s", r->auth))
			goto err2;
	}
	else {
		if (redisCommandNR(r->ctx, "PING"))
			goto err2;
	}

	if (redis_select_db(r, r->db))
		goto err2;

	while (wait-- >= 0) {
		ilog(LOG_INFO, "Asking Redis whether it's master or slave...");
		rp = redisCommand(r->ctx, "INFO");
		if (!rp) {
			goto err2;
		}

		s = strstr(rp->str, "role:");
		if (!s) {
			goto err3;
		}

		if (!memcmp(s, "role:master", 11) || !memcmp(s, "role:active-replica", 19)) {
			if (r->role == MASTER_REDIS_ROLE || r->role == ANY_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis %s in master mode", 
					endpoint_print_buf(&r->endpoint));
				goto done;
			} else if (r->role == SLAVE_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis %s in master mode, but wanted mode is slave; retrying...",
					endpoint_print_buf(&r->endpoint));
				goto next;
			}
		} else if (!memcmp(s, "role:slave", 10)) {
			if (r->role == SLAVE_REDIS_ROLE || r->role == ANY_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis %s in slave mode",
					endpoint_print_buf(&r->endpoint));
				goto done;
			} else if (r->role == MASTER_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis %s in slave mode, but wanted mode is master; retrying...",
					endpoint_print_buf(&r->endpoint));
				goto next;
			}
		} else {
			goto err3;
		}

next:
		freeReplyObject(rp);
		usleep(1000000);
	}

	goto err2;

done:
	freeReplyObject(rp);
	redis_check_type(r, "calls", NULL, "set");
	return 0;

err3:
	freeReplyObject(rp);
err2:
	if (r->ctx->err) {
		rlog(LOG_ERR, "Failed to connect to Redis %s, error: %s",
			endpoint_print_buf(&r->endpoint), r->ctx->errstr);
		return -1;
	}
	redisFree(r->ctx);
	r->ctx = NULL;
err:
	rlog(LOG_ERR, "Failed to connect to Redis %s",
		endpoint_print_buf(&r->endpoint));
	return -1;
}


void on_redis_notification(redisAsyncContext *actx, void *reply, void *privdata) {
	struct redis *r = 0;
	call_t *c = NULL;
	str callid;
	str keyspace_id;

	if (!rtpe_redis_notify) {
		rlog(LOG_ERROR, "A redis notification has been received but no redis_notify database found");
		return;
	}

	r = rtpe_redis_notify;

	mutex_lock(&r->lock);

	redisReply *rr = (redisReply*)reply;

	if (reply == NULL || rr->type != REDIS_REPLY_ARRAY)
		goto err;

	for (int j = 0; j < rr->elements; j++) {
		rlog(LOG_DEBUG, "Redis-Notify: %u) %s%s%s\n", j, FMT_M(rr->element[j]->str));
	}

	if (rr->elements != 4)
		goto err;

	// format: __keyspace@<db>__:<key>
	keyspace_id = STR_LEN(rr->element[2]->str, rr->element[2]->len);

	if (str_shift_cmp(&keyspace_id, "__keyspace@"))
		goto err;

	// extract <db>
	char *endp;
	r->db = strtoul(keyspace_id.s, &endp, 10);
	if (endp == keyspace_id.s || *endp != '_')
		goto err;
	if (str_shift(&keyspace_id, endp - keyspace_id.s + 3))
		goto err;
	if (keyspace_id.s[-1] != ':')
		goto err;

	// now at <key>
	callid = keyspace_id;

	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED)
		goto err;

	// select the right db for restoring the call
	if (redis_select_db(r, r->db)) {
		if (r->ctx && r->ctx->err)
			rlog(LOG_ERROR, "Redis error: %s", r->ctx->errstr);
		redisFree(r->ctx);
		r->ctx = NULL;
		goto err;
	}

	if (strncmp(rr->element[3]->str, "set", 3) == 0) {
		c = call_get(&callid);
		if (c) {
			rwlock_unlock_w(&c->master_lock);
			if (IS_FOREIGN_CALL(c)) {
				c->redis_hosted_db = rtpe_redis_write->db; // don't delete from foreign DB
				// redis_notify->lock is held
				redis_ports_release_push(true);
				redis_do_delete(c, rtpe_redis_write);
				call_destroy(c);
				release_closed_sockets();
				redis_ports_release_pop(true);
			}
			else {
				rlog(LOG_WARN, "Redis-Notifier: Ignoring SET received for OWN call: " STR_FORMAT "\n", STR_FMT(&callid));
				goto err;
			}
		}

		redis_select_db(r, r->db);
	        mutex_unlock(&r->lock);

		// unlock before restoring calls to avoid deadlock in case err happens
		json_restore_call(r, &callid, true);

	        mutex_lock(&r->lock);
	}

	if (strncmp(rr->element[3]->str, "del", 3) == 0) {
		c = call_get(&callid);
		if (!c) {
			rlog(LOG_NOTICE, "Redis-Notifier: DEL did not find call with callid: " STR_FORMAT "\n", STR_FMT(&callid));
			goto err;
		}
		rwlock_unlock_w(&c->master_lock);
		if (!IS_FOREIGN_CALL(c)) {
			rlog(LOG_WARN, "Redis-Notifier: Ignoring DEL received for an OWN call: " STR_FORMAT "\n", STR_FMT(&callid));
			goto err;
		}
		// redis_notify->lock is held
		redis_ports_release_push(true);
		call_destroy(c);
		release_closed_sockets();
		redis_ports_release_pop(true);
	}

err:
	if (c) // because of call_get(..)
		obj_put(c);

	mutex_unlock(&r->lock);
	release_closed_sockets();
	log_info_reset();
}

void redis_delete_async_context_connect(const redisAsyncContext *redis_delete_async_context, int status) {
	if (status == REDIS_ERR) {
		rtpe_redis_write->async_ctx = NULL;
		if (redis_delete_async_context->errstr) {
			rlog(LOG_ERROR, "redis_delete_async_context_connect error %d: %s",
				redis_delete_async_context->err, redis_delete_async_context->errstr);
		} else {
			rlog(LOG_ERROR, "redis_delete_async_context_connect error %d: no errstr",
				redis_delete_async_context->err);
		}
	} else if (status == REDIS_OK) {
		rlog(LOG_NOTICE, "redis_delete_async_context_connect initiated by user");
	} else {
		rlog(LOG_ERROR, "redis_delete_async_context_connect invalid status code %d", status);
	}
}

void redis_delete_async_context_disconnect(const redisAsyncContext *redis_delete_async_context, int status) {
	rtpe_redis_write->async_ctx = NULL;
	if (status == REDIS_ERR) {
		if (redis_delete_async_context->errstr) {
			rlog(LOG_ERROR, "redis_delete_async_context_disconnect error %d: %s",
				redis_delete_async_context->err, redis_delete_async_context->errstr);
		} else {
			rlog(LOG_ERROR, "redis_delete_async_context_disconnect error %d: no errstr",
				redis_delete_async_context->err);
		}
	} else if (status == REDIS_OK) {
		rlog(LOG_NOTICE, "redis_delete_async_context_disconnect initiated by user");
	} else {
		rlog(LOG_ERROR, "redis_delete_async_context_disconnect invalid status code %d", status);
	}
}

void redis_notify_async_context_disconnect(const redisAsyncContext *redis_notify_async_context, int status) {
	if (status == REDIS_ERR) {
		if (redis_notify_async_context->errstr) {
			rlog(LOG_ERROR, "redis_notify_async_context_disconnect error %d on context free: %s",
				redis_notify_async_context->err, redis_notify_async_context->errstr);
		} else {
			rlog(LOG_ERROR, "redis_notify_async_context_disconnect error %d on context free: no errstr",
				redis_notify_async_context->err);
		}
	} else if (status == REDIS_OK) {
		rlog(LOG_NOTICE, "redis_notify_async_context_disconnect initiated by user");
	} else {
		rlog(LOG_ERROR, "redis_notify_async_context_disconnect invalid status code %d", status);
	}
}

// connect_cb = connect callback, disconnect_cb = disconnect callback
int redis_async_context_alloc(struct redis *r, void *connect_cb, void *disconnect_cb) {
	// sanity checks
	if (!r) {
		rlog(LOG_ERROR, "redis_async_context_alloc: NULL r");
		return -1;
	} else {
		rlog(LOG_DEBUG, "redis_async_context_alloc: Use Redis %s", endpoint_print_buf(&r->endpoint));
	}

	// alloc async context
	r->async_ctx = redisAsyncConnect(r->host, r->endpoint.port);
	if (!r->async_ctx) {
		rlog(LOG_ERROR, "redis_async_context_alloc: can't create new");
		return -1;
	}

	if (r->async_ctx->err) {
		rlog(LOG_ERROR, "redis_async_context_alloc: can't create new error: %s", r->async_ctx->errstr);
		return -1;
	}

	redis_set_keepalive(r->async_ctx->c.fd);

	// callbacks async context
	if (redisAsyncSetConnectCallback(r->async_ctx, connect_cb) != REDIS_OK) {
		rlog(LOG_ERROR, "redis_async_context_alloc: can't set connect callback");
		return -1;
	}

	if (redisAsyncSetDisconnectCallback(r->async_ctx, disconnect_cb) != REDIS_OK) {
		rlog(LOG_ERROR, "redis_async_context_alloc: can't set disconnect callback");
		return -1;
	}

	rlog(LOG_DEBUG, "redis_async_context_alloc: Success");

	return 0;
}

int redis_async_event_base_action(struct redis *r, enum event_base_action action) {
	// sanity checks
	if (!r) {
		rlog(LOG_ERR, "redis_async_event_base_action: NULL r");
		return -1;
	} else {
		rlog(LOG_DEBUG, "redis_async_event_base_action: Use Redis %s", endpoint_print_buf(&r->endpoint));
	}

	if (!r->async_ev && action != EVENT_BASE_ALLOC) {
		rlog(LOG_NOTICE, "redis_async_event_base_action: async_ev is NULL on event base action %d", action);
		return -1;
	}

	// exec event base action
	switch (action) {
		case EVENT_BASE_ALLOC:
			r->async_ev = event_base_new();
			if (!r->async_ev) {
				rlog(LOG_ERROR, "redis_async_event_base_action: Fail alloc async_ev");
				return -1;
			} else {
				rlog(LOG_DEBUG, "redis_async_event_base_action: Success alloc async_ev");
			}
			break;

		case EVENT_BASE_FREE:
			event_base_free(r->async_ev);
			rlog(LOG_DEBUG, "redis_async_event_base_action: Success free async_ev");
			break;

		case EVENT_BASE_LOOPBREAK:
			if (event_base_loopbreak(r->async_ev)) {
				rlog(LOG_ERROR, "redis_async_event_base_action: Fail loopbreak async_ev");
				return -1;
			} else {
				rlog(LOG_DEBUG, "redis_async_event_base_action: Success loopbreak async_ev");
			}
			break;

		default:
			rlog(LOG_ERROR, "redis_async_event_base_action: No event base action found: %d", action);
			return -1;
	}

	return 0;
}

int redis_notify_subscribe_action(struct redis *r, enum subscribe_action action, int keyspace) {
	if (!r->async_ctx) {
		rlog(LOG_ERROR, "redis_notify_async_context is NULL on subscribe action");
		return -1;
	}

	if (r->async_ctx->err) {
		rlog(LOG_ERROR, "redis_notify_async_context error on subscribe action: %s", r->async_ctx->errstr);
		return -1;
	}

	switch (action) {
	case SUBSCRIBE_KEYSPACE:
		if (redisAsyncCommand(r->async_ctx, on_redis_notification, NULL, "psubscribe __keyspace@%i__:*", keyspace) != REDIS_OK) {
			rlog(LOG_ERROR, "Fail redisAsyncCommand on JSON SUBSCRIBE_KEYSPACE");
			return -1;
		}
		break;
	case UNSUBSCRIBE_KEYSPACE:
		if (redisAsyncCommand(r->async_ctx, on_redis_notification, NULL, "punsubscribe __keyspace@%i__:*", keyspace) != REDIS_OK) {
			rlog(LOG_ERROR, "Fail redisAsyncCommand on JSON UNSUBSCRIBE_KEYSPACE");
			return -1;
		}
		break;
	case UNSUBSCRIBE_ALL:
		if (redisAsyncCommand(r->async_ctx, on_redis_notification, NULL, "punsubscribe") != REDIS_OK) {
			rlog(LOG_ERROR, "Fail redisAsyncCommand on JSON UNSUBSCRIBE_ALL");
			return -1;
		}
		break;
	default:
		rlog(LOG_ERROR, "No subscribe action found: %d", action);
		return -1;
	}

	return 0;
}

static int redis_delete_async(struct redis *r) {
	// sanity checks
	if (!r) {
		rlog(LOG_ERROR, "redis_delete_async: Don't use Redis async deletions because no redis/redis_write.");
		return -1 ;
	}

	// alloc new redis async context
	if (r->async_ctx == NULL && redis_async_context_alloc(r, redis_delete_async_context_connect, redis_delete_async_context_disconnect) < 0) {
		r->async_ctx = NULL;
		rlog(LOG_ERROR, "redis_delete_async: Failed to alloc async_ctx");
		return -1;
	}

	// attach event base
	if (redisLibeventAttach(r->async_ctx, r->async_ev) == REDIS_ERR) {
		if (r->async_ctx->err) {
			rlog(LOG_ERROR, "redis_delete_async: redis_delete_async_context can't attach event base error: %s", r->async_ctx->errstr);
		} else {
			rlog(LOG_ERROR, "redis_delete_async: redis_delete_async_context can't attach event base");

		}
		return -1;
	}

	// commands
	if (r->auth) {
		if (redisAsyncCommand(r->async_ctx, NULL, NULL, "AUTH %s", r->auth) != REDIS_OK) {
			rlog(LOG_ERROR, "redis_delete_async: Fail redisAsyncCommand on AUTH");
			return -1;
		}
	} else {
		if (redisAsyncCommand(r->async_ctx, NULL, NULL, "PING") != REDIS_OK) {
			rlog(LOG_ERROR, "redis_delete_async: Fail redisAsyncCommand on PING");
			return -1;
		}
	}

	// delete commands
	gchar *redis_command;
	gint redis_command_total = 0;

	mutex_lock(&r->async_lock);
	while (!g_queue_is_empty(&r->async_queue)) {
		redis_command_total++;
		redis_command = g_queue_pop_head(&r->async_queue);

		if (redisAsyncCommand(r->async_ctx, NULL, NULL, redis_command) != REDIS_OK) {
			rlog(LOG_ERROR, "redis_delete_async: Fail redisAsyncCommand on DELETE");
		}

		g_free(redis_command);
	}
	mutex_unlock(&r->async_lock);

	rlog(LOG_NOTICE, "redis_delete_async: Queued DELETE redisAsyncCommand total: %d", redis_command_total);

	// dispatch event base => thread blocks here
	if (event_base_dispatch(r->async_ev) < 0) {
		rlog(LOG_ERROR, "redis_delete_async: Fail event_base_dispatch()");
		return -1;
	}

	// loopbreak
	redisAsyncDisconnect(r->async_ctx);
	r->async_ctx = NULL;

	return 0;
}

static int redis_notify(struct redis *r) {
	GList *l;

	if (!r) {
		rlog(LOG_ERROR, "redis_notify database is NULL on redis_notify()");
		return -1;
	}

	if (!r->async_ctx) {
		rlog(LOG_ERROR, "redis_notify_async_context is NULL on redis_notify()");
		return -1;
	}

	if (!r->async_ev) {
		rlog(LOG_ERROR, "redis_notify_event_base is NULL on redis_notify()");
		return -1;
	}

	// get redis_notify database
	rlog(LOG_INFO, "Use Redis %s to subscribe to notifications", endpoint_print_buf(&r->endpoint));

	// attach event base
	if (redisLibeventAttach(r->async_ctx, r->async_ev) == REDIS_ERR) {
		if (r->async_ctx->err) {
			rlog(LOG_ERROR, "redis_notify_async_context can't attach event base error: %s", r->async_ctx->errstr);
		} else {
			rlog(LOG_ERROR, "redis_notify_async_context can't attach event base");

		}
		return -1;
	}

	if (r->auth) {
		if (redisAsyncCommand(r->async_ctx, on_redis_notification, NULL, "AUTH %s", r->auth) != REDIS_OK) {
			rlog(LOG_ERROR, "Fail redisAsyncCommand on AUTH");
			return -1;
		}
	}

	// subscribe to the values in the configured keyspaces
	rwlock_lock_r(&rtpe_config.keyspaces_lock);
	for (l = rtpe_config.redis_subscribed_keyspaces.head; l; l = l->next) {
		int id = GPOINTER_TO_INT(l->data);
		if (id < 0)
			continue;
		redis_notify_subscribe_action(r, SUBSCRIBE_KEYSPACE, id);
	}
	rwlock_unlock_r(&rtpe_config.keyspaces_lock);

	// dispatch event base => thread blocks here
	if (event_base_dispatch(r->async_ev) < 0) {
		rlog(LOG_ERROR, "Fail event_base_dispatch()");
		return -1;
	}

	return 0;
}

void redis_delete_async_loop(void *d) {
	struct redis *r = NULL;

	// sanity checks
	r = rtpe_redis_write;
	if (!r) {
		rlog(LOG_ERROR, "redis_delete_async_loop: Don't use Redis async deletions because no redis/redis_write.");
		return ;
	}

	r->async_last = rtpe_now;

	// init libevent for pthread usage
	if (evthread_use_pthreads() < 0) {
		ilog(LOG_ERROR, "redis_delete_async_loop: evthread_use_pthreads failed.");
		return ;
	}

	// alloc libevent base
	if (redis_async_event_base_action(r, EVENT_BASE_ALLOC) < 0) {
		rlog(LOG_ERROR, "redis_delete_async_loop: Failed to EVENT_BASE_ALLOC.");
		return ;
	}

	// loop (almost) forever
	while (!rtpe_shutdown) {
		redis_delete_async(r);
		sleep(1);
	}
}

void redis_notify_loop(void *d) {
	int redis_notify_return = 0;
	const int64_t microseconds = 1000000L;
	int64_t next_run = rtpe_now;
	struct redis *r;

	r = rtpe_redis_notify;
	if (!r) {
		rlog(LOG_ERROR, "Don't use Redis notifications. See --redis-notifications parameter.");
		return ;
	}

	// init libevent for pthread usage
	if (evthread_use_pthreads() < 0) {
		ilog(LOG_ERROR, "evthread_use_pthreads failed");
		return ;
	}

	// alloc redis async context 
	if (redis_async_context_alloc(r, NULL, redis_notify_async_context_disconnect) < 0) {
		return ;
	}

	// alloc event base
	if (redis_async_event_base_action(r, EVENT_BASE_ALLOC) < 0) {
		return ;
	}

	// initial redis_notify
	if (redis_check_conn(r) == REDIS_STATE_CONNECTED) {
		redis_notify_return = redis_notify(r);
	}

	// loop redis_notify => in case of lost connection
	while (!rtpe_shutdown) {
		rtpe_now = now_us();
		if (rtpe_now < next_run) {
			usleep(100000);
			continue;
		}

		next_run = rtpe_now + microseconds;

		if (redis_check_conn(r) == REDIS_STATE_CONNECTED || redis_notify_return < 0) {
			r->async_ctx = NULL;
			// alloc new redis async context upon redis breakdown
			if (redis_async_context_alloc(r, NULL, redis_notify_async_context_disconnect) < 0) {
				continue;
			}

			// prepare notifications
			redis_notify_return = redis_notify(r);
		}
	}

	if (r->state == REDIS_STATE_CONNECTED) {
		// unsubscribe notifications
		redis_notify_subscribe_action(r, UNSUBSCRIBE_ALL, 0);

		// free async context
		redisAsyncDisconnect(r->async_ctx);
		r->async_ctx = NULL;
	}
}

struct redis *redis_new(const endpoint_t *ep, int db, const char *hostname, const char *auth,
		enum redis_role role, int no_redis_required, bool update_resolve) {
	struct redis *r;
	r = g_new0(struct redis, 1);

	r->endpoint = *ep;
	sockaddr_print(&ep->address, r->host, sizeof(r->host));
	r->db = db;
	r->auth = auth;
	r->hostname = hostname;
	r->role = role;
	r->state = REDIS_STATE_DISCONNECTED;
	r->no_redis_required = no_redis_required;
	r->restore_tick_us = 0;
	r->consecutive_errors = 0;
	r->update_resolve = update_resolve;
	mutex_init(&r->lock);

	if (redis_connect(r, 10, false)) {
		if (r->no_redis_required) {
			rlog(LOG_WARN, "Starting with no initial connection to Redis %s !",
				endpoint_print_buf(&r->endpoint));
			return r;
		}
		goto err;
	}

	// redis is connected
	rlog(LOG_INFO, "Established initial connection to Redis %s",
		endpoint_print_buf(&r->endpoint));
	r->state = REDIS_STATE_CONNECTED;
	return r;

err:
	mutex_destroy(&r->lock);
	g_free(r);
	return NULL;
}

struct redis *redis_dup(const struct redis *r, int db) {
	return redis_new(&r->endpoint,
				(db >= 0 ? db : r->db),
				r->hostname,
				r->auth,
				r->role,
				r->no_redis_required,
				r->update_resolve);
}

void redis_close(struct redis *r) {
	if (!r)
		return;
	if (r->ctx)
		redisFree(r->ctx);
	r->ctx = NULL;
	mutex_destroy(&r->lock);
	g_free(r);
}

static void redis_count_err_and_disable(struct redis *r)
{
	int allowed_errors;
	int64_t disable_time_us;

	allowed_errors = atomic_get_na(&rtpe_config.redis_allowed_errors);
	disable_time_us = atomic_get_na(&rtpe_config.redis_disable_time_us);

	if (allowed_errors < 0) {
		return;
	}

	r->consecutive_errors++;
	if (r->consecutive_errors > allowed_errors) {
		r->restore_tick_us = rtpe_now + disable_time_us;
		ilog(LOG_WARNING, "Redis server %s disabled for %" PRId64 " seconds",
				endpoint_print_buf(&r->endpoint),
				disable_time_us / 1000000L);
	}
}

/* must be called with r->lock held */
static int redis_check_conn(struct redis *r) {
	rtpe_now = now_us(); // XXX this needed here?

	if ((r->state == REDIS_STATE_DISCONNECTED) && r->restore_tick_us > rtpe_now) {
		ilog(LOG_WARNING, "Redis server '%s' is disabled. Don't try RE-Establishing for %" PRId64 " more seconds",
				r->hostname, (r->restore_tick_us - rtpe_now) / 1000000);
		return REDIS_STATE_DISCONNECTED;
	}

	if (r->state == REDIS_STATE_DISCONNECTED)
		ilog(LOG_INFO, "RE-Establishing connection for Redis server '%s'", r->hostname);

	// try redis connection
	if (r->ctx && redisCommandNR(r->ctx, "PING") == 0) {
		// redis is connected
		if (r->state == REDIS_STATE_DISCONNECTED) {
			rlog(LOG_INFO, "RE-Established connection to Redis %s; PING works",
				endpoint_print_buf(&r->endpoint));
			r->state = REDIS_STATE_CONNECTED;
		}
		return REDIS_STATE_CONNECTED;
	}

	// redis is disconnected
	if (r->state == REDIS_STATE_CONNECTED) {
		rlog(LOG_ERR, "Lost connection to Redis '%s'",
			r->hostname);
		r->state = REDIS_STATE_DISCONNECTED;
	}

	// try redis reconnect => will free current r->ctx
	if (redis_connect(r, 1, r->update_resolve)) {
		// redis is disconnected
		redis_count_err_and_disable(r);
		return REDIS_STATE_DISCONNECTED;
	}

	r->consecutive_errors = 0;

	// redis is connected
	if (r->state == REDIS_STATE_DISCONNECTED) {
		rlog(LOG_INFO, "RE-Established connection to Redis %s",
			endpoint_print_buf(&r->endpoint));
		r->state = REDIS_STATE_CONNECTED;
	}

	// redis is re-connected
	return REDIS_STATE_CONNECTED;
}

/* called with r->lock held and c->master_lock held */
static void redis_delete_call_json(call_t *c, struct redis *r) {
	redis_pipe(r, "DEL "PB"", PBSTR(&c->callid));
	redis_consume(r);
}

static void redis_delete_async_call_json(call_t *c, struct redis *r) {
	gchar *redis_command;

	redis_command = g_strdup_printf("SELECT %i", c->redis_hosted_db);
	g_queue_push_tail(&r->async_queue, redis_command);

	redis_command = g_strdup_printf("DEL " STR_FORMAT, STR_FMT(&c->callid));
	g_queue_push_tail(&r->async_queue, redis_command);
}

// XXX rework restore procedure to use functions like this everywhere and eliminate the GHashTable

/* Call deserialization logic moved to daemon/call_state.c */

static void json_restore_call(struct redis *r, const str *callid, bool foreign) {
	redisReply* rr_jsonStr;

	mutex_lock(&r->lock);
	rr_jsonStr = redis_get(r, REDIS_REPLY_STRING, "GET " PB, PBSTR(callid));
	mutex_unlock(&r->lock);

	if (!rr_jsonStr) {
		rlog(LOG_WARNING, "Failed to restore call ID '" STR_FORMAT_M "' from Redis: could not retrieve data",
				STR_FMT_M(callid));
		return;
	}

	str payload = STR_LEN(rr_jsonStr->str, rr_jsonStr->len);
	int rc = call_restore_from_payload(callid, &payload, foreign);
	if (rc) {
		mutex_lock(&r->lock);
		if (r->ctx && r->ctx->err)
			rlog(LOG_WARNING, "Failed to restore call ID '" STR_FORMAT_M "' from Redis: (%s)",
					STR_FMT_M(callid), r->ctx->errstr);
		else
			rlog(LOG_WARNING, "Failed to restore call ID '" STR_FORMAT_M "' from Redis",
					STR_FMT_M(callid));
		mutex_unlock(&r->lock);

		mutex_lock(&rtpe_redis_write->lock);
		redis_select_db(rtpe_redis_write, rtpe_redis_write->db);
		redisCommandNR(rtpe_redis_write->ctx, "DEL " PB, PBSTR(callid));
		mutex_unlock(&rtpe_redis_write->lock);

		if (rtpe_redis_notify) {
			mutex_lock(&rtpe_redis_notify->lock);
			redisCommandNR(rtpe_redis_notify->ctx, "DEL " PB, PBSTR(callid));
			mutex_unlock(&rtpe_redis_notify->lock);
		}
	}
	freeReplyObject(rr_jsonStr);
}

/* Call serialization and snapshot logic moved to daemon/call_state.c */

struct thread_ctx {
	GQueue r_q;
	mutex_t r_m;
	bool foreign;
};

static void restore_thread(void *call_p, void *ctx_p) {
	struct thread_ctx *ctx = ctx_p;
	redisReply *call = call_p;
	struct redis *r;
	str callid = STR_LEN(call->str, call->len);

	rlog(LOG_DEBUG, "Processing call ID '%s%.*s%s' from Redis", FMT_M(REDIS_FMT(call)));

	mutex_lock(&ctx->r_m);
	r = g_queue_pop_head(&ctx->r_q);
	mutex_unlock(&ctx->r_m);

	rtpe_now = now_us();
	json_restore_call(r, &callid, ctx->foreign);

	mutex_lock(&ctx->r_m);
	g_queue_push_tail(&ctx->r_q, r);
	mutex_unlock(&ctx->r_m);
	release_closed_sockets();
}

int redis_restore(struct redis *r, bool foreign, int db) {
	redisReply *calls = NULL, *call;
	int ret = -1;
	GThreadPool *gtp;
	struct thread_ctx ctx;

	if (!r)
		return 0;

	for (unsigned int i = 0; i < num_log_levels; i++)
		rtpe_config.common.log_levels[i] |= LOG_FLAG_RESTORE;

	rlog(LOG_DEBUG, "Restoring calls from Redis...");

	mutex_lock(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED) {
		mutex_unlock(&r->lock);
		ret = 0;
		goto err;
	}
	if (db != -1)
		redis_select_db(r, db);

	calls = redis_get(r, REDIS_REPLY_ARRAY, "KEYS *");

	if (db != -1)
		redis_select_db(r, r->db);
	else
		db = r->db;

	mutex_unlock(&r->lock);

	if (!calls) {
		rlog(LOG_ERR, "Could not retrieve call list from Redis: %s",
				r->ctx ? r->ctx->errstr : "No redis context");
		goto err;
	}

	if (calls->elements == 0)
		goto out;

	mutex_init(&ctx.r_m);
	g_queue_init(&ctx.r_q);
	ctx.foreign = foreign;
	for (int i = 0; i < rtpe_config.redis_num_threads; i++) {
		struct redis *dup = redis_dup(r, db);
		if (!dup) {
			rlog(LOG_ERR, "Failed to create thread connection to Redis");
			goto err;
		}
		g_queue_push_tail(&ctx.r_q, dup);
	}
	gtp = g_thread_pool_new(restore_thread, &ctx, rtpe_config.redis_num_threads, TRUE, NULL);

	for (int i = 0; i < calls->elements; i++) {
		call = calls->element[i];
		if (call->type != REDIS_REPLY_STRING)
			continue;

		g_thread_pool_push(gtp, call, NULL);
	}

	g_thread_pool_stop_unused_threads();
	g_thread_pool_set_max_unused_threads(0);

	g_thread_pool_free(gtp, FALSE, TRUE);
	while ((r = g_queue_pop_head(&ctx.r_q)))
		redis_close(r);

out:
	ret = 0;

	freeReplyObject(calls);

err:
	for (unsigned int i = 0; i < num_log_levels; i++)
		if (rtpe_config.common.log_levels[i] > 0)
			rtpe_config.common.log_levels[i] &= ~LOG_FLAG_RESTORE;
	return ret;
}

void redis_update_onekey(call_t *c, struct redis *r) {
	unsigned int redis_expires_s;

	if (!r)
		return;
	if (IS_FOREIGN_CALL(c))
		return;

	LOCK(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED)
		return;

	atomic64_set_na(&c->last_redis_update_us, rtpe_now);

	rwlock_lock_r(&c->master_lock);

	redis_expires_s = rtpe_config.redis_expires_secs;

	c->redis_hosted_db = r->db;
	if (redis_select_db(r, c->redis_hosted_db)) {
		rlog(LOG_ERR, " >>>>>>>>>>>>>>>>> Redis error.");
		goto err;
	}

	bencode_buffer_t bbuf;
	void *to_free = NULL;
	str result = call_serialize_state(c, &to_free, &bbuf);
	if (!result.len)
		goto err;

	redis_pipe(r, "SET " PB " " PB " EX %i", PBSTR(&c->callid), PBSTR(&result), redis_expires_s);

	redis_consume(r);

	rwlock_unlock_r(&c->master_lock);

	g_free(to_free);
	bencode_buffer_free(&bbuf);

	return;
err:
	if (r->ctx && r->ctx->err)
		rlog(LOG_ERR, "Redis error: %s", r->ctx->errstr);
	redisFree(r->ctx);
	r->ctx = NULL;

	rwlock_unlock_r(&c->master_lock);
}

/* must be called lock-free */
static void redis_do_delete(call_t *c, struct redis *r) {
	int delete_async = rtpe_config.redis_delete_async;
	rlog(LOG_DEBUG, "Redis delete_async=%d", delete_async);

	if (!r)
		return;

	if (c->redis_hosted_db < 0)
		return;

	if (delete_async) {
		LOCK(&r->async_lock);
		rwlock_lock_r(&c->master_lock);
		redis_delete_async_call_json(c, r);
		rwlock_unlock_r(&c->master_lock);
		return;
	}

	LOCK(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED)
		return;
	rwlock_lock_r(&c->master_lock);

	if (redis_select_db(r, c->redis_hosted_db))
		goto err;

	redis_delete_call_json(c, r);

	rwlock_unlock_r(&c->master_lock);
	return;

err:
	if (r->ctx && r->ctx->err)
		rlog(LOG_ERR, "Redis error: %s", r->ctx->errstr);
	redisFree(r->ctx);
	r->ctx = NULL;

	rwlock_unlock_r(&c->master_lock);
}

/* must be called lock-free */
void redis_delete(call_t *c, struct redis *r) {
	if (IS_FOREIGN_CALL(c))
		return;

	redis_do_delete(c, r);
}





void redis_wipe(struct redis *r) {
	if (!r)
		return;

	LOCK(&r->lock);
	// coverity[sleep : FALSE]
	if (redis_check_conn(r) == REDIS_STATE_DISCONNECTED)
		return;
	redisCommandNR(r->ctx, "DEL calls");
}
