// epha-ots server
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Build: gcc -O2 -Wall -Wextra -pthread server.c -o epha-ots -lmicrohttpd
// Run:   ./epha-ots --port 8443 --cert cert.pem --key key.pem
// Dev:   ./epha-ots --http --port 9000
#define _GNU_SOURCE
#include <microhttpd.h>

#include <immintrin.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "debug_stuff.h"
#include "storage.h"

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

// ---------------- Config ----------------
#define DEFAULT_PORT 8443
#define MAX_BLOB_SIZE (128 * 1024) // 128 KiB per blob
#define DEFAULT_MAX_BLOBS 10000
#define DEFAULT_THREAD_POOL_SIZE 4
#define MIN_BLOB_SIZE (12 + 16 + 2 + 16) // nonce + salt + marker + GCM tag

#define RL_RATE 100.0
#define RL_BURST 2000.0
#define RL_BUCKETS 512

#define REPLACE_SIZE 10
#define REPLACE_UPTIME "UUUUUUUUUU"
#define REPLACE_SERVED "SSSSSSSSSS"

static struct {
	uint total_served;
	double start_time;
} statistics;

double app_uptime_hours(void)
{
	return (now_s() - statistics.start_time) / 60 / 60;
}

static volatile sig_atomic_t reaper_stop = 0;
static pthread_t reaper_tid;
static bool reaper_started = false;

#define _CONTENT_TYPE_STRING_MAX_SIZE 38
#define _CONTENT_TYPE_HTML "text/html; charset=utf-8"
#define _CONTENT_TYPE_CSS "text/css; charset=utf-8"
#define _CONTENT_TYPE_JS "application/javascript; charset=utf-8"
#define _CONTENT_TYPE_SVG "image/svg+xml"

typedef struct {
	uint8_t *data;
	size_t size;
	const char content_type[_CONTENT_TYPE_STRING_MAX_SIZE];
} asset_t;

enum assets_id_t {
	ASSET_CLIENT_HTML = 0,
	ASSET_CLIENT_CSS,
	ASSET_CLIENT_JS,
	ASSET_QRCODE_JS,
	ASSET_FAVICON_SVG,
	ASSETS_COUNT,
	KEY_PEM,
	CERT_PEM
};
static uint8_t *assets_memory;

static asset_t assets[ASSETS_COUNT] = {
	[ASSET_CLIENT_HTML] = { .content_type = _CONTENT_TYPE_HTML },
	[ASSET_CLIENT_CSS] = { .content_type = _CONTENT_TYPE_CSS },
	[ASSET_CLIENT_JS] = { .content_type = _CONTENT_TYPE_JS },
	[ASSET_QRCODE_JS] = { .content_type = _CONTENT_TYPE_JS },
	[ASSET_FAVICON_SVG] = { .content_type = _CONTENT_TYPE_SVG }
};
static const char *asset_file_paths[ASSETS_COUNT] = {
	[ASSET_CLIENT_HTML] = "assets/client.html",
	[ASSET_CLIENT_CSS] = "assets/client.css",
#if JS_MINIFY
	[ASSET_CLIENT_JS] = "assets/client.min.js",
	[ASSET_QRCODE_JS] = "assets/qrcode.min.js",
#else
	[ASSET_CLIENT_JS] = "assets/client.js",
	[ASSET_QRCODE_JS] = "assets/qrcode.js",
#endif
	[ASSET_FAVICON_SVG] = "assets/favicon.svg",
};
#define ASSET_PATH_STRING_MAX_SIZE 15
static const char asset_paths[ASSETS_COUNT][ASSET_PATH_STRING_MAX_SIZE] = {
	[ASSET_CLIENT_HTML] = "/",
	[ASSET_CLIENT_CSS] = "/client.css",
	[ASSET_CLIENT_JS] = "/client.js",
	[ASSET_QRCODE_JS] = "/qrcode.js",
	[ASSET_FAVICON_SVG] = "/favicon.svg",
};

void assets_free()
{
	free(assets_memory);
	assets_memory = NULL;
	for (uint i = 0; i < ASSETS_COUNT; ++i) {
		assets[i].data = NULL;
		assets[i].size = 0;
	}
}

bool assets_load()
{
	FILE *file_descriptors[ASSETS_COUNT] = {};
	size_t asset_sizes[ASSETS_COUNT] = {}, assets_size_total = 0;
	// open assets and calculate size
	for (uint i = 0; i < ASSETS_COUNT; ++i) {
		const char *const file_path = asset_file_paths[i];
		FILE **f = &file_descriptors[i];
		*f = fopen(file_path, "rb");
		if (!*f) {
			LOGE("Failed to open %s", file_path);
			goto close_assets_file_descriptors_and_exit_with_error;
		}
		if (fseek(*f, 0, SEEK_END) != 0) {
			++i;
			goto close_assets_file_descriptors_and_exit_with_error;
		}
		long file_size = ftell(*f);
		if (file_size < 0) {
			++i;
			goto close_assets_file_descriptors_and_exit_with_error;
		}
		asset_sizes[i] = file_size;
		assets_size_total += file_size;
		rewind(*f);
		continue;
close_assets_file_descriptors_and_exit_with_error:
		while (i) {
			--i;
			fclose(file_descriptors[i]);
		}
		return false;
	}

	// allocate memory
	assets_memory = (uint8_t *)malloc(assets_size_total);
	if (!assets_memory) {
		LOGE("Failed to allocate %lu bytes", assets_size_total);
		for (uint i = 0; ASSETS_COUNT; ++i) {
			fclose(file_descriptors[i]);
			assets_free();
			return false;
		}
	}

	// read files
	uint8_t *current_ptr = assets_memory;
	for (uint i = 0; i < ASSETS_COUNT; ++i) {
		asset_t *asset = &assets[i];
		size_t asset_size = asset_sizes[i];
		FILE *f = file_descriptors[i];
		size_t bytes_read = fread(current_ptr, 1, asset_size, f);
		if (bytes_read != asset_size) {
			LOGE("Error while reading %s", asset_file_paths[i]);
			// close opened file descriptors, free memory and exit with error
			for (; i < ASSETS_COUNT; ++i) {
				fclose(file_descriptors[i]);
				assets_free();
				return false;
			}
		}
		fclose(f);
		asset->data = current_ptr;
		asset->size = asset_size;
		current_ptr += asset_size;
	}
	LOG("%u static assets loaded for paths:", ASSETS_COUNT);
	for (uint i = 0; i < ASSETS_COUNT; ++i) {
		LOG("%s", asset_paths[i]);
		LOGD("%s\t%.1fKiB\n", asset_file_paths[i],
		     (float)assets[i].size / 1024.f);
	}
	LOGD("total size %lu bytes\n", assets_size_total);
	return true;
}

bool asset_find(const char *url, asset_t **asset)
{
	for (uint i = 0; i < ASSETS_COUNT; ++i) {
		if (0 ==
		    strncmp(url, asset_paths[i], ASSET_PATH_STRING_MAX_SIZE)) {
			*asset = &assets[i];
			return true;
		}
	}
	*asset = NULL;
	return false;
}

static uint8_t *tls_key_and_cert_memory;
static size_t tls_key_and_cert_memory_size;
static uint8_t *tls_cert, *tls_key;
void tls_data_free()
{
	if (!tls_key_and_cert_memory)
		return;
	secure_zero(tls_key_and_cert_memory, tls_key_and_cert_memory_size);
	free(tls_key_and_cert_memory);
	tls_key_and_cert_memory_size = 0;
	tls_key = NULL;
	tls_cert = NULL;
}

bool tls_data_load(const char *cert_path, const char *key_path)
{
	FILE *cert_file = NULL;
	FILE *key_file = NULL;
	size_t cert_size = 0;
	size_t key_size = 0;
	bool success = false;

	cert_file = fopen(cert_path, "rb");
	if (!cert_file) {
		LOGE("Failed to open certificate file %s", cert_path);
		goto cleanup;
	}
	if (fseek(cert_file, 0, SEEK_END) != 0) {
		goto cleanup;
	}
	long cert_len = ftell(cert_file);
	if (cert_len <= 0) {
		goto cleanup;
	}
	rewind(cert_file);
	cert_size = (size_t)cert_len;

	key_file = fopen(key_path, "rb");
	if (!key_file) {
		LOGE("Failed to open key file %s", key_path);
		goto cleanup;
	}
	if (fseek(key_file, 0, SEEK_END) != 0) {
		goto cleanup;
	}
	long key_len = ftell(key_file);
	if (key_len <= 0) {
		goto cleanup;
	}
	rewind(key_file);
	key_size = (size_t)key_len;

	tls_key_and_cert_memory_size = cert_size + key_size + 2; // 2 for \0
	tls_key_and_cert_memory =
		(uint8_t *)malloc(tls_key_and_cert_memory_size);
	if (!tls_key_and_cert_memory) {
		LOGE("Failed to allocate %zu bytes for certificate the and the key",
		     tls_key_and_cert_memory_size);
		goto cleanup;
	}
	tls_key = tls_key_and_cert_memory;
	tls_cert = tls_key_and_cert_memory + key_size + 1;

	size_t read = fread(tls_cert, 1, cert_size, cert_file);
	if (read != cert_size) {
		LOGE("Failed to read certificate file %s", cert_path);
		goto cleanup;
	}
	tls_cert[cert_size] = '\0';

	read = fread(tls_key, 1, key_size, key_file);
	if (read != key_size) {
		LOGE("Failed to read key file %s", key_path);
		goto cleanup;
	}
	tls_key[key_size] = '\0';

	success = true;
cleanup:
	if (cert_file)
		fclose(cert_file);
	if (key_file)
		fclose(key_file);
	if (!success) {
		tls_data_free();
	}
	return success;
}

// Frees expired blobs until shutdown is requested
static void *reaper_thread(void *arg)
{
	LOGD("%s\n", __FUNCTION__);
	(void)arg;
	for (;;) {
		if (reaper_stop)
			break;
		pthread_mutex_lock(&blob_storage.mutex);
		double t = now_s();
		for (int i = 0; i < blob_storage.capacity; i++)
			if (blob_storage.items[i].in_use &&
			    blob_storage.items[i].expires_at <= t)
				blob_free_locked(&blob_storage.items[i]);
		pthread_mutex_unlock(&blob_storage.mutex);
		if (reaper_stop)
			break;
		usleep(250 * 1000); // 250 ms
	}
	return NULL;
}

static uint8_t *html_uptime_ptr, *html_served_ptr;
static uint8_t *find_10(const uint8_t *data, size_t size, const char ch)
{
	const uint8_t *end = data + size;
	__m256i xx = _mm256_set1_epi8(ch);
	while (end - data >= 32) {
		__m256i v = _mm256_loadu_si256((const __m256i *)data);
		__m256i eq = _mm256_cmpeq_epi8(v, xx);
		if (!_mm256_testz_si256(eq, eq)) {
			uint total = 0;
			const uint8_t *first = NULL;
			for (uint i = 0; i < 41 && total < 10; ++i) {
				if (data[i] == ch) {
					++total;
					first = total == 1 ? data + i : first;
				}
				// TODO: didn't managed yet
				// LOGD("%c %u %u\n", data[i], i, total);
				// LOGD("add %u \t first %p",
				//      0xFF ^ (data[i] - ch),
				//      (uint8_t *)((uint64_t)(data + i) *
				// 		 (total & 1)));
				// total += 0xFF ^ (data[i] - ch);
				// first = (uint8_t *)((uint64_t)(data + i) *
				// 		    (total & 1));
			}
			if (total == 10) {
				return first;
			}
		}
		data += 32;
	}
	return NULL;
}

// Extract `<id>` out of "/blob/<id>[?query]" style paths.
static bool parse_blob_id(const char *url, char out_id[MAX_ID_LEN + 1])
{
	const char *prefix = "/blob/";
	size_t prefix_len = strlen(prefix);
	if (!url || strncmp(url, prefix, prefix_len) != 0)
		return false;
	const char *id = url + prefix_len;
	if (!*id)
		return false;
	const char *q = strchr(id, '?');
	size_t len = q ? (size_t)(q - id) : strlen(id);
	if (len == 0 || len > MAX_ID_LEN)
		return false;
	memcpy(out_id, id, len);
	out_id[len] = '\0';
	return id_valid(out_id);
}
// ---------------- Rate limiting ----------------
struct RL {
	uint32_t ip;
	double tokens;
	double last;
	bool used;
};
static struct RL g_rl[RL_BUCKETS];
static pthread_mutex_t g_rl_mu = PTHREAD_MUTEX_INITIALIZER;

// Collapse sockaddr* into a bucket key; IPv6 (or others) coarsely share a
// slot.
static uint32_t ip_to_u32(const struct sockaddr *sa)
{
	if (!sa)
		return 0;
	if (sa->sa_family == AF_INET)
		return ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
	return 0; // non-IPv4 share a bucket
}

// Token-bucket guard: one shared limiter per hashed IP.
static bool rl_allow(const struct sockaddr *sa)
{
	uint32_t ip = ip_to_u32(sa);
	uint32_t idx = ip % RL_BUCKETS;
	double t = now_s();

	pthread_mutex_lock(&g_rl_mu);
	struct RL *e = &g_rl[idx];
	if (!e->used || e->ip != ip) {
		e->ip = ip;
		e->tokens = RL_BURST;
		e->last = t;
		e->used = true;
	}
	e->tokens += (t - e->last) * RL_RATE;
	if (e->tokens > RL_BURST)
		e->tokens = RL_BURST;
	e->last = t;
	bool ok = false;
	if (e->tokens >= 1.0) {
		e->tokens -= 1.0;
		ok = true;
	}
	pthread_mutex_unlock(&g_rl_mu);
	LOGD("%s ---> %b\n", __FUNCTION__, ok);
	return ok;
}

// ---------------- HTTP helpers ----------------
// Helper to centralize queueing logic and Content-Type headers.
static enum MHD_Result send_response(struct MHD_Connection *c, unsigned code,
				     const void *data, size_t len,
				     const char *content_type,
				     enum MHD_ResponseMemoryMode mode)
{
	LOGD("responding %lu bytes of %s\n", len, content_type);
	struct MHD_Response *r =
		MHD_create_response_from_buffer(len, (void *)data, mode);
	if (!r)
		return MHD_NO;
	if (content_type)
		MHD_add_response_header(r, "Content-Type", content_type);
	MHD_add_response_header(r, "Cache-Control", "no-store");
	enum MHD_Result res = MHD_queue_response(c, code, r);
	MHD_destroy_response(r);
	return res;
}

// Format and emit a small JSON blob
static enum MHD_Result send_json(struct MHD_Connection *c, unsigned code,
				 const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	return send_response(c, code, buf, strlen(buf),
			     "application/json; charset=utf-8",
			     MHD_RESPMEM_MUST_COPY);
}

// Emit plain text; convenience wrapper around send_response.
static enum MHD_Result send_text(struct MHD_Connection *c, unsigned code,
				 const char *s)
{
	return send_response(c, code, s, strlen(s), "text/plain; charset=utf-8",
			     MHD_RESPMEM_MUST_COPY);
}
// Request ctx for POST accumulation
struct ReqCtx {
	uint8_t *body;
	size_t len, cap;
	char id[MAX_ID_LEN + 1];
	bool have_id;
	bool rate_checked;
};

// Dispose buffers accumulated for the active HTTP request.
static void req_ctx_clear(struct ReqCtx *ctx)
{
	if (!ctx)
		return;
	// POST bodies are zeroed before release to avoid lingering secrets.
	if (ctx->body) {
		secure_zero(ctx->body, ctx->len);
		free(ctx->body);
		ctx->body = NULL;
	}
	ctx->len = 0;
	ctx->cap = 0;
	ctx->have_id = false;
	secure_zero(ctx->id, sizeof(ctx->id));
}

// Main application handler invoked by libmicrohttpd for each HTTP exchange.
// Handles rate limiting, static asset serving, blob POST/GET, and health
// checks.
static enum MHD_Result ahc(void *cls, struct MHD_Connection *conn,
			   const char *url, const char *method, const char *ver,
			   const char *upload_data, size_t *upload_data_size,
			   void **con_cls)
{
	(void)cls;
	(void)ver;

	const union MHD_ConnectionInfo *ci = MHD_get_connection_info(
		conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
#ifdef DEBUG
	LOGD("====== REQ %s ======\n", now_local_iso8601());
	LOGD("%s %s %s\n", method, url, ver);
	// if (ci && ci->client_addr)
	// log_client_addr(ci->client_addr);

	MHD_get_connection_values(conn, MHD_COOKIE_KIND, &log_cookie_cb, NULL);
	MHD_get_connection_values(conn, MHD_GET_ARGUMENT_KIND, &log_query_cb,
				  NULL);

	const char *ctype = MHD_lookup_connection_value(
		conn, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_TYPE);
	const char *clen = MHD_lookup_connection_value(
		conn, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_LENGTH);
	if (ctype) {
		LOGD("-- Body plan -- Content-Type: %s | Content-Length: %s\n",
		     ctype, clen ? clen : "(unknown)");
	}
#endif
	// First call: allocate per-request ctx
	struct ReqCtx *ctx = *con_cls;
	bool new_ctx = false;
	if (!ctx) {
		ctx = (struct ReqCtx *)calloc(1, sizeof(*ctx));
		if (!ctx)
			return MHD_NO;
		*con_cls = ctx;
		new_ctx = true;
	}

	// Per-IP debounce
	// TODO fix debounce; Tailscale proxy is local, parse X-Forwarded-For header
	if (false && !ctx->rate_checked) {
		LOGD("rate dhecking path\n");
		bool allowed = true;
		if (ci && ci->client_addr)
			allowed = rl_allow(ci->client_addr);
		ctx->rate_checked = true;
		if (!allowed)
			return send_text(conn, MHD_HTTP_TOO_MANY_REQUESTS,
					 "Too Many Requests");
	}

	if (new_ctx)
		return MHD_YES;

	// GET
	if (0 == memcmp(method, "GET", 4)) {
		asset_t *asset = NULL;
		if (asset_find(url, &asset)) {
			char str_uptime[10] = { ' ' };
			char str_served[10] = { ' ' };
			sprintf(str_uptime, "%.1fH", app_uptime_hours());
			sprintf(str_served, "%u", statistics.total_served);
			memcpy(html_uptime_ptr, &str_uptime, 10);
			memcpy(html_served_ptr, &str_served, 10);

			return send_response(conn, MHD_HTTP_OK, asset->data,
					     asset->size, asset->content_type,
					     MHD_RESPMEM_PERSISTENT);
		} else if (0 == strcmp(url, "/status")) {
			LOGD("%s requested…\n", url);
			// STATUS
			int used = 0, cap = 0;
			pthread_mutex_lock(&blob_storage.mutex);
			used = blob_storage.in_use;
			cap = blob_storage.capacity;
			pthread_mutex_unlock(&blob_storage.mutex);
			return send_json(
				conn, MHD_HTTP_OK,
				"{\"ok\":true,\"in_use\":%d,\"max\":%d}", used,
				cap);
		} else if (0 == strncmp(url, "/blob/", 6)) {
			LOGD("%s requested…", url);
			// BLOB
			char id[MAX_ID_LEN + 1];
			if (!parse_blob_id(url, id))
				return send_text(conn, MHD_HTTP_BAD_REQUEST,
						 "Bad id");
			uint8_t *blob = NULL;
			size_t blob_len = 0;
			if (!blob_take(id, &blob, &blob_len))
				return send_text(conn, MHD_HTTP_NOT_FOUND,
						 "Not Found");
			enum MHD_Result res =
				send_response(conn, MHD_HTTP_OK, blob, blob_len,
					      "application/octet-stream",
					      MHD_RESPMEM_MUST_COPY);
			secure_zero(blob, blob_len);
			free(blob);
			return res;

		} else {
			LOGE("Client tried to GET %s which is not found", url);
		}
	}
	// POST /blob/<ID>
	else if (0 == strcmp(method, "POST") &&
		 0 == strncmp(url, "/blob/", 6)) {
		char id_buf[MAX_ID_LEN + 1];
		if (!parse_blob_id(url, id_buf))
			return send_text(conn, MHD_HTTP_BAD_REQUEST, "Bad id");
		if (!ctx->have_id) {
			strncpy(ctx->id, id_buf, sizeof(ctx->id) - 1);
			ctx->id[sizeof(ctx->id) - 1] = '\0';
			ctx->have_id = true;
		} else if (strcmp(ctx->id, id_buf) != 0) {
			return send_text(conn, MHD_HTTP_BAD_REQUEST, "Bad id");
		}
		if (*upload_data_size) {
			const size_t max_blob = MAX_BLOB_SIZE;
			size_t incoming = *upload_data_size;
			if (ctx->len >= max_blob || incoming > max_blob ||
			    incoming > max_blob - ctx->len) {
				*upload_data_size = 0;
				return send_text(conn,
						 MHD_HTTP_CONTENT_TOO_LARGE,
						 "Payload Too Large");
			}
			size_t need = ctx->len + incoming;
			if (need > ctx->cap) {
				size_t ncap = MAX(
					4096, ctx->cap ? ctx->cap * 2 : 4096);
				while (ncap < need)
					ncap *= 2;
				if (ncap > MAX_BLOB_SIZE)
					ncap = MAX_BLOB_SIZE;
				uint8_t *nb =
					(uint8_t *)realloc(ctx->body, ncap);
				if (!nb) {
					*upload_data_size = 0;
					return send_text(
						conn,
						MHD_HTTP_INTERNAL_SERVER_ERROR,
						"OOM");
				}
				ctx->body = nb;
				ctx->cap = ncap;
			}
			memcpy(ctx->body + ctx->len, upload_data,
			       *upload_data_size);
			ctx->len += *upload_data_size;
			*upload_data_size = 0;
			return MHD_YES;
		} else {
			if (!ctx->body || ctx->len < MIN_BLOB_SIZE) {
				req_ctx_clear(ctx);
				return send_text(conn, MHD_HTTP_BAD_REQUEST,
						 "Bad blob");
			}
			enum BlobPutStatus st =
				blob_put(ctx->id, ctx->body, ctx->len);
			req_ctx_clear(ctx);
			switch (st) {
			case BLOB_PUT_OK:
				++(statistics.total_served);
				return send_json(conn, MHD_HTTP_OK,
						 "{\"ok\":true}");
			case BLOB_PUT_DUP:
				return send_text(conn, MHD_HTTP_CONFLICT,
						 "Duplicate id");
			case BLOB_PUT_FULL:
				return send_text(conn,
						 MHD_HTTP_SERVICE_UNAVAILABLE,
						 "Store Unavailable");
			default:
				return send_text(conn,
						 MHD_HTTP_INTERNAL_SERVER_ERROR,
						 "Store Failure");
			}
		}
	}

	return send_text(conn, MHD_HTTP_NOT_FOUND, "Not Found");
}

static void req_done(void *cls, struct MHD_Connection *c, void **con_cls,
		     enum MHD_RequestTerminationCode toe)
{
	(void)cls;
	(void)c;
	(void)toe;
	if (*con_cls) {
		struct ReqCtx *ctx = (struct ReqCtx *)(*con_cls);
		req_ctx_clear(ctx);
		free(ctx);
		*con_cls = NULL;
	}
}

static volatile sig_atomic_t stop_request_loop = 0;
// Set by signal handlers to break the request loop.
static void on_sigint(int s)
{
	(void)s;
	stop_request_loop = 1;
	reaper_stop = 1;
}

int main(int argc, char **argv)
{
	const char *cert_path = "cert.pem";
	const char *key_path = "key.pem";
	uint port = DEFAULT_PORT;
	int ttl_sec = DEFAULT_TTL_SEC;
	int max_blobs = DEFAULT_MAX_BLOBS;
	uint thread_pool_size = 0;
	bool use_tls = true;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--port") && i + 1 < argc)
			port = (unsigned short)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--cert") && i + 1 < argc)
			cert_path = argv[++i];
		else if (!strcmp(argv[i], "--key") && i + 1 < argc)
			key_path = argv[++i];
		else if (!strcmp(argv[i], "--ttl") && i + 1 < argc)
			ttl_sec = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--max") && i + 1 < argc)
			max_blobs = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--threads") && i + 1 < argc) {
			long v = strtol(argv[++i], NULL, 10);
			if (v > 0 && v <= UINT_MAX)
				thread_pool_size = (unsigned int)v;
		} else if (!strcmp(argv[i], "--http"))
			use_tls = false;
		else if (!strcmp(argv[i], "--help")) {
			fprintf(stderr,
				"Usage: %s [--port N] [--cert cert.pem] [--key key.pem] [--ttl "
				"SEC] [--max N] [--threads N] [--http]\n",
				argv[0]);
			return EXIT_SUCCESS;
		}
	}

	log_init();
	LOG("Epha init.");

	if (thread_pool_size == 0) {
		long cpu = sysconf(_SC_NPROCESSORS_ONLN);
		if (cpu > 1 && cpu <= (long)UINT_MAX)
			thread_pool_size = (unsigned int)cpu - 1;
		else
			thread_pool_size = DEFAULT_THREAD_POOL_SIZE;
	}

	// Init store & reaper
	blob_storage.items =
		(struct blob_t *)calloc(max_blobs, sizeof(struct blob_t));
	if (!blob_storage.items) {
		LOGE("OOM");
		log_close();
		return EXIT_FAILURE;
	}
	blob_storage.capacity = max_blobs;
	blob_storage.ttl_seconds = ttl_sec;

	pthread_t tid;
	if (pthread_create(&tid, NULL, reaper_thread, NULL) != 0) {
		LOGE("Failed to start reaper");
		log_close();
		return EXIT_FAILURE;
	}
	reaper_tid = tid;
	reaper_started = true;

	// TLS
	if (use_tls) {
		if (!MHD_is_feature_supported(MHD_FEATURE_TLS)) {
			LOGE("libmicrohttpd built without TLS; use --http or install "
			     "TLS-enabled build.");
			log_close();
			return EXIT_FAILURE;
		}
		if (tls_data_load(cert_path, key_path)) {
			LOGE("Failed to read TLS cert/key (cert=%s, key=%s)",
			     cert_path, key_path);
			log_close();
			return EXIT_FAILURE;
		}
	}

	if (!MHD_is_feature_supported(MHD_FEATURE_THREADS)) {
		LOGE("libmicrohttpd built without thread support; thread pool required.");
		log_close();
		return EXIT_FAILURE;
	}

	if (!assets_load()) {
		LOGE("Failed to load assets.");
		log_close();
		return EXIT_FAILURE;
	}

	html_uptime_ptr = find_10(assets[ASSET_CLIENT_HTML].data,
				  assets[ASSET_CLIENT_HTML].size, 'U');
	html_served_ptr = find_10(assets[ASSET_CLIENT_HTML].data,
				  assets[ASSET_CLIENT_HTML].size, 'S');
	statistics.start_time = now_s();

	unsigned int daemon_flags = MHD_USE_INTERNAL_POLLING_THREAD |
				    (use_tls ? MHD_USE_TLS : 0);
	struct MHD_Daemon *d =
		use_tls ?
			MHD_start_daemon(
				daemon_flags, port, NULL, NULL, &ahc, NULL,
				MHD_OPTION_HTTPS_MEM_KEY, tls_key,
				MHD_OPTION_HTTPS_MEM_CERT, tls_cert,
				MHD_OPTION_THREAD_POOL_SIZE, thread_pool_size,
				MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
				MHD_OPTION_NOTIFY_COMPLETED, req_done, NULL,
				MHD_OPTION_LISTENING_ADDRESS_REUSE, 1,
				MHD_OPTION_END) :
			MHD_start_daemon(
				daemon_flags, port, NULL, NULL, &ahc, NULL,
				MHD_OPTION_THREAD_POOL_SIZE, thread_pool_size,
				MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
				MHD_OPTION_NOTIFY_COMPLETED, req_done, NULL,
				MHD_OPTION_LISTENING_ADDRESS_REUSE, 1,
				MHD_OPTION_END);

	if (!d) {
		perror("MHD_start_daemon");
		LOGE("Failed to start daemon on port %u. Hints:\n"
		     "  - Port busy? try --port 9000\n"
		     "  - TLS disabled in libmicrohttpd? use --http\n"
		     "  - Invalid cert/key? regenerate dev certs",
		     port);
		tls_data_free();
		log_close();
		return EXIT_FAILURE;
	}

	LOG("%s epha-ots server on :%u (TTL=%ds, max=%d, %.1fKiB/blob, pool=%u threads)",
	    use_tls ? "HTTPS" : "HTTP", port, ttl_sec, max_blobs,
	    ((float)MAX_BLOB_SIZE / 1024.0f), thread_pool_size);
	LOG("Endpoints: POST /blob/<id>, GET /blob/<id>, GET /status");

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);

	while (!stop_request_loop)
		pause();

	reaper_stop = 1;
	if (reaper_started) {
		// Wait for the janitor thread so it cannot touch freed slots
		pthread_join(reaper_tid, NULL);
		reaper_started = false;
	}

	MHD_stop_daemon(d);
	tls_data_free();
	assets_free();

	pthread_mutex_lock(&blob_storage.mutex);
	for (int i = 0; i < blob_storage.capacity; i++)
		if (blob_storage.items[i].in_use)
			blob_free_locked(&blob_storage.items[i]);
	secure_zero(blob_storage.items,
		    (size_t)blob_storage.capacity * sizeof(struct blob_t));
	free(blob_storage.items);
	pthread_mutex_unlock(&blob_storage.mutex);

	LOG("Epha exit normal.");
	log_close();
	return EXIT_SUCCESS;
}
