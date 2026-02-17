/*
 * Copyright (C) 2025 epha-ots authors
 *
 * This file is part of epha-ots.
 *
 * epha-ots is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * epha-ots is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with epha-ots.  If not, see <https://www.gnu.org/licenses/>.
 */
// SPDX-License-Identifier: GPL-3.0-or-later
// epha-ots server

#include <sys/types.h>
#define _GNU_SOURCE
#include <microhttpd.h>

#if SIMD_X86
#include <immintrin.h>
#endif

#if SIMD_ARM
#include <arm_neon.h>
#endif

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "version.h"
#include "log.h"
#include "debug_stuff.h"
#include "balloc.h"
#include "storage.h"
#if DEBOUNCER
#include "debouncer.h"
#endif

#ifdef TRACY_ENABLE
#include "tracy/TracyC.h"
#endif

// ---------------- Config ----------------
#define DEFAULT_PORT (8443)
#define BLOB_SIZE_MIN (12 + 16 + 2 + 16) // nonce + salt + marker + GCM tag

#define REAPER_INTERVAL_S (5)
#define EPOLL_EVENTS_MAX (2)
#define REQUESTS_MAX (1024 * 8)
#if DEBOUNCER
#define PER_IP_CONN_LIMIT (8)
#endif

#define STORAGE_BLOBS_MAX (2 * 131072)
#define ID_LENGTH (32)
#define BLOB_TTL_S (60 * 60)

// NOTE: be careful
#define REPLACE_SIZE (16)
#define REPLACE_UPTIME_CH ('U')
#define REPLACE_SERVED_CH ('S')
#define REPLACE_VERSION_CH ('V')

static struct {
	uint total_served;
	// used to count uptime
	monotonic_time_t start_time;
#if STATISTICS
	uint64_t req_ctx_total_created;
	uint64_t req_ctx_alive_current;
	uint64_t req_ctx_alive_max;
	uint64_t connections_total;
	uint64_t connections_unknown;
	uint64_t connections_debounced;
#endif
} statistics;

float app_uptime_hours()
{
	return (float)(monotonic_now_s() - statistics.start_time) / 60.f / 60.f;
}

#if TAILSCALE
static bool tailscale_forwarded_addr(struct MHD_Connection *conn,
				     struct sockaddr_storage *out)
{
	const char *xff = MHD_lookup_connection_value(conn, MHD_HEADER_KIND,
						      "X-Forwarded-For");
	if (!xff || !*xff)
		return false;

	char buf[INET6_ADDRSTRLEN];
	size_t len = strcspn(xff, ",");
	if (len == 0)
		return false;
	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;
	memcpy(buf, xff, len);
	buf[len] = '\0';

	memset(out, 0, sizeof(*out));

	struct sockaddr_in *v4 = (struct sockaddr_in *)out;
	if (inet_pton(AF_INET, buf, &v4->sin_addr) == 1) {
		v4->sin_family = AF_INET;
		return true;
	}

	struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)out;
	if (inet_pton(AF_INET6, buf, &v6->sin6_addr) == 1) {
		v6->sin6_family = AF_INET6;
		return true;
	}

	return false;
}
#endif

static const struct sockaddr *
connection_peer_addr([[maybe_unused]] struct MHD_Connection *conn,
		     const union MHD_ConnectionInfo *ci,
		     [[maybe_unused]] struct sockaddr_storage *storage,
		     bool *forwarded)
{
	if (forwarded)
		*forwarded = false;
#if TAILSCALE
	if (tailscale_forwarded_addr(conn, storage)) {
		if (forwarded)
			*forwarded = true;
		return (const struct sockaddr *)storage;
	}
#endif
	return ci ? ci->client_addr : NULL;
}

enum HEADER_PROFILE {
	HP_OTHER,
	HP_HTML_VIEWER,
	HP_STATIC_ASSET,
	HP_API_BLOB,
	HP_COUNT
};

#define _CONTENT_TYPE_STRING_MAX_SIZE (38)
#define _CONTENT_TYPE_HTML "text/html; charset=utf-8"
#define _CONTENT_TYPE_CSS "text/css; charset=utf-8"
#define _CONTENT_TYPE_JS "application/javascript; charset=utf-8"
#define _CONTENT_TYPE_SVG "image/svg+xml"

/*
 * STATIC ASSETS
 */

typedef struct {
	uint8_t *data;
	size_t size;
	const char content_type[_CONTENT_TYPE_STRING_MAX_SIZE];
} asset_t;

enum assets_id_t {
#if ASSEMBLED_HTML
	ASSET_CLIENT_ASSEMBLED_HTML = 0,
#else
	ASSET_CLIENT_HTML = 0,
	ASSET_CLIENT_CSS,
	ASSET_CLIENT_JS,
	ASSET_QRCODE_JS,
#endif
	ASSET_FAVICON_SVG,
	ASSETS_COUNT,
};
static uint8_t *assets_memory;

static asset_t assets[ASSETS_COUNT] = {
#if ASSEMBLED_HTML
	[ASSET_CLIENT_ASSEMBLED_HTML] = { .content_type = _CONTENT_TYPE_HTML },
#else
	[ASSET_CLIENT_HTML] = { .content_type = _CONTENT_TYPE_HTML },
	[ASSET_CLIENT_CSS] = { .content_type = _CONTENT_TYPE_CSS },
	[ASSET_CLIENT_JS] = { .content_type = _CONTENT_TYPE_JS },
	[ASSET_QRCODE_JS] = { .content_type = _CONTENT_TYPE_JS },
#endif
	[ASSET_FAVICON_SVG] = { .content_type = _CONTENT_TYPE_SVG }
};

static const char *asset_file_paths[ASSETS_COUNT] = {
#if ASSEMBLED_HTML
	[ASSET_CLIENT_ASSEMBLED_HTML] = "assets/client_assembled.html",
#else
	[ASSET_CLIENT_HTML] = "assets/client.html",
	[ASSET_CLIENT_CSS] = "assets/client.css",
#if JS_MINIFY
	[ASSET_CLIENT_JS] = "assets/client.min.js",
	[ASSET_QRCODE_JS] = "assets/qrcode.min.js",
#else
	[ASSET_CLIENT_JS] = "assets/client.js",
	[ASSET_QRCODE_JS] = "assets/qrcode.js",
#endif
#endif
	[ASSET_FAVICON_SVG] = "assets/favicon.svg",
};

#define ASSET_PATH_STRING_MAX_SIZE 15
static const char asset_paths[ASSETS_COUNT][ASSET_PATH_STRING_MAX_SIZE] = {
#if ASSEMBLED_HTML
	[ASSET_CLIENT_ASSEMBLED_HTML] = "/",
#else
	[ASSET_CLIENT_HTML] = "/",
	[ASSET_CLIENT_CSS] = "/client.css",
	[ASSET_CLIENT_JS] = "/client.js",
	[ASSET_QRCODE_JS] = "/qrcode.js",
#endif
	[ASSET_FAVICON_SVG] = "/favicon.svg",
};

/*
 * In case of errors server will not start, thus we do not care of closing fds — OS will do it automatically
 */
ssize_t open_file_and_get_size(const char *file_path, int *fd_out)
{
	int fd = open(file_path, O_RDONLY);
	if (fd < 0) {
		LOGE("Failed to open file %s", file_path);
		return -1;
	}
	*fd_out = fd;
	struct stat statbuf = { 0 };
	if (fstat(fd, &statbuf) < 0) {
		LOGE("Failed to get the size of file %s", file_path);
		return -1;
	}
	ssize_t file_size = statbuf.st_size; 
	if (file_size <= 0) {
		LOGE("Unacceptable size of file %s (%ld bytes)", file_path, file_size);
		return -1;
	}
	return file_size;
}

bool read_and_close_file(int fd, uint8_t *out, ssize_t size)
{
	for (ssize_t offset = 0; offset < size;) {
		ssize_t bytes_read = read(fd, out + offset, size - offset);
		if (0 == bytes_read) {
			LOGE("File is shorter than expected (%ld vs %ld)",
			     offset, size);
			return false;
		}
		if (-1 == bytes_read) {
			LOGE("Error while reading %s", strerror(errno));
			return false;
		}
		offset += bytes_read;
	}
	close(fd);
	return true;
}

/*
 * In case of errors server will not start, thus we do not care of closing fds — OS will do it automatically
 */
bool assets_load()
{
	int file_descriptors[ASSETS_COUNT] = {};
	ssize_t asset_sizes[ASSETS_COUNT] = {}, assets_size_total = 0;
	// open assets and calculate size
	for (size_t i = 0; i < ASSETS_COUNT; ++i) {
		ssize_t asset_size = open_file_and_get_size(
			asset_file_paths[i], &file_descriptors[i]);
		if (asset_size < 0) {
			return false;
		}
		asset_sizes[i] = asset_size;
		assets_size_total += asset_size;
	}

	// allocate memory
	assets_memory = (uint8_t *)malloc(assets_size_total);
	if (!assets_memory) {
		LOGE("Failed to allocate %lu bytes", assets_size_total);
		return false;
	}

	// read files
	uint8_t *current_ptr = assets_memory;
	for (size_t i = 0; i < ASSETS_COUNT; ++i) {
		size_t asset_size = asset_sizes[i];

		if (!read_and_close_file(file_descriptors[i], current_ptr,
					 asset_size)) {
			LOGE("Failed to read file %s", asset_file_paths[i]);
			return false;
		}

		assets[i].data = current_ptr;
		assets[i].size = asset_size;
		current_ptr += asset_size;
	}
	LOG("%u static assets loaded for paths:", ASSETS_COUNT);
	for (size_t i = 0; i < ASSETS_COUNT; ++i) {
		LOG("%s", asset_paths[i]);
		LOGD("%s\t%.1fKiB\n", asset_file_paths[i],
		     (float)assets[i].size / 1024.f);
	}
	LOGD("total size %lu bytes\n", assets_size_total);
	return true;
}

bool asset_find(const char *url, asset_t **asset)
{
	for (size_t i = 0; i < ASSETS_COUNT; ++i) {
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
void tls_data_zero()
{
	if (!tls_key_and_cert_memory)
		return;
	secure_zero(tls_key_and_cert_memory, tls_key_and_cert_memory_size);
}

/*
 * TLS helpers
 * In case of errors server will not start, thus we do not care of closing fds — OS will do it automatically
  */
bool tls_data_load(const char *cert_path, const char *key_path)
{
	int cert_file = -1;
	int key_file = -1;

	ssize_t cert_size = open_file_and_get_size(cert_path, &cert_file);
	if (cert_size < 0) {
		return false;
	}

	ssize_t key_size = open_file_and_get_size(key_path, &key_file);
	if (key_size < 0) {
		return false;
	}

	tls_key_and_cert_memory_size = cert_size + key_size + 2; // 2 for \0
	tls_key_and_cert_memory =
		(uint8_t *)malloc(tls_key_and_cert_memory_size);
	if (!tls_key_and_cert_memory) {
		LOGE("Failed to allocate %zu bytes for certificate the and the key",
		     tls_key_and_cert_memory_size);
	}
	tls_key = tls_key_and_cert_memory;
	tls_cert = tls_key_and_cert_memory + key_size + 1;

	if (!read_and_close_file(cert_file, tls_cert, cert_size)) {
		LOGE("Error while reading %s", cert_path);
		return false;
	}
	tls_cert[cert_size] = '\0';

	if (!read_and_close_file(key_file, tls_key, key_size)) {
		LOGE("Error while reading %s", cert_path);
		return false;
	}
	tls_key[key_size] = '\0';

	return false;
}

static bool all16_eq_byte_scalar(const uint8_t *data, size_t remaining,
				 uint8_t ch)
{
	if (remaining < REPLACE_SIZE)
		return false;
	for (size_t i = 0; i < REPLACE_SIZE; ++i) {
		if (data[i] != ch)
			return false;
	}
	return true;
}

static bool all16_eq_byte(const uint8_t *data, size_t remaining, uint8_t ch)
{
	if (remaining < REPLACE_SIZE)
		return false;
#if SIMD_X86
	if (remaining >= 16) {
		__m128i v = _mm_loadu_si128((const __m128i *)data);
		__m128i c = _mm_set1_epi8((char)ch);
		__m128i eq = _mm_cmpeq_epi8(v, c);
		unsigned int mask = (unsigned int)_mm_movemask_epi8(eq);
		const unsigned int full = (REPLACE_SIZE == 32) ?
						  0xFFFFFFFFu :
						  ((1u << REPLACE_SIZE) - 1u);
		return (mask & full) == full;
	}
#elif SIMD_ARM
	if (remaining >= 16) {
		uint8x16_t v = vld1q_u8(data);
		uint8x16_t c = vdupq_n_u8(ch);
		uint8x16_t eq = vceqq_u8(v, c);
		uint8_t mask[16];
		vst1q_u8(mask, eq);
		for (size_t i = 0; i < REPLACE_SIZE; ++i) {
			if (mask[i] != 0xFF)
				return false;
		}
		return true;
	}
#endif
	return all16_eq_byte_scalar(data, remaining, ch);
}

static char *html_uptime_ptr, *html_served_ptr, *html_version_ptr;

static uint8_t *find_16_scalar(const uint8_t *data, size_t size, uint8_t ch)
{
	if (size < REPLACE_SIZE)
		return NULL;
	for (size_t i = 0; i <= size - REPLACE_SIZE; ++i) {
		if (data[i] == ch &&
		    all16_eq_byte_scalar(data + i, size - i, ch))
			return (uint8_t *)(data + i);
	}
	return NULL;
}

static uint8_t *find_16(const uint8_t *data, size_t size, const char ch)
{
	// although it is five times faster, we are talking
	// about few microseconds, twice for the lifetime
	[[maybe_unused]] const uint8_t *end = data + size;
#if SIMD_X86 && defined(__AVX2__)
	__m256i target = _mm256_set1_epi8(ch);
	while ((size_t)(end - data) >= 32) {
		__m256i v = _mm256_loadu_si256((const __m256i *)data);
		__m256i eq = _mm256_cmpeq_epi8(v, target);
		if (!_mm256_testz_si256(eq, eq)) {
			uint8_t mask[32];
			_mm256_storeu_si256((__m256i *)mask, eq);
			for (size_t i = 0; i < 32; ++i) {
				size_t remaining = (size_t)(end - (data + i));
				if (mask[i] == 0xFF &&
				    all16_eq_byte(data + i, remaining,
						  (uint8_t)ch))
					return (uint8_t *)(data + i);
			}
		}
		data += 32;
	}
	return find_16_scalar(data, (size_t)(end - data), (uint8_t)ch);
#elif SIMD_ARM
	uint8x16_t target = vdupq_n_u8((uint8_t)ch);
	while ((size_t)(end - data) >= 16) {
		uint8x16_t v = vld1q_u8(data);
		uint8x16_t eq = vceqq_u8(v, target);
		uint8_t mask[16];
		vst1q_u8(mask, eq);
		for (size_t i = 0; i < 16; ++i) {
			size_t remaining = (size_t)(end - (data + i));
			if (mask[i] == 0xFF &&
			    all16_eq_byte(data + i, remaining, (uint8_t)ch))
				return (uint8_t *)(data + i);
		}
		data += 16;
	}
	return find_16_scalar(data, (size_t)(end - data), (uint8_t)ch);
#else
	return find_16_scalar(data, size, (uint8_t)ch);
#endif
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverride-init"
static const int HEXVAL[256] = {
	/* default -1 (0xFF) -> we’ll treat high bit as “invalid” */
	[0 ... 255] = (signed char)0x80,
	['0'] = 0,
	['1'] = 1,
	['2'] = 2,
	['3'] = 3,
	['4'] = 4,
	['5'] = 5,
	['6'] = 6,
	['7'] = 7,
	['8'] = 8,
	['9'] = 9,
	['A'] = 10,
	['B'] = 11,
	['C'] = 12,
	['D'] = 13,
	['E'] = 14,
	['F'] = 15,
	['a'] = 10,
	['b'] = 11,
	['c'] = 12,
	['d'] = 13,
	['e'] = 14,
	['f'] = 15
};
#pragma GCC diagnostic pop

bool id_hex_to_bytes(const char *restrict in, uint8_t *restrict out)
{
	const unsigned char *s = (const unsigned char *)in;
	size_t o = 0;
	for (size_t i = 0; i < ID_LENGTH; i += 2) {
		unsigned a = (unsigned)HEXVAL[s[i + 0]];
		unsigned b = (unsigned)HEXVAL[s[i + 1]];
		if ((a | b) & 0x80)
			return false;
		out[o++] = (unsigned char)((a << 4) | b);
	}
	return true;
}

// ---------------- HTTP helpers ----------------
// Helper to centralize queueing logic and Content-Type headers.
static enum MHD_Result send_response(struct MHD_Connection *c, unsigned code,
				     const void *data, size_t len,
				     const char *content_type,
				     enum MHD_ResponseMemoryMode mode,
				     enum HEADER_PROFILE header_profile)
{
	LOGD("responding %lu bytes of %s\n", len,
	     content_type ? content_type : "~");
	struct MHD_Response *resp =
		MHD_create_response_from_buffer(len, (void *)data, mode);
	if (!resp)
		return MHD_NO;
	MHD_add_response_header(resp, "X-Content-Type-Options", "nosniff");
	if (content_type)
		MHD_add_response_header(resp, "Content-Type", content_type);

	switch (header_profile) {
	case HP_HTML_VIEWER:
		MHD_add_response_header(resp, "Referrer-Policy", "no-referrer");
		MHD_add_response_header(resp, "X-Frame-Options", "DENY");
		MHD_add_response_header(resp, "Cross-Origin-Opener-Policy",
					"same-origin");
		MHD_add_response_header(resp, "Cross-Origin-Resource-Policy",
					"same-site");

		break;
	case HP_STATIC_ASSET:
		MHD_add_response_header(resp, "Referrer-Policy", "no-referrer");
		MHD_add_response_header(resp, "X-Frame-Options", "DENY");
		MHD_add_response_header(resp, "Cross-Origin-Opener-Policy",
					"same-origin");
		break;
	case HP_OTHER:
	case HP_API_BLOB:
		MHD_add_response_header(resp, "Cache-Control", "no-store");
		MHD_add_response_header(resp, "Referrer-Policy", "no-referrer");
		MHD_add_response_header(resp, "Cross-Origin-Resource-Policy",
					"same-origin");
		break;
	default:
		unreachable();
		break;
	}

	enum MHD_Result res = MHD_queue_response(c, code, resp);
	MHD_destroy_response(resp);
	return res;
}

// Emit plain text; convenience wrapper around send_response.
static enum MHD_Result send_text(struct MHD_Connection *c, unsigned code,
				 const char *s)
{
	return send_response(c, code, s, strlen(s), "text/plain; charset=utf-8",
			     MHD_RESPMEM_MUST_COPY, HP_OTHER);
}

typedef struct req_ctx_t {
	blk_t *post_body; // allocation that receives an in-flight POST body
	blk_t *blob_send; // blob fetched for GET replies; freed after send
	blk_size_t expected; // advertised Content-Length for the current POST
	blk_size_t read; // bytes already written into post_body->data
	htable_key_t id; // blob identifier associated with this request
	bool have_id; // guards against mid-stream ID changes
#if DEBOUNCER
	bool rate_checked; // ensures we only rate-limit once per connection
#endif
} req_ctx_t;

#include "flalloc.h"

static flalloc_t *req_flalloc;

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
#ifdef TRACY_ENABLE
	static _Thread_local bool tracy_named = false;
	if (!tracy_named) {
		TracyCSetThreadName("http-handler");
		tracy_named = true;
	}
	TracyCZoneN(ahc_zone, "ahc", 1);
#define AHC_RETURN(value)                \
	do {                             \
		TracyCZoneEnd(ahc_zone); \
		return (value);          \
	} while (0)
#else
#define AHC_RETURN(value) return (value)
#endif

	const union MHD_ConnectionInfo *ci = MHD_get_connection_info(
		conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
#ifdef DEBUG
	LOGD("====== REQ %s ======\n", now_local_iso8601());
	LOGD("%s %s %s\n", method, url, ver);

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
	struct req_ctx_t *ctx = *con_cls;
	bool new_ctx = false;
	if (!ctx) {
#ifdef TRACY_ENABLE
		TracyCZoneN(req_ctx_alloc_zone, "req_ctx_alloc", 1);
#endif
		ctx = flaalloc(req_flalloc);
#ifdef TRACY_ENABLE
		TracyCZoneEnd(req_ctx_alloc_zone);
#endif
		if (!ctx)
			AHC_RETURN(MHD_NO);
#if STATISTICS
		statistics.req_ctx_total_created += 1;
		statistics.req_ctx_alive_current += 1;
		if (statistics.req_ctx_alive_current >
		    statistics.req_ctx_alive_max) {
			statistics.req_ctx_alive_max =
				statistics.req_ctx_alive_current;
		}
#endif
		*con_cls = ctx;
		new_ctx = true;
	}

	struct sockaddr_storage peer_storage;
#if STATISTICS
	bool forwarded = false;
#endif
	const struct sockaddr *peer = connection_peer_addr(conn, ci,
							   &peer_storage,
#if STATISTICS
							   &forwarded
#else
							   NULL
#endif
	);

	bool is_get = (0 == memcmp(method, "GET", 4));
	asset_t *asset = NULL;
	bool is_get_path_static = false;
	bool is_get_path_root = false;
	if (is_get) {
		is_get_path_root = 0 == memcmp(url, "/", 2);
		is_get_path_static = asset_find(url, &asset);
	}

#if STATISTICS
	if (new_ctx) {
		statistics.connections_total += 1;
		if (!peer)
			statistics.connections_unknown += 1;
	}
#endif

#if DEBOUNCER
	// Per-IP debounce
	if (!ctx->rate_checked) {
		ctx->rate_checked = true;
		bool should_limit = !is_get_path_static;
		if (should_limit && !debouncer_allow_addr(peer)) {
			LOGD("Request debounced (429 Too Many Requests).\n");
#if STATISTICS
			statistics.connections_debounced += 1;
#endif
			AHC_RETURN(send_text(conn, MHD_HTTP_TOO_MANY_REQUESTS,
					     "Too Many Requests"));
		}
	}
#endif

	if (new_ctx)
		AHC_RETURN(MHD_YES);

	bool is_path_blob = 0 == strncmp(url, "/blob/", 6);

	if (!is_path_blob) {
		LOGD("%s requested…\n", url);
		if (is_get_path_static) {
			if (is_get_path_root) {
				// NOTE: be careful
				snprintf(html_uptime_ptr, REPLACE_SIZE,
					 "%-14.1fH", app_uptime_hours());
				html_uptime_ptr[REPLACE_SIZE - 1] = ' ';
				// NOTE: be careful
				snprintf(html_served_ptr, REPLACE_SIZE, "%-15u",
					 statistics.total_served);
				html_served_ptr[REPLACE_SIZE - 1] = ' ';
				// NOTE: be careful
				snprintf(html_version_ptr, REPLACE_SIZE,
					 "%-15.15s", EPHA_VERSION);
				html_version_ptr[REPLACE_SIZE - 1] = ' ';
			}
			AHC_RETURN(send_response(
				conn, MHD_HTTP_OK, asset->data, asset->size,
				asset->content_type, MHD_RESPMEM_PERSISTENT,
				is_get_path_root ? HP_HTML_VIEWER :
						   HP_STATIC_ASSET));
		} else if (0 == strncmp(url, "/status", 8)) {
			storage_status_t stats = storage_status();
			size_t blobs_in_use = 0;
			for (size_t j = 0;
			     j < sizeof(stats.in_use) / sizeof(stats.in_use[0]);
			     ++j) {
				blobs_in_use += stats.in_use[j];
			}

			char payload[256];
#if STATISTICS
			int written = snprintf(
				payload, sizeof(payload),
				"{\"uptime_hours\":%.1f,\"total_served\":%u,"
				"\"blobs_in_use\":%zu,\"connections\":{"
				"\"total\":%lu,\"unknown\":%lu,"
				"\"debounced\":%lu}}",
				app_uptime_hours(), statistics.total_served,
				blobs_in_use, statistics.connections_total,
				statistics.connections_unknown,
				statistics.connections_debounced);
#else
			int written = snprintf(payload, sizeof(payload),
					       "{\"uptime_hours\":%.1f,"
					       "\"total_served\":%u,"
					       "\"blobs_in_use\":%zu}",
					       app_uptime_hours(),
					       statistics.total_served,
					       blobs_in_use);
#endif
			if (written < 0 || (size_t)written >= sizeof(payload)) {
				AHC_RETURN(send_text(
					conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
					"Status error"));
			}

			AHC_RETURN(send_response(
				conn, MHD_HTTP_OK, payload, (size_t)written,
				"application/json; charset=utf-8",
				MHD_RESPMEM_MUST_COPY, HP_OTHER));
		}
	} else if (ID_LENGTH == strnlen(url + 6, 1 + ID_LENGTH)) {
		// path is '/blob/*'
		htable_key_t id;
		if (!id_hex_to_bytes(url + 6, id.bytes)) {
			LOGD("%s Bad id!\n", url);
			AHC_RETURN(send_text(conn, MHD_HTTP_BAD_REQUEST,
					     "Bad id"));
		}
		if (is_get) {
			// GET /blob/*
			blk_t *blob = storage_blob_get(id);
			if (!blob) {
				LOGD("%s Not found!\n", url);
				AHC_RETURN(send_text(conn, MHD_HTTP_NOT_FOUND,
						     "Not Found"));
			}
			ctx->blob_send = blob;
			AHC_RETURN(send_response(
				conn, MHD_HTTP_OK, blob->data, blob->size,
				"application/octet-stream",
				MHD_RESPMEM_PERSISTENT, HP_API_BLOB));
		} else if (0 == strncmp(method, "POST", 5)) {
			// POST /blob/*
			if (!ctx->have_id) {
				ctx->id.h = id.h;
				ctx->id.l = id.l;
				ctx->have_id = true;
			} else if (ctx->id.h != id.h || ctx->id.l != id.l) {
				LOGD("%s Bad id (request was initially for another ID)!\n",
				     url);
				AHC_RETURN(send_text(conn, MHD_HTTP_BAD_REQUEST,
						     "Bad id"));
			}

			// if we have something to read
			if (*upload_data_size) {
				// get the blob size via header
				if (0 == ctx->expected) {
					const char *content_length_str =
						MHD_lookup_connection_value(
							conn, MHD_HEADER_KIND,
							"Content-Length");
					if (content_length_str) {
						unsigned long content_length =
							strtoul(content_length_str,
								NULL, 10);
						// is content length provided?
						if (!content_length ||
						    ULONG_MAX ==
							    content_length) {
							AHC_RETURN(send_text(
								conn,
								MHD_HTTP_BAD_REQUEST,
								"Bad Content-Length"));
						}
						// is size ok?
						bool is_too_large =
							content_length >
							BLOB_SIZE_MAX;
						bool is_too_small =
							content_length <
							BLOB_SIZE_MIN;
						if (is_too_large ||
						    is_too_small) {
							LOGD("%s the blob is too large (%.2f)KiB!\n",
							     url,
							     (double)ctx->expected /
								     1024.0);
							*upload_data_size = 0;
							AHC_RETURN(send_text(
								conn,
								MHD_HTTP_CONTENT_TOO_LARGE,
								is_too_large ?
									"Payload Too Large" :
									"Payload Too Small"));
						}
						ctx->expected = content_length;
					} else {
						LOGD("%s no content header!\n",
						     url);
						AHC_RETURN(send_text(
							conn,
							MHD_HTTP_CONTENT_TOO_LARGE,
							"Provide Content-Length header."));
					}
				}

				size_t incoming = *upload_data_size;
				LOGD("content lenght %u, already read %u"
				     "\nincoming data: %zu(%.2fKiB)\n",
				     ctx->expected, ctx->read, incoming,
				     (double)incoming / 1024.0);

				if (!ctx->post_body) {
					// storage CREATE
					if (storage_blob_is_already_taken(
						    ctx->id)) {
						LOGD("%s trying to put a duplicate!\n",
						     url);
						AHC_RETURN(send_text(
							conn,
							MHD_HTTP_BAD_REQUEST,
							"Duplicate!"));
					}
					monotonic_time_t valid_until =
						monotonic_now_s() + BLOB_TTL_S;
					ctx->post_body = storage_blob_create(
						ctx->id, ctx->expected,
						valid_until);
					if (!ctx->post_body) {
						LOGD("%s cannot get the chunk for the blob!\n",
						     url);
						AHC_RETURN(send_text(
							conn,
							MHD_HTTP_INTERNAL_SERVER_ERROR,
							"OOM"));
					}
				}
				if (ctx->read + incoming >
				    ctx->post_body->size) {
					blk_size_t remaining =
						ctx->post_body->size -
						ctx->read;
					LOGD("%s payload overflow: read=%u incoming=%zu size=%u\n",
					     url, ctx->read, incoming,
					     ctx->post_body->size);
					if (remaining == 0) {
						*upload_data_size = 0;
						AHC_RETURN(send_text(
							conn,
							MHD_HTTP_BAD_REQUEST,
							"Body longer than Content-Length"));
					}
					incoming = remaining;
				}
				memcpy(ctx->post_body->data + ctx->read,
				       upload_data, incoming);
				*upload_data_size = 0;
				ctx->read += incoming;
				AHC_RETURN(MHD_YES);
			}
			// and when it is nothing to read
			else {
				if (!ctx->post_body ||
				    ctx->read != ctx->expected) {
					LOGD("%s bad blob!\n", url);
					if (ctx->have_id) {
						blk_t *bad_blob =
							storage_blob_get(
								ctx->id);
						if (bad_blob) {
							storage_blob_free(
								bad_blob);
							ctx->post_body = NULL;
						}
					}
					AHC_RETURN(send_text(
						conn, MHD_HTTP_BAD_REQUEST,
						"Bad blob"));
				}
				statistics.total_served += 1;
				AHC_RETURN(send_response(
					conn, MHD_HTTP_OK, NULL, 0, NULL,
					MHD_RESPMEM_PERSISTENT, HP_API_BLOB));
			}
		}
	}
	LOGD("path not found %s\n", url);
	AHC_RETURN(send_text(conn, MHD_HTTP_NOT_FOUND, "Not Found"));
#undef AHC_RETURN
}

static void req_done(void *cls, struct MHD_Connection *c, void **con_cls,
		     enum MHD_RequestTerminationCode toe)
{
	LOGD("_______-----------=====---------______\n");
#ifdef TRACY_ENABLE
	TracyCZoneN(req_done_zone, "req_done", 1);
#endif
	(void)cls;
	(void)c;
	(void)toe;
	if (*con_cls) {
		struct req_ctx_t *ctx = (struct req_ctx_t *)(*con_cls);
		ctx->post_body = NULL;
		if (ctx->blob_send) {
			storage_blob_free(ctx->blob_send);
			ctx->blob_send = NULL;
		}
		secure_zero(ctx->id.bytes, sizeof(ctx->id.bytes));
#if STATISTICS
		if (statistics.req_ctx_alive_current > 0) {
			statistics.req_ctx_alive_current -= 1;
		}
#endif
		flafree(req_flalloc, ctx);
		*con_cls = NULL;
	}
#ifdef TRACY_ENABLE
	TracyCZoneEnd(req_done_zone);
#endif
}

static volatile sig_atomic_t stop_main_loop = 0;
// Set by signal handlers to break the request loop.
static void on_sigint(int sig)
{
	LOG("received signal %s", strsignal(sig));
	stop_main_loop = 1;
}

int main(int argc, char **argv)
{
	const char *cert_path = "cert.pem";
	const char *key_path = "key.pem";
	uint port = DEFAULT_PORT;
	bool use_tls = true;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--port") && i + 1 < argc)
			port = (unsigned short)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--cert") && i + 1 < argc)
			cert_path = argv[++i];
		else if (!strcmp(argv[i], "--key") && i + 1 < argc)
			key_path = argv[++i];
		else if (!strcmp(argv[i], "--http")) {
			use_tls = false;
		} else if (!strcmp(argv[i], "--version")) {
			printf("epha-ots %s\n", EPHA_VERSION);
			return EXIT_SUCCESS;
		} else if (!strcmp(argv[i], "--help")) {
			fprintf(stderr,
				"Usage: %s [--port N] [--cert cert.pem] [--key key.pem]"
				" [--http] [--version]\n",
				argv[0]);
			return EXIT_SUCCESS;
		}
	}

	log_init();
	LOG("Epha init. Version %s", EPHA_VERSION);

	storage_init(STORAGE_BLOBS_MAX);

	struct MHD_Daemon *d = NULL;
	void *req_ctx_memory = NULL;
	flalloc_size_t req_ctx_memory_size = 0;
	int exit_code = EXIT_FAILURE;
	int efd = -1;
	int reaper_tfd = -1;

	// TLS
	if (use_tls) {
		if (!MHD_is_feature_supported(MHD_FEATURE_TLS)) {
			LOGE("libmicrohttpd built without TLS; use --http or install "
			     "TLS-enabled build.");
			goto cleanup;
		}
		if (!tls_data_load(cert_path, key_path)) {
			LOGE("Failed to read TLS cert/key (cert=%s, key=%s)",
			     cert_path, key_path);
			goto cleanup;
		}
	}

	if (!assets_load()) {
		LOGE("Failed to load assets.");
		goto cleanup;
	}

	html_uptime_ptr = (char *)find_16(assets[0].data, assets[0].size,
					  REPLACE_UPTIME_CH);
	if (!html_uptime_ptr) {
		LOGE("Cannot find the point of uptime setting in HTML.");
	}
	html_served_ptr = (char *)find_16(assets[0].data, assets[0].size,
					  REPLACE_SERVED_CH);
	if (!html_served_ptr) {
		LOGE("Cannot find the point of served setting in HTML.");
	}
	html_version_ptr = (char *)find_16(assets[0].data, assets[0].size,
					   REPLACE_VERSION_CH);
	if (!html_version_ptr) {
		LOGE("Cannot find the point of version setting in HTML.");
	}

	req_ctx_memory_size = flafootprint(REQUESTS_MAX);
	req_ctx_memory = malloc(req_ctx_memory_size);
	if (!req_ctx_memory) {
		LOGE("Failed to allocate %.2f KiB of memory for requests.",
		     (float)req_ctx_memory_size / 1024.f);
		goto cleanup;
	}
	req_flalloc = flainit(req_ctx_memory, REQUESTS_MAX);

	statistics.start_time = monotonic_now_s();

	unsigned int daemon_flags = MHD_USE_EPOLL_LINUX_ONLY |
				    (use_tls ? MHD_USE_TLS : 0);

	d = use_tls ?
		    MHD_start_daemon(daemon_flags, port, NULL, NULL, &ahc, NULL,
				     MHD_OPTION_HTTPS_MEM_KEY, tls_key,
				     MHD_OPTION_HTTPS_MEM_CERT, tls_cert,
#if !TAILSCALE
				     MHD_OPTION_CONNECTION_TIMEOUT,
				     (unsigned int)10,
#endif
				     MHD_OPTION_NOTIFY_COMPLETED, req_done,
				     NULL, MHD_OPTION_LISTENING_ADDRESS_REUSE,
				     1, MHD_OPTION_CONNECTION_LIMIT,
				     (unsigned int)REQUESTS_MAX,
#if DEBOUNCER
				     MHD_OPTION_PER_IP_CONNECTION_LIMIT,
				     (unsigned int)PER_IP_CONN_LIMIT,
#endif
				     MHD_OPTION_END) :
		    MHD_start_daemon(daemon_flags, port, NULL, NULL, &ahc, NULL,
#if !TAILSCALE
				     MHD_OPTION_CONNECTION_TIMEOUT,
				     (unsigned int)10,
#endif
				     MHD_OPTION_NOTIFY_COMPLETED, req_done,
				     NULL, MHD_OPTION_LISTENING_ADDRESS_REUSE,
				     1, MHD_OPTION_CONNECTION_LIMIT,
				     (unsigned int)REQUESTS_MAX,
#if DEBOUNCER
				     MHD_OPTION_PER_IP_CONNECTION_LIMIT,
				     (unsigned int)PER_IP_CONN_LIMIT,
#endif
				     MHD_OPTION_END);

	if (!d) {
		LOGE("MHD_start_daemon");
		LOGE("Failed to start daemon on port %u. Hints:\n"
		     "  - Port busy? try --port 9000\n"
		     "  - TLS disabled in libmicrohttpd? use --http\n"
		     "  - Invalid cert/key? regenerate dev certs",
		     port);
		goto cleanup;
	}

	LOG("%s epha-ots server on :%u (max=%d, %.1f KiB/blob)",
	    use_tls ? "HTTPS" : "HTTP", port, STORAGE_BLOBS_MAX,
	    ((float)BLOB_SIZE_MAX / 1024.0f));
	LOG("Endpoints: POST /blob/<id>, GET /blob/<id>, GET /status");

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);

	const union MHD_DaemonInfo *di =
		MHD_get_daemon_info(d, MHD_DAEMON_INFO_EPOLL_FD);
	if (!di) {
		LOGE("MHD_get_daemon_info");
		goto cleanup;
	}
	int mhd_epfd = di->epoll_fd;
	if (mhd_epfd < 0) {
		LOGE("Invalid epoll fd from MHD daemon");
		goto cleanup;
	}

	efd = epoll_create1(EPOLL_CLOEXEC);
	reaper_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	if (efd < 0 || reaper_tfd < 0) {
		LOGE("epoll_create1: %s, %i %i", strerror(errno), efd,
		     reaper_tfd);
		goto cleanup;
	}
	struct itimerspec reaper_timer_spec = {
		.it_interval = { .tv_sec = REAPER_INTERVAL_S, .tv_nsec = 0 }
	};
	reaper_timer_spec.it_value = reaper_timer_spec.it_interval;
	if (timerfd_settime(reaper_tfd, 0, &reaper_timer_spec, NULL) < 0) {
		LOGE("timerfd_settime: %s", strerror(errno));
		goto cleanup;
	}

	struct epoll_event mhd_ev = {
		.events = EPOLLIN,
		.data.fd = mhd_epfd,
	};
	struct epoll_event reaper_ev = { .events = EPOLLIN,
					 .data.fd = reaper_tfd };
	if (epoll_ctl(efd, EPOLL_CTL_ADD, mhd_epfd, &mhd_ev) < 0 ||
	    epoll_ctl(efd, EPOLL_CTL_ADD, reaper_tfd, &reaper_ev) < 0) {
		LOGE("epoll_ctl: %s", strerror(errno));
		goto cleanup;
	}

	struct epoll_event events[EPOLL_EVENTS_MAX];
	uint64_t epoll_timeout = REAPER_INTERVAL_S * 1000;
	while (!stop_main_loop) {
		int events_num = epoll_wait(efd, events, EPOLL_EVENTS_MAX,
					    epoll_timeout);
		for (int i = 0; i < events_num; ++i) {
			if (events[i].data.fd == mhd_epfd) {
				if (MHD_run(d) == MHD_NO) {
					LOGE("MHD_run failed");
					goto cleanup;
				}
				MHD_get_timeout64(d, &epoll_timeout);
			} else {
				LOGD("reaper\n");
				uint64_t dummy;
				(void)!read(events[i].data.fd, &dummy,
					    sizeof(dummy));
				storage_reaper();
			}
		}
		if (events_num == 0) {
			if (MHD_run(d) == MHD_NO) {
				LOGE("MHD_run failed");
				goto cleanup;
			}
			MHD_get_timeout64(d, &epoll_timeout);
		}
	}

	exit_code = EXIT_SUCCESS;

cleanup:
	if (d) {
		MHD_stop_daemon(d);
	}
	// we do not need to free memory, just to zero the sensitive one
	tls_data_zero();
	storage_zero();

	if (req_ctx_memory) {
		secure_zero(req_ctx_memory, req_ctx_memory_size);
	}
#if STATISTICS
	LOG("req_ctx_t statistics: total created=%lu, peak alive=%lu, alive now=%lu",
	    statistics.req_ctx_total_created, statistics.req_ctx_alive_max,
	    statistics.req_ctx_alive_current);
	LOG("connection statistics: total=%lu, unknown=%lu",
	    statistics.connections_total, statistics.connections_unknown);
#if DEBOUNCER
	LOG("debouncer statistics: total debounced=%lu, capacity=%u, window_ms=%u",
	    statistics.connections_debounced, DEB_CAP, DEB_WINDOW_MS);
#endif
#endif

	if (exit_code == EXIT_SUCCESS)
		LOG("Epha exit normal.");
	log_close();
	return exit_code;
}
