
#pragma once

#include <microhttpd.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define DEB_WINDOW_MS (150U) // one request per IP every 150 ms
#define DEB_CAP (1024U) // power-of-two table size (tracks ~1K IPs)

typedef struct {
	uint64_t key;
	uint32_t until_ms;
} deb_entry_t;

static deb_entry_t deb_tbl[DEB_CAP];
static uint32_t deb_mask = DEB_CAP - 1;
static uint32_t deb_sweep = 0;

static inline uint32_t deb_now_ms()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)(ts.tv_sec * 1000u +
			  (uint32_t)(ts.tv_nsec / 1000000u));
}

static inline uint64_t deb_mix(uint64_t x)
{
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdULL;
	x ^= x >> 33;
	x *= 0xc4ceb9fe1a85ec53ULL;
	x ^= x >> 33;
	return x;
}

static inline uint64_t deb_ip_key(const struct sockaddr *sa)
{
	if (!sa)
		return 0;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *v4 = (const struct sockaddr_in *)sa;
		return deb_mix((uint64_t)ntohl(v4->sin_addr.s_addr));
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)sa;
		uint64_t a = 0, b = 0;
		memcpy(&a, &v6->sin6_addr.s6_addr[0], 8);
		memcpy(&b, &v6->sin6_addr.s6_addr[8], 8);
		return deb_mix(a ^ (b << 1));
	}
	return 0;
}

static inline bool debouncer_allow_key(uint64_t key, uint32_t now)
{
	if (key == 0)
		return true; // unknown -> allow

	uint32_t i = (uint32_t)(key ^ (key >> 32)) & deb_mask;

	for (size_t p = 0; p <= deb_mask; ++p) {
		deb_entry_t *e = &deb_tbl[(i + p) & deb_mask];
		if (e->key == key) {
			if ((int32_t)(e->until_ms - now) > 0)
				return false;
			e->until_ms = now + DEB_WINDOW_MS;
			return true;
		}
		if (e->key == 0) {
			e->key = key;
			e->until_ms = now + DEB_WINDOW_MS;
			return true;
		}
	}
	// Table full: cheap eviction (clock sweep)
	deb_tbl[deb_sweep++ & deb_mask] =
		(deb_entry_t){ key, now + DEB_WINDOW_MS };
	return true;
}

static inline bool debouncer_allow_addr_now(const struct sockaddr *sa,
					    uint32_t now)
{
	return debouncer_allow_key(deb_ip_key(sa), now);
}

static inline bool debouncer_allow_addr(const struct sockaddr *sa)
{
	return debouncer_allow_addr_now(sa, deb_now_ms());
}

// returns true to ALLOW, false to REJECT (429)
static inline bool debouncer_allow(struct MHD_Connection *conn)
{
	const union MHD_ConnectionInfo *ci = MHD_get_connection_info(
		conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
	return debouncer_allow_addr(ci ? ci->client_addr : NULL);
}
