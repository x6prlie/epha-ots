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

#pragma once

#include <time.h>
#include <stdio.h>
#include <microhttpd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

static __always_inline const char *now_local_iso8601();

static inline enum MHD_Result log_header_cb(void *cls, enum MHD_ValueKind kind,
					    const char *k, const char *v)
{
	(void)cls;
	(void)kind;
	LOG("H  %s: %s\n", k ? k : "", v ? v : "");
	return MHD_YES;
}
static inline enum MHD_Result log_cookie_cb(void *cls, enum MHD_ValueKind kind,
					    const char *k, const char *v)
{
	(void)cls;
	(void)kind;
	LOG("CK %s=%s\n", k ? k : "", v ? v : "");
	return MHD_YES;
}
static inline enum MHD_Result log_query_cb(void *cls, enum MHD_ValueKind kind,
					   const char *k, const char *v)
{
	(void)cls;
	(void)kind;
	LOG("Q  %s=%s\n", k ? k : "", v ? v : "");
	return MHD_YES;
}
static inline void log_client_addr(const struct sockaddr *sa)
{
	if (!sa) {
		LOG("Client: (unknown)\n");
		return;
	}
	char host[NI_MAXHOST] = "";
	uint16_t port = 0;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
		inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
		port = ntohs(in->sin_port);
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *)sa;
		inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
		port = ntohs(in6->sin6_port);
	}
	LOG("Client: %s:%u\n", host[0] ? host : "(unprintable)",
	    (unsigned)port);
}
