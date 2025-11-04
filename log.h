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

#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#define ANSI_RESET "\x1b[0m"
#define ANSI_RED "\x1b[31m"
#define ANSI_GREEN "\x1b[32m"
#define ANSI_CYAN "\x1b[36m"

#if SYSLOG
#include <syslog.h>
#endif

static __always_inline const char *now_local_iso8601()
{
	static thread_local char buf[32];
	time_t t = time(NULL);
	struct tm tm;
	if (!localtime_r(&t, &tm))
		return NULL;
	if (strftime(buf, 32, "%Y-%m-%d %H:%M:%S %z", &tm) == 0)
		return "time buffer too small";
	return buf;
}

static inline void logd_(const char *restrict func, const char *restrict fmt,
			 ...)
{
#if DEBUG
	va_list ap;
	va_start(ap, fmt);

#ifdef _PTHREAD_H
	// LOCK
	flockfile(stdout);
#endif
	fprintf(stdout, ANSI_CYAN);
	fprintf(stdout, "[D][%s] %s: ", now_local_iso8601(), func);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fprintf(stdout, ANSI_RESET);
	fflush(stdout);
#ifdef _PTHREAD_H
	// UNLOCK
	funlockfile(stdout);
#endif
#else
	(void)func;
	(void)fmt;
#endif
}

#if defined(__GNUC__) || defined(__clang__)
#define LOG_PRINTF_ATTR(fmt_idx, arg_idx) \
	__attribute__((format(printf, fmt_idx, arg_idx)))
#else
#define LOG_PRINTF_ATTR(fmt_idx, arg_idx)
#endif

void log_init(void);
void log_close(void);
void log_(bool ERROR, const char *restrict func, const char *restrict fmt, ...)
	LOG_PRINTF_ATTR(3, 4);

#undef LOG_PRINTF_ATTR

#define LOG(fmt, ...) log_(false, __func__, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) log_(true, __func__, fmt, ##__VA_ARGS__)
// it is really terrible to not to have a good debugger
#define LOGD(fmt, ...) logd_(__func__, fmt, ##__VA_ARGS__)
