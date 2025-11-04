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

#include "log.h"

#include <stdlib.h>

#if FILELOG
static const char *const log_file_path = "epha.log";
static FILE *log_file;
#endif

void log_init(void)
{
#if SYSLOG
	const int options = LOG_CONS | LOG_NDELAY | LOG_PID;
	const int facility = LOG_USER;
	openlog(NULL, options, facility);
#endif
#if FILELOG
	log_file = fopen(log_file_path, "a");
	if (!log_file) {
		fprintf(stderr,
			"Cannot open file %s in order to init logger!\n",
			log_file_path);
		exit(EXIT_FAILURE);
	}
#endif
}

void log_close(void)
{
#if SYSLOG
	closelog();
#endif
#if FILELOG
	if (log_file) {
		fflush(log_file);
		fclose(log_file);
		log_file = NULL;
	}
#endif
}

void log_(bool ERROR, const char *restrict func, const char *restrict fmt, ...)
{
#if FILELOG
	FILE *out_ = log_file;
#else
	FILE *out_ = ERROR ? stderr : stdout;
#endif
	if (!out_)
		unreachable();

	va_list ap;
	va_start(ap, fmt);
#if SYSLOG
	va_list ap_syslog;
	va_copy(ap_syslog, ap);
#endif

#ifdef _PTHREAD_H
	// LOCK
	flockfile(out_);
#endif

#if !FILELOG
	if (ERROR) {
		fprintf(out_, ANSI_RED);
	} else {
		fprintf(out_, ANSI_GREEN);
	}
#endif

	fprintf(out_, "[%c][%s] %s: ", ERROR ? 'E' : 'I', now_local_iso8601(),
		func);
	vfprintf(out_, fmt, ap);
	va_end(ap);

#if !FILELOG
	fprintf(out_, ANSI_RESET);
#endif

	fprintf(out_, "\n");

#ifdef _PTHREAD_H
	// UNLOCK
	funlockfile(out_);
#endif

#if SYSLOG
	vsyslog(ERROR ? LOG_ERR : LOG_INFO, fmt, ap_syslog);
	va_end(ap_syslog);
#endif
}
