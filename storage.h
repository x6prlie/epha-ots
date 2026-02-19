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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "log.h"
#include "types.h"

/*
 * ====================================================================== 
 */

// helpers
typedef uint32_t monotonic_time_t;
static inline monotonic_time_t monotonic_now_s();
void secure_zero(void *p, size_t n);

void storage_init(htable_index_t htable_size);
void storage_zero();
blk_t storage_blob_create(htable_key_t id, blk_size_t size);
bool storage_blob_publish(htable_key_t id, monotonic_time_t valid_until);
void storage_blob_abort(htable_key_t id);
bool storage_blob_is_already_taken(htable_key_t id);
// the caller becomes the owner
// and must call storage_blob_free after reading
blk_t storage_blob_get(htable_key_t id);
void storage_blob_free(blk_t blob);

typedef struct storage_status_t storage_status_t;
storage_status_t storage_status();

void storage_reaper();

/*
 * ====================================================================== 
 */

static inline monotonic_time_t monotonic_now_s()
{
	struct timespec ts;
	// man clock_gettime: This clock does not count time that the system is suspended.
	// On Linux, that point corresponds to the number of seconds
	// that the system has been running since it was booted.
	// therefore we can chop it to u32
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (monotonic_time_t)ts.tv_sec;
}

typedef struct storage_status_t {
	// must be carefull
	size_t in_use[11];
	size_t max[11];
} storage_status_t;
