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

// open adressing scheme with linear probing
#pragma once

#include <stdint.h>

/*
 * ====================================================================== 
 */

// implemented in storage.c
static __always_inline void htable_swap(htable_index_t a, htable_index_t b);
static __always_inline uint64_t htable_hash(htable_key_t data);

// implemented in storage.c
static __always_inline bool key_cmp(htable_key_t a, htable_key_t b);
static __always_inline bool key_is_null(htable_key_t a);
static __always_inline void key_set_null(htable_key_t *a);

// table_size must be a power of 2
static __always_inline htable_index_t lp_home_index(uint64_t hash,
						    htable_index_t table_size);
// keys must not be full
static __always_inline htable_index_t
lp_find_free_slot(const htable_key_t *keys, const htable_key_t key,
		  htable_index_t table_size);
static __always_inline htable_index_t lp_lookup(const htable_key_t *keys,
						const htable_key_t key,
						htable_index_t table_size);
// must be called only on existed keys
// returns the index of erased key
static __always_inline htable_index_t lp_erase(htable_key_t *keys,
					       const htable_index_t i,
					       htable_index_t table_size);

/*
 * ====================================================================== 
 */

#include "log.h"
#include "types.h"

#if STATISTICS
static struct {
	uint64_t insertion_count;
	uint64_t hash_collision_count;
	uint64_t total_went_due_to_collisions;
} lp_statistics;
#endif

static __always_inline htable_index_t lp_home_index(uint64_t h,
						    htable_index_t table_size)
{
	return h & (table_size - 1);
}

static __always_inline htable_index_t
lp_find_free_slot(const htable_key_t *keys, const htable_key_t key,
		  htable_index_t table_size)
{
#if STATISTICS
	lp_statistics.insertion_count++;
#endif
	const uint64_t h = htable_hash(key);
	htable_index_t i = lp_home_index(h, table_size);
	if (key_is_null(keys[i])) {
		return i;
	} else {
#if STATISTICS
		lp_statistics.hash_collision_count++;
#endif
repeat:
		for (; i < table_size; ++i) {
#if STATISTICS
			lp_statistics.total_went_due_to_collisions++;
#endif
			if (key_is_null(keys[i])) {
				return i;
			}
		}
		i = 0;
		goto repeat;
	}
}

static __always_inline htable_index_t lp_lookup(const htable_key_t *keys,
						const htable_key_t key,
						htable_index_t table_size)
{
	const uint64_t h = htable_hash(key);
	const htable_index_t i = lp_home_index(h, table_size);
	if (key_cmp(keys[i], key)) {
		return i;
	}
	htable_index_t j = i + 1;
	for (; j < table_size; ++j) {
		if (key_is_null(keys[j])) {
			return table_size;
		}
		if (key_cmp(keys[j], key)) {
			return j;
		}
	}
	j = 0;
	for (; j < i; ++j) {
		if (key_is_null(keys[j])) {
			return table_size;
		}
		if (key_cmp(keys[j], key)) {
			return j;
		}
	}
	return table_size;
}

static __always_inline htable_index_t lp_erase(htable_key_t *keys,
					       const htable_index_t start_idx,
					       htable_index_t table_size)
{
	htable_index_t hole = start_idx;
	htable_index_t next = hole;

	while (true) {
		next = next + 1;
		if (next == table_size) {
			next = 0;
		}

		if (key_is_null(keys[next]) || next == start_idx) {
			break;
		}

		htable_index_t home =
			lp_home_index(htable_hash(keys[next]), table_size);

		if (((next > hole) && ((home <= hole) || (home > next))) ||
		    ((next < hole) && ((home <= hole) && (home > next)))) {
			htable_swap(hole, next);

			hole = next;
		}
	}

	key_set_null(&keys[hole]);
	return hole;
}
