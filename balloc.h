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

/*
 * bucket allocator for storing encrypted secrets
*/

#pragma once

#include <stdint.h>
#include <string.h>

#include "log.h"
#include "types.h"

/*
 * ====================================================================== 
 */

// 128 B
#define BLOB_ALLOC_LOG_OF_SIZE_MIN (7)
// #define BLOB_ALLOC_SIZE_MIN (1 << BLOB_ALLOC_LOG_OF_SIZE_MIN)
// 128 KiB per blob max
#define BLOB_LOG_OF_SIZE_MAX (BLOB_ALLOC_LOG_OF_SIZE_MIN + 10)
#define BLOB_SIZE_MAX (1 << BLOB_LOG_OF_SIZE_MAX)
/*
 * 11 buckets from 128B*131072 to 128KiB*128;
 */
#define BUCKETS_COUNT (BLOB_LOG_OF_SIZE_MAX - BLOB_ALLOC_LOG_OF_SIZE_MIN + 1)

// bucket index type
typedef uint64_t bindex_t;
// buckets to store objects of same size
typedef struct bucket_t bucket_t;
// struct to enclose buckets
typedef struct balloc_t balloc_t;

// calculate the memory needed
static blk_size_t bfootprint();
// provide ZEROED memory
static balloc_t *binit(void *memory, blk_size_t memory_size);

// size must never be 0 or 1
static inline bindex_t bindex(blk_size_t size);

static inline blk_t *balloc(balloc_t *ba, blk_size_t size);
static inline void bfree(balloc_t *ba, blk_t *blk);

// the size of a bucket
static inline size_t bbucket_capacity(bindex_t index);
// the size of an item in a bucket
static inline blk_size_t bbucket_item_size_max(bindex_t index);
static inline size_t bbucket_items_free(balloc_t *ba, bindex_t index);

/*
 * ====================================================================== 
 */

#if STATISTICS
static struct {
	uint64_t try_allocs[BUCKETS_COUNT];
	uint64_t allocs_used_size[BUCKETS_COUNT];
	uint32_t used_at_once_max[BUCKETS_COUNT];
	uint32_t no_space_errors_count[BUCKETS_COUNT];
} balloc_statistics;
#endif

typedef struct __attribute__((aligned(16))) bucket_t {
	blk_t *next_free;
	blk_t *blk;
	uint32_t free;
} bucket_t;

typedef struct __attribute__((aligned(16))) balloc_t {
	bucket_t *buckets;
} balloc_t;

static inline size_t bbucket_capacity(bindex_t index)
{
	return 1 << (BLOB_LOG_OF_SIZE_MAX - index);
}

static inline size_t bbucket_items_free(balloc_t *ba, bindex_t index)
{
	return ba->buckets[index].free;
}

static inline blk_size_t bbucket_item_size_max(bindex_t index)
{
	return 1 << (BLOB_ALLOC_LOG_OF_SIZE_MIN + index);
}

static inline blk_size_t bfootprint()
{
	static_assert(sizeof(bucket_t) % 16 == 0,
		      "bucket_t must be aligned 16");
	static_assert(sizeof(blk_t) % 16 == 0, "blk_t must be aligned 16");
	blk_size_t footprint =
		(sizeof(bucket_t) + sizeof(blk_t)) * BUCKETS_COUNT;
	for (size_t i = 0; i < BUCKETS_COUNT; ++i) {
		const unsigned count = bbucket_capacity(i);
		const unsigned payload_size = bbucket_item_size_max(i);
		const unsigned block_size = sizeof(blk_t) + payload_size;
		footprint += count * block_size;
	}
	return footprint;
}

static inline balloc_t *binit(void *memory, blk_size_t memory_size)
{
	blk_size_t buckets_data_size = sizeof(bucket_t) * BUCKETS_COUNT;
	// buckets go last
	void *ptr = memory + memory_size - sizeof(balloc_t) - buckets_data_size;
	bucket_t *buckets = (bucket_t *)ptr;
	ptr += buckets_data_size;
	balloc_t *ba = (balloc_t *)ptr;
	ba->buckets = buckets;

	// actual data go first
	ptr = memory;
	for (size_t i = 0; i < BUCKETS_COUNT; ++i) {
		ptr += sizeof(bucket_t);
		buckets[i].blk = (blk_t *)(ptr);
		ptr += sizeof(blk_t);
		buckets[i].blk->data = (blk_t *)(ptr);
		void *arena = buckets[i].blk->data;

		const unsigned count = bbucket_capacity(i);
		buckets[i].free = count;
		const unsigned payload_size = bbucket_item_size_max(i);
		const unsigned block_size = sizeof(blk_t) + payload_size;
		buckets[i].blk->size = count * block_size;

		void *arena_last = (arena + (count - 1) * block_size);
		blk_t *chunk = NULL;
		blk_t *previous = NULL;
		for (; arena <= arena_last; arena += block_size) {
			chunk = (blk_t *)(arena);
			chunk->data = (blk_t *)(arena + sizeof(blk_t));
			chunk->size = payload_size;
			// reuse data pointer to link freelist nodes while free
			chunk->data = (uint8_t *)previous;
			previous = chunk;
		}
		buckets[i].next_free = chunk;
		ptr += block_size * count;
	}
	return ba;
}

static inline bindex_t bindex(blk_size_t size)
{
	bindex_t index = ilog2_u64(size - 1) - BLOB_ALLOC_LOG_OF_SIZE_MIN + 1;
	// index < 0 ⇒ 1
	bindex_t is_negative = index >> 63;
	// is_negative ⇒ 0xFFFFFFFF
	int64_t mask = (int64_t)(is_negative - 1);
	return index & mask;
}

static inline blk_t *balloc(balloc_t *ba, blk_size_t size)
{
	const bindex_t i = bindex(size);
	LOGD("of size %llu from bucket[%llu], free %u\n",
	     (unsigned long long)size, (unsigned long long)i,
	     ba->buckets[i].free);
	if (ba->buckets[i].free) {
		blk_t *ret = ba->buckets[i].next_free;
		ba->buckets[i].next_free = (blk_t *)ret->data;
		ret->data = (uint8_t *)ret + sizeof(blk_t);
		ret->size = size;
		ba->buckets[i].free--;
#if STATISTICS
		balloc_statistics.try_allocs[i]++;
		const uint32_t items_used =
			bbucket_capacity(i) - bbucket_items_free(ba, i);
		if (items_used > balloc_statistics.used_at_once_max[i]) {
			balloc_statistics.used_at_once_max[i] = items_used;
		}
		balloc_statistics.allocs_used_size[i] += size;
#endif
		return ret;
	} else {
#if STATISTICS
		balloc_statistics.try_allocs[i]++;
		balloc_statistics.no_space_errors_count[i]++;
#endif
		return NULL;
	}
}

static inline void bfree(balloc_t *ba, blk_t *blk)
{
	const bindex_t i = bindex(blk->size);
	LOGD("of size %llu to bucket[%llu]\n", (unsigned long long)blk->size,
	     (unsigned long long)i);
	// stash next pointer in data field before returning to pool
	blk->data = (uint8_t *)(ba->buckets[i].next_free);
	ba->buckets[i].next_free = blk;
	ba->buckets[i].free++;
}
