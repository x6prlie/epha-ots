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

#include "storage.h"

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

/*
 * ====================================================================== 
 */

#define VALID_UNTIL_EMPTY UINT32_MAX

static void htable_swap(htable_index_t a, htable_index_t b);
static uint64_t htable_hash(htable_key_t data);

// key-specific
static bool key_cmp(htable_key_t a, htable_key_t b);
static bool key_is_null(htable_key_t a);
static void key_set_null(htable_key_t *a);

bool htable_get_blob_index(htable_key_t id, size_t *index);
bool htable_find_free_slot(htable_key_t id, size_t size, htable_index_t *index);
// i MUST be in the table
htable_index_t htable_erase_slot(const htable_index_t i);

/*
 * ====================================================================== 
 */

#include "log.h"
#include "balloc.h"
#include "linear_probing.h"

#ifdef TRACY_ENABLE
#include "tracy/TracyC.h"
#define STORAGE_ZONE(var, label) TracyCZoneN(var, label, 1)
#define STORAGE_ZONE_END(var) TracyCZoneEnd(var)
#define STORAGE_RETURN(var, value)     \
	do {                           \
		STORAGE_ZONE_END(var); \
		return (value);        \
	} while (0)
#else
#define STORAGE_ZONE(var, label)
#define STORAGE_ZONE_END(var)
#define STORAGE_RETURN(var, value) return (value)
#endif

static htable_key_t *blob_ids;
static monotonic_time_t *blob_valid_until;
static htable_index_t htable_free, htable_size;

static htable_key_t *blob_ids_invalid;
static htable_index_t blob_ids_invalid_count;

static blk_t mallocated_data;
static blk_t **blob_data;
static balloc_t *balloc_data;

#if STATISTICS
static uint64_t storage_rip_total;
#endif

#if SIMD_X86
#include <immintrin.h>
#endif

#if SIMD_ARM
#include <arm_neon.h>
#endif

static bool key_cmp(htable_key_t a, htable_key_t b)
{
	return a.h == b.h && a.l == b.l;
}

static bool key_is_null(htable_key_t a)
{
	return (a.h | a.l) == 0;
}

static void key_set_null(htable_key_t *a)
{
	a->h = 0;
	a->l = 0;
}

static void htable_swap(htable_index_t a, htable_index_t b)
{
	if (a == b) {
		return;
	}
	{
		htable_key_t tmp = blob_ids[a];
		blob_ids[a] = blob_ids[b];
		blob_ids[b] = tmp;
	}
	{
		blk_t *tmp = blob_data[a];
		blob_data[a] = blob_data[b];
		blob_data[b] = tmp;
	}
	{
		double tmp = blob_valid_until[a];
		blob_valid_until[a] = blob_valid_until[b];
		blob_valid_until[b] = tmp;
	}
}

static uint64_t htable_hash_rotl64(uint64_t x, unsigned r)
{
	return (x << r) | (x >> (64 - r));
}

static uint64_t htable_hash(htable_key_t data)
{
	const uint64_t k0 = 0x9e3779b97f4a7c15ULL;
	const uint64_t k1 = 0xbf58476d1ce4e5b9ULL;

	uint64_t a = data.h ^ k0;
	uint64_t b = data.l ^ k1;

	uint64_t mixed = (a + htable_hash_rotl64(b, 23)) ^
			 (b + htable_hash_rotl64(a, 41));

	uint64_t z = mixed;
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	z = z ^ (z >> 31);

	return z;
}

bool htable_get_blob_index(htable_key_t id, size_t *index)
{
	*index = lp_lookup(blob_ids, id, htable_size);
	return *index != htable_size;
}

bool htable_find_free_slot(htable_key_t id, size_t size, htable_index_t *index)
{
	(void)size;
	if (!htable_free) {
		LOGE("No empty slots!");
		return false;
	}

	*index = lp_find_free_slot(blob_ids, id, htable_size);
	return true;
}

htable_index_t htable_erase_slot(const htable_index_t i)
{
	return lp_erase(blob_ids, i, htable_size);
}

void storage_init(htable_index_t _htable_size)
{
	STORAGE_ZONE(init_zone, "storage_init");
	// as we have _htable_size a pow of 2, it is always multiple of 16
	const size_t ids_byte_size = sizeof(htable_key_t) * _htable_size;
	const size_t ids_invalid_byte_size =
		sizeof(htable_key_t) * _htable_size;
	const size_t blob_valid_until_byte_size =
		sizeof(monotonic_time_t) * _htable_size;
	const size_t blob_data_byte_size = sizeof(blk_t) * _htable_size;
	const size_t buckets_data_byte_size = bfootprint();
	const size_t size_total = ids_byte_size + ids_invalid_byte_size +
				  blob_valid_until_byte_size +
				  blob_data_byte_size + buckets_data_byte_size;

	const size_t alignment = sizeof(htable_key_t);
	if (0 != posix_memalign(&mallocated_data.data, alignment, size_total)) {
		LOGE("Cannot allocate aligned memory (%.2fMiB)",
		     size_total / 1024.0 / 1024.0);
		exit(EXIT_FAILURE);
	}
	mallocated_data.size = size_total;
	memset(mallocated_data.data, 0, size_total);

	// forbid moving out data to swap
	// ulimit -l is 8KiB on my system for an unpriviledged user and 64 (sic!) on my phone
#if LOCK_MEMORY_TO_RAM
	if (0 != mlock(mallocated_data.data, mallocated_data.size)) {
		LOGE("Cannot lock memory to RAM! (%.2fMiB)",
		     size_total / 1024.0 / 1024.0);
		exit(EXIT_FAILURE);
	}
#endif

	htable_free = htable_size = _htable_size;

	blob_ids_invalid = mallocated_data.data;
	blob_ids = (void *)blob_ids_invalid + ids_invalid_byte_size;
	blob_valid_until = (void *)blob_ids + ids_byte_size;
	blob_data = (void *)blob_valid_until + blob_valid_until_byte_size;
	for (size_t i = 0; i < htable_size; ++i) {
		blob_valid_until[i] = VALID_UNTIL_EMPTY;
	}

	balloc_data = binit((void *)blob_data + blob_data_byte_size,
			    buckets_data_byte_size);

	LOGD("allocated total of %.2f MiB\n", size_total / (1024.0 * 1024.0));
	STORAGE_ZONE_END(init_zone);
}

void storage_zero()
{
	STORAGE_ZONE(free_zone, "storage_zero");
	htable_index_t htable_used = htable_size - htable_free;
	if (htable_used > 0) {
		LOGE("dropping %lu secrets", htable_used);
	}
	secure_zero(mallocated_data.data, mallocated_data.size);
#if STATISTICS
	LOG("lp statistics:\n"
	    "inserts: %zu\n"
	    "collisions: %zu\n"
	    "total went due to collisions: %zu",
	    lp_statistics.insertion_count, lp_statistics.hash_collision_count,
	    lp_statistics.total_went_due_to_collisions);
	LOG("balloc_statistics:");
	uint64_t total_transfered_size_real = 0;
	uint64_t total_transfered_size = 0;
	uint64_t total_allocs = 0;
	uint64_t total_allocs_failed = 0;
	for (size_t i = 0; i < BUCKETS_COUNT; ++i) {
		const uint64_t try_allocs = balloc_statistics.try_allocs[i];
		const uint64_t allocs_failed =
			balloc_statistics.no_space_errors_count[i];
		const uint32_t used = balloc_statistics.used_at_once_max[i];
		const uint32_t capacity = bbucket_capacity(i);
		const uint64_t used_size =
			balloc_statistics.allocs_used_size[i];
		const uint32_t item_size_max = bbucket_item_size_max(i);
		const uint64_t used_size_real =
			item_size_max * (try_allocs - allocs_failed);

		LOG(" <===> bucket %zu, up to %.1f KiB", i,
		    (double)item_size_max / 1024.0);
		LOG("allocations count %zu", try_allocs);
		LOG("unsuccessful %zu (%.1f%%)", allocs_failed,
		    (double)allocs_failed / (double)try_allocs * 100.0);
		LOG("max used at once: %u of %u items (%.1f%%)", used, capacity,
		    (float)used / (float)capacity * 100.f);
		LOG("data transfered: useful %.2f MiB, real used %.2f MiB (%.1f%%)",
		    (double)used_size / 1024.0 / 1024.0,
		    (double)used_size_real / 1024.0 / 1024.0,
		    (double)used_size / used_size_real * 100.0);
		LOG("average data size %.2f KiB",
		    (double)used_size / (try_allocs - allocs_failed));

		total_allocs += try_allocs;
		total_allocs_failed += allocs_failed;
		total_transfered_size_real += used_size_real;
		total_transfered_size += used_size;
	}
	LOG("total allocations count %zu (%zu + %zu, fail ratio %.f%%)",
	    total_allocs, (total_allocs - total_allocs_failed),
	    total_allocs_failed,
	    (double)total_allocs_failed / total_allocs * 100.0);
	LOG("total data transfered: useful %.2f MiB, real used %.2f MiB (%.1f%%)",
	    (double)total_transfered_size / 1024.0 / 1024.0,
	    (double)total_transfered_size_real / 1024.0 / 1024.0,
	    (double)total_transfered_size / (double)total_transfered_size_real *
		    100.0);

	LOG("total rip: %zu", storage_rip_total);

#endif
	STORAGE_ZONE_END(free_zone);
}

blk_t *storage_blob_create(htable_key_t id, blk_size_t size,
			   monotonic_time_t valid_until)
{
	STORAGE_ZONE(create_zone, "storage_blob_create");
	if (key_is_null(id)) {
		LOGE("cannot create for null key");
		STORAGE_RETURN(create_zone, NULL);
	}
	htable_index_t index;
	if (!htable_find_free_slot(id, size, &index)) {
		LOGE("no free indices in hash table");
		STORAGE_RETURN(create_zone, NULL);
	}
	blk_t *blk = balloc(balloc_data, size);
	if (!blk) {
		LOGE("cannot allocate %lu bytes", size);
		STORAGE_RETURN(create_zone, NULL);
	}

	blob_ids[index] = id;
	blob_data[index] = blk;
	blob_valid_until[index] = valid_until;

	htable_free -= 1;
	LOGD("finished successfully\n");
	STORAGE_RETURN(create_zone, blk);
}

bool storage_blob_is_already_taken(htable_key_t id)
{
	STORAGE_ZONE(is_taken_zone, "storage_blob_is_already_taken");
	bool taken = htable_size != lp_lookup(blob_ids, id, htable_size);
	STORAGE_ZONE_END(is_taken_zone);
	return taken;
}

blk_t *storage_blob_get(htable_key_t id)
{
	STORAGE_ZONE(get_zone, "storage_blob_get");
	size_t index;
	if (htable_get_blob_index(id, &index)) {
		blk_t *ret = blob_data[index];
		LOGD("index %llu, of %llu\n", (unsigned long long)index,
		     (unsigned long long)ret->size);
		index = htable_erase_slot(index);
		secure_zero(blob_ids[index].bytes, 16);
		blob_valid_until[index] = VALID_UNTIL_EMPTY;
		htable_free += 1;
		STORAGE_RETURN(get_zone, ret);
	} else {
		STORAGE_RETURN(get_zone, NULL);
	}
}

void storage_blob_free(blk_t *block)
{
	STORAGE_ZONE(free_blob_zone, "storage_blob_free");
	LOGD("_\n");
	secure_zero(block->data, block->size);
	bfree(balloc_data, block);
	STORAGE_ZONE_END(free_blob_zone);
}

storage_status_t storage_status()
{
	storage_status_t status;
	for (size_t i = 0; i < BUCKETS_COUNT; ++i) {
		status.max[i] = bbucket_capacity(i);
		status.in_use[i] =
			status.max[i] - bbucket_items_free(balloc_data, i);
	}
	return status;
}

void storage_reaper()
{
	STORAGE_ZONE(reaper_gather_zone, "storage_reaper_gather");
	monotonic_time_t time_now = monotonic_now_s();
	// on my laptop this part is faster with AVX2,
	// but rip zone become much slower if the hash table is small. frequency drop?
#if SIMD_X86
	const htable_index_t size = htable_size;
	htable_index_t i = 0;
	htable_index_t count = blob_ids_invalid_count;
	const __m256i bias = _mm256_set1_epi32(INT32_MIN);
	const __m256i time_vec =
		_mm256_xor_si256(_mm256_set1_epi32((int32_t)time_now), bias);
	for (; i + 8 <= size; i += 8) {
		const __m256i until_vec = _mm256_loadu_si256(
			(const __m256i *)(const void *)(blob_valid_until + i));
		const __m256i cmp = _mm256_cmpgt_epi32(
			time_vec, _mm256_xor_si256(until_vec, bias));
		unsigned int mask = (unsigned int)_mm256_movemask_ps(
			_mm256_castsi256_ps(cmp));
		while (mask) {
			const unsigned int idx = __builtin_ctz(mask);
			mask &= mask - 1;
			blob_ids_invalid[count++] = blob_ids[i + idx];
		}
	}
	for (; i < size; ++i) {
		if (blob_valid_until[i] < time_now) {
			blob_ids_invalid[count++] = blob_ids[i];
		}
	}
	blob_ids_invalid_count = count;
#else
	for (htable_index_t i = 0; i < htable_size; ++i) {
		if (blob_valid_until[i] < time_now) {
			blob_ids_invalid[blob_ids_invalid_count] = blob_ids[i];
			++blob_ids_invalid_count;
		}
	}
#endif
	STORAGE_ZONE_END(reaper_gather_zone);

#if STATISTICS
	storage_rip_total += blob_ids_invalid_count;
#endif
	if (blob_ids_invalid_count) {
		LOGD("to rip %llu\n",
		     (unsigned long long)blob_ids_invalid_count);
	}

	STORAGE_ZONE(reaper_rip_zone, "storage_rip");
	for (htable_index_t i = 0; i < blob_ids_invalid_count; ++i) {
		blk_t *block = storage_blob_get(blob_ids_invalid[i]);
		if (!block) {
			unreachable();
		}
		storage_blob_free(block);
	}
	secure_zero(blob_ids_invalid,
		    sizeof(*blob_ids_invalid) * blob_ids_invalid_count);
	blob_ids_invalid_count = 0;
	STORAGE_ZONE_END(reaper_rip_zone);
}

void secure_zero(void *p, size_t n)
{
#if defined(__GLIBC__) || defined(__APPLE__) || defined(__FreeBSD__) || \
	defined(__OpenBSD__) || defined(__NetBSD__) ||                  \
	defined(__DragonFly__) || defined(__sun)
	explicit_bzero(p, n);
#else
	// but for Android we have this
	volatile uint8_t *volatilep = p;
	for (size_t i = 0; i < n; ++i) {
		volatilep[i] = 0;
	}
#endif
}
