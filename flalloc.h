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
 * zeroed-on-alloc freelist pool allocator for request context
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * ====================================================================== 
 */

typedef uint32_t flalloc_size_t;
typedef union flalloc_block_t flalloc_block_t;
typedef struct flalloc_t flalloc_t;

static inline flalloc_size_t flafootprint(flalloc_size_t count);
static inline flalloc_t *flainit(void *memory, flalloc_size_t count);
static inline req_ctx_t *flaalloc(flalloc_t *alloc);
static inline void flafree(flalloc_t *alloc, void *ptr);

/*
 * ====================================================================== 
 */

union flalloc_block_t {
	flalloc_block_t *next;
	req_ctx_t req_ctx;
};

struct flalloc_t {
	flalloc_block_t *free_list;
	flalloc_size_t capacity;
	flalloc_size_t available;
};

static inline flalloc_size_t flafootprint(flalloc_size_t count)
{
	return count * sizeof(flalloc_block_t) + sizeof(flalloc_t);
}

static inline flalloc_t *flainit(void *memory, flalloc_size_t count)
{
	flalloc_size_t footprint = flafootprint(count);
	flalloc_t *alloc =
		(flalloc_t *)(memory + footprint - sizeof(flalloc_t));

	alloc->capacity = count;
	alloc->available = count;
	alloc->free_list = NULL;

	flalloc_block_t *pool = memory;
	alloc->free_list = pool;
	for (flalloc_size_t i = 0; i < count - 1; ++i) {
		pool[i].next = &pool[i + 1];
	}
	pool[count - 1].next = NULL;

	return alloc;
}

static inline req_ctx_t *flaalloc(flalloc_t *alloc)
{
	flalloc_block_t *block = alloc->free_list;
	if (!block) {
		return NULL;
	}

	alloc->free_list = block->next;
	alloc->available -= 1;
	memset(block, 0, sizeof(*block));
	return &(block->req_ctx);
}

static inline void flafree(flalloc_t *alloc, void *ptr)
{
	flalloc_block_t *block = (flalloc_block_t *)ptr;
	block->next = alloc->free_list;
	alloc->free_list = block;
	alloc->available += 1;
}
