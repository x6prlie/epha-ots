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

// max 4GiB
typedef uint32_t blk_size_t;
typedef struct blk_t {
	void *data;
	blk_size_t size;
} blk_t;

typedef union __attribute__((aligned(16))) {
	uint8_t bytes[16];
	struct {
		uint64_t h, l;
	};
	// struct {
	// 	uint32_t a, b, c, d;
	// };
} htable_key_t;

typedef uint32_t htable_index_t;
