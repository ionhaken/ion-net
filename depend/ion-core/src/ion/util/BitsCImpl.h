/*
 * Copyright 2023 Markus Haikonen, Ionhaken
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <ion/Base.h>

#include <assert.h>

#ifdef _MSC_VER
	#include <intrin.h>
#endif

#if defined(__has_builtin)
	#define ION_HAS_BUILTIN(x) __has_builtin(x)
#else
	#define ION_HAS_BUILTIN(x) 0
#endif

static inline int ion_CountLeadingZeroes32(unsigned long x)
{
#if defined(_MSC_VER)
	unsigned long r;
	return _BitScanReverse(&r, x) ? (31 - r) : 32;
#elif ION_HAS_BUILTIN(__builtin_clzl)
	return x != 0 /* Undefined behavior in GCC*/ ? __builtin_clz(x) : 32;
#else
	/* http://graphics.stanford.edu/~seander/bithacks.html */
	static const char lookup[32] = {31, 22, 30, 21, 18, 10, 29, 2,	20, 17, 15, 13, 9, 6,  28, 1,
									23, 19, 11, 3,	16, 14, 7,	24, 12, 4,	8,	25, 5, 26, 27, 0};

	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	return lookup[((x * 0x07c4acddU) & 0xffffffffU) >> 27];
#endif	// _MSC_VER
}

static inline int ion_CountLeadingZeroes64(unsigned long long v)
{
#if defined(_MSC_VER)
	unsigned long r;
	#if defined(_WIN64)
	return _BitScanReverse64(&r, v) ? (63 - r) : 64;
	#else
	// Scan the high 32 bits.
	if (_BitScanReverse(&r, (unsigned long)(v >> 32)))
	{
		return 63 - (r + 32);
	}

	// Scan the low 32 bits.
	return _BitScanReverse(&r, (unsigned long)(v & 0xFFFFFFFF)) ? 63 - r : 64;
	#endif	// _WIN64
#elif ION_HAS_BUILTIN(__builtin_clzl)
	// __builtin_clzll wrapper
	return v != 0 ? __builtin_clzl(v) : 64;
#else
	static_assert(false, "Not implemented");
	return 64;
#endif	// _MSC_VER
}

// Index of first set bit or -1 if no bit is set. Note: This does not equal to __builtin_ffs()
static inline int ion_FindFirstSetBit32(unsigned long r)
{
#ifdef _MSC_VER
	unsigned long offset;
	return _BitScanForward(&offset, r) ? (int)offset : -1;
#elif ION_HAS_BUILTIN(__builtin_ffs)
	// __builtin_ffs returns one plus the index of the least significant 1-bit of x, or if x is zero, returns zero.
	return __builtin_ffs(r) - 1;
#else
	static_assert(false, "Not implemented");
#endif
}

static inline int ion_FindFirstSetBit64(unsigned long long r)
{
#if defined(_MSC_VER) && defined(_WIN64)
	unsigned long offset;
	return _BitScanForward64(&offset, r) ? (int)offset : -1;
#elif ION_HAS_BUILTIN(__builtin_ffsll)
	return __builtin_ffsll(r) - 1;
#else
	int index = ion_FindFirstSetBit32((unsigned long)(r & 0xFFFFFFFF));
	if (index == -1)
	{
		index = ion_FindFirstSetBit32((unsigned long)((r >> 32) & 0xFFFFFFFF));
		if (index == -1)
		{
			return -1;
		}
		index += 32;
	}
	return index;
#endif
}
