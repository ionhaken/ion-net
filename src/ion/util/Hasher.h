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

#if ION_EXTERNAL_HASH == 1
ION_PRAGMA_WRN_PUSH
	// ION_PRAGMA_WRN_IGNORE_CONVERSION_LOSS_OF_DATA
	#if ION_BUILD_DEBUG
		#define XXH_DEBUGLEVEL 1
	#endif
	#include <xxhash/xxh3.h>
ION_PRAGMA_WRN_POP
#endif
#include <functional>  // std::hash

namespace ion
{
//
// Hash operations
//
inline uint64_t HashMemory64(const void* p, size_t byteCount, uint32_t seed) { return XXH3_64bits_withSeed(p, byteCount, seed); }
inline uint64_t HashMemory64(const void* p, size_t byteCount) { return XXH3_64bits(p, byteCount); }

inline size_t HashMemory(const void* p, size_t byteCount)
{
	if constexpr (sizeof(size_t) == 8)
	{
		return XXH64(p, byteCount, 0);
	}
	else
	{
		return XXH32(p, byteCount, 0);
	}
}

inline size_t HashDJB2(const char* str)
{
	// http://www.cse.yorku.ca/~oz/hash.html djb2
	// https://softwareengineering.stackexchange.com/questions/49550/which-hashing-algorithm-is-best-for-uniqueness-and-speed/145633#145633
	size_t hash = 5381;
	int c;
	while ((c = *str++) != 0)
	{
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}
	return hash;
}

template <typename K>
inline size_t HashKey(const K* key, size_t byteCount)
{
	return HashMemory(key, byteCount);
}

template <typename TKey>
struct Hasher
{
	inline size_t operator()(const TKey& key) const;
};

template <typename TKey>
inline size_t Hasher<TKey>::operator()(const TKey& key) const
{
	return std::hash<TKey>{}(key);	// HashKey(&key, sizeof(TKey));
}

template <>
inline size_t Hasher<uint16_t>::operator()(const uint16_t& key) const
{
	return std::hash<uint16_t>{}(key);
}

constexpr uint32_t Hash32(uint32_t x)
{
#if 1
	// MurMurHash3Finalizer
	x ^= x >> 16;
	x *= 0x85ebca6b;
	x ^= x >> 13;
	x *= 0xc2b2ae35;
	x ^= x >> 16;
	return x;
#else  // #TODO: Test with this
	// https://nullprogram.com/blog/2018/07/31/
	x ^= x >> 16;
	x *= 0x7feb352dU;
	x ^= x >> 15;
	x *= 0x846ca68bU;
	x ^= x >> 16;
	return x;
#endif
}
constexpr uint64_t Hash64(uint64_t x)
{
#if 1
	// MurMurHash3Finalizer
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccd;
	x ^= x >> 33;
	x *= 0xc4ceb9fe1a85ec53;
	x ^= x >> 33;
	return x;
#else  // #TODO: Test with this
	// SplitMix
	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9U;
	x ^= x >> 27;
	x *= 0x94d049bb133111ebU;
	x ^= x >> 31;
	return x;
#endif
}

template <>
inline size_t Hasher<uint32_t>::operator()(const uint32_t& key) const
{
	uint32_t x = Hash32(key);
	if constexpr (sizeof(size_t) == 8)
	{
		return (uint64_t(x) << 32) | uint64_t(Hash32(key ^ x));
	}
	else
	{
		return x;
	}
}

template <>
inline size_t Hasher<uint64_t>::operator()(const uint64_t& key) const
{
	if constexpr (sizeof(size_t) == 8)
	{
		return Hash64(key);
	}
	else
	{
		return static_cast<size_t>((Hash64(key) * 0x8000000080000001) >> 32);
	}
}
}  // namespace ion
