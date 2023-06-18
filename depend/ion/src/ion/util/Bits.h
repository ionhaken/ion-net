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
#include <ion/util/BitsCImpl.h>
#if __cplusplus >= 202002L && ION_PLATFORM_MICROSOFT
	#include <bit>
#endif

namespace ion
{
template <typename T>
[[nodiscard]] inline int CountTrailingZeroes(T v)
{
#if ION_COMPILER_MSVC
	unsigned long idx;
	return _BitScanForward(&idx, ion::SafeRangeCast<uint32_t>(v)) ? int(idx) : sizeof(T) * 8;
#elif ION_HAS_BUILTIN(__builtin_ctzll)
	return v != 0 ? __builtin_ctz(v) : sizeof(T) * 8;
#else
	static_assert(false, "Not implemented");
#endif
}

template <>
[[nodiscard]] inline int CountTrailingZeroes(uint64_t v)
{
#if ION_COMPILER_MSVC
	unsigned long idx;
	#ifdef _WIN64
	return _BitScanForward64(&idx, v) ? (int)idx : 64;
	#else
	if (_BitScanForward(&idx, (uint32_t)(v & 0xffffffff)))
	{
		return int(idx);
	}
	return (_BitScanForward(&idx, (uint32_t)(v >> 32))) ? (idx + 32) : 64;
	#endif
#elif ION_HAS_BUILTIN(__builtin_ctzll)
	return v != 0 ? __builtin_ctzll(v) : 64;
#else
	static_assert(false, "Not implemented");
#endif
}

// https://lemire.me/blog/2018/02/21/iterating-over-set-bits-quickly/
template <typename T, typename Callback>
void ForEachEnabledBit(T bitset, Callback&& callback)
{
	while (bitset != 0)
	{
#if 1  // Probably faster when supporting bit manipulation instructions set / #TODO: Measure
		ION_PRAGMA_WRN_PUSH;
		ION_PRAGMA_WRN_IGNORE_UNARY_MINUS_TO_UNSIGNED_TYPE;
		T t = bitset & -bitset;
		ION_PRAGMA_WRN_POP;
		int r = CountTrailingZeroes(bitset);
		callback(r);
		bitset ^= t;
#else
		int r = CountTrailingZeroes(bitset);
		callback(r);
		bitset ^= (T(1) << r);
#endif
	}
}

template <typename T>
[[nodiscard]] inline int CountLeadingZeroes(T v)
{
	return ion_CountLeadingZeroes32(ion::SafeRangeCast<unsigned long>(v));
}

template <>
[[nodiscard]] inline int CountLeadingZeroes(uint64_t v)
{
	return ion_CountLeadingZeroes64(ion::SafeRangeCast<unsigned long long>(v));
}

template <class To, class From,
		  std::enable_if_t<std::conjunction_v<std::bool_constant<sizeof(To) == sizeof(From)>, std::is_trivially_copyable<To>,
											  std::is_trivially_copyable<From>>,
						   int> = 0>
[[nodiscard]] constexpr To BitCast(const From& src) noexcept
{
#if __cplusplus >= 202002L && ION_PLATFORM_MICROSOFT
	return std::bit_cast<To>(src);
#else
	static_assert(std::is_trivially_constructible_v<To>,
				  "This implementation additionally requires destination type to be trivially constructible");

	To dst;
	memcpy(&dst, &src, sizeof(To));
	return dst;
#endif
}

namespace byte_order
{
namespace detail
{
template <typename T, typename TUnsigned>
union ByteSequence
{
	constexpr ByteSequence(const T& t) : mValue(t) {}
	T mValue;
	TUnsigned mUnsigned;
	uint8_t mBytes[sizeof(T)];
};

template <typename T>
constexpr T ReverseByteOrder64(const T& data)
{
	ByteSequence<T, uint64_t> seq(data);
	seq.mUnsigned = ((uint64_t)seq.mBytes[7] << 0) | ((uint64_t)seq.mBytes[6] << 8) | ((uint64_t)seq.mBytes[5] << 16) |
					((uint64_t)seq.mBytes[4] << 24 | ((uint64_t)seq.mBytes[3] << 32) | ((uint64_t)seq.mBytes[2] << 40) |
					 ((uint64_t)seq.mBytes[1] << 48) | ((uint64_t)seq.mBytes[0] << 56));
	return seq.mValue;
}

template <typename T>
constexpr T ReverseByteOrder32(const T& data)
{
	ByteSequence<T, uint32_t> seq(data);
	seq.mUnsigned =
	  ((uint32_t)seq.mBytes[3] << 0) | ((uint32_t)seq.mBytes[2] << 8) | ((uint32_t)seq.mBytes[1] << 16) | ((uint32_t)seq.mBytes[0] << 24);
	return seq.mValue;
}
}  // namespace detail

constexpr int64_t HostToBigEndian(const int64_t data) { return detail::ReverseByteOrder64(data); }
constexpr int32_t HostToBigEndian(const int32_t data) { return detail::ReverseByteOrder32(data); }
constexpr int64_t BigEndianToHost(const int64_t data) { return detail::ReverseByteOrder64(data); }
constexpr int32_t BigEndianToHost(const int32_t data) { return detail::ReverseByteOrder32(data); }

constexpr double HostToBigEndian(const double data) { return detail::ReverseByteOrder64(data); }
constexpr float HostToBigEndian(const float data) { return detail::ReverseByteOrder32(data); }
constexpr double BigEndianToHost(const double data) { return detail::ReverseByteOrder64(data); }
constexpr float BigEndianToHost(const float data) { return detail::ReverseByteOrder32(data); }

}  // namespace byte_order

template <typename T>
constexpr T BitCountToByteCount(T v)
{
	return (v + 7) >> 3;
}

template <typename T>
constexpr T ByteCountToBitCount(T v)
{
	return v << 3;
}

}  // namespace ion
