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
#include <ion/debug/Error.h>
#include <ion/util/Fraction.h>

#include <cmath>

namespace ion
{
template <typename Value>
[[nodiscard]] constexpr bool IsPowerOfTwo(const Value n)
{
	ION_ASSERT_FMT_IMMEDIATE(n != 0, "Cannot check power of two if n is 0");
	return (n & (n - 1)) == 0;
}

template <typename T>
struct BaseType
{
	using type = T;
};

template <typename Value, typename Divider>
[[nodiscard]] constexpr Value Mod(const Value value, const Divider divider)
{
	return value % divider;
}

template <>
[[nodiscard]] inline float Mod(const float value, const float divider)
{
	return std::fmod(value, divider);  // divider - int(divider / value) * value;
}

// Increase value wrapped without modulo
constexpr int32_t IncrWrapped(int32_t value, int32_t range)
{
	ION_ASSERT_FMT_IMMEDIATE(value < range, "Invalid initial value %i/%i", value, range);
	ION_ASSERT_FMT_IMMEDIATE(range > 0, "Invalid range");
	int32_t temp = value + 1;
	return (temp < range) ? temp : 0;
}

// Decrease value wrapped without modulo
constexpr int32_t DecrWrapped(int32_t value, int32_t range)
{
	ION_ASSERT_FMT_IMMEDIATE(value < range, "Invalid initial value %i/%i", value, range);
	ION_ASSERT_FMT_IMMEDIATE(range > 0, "Invalid range");
	int32_t temp = (value > 0) ? value : range;
	return temp - 1;
}

template <typename Value>
[[nodiscard]] constexpr Value Reciprocal(const Value value)
{
	static_assert(std::is_floating_point<Value>::value, "Specialize for non floating point types");
	return Value(1) / value;
}

// Modulo when divider is power of two
template <typename Value, typename Divider>
[[nodiscard]] constexpr Value Mod2(const Value value, const Divider divider)
{
	ION_ASSERT_FMT_IMMEDIATE(divider != 0 && (divider & (divider - 1)) == 0, "Divider must be power of two");
	return value & (divider - 1);
}

// Calculate offset for aligning given position.
template <typename Position, typename Alignment>
[[nodiscard]] constexpr Position ByteAlignOffset(const Position pos, const Alignment alignment)
{
	ION_PRAGMA_WRN_PUSH;
	ION_PRAGMA_WRN_IGNORE_UNARY_MINUS_TO_UNSIGNED_TYPE;
	return Mod2<Position, Alignment>(-pos, alignment);
	ION_PRAGMA_WRN_POP;
}

// Align given position
template <typename Position, typename Alignment>
[[nodiscard]] inline Position ByteAlignPosition(const Position pos, const Alignment alignment)
{
	ION_ASSERT_FMT_IMMEDIATE(alignment != 0 && (alignment & (alignment - 1)) == 0, "Alignment must be power of two");
	ION_PRAGMA_WRN_PUSH;
	ION_PRAGMA_WRN_IGNORE_UNARY_MINUS_TO_UNSIGNED_TYPE;
	return (pos + (alignment - 1)) & -alignment;  // Some operations less than using ByteAlignOffset()
	ION_PRAGMA_WRN_POP;
}

template <typename T>
[[nodiscard]] inline T* AlignAddress(T* pointer, size_t alignment = alignof(T))
{
	return reinterpret_cast<T*>(ByteAlignPosition(reinterpret_cast<uintptr_t>(pointer), alignment));
}

namespace Math
{
// http://www.math.illinois.edu/~ajh/453/pi-cf.pdf
template <typename T = Fraction<int32_t>>
constexpr inline T Pi()
{
	return static_cast<T>(ion::Fraction32(1736484781, 552740273));
}
constexpr inline Fraction<int32_t> Pi32() { return ion::Fraction32(1736484781, 552740273); }
constexpr inline double Pi() { return 3.14159265358979323846264338327950; }
// static constexpr inline Fraction<int64_t> Pi64() { return ion::Fraction64(1736484781, 552740273); }

template <typename T>
constexpr inline T WrappedDelta(T from, T to, T range)
{
	auto delta = from - to;
	if (delta > T(0))
	{
		if (delta <= range)
		{
			return delta;
		}
		else
		{
			return -(range * T(2) - delta);
		}
	}
	else
	{
		if (delta >= -range)
		{
			return delta;
		}
		else
		{
			return (range * T(2) + delta);
		}
	}
}

template <class T>
inline T Pow2(T p)
{
	return p * p;
}
}  // namespace Math

[[nodiscard]] inline float cos(float v) { return std::cos(v); }

[[nodiscard]] inline float sin(float v) { return std::sin(v); }

[[nodiscard]] inline double cos(double v) { return std::cos(v); }

[[nodiscard]] inline double sin(double v) { return std::sin(v); }

template <typename T>
[[nodiscard]] inline T atan2(T y, T x)
{
	return std::atan2(y, x);
}

// inline double atan2(double y, double x) { return std::atan2(y, x); }

[[nodiscard]] inline float fmod(float x, float y) { return std::fmod(x, y); }

[[nodiscard]] inline double fmod(double x, double y) { return std::fmod(x, y); }

[[nodiscard]] inline float Abs(float value) noexcept { return std::abs(value); }

[[nodiscard]] inline double Abs(double value) noexcept { return std::abs(value); }

[[nodiscard]] inline float sqrt(float x) noexcept { return std::sqrt(x); }

[[nodiscard]] inline double sqrt(double x) noexcept { return std::sqrt(x); }

[[nodiscard]] inline float exp(float x) noexcept { return std::exp(x); }

[[nodiscard]] inline double exp(double x) noexcept { return std::exp(x); }

template <typename T>
[[nodiscard]] inline T round(T x) noexcept
{
	return std::round(x);
}

namespace math
{
template <typename T>
[[nodiscard]] inline bool IsNear(const T& a, const T& b)
{
	return (a >= b - std::numeric_limits<T>::epsilon() && a <= b + std::numeric_limits<T>::epsilon());
}

// Scales floating point value to integer value safely i.e. does not multiply original value to avoid overflow.
template <typename Float, typename Integer>
[[nodiscard]] constexpr Integer ScaleFloatToInteger(Float value, Integer scale)
{
	Integer whole(static_cast<Integer>(value));
	Integer fraction = static_cast<Integer>((value - whole) * scale);
	return whole * scale + fraction;
}
}  // namespace math

template <typename Vec, typename LengthType = typename Vec::type>
[[nodiscard]] constexpr LengthType LengthSqr(const Vec& vec)
{
	return vec.x() * vec.x() + vec.y() * vec.y();
}

template <typename Vec, typename LengthType = typename Vec::type>
[[nodiscard]] inline LengthType Length(const Vec& vec)
{
	return ion::sqrt(ion::LengthSqr(vec));
}

// Manhanttan distanc
template <typename Vec, typename DistanceType = typename Vec::type>
[[nodiscard]] constexpr DistanceType ManhattanDistance(const Vec& a, const Vec& b)
{
	return ion::Abs(a.x() - b.x()) + ion::Abs(a.y() - b.y());
}

template <typename Vec>
[[nodiscard]] inline Vec Normalize(const Vec& vec)
{
	typename Vec::type len = ion::Length(vec);
	if (len > 0)
	{
		return Vec(vec.x() / len, vec.y() / len);
	}
	else
	{
		return Vec(0, 0);
	}
}

//
// Minimum - Maxmimum operations
//
template <typename T>
[[nodiscard]] constexpr const T& Min(const T& left, const T& right)
{
#ifdef min
	return min(left, right);
#else
	return left < right ? left : right;
#endif
}

template <typename T>
[[nodiscard]] constexpr const T& Max(const T& left, const T& right)
{
#ifdef max
	return max(left, right);
#else
	return left < right ? right : left;
#endif
}

template <typename T>
[[nodiscard]] constexpr const T& MinMax(const T& low, const T& value, const T& high)
{
	ION_ASSERT_FMT_IMMEDIATE(low <= high, "Invalid limits");
	return value < low ? low : (value > high ? high : value);
}

template <typename T>
[[nodiscard]] constexpr const T& Clamp(const T& value, const T& low, const T& high)
{
	ION_ASSERT_FMT_IMMEDIATE(low <= high, "Invalid limits");
	return value < low ? low : (value > high ? high : value);
}

}  // namespace ion
