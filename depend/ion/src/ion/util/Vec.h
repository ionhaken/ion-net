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
#include <ion/util/Math.h>
#include <ion/util/Bool.h>
#include <ion/tracing/Log.h>

namespace ion
{
template <typename T, size_t N>
struct Vec
{
	static_assert(N >= 1, "Invalid Vec size");
	
	static constexpr size_t ElementCount = N;
	
	using type = T;

	constexpr Vec() = default;
	Vec(const Vec& copy) = default;
	Vec(Vec&& other) = default;
	Vec& operator=(const Vec& other)
	{
		mData = other.mData;
		return *this;
	}

	constexpr Vec& operator=(Vec&& other)
	{
		mData = std::move(other.mData);
		return *this;
	}

	constexpr Vec(T x, T y, T z, T w) : mData{x, y, z, w} {}

	constexpr Vec(T x, T y, T z) : mData{x, y, z} {}

	constexpr Vec(T x, T y) : mData{x, y} {}

	Vec(const T& splat)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] = splat;
		}
	}

	template <typename Type>
	ION_FORCE_INLINE const Vec operator<<(const Type& v) const
	{
		Vec result(*this);
		result.ShiftLeft(v);
		return result;
	}

	template <typename Type>
	ION_FORCE_INLINE Vec& operator<<=(const Type& v)
	{
		ShiftLeft(v);
		return *this;
	}

	template <typename Type>
	ION_FORCE_INLINE const Vec operator>>(const Type& v) const
	{
		Vec result(*this);
		result.ShiftRight(v);
		return result;
	}

	template <typename Type>
	ION_FORCE_INLINE Vec& operator>>=(const Type& v)
	{
		ShiftRight(v);
		return *this;
	}

	ION_FORCE_INLINE const Vec operator^(const Vec& v) const
	{
		Vec result(*this);
		result.Xor(v);
		return result;
	}

	ION_FORCE_INLINE Vec& operator^=(const Vec& v)
	{
		Xor(v);
		return *this;
	}

	ION_FORCE_INLINE const Vec operator&(const Vec& v) const
	{
		Vec result(*this);
		result.And(v);
		return result;
	}

	ION_FORCE_INLINE Vec& operator&=(const Vec& v)
	{
		And(v);
		return *this;
	}

	ION_FORCE_INLINE const Vec operator|(const Vec& v) const
	{
		Vec result(*this);
		result.Or(v);
		return result;
	}

	ION_FORCE_INLINE Vec& operator|=(const Vec& v)
	{
		Or(v);
		return *this;
	}

	[[nodiscard]] constexpr T operator[](size_t i) const
	{
		ION_ASSERT_FMT_IMMEDIATE(i < N, "Invalid index");
		return mData[i];
	}

	[[nodiscard]] constexpr T& operator[](size_t i)
	{
		ION_ASSERT_FMT_IMMEDIATE(i < N, "Invalid index");
		return mData[i];
	}

	ION_FORCE_INLINE void Set(size_t index, const T& v) { mData[index] = v; }

	inline const Vec operator-(const Vec& v) const
	{
		Vec result(*this);
		result.Subtract(v);
		return result;
	}

	inline Vec& operator-=(const Vec& v)
	{
		Subtract(v);
		return *this;
	}

	ION_FORCE_INLINE bool operator==(const Vec& other) const { return !(*this != other); }

	inline bool operator!=(const Vec& other) const
	{
		for (size_t i = 0; i < N; ++i)
		{
			if (mData[i] != other[i])
			{
				return true;
			}
		}
		return false;
	}

	constexpr inline const Vec operator-() const
	{
		Vec result(*this);
		result.Invert();
		return result;
	}

	inline const Vec operator*(T s) const
	{
		Vec result;
		for (size_t i = 0; i < N; i++)
		{
			result[i] = mData[i] * s;
		}
		return result;
	}

	inline const Vec operator/(T s) const
	{
		Vec result;
		for (size_t i = 0; i < N; i++)
		{
			result[i] = mData[i] / s;
		}
		return result;
	}

	inline const Vec operator+(T s) const
	{
		Vec result;
		for (size_t i = 0; i < N; i++)
		{
			result[i] = mData[i] + s;
		}
		return result;
	}
	inline const Vec operator-(T s) const
	{
		Vec result;
		for (size_t i = 0; i < N; i++)
		{
			result[i] = mData[i] - s;
		}
		return result;
	}

	inline Vec operator+(const Vec& v) const
	{
		Vec result(*this);
		result.Add(v);
		return result;
	}

	inline Vec operator/(const Vec& v) const
	{
		Vec result(*this);
		result.Divide(v);
		return result;
	}

	inline const Vec operator*(const Vec& v) const
	{
		Vec result(*this);
		result.Multiply(v);
		return result;
	}

	inline Vec& operator+=(const Vec& v)
	{
		Add(v);
		return *this;
	}

	inline Vec& operator*=(T s)
	{
		Scale(s);
		return *this;
	}

	inline Vec& operator*=(const Vec& v)
	{
		Multiply(v);
		return *this;
	}

	inline Vec& operator/=(const Vec& v)
	{
		Divide(v);
		return *this;
	}

	inline Vec& operator%=(T v) const
	{
		Mod(v);
		return *this;
	}

	inline Vec operator%(T v) const
	{
		Vec result(*this);
		result.Mod(v);
		return result;
	}

	constexpr const T* Data() const { return mData.Data(); }

	constexpr T* Data() { return mData.Data(); }

	// Manhanttan distance
	[[nodiscard]] T MDistance(T x1, T y1) const { return ion::ManhattanDistance<T>(*this, Vec(x1, y1)); }

	[[nodiscard]] constexpr T Distance(T x1, T y1) const
	{
		auto xa = x() - x1;
		auto ya = y() - y1;
		return T(ion::sqrt(xa * xa + ya * ya));
	}

	[[nodiscard]] constexpr T Distance(const Vec& p) const { return Distance(p.x(), p.y()); }

	[[nodiscard]] constexpr T Length() const { return ion::Length(*this); }

	[[nodiscard]] constexpr T LengthSqr() const { return ion::LengthSqr(*this); }

	[[nodiscard]] constexpr T Cross(Vec& other) { return Vec::Cross(*this, other); }

	[[nodiscard]] constexpr T Dot(Vec& other) { return Vec::Dot(*this, other); }

	[[nodiscard]] constexpr Vec NormalizedNonZero() const
	{
		auto len = Length();
		ION_ASSERT_FMT_IMMEDIATE(len > 0, "Zero vector");
#if ION_CONFIG_FAST_MATH
		auto inv = ion::Reciprocal(len);
		return Vec(x() * inv, y() * inv);
#else
		return Vec(x() / len, y() / len);
#endif
	}

	[[nodiscard]] inline Vec Normalized() const { return ion::Normalize(*this); }

	[[nodiscard]] static constexpr T Cross(const Vec& v1, const Vec& v2) { return v1.x * v2.y - v1.y * v2.x; }

	[[nodiscard]] static constexpr T Dot(const Vec& v1, const Vec& v2) { return v1.x() * v2.x() + v1.y() * v2.y(); }

	[[nodiscard]] static inline Vec FromAngle(const float radians) { return Vec(ion::cos(radians), ion::sin(radians)); }

	[[nodiscard]] constexpr const T& x() const { return mData[0]; }
	[[nodiscard]] constexpr const T& y() const { return mData[1]; }
	[[nodiscard]] constexpr const T& z() const { return mData[2]; }
	[[nodiscard]] constexpr T& x() { return mData[0]; }
	[[nodiscard]] constexpr T& y() { return mData[1]; }
	[[nodiscard]] constexpr T& z() { return mData[2]; }

	static size_t Size() { return N; }

	constexpr Bool<N> operator>=(const Vec& other) const
	{
		Bool<N> res;
		for (size_t i = 0; i < N; ++i)
		{
			res[i] = mData[i] >= other[i];
		}
		return res;
	}
	constexpr Bool<N> operator<=(const Vec& other) const
	{
		Bool<N> res;
		for (size_t i = 0; i < N; ++i)
		{
			res[i] = mData[i] <= other[i];
		}
		return res;
	}
	constexpr Bool<N> operator>(const Vec& other) const
	{
		Bool<N> res;
		for (size_t i = 0; i < N; ++i)
		{
			res[i] = mData[i] > other[i];
		}
		return res;
	}
	constexpr Bool<N> operator<(const Vec& other) const
	{
		Bool<N> res;
		for (size_t i = 0; i < N; ++i)
		{
			res[i] = mData[i] < other[i];
		}
		return res;
	}

private:
	ion::Array<T, N> mData;

	template <typename Type>
	inline void ShiftLeft(Type shift)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] <<= shift;
		}
	}

	template <typename Type>
	inline void ShiftRight(Type shift)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] >>= shift;
		}
	}

	inline void Xor(const Vec& other)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] ^= other[i];
		}
	}

	inline void And(const Vec& other)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] &= other[i];
		}
	}

	inline void Or(const Vec& other)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] |= other[i];
		}
	}

	inline void Mod(T scalar)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] %= scalar;
		}
	}

	inline void Scale(T scalar)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] *= scalar;
		}
	}

	inline void Invert()
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] = -mData[i];
		}
	}

	inline void Add(const Vec& v)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] += v[i];
		}
	}

	inline void Divide(const Vec& v)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] /= v[i];
		}
	}

	inline void Multiply(const Vec& v)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] *= v[i];
		}
	}

	inline void Subtract(const Vec& v)
	{
		for (size_t i = 0; i < N; ++i)
		{
			mData[i] -= v[i];
		}
	}
};

template <typename T, size_t N>
[[nodiscard]] inline Vec<T, N> Abs(const Vec<T, N>& a)
{
	Vec<T, N> out;
	for (size_t i = 0; i < N; ++i)
	{
		out[i] = ion::Abs(a[i]);
	}
	return out;
}

template <typename T>
using Vec2 = Vec<T, 2>;

using Vec2f = Vec<float, 2>;

using Vec3f = Vec<float, 3>;

using Vec2d = Vec<double, 2>;

inline ion::Vec2f MinMax(const ion::Vec2f& low, const ion::Vec2f& value, const ion::Vec2f& high)
{
	return ion::Vec2f(ion::MinMax(low.x(), value.x(), high.x()), ion::MinMax(low.y(), value.y(), high.y()));
}

[[nodiscard]] inline ion::Vec2f Min(const ion::Vec2f& left, const ion::Vec2f& right)
{
	return ion::Vec2f(ion::Min(left.x(), right.x()), ion::Min(left.y(), right.y()));
}

[[nodiscard]] inline ion::Vec2f Max(const ion::Vec2f& left, const ion::Vec2f& right)
{
	return ion::Vec2f(ion::Max(left.x(), right.x()), ion::Max(left.y(), right.y()));
}

namespace serialization
{
namespace detail
{
inline ion::UInt ConvertVec2ToStringBuffer(char* buffer, size_t bufferLen, double x, double y);
inline void ConvertVec2FromStringBuffer(double& x, double& y, const char* src);
}  // namespace detail

template <>
inline ion::UInt Serialize(const ion::Vec<float, 2>& value, StringWriter& writer)
{
	auto u = detail::ConvertVec2ToStringBuffer(writer.Data(), writer.Available(), value.x(), value.y());
	writer.Skip(u);
	return u;
}

template <>
inline ion::UInt Serialize(const ion::Vec<double, 2>& value, StringWriter& writer)
{
	auto u = detail::ConvertVec2ToStringBuffer(writer.Data(), writer.Available(), value.x(), value.y());
	writer.Skip(u);
	return u;
}

template <>
inline void Deserialize(ion::Vec<float, 2>& dst, StringReader& reader)
{
	double x, y;
	detail::ConvertVec2FromStringBuffer(x, y, reader.Data());
	dst = ion::Vec<float, 2>(static_cast<float>(x), static_cast<float>(y));
}
template <>
inline void Deserialize(ion::Vec<double, 2>& dst, StringReader& reader)
{
	detail::ConvertVec2FromStringBuffer(dst.x(), dst.y(), reader.Data());
}
}  // namespace serialization

namespace tracing
{
template <>
inline void Handler(LogEvent& e, const ion::Vec<float, 2>& value)
{
	char buffer[32];
	StringWriter writer(buffer, 32);
	serialization::Serialize(value, writer);
	e.Write(buffer);
}
template <>
inline void Handler(LogEvent& e, const ion::Vec<double, 2>& value)
{
	char buffer[32];
	StringWriter writer(buffer, 32);
	serialization::Serialize(value, writer);
	e.Write(buffer);
}
}  // namespace tracing
}  // namespace ion

#include <ion/string/String.h>
#include <ion/container/Vector.h>

namespace ion::serialization::detail
{
inline ion::UInt ConvertVec2ToStringBuffer(char* buffer, size_t bufferLen, double x, double y)
{
	return ion::UInt(snprintf(buffer, bufferLen, "%.4g %.4g", x, y));
}

inline void ConvertVec2FromStringBuffer(double& x, double& y, const char* src)
{
	ion::String str(src);
	ion::SmallVector<ion::String, 2> list;
	str.Tokenize(list);
	if (list.Size() == 2)
	{
		StringReader reader0(list[0].CStr(), list[0].Length());
		StringReader reader1(list[1].CStr(), list[1].Length());
		Deserialize(x, reader0);
		Deserialize(y, reader1);
	}
	else
	{
		x = 0;
		y = 0;
	}
}
}  // namespace ion::serialization::detail
