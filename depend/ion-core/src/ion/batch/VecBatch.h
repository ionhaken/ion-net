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

#include <ion/batch/BoolBatch.h>
#include <ion/util/Vec.h>

namespace ion
{
template <typename Type = float>
class RawBatch
{
	static constexpr const size_t N = ION_BATCH_SIZE;
#if ION_SIMD
	using T = xsimd::batch<Type, N>;

	template <size_t A, class Dest, class Source = Dest>
	static inline xsimd::batch_bool<Dest, A> BatchBoolCast(const xsimd::batch_bool<Source, A>& x) noexcept
	{
		return xsimd::batch_bool<Dest, A>(xsimd::batch_cast<Dest>(xsimd::batch<Source, A>(x()) /*.data*/));
	}

	template <size_t A, class Dest, class Source = Dest>
	static inline xsimd::batch<Dest, A> BatchCast(const xsimd::batch<Source, A>& x) noexcept
	{
		return xsimd::batch_cast<Dest>(x);
	}

#else
	using T = ion::Vec<Type, N>;

	template <size_t A, class Dest, class Source = Dest>
	static ION_FORCE_INLINE ion::Vec<Dest, A> BatchBoolCast(const ion::Bool<A>& x) noexcept
	{
		ion::Vec<Dest, A> v;
		for (size_t i = 0; i < A; ++i)
		{
			v[i] = Dest(x[i]);
		}
		return v;
	}

	template <size_t A, class Dest, class Source = Dest>
	static ION_FORCE_INLINE ion::Vec<Dest, A> BatchCast(const ion::Vec<Source, A>& x) noexcept
	{
		ion::Vec<Dest, A> v;
		for (size_t i = 0; i < A; ++i)
		{
			v[i] = static_cast<Dest>(x[i]);
		}
		return v;
	}

#endif

public:
	using type = Type;

#if ION_SIMD
	static constexpr const size_t DefaultAlignment = XSIMD_DEFAULT_ALIGNMENT;
#else
	static constexpr const size_t DefaultAlignment = alignof(T);
#endif
	static constexpr size_t ElementCount = N;

	constexpr RawBatch() {}

	RawBatch(const Type* v, [[maybe_unused]] size_t num)
	{
		ION_ASSERT_FMT_IMMEDIATE(num == ElementCount, "Expected full elements");
#if ION_SIMD
		mValue.load_unaligned(v);
#else
		std::memcpy(&mValue, v, sizeof(mValue));
#endif
	}

	template <size_t... Is>
	constexpr RawBatch(std::initializer_list<Type> il, std::index_sequence<Is...>) : mValue{{(il.begin()[Is])...}}
	{
	}

	constexpr RawBatch(const T& v) : mValue(v) {}

	constexpr RawBatch(const RawBatch& v) : mValue(v.Raw()) {}

	constexpr RawBatch(const RawBoolBatch<Type>& v) : mValue(reinterpret_cast<const T>(v.Raw())) {}

	template <typename Other>
	constexpr RawBatch(const RawBoolBatch<Other>& v) : mValue(T(BatchBoolCast<N, Type>(v.Raw())))
	{
	}

	template <typename Other>
	constexpr RawBatch(const RawBatch<Other>& v) : mValue(BatchCast<N, Type>(v.Raw()))
	{
	}

	constexpr RawBatch operator+(Type v) const { return RawBatch(mValue + v); }
	constexpr RawBatch operator+(const RawBatch& other) const { return RawBatch(mValue + other.mValue); }
	constexpr RawBatch& operator+=(const Type& v)
	{
		mValue += v;
		return *this;
	}

	constexpr RawBatch& operator+=(const RawBatch& v)
	{
		mValue += v.mValue;
		return *this;
	}

	constexpr RawBatch operator-(Type v) const { return RawBatch(mValue - v); }
	constexpr RawBatch operator-(const RawBatch& other) const { return RawBatch(mValue - other.mValue); }
	constexpr RawBatch operator-() const { return RawBatch(-mValue); }

	constexpr RawBatch& operator-=(const Type& v)
	{
		mValue -= v;
		return *this;
	}

	constexpr RawBatch& operator-=(const RawBatch& v)
	{
		mValue -= v.mValue;
		return *this;
	}

	constexpr RawBatch operator*(Type v) const { return RawBatch(mValue * v); }
	constexpr RawBatch operator*(const RawBatch& other) const { return RawBatch(mValue * other.mValue); }

	constexpr RawBatch& operator*=(const Type& v)
	{
		mValue *= v;
		return *this;
	}

	constexpr RawBatch& operator*=(const RawBatch& v)
	{
		mValue *= v.mValue;
		return *this;
	}

	[[nodiscard]] constexpr RawBatch operator/(Type v) const { return RawBatch(mValue / v); }
	[[nodiscard]] constexpr RawBatch operator/(const RawBatch& other) const { return RawBatch(mValue / other.mValue); }
	constexpr RawBatch& operator/=(const Type& v)
	{
		mValue /= v;
		return *this;
	}
	constexpr RawBatch& operator/=(const RawBatch& v)
	{
		mValue /= v.mValue;
		return *this;
	}

	[[nodiscard]] constexpr RawBatch operator|(const RawBatch& other) const { return RawBatch(mValue | other.Raw()); }
	constexpr RawBatch& operator|=(const RawBatch& other) const
	{
		mValue |= other.mValue;
		return *this;
	}
	[[nodiscard]] constexpr RawBatch operator&(const RawBatch& other) const { return RawBatch(mValue & other.Raw()); }
	constexpr RawBatch& operator&=(const RawBatch& other) const
	{
		mValue &= other.mValue;
		return *this;
	}
	[[nodiscard]] constexpr RawBatch operator^(const RawBatch& other) const { return RawBatch(mValue ^ other.Raw()); }
	constexpr RawBatch& operator^=(const RawBatch& other) const
	{
		mValue ^= other.mValue;
		return *this;
	}
	[[nodiscard]] constexpr RawBatch operator%(const RawBatch& other) const

	{
#if ION_SIMD
		return RawBatch(xsimd::fmod(mValue, other.mValue));
#else
		return RawBatch(mValue % other.mValue);
#endif
	}

	constexpr RawBatch& operator%=(const RawBatch& other) const
	{
#if ION_SIMD
		mValue = xsimd::fmod(mValue, other.mValue);
#else
		mValue = mValue % other.mValue;
#endif
		return *this;
	}

	template<typename ShiftType>
	[[nodiscard]] constexpr RawBatch operator<<(ShiftType shift) const
	{
		return RawBatch(mValue << shift);
	}

	template <typename ShiftType>
	constexpr RawBatch& operator<<=(ShiftType shift)
	{
		mValue <<= shift;
		return *this;
	}

	template <typename ShiftType>
	[[nodiscard]] constexpr RawBatch operator>>(ShiftType shift) const
	{
		return RawBatch(mValue >> shift);
	}

	template <typename ShiftType>
	constexpr RawBatch& operator>>=(ShiftType shift)
	{
		mValue = mValue >> shift;
		return *this;
	}

	[[nodiscard]] constexpr Type operator[](size_t index) const { return /*mValue.get(index)*/ mValue[index]; }

	[[nodiscard]] constexpr Type& operator[](size_t index) { return /*mValue.get(index)*/ mValue[index]; }

#if ION_SIMD

	constexpr RawBatch(const Type& a) : mValue(a) {}

	[[nodiscard]] constexpr ion::Vec<Type, ElementCount> Scalar() const
	{
		ION_ALIGN(DefaultAlignment) ion::Vec<Type, ElementCount> values;
		mValue.store_aligned(values.Data());
		return values;
	}

	inline void Set(size_t index, const Type& v)
	{
		mValue[index] = v;
	}

	inline void LoadAligned(const ion::Vec<Type, ElementCount>& v) { mValue.load_aligned(v.Data()); }

	[[nodiscard]] T Sqrt() const { return xsimd::sqrt(mValue); }

#else

	inline void LoadAligned(const ion::Vec<Type, ElementCount>& v) { mValue = v; }

	constexpr RawBatch(const Type& a)
	{
		for (size_t i = 0; i < ElementCount; ++i)
		{
			mValue[i] = a;
		}
	}

	inline const ion::Vec<Type, ElementCount>& Scalar() const { return mValue; }

	inline void Set(size_t index, const Type& v) { mValue[index] = v; }
#endif

	[[nodiscard]] static size_t Size() { return ElementCount; }

	[[nodiscard]] constexpr T& Raw() { return mValue; }

	[[nodiscard]] constexpr const T& Raw() const { return mValue; }

	constexpr RawBoolBatch<Type> operator>=(const RawBatch<Type>& other) const { return mValue >= other.mValue; }
	constexpr RawBoolBatch<Type> operator<=(const RawBatch<Type>& other) const { return mValue <= other.mValue; }
	constexpr RawBoolBatch<Type> operator>(const RawBatch<Type>& other) const { return mValue > other.mValue; }
	constexpr RawBoolBatch<Type> operator<(const RawBatch<Type>& other) const { return mValue < other.mValue; }

private:

	ION_ALIGN(DefaultAlignment) T mValue;
};

namespace detail
{
template <typename T, typename F, std::size_t... Is>
[[nodiscard]] constexpr auto MakeFloatBatch(F&& f, std::index_sequence<Is...>) -> RawBatch<T>
{
	return {{f(std::integral_constant<std::size_t, Is>{})...}};
}
}  // namespace detail

template <typename T, typename F>
[[nodiscard]] constexpr ion::RawBatch<T> MakeFloatBatch(F&& f)
{
	return detail::MakeFloatBatch<T>(f, std::make_index_sequence<RawBatch<T>::ElementCount>{});
}

template <typename T = RawBatch<float>>
class VecBatch
{
public:
	using Type = typename T::type;

	static constexpr size_t ElementCount = T::ElementCount;

	VecBatch() = default;

	inline VecBatch(const Vec2<Type>& v) : mX(v.x()), mY(v.y()) {}

	inline VecBatch(const T& x, const T& y) : mX(x), mY(y) {}

	static size_t Size() { return ElementCount; }

	inline void Set(size_t index, const ion::Vec2<Type>& v)
	{
		mX.Set(index, v.x());
		mY.Set(index, v.y());
	}

	inline VecBatch& operator-=(const VecBatch& v)
	{
		mX -= v.mX;
		mY -= v.mY;
		return *this;
	}

	inline VecBatch& operator-=(const Type& v)
	{
		T splat(v);
		mX -= splat;
		mY -= splat;
		return *this;
	}

	inline VecBatch operator-(const VecBatch& v) const { return VecBatch(mX - v.mX, mY - v.mY); }


	inline VecBatch operator-() const { return VecBatch(-mX, -mY); }

	inline VecBatch& operator+=(const VecBatch& v)
	{
		mX += v.mX;
		mY += v.mY;
		return *this;
	}

	inline VecBatch& operator+=(const Type& v)
	{
		T splat(v);
		mX += splat;
		mY += splat;
		return *this;
	}

	inline VecBatch operator+(const Vec<Type, 2>& v) const { return VecBatch(mX + v.x(), mY + v.y()); }

	inline VecBatch<T> operator+(const VecBatch<T>& v) const { return VecBatch<T>(mX + v.mX, mY + v.mY); }

	inline VecBatch operator+(Type v) const { return VecBatch(mX + v, mY + v); }

	inline VecBatch& operator*=(const VecBatch& v)
	{
		mX *= v.mX;
		mY *= v.mY;
		return *this;
	}

	inline VecBatch& operator*=(const Type& v)
	{
		T splat(v);
		mX *= splat;
		mY *= splat;
		return *this;
	}

	inline VecBatch operator*(const VecBatch& v) const { return VecBatch(mX * v.mX, mY * v.mY); }

	inline VecBatch operator*(const RawBatch<Type>& v) const { return VecBatch(mX * v, mY * v); }

	inline VecBatch operator*(const Type v) const
	{
		T splat(v);
		return VecBatch(mX * splat, mY * splat);
	}

	inline VecBatch& operator/=(const VecBatch& v)
	{
		mX /= v.mX;
		mY /= v.mY;
		return *this;
	}

	inline VecBatch& operator/=(const Type& v)
	{
		T splat(v);
		mX /= splat;
		mY /= splat;
		return *this;
	}

	inline VecBatch operator/(const VecBatch& v) const { return VecBatch(mX / v.mX, mY / v.mY); }

	inline VecBatch operator/(const Type v) const
	{
		T splat(v);
		return VecBatch(mX / splat, mY / splat);
	}

	[[nodiscard]] constexpr T& X() { return mX; }

	[[nodiscard]] constexpr T& Y() { return mY; }

	[[nodiscard]] constexpr const T& X() const { return mX; }

	[[nodiscard]] constexpr const T& Y() const { return mY; }

	[[nodiscard]] constexpr ion::Vec2<Type> operator[](size_t index) const { return ion::Vec2<float>(mX[index], mY[index]); }

	[[nodiscard]] constexpr T LengthSqr() const { return T(mX * mX + mY * mY); }

	[[nodiscard]] constexpr T Length() const { return LengthSqr().Sqrt(); }

	[[nodiscard]] constexpr T DistanceSqr(VecBatch<T> other) const
	{
		other = other - *this;
		return other.LengthSqr();
	}

	[[nodiscard]] constexpr T Distance(const VecBatch<T>& other) const { return DistanceSqr(other).Sqrt(); }

	bool IsYLessThan(Type limit) const
	{
		auto y = Y().Scalar();
		return y[0] < limit || y[1] < limit || y[2] < limit || y[3] < limit;
	}

private:
	T mX;
	T mY;
};

template <typename T>
inline VecBatch<T>& operator+=(VecBatch<T>& lhs, const VecBatch<T>& rhs)
{
	lhs = VecBatch(lhs + rhs);
	return lhs;
}

template <typename T, typename Type>
inline VecBatch<T>& operator+=(VecBatch<T>& lhs, const Type& rhs)
{
	lhs = VecBatch<T>(lhs + rhs);
	return lhs;
}

template <typename T>
inline VecBatch<T>& operator-=(VecBatch<T>& lhs, const VecBatch<T>& rhs)
{
	lhs = VecBatch(lhs - rhs);
	return lhs;
}

template <typename T>
inline VecBatch<T>& operator*=(VecBatch<T>& lhs, const VecBatch<T>& rhs)
{
	lhs = VecBatch(lhs * rhs);
	return lhs;
}

template <typename T, typename Type>
inline VecBatch<T>& operator*=(VecBatch<T>& lhs, const Type& rhs)
{
	lhs = VecBatch<T>(lhs * rhs);
	return lhs;
}

template <typename T, typename Type>
inline VecBatch<T>& operator/=(VecBatch<T>& lhs, const Type& rhs)
{
	lhs = VecBatch<T>(lhs / rhs);
	return lhs;
}

template <typename T>
inline VecBatch<T>& operator/=(VecBatch<T>& lhs, const VecBatch<T>& rhs)
{
	lhs = VecBatch(lhs / rhs);
	return lhs;
}

template <typename T = RawBatch<float>>
[[nodiscard]] inline VecBatch<T> RadiansToUVec(const T& in)
{
#if ION_SIMD
	VecBatch<T> out;
	xsimd::sincos(in.Raw(), out.Y().Raw(), out.X().Raw());
	return out;
#else
	VecBatch<T> out;
	for (size_t i = 0; i < VecBatch<T>::Size(); ++i)
	{
		out.Set(i, ion::Vec<float, 2>(std::cos(in.Raw()[i]), std::sin(in.Raw()[i])));
	}
	return out;
#endif
}

using Float32Batch = RawBatch<>;
using Int32Batch = RawBatch<int32_t>;
using UInt32Batch = RawBatch<uint32_t>;
using Vec2fBatch = VecBatch<>;

template <typename T, size_t Count = ION_BATCH_SIZE>
struct Batch : public ion::Vec<T, Count>
{
	Batch() : ion::Vec<T, Count>() {}
	Batch(const T& splat) : ion::Vec<T, Count>(splat) {}
	Batch(const ion::Vec<T, Count>& other) : ion::Vec<T, Count>(other) {}
};

#if ION_BATCH_SIZE != 4
template <>
struct Batch<float, 4> : public ion::Vec<float, 4>
{
	Batch() : ion::Vec<float, 4>() {}
	Batch(const ion::Vec<float, 4>& other) : ion::Vec<float, 4>(other) {}
	Batch(float x, float y, float z, float a) : ion::Vec<float, 4>(x, y, z, a) {}
};

template <>
struct Batch<int32_t, 4> : public ion::Vec<int32_t, 4>
{
	Batch() : ion::Vec<int32_t, 4>() {}
	Batch(const ion::Vec<int32_t, 4>& other) : ion::Vec<int32_t, 4>(other) {}
	Batch(int32_t x, int32_t y, int32_t z, int32_t a) : ion::Vec<int32_t, 4>(x, y, z, a) {}
};
#endif

template <>
struct Batch<ion::Vec2f, VecBatch<>::ElementCount> : public VecBatch<>
{
	Batch() {}
	Batch(const ion::Vec2f& other) : ion::VecBatch<>(other) {}
	Batch(const ion::Vec2fBatch& other) : ion::VecBatch<>(other) {}
};

template <>
struct Batch<int32_t, ion::Int32Batch::ElementCount> : public ion::Int32Batch
{
	Batch(const ion::Int32Batch& other) : ion::Int32Batch(other) {}
	Batch() {}
	Batch(int32_t a, int32_t b, int32_t c, int32_t d) : ion::Int32Batch({a, b, c, d}) {}
};

template <>
struct Batch<uint32_t, ion::UInt32Batch::ElementCount> : public ion::UInt32Batch
{
	constexpr Batch(const ion::UInt32Batch& other) : ion::UInt32Batch(other) {}
	constexpr Batch() {}
	constexpr Batch(uint32_t a, uint32_t b, uint32_t c, uint32_t d) : ion::UInt32Batch({a, b, c, d}) {}
};

template <>
struct Batch<float, ion::Float32Batch::ElementCount> : public ion::Float32Batch
{
	constexpr Batch(const ion::Float32Batch& other) : ion::Float32Batch(other) {}
	constexpr Batch() {}
	inline Batch(float a, float b, float c, float d) : ion::Float32Batch({a, b, c, d}) {}
	Batch(const float* data, size_t count) : ion::Float32Batch(data, count) {}
};

template <>
[[nodiscard]] inline ion::Vec<float, Float32Batch::ElementCount> GetAsScalar(const Float32Batch& t)
{
	return t.Scalar();
}

template <typename T = float, typename F>
[[nodiscard]] constexpr ion::VecBatch<RawBatch<T>> MakeVecBatch(F&& f)
{
	return ion::VecBatch<RawBatch<T>>(ion::MakeFloatBatch<float>([&](size_t i) { return f(i).x(); }),
									  ion::MakeFloatBatch<float>([&](size_t i) { return f(i).y(); }));
}

template <>
struct BaseType<Float32Batch>
{
	using type = float;
};

template <>
struct BaseType<Int32Batch>
{
	using type = int32_t;
};

template <typename T, size_t s>
struct BaseType<Batch<T, s>>
{
	using type = T;
};

template<>
[[nodiscard]] inline ion::Batch<float, 4> Absf(const ion::Batch<float, 4> a)
{
#if ION_SIMD
	return ion::Batch<float, 4>(xsimd::fabs(a.Raw()));
#else
	ion::Batch<float, 4> out;
	for (size_t i = 0; i < 4; ++i)
	{
		out.Set(i, ion::Absf(a[i]));		
	}
	return out;
#endif
}

[[nodiscard]] inline Float32Batch WrapValue(const Float32Batch& a, float limit)
{
#if ION_SIMD	
	auto first = xsimd::select(a.Raw() > limit, a.Raw() - limit * 2, a.Raw());
	return Float32Batch(xsimd::select(first < -limit, first + limit * 2, first));
#else
	Float32Batch out;
	for (size_t i = 0; i < Float32Batch::ElementCount; ++i)
	{
		float first = a[i] > limit ? a[i] - limit * 2 : a[i];
		first = first < -limit ? first + limit * 2 : first;
		out.Set(i, first);
		
	}
	return out;
#endif
}

[[nodiscard]] inline Float32Batch atan2(const Float32Batch& a, const Float32Batch& b)
{
#if ION_SIMD
	return Float32Batch(xsimd::atan2(a.Raw(), b.Raw()));
#else
	Float32Batch out;
	for (size_t i = 0; i < Float32Batch::ElementCount; ++i)
	{
		out.Set(i, std::atan2(a[i], b[i]));
	}
	return out;
#endif
}
}  // namespace ion
