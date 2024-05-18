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

	template <typename ShiftType>
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

	inline void Set(size_t index, const Type& v) { mValue[index] = v; }

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

template <size_t Dim = 2, typename T = RawBatch<float>>
class VecBatch
{
public:
	using Type = typename T::type;

	static constexpr size_t ElementCount = T::ElementCount;

	VecBatch() = default;

	inline VecBatch(const Vec2<Type>& v) : mData{v.x(), v.y()} { static_assert(Dim == 2, "invalid dimension"); }

	inline VecBatch(const Vec3<Type>& v) : mData{v.x(), v.y(), v.z()} { static_assert(Dim == 3, "invalid dimension"); }

	inline VecBatch(const T& x, const T& y) : mData{x, y} { static_assert(Dim == 2, "invalid dimension"); }

	inline VecBatch(const T& x, const T& y, const T& z) : mData{x, y, z} { static_assert(Dim == 3, "invalid dimension"); }

	static size_t Size() { return ElementCount; }

	inline void Set(size_t index, const ion::Vec2<Type>& v)
	{
		static_assert(Dim == 2, "invalid dimension"); 
		X().Set(index, v.x());
		Y().Set(index, v.y());
	}

	inline void Set(size_t index, const ion::Vec3<Type>& v)
	{
		static_assert(Dim == 3, "invalid dimension"); 
		X().Set(index, v.x());
		Y().Set(index, v.y());
		Z().Set(index, v.z());
	}

	inline VecBatch& operator-=(const VecBatch& v)
	{
		X() -= v.X();
		Y() -= v.Y();
		if constexpr (Dim == 3)
		{
			Z() -= v.Z();
		}
		return *this;
	}

	inline VecBatch& operator-=(const Type& v)
	{
		T splat(v);
		X() -= splat;
		Y() -= splat;
		if constexpr (Dim == 3)
		{
			Z() -= splat;
		}
		return *this;
	}

	inline VecBatch operator-(const VecBatch& v) const
	{
		if constexpr (Dim == 3)
		{
			return VecBatch(X() - v.X(), Y() - v.Y(), Z() - v.Z());
		}
		else
		{
			return VecBatch(X() - v.X(), Y() - v.Y());
		}
	}

	inline VecBatch operator-() const
	{
		if constexpr (Dim == 3)
		{
			return VecBatch(-X(), -Y(), -Z());
		}
		else
		{
			return VecBatch(-X(), -Y());
		}
	}

	inline VecBatch& operator+=(const VecBatch& v)
	{
		X() += v.X();
		Y() += v.Y();
		if constexpr (Dim == 3)
		{
			Z() += v.Z();
		}
		return *this;
	}

	inline VecBatch& operator+=(const Type& v)
	{
		T splat(v);
		X() += splat;
		Y() += splat;
		if constexpr (Dim == 3)
		{
			Z() += splat;
		}
		return *this;
	}

	inline VecBatch operator+(const Vec<Type, Dim>& v) const
	{
		if constexpr (Dim == 3)
		{
			return VecBatch(X() + v.x(), Y() + v.y(), Z() + v.z());
		}
		else
		{
			return VecBatch(X() + v.x(), Y() + v.y());
		}
	}

	inline VecBatch operator+(const VecBatch<Dim, T>& v) const
	{
		if constexpr (Dim == 3)
		{
			return VecBatch<Dim, T>(X() + v.X(), Y() + v.Y(), Z() + v.Z());
		}
		else
		{
			return VecBatch<Dim, T>(X() + v.X(), Y() + v.Y());
		}
	}

	inline VecBatch operator+(Type v) const
	{
		if constexpr (Dim == 3)
		{
			return VecBatch<Dim, T>(X() + v, Y() + v, Z() + v);
		}
		else
		{
			return VecBatch<Dim, T>(X() + v, Y() + v);
		}
	}

	inline VecBatch& operator*=(const VecBatch& v)
	{
		X() *= v.X();
		Y() *= v.Y();
		if constexpr (Dim == 3)
		{
			Z() *= v.Z();
		}
		return *this;
	}

	inline VecBatch& operator*=(const Type& v)
	{
		T splat(v);
		X() *= splat;
		Y() *= splat;
		if constexpr (Dim == 3)
		{
			Z() *= splat;
		}
		return *this;
	}

	inline VecBatch operator*(const VecBatch& v) const
	{
		if constexpr (Dim == 3)
		{
			return VecBatch(X() * v.X(), Y() * v.Y(), Z() * v.Z());
		}
		else
		{
			return VecBatch(X() * v.X(), Y() * v.Y());
		}
	}

	inline VecBatch operator*(const RawBatch<Type>& v) const
	{
		if constexpr (Dim == 3)
		{
			return VecBatch(X() * v, Y() * v, Z() * v);
		}
		else
		{
			return VecBatch(X() * v, Y() * v);
		}
	}

	inline VecBatch operator*(const Type v) const
	{
		T splat(v);
		if constexpr (Dim == 3)
		{
			return VecBatch(X() * splat, Y() * splat, Z() * splat);
		}
		else
		{
			return VecBatch(X() * splat, Y() * splat);
		}
	}

	inline VecBatch& operator/=(const VecBatch& v)
	{
		X() /= v.X();
		Y() /= v.Y();
		if constexpr (Dim == 3)
		{
			Z() /= v.Z();
		}
		return *this;
	}

	inline VecBatch& operator/=(const Type& v)
	{
		T splat(v);
		X() /= splat;
		Y() /= splat;
		if constexpr (Dim == 3)
		{
			Z() /= splat;
		}
		return *this;
	}

	inline VecBatch operator/(const VecBatch& v) const
	{
		if constexpr (Dim == 3)
		{
			return VecBatch(X() / v.X(), Y() / v.Y(), Z() / v.Z());
		}
		else
		{
			return VecBatch(X() / v.X(), Y() / v.Y());
		}
	}

	inline VecBatch operator/(const Type v) const
	{
		T splat(v);
		if constexpr (Dim == 3)
		{
			return VecBatch(X() / splat, Y() / splat, Z() / splat);
		}
		else
		{
			return VecBatch(X() / splat, Y() / splat);
		}
	}

	[[nodiscard]] constexpr T& X() { return mData[0]; }

	[[nodiscard]] constexpr T& Y() { return mData[1]; }

	[[nodiscard]] constexpr T& Z() { return mData[2]; }

	[[nodiscard]] constexpr const T& X() const { return mData[0]; }

	[[nodiscard]] constexpr const T& Y() const { return mData[1]; }

	[[nodiscard]] constexpr const T& Z() const { return mData[2]; }

	[[nodiscard]] constexpr ion::Vec<Type, Dim> operator[](size_t index) const
	{
		if constexpr (Dim == 3)
		{
			return ion::Vec3<float>(X()[index], Y()[index], Z()[index]);
		}
		else if constexpr (Dim == 2) 
		{
			return ion::Vec2<float>(X()[index], Y()[index]);
		}
	}

	[[nodiscard]] constexpr T LengthSqr() const
	{
		if constexpr (Dim == 3)
		{
			return T(X() * X() + Y() * Y(), Z() * Z());
		}
		else
		{
			return T(X() * X() + Y() * Y());
		}
	}

	[[nodiscard]] constexpr T Length() const { return LengthSqr().Sqrt(); }

	[[nodiscard]] constexpr T DistanceSqr(VecBatch<Dim, T> other) const
	{
		other = other - *this;
		return other.LengthSqr();
	}

	[[nodiscard]] constexpr T Distance(const VecBatch<Dim, T>& other) const { return DistanceSqr(other).Sqrt(); }

	bool IsYLessThan(Type limit) const
	{
		auto y = Y().Scalar();
		return y[0] < limit || y[1] < limit || y[2] < limit || y[3] < limit;
	}

private:
	ion::Array<T, Dim> mData;
};

template <size_t Dim, typename T>
inline VecBatch<Dim, T>& operator+=(VecBatch<Dim, T>& lhs, const VecBatch<Dim, T>& rhs)
{
	lhs = VecBatch(lhs + rhs);
	return lhs;
}

template <size_t Dim, typename T, typename Type>
inline VecBatch<Dim, T>& operator+=(VecBatch<Dim, T>& lhs, const Type& rhs)
{
	lhs = VecBatch<T>(lhs + rhs);
	return lhs;
}

template <size_t Dim, typename T>
inline VecBatch<Dim, T>& operator-=(VecBatch<Dim, T>& lhs, const VecBatch<Dim, T>& rhs)
{
	lhs = VecBatch(lhs - rhs);
	return lhs;
}

template <size_t Dim, typename T>
inline VecBatch<Dim, T>& operator*=(VecBatch<Dim, T>& lhs, const VecBatch<Dim, T>& rhs)
{
	lhs = VecBatch(lhs * rhs);
	return lhs;
}

template <size_t Dim, typename T, typename Type>
inline VecBatch<Dim, T>& operator*=(VecBatch<Dim, T>& lhs, const Type& rhs)
{
	lhs = VecBatch<Dim, T>(lhs * rhs);
	return lhs;
}

template <size_t Dim, typename T, typename Type>
inline VecBatch<Dim, T>& operator/=(VecBatch<Dim, T>& lhs, const Type& rhs)
{
	lhs = VecBatch<T>(lhs / rhs);
	return lhs;
}

template <size_t Dim, typename T>
inline VecBatch<Dim, T>& operator/=(VecBatch<Dim, T>& lhs, const VecBatch<Dim, T>& rhs)
{
	lhs = VecBatch(lhs / rhs);
	return lhs;
}

template <size_t Dim, typename T = RawBatch<float>>
[[nodiscard]] inline VecBatch<Dim, T> RadiansToUVec(const T& in)
{
#if ION_SIMD
	VecBatch<Dim, T> out;
	if constexpr (Dim == 3)
	{
		xsimd::sincos(in.Raw(), out.Y().Raw(), out.X().Raw());
		out.Z() = 0;
	}
	else
	{
		xsimd::sincos(in.Raw(), out.Y().Raw(), out.X().Raw());
	}
	return out;
#else
	VecBatch<Dim, T> out;
	for (size_t i = 0; i < VecBatch<Dim, T>::Size(); ++i)
	{
		out.Set(i, ion::Vec<float, Dim>(std::cos(in.Raw()[i]), std::sin(in.Raw()[i])));
	}
	return out;
#endif
}

using Float32Batch = RawBatch<>;
using Int32Batch = RawBatch<int32_t>;
using Int16Batch = RawBatch<int16_t>;
using UInt32Batch = RawBatch<uint32_t>;
using Vec2fBatch = VecBatch<2>;
using Vec3fBatch = VecBatch<3>;

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
struct Batch<ion::Vec2f, VecBatch<2>::ElementCount> : public VecBatch<2>
{
	Batch() {}
	Batch(const ion::Vec2f& other) : ion::VecBatch<>(other) {}
	Batch(const ion::Vec2fBatch& other) : ion::VecBatch<>(other) {}
};

template <>
struct Batch<ion::Vec3f, VecBatch<3>::ElementCount> : public VecBatch<3>
{
	Batch() {}
	Batch(const ion::Vec3f& other) : ion::VecBatch<3>(other) {}
	Batch(const ion::Vec3fBatch& other) : ion::VecBatch<3>(other) {}
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

template <size_t Dim = 2, typename T = float, typename F>
[[nodiscard]] constexpr ion::VecBatch<Dim, RawBatch<T>> MakeVecBatch(F&& f)
{
	if constexpr (Dim == 2)
	{
		return ion::VecBatch<Dim, RawBatch<T>>(ion::MakeFloatBatch<float>([&](size_t i) { return f(i).x(); }),
											   ion::MakeFloatBatch<float>([&](size_t i) { return f(i).y(); }));
	}
	else if constexpr (Dim == 3)
	{
		return ion::VecBatch<Dim, RawBatch<T>>(ion::MakeFloatBatch<float>([&](size_t i) { return f(i).x(); }),
											   ion::MakeFloatBatch<float>([&](size_t i) { return f(i).y(); }),
											   ion::MakeFloatBatch<float>([&](size_t i) { return f(i).z(); }));
	}
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

[[nodiscard]] inline Float32Batch Abs(const Float32Batch& a)
{
#if ION_SIMD
	return Float32Batch(xsimd::fabs(a.Raw()));
#else
	Float32Batch out;
	for (size_t i = 0; i < Float32Batch::ElementCount; ++i)
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
