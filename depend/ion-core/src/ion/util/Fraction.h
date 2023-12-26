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

#include <limits>
#include <type_traits>	// make_unsigned

#include <ion/Types.h>
#include <ion/util/Wider.h>

namespace ion
{
template <typename TSigned>
class Fraction
{
public:
	typedef typename std::make_unsigned<TSigned>::type TUnsigned;

	explicit constexpr Fraction(TSigned numerator, TUnsigned denominator) : mNumerator(numerator), mDenominator(denominator) {}

	constexpr Fraction(short val) : mNumerator(val), mDenominator(1) {}

	explicit constexpr Fraction(unsigned short val) : mNumerator(val), mDenominator(1) {}

	constexpr Fraction(int val) : mNumerator(val), mDenominator(1) {}

	explicit constexpr Fraction(unsigned int val) : mNumerator(val), mDenominator(1) {}

	explicit constexpr Fraction(long val) : mNumerator(val), mDenominator(1) {}

	explicit constexpr Fraction(unsigned long val) : mNumerator(val), mDenominator(1) {}

	explicit constexpr Fraction(long long val) : mNumerator(val), mDenominator(1) {}

	explicit constexpr Fraction(unsigned long long val) : mNumerator(val), mDenominator(1) {}
#if ION_CONFIG_REAL_IS_FIXED_POINT
	explicit 
		#endif
		constexpr operator float() const noexcept { return static_cast<float>(mNumerator) / mDenominator; }

	explicit constexpr operator double() const noexcept { return static_cast<double>(mNumerator) / mDenominator; }

	explicit constexpr operator int32_t() const noexcept { return static_cast<int32_t>(mNumerator) / mDenominator; }

	explicit constexpr operator int64_t() const noexcept { return static_cast<int64_t>(mNumerator) / mDenominator; }

	explicit constexpr operator uint64_t() const noexcept { return static_cast<uint64_t>(mNumerator) / mDenominator; }

	constexpr TSigned Numerator() const { return mNumerator; }
	constexpr TUnsigned Denominator() const { return mDenominator; }

private:
	TSigned mNumerator;
	TUnsigned mDenominator;
};

template <typename T>
constexpr Fraction<T> operator*(Fraction<T> lhs, uint64_t rhs) noexcept
{
	return Fraction<T>(static_cast<T>(lhs.Numerator() * rhs), lhs.Denominator());
}

template <typename T>
constexpr uint64_t operator*(uint64_t lhs, Fraction<T> rhs) noexcept
{
	return lhs * rhs.Numerator() / rhs.Denominator();
}

template <typename T>
constexpr float operator*(float lhs, Fraction<T> rhs) noexcept
{
	return lhs * rhs.Numerator() / rhs.Denominator();
}

template <typename T>
constexpr double operator*(double lhs, Fraction<T> rhs) noexcept
{
	return lhs * rhs.Numerator() / rhs.Denominator();
}

template <typename T>
constexpr Fraction<T> operator+(Fraction<T> lhs, Fraction<T> rhs) noexcept
{
	if (lhs.Denominator() != rhs.Denominator())
	{
		lhs = lhs * Fraction<T>(1, rhs.Denominator());
		rhs = rhs * Fraction<T>(1, lhs.Denominator());
		ION_ASSERT_FMT_IMMEDIATE(lhs.Denominator() == rhs.Denominator(), "Cannot do addition");
	}
	return Fraction<T>(lhs.Numerator() + rhs.Numerator(), lhs.Denominator());
}

template <typename T>
constexpr Fraction<T> operator/(Fraction<T> lhs, Fraction<T> rhs) noexcept
{
	return Fraction<T>(lhs.Numerator() * rhs.Denominator(), rhs.Numerator() * lhs.Denominator());
}

template <typename T>
constexpr Fraction<T> operator*(Fraction<T> lhs, Fraction<T> rhs) noexcept
{
	if (rhs.Numerator() == 0 || lhs.Numerator() == 0)
	{
		lhs = Fraction<T>(0);
	}
	else
	{
		typename Wider<T>::type num;
		typename Wider<typename Fraction<T>::TUnsigned>::type den;
		num = static_cast<typename Wider<T>::type>(lhs.Numerator()) * rhs.Numerator();
		den = static_cast<typename Wider<typename Fraction<T>::TUnsigned>::type>(lhs.Denominator()) * rhs.Denominator();
		while (num >= (std::numeric_limits<T>::max)() || den >= (std::numeric_limits<T>::max)())
		{
			num >>= 1;
			den >>= 1;
		}
		lhs = Fraction<T>(static_cast<T>(num), static_cast<typename Fraction<T>::TUnsigned>(den));
	}
	return lhs;
}

typedef Fraction<int64_t> Fraction64;
typedef Fraction<int32_t> Fraction32;
}  // namespace ion
