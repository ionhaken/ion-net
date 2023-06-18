#pragma once
/*
 * Modified from https://github.com/louis-langholtz/PlayRho/blob/master/PlayRho/Common/Fixed.hpp
 * Copyright (c) 2017 Louis Langholtz
 */

#include <cstdint>
#include <limits>
#include <cmath>

#include <ion/util/Wider.h>

#undef min
#undef max

// #define ION_FIXEDPOINT_INF_NAN

namespace ion
{
/// FixedPoint.
///
/// @details This is a fixed point type template for a given base type using a given number
/// of fraction bits.
///
/// This is a 32-bit sized fixed point type with a 18.14 format.
/// With a 14-bit fraction part:
///   * 0.000061035156250 is the smallest double precision value that can be represented;
///   *
template <typename BASE_TYPE, unsigned int FRACTION_BITS>
class FixedPoint
{
public:
	using value_type = BASE_TYPE;
	static constexpr unsigned int FractionBits = FRACTION_BITS;
	static constexpr value_type ScaleFactor = static_cast<value_type>(1u << FractionBits);

	static constexpr FixedPoint GetMin() noexcept { return FixedPoint{1, scalar_type{1}}; }

	static constexpr FixedPoint GetInfinity() noexcept { return FixedPoint{numeric_limits::max(), scalar_type{1}}; }

	static constexpr FixedPoint GetMax() noexcept
	{
		// max reserved for +inf
		return FixedPoint{numeric_limits::max() - 1, scalar_type{1}};
	}

	static constexpr inline FixedPoint GetNaN() noexcept { return FixedPoint{numeric_limits::lowest(), scalar_type{1}}; }

	static constexpr FixedPoint GetNegativeInfinity() noexcept
	{
		// lowest reserved for NaN
		return FixedPoint{numeric_limits::lowest() + 1, scalar_type{1}};
	}

	static constexpr FixedPoint GetLowest() noexcept
	{
		// lowest reserved for NaN
		// lowest + 1 reserved for -inf
		return FixedPoint{numeric_limits::lowest() + 2, scalar_type{1}};
	}

	template <typename T>
	static constexpr value_type GetFromFloat(T val) noexcept
	{
		static_assert(std::is_floating_point<T>::value, "floating point value required");
		// Note: std::isnan(val) *NOT* constant expression, so can't use here!
		return !(val <= 0 || val >= 0)						   ? GetNaN().m_value
			   : (val > static_cast<long double>(GetMax()))	   ? GetInfinity().m_value
			   : (val < static_cast<long double>(GetLowest())) ? GetNegativeInfinity().m_value
															   : static_cast<value_type>(val * ScaleFactor);
	}

	template <typename T>
	static constexpr value_type GetFromSignedInt(T val) noexcept
	{
		static_assert(std::is_integral<T>::value, "integral value required");
		static_assert(std::is_signed<T>::value, "must be signed");
		return static_cast<value_type>((val > (GetMax().m_value / ScaleFactor))		 ? GetInfinity().m_value
									   : (val < (GetLowest().m_value / ScaleFactor)) ? GetNegativeInfinity().m_value
																					 : val * ScaleFactor);
	}

	using wider_type = typename ion::Wider<value_type>::type;
	using unsigned_wider_type = typename std::make_unsigned<wider_type>::type;

	template <typename T>
	static constexpr value_type GetFromUnsignedInt(T val) noexcept
	{
		static_assert(std::is_integral<T>::value, "integral value required");
		static_assert(!std::is_signed<T>::value, "must be unsigned");
		const auto max = static_cast<unsigned_wider_type>(GetMax().m_value / ScaleFactor);
		return (val > max) ? GetInfinity().m_value : static_cast<value_type>(val) * ScaleFactor;
	}

	FixedPoint() = default;

	constexpr FixedPoint(long double val) noexcept : m_value{GetFromFloat(val)}
	{
		ION_ASSERT_FMT_IMMEDIATE(m_value >= GetLowest().m_value && m_value <= GetMax().m_value, "Overflow");
	}

	constexpr FixedPoint(double val) noexcept : m_value{GetFromFloat(val)}
	{
		ION_ASSERT_FMT_IMMEDIATE(m_value >= GetLowest().m_value && m_value <= GetMax().m_value, "Overflow");
	}

	constexpr FixedPoint(float val) noexcept : m_value{GetFromFloat(val)} {}

	constexpr FixedPoint(unsigned long long val) noexcept : m_value{GetFromUnsignedInt(val)} {}

	constexpr FixedPoint(unsigned long val) noexcept : m_value{GetFromUnsignedInt(val)} {}

	constexpr FixedPoint(unsigned int val) noexcept : m_value{GetFromUnsignedInt(val)} {}

	constexpr FixedPoint(long int val) noexcept : m_value{GetFromSignedInt(val)}
	{
		ION_ASSERT_FMT_IMMEDIATE(m_value >= GetLowest().m_value && m_value <= GetMax().m_value, "Overflow");
	}

	constexpr FixedPoint(long long val) noexcept : m_value{GetFromSignedInt(val)}
	{
		ION_ASSERT_FMT_IMMEDIATE(m_value >= GetLowest().m_value && m_value <= GetMax().m_value, "Overflow");
	}

	template <typename T>
	constexpr FixedPoint(const Fraction<T>& f) noexcept
	  : m_value{static_cast<value_type>(static_cast<wider_type>(f.Numerator()) * ScaleFactor / f.Denominator())}
	{
	}

	constexpr FixedPoint(int val) noexcept : m_value{GetFromSignedInt(val)}
	{
		ION_ASSERT_FMT_IMMEDIATE(m_value >= GetLowest().m_value && m_value <= GetMax().m_value, "Overflow");
	}

	constexpr FixedPoint(short val) noexcept : m_value{GetFromSignedInt(val)} {}

	constexpr FixedPoint(value_type val, unsigned int fraction) noexcept
	  : m_value{static_cast<value_type>(static_cast<uint32_t>(val * ScaleFactor) | fraction)}
	{
	}

	template <typename BT, unsigned int FB>
	constexpr FixedPoint(const FixedPoint<BT, FB> val) noexcept : FixedPoint(static_cast<long double>(val))
	{
	}

	// Methods

	template <typename T>
	constexpr T ConvertTo() const noexcept
	{
		return isnan()		 ? std::numeric_limits<T>::signaling_NaN()
			   : !isfinite() ? std::numeric_limits<T>::infinity() * getsign()
							 : static_cast<T>(m_value) / ScaleFactor;
	}

	constexpr bool IsEqual(const FixedPoint& other) const noexcept { return !isnan() && !other.isnan() && m_value == other.m_value; }

	constexpr bool IsLessThan(const FixedPoint& other) const noexcept
	{
		ION_ASSERT_FMT_IMMEDIATE(!isnan() && !other.isnan(), "Operation not supported");
		return m_value < other.m_value;
	}

	constexpr bool IsLessThanOrEqual(const FixedPoint& other) const noexcept
	{
		ION_ASSERT_FMT_IMMEDIATE(!isnan() && !other.isnan(), "Operation not supported");
		return m_value <= other.m_value;
	}

	constexpr bool IsGreaterThan(const FixedPoint& other) const noexcept
	{
		ION_ASSERT_FMT_IMMEDIATE(!isnan() && !other.isnan(), "Operation not supported");
		return m_value > other.m_value;
	}

	constexpr bool IsGreaterThanOrEqual(const FixedPoint& other) const noexcept
	{
		ION_ASSERT_FMT_IMMEDIATE(!isnan() && !other.isnan(), "Operation not supported");
		return m_value >= other.m_value;
	}

	// Unary operations

	explicit constexpr operator long double() const noexcept { return ConvertTo<long double>(); }

	explicit constexpr operator double() const noexcept { return ConvertTo<double>(); }

	explicit constexpr operator float() const noexcept { return ConvertTo<float>(); }

	explicit constexpr operator long long() const noexcept { return m_value / ScaleFactor; }

	explicit constexpr operator long() const noexcept { return m_value / ScaleFactor; }

	explicit constexpr operator unsigned long long() const noexcept
	{
		// Behavior is undefined if m_value is negative
		return static_cast<unsigned long long>(m_value / ScaleFactor);
	}

	explicit constexpr operator unsigned long() const noexcept
	{
		// Behavior is undefined if m_value is negative
		return static_cast<unsigned long>(m_value / ScaleFactor);
	}

	explicit constexpr operator unsigned int() const noexcept
	{
		// Behavior is undefined if m_value is negative
		return static_cast<unsigned int>(m_value / ScaleFactor);
	}

	explicit constexpr operator int() const noexcept { return static_cast<int>(m_value / ScaleFactor); }

	explicit constexpr operator short() const noexcept { return static_cast<short>(m_value / ScaleFactor); }

	template <typename T>
	explicit constexpr operator Fraction<T>() const noexcept
	{
		return Fraction<T>(m_value, ScaleFactor);
	}

	constexpr FixedPoint operator-() const noexcept
	{
#ifdef ION_FIXEDPOINT_INF_NAN
		return (isnan()) ? *this : Fixed{-m_value, scalar_type{1}};
#else
		ION_ASSERT_FMT_IMMEDIATE(!isnan(), "Operation not supported");
		return FixedPoint{-m_value, scalar_type{1}};
#endif
	}

	constexpr FixedPoint operator+() const noexcept { return *this; }

	explicit constexpr operator bool() const noexcept { return m_value != 0; }

	constexpr bool operator!() const noexcept { return m_value == 0; }

	constexpr FixedPoint& operator+=(FixedPoint val) noexcept
	{
#ifdef ION_FIXEDPOINT_INF_NAN
		if (isnan() || val.isnan() || ((m_value == GetInfinity().m_value) && (val.m_value == GetNegativeInfinity().m_value)) ||
			((m_value == GetNegativeInfinity().m_value) && (val.m_value == GetInfinity().m_value)))
		{
			*this = GetNaN();
		}
		else if (val.m_value == GetInfinity().m_value)
		{
			m_value = GetInfinity().m_value;
		}
		else if (val.m_value == GetNegativeInfinity().m_value)
		{
			m_value = GetNegativeInfinity().m_value;
		}
		else if (isfinite() && val.isfinite())
#else
		ION_ASSERT_FMT_IMMEDIATE(!isnan() && !val.isnan() && isfinite() && val.isfinite(), "Operation not supported");
#endif
		{
			const auto result = wider_type{m_value} + val.m_value;
#ifdef ION_FIXEDPOINT_INF_NAN
			if (result > GetMax().m_value)
			{
				// overflow from max
				m_value = GetInfinity().m_value;
			}
			else if (result < GetLowest().m_value)
			{
				// overflow from lowest
				m_value = GetNegativeInfinity().m_value;
			}
			else
#else
			ION_ASSERT_FMT_IMMEDIATE(result <= GetMax().m_value, "Overflow");
			ION_ASSERT_FMT_IMMEDIATE(result >= GetLowest().m_value, "Negative overflow");
#endif
			{
				m_value = static_cast<value_type>(result);
			}
		}
		return *this;
	}

	constexpr FixedPoint& operator-=(FixedPoint val) noexcept
	{
#ifdef ION_FIXEDPOINT_INF_NAN
		if (isnan() || val.isnan() || ((m_value == GetInfinity().m_value) && (val.m_value == GetInfinity().m_value)) ||
			((m_value == GetNegativeInfinity().m_value) && (val.m_value == GetNegativeInfinity().m_value)))
		{
			*this = GetNaN();
		}
		else if (val.m_value == GetInfinity().m_value)
		{
			m_value = GetNegativeInfinity().m_value;
		}
		else if (val.m_value == GetNegativeInfinity().m_value)
		{
			m_value = GetInfinity().m_value;
		}
		else if (isfinite() && val.isfinite())
#else
		ION_ASSERT_FMT_IMMEDIATE(!isnan(), "Value is NaN");
		ION_ASSERT_FMT_IMMEDIATE(!val.isnan(), "Other value is NaN");
		ION_ASSERT_FMT_IMMEDIATE(isfinite(), "Value is not finite");
		ION_ASSERT_FMT_IMMEDIATE(val.isfinite(), "Other value is not finite");
#endif
		{
			const auto result = wider_type{m_value} - val.m_value;
#ifdef ION_FIXEDPOINT_INF_NAN
			if (result > GetMax().m_value)
			{
				// overflow from max
				m_value = GetInfinity().m_value;
			}
			else if (result < GetLowest().m_value)
			{
				// overflow from lowest
				m_value = GetNegativeInfinity().m_value;
			}
			else
#else
			ION_ASSERT_FMT_IMMEDIATE(result <= GetMax().m_value, "Overflow");
			ION_ASSERT_FMT_IMMEDIATE(result >= GetLowest().m_value, "Negative overflow");
#endif
			{
				m_value = static_cast<value_type>(result);
			}
		}
		return *this;
	}

	constexpr FixedPoint& operator*=(FixedPoint val) noexcept
	{
#ifdef ION_FIXEDPOINT_INF_NAN
		if (isnan() || val.isnan())
		{
			*this = GetNaN();
		}
		else if (!isfinite() || !val.isfinite())
		{
			if (m_value == 0 || val.m_value == 0)
			{
				*this = GetNaN();
			}
			else
			{
				*this = ((m_value > 0) != (val.m_value > 0)) ? -GetInfinity() : GetInfinity();
			}
		}
		else
#else
		ION_ASSERT_FMT_IMMEDIATE(!isnan(), "Value is NaN");
		ION_ASSERT_FMT_IMMEDIATE(!val.isnan(), "Other value is NaN");
		ION_ASSERT_FMT_IMMEDIATE(isfinite() || (val.m_value == FixedPoint(1).m_value || !val.isfinite()), "Value is not finite");
		ION_ASSERT_FMT_IMMEDIATE(val.isfinite() || (this->m_value == FixedPoint(1).m_value || !isfinite()), "Other value is not finite");
#endif
		{
			const wider_type product = wider_type{m_value} * wider_type{val.m_value};
			wider_type result;
if constexpr ((((wider_type{0})-1) >> 1) == ((wider_type{0})-1))
{
			// Right shift of a negative signed number has implementation-defined behaviour.
			// Use shifting if compiler generates arithmetic shift (sign is not lost)
			result = product >> FractionBits;
}
else
{
			result = product / ScaleFactor;
}

#ifdef ION_FIXEDPOINT_INF_NAN
			if (product != 0 && result == 0)
			{
				// underflow
				m_value = static_cast<value_type>(result);
			}
			else if (result > GetMax().m_value)
			{
				// overflow from max
				m_value = GetInfinity().m_value;
			}
			else if (result < GetLowest().m_value)
			{
				// overflow from lowest
				m_value = GetNegativeInfinity().m_value;
			}
			else
#else
			ION_ASSERT_FMT_IMMEDIATE(
			  result <= GetMax().m_value || (val.m_value == FixedPoint(1).m_value || this->m_value == FixedPoint(1).m_value), "Overflow %f",
			  ConvertTo<float>());
			ION_ASSERT_FMT_IMMEDIATE(
			  result >= GetLowest().m_value || (val.m_value == FixedPoint(1).m_value || this->m_value == FixedPoint(1).m_value),
			  "Negative overflow %f", ConvertTo<float>());
#endif
			{
				m_value = static_cast<value_type>(result);
			}
		}
		return *this;
	}

	constexpr FixedPoint& operator/=(FixedPoint val) noexcept
	{
#ifdef ION_FIXEDPOINT_INF_NAN
		if (isnan() || val.isnan())
		{
			*this = GetNaN();
		}
		else if (!isfinite() && !val.isfinite())
		{
			*this = GetNaN();
		}
		else if (!isfinite())
		{
			*this = ((m_value > 0) != (val.m_value > 0)) ? -GetInfinity() : GetInfinity();
		}
		else if (!val.isfinite())
		{
			*this = 0;
		}
		else
#endif
#if ION_CONFIG_FAST_MATH
		{
			ion::Fraction32 fraction(val);
			auto inv = ion::Fraction(fraction.Denominator(), fraction.Numerator());
			*this = *this * inv;
		}
#else
		{
			const auto product = wider_type{m_value} * ScaleFactor;
			const auto result = product / val.m_value;
	#ifdef ION_FIXEDPOINT_INF_NAN
			if (product != 0 && result == 0)
			{
				// underflow
				m_value = static_cast<value_type>(result);
			}
			else if (result > GetMax().m_value)
			{
				// overflow from max
				m_value = GetInfinity().m_value;
			}
			else if (result < GetLowest().m_value)
			{
				// overflow from lowest
				m_value = GetNegativeInfinity().m_value;
			}
			else
	#else
			ION_ASSERT_FMT_IMMEDIATE(result <= GetMax().m_value, "Overflow");
			ION_ASSERT_FMT_IMMEDIATE(result >= GetLowest().m_value, "Negative overflow");
	#endif
			{
				m_value = static_cast<value_type>(result);
			}
		}
#endif
		return *this;
	}

	constexpr FixedPoint& operator%=(FixedPoint val) noexcept
	{
		ION_ASSERT_FMT_IMMEDIATE(!isnan() && !val.isnan(), "Operation not supported");
		m_value %= val.m_value;
		return *this;
	}

	constexpr bool isnan() const noexcept { return m_value == GetNaN().m_value; }

private:
	friend class FixedMath;

	struct scalar_type
	{
		value_type value = 1;
	};

	using numeric_limits = std::numeric_limits<value_type>;

	constexpr FixedPoint(value_type val, scalar_type scalar) noexcept : m_value{val * scalar.value} {}

	constexpr bool isfinite() const noexcept { return (m_value > GetNegativeInfinity().m_value) && (m_value < GetInfinity().m_value); }

	constexpr int getsign() const noexcept { return (m_value >= 0) ? +1 : -1; }

	value_type m_value;
};

using Fixed32 = FixedPoint<std::int32_t, 14>;

// Fixed32 free functions.

constexpr Fixed32 operator+(Fixed32 lhs, Fixed32 rhs) noexcept
{
	lhs += rhs;
	return lhs;
}

constexpr Fixed32 operator-(Fixed32 lhs, Fixed32 rhs) noexcept
{
	lhs -= rhs;
	return lhs;
}

constexpr Fixed32 operator*(Fixed32 lhs, Fixed32 rhs) noexcept
{
	lhs *= rhs;
	return lhs;
}

constexpr Fixed32 operator/(Fixed32 lhs, Fixed32 rhs) noexcept
{
	lhs /= rhs;
	return lhs;
}

constexpr Fixed32 operator%(Fixed32 lhs, Fixed32 rhs) noexcept
{
	lhs %= rhs;
	return lhs;
}

constexpr bool operator==(Fixed32 lhs, Fixed32 rhs) noexcept { return lhs.IsEqual(rhs); }

constexpr bool operator!=(Fixed32 lhs, Fixed32 rhs) noexcept { return !lhs.IsEqual(rhs); }

constexpr bool operator<=(Fixed32 lhs, Fixed32 rhs) noexcept { return lhs.IsLessThanOrEqual(rhs); }

constexpr bool operator>=(Fixed32 lhs, Fixed32 rhs) noexcept { return lhs.IsGreaterThanOrEqual(rhs); }

constexpr bool operator<(Fixed32 lhs, Fixed32 rhs) noexcept { return lhs.IsLessThan(rhs); }

constexpr bool operator>(Fixed32 lhs, Fixed32 rhs) noexcept { return lhs.IsGreaterThan(rhs); }

constexpr ion::Fixed32 sqrt(ion::Fixed32 x)
{
	ION_ASSERT_FMT_IMMEDIATE(x >= 0 && !std::isinf(static_cast<float>(x)), "Invalid input");
	if (x < ion::Fraction32(1, 100))
	{
		return ion::Fixed32(0u);
	}

	ion::Fixed32 currentVal(x);
	currentVal *= ion::Fraction32(1, 2);

	int i = ((1 << 5) | static_cast<int>(x));
	while ((i >>= 1) != 0)
	{
		currentVal += x / currentVal;
		currentVal *= ion::Fraction32(1, 2);
	}
	return currentVal;
}
}  // namespace ion

namespace std
{
// Fixed32

template <>
class numeric_limits<ion::Fixed32>
{
public:
	static constexpr bool is_specialized = true;

	static constexpr ion::Fixed32 min() noexcept { return ion::Fixed32::GetMin(); }
	static constexpr ion::Fixed32 max() noexcept { return ion::Fixed32::GetMax(); }
	static constexpr ion::Fixed32 lowest() noexcept { return ion::Fixed32::GetLowest(); }

	static constexpr int digits = 31 - ion::Fixed32::FractionBits;
	static constexpr int digits10 = 31 - ion::Fixed32::FractionBits;
	static constexpr int max_digits10 = 5;

	static constexpr bool is_signed = true;
	static constexpr bool is_integer = false;
	static constexpr bool is_exact = true;
	static constexpr int radix = 0;
	static constexpr int min_exponent = 0;
	static constexpr int min_exponent10 = 0;
	static constexpr int max_exponent = 0;
	static constexpr int max_exponent10 = 0;

	static constexpr bool has_infinity = true;
	static constexpr bool has_quiet_NaN = true;
	static constexpr bool has_signaling_NaN = false;
	static constexpr float_denorm_style has_denorm = denorm_absent;
	static constexpr bool has_denorm_loss = false;
	static constexpr ion::Fixed32 infinity() noexcept { return ion::Fixed32::GetInfinity(); }
	static constexpr ion::Fixed32 quiet_NaN() noexcept { return ion::Fixed32::GetNaN(); }

	static constexpr bool is_iec559 = false;
	static constexpr bool is_bounded = true;
	static constexpr bool is_modulo = false;

	static constexpr bool traps = false;
	static constexpr bool tinyness_before = false;
	static constexpr float_round_style round_style = round_toward_zero;
};
}  // namespace std
