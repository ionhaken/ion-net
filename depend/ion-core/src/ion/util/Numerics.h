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
#include <ion/util/Vec.h>

namespace ion
{
namespace numerics
{
// Linear interpolation
template <typename T, typename U>
[[nodiscard]] constexpr T Lerp(const T& v0, const T& v1, U t)
{
	// #TODO: Support bool batch
	// ION_ASSERT_FMT_IMMEDIATE(t >= U(0) && t <= U(1), "Invalid time");
	return v0 + ((v1 - v0) * t);
}

template <typename T, typename U>
[[nodiscard]] constexpr T LerpPrecise(const T& v0, const T& v1, U t)
{
	// #TODO: Support bool batch
	// ION_ASSERT_FMT_IMMEDIATE(t >= U(0) && t <= U(1), "Invalid time");
	return v0 * (-t + 1.0f) + v1 * t;
}

template <typename T, typename U>
[[nodiscard]] constexpr T AngleLerp(const T& a1, const T& a2, U fraction)
{
	T diff(a2 - a1);
	T wrappedDiff = ion::WrapValue(diff, ion::Math::Pi<float>());
	return a1 + (wrappedDiff * fraction);
}

template <typename T, typename U>
[[nodiscard]] constexpr T AngleHerp(const T& a1, const T& /*v1*/, const T& a2, const T& /*v2*/, U fraction)
{
	T diff(a2 - a1);
	//auto iVelWrapped = ion::WrapValue(v1, ion::Math::Pi<float>());
	//auto iVel = v1 - iVelWrapped;

	T wrappedDiff = ion::WrapValue(diff, ion::Math::Pi<float>());
	return a1 + ((wrappedDiff /*+ iVel*/) * fraction);
}

// Returns the unit length vector for the given angle (in radians).
template <typename RadiansType, typename VecType = ion::Vec2<RadiansType>>
[[nodiscard]] constexpr VecType RadiansToUVec(RadiansType radians)
{
	return VecType(static_cast<typename VecType::type>(ion::cos(radians)), static_cast<typename VecType::type>(ion::sin(radians)));
}

template <typename VecType, typename RadiansType = typename VecType::type>
[[nodiscard]] constexpr RadiansType UVecToRadians(const VecType& vec)
{
	return ion::atan2(vec.y(), vec.x());
}

template <typename DegreeType, typename VecType = ion::Vec2<DegreeType>>
[[nodiscard]] constexpr VecType DegreesToUVec(DegreeType degrees)
{
	return RadiansToUVec(DegreesToRadians(degrees));
}

template <typename T>
[[nodiscard]] constexpr T DegreesToRadians(T degrees)
{
	// return degrees / (static_cast<T>(ion::Fraction32(180)) / ion::Math::Pi<T>());
	return ion::Math::Pi<T>() * degrees / (static_cast<T>(ion::Fraction32(180)));
}

template <typename T>
[[nodiscard]] constexpr T RadiansToDegrees(T radians)
{
	return radians * (static_cast<T>(ion::Fraction32(180)) / ion::Math::Pi<T>());
}

template <typename T>
[[nodiscard]] constexpr T PointDistanceFromPlane(const ion::Vec2<T>& point, const ion::Vec2<T>& p1, const ion::Vec2<T>& p2)
{
	T a = p1.y - p2.y;
	T b = p2.x - p1.x;
	T c = p1.x * p2.y - p2.x * p1.y;
	return std::abs(a * point.x + b * point.y + c) / sqrt(a * a + b * b);
}

template <typename T>
[[nodiscard]] constexpr ion::Vec2<T> ProjectPointOnLine(const ion::Vec2<T>& point, const ion::Vec2<T>& p1, const ion::Vec2<T>& p2)
{
	ion::Vec2<T> planePoint{(p1.x() + p2.x()) / 2, (p1.y() + p2.y()) / 2};
	ion::Vec2<T> planeNormal{p1.y() - p2.y(), p2.x() - p1.x()};
	planeNormal = ion::Normalize(planeNormal);
	auto signedDistancePlanePoint = planeNormal.Dot(planeNormal, point - planePoint);
	ion::Vec2<T> translationVector = planeNormal * signedDistancePlanePoint;
	return point - translationVector;
}

template <typename T>
[[nodiscard]] constexpr ion::Vec2<T> ProjectPointOnSegment(const ion::Vec2<T>& point, const ion::Vec2<T>& p1, const ion::Vec2<T>& p2)
{
	ion::Vec2<T> linePoint = ProjectPointOnLine(point, p1, p2);
	auto distanceToP1Sqr = (linePoint - p1).LengthSqr();
	auto distanceToP2Sqr = (linePoint - p2).LengthSqr();
	auto segmentLengthSqr = (p1 - p2).LengthSqr();
	if (distanceToP1Sqr < distanceToP2Sqr)
	{
		return distanceToP1Sqr > segmentLengthSqr ? p1 : linePoint;
	}
	else
	{
		return distanceToP2Sqr > segmentLengthSqr ? p2 : linePoint;
	}
}

template <typename VecType, typename OutType = typename VecType::type>
inline OutType DotProduct(VecType& left, VecType& right)
{
	return right.x() * left.x() + right.y() * left.y();
}
}  // namespace numerics
}  // namespace ion
