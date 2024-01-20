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
#include <ion/container/Vector.h>

#include <ion/fixedpoint/FixedMath.h>
#include <ion/string/String.h>
#include <ion/util/Vec.h>

namespace ion
{
using Fixed32Vec2 = Vec2<Fixed32>;

template <>
[[nodiscard]] inline Fixed32 Length(const Fixed32Vec2& vec)
{
	const unsigned int LargeScale = 100;
	if (ion::Absf(vec.x()) + ion::Absf(vec.y()) > LargeScale)
	{
		Fixed32 x = vec.x() / LargeScale;
		Fixed32 y = vec.y() / LargeScale;
		return ion::sqrt(x * x + y * y) * LargeScale;
	}
	else
	{
		return ion::sqrt(vec.x() * vec.x() + vec.y() * vec.y());
	}
}

template <>
[[nodiscard]] inline Fixed32Vec2 Normalize(const Fixed32Vec2& vec)
{
	auto len = ion::Length(vec);
	if (len > 0)
	{
	#if ION_CONFIG_FAST_MATH
		/*auto inv = ion::Reciprocal(len);
		return Vec(x() * inv, y() * inv);*/
		return Vec(x() / len, y() / len);
	#else
		return Fixed32Vec2(vec.x() / len, vec.y() / len);
	#endif
	}
	else
	{
		return Fixed32Vec2(0, 0);
	}
}

template <>
inline void tracing::Handler(LogEvent& e, const Vec2<ion::Fixed32>& value)	// , char* buffer, size_t size)
{
	char buffer[32];
	snprintf(buffer, 32, "%f, %f", static_cast<float>(value.x()), static_cast<float>(value.y()));
	e.Write(buffer);
}
}  // namespace ion
