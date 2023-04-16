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
#include <ion/json/JSONSerialization.h>
#include <ion/fixedpoint/FixedVec2.h>

namespace ion::serialization
{
template <>
inline void Deserialize(Vec2<Fixed32>& dst, const char* src, void*);

template <>
inline ion::UInt Serialize(const Vec2<Fixed32>& src, char* buffer, size_t bufferLen, const void*);

template <>
inline void Deserialize(FixedPoint<std::int32_t, 14>& dst, const char* src, void*);

template <>
inline ion::UInt Serialize(const FixedPoint<std::int32_t, 14>& src, char* buffer, size_t bufferLen, const void*);

template <>
inline bool Serialize(const FixedPoint<std::int32_t, 14>& in, const char* name, ion::JSONStructWriter& out, const void* ctx)
{
	char buffer[10];
	Serialize<Fixed32>(in, buffer, 10, ctx);
	ion::StackString<256> str(buffer);
	out.AddMember(name, str.CStr());
	return true;
}

template <>
inline bool Deserialize(FixedPoint<std::int32_t, 14>& out, const char* name, ion::JSONStructReader& in, void* ctx)
{
	auto stringView = in.GetString(name);
	Deserialize<Fixed32>(out, stringView.CStr(), ctx);
	return true;
}

template <>
inline bool Serialize(const Vec2<FixedPoint<std::int32_t, 14>>& in, const char* name, ion::JSONStructWriter& out, const void* ctx)
{
	ion::JSONStructWriter pivot(out, name);
	Serialize(in.x(), "x", pivot, ctx);
	Serialize(in.y(), "y", pivot, ctx);
	return true;
}

template <>
inline bool Deserialize(Vec2<FixedPoint<std::int32_t, 14>>& out, const char* name, ion::JSONStructReader& in, void* ctx)
{
	ion::JSONStructReader pivot(in.Child(name));
	Deserialize(out.x(), "x", pivot, ctx);
	Deserialize(out.y(), "y", pivot, ctx);
	return true;
}

template <>
inline void Deserialize(FixedPoint<std::int32_t, 14>& dst, const char* src, void*)
{
	ion::String str(src);
	ion::SmallVector<ion::String, 2> list;
	str.Tokenize(list, ".", false);
	int32_t left;
	int32_t right;
	if (list.Size() == 2)
	{
		bool isNegative = false;  // This is for handling negative values between 0...-1
		{
			auto* buffer = list[0].CStr();
			for (size_t i = 0; i < list[0].Length(); ++i)
			{
				if (buffer[i] >= '0' && buffer[i] <= '9')
				{
					break;
				}
				else if (buffer[i] == '-')
				{
					isNegative = true;
					break;
				}
			}
		}

		ion::serialization::Deserialize(left, list[0].CStr(), nullptr);
		if (left < 0)
		{
			ION_ASSERT(isNegative, "Value was consider negative");
			left = -left;
		}

		int multiplier = 10;
		ion::serialization::Deserialize(right, list[1].CStr(), nullptr);

		while (right > multiplier)
		{
			multiplier *= 10;
		}

		{
			auto* buffer = list[1].CStr();
			for (size_t i = 0; i < list[1].Length(); ++i)
			{
				if (buffer[i] == '0')
				{
					multiplier *= 10;
				}
				else
				{
					break;
				}
			}
		}

		left *= multiplier;
		left += right;
		right = multiplier;
		if (isNegative)
		{
			left = -left;
		}
	}
	else
	{
		ion::serialization::Deserialize(left, src, nullptr);
		right = 1;
	}
	dst = ion::Fraction32(left, right);
}

template <>
inline void Deserialize(Vec2<FixedPoint<std::int32_t, 14>>& dst, const char* src, void*)
{
	ion::String str(src);
	ion::SmallVector<ion::String, 2> list;
	str.Tokenize(list);
	if (list.Size() == 2)
	{
		ion::serialization::Deserialize(dst.x(), list[0].CStr(), nullptr);
		ion::serialization::Deserialize(dst.y(), list[1].CStr(), nullptr);
	}
}

template <>
inline ion::UInt Serialize(const FixedPoint<std::int32_t, 14>& src, char* buffer, size_t bufferLen, const void*)
{
	float floatval = src.ConvertTo<float>();
	return ion::serialization::Serialize(floatval, buffer, bufferLen, nullptr);
}

template <>
inline ion::UInt Serialize(const Vec2<FixedPoint<std::int32_t, 14>>& data, char* buffer, size_t bufferLen, const void*)
{
	ion::Vec2f floatvec{data.x().ConvertTo<float>(), data.y().ConvertTo<float>()};
	return ion::serialization::Serialize(floatvec, buffer, bufferLen, nullptr);
}

}  // namespace ion::serialization
