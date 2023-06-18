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
inline void Deserialize(Vec2<Fixed32>& dst, StringReader& reader);

template <>
inline ion::UInt Serialize(const Vec2<Fixed32>& src, StringWriter& writer);

template <>
inline void Deserialize(FixedPoint<std::int32_t, 14>& dst, StringReader& reader);

template <>
inline ion::UInt Serialize(const FixedPoint<std::int32_t, 14>& src, StringWriter& writer);

template <>
inline bool Serialize(const FixedPoint<std::int32_t, 14>& in, const char* name, ion::JSONStructWriter& out)
{
	char buffer[10];
	StringWriter writer(buffer, 10);
	Serialize<Fixed32>(in, writer);
	ion::StackString<256> str(buffer);
	out.AddMember(name, str.CStr());
	return true;
}

template <>
inline bool Deserialize(FixedPoint<std::int32_t, 14>& out, const char* name, ion::JSONStructReader& in)
{
	auto stringView = in.GetString(name);
	StringReader reader(stringView.CStr(), stringView.Length());
	Deserialize<Fixed32>(out, reader);
	return true;
}

template <>
inline bool Serialize(const Vec2<FixedPoint<std::int32_t, 14>>& in, const char* name, ion::JSONStructWriter& out)
{
	ion::JSONStructWriter pivot(out, name);
	Serialize(in.x(), "x", pivot);
	Serialize(in.y(), "y", pivot);
	return true;
}

template <>
inline bool Deserialize(Vec2<FixedPoint<std::int32_t, 14>>& out, const char* name, ion::JSONStructReader& in)
{
	ion::JSONStructReader pivot(in.Child(name));
	Deserialize(out.x(), "x", pivot);
	Deserialize(out.y(), "y", pivot);
	return true;
}

template <>
inline void Deserialize(FixedPoint<std::int32_t, 14>& dst, StringReader& reader)
{
	ion::String str(reader.Data());
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

		StringReader reader0(list[0].CStr(), list[0].Length());
		ion::serialization::Deserialize(left, reader0);
		if (left < 0)
		{
			ION_ASSERT(isNegative, "Value was consider negative");
			left = -left;
		}

		int multiplier = 10;
		StringReader reader1(list[1].CStr(), list[1].Length());
		ion::serialization::Deserialize(right, reader1);

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
		ion::serialization::Deserialize(left, reader);
		right = 1;
	}
	dst = ion::Fraction32(left, right);
}

template <>
inline void Deserialize(Vec2<FixedPoint<std::int32_t, 14>>& dst, StringReader& reader)
{
	ion::String str(reader.Data());
	ion::SmallVector<ion::String, 2> list;
	str.Tokenize(list);
	if (list.Size() == 2)
	{
		StringReader reader0(list[0].CStr(), list[0].Length());
		StringReader reader1(list[1].CStr(), list[1].Length());
		ion::serialization::Deserialize(dst.x(), reader0);
		ion::serialization::Deserialize(dst.y(), reader1);
	}
}

template <>
inline ion::UInt Serialize(const FixedPoint<std::int32_t, 14>& src, StringWriter& writer)
{
	float floatval = src.ConvertTo<float>();
	return ion::serialization::Serialize(floatval, writer);
}

template <>
inline ion::UInt Serialize(const Vec2<FixedPoint<std::int32_t, 14>>& data, StringWriter& writer)
{
	ion::Vec2f floatvec{data.x().ConvertTo<float>(), data.y().ConvertTo<float>()};
	return ion::serialization::Serialize(floatvec, writer);
}

}  // namespace ion::serialization
