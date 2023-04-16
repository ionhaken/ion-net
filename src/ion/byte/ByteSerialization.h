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
#include <ion/Types.h>
#include <ion/byte/ByteWriter.h>
#include <ion/container/ForEach.h>
#include <ion/util/Bits.h>

namespace ion
{
class String;
}
namespace ion::serialization
{

namespace detail
{
template <typename LengthType, typename DataType>
LengthType DeserializeLength(ion::ByteReader& reader)
{
	const constexpr size_t MaxItems = 16 * 1024;
	LengthType s = 0;
	if (reader.Available() >= sizeof(LengthType))
	{
		reader.ReadAssumeAvailable(s);
		// Make some assumptions about available amount of data, when remote is sending huge array.
		// We are doing this to avoid running out of memory due to bad content.
		if (s > MaxItems /*|| (s >= 8 * 1024 / sizeof(DataType) && reader.Available() < (sizeof(DataType) * s) / 2)*/)
		{
			ION_ABNORMAL("Too large array to be deserialized");
			s = 0;
		}
	}
	return s;
}
}  // namespace detail

template <typename Type, typename WriterType>
inline void Serialize(const Type& value, WriterType& writer)
{
	if constexpr (ion::IsFixedArray<Type>::value)
	{
		if constexpr (std::is_integral<typename Type::Type>::value || std::is_floating_point<typename Type::Type>::value)
		{
			constexpr ion::ByteSizeType s = ion::SafeRangeCast<ion::ByteSizeType>(sizeof(value));
			writer.WriteArray(reinterpret_cast<const uint8_t*>(value.Data()), s);
		}
		else
		{
			ion::ForEach(value, [&](const auto& elem) { Serialize(elem, writer, nullptr); });
		}
	}
	else if constexpr (ion::IsArray<Type>::value)
	{
		uint32_t s = value.Size();
		writer.EnsureCapacity(sizeof(typename Type::Type) * s + sizeof(uint32_t));
		writer.WriteKeepCapacity(s);
		if constexpr (std::is_integral<typename Type::Type>::value || std::is_floating_point<typename Type::Type>::value)
		{
			writer.WriteArrayKeepCapacity(reinterpret_cast<const uint8_t*>(value.Data()), sizeof(typename Type::Type) * s);
		}
		else
		{
			ion::ForEach(value, [&](const auto& elem) { Serialize(elem, writer, nullptr); });
		}
	}
	else if constexpr (std::is_enum<Type>::value)
	{
		using EnumType = typename std::underlying_type<Type>::type;
		static_assert(!std::is_enum<EnumType>::value, "Invalid enum");
		const EnumType enumValue = static_cast<EnumType>(value);
		return Serialize(enumValue, writer);
	}
	else if constexpr (std::is_trivially_copyable_v<Type>)
	{
		writer.Write(value);
	}
	else
	{
		Type::TypeConversionNotImplemented();
	}
}

template <typename Type>
inline bool Deserialize(Type& dst, ion::ByteReader& reader, void* ctx)
{
	bool success = true;
	if constexpr (IsFixedArray<Type>::value)
	{
		if constexpr (std::is_integral<typename Type::Type>::value || std::is_floating_point<typename Type::Type>::value)
		{
			constexpr ion::ByteSizeType s = ion::SafeRangeCast<ion::ByteSizeType>(sizeof(dst));
			if (reader.Available() >= s)
			{
				reader.ReadAssumeAvailable(reinterpret_cast<uint8_t*>(dst.Data()), s);
			}
		}
		else
		{
			for (size_t i = 0; i < dst.Size(); ++i)
			{
				success &= Deserialize(dst[i], reader, nullptr);
			}
		}
	}
	else if constexpr (IsArray<Type>::value)
	{
		uint32_t s = detail::DeserializeLength<uint32_t, typename Type::Type>(reader);
		if constexpr (std::is_integral<typename Type::Type>::value || std::is_floating_point<typename Type::Type>::value)
		{
			if (reader.Available() >= sizeof(typename Type::Type) * s)
			{
				dst.Resize(s);
				reader.ReadAssumeAvailable(reinterpret_cast<uint8_t*>(dst.Data()), sizeof(typename Type::Type) * s);
			}
			else
			{
				return false;
			}
		}
		else
		{
			dst.Reserve(s + dst.Size());
			for (size_t i = 0; i < s; ++i)
			{
				typename Type::Type v;
				success &= Deserialize(v, reader, nullptr);
				dst.Add(v);
			}
		}
	}
	else if constexpr (std::is_enum<Type>::value)
	{
		using EnumType = typename std::underlying_type<Type>::type;
		static_assert(!std::is_convertible<Type, EnumType>::value, "Scoped enums allowed only");
		static_assert(!std::is_enum<EnumType>::value, "Invalid enum");
		EnumType enumValue;
		success = Deserialize(enumValue, reader, ctx);
		dst = static_cast<Type>(enumValue);
	}
	else if constexpr (std::is_trivially_copyable_v<Type>)
	{
		if (reader.Available() >= sizeof(Type))
		{
			reader.ReadAssumeAvailable(dst);
		}
		else
		{
			success = false;
		}
	}
	else
	{
		Type::TypeConversionNotImplemented();
	}
	return success;
}

template <>
void Serialize(const String& src, ion::ByteWriter& writer);

template <>
bool Deserialize(String& dst, ion::ByteReader& reader, void*);

template <typename Type>
inline bool Deserialize(Type& dst, ion::ByteReader& reader)
{
	return Deserialize(dst, reader, nullptr);
}


}  // namespace ion::serialization

namespace ion
{
template <typename T>
inline bool ByteReader::Process(T& t)
{
	return ion::serialization::Deserialize(t, *this, nullptr);
}
template <typename T>
inline bool ByteWriter::Process(const T& t)
{
	ion::serialization::Serialize(t, *this);
	return true;
}

template <typename T>
inline bool ByteWriterUnsafe::Process(const T& t)
{
	ion::serialization::Serialize(t, *this);
	return true;
}

template <typename T>
inline bool BufferWriterUnsafe::Process(const T& t)
{
	ion::serialization::Serialize(t, *this);
	return true;
}


}  // namespace ion
