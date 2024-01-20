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
#include <ion/debug/Error.h>

#include <inttypes.h>
#include <type_traits>
#if ION_EXTERNAL_STRING_CONVERSIONS == 1
	#include <itoa/to_text_from_integer.h>
#endif

#include <ion/string/StringWriter.h>

// Type to char buffer serialization/deserialization. Please note that serialization checks buffer size only in debug mode. If you need
// checked serialization, please use ByteWriter::Process() (See ByteSerialization.h)
namespace ion::serialization
{
void ConvertCharFromStringBuffer(char& dst, const char* src);
void ConvertUnsignedCharFromStringBuffer(unsigned char& dst, const char* src);
void ConvertIntFromStringBuffer(int& dst, const char* src);
void ConvertUnsignedIntFromStringBuffer(unsigned int& dst, const char* src);
void ConvertUnsignedLongFromStringBuffer(unsigned long& dst, const char* src);
void ConvertUnsignedLongLongFromStringBuffer(unsigned long long& dst, const char* src);
void ConvertLongLongFromStringBuffer(long long& dst, const char* src);
void ConvertLongFromStringBuffer(long& dst, const char* src);
void ConvertFloatFromStringBuffer(float& dst, const char* src);
void ConvertDoubleFromStringBuffer(double& dst, const char* src);
ion::UInt ConvertBoolToStringBuffer(char* buffer, size_t bufferLen, const bool& data);
ion::UInt ConvertCharToStringBuffer(char* buffer, size_t bufferLen, const char& data);
void ConvertInt8ToStringBuffer(char* buffer, size_t bufferLen, const int8_t& data);
ion::UInt ConvertUInt8ToStringBuffer(char* buffer, size_t bufferLen, const uint8_t& data);
void ConvertInt16ToStringBuffer(char* buffer, size_t bufferLen, const int16_t& data);
void ConvertUInt16ToStringBuffer(char* buffer, size_t bufferLen, const uint16_t& data);
void ConvertInt32ToStringBuffer(char* buffer, size_t bufferLen, const int32_t& data);
void ConvertUInt32ToStringBuffer(char* buffer, size_t bufferLen, const uint32_t& data);
void ConvertInt64ToStringBuffer(char* buffer, size_t bufferLen, const int64_t& data);
void ConvertUInt64ToStringBuffer(char* buffer, size_t bufferLen, const uint64_t& data);
void ConvertLongToStringBuffer(char* buffer, size_t bufferLen, const long& data);
void ConvertUnsignedLongToStringBuffer(char* buffer, size_t bufferLen, const unsigned long& data);
ion::UInt ConvertFloatToStringBuffer(char* buffer, size_t bufferLen, const float& data);
ion::UInt ConvertDoubleToStringBuffer(char* buffer, size_t bufferLen, const double& data);

template <typename Type>
inline void Deserialize(Type& dst, ion::StringReader& reader)
{
	if constexpr (std::is_enum<Type>::value)
	{
		using EnumType = typename std::underlying_type<Type>::type;
		static_assert(!std::is_convertible<Type, EnumType>::value, "Scoped enums allowed only");
		static_assert(!std::is_enum<EnumType>::value, "Invalid enum");
		EnumType enumValue;
		Deserialize(enumValue, reader);
		dst = static_cast<Type>(enumValue);
	}
	else
	{
		Type::TypeConversionNotImplemented();  // Add new specialization
	}
}

template <>
inline void Deserialize(char& dst, ion::StringReader& reader)
{
	ConvertCharFromStringBuffer(dst, reader.Data());
}

template <>
inline void Deserialize(unsigned char& dst, ion::StringReader& reader)
{
	ConvertUnsignedCharFromStringBuffer(dst, reader.Data());
}

template <>
inline void Deserialize(int& dst, ion::StringReader& reader)
{
	ConvertIntFromStringBuffer(dst, reader.Data());
}

template <>
inline void Deserialize(unsigned int& dst, ion::StringReader& reader)
{
	ConvertUnsignedIntFromStringBuffer(dst, reader.Data());
}

template <>
void Deserialize(unsigned short& dst, ion::StringReader& reader);

template <>
inline void Deserialize(unsigned long& dst, ion::StringReader& reader)
{
	ConvertUnsignedLongFromStringBuffer(dst, reader.Data());
}

template <>
inline void Deserialize(unsigned long long& dst, ion::StringReader& reader)
{
	ConvertUnsignedLongLongFromStringBuffer(dst, reader.Data());
}

template <>
inline void Deserialize(long long& dst, ion::StringReader& reader)
{
	ConvertLongLongFromStringBuffer(dst, reader.Data());
}

template <>
inline void Deserialize(long& dst, ion::StringReader& reader)
{
	ConvertLongFromStringBuffer(dst, reader.Data());
}

template <>
inline void Deserialize(float& dst, ion::StringReader& reader)
{
	ConvertFloatFromStringBuffer(dst, reader.Data());
}

template <>
inline void Deserialize(double& dst, ion::StringReader& reader)
{
	ConvertDoubleFromStringBuffer(dst, reader.Data());
}

ion::UInt Serialize(const char* data, ion::StringWriter& writer);

template <typename Type>
inline ion::UInt Serialize(const Type& data, ion::StringWriter& writer)
{
	if constexpr (std::is_enum<Type>::value)
	{
		using EnumType = typename std::underlying_type<Type>::type;
		static_assert(!std::is_enum<EnumType>::value, "Invalid enum");
		const EnumType enumValue = static_cast<EnumType>(data);
		return Serialize(enumValue, writer);
	}
	else
	{
		Type::TypeConversionNotImplemented();  // Add new specialization
	}
}
template <>
inline ion::UInt Serialize(const bool& data, ion::StringWriter& writer)
{
	// jeaiii::to_text(buffer, data);
	return ConvertBoolToStringBuffer(writer.Data(), writer.Available(), data);
}

template <>
inline ion::UInt Serialize(const char& data, ion::StringWriter& writer)
{
	auto u = ConvertCharToStringBuffer(writer.Data(), writer.Available(), data);
	writer.Skip(u);
	return u;
}

template <>
inline ion::UInt Serialize(const int8_t& data, ion::StringWriter& writer)
{
	char* end = jeaiii::to_text(writer.Data(), data);
	*end = 0;
	ion::UInt u = ion::UInt(end - writer.Data());
	writer.Skip(u);
	return u;
	////ConvertInt8ToStringBuffer(buffer, bufferLen, data);
}

template <>
inline ion::UInt Serialize(const uint8_t& data, ion::StringWriter& writer)
{
	char* end = jeaiii::to_text(writer.Data(), data);
	*end = 0;
	ion::UInt u = ion::UInt(end - writer.Data());
	writer.Skip(u);
	return u;
	// ConvertUInt8ToStringBuffer(buffer, bufferLen, data);
}

template <>
inline ion::UInt Serialize(const int16_t& data, ion::StringWriter& writer)
{
	char* end = jeaiii::to_text(writer.Data(), data);
	*end = 0;
	ion::UInt u = ion::UInt(end - writer.Data());
	writer.Skip(u);
	return u;
	// ConvertInt16ToStringBuffer(buffer, bufferLen, data);
}

template <>
inline ion::UInt Serialize(const uint16_t& data, ion::StringWriter& writer)
{
	char* end = jeaiii::to_text(writer.Data(), data);
	*end = 0;
	ion::UInt u = ion::UInt(end - writer.Data());
	writer.Skip(u);
	return u;
	// ConvertUInt16ToStringBuffer(buffer, bufferLen, data);
}

template <>
inline ion::UInt Serialize(const int32_t& data, ion::StringWriter& writer)
{
	char* end = jeaiii::to_text(writer.Data(), data);
	*end = 0;
	ion::UInt u = ion::UInt(end - writer.Data());
	writer.Skip(u);
	return u;
	// ConvertInt32ToStringBuffer(buffer, bufferLen, data);
}

template <>
inline ion::UInt Serialize(const uint32_t& data, ion::StringWriter& writer)
{
	char* end = jeaiii::to_text(writer.Data(), data);
	*end = 0;
	ion::UInt u = ion::UInt(end - writer.Data());
	writer.Skip(u);
	return u;
	// ConvertUInt32ToStringBuffer(buffer, bufferLen, data);
}

template <>
inline ion::UInt Serialize(const int64_t& data, ion::StringWriter& writer)
{
	char* end = jeaiii::to_text(writer.Data(), data);
	*end = 0;
	ion::UInt u = ion::UInt(end - writer.Data());
	writer.Skip(u);
	return u;
	// ConvertInt64ToStringBuffer(buffer, bufferLen, data);
}

template <>
inline ion::UInt Serialize(const uint64_t& data, ion::StringWriter& writer)
{
	char* end = jeaiii::to_text(writer.Data(), data);
	*end = 0;
	ion::UInt u = ion::UInt(end - writer.Data());
	writer.Skip(u);
	return u;
	// ConvertUInt64ToStringBuffer(buffer, bufferLen, data);
}

template <>
inline ion::UInt Serialize(const float& data, ion::StringWriter& writer)
{
	return ConvertFloatToStringBuffer(writer.Data(), writer.Available(), data);
}

template <>
inline ion::UInt Serialize(const double& data, ion::StringWriter& writer)
{
	return ConvertDoubleToStringBuffer(writer.Data(), writer.Available(), data);
}

// #TODO: Get rid of these ----------
#if ION_PLATFORM_LINUX
template <>
inline ion::UInt Serialize(const long long& data, ion::StringWriter& writer)
{
	char* end = jeaiii::to_text(writer.Data(), data);
	*end = 0;
	ion::UInt u = ion::UInt(end - writer.Data());
	writer.Skip(u);
	return u;
	// ConvertInt64ToStringBuffer(buffer, bufferLen, data);
}
#endif
#if ION_PLATFORM_MICROSOFT || defined(ION_ARCH_ARM_32)
template <>
inline ion::UInt Serialize(const long& data, ion::StringWriter& writer)
{
	char* end = jeaiii::to_text(writer.Data(), data);
	*end = 0;
	ion::UInt u = ion::UInt(end - writer.Data());
	writer.Skip(u);
	return u;
	// ConvertInt64ToStringBuffer(buffer, bufferLen, data);
}
template <>
inline ion::UInt Serialize(const unsigned long& data, ion::StringWriter& writer)
{
	char* end = jeaiii::to_text(writer.Data(), data);
	*end = 0;
	ion::UInt u = ion::UInt(end - writer.Data());
	writer.Skip(u);
	return u;
	// ConvertUInt64ToStringBuffer(buffer, bufferLen, data);
}
#endif
// ----------

template <>
UInt Serialize(const StringView& data, StringWriter& writer);

}  // namespace ion::serialization
