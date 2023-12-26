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
#include <ion/Base.h>
#include <ion/string/String.h>

namespace ion::serialization
{
void ConvertCharFromStringBuffer(char& dst, const char* src)
{
	long int value = strtol(src, nullptr, 10);
	dst = ion::SafeRangeCast<char>(value);
}

void ConvertUnsignedCharFromStringBuffer(unsigned char& dst, const char* src)
{
	long unsigned value = strtoul(src, nullptr, 10);
	dst = ion::SafeRangeCast<unsigned char>(value);
}

template <>
void Deserialize(unsigned short& dst, StringReader& reader)
{
	long unsigned value = strtoul(reader.Data(), nullptr, 10);
	dst = ion::SafeRangeCast<unsigned short>(value);
}

void ConvertIntFromStringBuffer(int& dst, const char* src)
{
	long int value = strtol(src, nullptr, 10);
	dst = ion::SafeRangeCast<int>(value);
}

void ConvertUnsignedIntFromStringBuffer(unsigned int& dst, const char* src)
{
	long unsigned value = strtoul(src, nullptr, 10);
	dst = ion::SafeRangeCast<unsigned int>(value);
}

void ConvertUnsignedLongFromStringBuffer(unsigned long& dst, const char* src)
{
	long unsigned value = strtoul(src, nullptr, 10);
	dst = value;
}

void ConvertUnsignedLongLongFromStringBuffer(unsigned long long& dst, const char* src)
{
	unsigned long long value = strtoull(src, nullptr, 10);
	dst = value;
}

void ConvertLongLongFromStringBuffer(long long& dst, const char* src)
{
	long long value = strtoll(src, nullptr, 10);
	dst = value;
}

void ConvertLongFromStringBuffer(long& dst, const char* src)
{
	long value = strtol(src, nullptr, 10);
	dst = value;
}

void ConvertFloatFromStringBuffer(float& dst, const char* src)
{
	double value = strtod(src, nullptr);
	dst = static_cast<float>(value);
}

void ConvertDoubleFromStringBuffer(double& dst, const char* src)
{
	double value = strtod(src, nullptr);
	dst = value;
}

ion::UInt ConvertBoolToStringBuffer(char* buffer, size_t bufferLen, const bool& data)
{
	return ion::UInt(snprintf(buffer, bufferLen, "%s", data ? "true" : "false"));
}

ion::UInt ConvertCharToStringBuffer(char* buffer, size_t bufferLen, const char& data) { return snprintf(buffer, bufferLen, "%c", data); }

void ConvertInt8ToStringBuffer(char* buffer, size_t bufferLen, const int8_t& data) { snprintf(buffer, bufferLen, "%" PRIi8, data); }

ion::UInt ConvertUInt8ToStringBuffer(char* buffer, size_t bufferLen, const uint8_t& data)
{
	return ion::UInt(snprintf(buffer, bufferLen, "%" PRIu8, data));
}

void ConvertInt16ToStringBuffer(char* buffer, size_t bufferLen, const int16_t& data) { snprintf(buffer, bufferLen, "%" PRIi16, data); }

void ConvertUInt16ToStringBuffer(char* buffer, size_t bufferLen, const uint16_t& data) { snprintf(buffer, bufferLen, "%" PRIu16, data); }

void ConvertInt32ToStringBuffer(char* buffer, size_t bufferLen, const int32_t& data) { snprintf(buffer, bufferLen, "%" PRIi32, data); }

void ConvertUInt32ToStringBuffer(char* buffer, size_t bufferLen, const uint32_t& data) { snprintf(buffer, bufferLen, "%" PRIu32, data); }

void ConvertInt64ToStringBuffer(char* buffer, size_t bufferLen, const int64_t& data) { snprintf(buffer, bufferLen, "%" PRIi64, data); }

void ConvertUInt64ToStringBuffer(char* buffer, size_t bufferLen, const uint64_t& data) { snprintf(buffer, bufferLen, "%" PRIu64, data); }

void ConvertLongToStringBuffer(char* buffer, size_t bufferLen, const long& data) { snprintf(buffer, bufferLen, "%li", data); }

void ConvertUnsignedLongToStringBuffer(char* buffer, size_t bufferLen, const unsigned long& data)
{
	snprintf(buffer, bufferLen, "%lu", data);
}

ion::UInt ConvertFloatToStringBuffer(char* buffer, size_t bufferLen, const float& data)
{
	return ion::UInt(snprintf(buffer, bufferLen, "%f", data));
}

ion::UInt ConvertDoubleToStringBuffer(char* buffer, size_t bufferLen, const double& data)
{
	return ion::UInt(snprintf(buffer, bufferLen, "%f", data));
}

ion::UInt Serialize(const char* data, StringWriter& writer)
{
	auto u = ion::UInt(ion::StringCopy(writer.Data(), ion::Min(writer.Available(), ion::StringLen(data) + 1), data));
	writer.Skip(u);
	return u;
}

template <>
UInt Serialize(const StringView& data, StringWriter& writer)
{
	return writer.Write(data);
}

}  // namespace ion::serialization
