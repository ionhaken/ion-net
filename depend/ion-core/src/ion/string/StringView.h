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

#include <ion/container/ArrayView.h>
#include <ion/tracing/Log.h>
#include <ion/util/SafeRangeCast.h>
#include <ion/string/StringUtil.h>
#include <ion/string/StringWriter.h>

namespace ion
{
const char gNullString = 0;
class StringView
{
public:
	StringView() : mArray(&gNullString, 0) {}

	// StringView(const ion::String& string) : mArray(string.CStr(), ion::SafeRangeCast<uint32_t>(string.Length())) {}
	constexpr explicit StringView(const char* const text, size_t size) : mArray(text, size) {}

	// Compile time view of string. If compilation fails, use ion::StringLength() to get runtime string length for string view.
	// Note: It's not always good idea to have compile time generated view as it uses additional memory for string length.
	ION_CONSTEVAL StringView(const char text[]) : StringView(text, ion::ConstexprStringLength(text)) {}

	[[nodiscard]] const char* const CStr() const { return mArray.Data(); }
	[[nodiscard]] size_t Length() const { return mArray.Size(); }

private:
	ArrayView<const char, size_t> mArray;
};

namespace serialization
{
template <>
inline ion::UInt Serialize(const StringView& data, StringWriter& writer)
{
	ION_ASSERT_FMT_IMMEDIATE(writer.Available() > data.Length(), "Out of buffer");
	memcpy(writer.Data(), data.CStr(), data.Length());
	writer.Skip(data.Length());
	return ion::SafeRangeCast<ion::UInt>(data.Length());
}

}  // namespace serialization

}  // namespace ion
