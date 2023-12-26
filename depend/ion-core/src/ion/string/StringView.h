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

namespace ion
{

template <size_t StackCapacity, size_t MaxCapacity>
class StackStringFormatter;

template <size_t StackCapacity>
class StackString;

template <typename Allocator>
class BasicString;

class String;

class StringView
{
	friend class String;
	friend class StringWriter;
	friend class JSONStructWriter;

public:
	StringView();

	constexpr explicit StringView(const char* const text, size_t size) : mArray(text, size) {}

	// Compile time view of string. If compilation fails, use ion::StringLength() to get runtime string length for string view.
	// Note: It's not always good idea to have compile time generated view as it uses additional memory for string length.
	ION_CONSTEVAL StringView(const char text[]) : StringView(text, ConstexprStringLength(text)) {}

	explicit StringView(const String& string);

	template <size_t StackCapacity, size_t MaxCapacity = 256 * 1024>
	constexpr StringView(const StackStringFormatter<StackCapacity, MaxCapacity>& formatter)
	  : StringView(formatter.CStr(), formatter.Length())
	{
	}

	template <size_t StackCapacity>
	constexpr StringView(const StackString<StackCapacity>& stackString) : StringView(stackString.CStr(), stackString.Length())
	{
	}

	template <typename Allocator>
	constexpr StringView(const BasicString<Allocator>& string) : StringView(string.CStr(), string.Length())
	{
	}

	[[nodiscard]] const char* const CStr() const
	{
		ION_ASSERT_FMT_IMMEDIATE(mArray.Data()[Length()] == 0, "String is not null terminated");
		return mArray.Data();
	}
	[[nodiscard]] size_t Length() const { return mArray.Size(); }

	[[nodiscard]] bool operator==(const char* str) const;

	[[nodiscard]] bool operator==(const StringView other) const
	{
		return other.Length() == Length() && memcmp(mArray.Data(), other.mArray.Data(), Length()) == 0;
	}

private:
	// To by-pass assert of CStr() - used by friend classes only.
	[[nodiscard]] const char* const Copy() const { return mArray.Data(); }

	ArrayView<const char, size_t> mArray;
};

}  // namespace ion
