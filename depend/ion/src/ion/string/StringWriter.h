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

#include <ion/string/StringView.h>
#include <ion/string/StringUtil.h>

namespace ion
{
class String;

template <typename Buffer = ion::String>
class StringWriter
{
public:
	StringWriter(Buffer& buffer) : mString(buffer), mWritePos(buffer.Length()) {}

	~StringWriter() { mString.Resize(mWritePos); }

	void Write(const char* const value)
	{
		Write(value, strlen(value) + 1);
		mWritePos--;
	}

	template <typename T>
	void Write(const T& value)
	{
		Write(value, 256);
	}

	template <>
	void Write(const Buffer& value)
	{
		Write(value, value.Length() + 1);
		mWritePos--;
	}

private:
	template <typename T>
	void Write(const T& value, size_t maxLen)
	{
		mString.Resize(maxLen + mWritePos);
		mWritePos += ion::serialization::Serialize(value, &mString.Data()[mWritePos], maxLen, nullptr);
	}

	Buffer& mString;
	size_t mWritePos;
};

struct EditableStringView
{
	char* mData;
	size_t len;
};

template<>
class StringWriter<EditableStringView>
{
public:
	StringWriter<EditableStringView>(EditableStringView stringSpan)
	  : mWritePosition(stringSpan.mData), mBufferEndPosition(stringSpan.mData + stringSpan.len)
	{
	}
	template <typename T>
	inline char* Write(const T& data);
	inline char* Write(const char* string);

	size_t Count(char* source) const { return size_t(mWritePosition - source); };
	size_t Available() const { return size_t(mBufferEndPosition - mWritePosition); };

private:
	char* mWritePosition;
	char* mBufferEndPosition;
};

template <typename T>
inline char* StringWriter<EditableStringView>::Write(const T& data)
{
	auto count = ion::serialization::Serialize(data, mWritePosition, Available(), nullptr);
	mWritePosition += count;
	return mWritePosition;
}

template <>
inline char* StringWriter<EditableStringView>::Write(const StringView& string)
{
	auto count = ion::serialization::Serialize(string, mWritePosition, Available(), nullptr);
	mWritePosition += count;
	return mWritePosition;
}

inline char* StringWriter<EditableStringView>::Write(const char* string) { return Write(StringView(string, ion::StringLen(string))); }

}  // namespace ion
