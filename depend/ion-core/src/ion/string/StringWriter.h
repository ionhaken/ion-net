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

#include <ion/string/StringUtil.h>
#include <ion/tracing/Tracing.h>

namespace ion
{
class String;

class StringWriter
{
public:
	StringWriter(char* buffer, size_t len) : mBuffer(buffer), mEnd(buffer + len) {}
	char* Data() { return mBuffer; }
	void Skip(size_t s)
	{
		ION_ASSERT_FMT_IMMEDIATE(size_t(mEnd - mBuffer) >= s, "Buffer overflow");
		mBuffer += s;
	}

	size_t Available() { return size_t(mEnd - mBuffer); }

	void* mContext = nullptr;

private:
	char* mBuffer;
	char* mEnd;
};

class StringReader
{
public:
	StringReader(const char* buffer, size_t len) : mBuffer(buffer), mEnd(buffer + len) {}
	const char* Data() { return mBuffer; }
	void Skip(size_t s)
	{
		ION_ASSERT_FMT_IMMEDIATE(size_t(mEnd - mBuffer) >= s, "Buffer overflow");
		mBuffer += s;
	}
	void* mContext = nullptr;

	size_t Available() { return size_t(mEnd - mBuffer); }

private:
	const char* mBuffer;
	const char* mEnd;
};

}  // namespace ion
