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

#include <cstdio>

namespace ion
{

template <size_t StackCapacity, size_t MaxCapacity = 256 * 1024>
class StackStringFormatter
{
public:
	ION_CLASS_NON_COPYABLE(StackStringFormatter);

	StackStringFormatter()
	{
		mData.ResizeFast(StackCapacity);
	}

	template <typename... Args>
	int Format(const char* format, Args&&... args)
	{
		int written;
		int newCapacity = 0;
		do
		{
			written = snprintf(mData.Data(), mData.Size(), format, std::forward<Args>(args)...);
		} while (!FormatInternal(written, format, newCapacity));
		mUsedSpace = written;
		return written;
	}

	// C support
	int Format(const char* format, va_list arglist)
	{
		int written;
		int newCapacity = 0;
		do
		{
			written = vsnprintf(mData.Data(), mData.Size(), format, arglist);
		} while (!FormatInternal(written, format, newCapacity));
		mUsedSpace = written;
		return written;
	}

	int Format(const char* format)
	{
		size_t len = ion::StringLen(format);
		mData.Clear();
		if (len + 1 >= mData.Size())
		{
			mData.ResizeFast(len + 1, len + 1);
		}
		StringCopy(mData.Data(), len + 1, format);
		mUsedSpace = len;
		return int(len);
	}

	[[nodiscard]] inline const char* CStr() const
	{
#if (ION_ASSERTS_ENABLED == 1)
		mIsUsed = true;
#endif
		return mData.Data();
	}

	[[nodiscard]] size_t Length() const { return mUsedSpace; }

	~StackStringFormatter()
	{
#if (ION_ASSERTS_ENABLED == 1)
		ION_ASSERT(mIsUsed, "String formatter result not used");
#endif
	}

private:
	bool FormatInternal(int written, const char* format, int& newCapacity)
	{
#if (ION_ASSERTS_ENABLED == 1)
		ION_ASSERT(!mIsUsed, "Can't format string when it's already used");
#endif
		ION_ASSERT(written != -1, "Formatting error for string '" << format << "'");
		if (written < int(mData.Size()) - 1)
		{
			return true;
		}

		if (newCapacity == 0)
		{
			newCapacity = ion::Max(int(mData.Size()), int(strlen(format))) * 2 + 1;	 // Minimum required capacity
		}
		else
		{
			newCapacity = (int(mData.Size())) * 2 + 1;	// Aggressively find capacity
		}
		if (newCapacity > MaxCapacity)
		{
			return true;
		}
		mData.Clear();	// Prevent reallocation to copy contents
		mData.ResizeFast(newCapacity, newCapacity);
		return false;
	}

	ion::SmallVector<char, StackCapacity> mData;
#if (ION_ASSERTS_ENABLED == 1)
	mutable bool mIsUsed = false;
#endif
	size_t mUsedSpace = 0;
};
}  // namespace ion
