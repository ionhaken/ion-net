#pragma once

#include <ion/container/Vector.h>

#include <cstdio>

namespace ion
{

template <size_t StackCapacity, int MaxCapacity = 256 * 1024>
class StackStringFormatter
{
public:
	ION_CLASS_NON_COPYABLE(StackStringFormatter);

	StackStringFormatter() { mData.Resize(StackCapacity); }

	template <typename... Args>
	int Format(const char* format, Args&&... args)
	{
		int written;
		int newCapacity = 0;
		do
		{
			written = snprintf(mData.Data(), mData.Size(), format, std::forward<Args>(args)...);
		} while (!FormatInternal(written, format, newCapacity));

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
		return written;
	}

	int Format(const char* format) 
	{ 
		size_t len = strlen(format);
		mData.Clear();
		mData.ResizeFast(len + 1, len + 1);	
		StringCopy(mData.Data(), len + 1, format);
		return int(len);
	}

	inline const char* CStr() const
	{
#if (ION_ASSERTS_ENABLED == 1)
		mIsUsed = true;
#endif
		return mData.Data();
	}

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
};
}  // namespace ion
