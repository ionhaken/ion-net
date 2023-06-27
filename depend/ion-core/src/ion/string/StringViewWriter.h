#pragma once

#include <ion/string/StringWriter.h>
#include <ion/string/StringSerialization.h>

namespace ion
{
template <typename Buffer = ion::String>
class StringViewWriter
{
public:
	StringViewWriter(Buffer& buffer) : mString(buffer), mWritePos(buffer.Length()) {}

	~StringViewWriter() { mString.Resize(mWritePos); }

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
		ion::StringWriter writer(&mString.Data()[mWritePos], maxLen);
		mWritePos += ion::serialization::Serialize(value, writer);
	}

	Buffer& mString;
	size_t mWritePos;
};

struct EditableStringView
{
	char* mData;
	size_t len;
};

template <>
class StringViewWriter<EditableStringView>
{
public:
	StringViewWriter<EditableStringView>(EditableStringView stringSpan)
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
inline char* StringViewWriter<EditableStringView>::Write(const T& data)
{
	ion::StringWriter writer(mWritePosition, Available());
	auto count = ion::serialization::Serialize(data, writer);
	mWritePosition += count;
	return mWritePosition;
}

template <>
inline char* StringViewWriter<EditableStringView>::Write(const StringView& string)
{
	ion::StringWriter writer(mWritePosition, Available());
	auto count = ion::serialization::Serialize(string, writer);
	mWritePosition += count;
	return mWritePosition;
}

inline char* StringViewWriter<EditableStringView>::Write(const char* string) { return Write(StringView(string, ion::StringLen(string))); }

}  // namespace ion

