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
#include <ion/util/Hasher.h>
#include <ion/memory/GlobalAllocator.h>
#include <ion/string/StringView.h>
#include <ion/string/StringFormatter.h>
#include <ion/util/Math.h>

#include <string>
#if ION_PLATFORM_MICROSOFT
	#include <memory>
#endif

namespace ion
{
class StringView;

template <typename TAllocator = GlobalAllocator<char>>
class BasicString
{
public:
	using Allocator = TAllocator;
	using NativeType = std::basic_string<char, std::char_traits<char>, Allocator>;
	using ElementType = typename NativeType::value_type;

	BasicString(const char* aString) : mImpl(aString) {}

	BasicString(const char* aString, size_t length) : mImpl(aString, length) {}

	void operator=(const char* str) { mImpl = str; }

/*/ #if ION_PLATFORM_LINUX
	template <typename Resource>
	BasicString(Resource*) : mImpl()
	{
	}

	template <typename Resource>
	BasicString(Resource*, const char* aString) : mImpl(aString)
	{
	}
#else*/
	template <typename Resource>
	BasicString(Resource* resource) : mImpl(resource)
	{
	}

	template <typename Resource>
	BasicString(Resource* resource, const char* aString) : mImpl(resource)
	{
		mImpl = aString;
	}
//#endif

	void Resize(size_t len) { mImpl.resize(len); }

	BasicString() {}
	~BasicString() {}

	template <size_t charCount>
	void StrCopy(char (&output)[charCount], const char* pSrc)
	{
		strncpy(output, pSrc, charCount);
		output[charCount - 1] = 0;
	}

	template <typename Other>
	bool operator==(const BasicString<Other>& other) const
	{
		return Native().compare(other.Native()) == 0;
	}

	bool operator==(const char* other) const { return Native().compare(other) == 0; }

	char operator[](size_t index) const { return Native()[index]; }

	[[nodiscard]] const char* CStr() const { return mImpl.c_str(); }

	[[nodiscard]] char* Data() { return &mImpl.front(); }
	[[nodiscard]] const char* Data() const { return mImpl.data(); }

	[[nodiscard]] ion::BasicString<> SubStr(size_t pos = 0, size_t len = std::string::npos) const
	{
		if (pos < mImpl.size())
		{
			return mImpl.substr(pos, len).c_str();
		}
		return "";
	}

	/*template <typename OtherString>
	[[nodiscard]] constexpr int Compare(const OtherString& other) const
	{
		return mImpl.compare(other.CStr());
	}*/

	template <class ContainerT>
	void Tokenize(ContainerT& tokens) const
	{
		Tokenize(tokens, " ", false);
	}

	template <class ContainerT>
	void Tokenize(ContainerT& tokens, const char* delimiters, bool trimEmpty) const;

	size_t Length() const { return mImpl.length(); }

	using Iterator = std::string::iterator;
	using ConstIterator = std::string::const_iterator;

	Iterator Begin() { return mImpl.begin(); }
	ConstIterator Begin() const { return mImpl.begin(); }
	Iterator End() { return mImpl.end(); }
	ConstIterator End() const { return mImpl.end(); }
	[[nodiscard]] bool IsEmpty() const { return Native().empty(); }

	[[nodiscard]] size_t Find(const char* str) { return Native().find(str); }

	[[nodiscard]] size_t FindFirstOf(const char c, size_t pos = 0) const { return Native().find_first_of(c, pos); }

	[[nodiscard]] size_t FindLastOf(const char c, size_t pos = std::string::npos) const { return Native().find_last_of(c, pos); }

	void Reserve(size_t s) { Native().reserve(s); }

	[[nodiscard]] size_t Capacity() const { return Native().capacity(); }

	template <typename... Args>
	int Format(Args&&... args);

	NativeType& Native() { return mImpl; }

	const NativeType& Native() const { return mImpl; }

private:
	NativeType mImpl;
};

}  // namespace ion
#include <ion/string/StackString.h>
namespace ion
{
template <size_t N>
class StackString;

class String : public BasicString<>
{
public:
	String(const StringView& view) : BasicString<>(view.CStr(), view.Length()) {}
	String(const wchar_t* aString);

	StringView View() const { return ion::StringView(Data(), Length()); }

	template <size_t N>
	String(StackString<N>& string);

	String() {}
	~String() {}

	String(const NativeType& native) { Native() = native; }

	void Replace(size_t index, const char c) { Native().replace(index, 1, 1, c); }

	String(const char* aString) : BasicString<>(aString) {}

	String(const char* aString, size_t length) : BasicString<>(aString, length) {}

	operator std::string() const { return std::string(Native().c_str()); }

	ion::String operator+(const ion::String& other)
	{
		NativeType str = Native() + other.Native();
		return ion::String(str.c_str());
	}

	ion::String& operator+=(const ion::String& other)
	{
		Native() += other.Data();
		return *this;
	}


	template <size_t charCount>
	ion::String& operator+(const char (&other)[charCount])
	{
		Native() += other;
		return *this;
	}
	size_t Hash() const
	{
#if ION_PLATFORM_LINUX
		return ion::HashDJB2(CStr());  // #TODO: Fix build
#else
		return std::hash<NativeType>{}(Native());
#endif
	}

	constexpr bool operator==(const String& other) const { return Native().compare(other.Native()) == 0; }

	template <size_t N>
	constexpr bool operator==(const StackString<N>& other) const
	{
		return Native().compare(other->Native()) == 0;
	}

	int Compare(const String& other) const { return Native().compare(other.Native()); }

	/*bool operator==(const char* other) const
	{
		return Native().compare(other) == 0;
	}*/

#if ION_PLATFORM_MICROSOFT
	std::unique_ptr<wchar_t[]> WStr() const;
	std::wstring WideString() const;
#endif
};

// #TODO: Need to specialize string hashes case by case
template <>
inline size_t Hasher<ion::String>::operator()(const ion::String& key) const
{
	return ion::HashDJB2(key.CStr());
}

template <size_t N>
String::String(ion::StackString<N>& string) : BasicString<>(string.CStr())
{
}

template <typename TAllocator>
template <class ContainerT>
void BasicString<TAllocator>::Tokenize(ContainerT& tokens, const char* delimiters, bool trimEmpty) const
{
	typename NativeType::size_type pos, lastPos = 0;

	while (true)
	{
		pos = mImpl.find_first_of(delimiters, lastPos);
		if (pos == std::string::npos)
		{
			pos = mImpl.length();

			if (pos != lastPos || !trimEmpty)
			{
				tokens.Add(String(mImpl.data() + lastPos, (size_t)pos - lastPos));
			}
			break;
		}
		else
		{
			if (pos != lastPos || !trimEmpty)
			{
				tokens.Add(String(mImpl.data() + lastPos, (size_t)pos - lastPos));
			}
		}

		lastPos = pos + 1;
	}
}

template <typename TAllocator>
template <typename... Args>
int BasicString<TAllocator>::Format(Args&&... args)
{
	StackStringFormatter<32> tmp;	 // Parameters may have reference to local string, so we need to use temporary container.
	int written;
	{
		written = tmp.Format(std::forward<Args>(args)...);
	}
	Native() = tmp.CStr();
	return written;
}


namespace serialization
{
template <>
inline void Deserialize(ion::String& dst, StringReader& reader)
{
	dst = reader.Data();
}

template <>
inline ion::UInt Serialize(const ion::String& data, StringWriter& writer)
{
	auto u = ion::UInt(ion::StringCopy(writer.Data(), ion::Min(writer.Available(), data.Length()+1), data.CStr()));
	writer.Skip(u);
	return u;
}


}  // namespace serialization

}  // namespace ion
