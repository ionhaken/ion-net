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
#include <ion/byte/ByteBufferBase.h>

namespace ion
{
// Reads data from byte mBuffer. To read data from a custom container please use ByteBufferView.
class ION_EXPORT ByteReader
{
public:
	ION_CLASS_NON_COPYABLE(ByteReader);
	ByteReader() noexcept : mBuffer(nullptr), mEnd(nullptr), mStart(nullptr) {}

	// #TODO: Replace with ByteBufferView
	template <typename Data>
	ByteReader(const Data* source, size_t size) noexcept
	  : mBuffer(reinterpret_cast<const ion::u8*>(source)), mEnd(mBuffer + size), mStart(mBuffer)
	{
	}

	template <typename Source>
	ByteReader(const Source& source) noexcept
	  : mBuffer(reinterpret_cast<const ion::u8*>(source.Begin())), mEnd(reinterpret_cast<const ion::u8*>(source.End())), mStart(mBuffer)
	{
	}

	ByteReader(ByteReader&& other) noexcept : mBuffer(other.mBuffer), mEnd(other.mEnd), mStart(other.mStart)
	{
		other.mBuffer = nullptr;
		other.mEnd = nullptr;
		other.mStart = nullptr;
	}

	ByteReader& operator=(ByteReader&& other) noexcept
	{
		ION_ASSERT(this != &other, "Assign self");
		{
			mEnd = other.mEnd;
			mBuffer = other.mBuffer;
			mStart = other.mStart;
			other.mEnd = nullptr;
			other.mBuffer = nullptr;
			other.mStart = nullptr;
		}
		return *this;
	}

	~ByteReader() {}

	[[nodiscard]] ION_FORCE_INLINE ByteSizeType Available() const { return static_cast<ByteSizeType>(mEnd - mBuffer); }

	[[nodiscard]] ION_FORCE_INLINE ByteSizeType ReadOffset() const { return static_cast<ByteSizeType>(mBuffer - mStart); }

	[[nodiscard]] ION_FORCE_INLINE ByteSizeType Size() const { return static_cast<ByteSizeType>(mEnd - mStart); }

	// Returns reference to mBuffer. Faster when operating directly with data, but mBuffer must be aligned correctly
	template <typename T>
	[[nodiscard]] ION_FORCE_INLINE const T& ReadAssumeAvailable()
	{
		ION_ASSERT(Available() >= sizeof(T), "Out of mBuffer: " << Available() << "/" << sizeof(T) << " bytes available");
		const T* p = ion::AssumeAligned(reinterpret_cast<const T*>(mBuffer));
		mBuffer += sizeof(T);
		return *p;
	}

	// Reads data directly to destination. Faster when storing data.
	template <typename T>
	ION_FORCE_INLINE void ReadAssumeAvailable(T& ION_RESTRICT dst)
	{
		ReadAssumeAvailable(reinterpret_cast<u8*>(&dst), sizeof(T));
	}

	[[nodiscard]] bool ReadArray(u8* ION_RESTRICT data, ByteSizeType len)
	{
		if (Available() < len)
		{
			return false;
		}
		ReadAssumeAvailable(data, len);
		return true;
	}

	template <typename T>
	[[nodiscard]] ION_FORCE_INLINE bool Read(T& dst)
	{
		return ReadArray(reinterpret_cast<u8*>(&dst), sizeof(T));
	}

	ION_FORCE_INLINE void ReadAssumeAvailable(u8* ION_RESTRICT data, ByteSizeType len)
	{
		ION_ASSERT(Available() >= len, "Out of mBuffer: " << Available() << "/" << len << " bytes available");
		memcpy(data, mBuffer, len);
		mBuffer += len;
	}

	// Do reading via serialization::Deserialize()
	template <typename T>
	inline bool Process(T& t);

	void SkipBytes(ByteSizeType s) { mBuffer += s; }
	
	template <typename Callback>
	size_t ReadDirectly(Callback&& callback)
	{
		size_t numRead = callback((byte*)mBuffer, (byte*)mEnd); // #TODO: Convert all to byte
		mBuffer += numRead;
		ION_ASSERT(mBuffer <= mEnd, "Out of buffer");
		return numRead;
	}

private:
	const u8* mBuffer;
	const u8* mEnd;
	const u8* mStart;
};
}  // namespace ion
