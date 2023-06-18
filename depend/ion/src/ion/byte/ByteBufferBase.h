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
#include <ion/debug/AccessGuard.h>
#include <ion/container/Vector.h>
#include <ion/container/Array.h>
#include <ion/memory/Memory.h>
#include <ion/util/Math.h>

namespace ion
{
class ByteWriter;
class ByteReader;

using ByteSizeType = uint32_t;

class ION_EXPORT ByteBufferBase
{
	friend class ByteWriter;
	friend class ByteReader;
	friend class BufferWriterUnsafe;

public:
	ByteBufferBase() {}

	virtual ~ByteBufferBase() {}

	constexpr ByteSizeType Capacity() const { return mCapacity; }

	constexpr ByteSizeType Size() const { return mNumberOfBytesUsed; }

	inline void Rewind(ByteSizeType position = 0)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		ION_ASSERT(position <= Capacity(), "Invalid buffer position");
		mNumberOfBytesUsed = position;
	}

	constexpr u8* Begin() { return mDataPtr; }
	constexpr const u8* const Begin() const { return mDataPtr; }
	constexpr u8* End() { return mDataPtr + Size(); }
	constexpr const u8* const End() const { return mDataPtr + Size(); }

protected:
	constexpr void SetBuffer(u8* data, ByteSizeType bytes)
	{
		mDataPtr = data;
		mCapacity = bytes;
	}

	constexpr void OverrideData(u8* data, ByteSizeType bytes, ByteSizeType bitsUsed)
	{
		mIsExternalData = true;
		SetBuffer(data, bytes);
		mNumberOfBytesUsed = bitsUsed/8;
	}

	inline void OnStartWriting() const { ION_ACCESS_GUARD_START_WRITING(mGuard); }

	inline void OnStopWriting(u8* endPos)
	{
		ByteSizeType numberOfBytes = ByteSizeType(endPos - mDataPtr);
		ION_ASSERT(mCapacity >= numberOfBytes, "Buffer overflow");
		mNumberOfBytesUsed = numberOfBytes;
		ION_ACCESS_GUARD_STOP_WRITING(mGuard);
	}
	void Extend(ByteSizeType size)
	{
		if (size > Capacity())
		{
			SetSize((Capacity() + 512) * 2  + size);
		}
		else
		{
			SetSize(Capacity());
		}
	}

protected:
	u8* ION_RESTRICT mDataPtr;
	uint32_t mNumberOfBytesUsed = 0;
	uint32_t mCapacity;
	bool mIsExternalData = false; // #TODO: Remove, this is ByteBufferView property.
	ION_ACCESS_GUARD(mGuard);

private:

	virtual void SetSize(ByteSizeType size) = 0;
};
}  // namespace ion
