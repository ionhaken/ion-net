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

#include <ion/byte/ByteWriter.h>

namespace ion
{
namespace serialization
{
struct Tag
{
	size_t mIndex;
};
}  // namespace serialization

// A view to container that will be accessed by byte writer or byte reader.
// View will resize container to written size after end of life span
template <typename T>
class ByteBufferView : public ByteBufferBase
{
public:
	ION_CLASS_NON_COPYABLE(ByteBufferView);

	ByteBufferView(T& buffer) : mBuffer(buffer)
	{
		SetBuffer(mBuffer.Data(), mBuffer.Size());
		Rewind(mBuffer.Size());
	}

	~ByteBufferView() { mBuffer.ResizeFast(Size()); }

protected:
	void SetSize(ByteSizeType size) final { Reserve(size); }

private:
	inline void Reserve(ByteSizeType size)
	{
		mBuffer.ResizeFast(size);
		SetBuffer(mBuffer.Data(), size);
	}

	T& mBuffer;
};

template <>
class ByteBufferView<byte*> : public ByteBufferBase
{
public:
	ION_CLASS_NON_COPYABLE(ByteBufferView<byte*>);

	ByteBufferView(byte* buffer, size_t size) : mBuffer(buffer)
	{
		SetBuffer(mBuffer, SafeRangeCast<ByteSizeType>(size));
		Rewind(0);
	}

	~ByteBufferView() {}

protected:
	void SetSize(ByteSizeType) final { ION_ASSERT(false, "Out of buffer"); }

private:
	byte* mBuffer;
};

// A temporary byte container that can be written and read. If data is expected to stay in memory, it's better not to use ByteBuffer, but
// just have view to the data using ByteBufferView when needed
template <size_t SmallBufferSize = 0, typename Allocator = ion::GlobalAllocator<ion::u8>>
class ByteBuffer : public ByteBufferBase
{
public:
	ION_CLASS_NON_ASSIGNABLE(ByteBuffer);

	ByteBuffer()
	{
		if constexpr (SmallBufferSize > 0)
		{
			mBuffer.ResizeFastKeepCapacity(SmallBufferSize);
		}
		SetBuffer(mBuffer.Data(), SmallBufferSize);
	}

	template <typename Resource>
	ByteBuffer(Resource* resource) : mBuffer(resource)
	{
		if constexpr (SmallBufferSize > 0)
		{
			mBuffer.ResizeFastKeepCapacity(SmallBufferSize);
		}
		SetBuffer(mBuffer.Data(), SmallBufferSize);
	}

	explicit ByteBuffer(ByteSizeType numBytes)
	{
		mBuffer.ResizeFast(numBytes);
		SetBuffer(mBuffer.Data(), numBytes);
	}

	template <typename Resource>
	ByteBuffer(Resource* resource, ByteSizeType numBytes) : mBuffer(resource)
	{
		mBuffer.ResizeFast(numBytes);
		SetBuffer(mBuffer.Data(), numBytes);
	}

	ByteBuffer(const ByteBuffer& other) : mBuffer(other.mBuffer)
	{
		if (other.mIsExternalData)
		{
			OverrideData(other.mDataPtr, other.mCapacity, other.mNumberOfBytesUsed);
		}
		else
		{
			SetBuffer(mBuffer.Data(), mBuffer.Size());
			mNumberOfBytesUsed = other.mNumberOfBytesUsed;
		}
	}

	ByteBuffer& operator=(ByteBuffer&& other)
	{
		if (other.mIsExternalData)
		{
			OverrideData(other.mDataPtr, other.mCapacity, other.mNumberOfBytesUsed);
		}
		else
		{
			mBuffer = std::move(other.mBuffer);
			SetBuffer(mBuffer.Data(), mBuffer.Size());
			mNumberOfBytesUsed = other.mNumberOfBytesUsed;
		}
		return *this;
	}

	ByteBuffer(ByteBuffer&& other) : mBuffer(std::move(other.mBuffer))
	{
		if (other.mIsExternalData)
		{
			OverrideData(other.mDataPtr, other.mCapacity, other.mNumberOfBytesUsed);
		}
		else
		{
			SetBuffer(mBuffer.Data(), mBuffer.Size());
			mNumberOfBytesUsed = other.mNumberOfBytesUsed;
		};
	}

	inline void Reserve(ByteSizeType size)
	{
		mBuffer.ResizeFast(size);
		SetBuffer(mBuffer.Data(), mBuffer.Size());
	}

protected:
	void SetSize(ByteSizeType size) final { Reserve(size); }

	void Clear()
	{
		mBuffer.Clear();
		mBuffer.ShrinkToFit();
		SetBuffer(nullptr, 0);
	}

private:
	ion::Vector<ion::u8, Allocator, ByteSizeType, SmallBufferSize> mBuffer;
};

}  // namespace ion
