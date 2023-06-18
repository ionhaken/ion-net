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
#include <ion/byte/ByteReader.h>

namespace ion
{

// Writes data to memory address with no bounds checking
class ByteWriterUnsafe
{
	friend class ByteWriter;
	friend class BufferWriterUnsafe;

public:
	ION_CLASS_NON_COPYABLE(ByteWriterUnsafe);

	ByteWriterUnsafe(byte* start) : ByteWriterUnsafe(start, start) {}

	ByteWriterUnsafe(byte* start, byte* pos) : mPos(pos), mStart(start) { ION_ASSERT(mStart <= mPos, "Invalid buffer"); }

	ION_FORCE_INLINE size_t NumBytesUsed() const { return size_t(mPos - mStart); }

	ION_FORCE_INLINE bool IsValid() const { return mStart != nullptr; }

	ByteWriterUnsafe(ByteWriterUnsafe&& other) noexcept : mPos(other.mPos), mStart(other.mStart)
	{
		other.mPos = nullptr;
		other.mStart = nullptr;
	}

	ByteWriterUnsafe& operator=(ByteWriterUnsafe&& other) noexcept
	{
		mStart = other.mStart;
		mPos = other.mPos;
		other.mStart = nullptr;
		other.mPos = nullptr;
		return *this;
	}

	// Requests writable block from buffer. Buffer must be aligned correctly
	template <typename T>
	[[nodiscard]] ION_FORCE_INLINE T& Write()
	{
		auto* p = ion::AssumeAligned(reinterpret_cast<T*>(mPos));
		mPos += sizeof(T);
		return *p;
	}

	// Requests writable array block from buffer. Buffer must be aligned correctly
	template <typename T>
	[[nodiscard]] ION_FORCE_INLINE T& WriteArray(size_t len)
	{
		auto* p = ion::AssumeAligned(reinterpret_cast<T*>(mPos));
		mPos += sizeof(T) * len;
		return *p;
	}

	ION_FORCE_INLINE void WriteArray(const u8* ION_RESTRICT data, size_t len)
	{
		ION_ASSERT((mPos + len < data) || (data + len < mPos), "Buffer aliasing");
		memcpy(mPos, data, len);
		mPos += len;
	}

	template <typename T>
	ION_FORCE_INLINE void Write(const T& data)
	{
		WriteArray(reinterpret_cast<const u8*>(&data), sizeof(T));
	}

	// Do writing via serialization::Serialize()
	template <typename T>
	inline bool Process(const T& t);

	template <typename Callback>
	size_t WriteDirectly(size_t maxLen, Callback&& callback)
	{
		size_t numWritten = callback(mPos, mPos + maxLen);
		mPos += numWritten;
		return numWritten;
	}

protected:
	byte* mPos;
	byte* mStart;
};

// Writes data to buffer with no bounds checking
class BufferWriterUnsafe
{
	ION_CLASS_NON_COPYABLE(BufferWriterUnsafe);

public:
	BufferWriterUnsafe(ByteBufferBase& ud) : mParent(ud.Begin() + ud.Size()), mSource(&ud) { mSource->OnStartWriting(); }

	BufferWriterUnsafe(BufferWriterUnsafe&& other) noexcept : mParent(std::move(other.mParent)), mSource(std::move(other.mSource))
	{
		other.mSource = nullptr;
	}

	BufferWriterUnsafe& operator=(BufferWriterUnsafe&& other) noexcept
	{
		mParent = std::move(other.mParent);
		mSource = other.mSource;
		return *this;
	}

	bool EnsureCapacity(ByteSizeType bytesAvailable)
	{
		if (Available() < bytesAvailable)
		{
			return Extend(bytesAvailable);
		}
		return true;
	}

	~BufferWriterUnsafe()
	{
		if (mSource)
		{
			mSource->OnStopWriting(mParent.mPos);
		}
	}

	template <typename T>
	ION_FORCE_INLINE void Write(const T& data)
	{
		mParent.Write(data);
	}

	ION_FORCE_INLINE void WriteArray(const u8* ION_RESTRICT data, size_t len) { mParent.WriteArray(data, len); }


	[[nodiscard]] inline ByteSizeType Available() const
	{
		ION_ASSERT(mSource->Capacity() >= mSource->Size(), "Invalid buffer");
		return static_cast<ByteSizeType>(mSource->Capacity() - mSource->Size());
	}

	template <typename T>
	inline bool Process(const T& t);

	template <typename Callback>
	size_t WriteDirectly(Callback&& callback)
	{
		size_t numWritten = mParent.WriteDirectly(Available(), std::forward<Callback&&>(callback));
		return numWritten;
	}

	void Flush() 
	{
		mSource->OnStopWriting(mParent.mPos);
		mSource = nullptr;
	}

	ION_FORCE_INLINE size_t NumBytesUsed() const { return mParent.NumBytesUsed(); }

private:
	bool Extend(ByteSizeType newAvailableCount);
	ByteWriterUnsafe mParent;
	ByteBufferBase* mSource;
};

// Writes data to byte buffer.
// To write data to a custom container please provide data inside ByteBufferView.
class ByteWriter
{
public:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(ByteWriter);

	ByteWriter(ByteBufferBase& ud) : mParent(ud.Begin() + ud.Size()), mEnd(ud.Begin() + ud.Capacity()), mSource(ud)
	{
		ION_ASSERT(mParent.mStart <= mParent.mPos, "Invalid mBuffer");
		ION_ASSERT(mEnd >= mParent.mPos, "Invalid mBuffer");
		mSource.OnStartWriting();
	}

	~ByteWriter()
	{
		ION_ASSERT(mEnd >= mParent.mPos, "Invalid mBuffer");
		mSource.OnStopWriting(mParent.mPos);
	}

	// Requests writable block from buffer. Buffer must be aligned correctly
	template <typename T>
	[[nodiscard]] inline T& WriteKeepCapacity()
	{
		ION_ASSERT(mParent.mPos + sizeof(T) <= mEnd, "Out of mBuffer");
		return mParent.Write<T>();
	}

	// Requests writable array block from buffer. Buffer must be aligned correctly
	template <typename T>
	[[nodiscard]] ION_FORCE_INLINE T& WriteArrayKeepCapacity(size_t len)
	{
		ION_ASSERT(mParent.mPos + sizeof(T) * len <= mEnd, "Out of Buffer");
		return mParent.WriteArray<T>(len);
	}

	bool Copy(ByteReader& src);

	inline void WriteArrayKeepCapacity(const u8* data, ByteSizeType len)
	{
		ION_ASSERT(mParent.mPos + len <= mEnd, "Out of buffer;Count=" << len << ";Available=" << Available());
		mParent.WriteArray(data, len);
	}

	// Writes array of bytes.
	// extraAllocation: Number of bytes allocated for buffer in addition to writed data.
	//					NOTE: this is added ONLY if write runs out of capacity.
	inline void WriteArray(const u8* data, ByteSizeType len, ByteSizeType extraAllocation = 0)
	{
		if (Available() < len)
		{
			if (!Extend(extraAllocation + len))
			{
				return;
			}
		}
		WriteArrayKeepCapacity(data, len);
	}

	template <typename T>
	inline void Write(const T& data)
	{
		WriteArray(reinterpret_cast<const u8*>(&data), sizeof(T), 0);
	}

	template <typename T>
	inline void WriteKeepCapacity(const T& data)
	{
		WriteArrayKeepCapacity(reinterpret_cast<const u8*>(&data), sizeof(T));
	}

	[[nodiscard]] inline ByteSizeType Available() const
	{
		ION_ASSERT(mEnd >= mParent.mPos, "Invalid buffer");
		return static_cast<ByteSizeType>(mEnd - mParent.mPos);
	}

	bool EnsureCapacity(ByteSizeType bytesAvailable)
	{
		if (Available() < bytesAvailable)
		{
			return Extend(bytesAvailable);
		}
		ION_ASSERT(mEnd >= mParent.mPos, "Invalid buffer");
		return true;
	}

	// Do writing via serialization::Serialize()
	template <typename T>
	inline bool Process(const T& t);

	ION_FORCE_INLINE size_t NumBytesUsed() const { return mParent.NumBytesUsed(); }

	template <typename Callback>
	size_t WriteDirectly(Callback&& callback)
	{
		size_t numWritten = mParent.WriteDirectly(Available(), std::forward<Callback&&>(callback));
		ION_ASSERT(mEnd >= mParent.mPos, "Out of buffer");
		return numWritten;
	}

private:
	ION_NO_INLINE bool Extend(ByteSizeType newAvailableCount);

	ByteWriterUnsafe mParent;
	u8* mEnd;
	ByteBufferBase& mSource;
};
}  // namespace ion
