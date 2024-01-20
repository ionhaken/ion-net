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
#include <ion/container/StaticRawBuffer.h>
#include <ion/container/Algorithm.h>
#include <ion/container/Deque.h>
#include <ion/util/SafeRangeCast.h>

namespace ion
{
template <typename T, size_t TSize, typename CountType = uint32_t>
class RingBuffer
{
public:
	RingBuffer() : mNumElems(0), mReadPos(0) { static_assert(TSize > 0, "Ring buffer size cannot be 0"); }

	~RingBuffer() { Clear(); }

	RingBuffer(const RingBuffer& other) : mNumElems(other.mNumElems), mReadPos(other.mReadPos)
	{
		for (CountType pos = 0; pos < mNumElems; ++pos)
		{
			auto idx = Mod(mReadPos + pos);
			mBuffer.Insert(idx, other.mBuffer[idx]);
		}
	}

	RingBuffer(const RingBuffer&& other) = delete;
	RingBuffer& operator=(RingBuffer&& other) = delete;

	RingBuffer& operator=(const RingBuffer& other)
	{
		Clear();
		mNumElems = other.mNumElems;
		mReadPos = other.mReadPos;
		for (CountType pos = 0; pos < other.mNumElems; ++pos)
		{
			auto idx = Mod(mReadPos + pos);
			mBuffer.Insert(idx, other.mBuffer[idx]);
		}
		return *this;
	}

	[[nodiscard]] constexpr size_t Capacity() const { return TSize; }

	[[nodiscard]] constexpr const T& operator[](size_t pos) const
	{
		ION_ASSERT_FMT_IMMEDIATE(pos < TSize, "Out of bounds");
		return mBuffer[Mod(mReadPos + ion::SafeRangeCast<CountType>(pos))];
	}

	inline void Add(const T& val) { PushBack(val); }

	ION_INLINE void PushFront(const T& val)
	{
		ION_ASSERT(mNumElems < TSize, "Buffer overflow");
		if (mReadPos != 0)
		{
			mReadPos--;
		}
		else
		{
			mReadPos = TSize - 1;
		}

		mBuffer.Insert(mReadPos, val);
		mNumElems++;
	}

	ION_INLINE void PushBack(const T& val)
	{
		ION_ASSERT(mNumElems < TSize, "Buffer overflow");
		mBuffer.Insert(Mod(mReadPos + mNumElems), val);
		mNumElems++;
	}

	ION_INLINE void PushBack(T&& val)
	{
		ION_ASSERT(mNumElems < TSize, "Buffer overflow");
		mBuffer.Insert(Mod(mReadPos + mNumElems), val);
		mNumElems++;
	}

	[[nodiscard]] constexpr T& Front() { return mBuffer[mReadPos]; }

	[[nodiscard]] constexpr const T& Front() const { return mBuffer[mReadPos]; }

	[[nodiscard]] constexpr T& Back() { return mBuffer[Mod(mReadPos + mNumElems - 1)]; }

	[[nodiscard]] constexpr const T& Back() const { return mBuffer[Mod(mReadPos + mNumElems - 1)]; }

	ION_INLINE void PopFront()
	{
		ION_ASSERT(mNumElems > 0, "Ring buffer out of data");
		mNumElems--;
		mBuffer.Erase(mReadPos);
		mReadPos++;
		if (mReadPos == TSize)
		{
			mReadPos = 0;
		}
	}

	ION_INLINE void PopBack()
	{
		ION_ASSERT(mNumElems > 0, "Ring buffer out of data");
		mBuffer.Erase(Mod(mReadPos + mNumElems - 1));
		mNumElems--;
	}

	ION_INLINE bool IsEmpty() const { return mNumElems == 0; }

	ION_INLINE bool IsFull() const { return mNumElems == TSize; }

	[[nodiscard]] constexpr size_t Size() const { return mNumElems; }

	void Erase(size_t pos)
	{
		ION_ASSERT(pos < TSize, "Out of bounds");
		const CountType mpos = Mod(mReadPos + ion::SafeRangeCast<uint32_t>(pos));
		if (mReadPos <= mpos)
		{
			ion::MoveForwardByOffset(&mBuffer[mpos] + 1, 1, mpos - mReadPos);
			PopFront();
		}
		else
		{
			const CountType lastPos = Mod(mReadPos + mNumElems - 1);
			ION_ASSERT(lastPos >= mpos, "out of bounds");
			ion::MoveBackByOffset(&mBuffer[mpos], 1, lastPos - mpos);
			PopBack();
		}
	}

	ION_INLINE void Clear()
	{
		if constexpr (std::is_trivially_destructible<T>::value)
		{
			mBuffer.Clear();
			mNumElems = 0;
		}
		else
		{
			while (!IsEmpty())
			{
				PopFront();
			}
		}
	}

	class Iterator
	{
		RingBuffer<T, TSize, CountType>& mRingBuffer;
		CountType mPos;

	public:
		using difference_type = int32_t;
		using value_type = T;
		using pointer = const T*;
		using reference = const T&;
		using iterator_category = std::forward_iterator_tag;

		Iterator(RingBuffer<T, TSize, CountType>& self, CountType pos = 0) : mRingBuffer(self), mPos(pos) {}
		Iterator& operator++()
		{
			mPos = mRingBuffer.Mod(mPos + 1);
			return *this;
		}
		Iterator operator++(int)
		{
			Iterator retval = *this;
			++(*this);
			return retval;
		}
		difference_type operator-(const Iterator& it)
		{
			if (mPos > it.mPos)
			{
				return mPos - it.mPos;
			}
			return mPos + (mRingBuffer.Capacity() - it.mPos);
		}
		Iterator& operator+(CountType count)
		{
			mPos = mRingBuffer.Mod(mPos + count);
			return *this;
		}

		bool operator==(Iterator other) const { return mPos == other.mPos; }
		bool operator!=(Iterator other) const { return !(*this == other); }
		T& operator*() { return mRingBuffer.mBuffer[mPos]; }

		CountType Index() const { return mPos; }
	};
	Iterator Begin() { return {*this, mReadPos}; }
	Iterator End() { return {*this, Mod(mReadPos + mNumElems + 1)}; }

	void Erase(const Iterator& iter)
	{
		ION_ASSERT(mNumElems > 0, "Cannot erase empty buffer");
		if (iter.Index() >= mReadPos)
		{
			Erase(iter.Index() - mReadPos);
		}
		else
		{
			Erase(iter.Index() + (TSize - 1 - mReadPos));
		}
	}

private:
	[[nodiscard]] constexpr CountType Mod(CountType val) const { return val % TSize; }

	ion::StaticBuffer<T, TSize> mBuffer;
	CountType mNumElems;
	CountType mReadPos;
};

template <typename T, size_t TSize, typename TAlloc = GlobalAllocator<T>, typename CountType = uint32_t>
class DynamicRingBuffer
{
public:
	DynamicRingBuffer() {}

	void Erase(size_t pos)
	{
		if (!mRingBuffer.IsEmpty())
		{
			auto size = mRingBuffer.Size();
			if (pos >= size)
			{
				mBackOverflow.Erase(pos - size);
			}
			else
			{
				mRingBuffer.Erase(pos);
			}
		}
		else
		{
			mBackOverflow.Erase(pos);
		}
	}

	[[nodiscard]] constexpr const T& operator[](size_t pos) const
	{
		if (!mRingBuffer.IsEmpty())
		{
			auto size = mRingBuffer.Size();
			if (pos >= size)
			{
				return mBackOverflow[pos - size];
			}
			else
			{
				return mRingBuffer[pos];
			}
		}
		else
		{
			return mBackOverflow[pos];
		}
	}

	void PushFront(const T& val)
	{
		if (!mRingBuffer.IsFull())
		{
			mRingBuffer.PushFront(val);
		}
		else
		{
			mBackOverflow.PushFront(mRingBuffer.Back());
			mRingBuffer.PopBack();
			mRingBuffer.PushFront(val);
		}
	}

	void PushBack(const T& val)
	{
		if (!mRingBuffer.IsFull() && mBackOverflow.IsEmpty())
		{
			mRingBuffer.PushBack(val);
		}
		else
		{
			mBackOverflow.PushBack(val);
		}
	}

	void PushBack(T&& val)
	{
		if (!mRingBuffer.IsFull() && mBackOverflow.IsEmpty())
		{
			mRingBuffer.PushBack(std::move(val));
		}
		else
		{
			mBackOverflow.PushBack(std::move(val));
		}
	}

	[[nodiscard]] constexpr T& Front() { return !mRingBuffer.IsEmpty() ? mRingBuffer.Front() : (mBackOverflow.Front()); }

	[[nodiscard]] constexpr const T& Front() const { return !mRingBuffer.IsEmpty() ? mRingBuffer.Front() : (mBackOverflow.Front()); }

	[[nodiscard]] constexpr T& Back() { return mBackOverflow.IsEmpty() ? mRingBuffer.Back() : mBackOverflow.Back(); }

	[[nodiscard]] constexpr const T& Back() const { return mBackOverflow.IsEmpty() ? mRingBuffer.Back() : mBackOverflow.Back(); }

	void PopBack()
	{
		if (mBackOverflow.IsEmpty())
		{
			mRingBuffer.PopBack();
		}
		else
		{
			mBackOverflow.PopBack();
		}
	}

	[[nodiscard]] constexpr size_t Size() const { return mRingBuffer.Size() + mBackOverflow.Size(); }

	ION_INLINE bool IsEmpty() const { return mRingBuffer.IsEmpty() && mBackOverflow.IsEmpty(); }

	void PopFront()
	{
		if (!mRingBuffer.IsEmpty())
		{
			mRingBuffer.PopFront();
		}
		else
		{
			mBackOverflow.PopFront();
		}
	}

	void Clear()
	{
		mRingBuffer.Clear();
		mBackOverflow.Clear();
	}

private:
	Deque<T, TAlloc> mBackOverflow;
	RingBuffer<T, TSize, CountType> mRingBuffer;
};
}  // namespace ion
