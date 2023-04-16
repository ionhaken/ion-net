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

#include <utility>

namespace ion
{
template <typename TValue, UInt TSize>
class StaticVector
{
public:
	inline StaticVector() {}

	explicit StaticVector(size_t s) { Resize(s); }

	inline ~StaticVector() { Clear(); }

	inline StaticVector(const StaticVector& other)
	{
		while (mNumElements < other.mNumElements)
		{
			Add(other[mNumElements]);
		}
	}

	inline StaticVector(StaticVector&& other)
	{
		while (mNumElements < other.mNumElements)
		{
			Add(std::move(other[mNumElements]));
		}
		other.Clear();
	}

	inline StaticVector& operator=(const StaticVector& other)
	{
		Clear();
		while (mNumElements < other.mNumElements)
		{
			Add(other[mNumElements]);
		}
		return *this;
	}

	inline StaticVector& operator=(StaticVector&& other)
	{
		Clear();
		while (mNumElements < other.mNumElements)
		{
			Add(std::move(other[mNumElements]));
		}
		other.Clear();
		return *this;
	}

	// #TODO: Move to algorithms
	inline void Remove(std::size_t index)
	{
		ION_ASSERT(index < mNumElements, "Index out of range");
		if (index != mNumElements - 1)
		{
			std::swap(mData[index], mData[mNumElements - 1]);
		}
		Pop();
	}

	void Add()
	{
		ION_ASSERT(mNumElements < TSize, "Index out of range");
		mData.Insert(mNumElements);
		mNumElements++;
	}

	void Add(const TValue& value)
	{
		ION_ASSERT(mNumElements < TSize, "Index out of range");
		mData.Insert(mNumElements, value);
		mNumElements++;
	}

	void Add(TValue&& value)
	{
		ION_ASSERT(mNumElements < TSize, "Index out of range");
		mData.Insert(mNumElements, value);
		mNumElements++;
	}

	template <typename... Args>
	void Add(const TValue& value, Args&&... args)
	{
		ION_ASSERT(mNumElements < TSize, "Index out of range");
		mData.Insert(mNumElements, value, std::forward<Args>(args)...);
		mNumElements++;
	}

	template <typename... Args>
	void Add(Args&&... args)
	{
		ION_ASSERT(mNumElements < TSize, "Index out of range");
		mData.Insert(mNumElements, std::forward<Args>(args)...);
		mNumElements++;
	}

	inline void Pop()
	{
		ION_ASSERT(mNumElements, "Container is already empty");
		mNumElements--;
		mData.Erase(mNumElements);
	}

	inline TValue& operator[](std::size_t index)
	{
		ION_ASSERT(index < mNumElements, "Index out of range");
		return mData[index];
	}

	inline const TValue& operator[](std::size_t index) const
	{
		ION_ASSERT(index < mNumElements, "Index out of range");
		return mData[index];
	}

	inline TValue& Back() { return mData[mNumElements - 1]; }

	inline const TValue& Back() const { return mData[mNumElements - 1]; }

	inline TValue& Front() { return mData[0]; }

	inline const TValue& Front() const { return mData[0]; }

	void Clear()
	{
		if constexpr (std::is_trivially_destructible<TValue>::value)
		{
			mData.Clear();
			mNumElements = 0;
		}
		else
		{
			while (mNumElements)
			{
				Pop();
			}
		}
	}

	inline size_t Size() const { return mNumElements; }

	inline size_t Capacity() const { return TSize; }

	inline bool IsEmpty() const { return mNumElements == 0; }

	inline bool IsFull() const { return mNumElements == TSize; }

	inline void Resize(size_t newSize)
	{
		while (mNumElements > newSize)
		{
			Pop();
		}
		while (mNumElements < newSize)
		{
			Add();
		}
	}

	inline TValue* Data() { return mData.Data(); }

	using Iterator = TValue*;			  // typename Array<TValue, TSize>::Iterator;
	using ConstIterator = const TValue*;  // typename Array<TValue, TSize>::ConstIterator;

	Iterator Begin() { return mData.Begin(); }
	ConstIterator Begin() const { return mData.Begin(); }
	Iterator begin() { return mData.Begin(); }
	ConstIterator begin() const { return mData.Begin(); }

	Iterator End() { return mData.Begin() + mNumElements; }
	ConstIterator End() const { return mData.Begin() + mNumElements; }
	Iterator end() { return mData.Begin() + mNumElements; }
	ConstIterator end() const { return mData.Begin() + mNumElements; }

	void Reserve(size_t s) { ION_ASSERT(s <= TSize, "Invalid size"); }

	Iterator Erase(Iterator iter)
	{
		size_t pos = iter - Begin();
		ION_ASSERT(mNumElements > 0, "Erasing from empty container");
		if (pos == mNumElements - 1)
		{
			Pop();
		}
		else
		{
			mData.EraseFillIn(pos, pos + 1, mNumElements);
			mNumElements--;
		}
		return mData.Begin() + pos;
	}

private:
	UInt mNumElements = 0;
	ion::StaticBuffer<TValue, TSize> mData;
};
}  // namespace ion
