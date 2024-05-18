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
#include <ion/container/Sort.h>

namespace ion
{
template <typename T, typename Allocator = ion::GlobalAllocator<T>>
class IdPool
{
public:
	constexpr IdPool() : mTotalItems(0) {}

	void Reset()
	{
		mFreeItems.Clear();
		mTotalItems = 0;
	}

	template <typename Resource>
	explicit IdPool(Resource* resource) : mFreeItems(resource), mTotalItems(0)
	{
	}

	constexpr IdPool(const IdPool& other) : mFreeItems(other.mFreeItems), mTotalItems(other.mTotalItems) {}

	constexpr IdPool(IdPool&& other) : mFreeItems(std::move(other.mFreeItems)), mTotalItems(other.mTotalItems) {}

	constexpr IdPool& operator=(const IdPool& other)
	{
		mFreeItems = other.mFreeItems;
		mTotalItems = other.mTotalItems;
		return *this;
	}

	void SortFree() { std::sort(mFreeItems.Begin(), mFreeItems.End()); }

	constexpr IdPool& operator=(IdPool&& other)
	{
		mFreeItems = std::move(other.mFreeItems);
		mTotalItems = other.mTotalItems;
		return *this;
	}

	T Reserve()
	{
		T val;
		if (mFreeItems.IsEmpty())
		{
			val = mTotalItems;
			ION_ASSERT(static_cast<T>(mTotalItems + 1) != 0, "Out of id space");
			mTotalItems++;
		}
		else
		{
			val = mFreeItems.Back();
			mFreeItems.Pop();
		}
		return val;
	}

	T Max() const { return mTotalItems; }

	T Size() const { return mTotalItems - static_cast<T>(mFreeItems.Size()); }

	// Remove excess free items
	void Shrink()
	{
		ion::Sort(mFreeItems.Begin(), mFreeItems.End());
		while (!mFreeItems.IsEmpty() && mFreeItems.Back() + 1 == mTotalItems)
		{
			mFreeItems.Pop();
			mTotalItems--;
		}
	}

	bool HasFreeItems() const { return !mFreeItems.IsEmpty(); }

	void Free(const T& index)
	{
#if ION_BUILD_DEBUG
		ION_ASSERT(index < mTotalItems, "Invalid index");
		ION_ASSERT(ion::Find(mFreeItems, index) == mFreeItems.End(), "Duplicate free:" << index);
#endif
		mFreeItems.Add(index);
	}

	ion::Vector<T> CreateUsedIdList()
	{
		ion::Vector<T> list;
		list.Reserve(mTotalItems);
		T freeIndex = 0;
		T pos = 0;
		T nextUsed;
		while (pos < mTotalItems)
		{
			nextUsed = freeIndex < mFreeItems.Size() ? mFreeItems[freeIndex] : mTotalItems;
			for (T i = pos; i < nextUsed; i++)
			{
				list.Add(i);
			}
			freeIndex++;
			pos = nextUsed + 1;
		}
		return list;
	}
	class ConstIterator
	{
	public:
		ConstIterator(T aPosition, T aTotalItems, ion::Vector<T>& someFreeItems)
		  : mTotalItems(aTotalItems), mPosition(aPosition), mFreeIndex(0), mFreeItems(someFreeItems)
		{
		}

		ConstIterator(T aTotalItems, ion::Vector<T>& someFreeItems) : mTotalItems(aTotalItems), mFreeIndex(0), mFreeItems(someFreeItems)
		{
			mPosition = 0;
			FindNextUsed();
			FindPosition();
		}

		inline ConstIterator operator++()
		{
			ConstIterator i = *this;
			mPosition = mPosition < mNextUsed ? mPosition + 1 : 0;
			/* if (mPosition > mNextUsed)
			{
				do
				{
					mFreeIndex++;
					mPosition = mNextUsed + 1;
					findNextUsed();
				} while (mPosition < mNextUsed);
			}		*/
			return i;
		}

		void FindPosition()
		{
			while (mPosition < mTotalItems && mPosition >= mNextUsed)
			{
				mFreeIndex++;
				mPosition = mNextUsed + 1;
				FindNextUsed();
			}
		}

		const T& operator*() { return static_cast<T>(mPosition); }
		const T* operator->() { return static_cast<T*>(&mPosition); }
		bool operator==(const ConstIterator& rhs) { return mPosition == rhs.mPosition; }
		bool operator!=(const ConstIterator& rhs) { return mPosition != rhs.mPosition; }

	private:
		void FindNextUsed() { mNextUsed = mFreeIndex < mFreeItems.Size() ? mFreeItems[mFreeIndex] : mTotalItems; }

		ion::Vector<T, Allocator>& mFreeItems;
		const T mTotalItems;
		T mPosition;
		T mFreeIndex;
		T mNextUsed;
	};

	ConstIterator Begin()
	{
		// mFreeItems.SortSimpleType();
		return ConstIterator(mTotalItems, mFreeItems);
	}

	ConstIterator End()
	{
		// mFreeItems.SortSimpleType();
		return ConstIterator(mTotalItems, mTotalItems, mFreeItems);
	}

private:
	ion::Vector<T, Allocator> mFreeItems;
	T mTotalItems;
};

}  // namespace ion
