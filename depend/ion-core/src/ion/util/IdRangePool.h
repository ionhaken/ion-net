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

#include <ion/container/PriorityQueue.h>
#include <ion/container/UnorderedMap.h>

namespace ion
{
// Id range pool
template <typename T, size_t SmallRangeSize = 4>
class IdRangePool
{
	struct Group
	{
		Group(T anIndex, T aCount) : mIndex(anIndex), mCount(aCount) {}
		bool operator<(const Group& other) const { return mIndex < other.mIndex; }
		T mIndex;
		T mCount;
	};

public:
	IdRangePool() : mTotalItems(0) {}

	T Reserve(const T aCount = 1)
	{
		T val;
		if (!mFreeItems.IsEmpty() && mFreeItems.Top().mCount >= aCount)
		{
			// ION_LOG_INFO("Reserve: Biggest free range=" << mFreeItems.Top().mIndex << "-" << mFreeItems.Top().mIndex +
			// mFreeItems.Top().mCount - 1);
			Group group = mFreeItems.Top();
			mFreeItems.Pop();
			// Use largest free item. Move unused part back to queue
			{
				val = group.mIndex;
				if (group.mCount != aCount)
				{
					val = group.mIndex + (group.mCount - aCount);
					group.mCount -= aCount;
					Free(group.mIndex, group.mCount);
				}
				// ION_LOG_INFO("Reserved range=" << val << "-" << val + aCount-1);
				return val;
			}
			// mSkippedFreeItems.Add(group);
			AddFreeRange(group.mIndex, group.mCount);
		}
		val = mTotalItems;
		mTotalItems += aCount;
		// ION_LOG_INFO("Reserved range=" << val << "-" << val +aCount-1);
		return val;
	}

	void Free(T anIndex, T aCount = 1)
	{
		for (;;)
		{
			// ION_LOG_INFO("FREE " << anIndex << "-" << anIndex+aCount -1);
			ION_ASSERT(aCount > 0 && (aCount + anIndex <= mTotalItems), "Invalid block");
			if (!mFreeItems.IsEmpty())
			{
				// ION_LOG_INFO("Free: Biggest free range=" << mFreeItems.Top().mIndex << "-" << mFreeItems.Top().mIndex +
				// mFreeItems.Top().mCount - 1);
				ION_ASSERT(mFreeItems.Top().mIndex != anIndex, "duplicate index");
				// Check if top free item is sequential
				if (TryMatch(mFreeItems.Top(), anIndex, aCount))
				{
					// ION_LOG_INFO("Merged index " << mFreeItems.Top().mIndex << "-" << mFreeItems.Top().mCount-1);

					// Check is the top free item the last item. If it is, it can be removed from list.
					while (mFreeItems.Top().mIndex + mFreeItems.Top().mCount == mTotalItems)
					{
						mTotalItems -= mFreeItems.Top().mCount;
						mFreeItems.Pop();
						// ION_LOG_INFO("Full range is " << mTotalItems);
						if (mFreeItems.IsEmpty())
						{
							return;
						}
					}
					return;
				}
			}
			auto nextAdjacentGroupIter = mGroupStartIndices.Find(anIndex + aCount);
			if (nextAdjacentGroupIter != mGroupStartIndices.End())
			{
				aCount += nextAdjacentGroupIter->second;
				// ION_LOG_INFO("Merging next range " << anIndex << "-" << anIndex + aCount-1);
				auto iter = mGroupEndIndices.Find(nextAdjacentGroupIter->first + nextAdjacentGroupIter->second);
				ION_ASSERT(iter != mGroupEndIndices.End(), "Invalid index");
				mGroupEndIndices.Erase(iter);
				mGroupStartIndices.Erase(nextAdjacentGroupIter);
				continue;
			}

			auto prevAdjacentGroupIter = mGroupEndIndices.Find(anIndex);
			if (prevAdjacentGroupIter != mGroupEndIndices.End())
			{
				aCount += prevAdjacentGroupIter->second;
				anIndex = prevAdjacentGroupIter->first - prevAdjacentGroupIter->second;
				// ION_LOG_INFO("Merging prev range " << anIndex << "-" << anIndex+aCount-1);
				auto iter = mGroupStartIndices.Find(anIndex);
				ION_ASSERT(iter != mGroupStartIndices.End(), "Invalid index");
				mGroupStartIndices.Erase(iter);
				mGroupEndIndices.Erase(prevAdjacentGroupIter);
				continue;
			}
			break;
		}

		if (anIndex + aCount == mTotalItems)
		{
			mTotalItems -= aCount;
			// ION_LOG_INFO("Full range is " << mTotalItems);
		}
		else
		{
			AddFreeRange(anIndex, aCount);
		}
	}

	T Max() const { return mTotalItems; }

private:
	void AddFreeRange(T index, T count)
	{
		// ION_LOG_INFO("Freeing range " << index << "-" << index + count - 1);
		ION_ASSERT(mFreeItems.IsEmpty() || mFreeItems.Top().mIndex != index, "Duplicate index");
		ION_ASSERT(mGroupStartIndices.Find(index) == mGroupStartIndices.End(), "Duplicate index");
		ION_ASSERT(mGroupEndIndices.Find(index + count) == mGroupEndIndices.End(), "Duplicate index");
		if (count > SmallRangeSize)
		{
			mFreeItems.Push(std::move(Group(index, count)));
		}
		else
		{
			mGroupStartIndices.Insert(index, count);
			mGroupEndIndices.Insert(index + count, count);
		}
	}

	inline bool TryMatch(Group& group, const T& anIndex, const T aCount)
	{
		if (group.mIndex == anIndex + aCount)
		{
			group.mIndex = anIndex;
			group.mCount += aCount;
			return true;
		}
		else if (group.mIndex + group.mCount == anIndex)
		{
			group.mCount += aCount;
			return true;
		}
		return false;
	}

	// #TODO: Queue only large items. Keep small items in map, otherwise they won't get used.
	ion::PriorityQueue<Group> mFreeItems;
	ion::UnorderedMap<T, T> mGroupStartIndices;
	ion::UnorderedMap<T, T> mGroupEndIndices;

	T mTotalItems;
};
}  // namespace ion
