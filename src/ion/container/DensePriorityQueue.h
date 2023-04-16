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
#include <ion/container/Array.h>
#include <ion/container/PriorityQueue.h>
#include <ion/container/Algorithm.h>
#include <ion/container/Vector.h>

namespace ion
{
// Priority queue where most of the elements have same priority
// #TODO: Support allocators
template <typename TValue, typename TIndex, size_t TShortRange, size_t TShortAllocation = 8>
class DensePriorityQueue
{
public:
	DensePriorityQueue() : mShortRangeBuffer(), mLongRangeBuffer(), mCurrentIndex(0) {}

	using List = ion::Vector<TValue>;

	DensePriorityQueue& operator=(const DensePriorityQueue& other)
	{
		for (size_t i = 0; i < TShortRange; ++i)
		{
			if (!other.mShortRangeBuffer[i].IsEmpty())
			{
				mShortRangeBuffer[i] = other.mShortRangeBuffer[i];
			}
			else
			{
				mShortRangeBuffer[i].Clear();
			}
		}
		mCurrentIndex = other.mCurrentIndex;
		mLongRangeBuffer = other.mLongRangeBuffer;
		return *this;
	}

	void Push(const TValue& element)
	{
		const TIndex index = element.GetPriority();
		ION_ASSERT(index <= static_cast<TIndex>(-1) - TShortRange, "Priority out of range");
		if (index < mCurrentIndex)
		{
			ION_ASSERT(mLongRangeBuffer.IsEmpty() || mLongRangeBuffer.Top().GetPriority() >= mCurrentIndex + TShortRange,
					   "Priority " << mLongRangeBuffer.Top().GetPriority() << " found in long range;min=" << mCurrentIndex + TShortRange);

			// Move [index + TShortRange, ...] to long range
			const TIndex end = ion::Max(static_cast<TIndex>(index + TShortRange), mCurrentIndex);
			TIndex pos = mCurrentIndex + TShortRange - 1;
			while (pos >= end)
			{
				MoveToLongRange(pos);
				pos--;
			}

			ION_ASSERT(mLongRangeBuffer.IsEmpty() || mLongRangeBuffer.Top().GetPriority() >= mCurrentIndex,
					   "Priority " << mLongRangeBuffer.Top().GetPriority() << " found in long range;min=" << mCurrentIndex);
			mCurrentIndex = index;
			if (!mLongRangeBuffer.IsEmpty())
			{
				for (TIndex i = GetNextInLongRange(); i < mCurrentIndex + TShortRange; i++)
				{
					MoveToShortRange(i);
				}
			}
			ION_ASSERT(mLongRangeBuffer.IsEmpty() || mLongRangeBuffer.Top().GetPriority() >= mCurrentIndex + TShortRange,
					   "Wrong priority in long range");
			AddShortRange(mCurrentIndex, element);
		}
		else if (IsEmpty())
		{
			mCurrentIndex = index;
			ION_ASSERT(mShortRangeBuffer[mCurrentIndex % TShortRange].IsEmpty(), "Short range clear not done");
			AddShortRange(mCurrentIndex, element);
		}
		else if (index - mCurrentIndex < TShortRange)
		{
			AddShortRange(index, element);
		}
		else
		{
			mLongRangeBuffer.Push(element);
			ION_ASSERT(mLongRangeBuffer.Top().GetPriority() >= mCurrentIndex + TShortRange, "Wrong priority in long range");
		}
		ION_ASSERT(!IsEmpty(), "New element not properly added");
	}

	bool IsEmpty() const { return mShortRangeBuffer[mCurrentIndex % TShortRange].IsEmpty(); }

	const TValue& Top() const
	{
		ION_ASSERT(mShortRangeBuffer[mCurrentIndex % TShortRange].Back().GetPriority() == mCurrentIndex,
				   "Invalid value in short range buffer");
		return mShortRangeBuffer[mCurrentIndex % TShortRange].Back();
	}

	List& TopList() { return mShortRangeBuffer[mCurrentIndex % TShortRange]; }

	void PopList()
	{
		mShortRangeBuffer[mCurrentIndex % TShortRange].Clear();
		Advance();
	}

	void Advance()
	{
		ION_ASSERT(mShortRangeBuffer[mCurrentIndex % TShortRange].IsEmpty(), "Advancing when not empty");
		// Find next used index from short range
		TIndex last = mCurrentIndex + TShortRange;
		do
		{
			mCurrentIndex++;
		} while (mCurrentIndex < last && mShortRangeBuffer[mCurrentIndex % TShortRange].IsEmpty());

		if (mShortRangeBuffer[mCurrentIndex % TShortRange].IsEmpty())
		{
			if (!mLongRangeBuffer.IsEmpty())
			{
				mCurrentIndex = GetNextInLongRange();
				// ION_LOG_INFO("Next In Long Range: " << mCurrentIndex);
				for (TIndex i = mCurrentIndex; i < mCurrentIndex + TShortRange; i++)
				{
					MoveToShortRange(i);
				}
				ION_ASSERT(mShortRangeBuffer[mCurrentIndex % TShortRange].Back().GetPriority() == mCurrentIndex,
						   "Invalid value in short range buffer");
			}
			else
			{
				mCurrentIndex = 0;
			}
		}
		else if (!mLongRangeBuffer.IsEmpty())
		{
			ION_ASSERT(mShortRangeBuffer[mCurrentIndex % TShortRange].Back().GetPriority() == mCurrentIndex,
					   "Invalid value in short range buffer");
			for (TIndex i = ion::Max(GetNextInLongRange(), static_cast<TIndex>(mCurrentIndex + 1)); i < mCurrentIndex + TShortRange; i++)
			{
				MoveToShortRange(i);
			}
			ION_ASSERT(mShortRangeBuffer[mCurrentIndex % TShortRange].Back().GetPriority() == mCurrentIndex,
					   "Invalid value in short range buffer");
		}
		ION_ASSERT(mLongRangeBuffer.IsEmpty() || mLongRangeBuffer.Top().GetPriority() >= mCurrentIndex + TShortRange,
				   "Wrong priority in long range");
	}

	void Pop()
	{
		// ION_LOG_INFO("My index before pop: " << mCurrentIndex);
		mShortRangeBuffer[mCurrentIndex % TShortRange].Pop();
		if (mShortRangeBuffer[mCurrentIndex % TShortRange].IsEmpty())
		{
			Advance();
		}
		ION_ASSERT(!IsEmpty() || mLongRangeBuffer.IsEmpty(), "Long range buffer not emptied properly");
		ION_ASSERT(mLongRangeBuffer.IsEmpty() || mLongRangeBuffer.Top().GetPriority() >= mCurrentIndex + TShortRange,
				   "Wrong priority in long range");
	}

private:
	void MoveToShortRange(TIndex index)
	{
		ION_ASSERT(mLongRangeBuffer.IsEmpty() || mLongRangeBuffer.Top().GetPriority() >= index, "Short range values in long range buffer");
		while (!mLongRangeBuffer.IsEmpty() && mLongRangeBuffer.Top().GetPriority() == index)
		{
			// ION_LOG_INFO("From long range " << index << " to pos " << (index % mShortRange));
			ION_ASSERT(
			  mShortRangeBuffer[index % TShortRange].IsEmpty() || mShortRangeBuffer[index % TShortRange].Back().GetPriority() == index,
			  "Invalid value in short range");
			AddShortRange(index, mLongRangeBuffer.Top());
			mLongRangeBuffer.Pop();
		}
		ION_ASSERT(mLongRangeBuffer.IsEmpty() || mLongRangeBuffer.Top().GetPriority() > index, "Short range values in long range buffer");
	}

	void MoveToLongRange(TIndex index)
	{
		ION_ASSERT(index - mCurrentIndex < TShortRange, "Invalid index");
		auto& buffer = mShortRangeBuffer[index % TShortRange];
		for (auto iter = buffer.Begin(); iter != buffer.End(); ++iter)
		{
			ION_ASSERT(iter->GetPriority() == index, "Priority " << iter->GetPriority() << " found when should be " << index);
			// ION_LOG_INFO("To long range " << index);
			mLongRangeBuffer.Push(*iter);
		}
		buffer.Clear();
	}

	TIndex GetNextInLongRange() const { return mLongRangeBuffer.Top().GetPriority(); }

	void AddShortRange(TIndex index, TValue element)
	{
		ION_ASSERT(index - mCurrentIndex < TShortRange, "Invalid index");
		ION_ASSERT(mShortRangeBuffer[index % TShortRange].IsEmpty() || mShortRangeBuffer[index % TShortRange].Back().GetPriority() == index,
				   "Invalid value in buffer");
		ION_ASSERT(element.GetPriority() == index, "Element priority does not match index");
		mShortRangeBuffer[index % TShortRange].Add(element);
	}

	ion::Array<List, TShortRange> mShortRangeBuffer;
	ion::PriorityQueue<TValue> mLongRangeBuffer;
	TIndex mCurrentIndex;
};
}  // namespace ion
