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

#include <ion/time/CoreTime.h>
#include <ion/container/RingBuffer.h>

namespace ion
{
template <typename Sample, typename Allocator = ion::GlobalAllocator<Sample>>
class MetricsCounter
{
	using BufferType = Deque<Sample, Allocator>;

public:
	inline void Add(const Sample& sample)
	{
		Update(sample.timestamp);
		mSamples.PushBack(sample);
		mTotalInPeriod += sample.value;
	}

	inline void Update(typename Sample::TimeType now)
	{
		while (!mSamples.IsEmpty() && static_cast<double>(TimeSince(now, mSamples.Front().timestamp)) / Sample::TimeScale > Sample::MaxAge)
		{
			mTotalInPeriod -= mSamples.Front().value;
			mSamples.PopFront();
		}
	}

	typename Sample::ValueType Total() const { return mTotalInPeriod; }
	const BufferType& Samples() const { return mSamples; }

private:
	typename Sample::ValueType mTotalInPeriod = 0;
	BufferType mSamples;
};
}  // namespace ion
