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
#include <ion/jobs/JobScheduler.h>
#include <ion/container/Algorithm.h>
#include <ion/memory/UniquePtr.h>

namespace ion
{

template <typename TData, size_t DefaultSize =
							ion::MinMax(static_cast<uint64_t>(1),
										// Stack reservation - By default, use 4KB from stack for intermediates
										static_cast<uint64_t>(4096u / sizeof(CriticalData<TData>)), static_cast<uint64_t>(ion::MaxThreads))>
class JobIntermediate
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(JobIntermediate);
	using AuxContainerType = ion::Vector<UniquePtr<CriticalData<TData>>>;

public:
	using Type = TData;

	JobIntermediate() : mFreeIndex(1) { mSmallContainers.Insert(0); }

	template <typename ThreadSafeResource>
	JobIntermediate(ThreadSafeResource* const resource) : mAuxContainers(resource), mFreeIndex(1)
	{
		mSmallContainers.Insert(0);
	}

	~JobIntermediate()
	{
		mSmallContainers.Erase(0);
		auto used = static_cast<size_t>(mFreeIndex);
		for (size_t index = 1; index < ion::Min(DefaultSize, used); ++index)
		{
			mSmallContainers.Erase(index);
		}
	}

	inline TData& GetMain()
	{
		ION_ASSERT(mIsValid, "Intermediate has been invalidated");
		return mSmallContainers[0].data;
	}

	template <typename TFunc>
	inline TData& Merge(TFunc&& func)
	{
		auto& main = GetMain();
		ForEachContainerNoMain([&](const TData& other) { func(main, other); });
		return main;
	}

	template <typename TFunc>
	inline void ForEachContainer(TFunc&& func)
	{
		ForEachContainer(func, 0);
	}

	template <typename TFunc>
	inline void ForEachContainerNoMain(TFunc&& func)
	{
		ForEachContainer(func, 1);
	}

	TData& GetFree()
	{
		ION_ASSERT(mIsValid, "Intermediate has been invalidated");
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		UInt index = IncrementFreeIndex();
		if (index < DefaultSize)
		{
			mSmallContainers.Insert(index);
			return mSmallContainers[index].data;
		}
		auto container = ion::MakeUnique<CriticalData<TData>>();
		auto& ref = container.get()->data;
		mMutex.Lock();
		if (mAuxContainers == nullptr)
		{
			mAuxContainers = ion::MakeUnique<AuxContainerType>();
		}
		mAuxContainers->Add(std::move(container));
		mMutex.Unlock();
		return ref;
	}

private:
	// Returns each used container.
	// Note: containers may be removed after call.
	template <typename TFunc>
	void ForEachContainer(TFunc&& func, size_t index)
	{
		ION_ASSERT(mIsValid, "Intermediate has been invalidated");
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		auto used = static_cast<size_t>(mFreeIndex);
		for (; index < ion::Min(DefaultSize, used); ++index)
		{
			func(mSmallContainers[index].data);
		}
		while (index < used)
		{
			ion::UniquePtr<CriticalData<TData>> other;
			other = std::move((*mAuxContainers)[index - DefaultSize]);	/// .Dequeue(other);
			func(other.get()->data);
			++index;
		}
		mIsValid = false;  // Invalidate container as aux containers were removed
	}

	UInt IncrementFreeIndex()
	{
		UInt index = mFreeIndex++;
		return index;
	}

	ION_ACCESS_GUARD(mGuard);
	StaticBuffer<CriticalData<TData>, DefaultSize> mSmallContainers;
	ion::Mutex mMutex;
	ion::UniquePtr<AuxContainerType> mAuxContainers;
	std::atomic<UInt> mFreeIndex;
	bool mIsValid = true;
};

template <typename TData, size_t DefaultSize, typename TFunc>
void ForEach(JobIntermediate<TData, DefaultSize>& data, TFunc&& func)
{
	data.ForEachContainer(func);
}
}  // namespace ion
