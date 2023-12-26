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

// TODO: Lock free version requires use of tokens, because we have worker pool
// and multiple workers could be the same producer. Otherwise items will be out of order even from single producer
#define MPSC_IS_LOCK_FREE 0

#if MPSC_IS_LOCK_FREE
	#if ION_COMPILER_MSVC
		#pragma warning(push, 0)
	#endif	// _MSC_VER
	#include "concurrentqueue\concurrentqueue.h"
	#if ION_COMPILER_MSVC
		#pragma warning(pop)
	#endif
#else
	#include <ion/arena/ArenaAllocator.h>
	#include <ion/memory/MultiPoolResource.h>
	#include <ion/concurrency/SPSCQueue.h>
	#include <atomic>
#endif


#include <ion/debug/AccessGuard.h>

namespace ion
{
template <typename T, typename TAllocator = ion::GlobalAllocator<T>>
class MPSCQueue
{
public:
#if MPSC_IS_LOCK_FREE
	class ProducerToken
	{
	public:
		ProducerToken(MPSCQueue& q) : mTokenImpl(q) {}

	private:
		moodycamel::ProducerToken mTokenImpl;
	};

	class ConsumerToken
	{
	public:
		ConsumerToken(MPSCQueue& q) : mTokenImpl(q) {}

	private:
		moodycamel::ConsumerToken mTokenImpl;
	};
#endif

	MPSCQueue() : mData() {}

	template <typename Resource>
	MPSCQueue(Resource* resource) : mData(resource)
	{
	}

	inline bool HasItems() const
	{
		bool hasItems;
		mMutex.Lock();
		hasItems = mData.HasItems();
		mMutex.Unlock();
		return hasItems;
	}

	inline bool Enqueue(T&& item)
	{
#if MPSC_IS_LOCK_FREE
		bool result = mData.enqueue(token.mTokenImpl, item);
		ION_ASSERT(result, "Out of memory");
		return result;
#else
		mMutex.Lock();
		auto result = mData.Enqueue(std::move(item));
		mMutex.Unlock();
		return result;
#endif
	}

	inline bool Enqueue(const T& item)
	{
#if MPSC_IS_LOCK_FREE
		bool result = mData.enqueue(token.mTokenImpl, item);
		ION_ASSERT(result, "Out of memory");
		return result;
#else
		mMutex.Lock();
		auto res = mData.Enqueue(item);
		mMutex.Unlock();
		return res;
#endif
	}

	inline bool Dequeue(T& item)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mReadGuard);  // Only single reader supported
#if MPSC_IS_LOCK_FREE
		return mData.template try_dequeue<T>(item);
#else
		return mData.Dequeue(item);
#endif
	}

	template <typename TFunc>
	void DequeueAll(TFunc&& func)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mReadGuard);
		mData.DequeueAll(std::forward<TFunc>(func));
	}

private:
#if MPSC_IS_LOCK_FREE
	using Allocator = typename TAllocator::template rebind<char>::other;
	moodycamel::ConcurrentQueue<T, Allocator> mData;
#else
	// Resource mResource;
	// Use SPSC queue, but have lock on writer side to create MPSC queue.
	ion::SPSCQueue<T, TAllocator> mData;
	Mutex mMutex;
#endif
	ION_ACCESS_GUARD(mReadGuard);
};

template <typename T, typename Allocator = GlobalAllocator<T>>
class MPSCQueueCounted
{
public:
	MPSCQueueCounted() : mData(), mSize(0) {}

	template <typename Resource>
	MPSCQueueCounted(Resource* resource) : mData(resource), mSize(0)
	{
	}

	size_t Size() const { return mSize; }

	void Enqueue(T&& data)
	{
		mSize++;
		mData.Enqueue(std::move(data));
	}

	bool Dequeue(T& data)
	{
		if (mData.Dequeue(data))
		{
			mSize--;
			return true;
		}
		return false;
	}

	template <typename TFunc>
	void DequeueAll(TFunc&& func)
	{
		T tmp;
		while (Dequeue(tmp))
		{
			func(tmp);
		}
	}

private:
	ion::MPSCQueue<T, Allocator> mData;
	std::atomic<size_t> mSize;
};

}  // namespace ion
