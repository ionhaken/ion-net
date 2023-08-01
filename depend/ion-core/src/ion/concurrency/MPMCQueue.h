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
#include <ion/memory/Memory.h>
#include <ion/memory/GlobalAllocator.h>

#if ION_EXTERNAL_MPMC_QUEUE
	#if ION_COMPILER_MSVC
		#pragma warning(push, 0)
	#endif	// _MSC_VER
	#define MOODYCAMEL_DYNAMIC_CAST ion::DynamicCast
	#define MOODYCAMEL_NO_THREAD_LOCAL
	#include "concurrentqueue/concurrentqueue.h"
	#if ION_COMPILER_MSVC
		#pragma warning(pop)
	#endif
#else
	#include <ion/container/Deque.h>
#endif

namespace ion
{
// Note: Benchmark before replacing global allocator with any arena allocator
template <typename TAllocator = GlobalAllocator<char>>
struct MPMCConcurrentQueueTraits : public moodycamel::ConcurrentQueueDefaultTraits
{
	using Allocator = typename TAllocator::template rebind<char>::other;

	// General-purpose size type. std::size_t is strongly recommended.
	typedef std::size_t size_t;

	// The type used for the enqueue and dequeue indices. Must be at least as
	// large as size_t. Should be significantly larger than the number of elements
	// you expect to hold at once, especially if you have a high turnover rate;
	// for example, on 32-bit x86, if you expect to have over a hundred million
	// elements or pump several million elements through your queue in a very
	// short space of time, using a 32-bit type *may* trigger a race condition.
	// A 64-bit int type is recommended in that case, and in practice will
	// prevent a race condition no matter the usage of the queue. Note that
	// whether the queue is lock-free with a 64-int type depends on the whether
	// std::atomic<std::uint64_t> is lock-free, which is platform-specific.
	typedef std::size_t index_t;

	// Internally, all elements are enqueued and dequeued from multi-element
	// blocks; this is the smallest controllable unit. If you expect few elements
	// but many producers, a smaller block size should be favoured. For few producers
	// and/or many elements, a larger block size is preferred. A sane default
	// is provided. Must be a power of 2.
	static const size_t BLOCK_SIZE = 32;

	// For explicit producers (i.e. when using a producer token), the block is
	// checked for being empty by iterating through a list of flags, one per element.
	// For large block sizes, this is too inefficient, and switching to an atomic
	// counter-based approach is faster. The switch is made for block sizes strictly
	// larger than this threshold.
	static const size_t EXPLICIT_BLOCK_EMPTY_COUNTER_THRESHOLD = 32;

	// How many full blocks can be expected for a single explicit producer? This should
	// reflect that number's maximum for optimal performance. Must be a power of 2.
	static const size_t EXPLICIT_INITIAL_INDEX_SIZE = 32;

	// How many full blocks can be expected for a single implicit producer? This should
	// reflect that number's maximum for optimal performance. Must be a power of 2.
	static const size_t IMPLICIT_INITIAL_INDEX_SIZE = 32;

	// The initial size of the hash table mapping thread IDs to implicit producers.
	// Note that the hash is resized every time it becomes half full.
	// Must be a power of two, and either 0 or at least 1. If 0, implicit production
	// (using the enqueue methods without an explicit producer token) is disabled.
	static const size_t INITIAL_IMPLICIT_PRODUCER_HASH_SIZE = 32;

	// Controls the number of items that an explicit consumer (i.e. one with a token)
	// must consume before it causes all consumers to rotate and move on to the next
	// internal queue.
	static const std::uint32_t EXPLICIT_CONSUMER_CONSUMPTION_QUOTA_BEFORE_ROTATE = 256;

	// The maximum number of elements (inclusive) that can be enqueued to a sub-queue.
	// Enqueue operations that would cause this limit to be surpassed will fail. Note
	// that this limit is enforced at the block level (for performance reasons), i.e.
	// it's rounded up to the nearest block size.
	static const size_t MAX_SUBQUEUE_SIZE = moodycamel::details::const_numeric_max<size_t>::value;
};

// https://github.com/cameron314/concurrentqueue
// the queue is not sequentially consistent; there is a happens-before relationship between when
// an element is put in the queue and when it comes out, but other things (such as pumping the queue until
// it's empty) require more thought to get right in all eventualities, because explicit memory ordering
// may have to be done to get the desired effect. In other words, it can sometimes be difficult to use
// the queue correctly.
template <typename T, typename TAllocator = ion::GlobalAllocator<char>>
class MPMCQueue
{
	static_assert(sizeof(T) < ION_CONFIG_CACHE_LINE_SIZE, "Use MPMCQueue only for small items");

public:
	MPMCQueue() {}

	template <typename Resource>
	MPMCQueue(Resource* const resource) : mData(32 * 6, resource)
	{
	}

	inline bool Dequeue(T& item)
	{
#if ION_EXTERNAL_MPMC_QUEUE
		return mData.template try_dequeue<T>(item);
#else
		mMutex.lock();
		if (!mData.IsEmpty())
		{
			item = std::move(mData.Back());
			mData.PopBack();
			mMutex.unlock();
			return true;
		}
		mMutex.unlock();
		return false;
#endif
	}

	inline bool Enqueue(const T& item)
	{
#if ION_EXTERNAL_MPMC_QUEUE
		bool result = mData.enqueue(item);
		ION_ASSERT(result, "Out of memory");
		return result;
#else
		mMutex.lock();
		mData.PushFront(std::move(item));
		mMutex.unlock();
		return true;
#endif
	}

	inline bool Enqueue(T&& item)
	{
#if ION_EXTERNAL_MPMC_QUEUE
		bool result = mData.enqueue(std::move(item));
		ION_ASSERT(result, "Out of memory");
		return result;
#else
		mMutex.lock();
		mData.PushFront(std::move(item));
		mMutex.unlock();
		return true;
#endif
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
#if ION_EXTERNAL_MPMC_QUEUE
	moodycamel::ConcurrentQueue<T, MPMCConcurrentQueueTraits<TAllocator>> mData;
#else
	ion::Deque<T, TAllocator<T>> mData;
	Mutex mMutex;
#endif
};
}  // namespace ion
