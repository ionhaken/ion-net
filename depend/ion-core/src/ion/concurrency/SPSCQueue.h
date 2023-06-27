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
#include <ion/debug/AccessGuard.h>
#include <ion/memory/GlobalAllocator.h>

#if ION_EXTERNAL_SPSC_QUEUE
	#if ION_COMPILER_MSVC
		#pragma warning(push, 0)
	#endif	// _MSC_VER
	#include <readerwriterqueue/readerwriterqueue.h>
	#if ION_COMPILER_MSVC
		#pragma warning(pop)
	#endif
#else
	#include <ion/concurrency/Mutex.h>
	#include <ion/container/Deque.h>
#endif


namespace ion
{
template <typename T, typename TAllocator = ion::GlobalAllocator<T>>
class SPSCQueue
{
public:
#if (ION_ASSERTS_ENABLED == 1)
	static_assert(sizeof(T) < ION_CONFIG_CACHE_LINE_SIZE * 2, "Use SPSCQueue only for small items");
#else
	static_assert(sizeof(T) < ION_CONFIG_CACHE_LINE_SIZE, "Use SPSCQueue only for small items");
#endif

	template <typename Resource>
	SPSCQueue(Resource* const resource) : mData(resource)
	{
	}

	SPSCQueue() : mData() {}

	bool HasItems() const
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mReadGuard);
		ION_ACCESS_GUARD_WRITE_BLOCK(mWriteGuard);
		return mData.peek() != nullptr;
	}

	bool Dequeue(T& item)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mReadGuard);  // Only single reader supported
#if ION_EXTERNAL_SPSC_QUEUE
		bool found = mData.template try_dequeue<T>(item);
#else
		bool found = false;
		mMutex.Lock();
		if (!mData.IsEmpty())
		{
			std::swap(item, mData.Back());
			mData.PopBack();
			found = true;
		}
		mMutex.Unlock();
#endif
		return found;
	}

	bool Enqueue(const T& item)
	{
		bool result;
		ION_ACCESS_GUARD_WRITE_BLOCK(mWriteGuard);	// Only single writer supported
#if ION_EXTERNAL_SPSC_QUEUE
		result = mData.enqueue(item);
#else
		mMutex.Lock();
		mData.PushFront(item);
		mMutex.Unlock();
		result = true;
#endif
		ION_ASSERT(result, "Out of memory");
		return result;
	}

	bool Enqueue(T&& item)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mWriteGuard);	// Only single writer supported
		bool result;
#if ION_EXTERNAL_SPSC_QUEUE
		result = mData.enqueue(std::move(item));
#else
		mMutex.Lock();
		mData.PushFront(std::move(item));
		mMutex.Unlock();
		result = true;
#endif
		ION_ASSERT(result, "Out of memory");
		return result;
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

	template <typename TFunc>
	void DequeueAllWith(T& tmp, TFunc&& func)
	{
		while (Dequeue(tmp))
		{
			func(tmp);
		}
	}

private:
#if ION_EXTERNAL_SPSC_QUEUE
	using Allocator = typename TAllocator::template rebind<char>::other;
	moodycamel::ReaderWriterQueue<T, Allocator, 512> mData;
#else
	ion::Deque<T, TAllocator> mData;
	ion::Mutex mMutex;
#endif
	ION_ACCESS_GUARD(mWriteGuard);
	ION_ACCESS_GUARD(mReadGuard);
};
}  // namespace ion
