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
#include <ion/concurrency/Synchronized.h>
#include <ion/concurrency/AtomicFlag.h>

namespace ion
{
// Thread safe object cache. Order of objects is not guaranteed, althought current implementation stores objects in a stack.
template <typename T, typename TAllocator>
class TSObjectCache
{
public:
	TSObjectCache() {}

	template <typename Resource>
	TSObjectCache(Resource* resource) : mItems(resource), mCount(0)
	{
	}

	inline size_t Count() const { return mCount; }

	// Will get an object from cache if no other thread is accessing the cache.
	[[nodiscard]] inline bool Dequeue(T& ret)
	{
		ret = nullptr;
		if (mItems.TryAccess(
			  [&](auto& items)
			  {
				  if (!items.IsEmpty())
				  {
					  mCount--;
					  ret = items.Back();
					  items.PopBack();
				  }
			  }))
		{
			return ret != nullptr;
		}
		return false;
	}

	// Adds object to cache if no other thread is accessing the cache
	[[nodiscard]] inline bool Enqueue(T& p)
	{
		if (mItems.TryAccess(
			  [&](auto& items)
			  {
				  items.Add(p);
				  mCount++;
			  }))
		{
			return true;
		}
		return false;
	}

private:
	// Using vector here, it seems to be faster than using linked list - probably due to pointer traversal being bad for cache
	ion::Synchronized<ion::Vector<T, TAllocator>, ion::AtomicFlag> mItems;
	std::atomic<size_t> mCount;
};

}  // namespace ion
