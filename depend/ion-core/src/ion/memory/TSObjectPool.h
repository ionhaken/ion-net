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
#include <ion/memory/ObjectPool.h>
#include <ion/concurrency/Synchronized.h>
#include <ion/memory/TSObjectCache.h>

namespace ion
{

template <typename T, typename Allocator>
class ThreadSafeObjectPool
{
public:
	template <typename Resource>
	ThreadSafeObjectPool(Resource* source, size_t allocationSize, size_t maxAllocationSize = 0xFFFFFFFF)
	  : mPool(source, allocationSize, maxAllocationSize)
	{
	}

	ThreadSafeObjectPool(size_t allocationSize, size_t maxAllocationSize = 0xFFFFFFFF) : mPool(allocationSize, maxAllocationSize) {}

	template <typename... Args>
	T* Acquire(Args&&... args)
	{
		ion::AutoLock<Mutex> mLock(mMutex);
		return mPool.Acquire(std::forward<Args>(args)...);
	}

	void Release(T* obj)
	{
		ion::AutoLock<Mutex> mLock(mMutex);
		mPool.Release(obj);
	}

	void Purge() { mPool.Purge(); }

private:
	ion::Mutex mMutex;
	ObjectPool<T, Allocator> mPool;
};

template <typename T, size_t InitialSize>
class TSStackObjectPool
{
	using Resource = ion::StackMemoryBuffer<sizeof(detail::ObjectNode<T>) * InitialSize + alignof(T)>;

public:
	TSStackObjectPool() : mPool(&mResource, InitialSize) {}

	template <typename... Args>
	T* Acquire(Args&&... args)
	{
		return mPool.Acquire(std::forward<Args>(args)...);
	}

	void Release(T* obj) { mPool.Release(obj); }

	void Purge() { mPool.Purge(); }

	~TSStackObjectPool() { Purge(); }

private:
	Resource mResource;
	ThreadSafeObjectPool<T, ArenaAllocator<T, ion::StackMemoryBuffer<sizeof(detail::ObjectNode<T>) * InitialSize + alignof(T)>>> mPool;
};
}  // namespace ion
