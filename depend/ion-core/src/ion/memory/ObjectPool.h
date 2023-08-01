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
#include <ion/concurrency/Mutex.h>
#include <ion/container/StaticRawBuffer.h>
#include <ion/memory/MonotonicBufferResource.h>

namespace ion
{
namespace detail
{
template <typename T>
struct ObjectNode
{
	ObjectNode() { payload.next = nullptr; }
	~ObjectNode() {}
	alignas(ion::Max(alignof(ObjectNode<T>*), alignof(T))) union
	{
		ObjectNode<T>* next;  // Used only when data is unused to point to next free object.
		AlignedStorage<T, 1> data;
	} payload;
};
}  // namespace detail

// Object Pool: Cache for objects that tries to allocate them from linear memory.
template <typename T, typename Allocator = GlobalAllocator<T>>
class ObjectPool
{
	static_assert(sizeof(T) <= 4096, "Object size probably above page size, should use just memory allocators for this");
	using Node = detail::ObjectNode<T>;
	Node* mFreeObjects = nullptr;
	LocalLinearMemoryBuffer<Allocator> mBuffer;
	size_t mAllocationSize;
	size_t mMaxAllocationSize;
	ION_ACCESS_GUARD(mGuard);

public:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(ObjectPool);

	template <typename Resource>
	ObjectPool(Resource* source, size_t initialCapacity, size_t maxAllocation = 0xFFFFFFFFu)
	  : mBuffer(source, initialCapacity * sizeof(Node)), mAllocationSize(initialCapacity), mMaxAllocationSize(maxAllocation)
	{
		ION_ASSERT(mAllocationSize <= mMaxAllocationSize, "Invalid object pool config");
	}
	ObjectPool(size_t initialCapacity, size_t maxAllocation = 0xFFFFFFFFu)
	  : mBuffer(initialCapacity * sizeof(Node)), mAllocationSize(initialCapacity), mMaxAllocationSize(maxAllocation)
	{
	}

	virtual ~ObjectPool()
	{
		Purge();
#if (ION_ASSERTS_ENABLED == 1)
		ION_ASSERT(mTotalAllocations == 0, "Memory leak: " << mTotalAllocations << " objects");
#endif
	}

	template <typename... Args>
	T* Acquire(Args&&... args)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		if (!mFreeObjects)
		{
			AllocteFreeObjects(mAllocationSize);
			if (!mFreeObjects)
			{
				return nullptr;
			}
			mAllocationSize = ion::Min(mMaxAllocationSize, mAllocationSize * 2);
		}
		Node* node = AcquireNode();
		node->payload.data.Insert(0, std::forward<Args>(args)...);
		return &node->payload.data[0];
	}

	void Release(T* obj)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		Node* node = reinterpret_cast<Node*>(obj);
		node->payload.data.Erase(0);
		ReleaseNode(node);
	}

	void Purge()
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
#if (ION_ASSERTS_ENABLED == 1)
		// No-op due to linear memory buffer
		while (mFreeObjects)
		{
			ION_ASSERT(mTotalAllocations > 0, "Pool corrupted");
			/*Node* node = */ AcquireNode();
			mTotalAllocations--;
		}
#endif
	}

	inline void ReleaseNode(Node* node)
	{
		node->payload.next = mFreeObjects;
		mFreeObjects = node;
	}

private:
#if (ION_ASSERTS_ENABLED == 1)
	size_t mTotalAllocations = 0;
#endif

	inline Node* AcquireNode()
	{
		Node* node = mFreeObjects;
		mFreeObjects = node->payload.next;
		return node;
	}

	void AllocteFreeObjects(size_t numObjects)
	{
		size_t respace = ion::Min(mMaxAllocationSize, mAllocationSize * 2) * sizeof(Node);
		for (; numObjects; --numObjects)
		{
			Node* node = reinterpret_cast<Node*>(mBuffer.Allocate(sizeof(Node), alignof(Node), respace));
			if (node == nullptr)
			{
				NotifyOutOfMemory();
				return;
			}

#if (ION_ASSERTS_ENABLED == 1)
			mTotalAllocations++;
#endif
			ION_ASSERT((uintptr_t(node) % alignof(Node)) == 0, "Object Node is not correctly aligned");
			ION_ASSERT((uintptr_t(node) % alignof(T)) == 0, "Object data is not correctly aligned");
			ReleaseNode(node);
		}
	}
};
}  // namespace ion

#include <ion/memory/MonotonicBufferResource.h>
#include <ion/arena/ArenaAllocator.h>

namespace ion
{
template <typename T, size_t InitialSize>
class StackObjectPool
{
	using Resource = ion::StackMemoryBuffer<sizeof(detail::ObjectNode<T>) * InitialSize + alignof(T)>;

public:
	StackObjectPool() : mPool(&mResource, InitialSize) {}

	template <typename... Args>
	T* Acquire(Args&&... args)
	{
		return mPool.Acquire(std::forward<Args>(args)...);
	}

	void Release(T* obj) { mPool.Release(obj); }

	~StackObjectPool() { mPool.Purge(); }

private:
	Resource mResource;
	ObjectPool<T, ArenaAllocator<T, ion::StackMemoryBuffer<sizeof(detail::ObjectNode<T>) * InitialSize + alignof(T)>>> mPool;
};

}  // namespace ion
