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
#include <ion/memory/TLSFResource.h>
#include <ion/memory/TSSmallMultiPool.h>
#include <ion/memory/ThreadSafeResource.h>
#include <ion/memory/VirtualMemoryBuffer.h>

namespace ion
{
template <typename BaseResource, MemTag Tag>
class TSMultiPoolResource
#if ION_CONFIG_MEMORY_RESOURCES == 1
  : public PolymorphicResourceInterface
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(TSMultiPoolResource);

public:
	template <typename Base>
	struct ResourceType
	{
		using type = ThreadSafeResource<BaseResource>;
	};

	// Assume polymorphic resource is already thread-safe
	template <>
	struct ResourceType<PolymorphicResource>
	{
		using type = BaseResource;
	};

	using PoolResource = typename ResourceType<BaseResource>::type;

	template <typename T>
	TSMultiPoolResource(T* res) : mResource(res), mPool(mResource)
	{
		mPool.Init();
	}
	TSMultiPoolResource() : mResource(), mPool(mResource) { mPool.Init(); }

	TSMultiPoolResource(size_t numBytesReserved) : mResource(numBytesReserved), mPool(mResource) { mPool.Init(); }

	~TSMultiPoolResource() { mPool.Deinit(); }

	ION_RESTRICT_RETURN_VALUE void* Allocate(size_t count, size_t align) ION_ATTRIBUTE_MALLOC
	{
		ION_MEMORY_SCOPE(Tag);
		return count <= mPool.MaxSize() && align <= SmallMultiPoolBase::Align
				 ? mPool.Allocate(count, align)
				 : PoolBlock::Allocate<PoolResource>(mResource, count, align, PoolBlock::NoList);
	}

	void Deallocate(void* p, size_t size)
	{
		uint8_t offset = 0;
		PoolBlock* block = nullptr;
		PoolBlock::GetInfo(p, block, offset);
		if (block->listId != 0xFF)
		{
			mPool.Deallocate(p, block->listId);
		}
		else
		{
			mResource.Deallocate(block, size);
		}
	}

	void* Reallocate(void* p, size_t, size_t, size_t) 
	{ 
		uint8_t offset = 0;
		PoolBlock* block = nullptr;
		PoolBlock::GetInfo(p, block, offset);

		ION_ASSERT(false, "TODO");
		return p;
	}

	void* PMRAllocate(size_t len, size_t align) final { return Allocate(len, align); }
	void* PMRReallocate(void* p, size_t s, size_t oldSize, size_t alignment) final { return Reallocate(p, s, oldSize, alignment); }
	void PMRDeallocate(void* p, size_t s) final { Deallocate(p, s); }

private:
	PoolResource mResource;
	TSSmallMultiPool<PoolResource> mPool;
#else
{
public:
	template <typename T>
	TSMultiPoolResource(T*)
	{
	}
	TSMultiPoolResource(size_t) {}
	TSMultiPoolResource() {}
#endif
};

template <size_t NumBytesReserved, MemTag Tag = ion::tag::Unset>
using TSMultiPoolResourceDefault = TSMultiPoolResource<TLSFResource<MonotonicBufferResource<NumBytesReserved, Tag>>, Tag>;

}  // namespace ion
