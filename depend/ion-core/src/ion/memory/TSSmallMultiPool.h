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

#include <ion/memory/SmallMultiPoolBase.h>
#include <ion/arena/ArenaAllocator.h>
#include <ion/container/StaticRawBuffer.h>
#include <ion/memory/TSObjectCache.h>
namespace ion
{
template <typename Resource, MemTag Tag = ion::tag::Unset>
class TSSmallMultiPool : public SmallMultiPoolBase
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(TSSmallMultiPool);

	using Store = ion::TSObjectCache<void*, ArenaAllocator<void*, Resource>>;
	//using Store = ion::TSObjectCacheLinkedList;

public:
	TSSmallMultiPool(Resource& resource) : mResource(resource) {}

	void Init()
	{
		for (size_t i = 0; i < GroupCount; ++i)
		{
			mFreePools.Insert(i, &mResource);
			//mFreePools.Insert(i);
		}
	}
	void Deinit()
	{
		for (size_t i = 0; i < GroupCount; ++i)
		{
			void* ptr;
			while (mFreePools[i].Dequeue(ptr))
			{
				uint8_t offset = 0;
				PoolBlock* block = nullptr;
				PoolBlock::GetInfo(ptr, block, offset);
				mResource.Deallocate(block, 1);
			}
			mFreePools.Erase(i);
		}
	}

	virtual ~TSSmallMultiPool() {}

	void* Allocate(size_t count, [[maybe_unused]] size_t align)
	{
		ION_ASSERT(align <= SmallMultiPoolBase::Align, "Unsupported align");
		ION_ASSERT(count <= MaxSize(), "Too large block;Max size=" << MaxSize());
		ION_ASSERT(count > 0, "Invalid size");
		size_t listId;
		if (count <= LowCount)
		{
			count += ByteAlignOffset(count, LowAlign);
			listId = (count - 1) / LowAlign;
			ION_ASSERT(listId < LowBuckets, "Invalid list");
		}
		else if (count <= MidCount)
		{
			count += ByteAlignOffset(count - LowCount, MidAlign);
			listId = (count - LowCount - 1) / MidAlign + LowBuckets;
			ION_ASSERT(listId < MidBuckets + LowBuckets, "Invalid list");
			ION_ASSERT((count % MidAlign) == 0, "Invalid alignment");
		}
		else
		{
			count += ByteAlignOffset(count - MidCount, HighAlign);
			listId = (count - MidCount - 1) / HighAlign + MidBuckets + LowBuckets;
			ION_ASSERT(listId < GroupCount, "Invalid list");
			ION_ASSERT((count % HighAlign) == 0, "Invalid alignment");
		}
		ION_ASSERT(listId != PoolBlock::NoList, "List id is reserved");

		void* data;
		auto& pool = mFreePools[listId];
		if (pool.Dequeue(data))
		{
			ION_ASSERT(ion::Mod2(reinterpret_cast<uintptr_t>(data), align) == 0, "Invalid aligment");
			{
				return data;
			}
		}
		return PoolBlock::Allocate<Resource>(mResource, count, 8, ion::SafeRangeCast<uint8_t>(listId));
	}

	void Deallocate(void* ptr, uint8_t listId)
	{
		ION_ASSERT(listId < GroupCount, "Invalid list " << listId);
		auto& pool = mFreePools[listId];
		if (pool.Count() * (listId + 1) <= 1023) 
		{
			if (pool.Enqueue(ptr)) 
			{
				return;
			}
		}
		#if 0
		size_t totalBuffered = mFreePools[listId].Enqueue(ptr);
		if (totalBuffered > 0)
		{
			if (totalBuffered * (listId + 1) <= 4095)
			{
				// Block buffered.
				return;
			}

			// Too many items in buffer. Let's deallocate one block from the list.
			if (!mFreePools[listId].Dequeue(ptr))
			{
				// Cannot get a block.
				return;
			}
		}
		#endif

		uint8_t offset = 0;
		PoolBlock* block = nullptr;
		PoolBlock::GetInfo(ptr, block, offset);
		mResource.Deallocate(block, 1);
	}

	bool IsEqual(void* p) const { return mResource.IsEqual(p); }

private:
	Resource& mResource;
	ion::StaticBuffer<Store, GroupCount> mFreePools;
};
}  // namespace ion
