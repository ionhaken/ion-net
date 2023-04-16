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
#include <ion/memory/ObjectPool.h>

namespace ion
{
template <typename Resource, MemTag Tag = ion::tag::Unset>
class SmallMultiPool : public SmallMultiPoolBase
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(SmallMultiPool);
	Resource& mResource;

	// #TODO: Use blocks allocated for actual data for freelist data, instead of allocating
	// space for free lists separately.
	struct FreeList
	{
		static constexpr size_t MaxPtrs = 255;	// This is waste, we could just have single pointer to next
		FreeList* next;
		void* ptr[MaxPtrs];
		uint8_t count;

		FreeList(FreeList* p)
		{
			next = p;
			count = 0;
		}

		void Push(void* p)
		{
			ptr[count] = p;
			++count;
		}

		void* Pop(size_t align)
		{
			if (ion::Mod2(reinterpret_cast<uintptr_t>(ptr[count - 1]), align) == 0)
			{
				return Pop();
			}
			else
			{
				return nullptr;
			}
		}

		void* Pop()
		{
			--count;
			return ptr[count];
		}

		bool HasData() const { return count > 0; }

		bool HasSpace() const { return count < MaxPtrs; }
	};

	using FreeListPool = ion::ObjectPool<FreeList, ArenaAllocator<FreeList, Resource>>;
	FreeListPool mFreeListPool;

	struct Store
	{
		static Store* Create(Resource& resource)
		{
			Store* store = reinterpret_cast<Store*>(resource.Allocate(sizeof(Store), alignof(Store)));
			new (store) Store();
			return store;
		}

		static void Delete(Resource& resource, FreeListPool& freeListPool, Store* store)
		{
			store->FreeAll(resource, freeListPool);
			resource.Deallocate(store, 0);
		}

		Store() { mCurrent = nullptr; }

		void* Allocate(FreeListPool& freeList, size_t align)
		{
			if (mCurrent)
			{
				if (mCurrent->HasData())
				{
					return mCurrent->Pop(align);
				}
				else
				{
					UnuseFreeList(freeList);
					if (mCurrent && mCurrent->HasData())
					{
						return mCurrent->Pop(align);
					}
				}
			}
			return nullptr;
		}

		void* Allocate(FreeListPool& freeList)
		{
			if (mCurrent)
			{
				if (mCurrent->HasData())
				{
					return mCurrent->Pop();
				}
				else
				{
					UnuseFreeList(freeList);
					if (mCurrent && mCurrent->HasData())
					{
						return mCurrent->Pop();
					}
				}
			}
			return nullptr;
		}

		void Deallocate(FreeListPool& freeList, void* data)
		{
			if (!mCurrent || !mCurrent->HasSpace())
			{
				mCurrent = freeList.Acquire(mCurrent);
				ION_ASSERT(mCurrent->HasSpace(), "Invalid free list state");
			}
			mCurrent->Push(data);
		}

		void FreeAll(Resource& resource, FreeListPool& freeListPool)
		{
			while (mCurrent != nullptr)
			{
				while (mCurrent->HasData())
				{
					void* p = mCurrent->Pop();
					uint8_t offset = 0;
					PoolBlock* block = nullptr;
					PoolBlock::GetInfo(p, block, offset);
					resource.Deallocate(block, 0);
				}
				UnuseFreeList(freeListPool);
			}
		}

	private:
		void UnuseFreeList(FreeListPool& freeList)
		{
			auto next = mCurrent->next;
			freeList.Release(mCurrent);
			mCurrent = next;
		}

		FreeList* mCurrent;
	};

public:
	SmallMultiPool(Resource& resource) : mResource(resource), mFreeListPool(&mResource, 1)
	{
		for (size_t i = 0; i < GroupCount; ++i)
		{
			mStore[i] = Store::Create(mResource);
			mAlignedStore[i] = Store::Create(mResource);
		}
	}

	virtual ~SmallMultiPool()
	{
		for (size_t i = 0; i < GroupCount; ++i)
		{
			Store::Delete(mResource, mFreeListPool, mStore[i]);
			Store::Delete(mResource, mFreeListPool, mAlignedStore[i]);
		}
	}

	void* Allocate(size_t count, size_t align)
	{
		ION_ASSERT(align <= 255, "Unsupported alignment " << align);
		ION_ASSERT(count <= MaxSize(), "Too large block;Max size=" << MaxSize());
		ION_ASSERT(count > 0, "Invalid size");
		size_t list;
		if (count <= LowCount)
		{
			count += ByteAlignOffset(count, LowAlign);
			list = (count - 1) / LowAlign;
			ION_ASSERT(list < LowBuckets, "Invalid list");
		}
		else if (count <= MidCount)
		{
			count += ByteAlignOffset(count - LowCount, MidAlign);
			list = (count - LowCount - 1) / MidAlign + LowBuckets;
			ION_ASSERT(list < MidBuckets + LowBuckets, "Invalid list");
			ION_ASSERT((count % MidAlign) == 0, "Invalid alignment");
		}
		else
		{
			count += ByteAlignOffset(count - MidCount, HighAlign);
			list = (count - MidCount - 1) / HighAlign + MidBuckets + LowBuckets;
			ION_ASSERT(list < GroupCount, "Invalid list");
			ION_ASSERT((count % HighAlign) == 0, "Invalid alignment");
		}

		void* data;
		if (align == alignof(void*))
		{
			data = mStore[list]->Allocate(mFreeListPool);
		}
		else
		{
			data = mAlignedStore[list]->Allocate(mFreeListPool, align);
		}
		if (data)
		{
			return data;
		}
		else
		{
			ION_ASSERT(list != PoolBlock::NoList, "List id is reserved");
			return PoolBlock::Allocate<Resource>(mResource, count, align, ion::SafeRangeCast<uint8_t>(list));
		}
	}

	void Deallocate(void* p, size_t)
	{
		uint8_t offset = 0;
		PoolBlock* block = nullptr;
		PoolBlock::GetInfo(p, block, offset);
		Deallocate(p, block->listId, offset);
	}

	void Deallocate(void* p, uint8_t listId, uint8_t offset)
	{
		ION_ASSERT(listId < GroupCount, "Invalid list " << listId);
		if (offset == alignof(void*))
		{
			mStore[listId]->Deallocate(mFreeListPool, p);
		}
		else
		{
			mAlignedStore[listId]->Deallocate(mFreeListPool, p);
		}
	}

	bool IsEqual(void* p) const { return mResource.IsEqual(p); }

private:
	Store* mStore[GroupCount];
	Store* mAlignedStore[GroupCount];
};
}  // namespace ion
