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
#include <ion/debug/MemoryTracker.h>
#include <ion/util/OsInfo.h>
#include <ion/memory/DebugAllocator.h>
#include <ion/memory/MonotonicBufferResource.h>

#if ION_EXTERNAL_MEMORY_POOL == 1
	#include <tlsf/tlsf.h>
	#if ION_MEMORY_TRACKER
		#include <ion/container/UnorderedMap.h>
	#endif
#endif

namespace ion
{

template <typename BaseResource = MonotonicBufferResource<64 * 1024, ion::tag::Unset>, MemTag Tag = ion::tag::Unset>
class TLSFResource
#if ION_CONFIG_MEMORY_RESOURCES == 1
{
	ION_ACCESS_GUARD(mGuard);
	BaseResource mResource;

	struct TLSFBlock
	{
		TLSFBlock* next;
		tlsf_pool_t* pool;
	};

	TLSFBlock* mHeadBlock = nullptr;
	TLSFBlock* mCurrentBlock = nullptr;
	size_t mTotalReservation = 0;
	tlsf_t* tlsf;
	char* ctrl;

	static constexpr size_t MinBlockSize = 8 * 1024;

	void Init()
	{
		ctrl = static_cast<char*>(mResource.Allocate(tlsf_size(), 64));
		tlsf = tlsf_create(ctrl);

		size_t blockSize = MinBlockSize * 3 - tlsf_size();
		mHeadBlock = CreatePoolBlock(blockSize);
		mCurrentBlock = mHeadBlock;
	}

public:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(TLSFResource);

	template <typename Resource>
	TLSFResource(Resource* res) : mResource(res)
	{
		Init();
	}

	TLSFResource(size_t numReserved = MinBlockSize * 3) : mResource(numReserved)
	{
		ION_ASSERT(numReserved >= MinBlockSize * 3, "Too small TLSFResource allocation");
		Init();
	}

	TLSFBlock* CreatePoolBlock(size_t blockSize)
	{
		ION_ASSERT(blockSize >= MinBlockSize, "Too small block size");
		TLSFBlock* block = static_cast<TLSFBlock*>(mResource.Allocate(blockSize, 64));
		if (block)
		{
			block->next = nullptr;
			mTotalReservation += blockSize;
			block->pool = tlsf_add_pool(tlsf, reinterpret_cast<uint8_t*>(block) + sizeof(TLSFBlock), blockSize - sizeof(TLSFBlock));
		}
		return block;
	}

	~TLSFResource()
	{
		TLSFBlock* block = mHeadBlock;
		do
		{
			tlsf_remove_pool(tlsf, block->pool);
			auto prev = block;
			block = block->next;
			mResource.Deallocate(prev, 0);
		} while (block);
		tlsf_destroy(tlsf);
		mResource.Deallocate(ctrl, 0);
	}

	
	ION_RESTRICT_RETURN_VALUE void* Allocate(size_t len, size_t align) ION_ATTRIBUTE_MALLOC
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		size_t allocationSize = ion::memory_tracker::AlignedAllocationSize(len, align);
		for (;;)
		{
			void* ptr;
			if (align <= tlsf_align_size())
			{
				ptr = ion::memory_tracker::OnAllocation(tlsf_malloc(tlsf, allocationSize), len, ion::detail::GetMemoryTagInternal<Tag>(),
														ion::memory_tracker::Layer::TLSF);
			}
			else
			{
				ptr = ion::memory_tracker::OnAlignedAllocation(tlsf_memalign(tlsf, align, allocationSize), len, align,
															   ion::detail::GetMemoryTagInternal<Tag>(), ion::memory_tracker::Layer::TLSF);
			}
			if (ptr)
			{
				return ptr;
			}
			size_t pageSize = OsMemoryPageSize();
			size_t chunkSize = ion::ByteAlignPosition(ion::Min(size_t(1) * 1024 * 1024, mTotalReservation), pageSize);
			size_t blockAllocationSize = ion::ByteAlignPosition((allocationSize + align) * 2, pageSize);

			auto* block = CreatePoolBlock(detail::NextMemoryBlockSize(blockAllocationSize, chunkSize));
			if (block == nullptr)
			{
				NotifyOutOfMemory();
				return nullptr;
			}
			mCurrentBlock->next = block;
			mCurrentBlock = block;
		}
	}

	void Deallocate(void* p, size_t)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		uint32_t alignment;
		tlsf_free(tlsf, ion::memory_tracker::OnAlignedDeallocation(p, alignment, ion::memory_tracker::Layer::TLSF));
	}

	void* Reallocate(void* p, size_t size) 
	{ 
		void* newPtr = tlsf_realloc(tlsf, p, size);
		return newPtr;		
	}

	bool IsEqual(void* p) const { return mResource.IsEqual(p); }

private:
};
#else
{
public:
	template <typename Resource>
	TLSFResource(Resource*)
	{
	}
	TLSFResource(size_t) {}
	TLSFResource() {}
};
#endif
}  // namespace ion
