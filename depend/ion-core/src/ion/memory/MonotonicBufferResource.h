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
#include <ion/container/Array.h>

#include <ion/debug/AccessGuard.h>
#include <ion/debug/MemoryTracker.h>

#include <ion/memory/GlobalAllocator.h>
#include <ion/memory/Memory.h>
#include <ion/memory/MemoryScope.h>

#include <cstring>	// memset
#include <ion/util/Math.h>

namespace ion
{

namespace detail
{

constexpr size_t NextMemoryBlockSize(size_t request, size_t minimumAllocation)
{
	// Big block size to detect strange memory allocations. Increase limit when needed.
	constexpr size_t BigBlockSize = size_t(512) * 1024 * 1024;
	request = ion::Max(request, minimumAllocation);
	ION_ASSERT_FMT_IMMEDIATE(request <= BigBlockSize, "Check allocation size: %lu MBytes", request / (1024 * 1024));
	return request;
}

struct MemoryBufferBlock
{
	MemoryBufferBlock* next;
	size_t size;
	size_t capacity;
	uint8_t data;

	bool IsEqual(void* p) const
	{
		auto* ptr = static_cast<uint8_t*>(p);
		return (ptr >= &data && ptr < ((&data) + capacity));
	}

	static constexpr size_t HeaderSize = sizeof(detail::MemoryBufferBlock*) + sizeof(size_t) + sizeof(size_t);
};
}  // namespace detail

template <typename Allocator = ion::GlobalAllocator<ion::u8>, bool allocateNewBlocks = true>
class LinearMemoryBuffer
{
	using BlockAllocator = typename Allocator::template rebind<detail::MemoryBufferBlock>::other;

	// Empty base optimization for allocator until [[unique_address]] support
	struct AllocatorProxy : BlockAllocator
	{
		detail::MemoryBufferBlock* mActiveBlock = nullptr;
		AllocatorProxy() : BlockAllocator() {}
		template <typename Resource>
		AllocatorProxy(Resource* resource) : BlockAllocator(resource)
		{
		}
	};

public:
	LinearMemoryBuffer() {}

	template <typename Resource>
	LinearMemoryBuffer(Resource* source) : mProxy(source)
	{
	}

	ION_RESTRICT_RETURN_VALUE void* Allocate(size_t len, size_t align, size_t respace
#if ION_MEMORY_TRACKER
											 ,
											 bool verbose = false
#endif
											 ) ION_ATTRIBUTE_MALLOC
	{
		for (;;)
		{
			auto* ptr = AllocateFromBlock(*mProxy.mActiveBlock, len, align);
			if constexpr (!allocateNewBlocks)
			{
				return ptr;
			}
			if (ptr)
			{
				return ptr;
			}
#if ION_MEMORY_TRACKER
			if (verbose)
			{
				// Improve buffer sizes if this happens
				ION_WRN("LinearMemoryBuffer allocating new block;request=" << len << ";align=" << align);
				// ION_DEBUG_BREAK;
			}
#endif
			if (mProxy.mActiveBlock->next == nullptr)
			{
				auto* newBlock = AllocateBlock(detail::NextMemoryBlockSize(len + align, respace));
				if (newBlock == nullptr)
				{
					return nullptr;
				}
				mProxy.mActiveBlock->next = newBlock;
				mProxy.mActiveBlock = newBlock;
			}
			else
			{
				mProxy.mActiveBlock = mProxy.mActiveBlock->next;
			}
		}
	}

	void Rewind(detail::MemoryBufferBlock* startBlock)
	{
		detail::MemoryBufferBlock* ptr = startBlock;
		do
		{
#if ION_BUILD_DEBUG
			std::memset(&ptr->data, 0xCD, ptr->capacity);
#endif
			ptr->size = 0;
			ptr = ptr->next;
		} while (ptr);
		mProxy.mActiveBlock = startBlock;
	}

	void RewindAndDeallocate(detail::MemoryBufferBlock* startBlock)
	{
		detail::MemoryBufferBlock* ptr = startBlock;
		ptr = ptr->next;
		while (ptr)
		{
			auto prev = ptr;
			ptr = ptr->next;
			DeallocateBlock(prev);
		}
		mProxy.mActiveBlock = startBlock;
		startBlock->next = nullptr;
		startBlock->size = 0;
	}

	size_t ActiveCapacity() const { return mProxy.mActiveBlock->capacity; }

	detail::MemoryBufferBlock* AllocateBlock(size_t blockSize)
	{
		size_t byteSize = blockSize + detail::MemoryBufferBlock::HeaderSize;
		byteSize += ion::ByteAlignOffset(byteSize, sizeof(detail::MemoryBufferBlock));
		auto numBufferBlocks = byteSize / sizeof(detail::MemoryBufferBlock);

		detail::MemoryBufferBlock* newBlock = mProxy.allocate(numBufferBlocks);
		if (newBlock)
		{
			newBlock->next = nullptr;
			newBlock->size = 0;
			newBlock->capacity = byteSize - detail::MemoryBufferBlock::HeaderSize;
			ION_ASSERT(newBlock->capacity >= blockSize, "Invalid capacity");
			ION_ASSERT(newBlock->capacity < blockSize + sizeof(detail::MemoryBufferBlock), "Invalid capacity");
		}
		return newBlock;
	}

	void DeallocateBlock(detail::MemoryBufferBlock* block) { mProxy.deallocate(block, 0); }

private:
	void* AllocateFromBlock(detail::MemoryBufferBlock& block, size_t len, size_t alignment)
	{
		uint8_t* addr = &block.data + block.size;
		uint8_t* alignedAddress = AlignAddress(addr, alignment);
		size_t offset = size_t(alignedAddress - addr);
		block.size += offset + len;
		if (block.size < block.capacity)
		{
			return alignedAddress;
		}
		block.size -= offset + len;
		return nullptr;
	}

	AllocatorProxy mProxy;
};

template <typename Allocator = ion::GlobalAllocator<ion::u8>>
class LocalLinearMemoryBuffer
{
public:
	LocalLinearMemoryBuffer(size_t capacity) : mBuffer(), mStartBlock(mBuffer.AllocateBlock(capacity)) { mBuffer.Rewind(mStartBlock); }

	template <typename Resource>
	LocalLinearMemoryBuffer(Resource* source, size_t capacity) : mBuffer(source), mStartBlock(mBuffer.AllocateBlock(capacity))
	{
		mBuffer.Rewind(mStartBlock);
	}

	inline void* Allocate(size_t len, size_t align, size_t respace) { return mBuffer.Allocate(len, align, respace); }

	~LocalLinearMemoryBuffer()
	{
		mBuffer.RewindAndDeallocate(mStartBlock);
		mBuffer.DeallocateBlock(mStartBlock);
	}

private:
	LinearMemoryBuffer<Allocator> mBuffer;
	detail::MemoryBufferBlock* mStartBlock;
};

template <size_t NumBytesReserved, MemTag Tag = ion::tag::Unset, typename Allocator = ion::GlobalAllocator<ion::u8>>
class MonotonicBufferResource
{
	void Init()
	{
		StartBlock()->next = nullptr;
		StartBlock()->size = 0;
		StartBlock()->capacity = NumBytesReserved;
		mBuffer.Rewind(StartBlock());
		memory_tracker::TrackStatic(NumBytesReserved, Tag);
	}

public:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(MonotonicBufferResource);

	template <typename Resource>
	MonotonicBufferResource(Resource*)
	{
	}
	MonotonicBufferResource(size_t) { Init(); }
	MonotonicBufferResource() { Init(); }

	~MonotonicBufferResource()
	{
		mBuffer.RewindAndDeallocate(StartBlock());
		memory_tracker::UntrackStatic(NumBytesReserved, Tag);
	}

	void Rewind()
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		mBuffer.Rewind(StartBlock());
	}

	bool IsEqual(void* p) const
	{
		const detail::MemoryBufferBlock* ptr = StartBlock();
		do
		{
			if (ptr->IsEqual(p))
			{
				return true;
			}
			ptr = ptr->next;
		} while (ptr);
		return false;
	}

	void* Allocate(size_t len, size_t align
#if ION_MEMORY_TRACKER
				   ,
				   bool verbose = false
#endif
	)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
#if ION_MEMORY_TRACKER
		ION_MEMORY_SCOPE(ion::detail::GetMemoryTagInternal<Tag>());
		return mBuffer.Allocate(len, align, mBuffer.ActiveCapacity(), verbose);
#else
		return mBuffer.Allocate(len, align, mBuffer.ActiveCapacity());
#endif
	}

	void Deallocate(void* p, size_t) { ION_ASSERT(IsEqual(p), "Invalid source"); }

private:
	detail::MemoryBufferBlock* StartBlock() { return reinterpret_cast<detail::MemoryBufferBlock*>(mDefaultBlock.Data()); }

	const detail::MemoryBufferBlock* StartBlock() const { return reinterpret_cast<const detail::MemoryBufferBlock*>(mDefaultBlock.Data()); }

	ION_ALIGN(alignof(detail::MemoryBufferBlock*))
	ion::Array<char, NumBytesReserved + detail::MemoryBufferBlock::HeaderSize> mDefaultBlock;
	LinearMemoryBuffer<Allocator> mBuffer;
	ION_ACCESS_GUARD(mGuard);
};

template <size_t s>
using StackMemoryBuffer = ion::MonotonicBufferResource<s, ion::tag::Temporary, ion::GlobalAllocator<ion::u8>>;

}  // namespace ion
