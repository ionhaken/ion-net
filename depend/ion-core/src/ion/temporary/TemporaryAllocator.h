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

#include <ion/concurrency/Thread.h>

#include <atomic>
#include <cstddef>
#include <ion/Base.h>
#include <ion/core/Core.h>

// Enable stats for tuning temporary allocator settings below.
#define ION_TEMPORARY_MEMORY_STATS ION_MEMORY_TRACKER

namespace ion
{
#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1

void TemporaryInit();

void TemporaryDeinit();

namespace temporary
{
constexpr size_t MaxAlign = 8;

constexpr size_t MaxPageSize = 32 * 1024 - (ION_CONFIG_CACHE_LINE_SIZE * 3);
constexpr size_t MaxPageMemoryPerThread = 16 * 1024 * 1024;

constexpr size_t MaxPagesPerThread = MaxPageMemoryPerThread / MaxPageSize;
	#if (ION_ASSERTS_ENABLED == 1)
constexpr bool AssertPageLimit = false;
	#endif

struct BytePool;

BytePool* ThreadInit();
void ThreadDeinit(BytePool* pool);
void ThreadDeferDeinit(BytePool* pool);
	#if ION_TEMPORARY_MEMORY_STATS
void StatBytesAllocated(size_t s);
void StatBytesInPages(size_t s);
void StatFailedOutOfPages();
void StatFailedLocked();
void StatFailedTooLarge();
void StatOutOfMemory();
	#else
inline void StatBytesAllocated(size_t) {}
inline void StatBytesInPages(size_t) {}
inline void StatFailedOutOfPages() {}
inline void StatFailedLocked() {}
inline void StatFailedTooLarge() {}
inline void StatOutOfMemory() {}
	#endif

template <size_t TSize>
struct BytePage
{
	// Hot for producer
	ION_ALIGN_CACHE_LINE BytePage* mNextPage = nullptr;
	BytePool* mSource = nullptr;
	std::atomic<uint32_t> mTotalProduced = 0;  // Consumer checks when 'mIsRemoving'
	uint32_t mBufferPos = 0;
	bool mLock = false;

	// Hot for both
	ION_ALIGN_CACHE_LINE
	#if (ION_ASSERTS_ENABLED == 1)
	uint32_t mGuard1 = 0xABBAABBA;
	#endif
	ION_ALIGN(MaxAlign) uint8_t mBuffer[TSize];
	#if (ION_ASSERTS_ENABLED == 1)
	uint32_t mGuard2 = 0xABBAABBA;
	#endif

	// Hot for consumer
	ION_ALIGN_CACHE_LINE std::atomic<uint32_t> mTotalConsumed = 0;
	std::atomic<bool> mIsRemoving = false;	// Thread stopped, ready to remove

	BytePage(BytePool* src) : mSource(src)
	{
	#if ION_BUILD_DEBUG
		memset(mBuffer, 0xDB, TSize);
	#endif
	}

	~BytePage()
	{
	#if ION_BUILD_DEBUG
		mLock = true;
		memset(mBuffer, 0xDC, TSize);
	#endif
	}

	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(BytePage);

	inline uint8_t* Peek()
	{
		ION_ASSERT_FMT_IMMEDIATE(!mLock, "Page is already being written to");
		mLock = true;
		ION_ASSERT_FMT_IMMEDIATE(mBufferPos < TSize, "Invalid buffer");
		if (mTotalProduced == mTotalConsumed)
		{
	#if ION_BUILD_DEBUG
			memset(mBuffer, 0xDD, mBufferPos);
	#endif
			mTotalProduced = 0;
			mTotalConsumed = 0;
			mBufferPos = 0;
		}
		return &mBuffer[mBufferPos];
	}

	inline void Acquire(uint32_t s)
	{
	#if (ION_ASSERTS_ENABLED == 1)
		ION_ASSERT_FMT_IMMEDIATE(mGuard1 == 0xABBAABBA, "Memory access out of bounds");
		ION_ASSERT_FMT_IMMEDIATE(mGuard2 == 0xABBAABBA, "Memory access out of bounds");
	#endif
		ION_ASSERT_FMT_IMMEDIATE(mLock, "Page was not being written to");
		ION_ASSERT_FMT_IMMEDIATE(s <= TSize && mBufferPos + s <= TSize, "Out of buffer; requested %zu/%zu bytes", s, TSize);
		mTotalProduced += s;
		ion::temporary::StatBytesAllocated(s);
		mBufferPos = ion::ByteAlignPosition(mBufferPos + s, uint32_t(MaxAlign));
		mLock = false;
	}

	inline void Release(uint32_t s)
	{
	#if (ION_ASSERTS_ENABLED == 1)
		ION_ASSERT_FMT_IMMEDIATE(mGuard1 == 0xABBAABBA, "Memory access out of bounds");
		ION_ASSERT_FMT_IMMEDIATE(mGuard2 == 0xABBAABBA, "Memory access out of bounds");
	#endif
		ION_ASSERT_FMT_IMMEDIATE(mTotalConsumed + s <= mTotalProduced, "Invalid number of bytes consumed (%zu vs %zu)",
								 size_t(mTotalConsumed + s), size_t(mTotalProduced));
		mTotalConsumed += s;
		if (mIsRemoving && mTotalConsumed == mTotalProduced)
		{
			ion::temporary::ThreadDeferDeinit(mSource);
			// If deinit managed to clear temporay pool, 'this' (BytePage) is now invalid.
		}
	}
};

struct BytePool
{
	static const constexpr size_t TSize = MaxPageSize;
	BytePage<TSize> mDefaultPage;
	BytePage<TSize>* mCurrentPage = nullptr;

	BytePool();

	void Purge();

	 // Tells other threads that they must try to clear pool after deallocating from this pool.
	void MarkRemoving();

	[[nodiscard]] bool CanPurge();

	~BytePool();

	BytePage<TSize>* GetNextPage();

	inline BytePage<TSize>* GetPage(size_t maxSize)
	{
		ION_ASSERT(!mCurrentPage->mIsRemoving, "Using page after thread deinit");
		if (!mCurrentPage->mLock)
		{
			if (mCurrentPage->mBufferPos + maxSize <= TSize)
			{
				return mCurrentPage;
			}
			else if (maxSize <= TSize)
			{
				return GetNextPage();
			}
			else
			{
				ion::temporary::StatFailedTooLarge();
			}
		}
		else
		{
			// Recursion, fall back to general allocator
			ion::temporary::StatFailedLocked();
		}
		return nullptr;
	}
};

}  // namespace temporary
#endif

// Allocator for temporary memory. You should use TemporaryAllocator for allocations that will have short time to live.
// E.g. allocations that are just routed to other system and deallocated. Usually another requirement
// is that allocations have variable size as ObjectPool may be better for fixed size allocations.
//
// TemporaryAllocator is not meant for stack allocation - there's StackAllocator for that.
//
// How TemporaryAllocator works is that it maintains pool of pages that are used for allocation.
// Once a page has been fully used, it will be removed from the pool until all allocations to the page have been released.
//
// If pool is out of pages, BackupAllocator will be used.
//
// Note: Does not work with MSVC std::vector+ASan
template <typename T, typename BackupAllocator = ion::GlobalAllocator<T>>
class TemporaryAllocator : public BackupAllocator
{
public:
#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1
	static_assert(alignof(T) <= temporary::MaxAlign, "Alignment not supported");
	struct TemporaryBlock
	{
		ION_ALIGN(temporary::MaxAlign) ion::temporary::BytePage<temporary::MaxPageSize>* mPage;
	#if ION_BUILD_DEBUG
		size_t mSize;
	#endif
		union
		{
			ION_ALIGN(temporary::MaxAlign) char mData;
		};
	};

	static constexpr size_t HeaderSize = offsetof(TemporaryBlock, mData);
#endif

	template <typename U, typename UAllocator>
	friend class TemporaryAllocator;

	using value_type = typename BackupAllocator::value_type;
	using size_type = typename BackupAllocator::size_type;
	using difference_type = typename BackupAllocator::difference_type;

	using propagate_on_container_copy_assignment = typename BackupAllocator::propagate_on_container_copy_assignment;
	using propagate_on_container_move_assignment = typename BackupAllocator::propagate_on_container_move_assignment;
	using propagate_on_container_swap = typename BackupAllocator::propagate_on_container_swap;

	template <class U>
	struct rebind
	{
		using other = TemporaryAllocator<U, typename BackupAllocator::template rebind<U>::other>;
	};
	using is_always_equal = typename BackupAllocator::is_always_equal;

	template <typename Source>
	explicit TemporaryAllocator(Source* const source) : BackupAllocator(source)
	{
	}
	explicit TemporaryAllocator() : BackupAllocator() {}
	explicit TemporaryAllocator(const TemporaryAllocator& other) : BackupAllocator(other) {}
	explicit TemporaryAllocator(TemporaryAllocator&& other) : BackupAllocator(other) {}
	TemporaryAllocator& operator=(TemporaryAllocator&& other)
	{
		BackupAllocator::operator=(std::move(other));
		return *this;
	}
	TemporaryAllocator& operator=(const TemporaryAllocator& other)
	{
		BackupAllocator::operator=(other);
		return *this;
	}

	template <typename U>
	explicit TemporaryAllocator(const TemporaryAllocator<U, typename BackupAllocator::template rebind<U>::other>& other)
	  : BackupAllocator(other)
	{
	}

	template <typename U>
	explicit TemporaryAllocator(TemporaryAllocator<U, typename BackupAllocator::template rebind<U>::other>&& other) : BackupAllocator(other)
	{
	}

	~TemporaryAllocator() {}

	inline T* Allocate(size_type n) { return AssumeAligned<T, alignof(T)>(AllocateRaw(n * sizeof(T))); }

	T* AllocateTwoPhasePre(size_type numBytes = sizeof(T))
	{
#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1
		TemporaryBlock* block;
		ion::temporary::BytePool& temporaryPool = ion::Thread::GetTemporaryPool();
		ion::temporary::BytePage<temporary::MaxPageSize>* page = temporaryPool.GetPage(numBytes + HeaderSize);
		if (page)
		{
			block = reinterpret_cast<TemporaryBlock*>(page->Peek());
			block->mPage = page;
		}
		else
		{
			block = reinterpret_cast<TemporaryBlock*>(BackupAllocator::AllocateRaw(numBytes + HeaderSize, temporary::MaxAlign));
			if (!block)
			{
				return nullptr;
			}
			block->mPage = nullptr;
		}
	#if ION_BUILD_DEBUG
		block->mSize = numBytes;
	#endif
		return AssumeAligned<T, temporary::MaxAlign>(reinterpret_cast<T*>(&block->mData));
#else
		ion::GlobalAllocator<T> allocator;
		return AssumeAligned<T, alignof(T)>((T*)(allocator.AllocateRaw(numBytes)));
#endif
	}

	bool AllocateTwoPhasePost([[maybe_unused]] T* ptr, [[maybe_unused]] size_type numBytes)
	{
#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1
		TemporaryBlock& block = *reinterpret_cast<TemporaryBlock*>(reinterpret_cast<char*>(ptr) - HeaderSize);
		if (block.mPage)
		{
			block.mPage->Acquire(uint32_t(numBytes + HeaderSize));
	#if ION_BUILD_DEBUG
			block.mSize = numBytes;
	#endif
			return true;
		}
		return false;
#else
		return false;
#endif
	}

	T* AllocateRaw(size_type numBytes, [[maybe_unused]] size_t alignment = alignof(T))
	{
#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1
		ION_ASSERT_FMT_IMMEDIATE(alignment <= temporary::MaxAlign, "Unsupported alignment");
		ion::temporary::BytePool& temporaryPool = ion::Thread::GetTemporaryPool();
		ion::temporary::BytePage<temporary::MaxPageSize>* page = temporaryPool.GetPage(numBytes + HeaderSize);

		TemporaryBlock* block;
		if (page)
		{
			block = reinterpret_cast<TemporaryBlock*>(page->Peek());
			page->Acquire(uint32_t(numBytes + HeaderSize));
			block->mPage = page;
		}
		else
		{
			block = reinterpret_cast<TemporaryBlock*>(BackupAllocator::AllocateRaw(numBytes + HeaderSize, alignment));
			if (!block)
			{
				return nullptr;
			}
			block->mPage = nullptr;
		}
	#if ION_BUILD_DEBUG
		block->mSize = numBytes;
	#endif
		return ion::AssumeAligned(reinterpret_cast<T*>(&block->mData));
#else
		ION_ASSERT(alignment == alignof(T), "alignment not supported");
		ion::GlobalAllocator<T> allocator;
		return (T*)(allocator.AllocateRaw(numBytes));
#endif
	}

	inline void DeallocateRaw(void* ptr, [[maybe_unused]] size_type n, [[maybe_unused]] size_t alignment = alignof(T))
	{
#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1
		TemporaryBlock* block = reinterpret_cast<TemporaryBlock*>(reinterpret_cast<char*>(ptr) - HeaderSize);
	#if ION_BUILD_DEBUG
		ION_ASSERT_FMT_IMMEDIATE(block->mSize == n, "Invalid deallocation;size=%zu;expected=%zu", n, block->mSize);
		memset(ptr, 0xDA, n);
	#endif
		if (block->mPage != nullptr)
		{
			block->mPage->Release(uint32_t(n + HeaderSize));
			// Block is now invalid, pool can be also invalid if deiniting allocator.
		}
		else
		{
			BackupAllocator::DeallocateRaw(block, n + HeaderSize);
		}
#else
		ion::GlobalAllocator<T> allocator;
		allocator.DeallocateRaw(ptr, n);
#endif
	}

	inline void Deallocate(T* ptr, [[maybe_unused]] size_type n) { DeallocateRaw(ptr, sizeof(T) * n); }

	// STL interface
	[[nodiscard]] inline T* allocate(size_type num) { return Allocate(num); }
	inline void deallocate(T* p, size_type num) { Deallocate(p, num); }
	template <typename U>
	inline void deallocate(U* p, size_type num)
	{
		DeallocateRaw(p, sizeof(U) * num);
	}

private:
};
}  // namespace ion
