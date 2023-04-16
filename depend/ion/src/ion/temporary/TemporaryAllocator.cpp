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
#include <ion/temporary/TemporaryAllocator.h>
#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1
	#include <ion/concurrency/Mutex.h>
	#include <ion/container/ForEach.h>
	#include <ion/container/Vector.h>

	#include <ion/memory/AllocatorTraits.h>
	#include <ion/memory/UniquePtr.h>

	#include <ion/hw/CPU.inl>

namespace ion
{
namespace temporary
{
using PageAllocator = GlobalAllocator<BytePage<BytePool::TSize>>;
namespace
{

struct PoolRegistry
{
	ion::Mutex mPoolRegistryMutex;
	ion::Vector<ion::CorePtr<BytePool>, ion::CoreAllocator<ion::CorePtr<BytePool>>> mEntries;
	#if ION_TEMPORARY_MEMORY_STATS
	std::atomic<size_t> mTotalBytesAllocated = 0;
	std::atomic<size_t> mTotalBytesInPages = 0;
	std::atomic<size_t> mNumLockedOut = 0;
	std::atomic<size_t> mNumOutOfPages = 0;
	std::atomic<size_t> mNumTooLarge = 0;
	std::atomic<size_t> mOutOfMemory = 0;
	#endif
};

static PoolRegistry* mPoolRegistry = nullptr;
}  // namespace

	#if ION_TEMPORARY_MEMORY_STATS
void StatBytesAllocated(size_t s) { mPoolRegistry->mTotalBytesAllocated += s; }
void StatBytesInPages(size_t s) { mPoolRegistry->mTotalBytesInPages += s; }
void StatFailedOutOfPages() { mPoolRegistry->mNumOutOfPages++; }
void StatFailedLocked() { mPoolRegistry->mNumLockedOut++; }
void StatFailedTooLarge() { mPoolRegistry->mNumTooLarge++; }
void StatOutOfMemory() { mPoolRegistry->mOutOfMemory++; }
	#endif


namespace
{
void TryPurgePool(CorePtr<BytePool>* iter)
{
	BytePool* pool = iter->Get();
	if (pool->CanPurge())
	{
		pool->Purge();
		ion::DeleteCorePtr(*iter);
		ion::UnorderedErase(mPoolRegistry->mEntries, iter);
	}
}
}


BytePool* ThreadInit()
{
	ION_ASSERT(mPoolRegistry != nullptr, "Temporary memory allocation not initialized");
	ion::AutoLock<ion::Mutex> lock(mPoolRegistry->mPoolRegistryMutex);
	ion::CorePtr<BytePool> pool(ion::MakeCorePtr<BytePool>());
	ION_CHECK_FATAL(pool.Get(), "Fatal: Out of memory for thread temporary memory");
	mPoolRegistry->mEntries.Add(std::move(pool));
	return mPoolRegistry->mEntries.Back().Get();
}

void ThreadDeinit(BytePool* pool)
{
	ion::AutoLock<ion::Mutex> lock(mPoolRegistry->mPoolRegistryMutex);
	auto iter = ion::FindIf(mPoolRegistry->mEntries, [&](auto& elem) { return elem.Get() == pool; });
	ION_ASSERT(iter != mPoolRegistry->mEntries.End(), "Purged too early");
	pool->MarkRemoving();
	TryPurgePool(iter);
}

void ThreadDeferDeinit(BytePool* pool)
{
	ion::AutoLock<ion::Mutex> lock(mPoolRegistry->mPoolRegistryMutex);
	auto iter = ion::FindIf(mPoolRegistry->mEntries, [&](auto& elem) { return elem.Get() == pool; });
	if (iter != mPoolRegistry->mEntries.End())	// If not found, was already purged by other thread
	{
		TryPurgePool(iter);
	}
}



BytePool::BytePool() : mDefaultPage(this), mCurrentPage(&mDefaultPage)
{
	mCurrentPage->mTotalProduced = 0;
	mCurrentPage->mTotalConsumed = 0;
	mCurrentPage->mBufferPos = 0;
	ion::temporary::StatBytesInPages(sizeof(BytePage<TSize>));
}

BytePool::~BytePool() { ION_ASSERT_FMT_IMMEDIATE(mDefaultPage.mNextPage == nullptr, "Leaking memory"); }

void BytePool::Purge()
{
	PageAllocator allocator;
	BytePage<TSize>* nextPage = mDefaultPage.mNextPage;
	while (nextPage != nullptr)
	{
		ION_ASSERT_FMT_IMMEDIATE(nextPage->mIsRemoving, "Page is not marked for removal");
		ION_ASSERT_FMT_IMMEDIATE(nextPage->mTotalConsumed == nextPage->mTotalProduced, "Page is not complete");
		auto current = nextPage;
		nextPage = nextPage->mNextPage;
		ion::Destroy(allocator, current);
	}
	mDefaultPage.mNextPage = nullptr;
}

void BytePool::MarkRemoving()
{
	mDefaultPage.mIsRemoving = true;
	BytePage<TSize>* nextPage = mDefaultPage.mNextPage;
	while (nextPage != nullptr)
	{
		nextPage->mIsRemoving = true;
		nextPage = nextPage->mNextPage;
	}
}

bool BytePool::CanPurge()
{
	bool canPurge = mDefaultPage.mTotalConsumed == mDefaultPage.mTotalProduced;
	BytePage<TSize>* nextPage = mDefaultPage.mNextPage;
	while (nextPage != nullptr)
	{
		canPurge &= nextPage->mTotalConsumed == nextPage->mTotalProduced;
		nextPage = nextPage->mNextPage;
	}
	return canPurge;
}

BytePage<BytePool::TSize>* BytePool::GetNextPage()
{
	int pageCount = 1;
	BytePage<TSize>* nextPage = &mDefaultPage;
	while (nextPage->mTotalProduced != nextPage->mTotalConsumed)
	{
		ION_ASSERT_FMT_IMMEDIATE(!nextPage->mIsRemoving, "Page is not marked for removal");
		nextPage = nextPage->mNextPage;
		if (nextPage == nullptr)
		{
			if (pageCount >= MaxPagesPerThread)
			{
				ion::temporary::StatFailedOutOfPages();
	#if (ION_ASSERTS_ENABLED == 1)
				if constexpr (AssertPageLimit)
				{
					ION_ASSERT_FMT_IMMEDIATE(false, "Max page count reached");
				}
	#endif
				return nullptr;
			}

			ION_MEMORY_SCOPE(ion::tag::Temporary);
			PageAllocator allocator;
			nextPage = ion::Construct(allocator, this);
			if (nextPage)
			{
				ion::temporary::StatBytesInPages(sizeof(BytePage<TSize>));
				nextPage->mNextPage = mDefaultPage.mNextPage;
				mDefaultPage.mNextPage = nextPage;
				break;
			}
			else
			{
				ion::temporary::StatOutOfMemory();
				return nullptr;
			}
		}
		pageCount++;
	}
	nextPage->mTotalProduced = 0;
	nextPage->mTotalConsumed = 0;
	#if ION_BUILD_DEBUG
	memset(nextPage->mBuffer, 0xCD, nextPage->mBufferPos);
	#endif
	nextPage->mBufferPos = 0;
	mCurrentPage = nextPage;
	return mCurrentPage;
}

}  // namespace temporary

void TemporaryInit()
{
	ion::MemoryScope memoryScope(ion::tag::Core);
	temporary::mPoolRegistry = new temporary::PoolRegistry();
	ION_CHECK_FATAL(temporary::mPoolRegistry, "Fatal: Out of memory for temporary memory pool");
}

void TemporaryDeinit()
{
	#if ION_CLEAN_EXIT
	ION_ASSERT_FMT_IMMEDIATE(temporary::mPoolRegistry->mEntries.IsEmpty(), "Leaking temporary memory");

	#if ION_TEMPORARY_MEMORY_STATS
	ION_LOG_FMT_IMMEDIATE("Temporary memory: Total %f MBytes allocated",
						  (float)(temporary::mPoolRegistry->mTotalBytesAllocated) / 1024 / 1024);
	ION_LOG_FMT_IMMEDIATE("Temporary memory: Total %f MBytes in pages",
						  (float)(temporary::mPoolRegistry->mTotalBytesInPages) / 1024 / 1024);
	ION_LOG_FMT_IMMEDIATE("Temporary memory: %zu times locked out", size_t(temporary::mPoolRegistry->mNumLockedOut));
	ION_LOG_FMT_IMMEDIATE("Temporary memory: %zu times out of pages", size_t(temporary::mPoolRegistry->mNumOutOfPages));
	ION_LOG_FMT_IMMEDIATE("Temporary memory: %zu times out of space", size_t(temporary::mPoolRegistry->mNumTooLarge));
	ION_LOG_FMT_IMMEDIATE("Temporary memory: %zu times out of memory", size_t(temporary::mPoolRegistry->mOutOfMemory));
	#endif
	ion::MemoryScope memoryScope(ion::tag::Core);
	delete temporary::mPoolRegistry;
	temporary::mPoolRegistry = nullptr;
	#endif
}
}  // namespace ion
#endif
