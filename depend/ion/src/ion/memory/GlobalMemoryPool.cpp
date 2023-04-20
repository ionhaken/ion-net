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

#include <ion/Base.h>
#if ION_CONFIG_GLOBAL_MEMORY_POOL
	#include <ion/container/Array.h>
	#include <ion/container/ForEach.h>

	#include <ion/memory/GlobalMemoryPool.h>
	#include <ion/memory/NativeAllocator.h>
	#include <ion/memory/TLSFResource.h>

	#include <ion/concurrency/MPSCQueue.h>
	#include <ion/concurrency/Mutex.h>

	#include <ion/core/Engine.h>

namespace ion
{

namespace
{

constexpr size_t NumBuckets = 512;
constexpr size_t NumElemsPerBucket = 512;

constexpr size_t MaxGlobalMemoryBlockSize = 128 * 1024;

struct Resource
{
	#if ION_CONFIG_MEMORY_RESOURCES == 1
	TLSFResource<MonotonicBufferResource<64 * 1024, ion::tag::External, ion::NativeAllocator<uint8_t>>, ion::tag::External> mTLSF;
	#endif
	MPSCQueue<void*, ion::NativeAllocator<char>> mFreeElems;

	inline void* Allocate(size_t size)
	{
	#if ION_CONFIG_MEMORY_RESOURCES == 1
		return mTLSF.Allocate(size, 8);
	#else
		return ion::NativeMalloc(size);
	#endif
	}

	inline void* Reallocate(void* ptr, size_t size)
	{
	#if ION_CONFIG_MEMORY_RESOURCES == 1
		return mTLSF.Reallocate(ptr, size);
	#else
		return ion::NativeRealloc(ptr, size);
	#endif
	}

	inline void Deallocate(void* ptr, [[maybe_unused]] size_t size)
	{
	#if ION_CONFIG_MEMORY_RESOURCES == 1
		mTLSF.Deallocate(ptr, size);
	#else
		return ion::NativeFree(ptr);
	#endif
	}

	inline void DeferDeallocate(void* ptr) { mFreeElems.Enqueue(ptr); }

	~Resource() {}

	void ProcessDeferDeallocations()
	{
		mFreeElems.DequeueAll([&](void* elem) { Deallocate(elem, 0); });
	}
};

template <typename T, class... Args>
[[nodiscard]] constexpr T* Construct(Args&&... args)
{
	memory_tracker::TrackStatic(sizeof(T), ion::tag::External);
	return new (static_cast<void*>(NativeAllocator<T>().allocate(1))) T(std::forward<Args>(args)...);
}

template <typename T>
constexpr void Destroy(T* p)
{
	memory_tracker::UntrackStatic(sizeof(T), ion::tag::External);
	p->~T();
	NativeAllocator<T>().deallocate(p, 1);
}

struct Bucket
{
	Bucket()
	{
		ion::ForEach(mResources, [](Resource*& elem) { elem = nullptr; });
	}
	~Bucket()
	{
		ion::ForEach(mResources,
					 [&](Resource*& resource)
					 {
						 if (resource)
						 {
							 Destroy(resource);
						 }
					 });
	}
	ion::Array<Resource*, NumElemsPerBucket> mResources;
};

struct Pool
{
	ion::Array<Bucket*, NumBuckets> mTlPool;
	Pool()
	{
		ion::ForEach(mTlPool, [](Bucket*& elem) { elem = nullptr; });
	}

	~Pool()
	{
		ion::ForEach(mTlPool,
					 [](Bucket*& elem)
					 {
						 if (elem)
						 {
							 Destroy(elem);
						 }
					 });
	}
};

struct BlockHeader
{
	uint32_t mSize;
	uint16_t mThreadId;
	uint8_t mAlignment;
	uint8_t mOffset;  // #TODO: Offset is avail from alignment
};

void* InitBlock(void* ptr, size_t size, size_t alignment, uint16_t blockThreadIndex)
{
	void* userPtr = AlignAddress(static_cast<BlockHeader*>(ptr) + 1, alignment);
	size_t offset(reinterpret_cast<char*>(userPtr) - reinterpret_cast<char*>(ptr));

	BlockHeader* headerPtr = static_cast<BlockHeader*>(userPtr) - 1;

	headerPtr->mSize = ion::SafeRangeCast<uint32_t>(size);
	headerPtr->mOffset = ion::SafeRangeCast<uint8_t>(offset);

	headerPtr->mThreadId = blockThreadIndex;
	headerPtr->mAlignment = ion::SafeRangeCast<uint8_t>(alignment / 8);
	return userPtr;
}

static Mutex gPoolMutex;
static Pool* gPool;
	#if ION_CLEAN_EXIT
static std::atomic<int64_t> gNumAllocations;
	#endif

}  // namespace

void GlobalMemoryInit()
{
	gPool = Construct<Pool>();
	#if ION_CLEAN_EXIT
	gNumAllocations = 0;
	#endif
}

void GlobalMemoryThreadInit(UInt index)
{
	UInt elemIndex = index % NumElemsPerBucket;
	UInt bucketIndex = index / NumElemsPerBucket;
	if (!gPool->mTlPool[bucketIndex])
	{
		AutoLock<Mutex> lock(gPoolMutex);
		if (!gPool->mTlPool[bucketIndex])
		{
			gPool->mTlPool[bucketIndex] = Construct<Bucket>();
		}
	}

	if (!gPool->mTlPool[bucketIndex]->mResources[elemIndex])
	{
		gPool->mTlPool[bucketIndex]->mResources[elemIndex] = Construct<Resource>();
	}
}

void GlobalMemoryThreadDeinit(UInt index)
{
	UInt elemIndex = index % NumElemsPerBucket;
	UInt bucketIndex = index / NumElemsPerBucket;
	gPool->mTlPool[bucketIndex]->mResources[elemIndex]->ProcessDeferDeallocations();
}

void GlobalMemoryDeinit()
{
	#if ION_CLEAN_EXIT
	AutoLock<Mutex> lock(gPoolMutex);
	if (gPool)
	{
		ion::ForEach(gPool->mTlPool,
					 [](Bucket*& elem)
					 {
						 if (elem)
						 {
							 ion::ForEach(elem->mResources,
										  [&](Resource* resource)
										  {
											  if (resource)
											  {
												  resource->ProcessDeferDeallocations();
											  }
										  });
						 }
					 });

		if (gNumAllocations <= 0)
		{
			Destroy(gPool);
			gPool = nullptr;
			ion::memory_tracker::PrintStats(true, ion::memory_tracker::Layer::Invalid);
		}
		else
		{
			// ION_LOG_FMT_IMMEDIATE("Delaying memory purge; %li allocations left in global memory pool", long(gNumAllocations));
			ion::memory_tracker::PrintStats(true, ion::memory_tracker::Layer::Global);
		}
	}
	#endif
}

void* GlobalMemoryAllocate(UInt index, size_t size, size_t alignment)
{
	ION_ASSERT_FMT_IMMEDIATE(alignment >= sizeof(BlockHeader), "Invalid alignment");
	size_t allocationSize = size + alignment;
	void* ptr;

	UInt blockThreadIndex = index;

	if (size <= MaxGlobalMemoryBlockSize && index != UInt(-1))
	{
		UInt elemIndex = index % NumElemsPerBucket;
		UInt bucketIndex = index / NumElemsPerBucket;

		gPool->mTlPool[bucketIndex]->mResources[elemIndex]->ProcessDeferDeallocations();
		ptr = gPool->mTlPool[bucketIndex]->mResources[elemIndex]->Allocate(allocationSize);
	#if ION_CLEAN_EXIT
		gNumAllocations++;
	#endif
	}
	else
	{
		ptr = ion::NativeMalloc(allocationSize);
		blockThreadIndex = UInt(-1);
	}
	if (!ptr)
	{
		NotifyOutOfMemory();
		return nullptr;
	}

	return InitBlock(ptr, size, alignment, uint16_t(blockThreadIndex));
}

void GlobalMemoryDeallocate(UInt index, void* userPtr)
{
	if (userPtr == nullptr)
	{
		return;
	}
	BlockHeader* headerPtr = static_cast<BlockHeader*>(userPtr) - 1;
	void* ptr = static_cast<char*>(userPtr) - headerPtr->mOffset;
	if (headerPtr->mThreadId == uint16_t(-1))
	{
		ion::NativeFree(ptr);
	}
	else
	{
		UInt elemIndex = headerPtr->mThreadId % NumElemsPerBucket;
		UInt bucketIndex = headerPtr->mThreadId / NumElemsPerBucket;
		if (headerPtr->mThreadId == index)
		{
			gPool->mTlPool[bucketIndex]->mResources[elemIndex]->Deallocate(ptr, 0);
		}
		else
		{
			gPool->mTlPool[bucketIndex]->mResources[elemIndex]->DeferDeallocate(ptr);
		}

	#if ION_CLEAN_EXIT
		gNumAllocations--;
		if (gNumAllocations == 0 &&
			// Early deinit only when doing dynamic exit
			ion::Engine::IsDynamicInitExit() && ion::Engine::IsDynamicInitDone())
		{
		#if ION_MEMORY_TRACKER
			ION_LOG_IMMEDIATE("External memory freed.");
		#endif
			GlobalMemoryDeinit();
		}
	#endif
	}
}

void* GlobalMemoryReallocate(UInt threadIndex, void* userPtr, size_t size)
{
	BlockHeader* headerPtr = static_cast<BlockHeader*>(userPtr) - 1;
	void* ptr = static_cast<char*>(userPtr) - headerPtr->mOffset;
	uint8_t alignment = headerPtr->mAlignment;
	ION_ASSERT_FMT_IMMEDIATE(headerPtr->mAlignment * 8 <= 16, "Invalid alignment for realloc");
	if (headerPtr->mThreadId == uint16_t(-1))
	{
		threadIndex = uint16_t(-1);
		ptr = ion::NativeRealloc(ptr, size + alignment);
		if (!ptr)
		{
			NotifyOutOfMemory();
			return nullptr;
		}
		userPtr = InitBlock(ptr, size, alignment * 8, uint16_t(-1));
	}
	else
	{
		UInt elemIndex = threadIndex % NumElemsPerBucket;
		UInt bucketIndex = threadIndex / NumElemsPerBucket;
		gPool->mTlPool[bucketIndex]->mResources[elemIndex]->ProcessDeferDeallocations();

		if (headerPtr->mThreadId == threadIndex && size <= MaxGlobalMemoryBlockSize)
		{
			ptr = gPool->mTlPool[bucketIndex]->mResources[elemIndex]->Reallocate(ptr, size + alignment);
			if (!ptr)
			{
				NotifyOutOfMemory();
				return nullptr;
			}
			userPtr = InitBlock(ptr, size, alignment * 8, uint16_t(threadIndex));
		}
		else
		{
			size_t oldBlockSize = headerPtr->mSize;
			void* newUserPtr = GlobalMemoryAllocate(threadIndex, size, alignment * 8);
			if (!newUserPtr)
			{
				NotifyOutOfMemory();
				return nullptr;
			}
			memcpy((char*)newUserPtr, (char*)userPtr, oldBlockSize);
			GlobalMemoryDeallocate(threadIndex, userPtr);
			userPtr = newUserPtr;
		}
	}
	return userPtr;
}

}  // namespace ion
#endif
