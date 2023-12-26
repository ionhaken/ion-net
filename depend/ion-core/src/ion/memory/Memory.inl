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

#include <ion/container/Array.h>
#include <ion/container/UnorderedMap.h>

#include <ion/debug/MemoryTracker.h>
#include <ion/debug/Profiling.h>

#include <ion/memory/GlobalMemoryPool.h>
#include <ion/memory/Memory.h>
#include <ion/memory/MonotonicBufferResource.h>
#include <ion/memory/NativeAllocator.h>

#include <ion/concurrency/Thread.h>

#include <ion/jobs/BaseJob.h>

#include <atomic>
#include <ion/Base.h>
#include <ion/core/Engine.h>

#if ION_PLATFORM_MICROSOFT
	#define ION_TARGET_PLATFORM 1
#else
	#define ION_TARGET_PLATFORM 0
#endif

#define ION_USE_DEBUG_ALLOC (!ION_CONFIG_MEMORY_RESOURCES && !ION_MEMORY_TRACKER && ION_TARGET_PLATFORM && ION_BUILD_DEBUG)

namespace ion
{

namespace detail
{
ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* NativeMalloc(size_t size) /*
																		 * GCC does not allow '__malloc__' attribute in this position on a
																		 * function definition [-Wgcc-compat] ION_ATTRIBUTE_MALLOC*/
{
	ION_PROFILER_SCOPE(Memory, "Memory alloc");
#if ION_USE_DEBUG_ALLOC
	return _malloc_dbg(size, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
	return malloc(size);
#endif
}

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* NativeRealloc(void* ptr, size_t size)
{
	ION_PROFILER_SCOPE(Memory, "Memory realloc");
	return realloc(ptr, size);
}

void NativeFree(void* pointer)
{
	ION_PROFILER_SCOPE(Memory, "Memory free");
	free(pointer);
}

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* Malloc(size_t size,
													 size_t alignment) /*
																		* GCC does not allow '__malloc__' attribute in this position on a
																		* function definition [-Wgcc-compat] ION_ATTRIBUTE_MALLOC*/
{
	ION_PROFILER_SCOPE(Memory, "Memory alloc");
#if ION_CONFIG_GLOBAL_MEMORY_POOL
	return GlobalMemoryAllocate(Thread::GetId(), size, alignment);
#else
	return ion::NativeAlignedMalloc(size, alignment);
#endif
}

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* Realloc(void* ptr, size_t size)
{
	ION_PROFILER_SCOPE(Memory, "Memory realloc");
#if ION_CONFIG_GLOBAL_MEMORY_POOL
	return GlobalMemoryReallocate(Thread::GetId(), ptr, size);
#else
	return ion::NativeRealloc(ptr, size);
#endif
}

void Free(void* ptr)
{
	ION_PROFILER_SCOPE(Memory, "Memory free");
#if ION_CONFIG_GLOBAL_MEMORY_POOL
	GlobalMemoryDeallocate(Thread::GetId(), ptr);
#else
	ion::NativeAlignedFree(ptr);
#endif
}

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* NativeAlignedMalloc(size_t size, size_t alignment)
{
	ION_PROFILER_SCOPE(Memory, "Memory aligned alloc");
#if ION_USE_DEBUG_ALLOC
	return _aligned_malloc_dbg(size, alignment, __FILE__, __LINE__);
#elif ION_PLATFORM_APPLE || ION_PLATFORM_LINUX
	void* pointer;
	posix_memalign(&pointer, alignment, size);
	ION_ASSERT(pointer, "Out of memory");
	return pointer;
#elif ION_PLATFORM_MICROSOFT
	return _aligned_malloc(size, alignment);
#else
	void* p1;	// original block
	void** p2;	// aligned block
	int offset = alignment - 1 + sizeof(void*);
	if ((p1 = (void*)malloc(size + offset)) == nullptr)
	{
		ION_ASSERT(false, "Out of memory");
		return nullptr;
	}
	p2 = (void**)(((size_t)(p1) + offset) & ~(alignment - 1));
	p2[-1] = p1;
	return p2;
#endif
}

void NativeAlignedFree(void* pointer)
{
	ION_PROFILER_SCOPE(Memory, "Memory aligned free");
#if ION_USE_DEBUG_ALLOC
	_aligned_free_dbg(pointer);
#elif ION_PLATFORM_APPLE || ION_PLATFORM_LINUX
	free(pointer);
#elif ION_PLATFORM_MICROSOFT
	_aligned_free(pointer);
#else
	free(((void**)pointer)[-1]);
#endif
}

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* NativeAlignedRealloc(void* ptr, size_t size, size_t oldSize, size_t alignment)
{
	ION_PROFILER_SCOPE(Memory, "Memory aligned realloc");
	void* newPtr = NativeAlignedMalloc(size, alignment);
	if (newPtr)
	{
		memcpy(newPtr, ptr, oldSize);
		NativeAlignedFree(ptr);
	}
	return newPtr;
}

#if ION_MEMORY_TRACKER

uint16_t GetMemoryTag()
{
	if (ion::Thread::GetCurrentJob() == nullptr)
	{
		return ion::Thread::MemoryTag();
	}
	return ion::Thread::GetCurrentJob()->Tag();
}

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* TrackedMalloc(size_t size, size_t alignment, MemTag tag)
{
	return ion::memory_tracker::OnAlignedAllocation(Malloc(ion::memory_tracker::AlignedAllocationSize(size, alignment), alignment), size,
													alignment, tag, ion::memory_tracker::Layer::Global);
}

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* TrackedRealloc(void* pointer, size_t size, MemTag tag)
{
	uint32_t alignment;
	void* actualPtr = ion::memory_tracker::OnAlignedDeallocation(pointer, alignment, ion::memory_tracker::Layer::Global);
	size_t newAllocationSize = ion::memory_tracker::AlignedAllocationSize(size, alignment);
	return ion::memory_tracker::OnAlignedAllocation(Realloc(actualPtr, newAllocationSize), size, alignment, tag,
													ion::memory_tracker::Layer::Global);
}

void TrackedFree(void* pointer, MemTag)
{
	ION_ASSERT(pointer, "Invalid free");
	uint32_t alignment;
	void* actualPtr = ion::memory_tracker::OnAlignedDeallocation(pointer, alignment, ion::memory_tracker::Layer::Global);
	Free(actualPtr);
}

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* TrackedNativeMalloc(size_t size, MemTag tag)
{
	return ion::memory_tracker::OnAllocation(NativeMalloc(ion::memory_tracker::AllocationSize(size)), size, tag,
											 ion::memory_tracker::Layer::Native);
}

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* TrackedNativeRealloc(void* pointer, size_t size, MemTag tag)
{
	void* actualPtr = ion::memory_tracker::OnDeallocation(pointer, ion::memory_tracker::Layer::Native);
	return ion::memory_tracker::OnAllocation(NativeRealloc(actualPtr, ion::memory_tracker::AllocationSize(size)), size, tag,
											 ion::memory_tracker::Layer::Native);
}

void TrackedNativeFree(void* pointer, MemTag)
{
	NativeFree(ion::memory_tracker::OnDeallocation(pointer, ion::memory_tracker::Layer::Native));
}

ION_RESTRICT_RETURN_VALUE void* TrackedNativeAlignedMalloc(size_t size, size_t alignment, MemTag tag)
{
	return ion::memory_tracker::OnAlignedAllocation(
	  NativeAlignedMalloc(ion::memory_tracker::AlignedAllocationSize(size, alignment), alignment), size, alignment, tag,
	  ion::memory_tracker::Layer::Native);
}

ION_RESTRICT_RETURN_VALUE void* TrackedNativeAlignedRealloc(void* ptr, size_t size, size_t oldSize, size_t alignment, MemTag tag)
{
	return ion::memory_tracker::OnAlignedAllocation(
	  NativeAlignedRealloc(ptr, ion::memory_tracker::AlignedAllocationSize(size, alignment),
						   ion::memory_tracker::AlignedAllocationSize(oldSize, alignment), alignment),
	  size, alignment, tag, ion::memory_tracker::Layer::Native);
}

void TrackedNativeAlignedFree(void* pointer, MemTag)
{
	uint32_t alignment;
	void* actualPtr = ion::memory_tracker::OnAlignedDeallocation(pointer, alignment, ion::memory_tracker::Layer::Native);
	NativeAlignedFree(actualPtr);
}
#endif

}  // namespace detail

}  // namespace ion

#if ION_CONFIG_GLOBAL_MEMORY_POOL || ION_MEMORY_TRACKER
[[nodiscard]] void* operator new(std::size_t s) noexcept(false)
{
	#if ION_MEMORY_TRACKER
	return ion::detail::TrackedMalloc(s, ion::detail::StdAlignment<uint8_t>(), ion::detail::GetMemoryTag());
	#else
	return ion::detail::Malloc(s, ion::detail::StdAlignment<uint8_t>());
	#endif
}

[[nodiscard]] void* operator new[](std::size_t s) noexcept(false)
{
	#if ION_MEMORY_TRACKER
	return ion::detail::TrackedMalloc(s, ion::detail::StdAlignment<uint8_t>(), ion::detail::GetMemoryTag());
	#else
	return ion::detail::Malloc(s, ion::detail::StdAlignment<uint8_t>());
	#endif
}

void operator delete(void* p) noexcept
{
	if (p)
	{
	#if ION_MEMORY_TRACKER
		return ion::detail::TrackedFree(p, ion::detail::GetMemoryTag());
	#else
		return ion::detail::Free(p);
	#endif
	}
}

void operator delete(void* p, size_t) noexcept
{
	if (p)
	{
	#if ION_MEMORY_TRACKER
		return ion::detail::TrackedFree(p, ion::detail::GetMemoryTag());
	#else
		return ion::detail::Free(p);
	#endif
	}
}

void operator delete[](void* p) noexcept
{
	if (p)
	{
	#if ION_MEMORY_TRACKER
		return ion::detail::TrackedFree(p, ion::detail::GetMemoryTag());
	#else
		return ion::detail::Free(p);
	#endif
	}
}

	#if (__cplusplus >= 201703L)
[[nodiscard]] void* operator new(std::size_t n, std::align_val_t align) noexcept(false)
{
		#if ION_MEMORY_TRACKER
	return ion::detail::TrackedMalloc(n, static_cast<size_t>(align), ion::detail::GetMemoryTag());
		#else
	return ion::detail::Malloc(n, static_cast<size_t>(align));
		#endif
}

[[nodiscard]] void* operator new[](std::size_t n, std::align_val_t align) noexcept(false)
{
		#if ION_MEMORY_TRACKER
	return ion::detail::TrackedMalloc(n, static_cast<size_t>(align), ion::detail::GetMemoryTag());
		#else
	return ion::detail::Malloc(n, static_cast<size_t>(align));
		#endif
}

void operator delete(void* const p, std::align_val_t const) noexcept
{
		#if ION_MEMORY_TRACKER
	return ion::detail::TrackedFree(p, ion::detail::GetMemoryTag());
		#else
	return ion::detail::Free(p);
		#endif
}
	#endif
#endif
