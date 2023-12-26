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

#include <cstddef>
#include <ion/Base.h>
#include <ion/tracing/Log.h>
#if ION_PLATFORM_APPLE || ION_PLATFORM_LINUX
	#include <stdlib.h>
#endif

#if ION_PLATFORM_MICROSOFT && ION_BUILD_DEBUG
	#include <crtdbg.h>
#endif

#if ION_COMPILER_MSVC 
	#include <memory> // std::assume_aligned
#endif

#define ION_ALIGNED_MALLOC(__size, __alignment) ion::AlignedMalloc(__size, __alignment, __FILE__, __LINE__)
#define ION_ALIGNED_FREE(__pointer)				ion::AlignedFree(__pointer)
#define ION_ALIGN_CLASS(__name)                                                    \
	[[nodiscard]] static inline void* operator new(size_t size) noexcept           \
	{                                                                              \
		return ION_ALIGNED_MALLOC(size, alignof(__name));                          \
	}                                                                              \
	[[nodiscard]] static inline void* operator new[](size_t size) noexcept         \
	{                                                                              \
		return ION_ALIGNED_MALLOC(size, alignof(__name));                          \
	}                                                                              \
	[[nodiscard]] static inline void* operator new(size_t, void* place) noexcept   \
	{                                                                              \
		return place;                                                              \
	}                                                                              \
	[[nodiscard]] static inline void* operator new[](size_t, void* place) noexcept \
	{                                                                              \
		return place;                                                              \
	}                                                                              \
	static inline void operator delete(void* obj) noexcept                         \
	{                                                                              \
		ION_ALIGNED_FREE(obj);                                                     \
	}                                                                              \
	static inline void operator delete[](void* obj) noexcept                       \
	{                                                                              \
		ION_ALIGNED_FREE(obj);                                                     \
	}                                                                              \
	static inline void operator delete(void* /*obj*/, void* /*place*/) noexcept    \
	{                                                                              \
	}                                                                              \
	static inline void operator delete[](void* /*obj*/, void* /*place*/) noexcept  \
	{                                                                              \
	}

namespace ion
{
using MemTag = uint16_t;

namespace tag
{
const MemTag IgnoreLeaks = 0;
const MemTag Unset = 1;
const MemTag Temporary = 2;	// Temporary and stack allocators, object pool
const MemTag Core = 3;
const MemTag Network = 4;
const MemTag Profiling = 5;
const MemTag Test = 6;
const MemTag Gameplay = 7;
const MemTag Physics = 8;
const MemTag Rendering = 9;
const MemTag External = 10;
const MemTag Online = 11;
const MemTag UI = 12;
const MemTag Audio = 13;
const MemTag NodeGraph = 14;
const MemTag Debug = 15;
const MemTag Count = 16;

#if ION_MEMORY_TRACKER
inline const char* Name(MemTag tag)
{
	switch (tag)
	{
	case IgnoreLeaks:
		return "Ignored";
	case Unset:
		return "Unset";
	case Temporary:
		return "Temporary";
	case Core:
		return "Core";
	case Network:
		return "Network";
	case Profiling:
		return "Profiling";
	case Test:
		return "Test";
	case Gameplay:
		return "Gameplay";
	case Physics:
		return "Physics";
	case Rendering:
		return "Rendering";
	case External:
		return "External";
	case Online:
		return "Online";
	case UI:
		return "UI";
	case Audio:
		return "Audio";
	case NodeGraph:
		return "NodeGraph";
	case Debug:
		return "Debug";
	case Count:
		return "Total";
	default:
		return "";
	}
}
#endif

}  // namespace tag


namespace detail
{

#if ION_MEMORY_TRACKER
uint16_t GetMemoryTag();

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* TrackedNativeAlignedMalloc(size_t size, size_t alignment, MemTag tag);
ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* TrackedNativeAlignedRealloc(void* ptr, size_t size, size_t oldSize, size_t alignment,
																		  MemTag tag);
void TrackedNativeAlignedFree(void* p, MemTag tag);
ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* TrackedNativeMalloc(size_t size, MemTag tag);
ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* TrackedNativeRealloc(void* ptr, size_t newSize, MemTag tag);
void TrackedNativeFree(void* p, MemTag tag);

#endif

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* NativeAlignedMalloc(size_t size, size_t alignment);
ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* NativeAlignedRealloc(void* ptr, size_t size, size_t oldSize, size_t alignment);
void NativeAlignedFree(void* p);

ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* NativeMalloc(size_t size);
ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* NativeRealloc(void* ptr, size_t size);
void NativeFree(void* p);

template <MemTag Tag>
inline MemTag GetMemoryTagInternal()
{
#if ION_MEMORY_TRACKER
	auto tag = GetMemoryTag();
	if (tag != ion::tag::IgnoreLeaks)
	{
		if constexpr (Tag == tag::Unset)
		{
			return tag;
		}
		else
		{
			return Tag;
		}
	}
#endif
	return ion::tag::IgnoreLeaks;
}


}  // namespace detail

[[nodiscard]] inline ION_RESTRICT_RETURN_VALUE void* NativeMalloc(size_t size)
{
#if ION_MEMORY_TRACKER
	return ion::detail::TrackedNativeMalloc(size, ion::detail::GetMemoryTag());
#else
	return ion::detail::NativeMalloc(size);
#endif
}

inline void* NativeRealloc(void* p, size_t s)
{
#if ION_MEMORY_TRACKER
	return ion::detail::TrackedNativeRealloc(p, s, ion::detail::GetMemoryTag());
#else
	return ion::detail::NativeRealloc(p, s);
#endif
}

inline void NativeFree(void* p)
{
#if ION_MEMORY_TRACKER
	ion::detail::TrackedNativeFree(p, ion::detail::GetMemoryTag());
#else
	ion::detail::NativeFree(p);
#endif
}

[[nodiscard]] inline ION_RESTRICT_RETURN_VALUE void* NativeAlignedMalloc(size_t size, size_t alignment)
{
	ION_ASSERT((alignment != 0) && ((alignment & (alignment - 1)) == 0), "Alignment not power of two");
#if ION_MEMORY_TRACKER
	auto ptr = ion::detail::TrackedNativeAlignedMalloc(size, alignment, ion::detail::GetMemoryTag());
#else
	auto ptr = ion::detail::NativeAlignedMalloc(size, alignment);
#endif
	return ptr;
}

inline void NativeAlignedFree(void* p)
{
#if ION_MEMORY_TRACKER
	ion::detail::TrackedNativeAlignedFree(p, ion::detail::GetMemoryTag());
#else
	ion::detail::NativeAlignedFree(p);
#endif
}


namespace detail
{
// For std containers to work, use for minimum aligment
template <typename T>
constexpr size_t StdAlignment() 
{
	constexpr size_t DefaultStdAlignment = alignof(void*) * 2;
	return DefaultStdAlignment >= alignof(T) ? DefaultStdAlignment : alignof(T);
}


#if ION_MEMORY_TRACKER
ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* TrackedMalloc(size_t size, size_t alignment, MemTag tag);
ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* TrackedRealloc(void* ptr, size_t newSize, MemTag tag);
void TrackedFree(void* p, MemTag tag);

#else
ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* Malloc(size_t size, size_t alignment);
ION_RESTRICT_RETURN_VALUE [[nodiscard]] void* Realloc(void* ptr, size_t size);
void Free(void* p);
#endif
}  // namespace detail

#if ION_MEMORY_TRACKER || !defined(_WIN32) || !ION_BUILD_DEBUG
[[nodiscard]] inline ION_RESTRICT_RETURN_VALUE void* Malloc(size_t size)
{
	#if ION_MEMORY_TRACKER
	return detail::TrackedMalloc(size, detail::StdAlignment<uint8_t>(), ion::detail::GetMemoryTag());
	#else
	return detail::Malloc(size, detail::StdAlignment<uint8_t>());
	#endif
}

[[nodiscard]] inline ION_RESTRICT_RETURN_VALUE void* Realloc(void* ptr, size_t size)
{
	#if ION_MEMORY_TRACKER
	return detail::TrackedRealloc(ptr, size, ion::detail::GetMemoryTag());
	#else
	return detail::Realloc(ptr, size);
	#endif
}

inline void Free(void* pointer)
{
	#if ION_MEMORY_TRACKER
	detail::TrackedFree(pointer, ion::detail::GetMemoryTag());
	#else
	detail::Free(pointer);
	#endif
}

[[nodiscard]] inline ION_RESTRICT_RETURN_VALUE void* AlignedMalloc(size_t size, size_t alignment, const char*, unsigned int)
{
	ION_ASSERT((alignment != 0) && ((alignment & (alignment - 1)) == 0), "Alignment not power of two");
	#if ION_MEMORY_TRACKER
	auto ptr = ion::detail::TrackedMalloc(size, alignment, ion::detail::GetMemoryTag());
	#else
	auto ptr = ion::detail::Malloc(size, alignment);
	#endif
	return ptr;
}

inline void AlignedFree(void* p)
{
	#if ION_MEMORY_TRACKER
	ion::detail::TrackedFree(p, ion::detail::GetMemoryTag());
	#else
	ion::detail::Free(p);
	#endif
}
#else  // Windows memory tracker
[[nodiscard]] inline ION_RESTRICT_RETURN_VALUE void* Malloc(size_t size) { return _malloc_dbg(size, _NORMAL_BLOCK, __FILE__, __LINE__); }

[[nodiscard]] inline ION_RESTRICT_RETURN_VALUE void* Realloc(void* ptr, size_t newSize)
{
	return _realloc_dbg(ptr, newSize, _NORMAL_BLOCK, __FILE__, __LINE__);
}

inline void Free(void* pointer) { _free_dbg(pointer, 1); }

[[nodiscard]] inline ION_RESTRICT_RETURN_VALUE void* AlignedMalloc(size_t size, size_t alignment, const char* file, unsigned int line)
{
	ION_ASSUME_FMT_IMMEDIATE((alignment != 0) && ((alignment & (alignment - 1)) == 0), "Alignment not power of two");
	ION_ASSUME_FMT_IMMEDIATE(alignment >= 16, "Invalid alignment");
	auto* p = _aligned_malloc_dbg(size, alignment, file, line);
	ION_ASSERT_FMT_IMMEDIATE(p, "Out of memory. Requested %zu, %zu bytes;alignment=", size, alignment);
	return p;
}
inline void AlignedFree(void* pointer) { _aligned_free_dbg(pointer); }
#endif

template <typename T, size_t N = alignof(T)>
[[nodiscard]] constexpr T* const AssumeAligned(T* const ptr)
{
	ION_ASSUME_FMT_IMMEDIATE(reinterpret_cast<uintptr_t>(ptr) % N == 0, "Invalid alignment;assumed alignment=%zu;found=%zu", N,
							 (reinterpret_cast<uintptr_t>(ptr) % N));
#if ION_COMPILER_MSVC
	return std::assume_aligned<N, T>(ptr);
#else
	return reinterpret_cast<T*>(__builtin_assume_aligned(ptr, N));
#endif
}

template <typename T, size_t N = alignof(T)>
[[nodiscard]] constexpr T& AssumeAligned(T& ref)
{
	return *AssumeAligned(&ref);
}

inline void NotifyOutOfMemory()
{
#if ION_CONFIG_ERROR_CHECKING
	ION_ABNORMAL("Out of memory");
#endif
}
}  // namespace ion
