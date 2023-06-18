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

#include <ion/util/Math.h>
#include <ion/util/SafeRangeCast.h>

namespace ion
{
struct MemoryStats
{
	uint64_t totalAllocs = 0;
};

namespace memory_tracker
{
void SetFatalMemoryLeakLimit(size_t s);
enum class Layer : uint8_t
{
	// TLSF resource
	TLSF,

	// Global memory pool
	Global,

	// Native/operating system memory pool, should be used only via global memory pool.
	Native,

	Invalid
};

#if ION_MEMORY_TRACKER
void TrackStatic(uint32_t size, ion::MemTag tag);
void UntrackStatic(uint32_t size, ion::MemTag tag);

namespace detail
{
struct MemHeader
{
	MemHeader(uint32_t size, MemTag tag) : guard1(0xAA55AA55), size(size), tag(tag), alignment(sizeof(MemHeader)), guard2(0xAA55AA55) {}

	MemHeader(uint32_t size, size_t alignment, MemTag tag)
	  : guard1(0xAA55AA55), size(size), tag(tag), alignment(ion::SafeRangeCast<uint16_t>(alignment)), guard2(0xAA55AA55)
	{
	}

	void Clear()
	{
		ION_ASSERT_FMT_IMMEDIATE(guard1 == 0xAA55AA55 && guard2 == 0xAA55AA55, "Mem block header corrupted (guard)");
		ION_ASSERT_FMT_IMMEDIATE(alignment % 4 == 0, "Mem block header corrupted (align)");
		memset(this, 0xDD, sizeof(MemHeader));
	}

	uint32_t guard1;
	uint32_t size;
	MemTag tag;
	uint16_t alignment;
	uint32_t guard2;
};

static_assert(sizeof(MemHeader) % 8 == 0, "Must be 8 bytes aligned");

struct MemFooter
{
	uint32_t guard1 = 0xAA55AA55;
	uint32_t guard2 = 0xAA55AA55;
	void Clear()
	{
		ION_ASSERT_FMT_IMMEDIATE(guard1 == 0xAA55AA55, "Mem block footer corrupted");
		ION_ASSERT_FMT_IMMEDIATE(guard2 == 0xAA55AA55, "Mem block footer corrupted");
		guard1 = 0xDDDDDDDD;
		guard2 = 0xDDDDDDDD;
	}
};

}  // namespace detail

inline size_t AllocationSize(size_t size) { return size + sizeof(detail::MemFooter) + sizeof(detail::MemHeader); }

inline size_t AlignedAllocationSize(size_t size, size_t alignment)
{
	size_t s = ion::Max(sizeof(detail::MemHeader), alignment) + AllocationSize(size);
	if ((s % alignment) != 0)
	{
		s += alignment - (s % alignment);
	}
	return s;
}

void* OnAllocation(void* ptr, size_t size, ion::MemTag tag, Layer layer);

void* OnAlignedAllocation(void* ptr, size_t size, size_t alignment, ion::MemTag tag, Layer layer);

void* OnDeallocation(void* ptr, Layer layer);

void* OnAlignedDeallocation(void* payload, uint32_t& outAlignment, Layer);

	#if ION_PLATFORM_MICROSOFT
int CrtMallocHook(int allocType, void* userData, size_t size, int blockType, long requestNumber, const unsigned char* filename,
				  int lineNumber);
	#endif

#else
inline size_t AllocationSize(size_t size) { return size; }

inline size_t AlignedAllocationSize(size_t size, size_t) { return size; }

inline void* OnAllocation(void* ptr, size_t, ion::MemTag, Layer) { return ptr; }

inline void* OnAlignedAllocation(void* ptr, size_t /*bytes*/, size_t /*alignment*/, ion::MemTag, Layer) { return ptr; }

inline void* OnDeallocation(void* ptr, Layer) { return ptr; }

inline void* OnAlignedDeallocation(void* ptr, uint32_t&, Layer) { return ptr; }

inline void TrackStatic(uint32_t, ion::MemTag) {}

inline void UntrackStatic(uint32_t, ion::MemTag) {}

#endif
void Stats(MemoryStats* stats = nullptr);

void PrintStats(bool breakOnLeaks, Layer layer);

void EnableWaitUserOnLeak();

void EnableTracking();

}  // namespace memory_tracker
}  // namespace ion
