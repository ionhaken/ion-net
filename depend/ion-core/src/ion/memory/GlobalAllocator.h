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

#include <new>	// std::align_val_t

namespace ion
{
template <typename T>
class GlobalAllocator
{
	static constexpr size_t MinimumAlignment = 8;
public:
	using value_type = T;
	using size_type = size_t;
	using difference_type = ptrdiff_t;

	using propagate_on_container_copy_assignment = std::false_type;
	using propagate_on_container_move_assignment = std::true_type;
	using propagate_on_container_swap = std::false_type;

	template <class U>
	struct rebind
	{
		using other = GlobalAllocator<U>;
	};
	using is_always_equal = std::true_type;

	constexpr GlobalAllocator() {}
	constexpr GlobalAllocator(const GlobalAllocator&) {}
	constexpr GlobalAllocator(GlobalAllocator&&) {}
	GlobalAllocator& operator=(GlobalAllocator&&) { return *this; }
	GlobalAllocator& operator=(const GlobalAllocator&) { return *this; }

	template <class U>
	constexpr GlobalAllocator(const GlobalAllocator<U>&)
	{
	}
	template <class U>
	constexpr GlobalAllocator(GlobalAllocator<U>&&)
	{
	}

	template <typename Source>
	constexpr GlobalAllocator([[maybe_unused]] Source* const source)
	{
		ION_ASSERT_FMT_IMMEDIATE(source == nullptr, "GlobalAllocator does not use resources");
	}

	~GlobalAllocator() throw() {}

	[[nodiscard]] inline T* AllocateRaw(size_type numBytes)
	{
		ION_ASSERT(numBytes % alignof(T) == 0, "Invalid allocation");
		if constexpr (alignof(T) <= MinimumAlignment)
		{
			T* ret = (T*)(ion::Malloc(numBytes));
			return ion::AssumeAligned(ret);
		}
		else
		{
			T* ret = (T*)(ION_ALIGNED_MALLOC(numBytes, alignof(T)));
			return ion::AssumeAligned(ret);
		}
	}

	[[nodiscard]] inline T* AllocateRaw(size_type numBytes, size_t alignment)
	{
		if (alignment <= MinimumAlignment)
		{
			T* ret = (T*)(ion::Malloc(numBytes));
			return ion::AssumeAligned(ret);
		}
		else
		{
			T* ret = (T*)(ION_ALIGNED_MALLOC(numBytes, alignment));
			return ion::AssumeAligned(ret);
		}
	}

	void* ReallocateRaw(void* p, size_t newSize) 
	{ 
		return Realloc(p, newSize);
	}

	inline void DeallocateRaw(void* p, size_type /*n*/)
	{
		if constexpr (alignof(T) <= MinimumAlignment)
		{
			Free(p);
		}
		else
		{
			ION_ALIGNED_FREE(p);
		}
	}

	inline void DeallocateRaw(void* p, size_type /*n*/, size_t alignment)
	{
		if (alignment <= MinimumAlignment)
		{
			Free(p);
		}
		else
		{
			ION_ALIGNED_FREE(p);
		}
	}

	// STL support
	[[nodiscard]] T* allocate(size_type num) { return AllocateRaw(num * sizeof(T)); }
	void deallocate(T* p, size_type num) { DeallocateRaw(p, sizeof(T) * num); }

	void deallocate(void* p, size_type num) { DeallocateRaw(p, num); }

};

template <class T1, class T2>
constexpr bool operator==(const ion::GlobalAllocator<T1>&, const ion::GlobalAllocator<T2>&)
{
	return true;
}

template <class T1, class T2>
constexpr bool operator!=(const ion::GlobalAllocator<T1>&, const ion::GlobalAllocator<T2>&)
{
	return false;
}


}  // namespace ion

