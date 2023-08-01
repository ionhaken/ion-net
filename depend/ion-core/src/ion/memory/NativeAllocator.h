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

namespace ion
{


template <typename T>
class NativeAllocator
{

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
		using other = NativeAllocator<U>;
	};
	using is_always_equal = std::true_type;

	constexpr NativeAllocator() {}
	constexpr NativeAllocator(const NativeAllocator&) {}
	constexpr NativeAllocator(NativeAllocator&&) {}
	NativeAllocator& operator=(NativeAllocator&&) { return *this; }
	NativeAllocator& operator=(const NativeAllocator&) { return *this; }

	template <class U>
	constexpr NativeAllocator(const NativeAllocator<U>&)
	{
	}
	template <class U>
	constexpr NativeAllocator(NativeAllocator<U>&&)
	{
	}

	template <typename Source>
	constexpr NativeAllocator([[maybe_unused]] Source* const source)
	{
		ION_ASSERT_FMT_IMMEDIATE(source == nullptr, "NativeAllocator does not use resources");
	}

	~NativeAllocator() throw() {}

	[[nodiscard]] inline T* AllocateRaw(size_type numBytes)
	{
		if constexpr (alignof(T) <= detail::StdAlignment<uint8_t>())
		{
			T* ret = (T*)(ion::NativeMalloc(numBytes));
			return ion::AssumeAligned(ret);
		}
		else
		{
			T* ret = (T*)(NativeAlignedMalloc(numBytes, alignof(T)));
			return ion::AssumeAligned(ret);
		}
	}

	[[nodiscard]] inline T* AllocateRaw(size_type numBytes, size_t alignment)
	{
		if (alignment <= detail::StdAlignment<uint8_t>())
		{
			T* ret = (T*)(ion::NativeMalloc(numBytes));
			return ion::AssumeAligned(ret);
		}
		else
		{
			T* ret = (T*)(NativeAlignedMalloc(numBytes, alignment));
			return ion::AssumeAligned(ret);
		}
	}

	inline void DeallocateRaw(void* p, size_type /*n*/)
	{
		if constexpr (alignof(T) <= detail::StdAlignment<uint8_t>())
		{
			ion::NativeFree(p);
		}
		else
		{
			NativeAlignedFree(p);
		}
	}

	inline void DeallocateRaw(void* p, size_type /*n*/, size_t alignment)
	{
		if (alignment <= detail::StdAlignment<uint8_t>())
		{
			ion::NativeFree(p);
		}
		else
		{
			NativeAlignedFree(p);
		}
	}

	// STL support
	[[nodiscard]] T* allocate(size_type num) { return AllocateRaw(num * sizeof(T)); }
	void deallocate(T* p, size_type num) { DeallocateRaw(p, sizeof(T) * num); }

	void deallocate(void* p, size_type num) { DeallocateRaw(p, num); }
};

template <class T1, class T2>
constexpr bool operator==(const ion::NativeAllocator<T1>&, const ion::NativeAllocator<T2>&)
{
	return true;
}

template <class T1, class T2>
constexpr bool operator!=(const ion::NativeAllocator<T1>&, const ion::NativeAllocator<T2>&)
{
	return false;
}

}  // namespace ion
