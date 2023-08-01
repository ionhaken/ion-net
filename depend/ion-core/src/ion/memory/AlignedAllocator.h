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
#include <ion/Base.h>
#include <ion/memory/Memory.h>

namespace ion
{
template <size_t Alignment, typename Allocator>
class AlignedAllocator : public Allocator
{
public:
	template <size_t UAlignment, typename UAllocator>
	friend class AlignedAllocator;

	using value_type = typename Allocator::value_type;

	typedef size_t size_type;
	typedef std::ptrdiff_t difference_type;
	typedef typename Allocator::value_type* pointer;
	using const_pointer = const typename Allocator::value_type*;
	using propagate_on_container_swap = std::true_type;

	AlignedAllocator() {}

	template <typename Source>
	AlignedAllocator(Source* const source) : Allocator(source)
	{
	}

	AlignedAllocator(const AlignedAllocator& other) : Allocator(other) {}

	template <size_t UAligment, typename U>
	AlignedAllocator(const AlignedAllocator<UAligment, typename Allocator::template rebind<U>::other>&)
	{
	}

	~AlignedAllocator() {}

	template <typename U>
	struct rebind
	{
		using other = AlignedAllocator<alignof(U), typename Allocator::template rebind<U>::other>;
	};

	inline value_type* Allocate(size_type n) { return AssumeAligned<value_type, Alignment>(AllocateRaw(n * sizeof(value_type))); }

	inline void Deallocate(pointer ptr, [[maybe_unused]] size_type n) { DeallocateRaw(ptr, sizeof(value_type) * n); }

	// inline void Deallocate(void* p, size_type n) { Deallocate(reinterpret_cast<value_type*>(p), n); }

	value_type* AllocateRaw(size_type numBytes) { return Allocator::AllocateRaw(numBytes, Alignment); }

	inline void DeallocateRaw(void* ptr, [[maybe_unused]] size_type n) { Allocator::DeallocateRaw(ptr, n, Alignment); }


	// STL support
	inline value_type* allocate(size_type n) { return Allocate(n); }
	inline void deallocate(pointer ptr, [[maybe_unused]] size_type n) { Deallocate(ptr, n); }
};
}  // namespace ion
