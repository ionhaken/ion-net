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

#include <cstddef>
#include <ion/Base.h>

namespace ion
{
template <typename T, typename ResourceProxy>
class DomainAllocator
{
public:
	template <typename U, typename UResourceProxy>
	friend class DomainAllocator;

	using value_type = T;
	using size_type = size_t;
	using difference_type = ptrdiff_t;
	using propagate_on_container_copy_assignment = std::false_type;
	using propagate_on_container_move_assignment = std::true_type;
	using propagate_on_container_swap = std::false_type;
	using is_always_equal = std::true_type;

	constexpr DomainAllocator() {}
	constexpr DomainAllocator(const DomainAllocator&) {}
	constexpr DomainAllocator(DomainAllocator&&) {}
	DomainAllocator& operator=(const DomainAllocator&) { return *this; }
	DomainAllocator& operator=(DomainAllocator&&) { return *this; }

	template <typename U>
	constexpr DomainAllocator(const DomainAllocator<U, ResourceProxy>&)
	{
	}

	template <typename U>
	constexpr DomainAllocator(DomainAllocator<U, ResourceProxy>&&)
	{
	}

	~DomainAllocator() {}

	template <class U>
	struct rebind
	{
		using other = DomainAllocator<U, ResourceProxy>;
	};

	T* address(T& x) const { return &x; }
	const T* address(const T& x) const { return &x; }
	size_type max_size() const throw() { return size_t(-1) / sizeof(value_type); }

	[[nodiscard]] inline T* AllocateRaw(size_type numBytes)
	{
		ION_ASSERT(numBytes % alignof(T) == 0, "Invalid allocation");
#if ION_CONFIG_MEMORY_RESOURCES == 1
		return ResourceProxy::template AllocateRaw<T>(numBytes, alignof(T));
#else
		ion::GlobalAllocator<T> fallback;
		return fallback.AllocateRaw(numBytes);
#endif
	}

	[[nodiscard]] inline T* AllocateRaw(size_type numBytes, size_t align)
	{
#if ION_CONFIG_MEMORY_RESOURCES == 1
		return ResourceProxy::template AllocateRaw<T>(numBytes, align);
#else
		ion::GlobalAllocator<T> fallback;
		return fallback.AllocateRaw(numBytes, align);
#endif
	}

	[[nodiscard]] inline T* allocate(size_type n) { return AssumeAligned<T, alignof(T)>(AllocateRaw(n * sizeof(T), alignof(T))); }

	[[nodiscard]] inline T* Allocate(size_type n) { return allocate(n); }

	inline void DeallocateRaw(void* p, [[maybe_unused]] size_type numBytes)
	{
#if ION_CONFIG_MEMORY_RESOURCES == 1
		ResourceProxy::template DeallocateRaw<T>(reinterpret_cast<T*>(p), numBytes);
#else
		ion::GlobalAllocator<T> fallback;
		fallback.DeallocateRaw(p, numBytes);
#endif
	}

	inline void DeallocateRaw(void* p, [[maybe_unused]] size_type numBytes, [[maybe_unused]] size_t alignment)
	{
#if ION_CONFIG_MEMORY_RESOURCES == 1
		ResourceProxy::template DeallocateRaw<T>(reinterpret_cast<T*>(p), numBytes, alignment);
#else
		ion::GlobalAllocator<T> fallback;
		fallback.DeallocateRaw(p, numBytes, alignment);
#endif
	}

	inline void deallocate(T* p, [[maybe_unused]] size_type n) { DeallocateRaw(p, n * sizeof(T)); }
	//inline void Deallocate(void* p, size_type n) { deallocate(reinterpret_cast<T*>(p), n); }
	inline void deallocate(void* p, size_type n) { DeallocateRaw(p, n); }

	template <class... Args>
	[[nodiscard]] static constexpr value_type* Construct(Args&&... args)
	{
		DomainAllocator a;
		return new (static_cast<void*>(a.allocate(1))) value_type(ion_forward(args)...);
	}

	static constexpr void Destroy(value_type* p)
	{
		DomainAllocator a;
		p->~value_type();
		a.deallocate(p, 1);
	}
};
}  // namespace ion
