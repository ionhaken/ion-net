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
#include <ion/memory/Ptr.h>

namespace ion
{
template <typename T, typename Source>
class ArenaAllocator
{
public:
	using source = Source;

	template <typename U, typename USource>
	friend class ArenaAllocator;

	using value_type = T;
	using size_type = size_t;
	using difference_type = ptrdiff_t;
	using propagate_on_container_copy_assignment = std::false_type;
	using propagate_on_container_move_assignment = std::false_type;
	using propagate_on_container_swap = std::false_type;
	using is_always_equal = std::false_type;

	template <class U>
	struct rebind
	{
		using other = ArenaAllocator<U, Source>;
	};

	ArenaAllocator(Source* const source) : mSource(source) {}
	ArenaAllocator(const ArenaAllocator& other) : mSource(other.mSource) {}
	ArenaAllocator(ArenaAllocator&& other) : mSource(std::move(other.mSource)) {}
	template <typename U>
	ArenaAllocator(const ArenaAllocator<U, Source>& other) : mSource(other.mSource)
	{
	}

	template <typename U>
	ArenaAllocator(const ArenaAllocator<U, Source>&& other) : mSource(std::move(other.mSource))
	{
	}

	ArenaAllocator& operator=(ArenaAllocator&& other)
	{
		mSource = std::move(other.mSource);
		return *this;
	}
	ArenaAllocator& operator=(const ArenaAllocator& other)
	{
		mSource = other.mSource;
		return *this;
	}

	~ArenaAllocator() {}

	T* address(T& x) const { return &x; }
	const T* address(const T& x) const { return &x; }
	size_type max_size() const throw() { return size_t(-1) / sizeof(value_type); }

	T* AllocateRaw(size_type numBytes, size_t align)
	{
		ION_ASSERT(numBytes % alignof(T) == 0, "Invalid allocation");
#if ION_CONFIG_MEMORY_RESOURCES == 1
		ION_ASSERT(mSource, "No memory resource");
		return reinterpret_cast<T*>(mSource->Allocate(numBytes, align));
#else
		ion::GlobalAllocator<T> fallback;
		return fallback.AllocateRaw(numBytes, align);
#endif
	}

	T* AllocateRaw(size_type numBytes)
	{
#if ION_CONFIG_MEMORY_RESOURCES == 1
		ION_ASSERT(mSource, "No memory resource");
		return reinterpret_cast<T*>(mSource->Allocate(numBytes, alignof(T)));
#else
		ion::GlobalAllocator<T> fallback;
		return fallback.AllocateRaw(numBytes);
#endif
	}

	inline void DeallocateRaw(void* p, [[maybe_unused]] size_type numBytes, [[maybe_unused]] size_t align)
	{
#if ION_BUILD_DEBUG
		memset(p, 0xCD, numBytes);
#endif
#if ION_CONFIG_MEMORY_RESOURCES == 1
		mSource->Deallocate(p, numBytes);
#else
		ion::GlobalAllocator<T> fallback;
		fallback.DeallocateRaw(p, numBytes, align);
#endif
	}

	inline void DeallocateRaw(void* p, [[maybe_unused]] size_type numBytes)
	{
#if ION_BUILD_DEBUG
		memset(p, 0xCD, numBytes);
#endif
#if ION_CONFIG_MEMORY_RESOURCES == 1
		mSource->Deallocate(p, numBytes);
#else
		ion::GlobalAllocator<T> fallback;
		fallback.DeallocateRaw(p, numBytes);
#endif
	}

	Source* GetSource() { return mSource; }

	const Source* GetSource() const { return mSource; }

	// STL support
	T* allocate(size_type n) { return AssumeAligned<T>(AllocateRaw(sizeof(T) * n, alignof(T))); }
	inline void deallocate(void* p, size_type n) { deallocate(reinterpret_cast<T*>(p), n); }
	void deallocate(T* p, size_type n) { DeallocateRaw((void*)p, n * sizeof(T)); }

private:
	Source* mSource = nullptr;
};

template <typename T, typename Resource>
using ArenaPtr = ion::Ptr<T>;

template <typename T, typename Resource, typename... Args>
ion::ArenaPtr<T, Resource> MakeArenaPtr(Resource* resource, Args&&... args)
{
	ion::ArenaAllocator<T, Resource> allocator(resource);
	ion::ArenaPtr<T, Resource> ptr(new (allocator.allocate(1)) T(std::forward<Args>(args)...));
	return std::move(ptr);
}

template <typename T, typename Resource, typename... Args>
ion::ArenaPtr<T, Resource> MakeArenaPtrRaw(Resource* resource, size_t numBytes, Args&&... args)
{
	ion::ArenaAllocator<T, Resource> allocator(resource);
	ion::ArenaPtr<T, Resource> ptr(new (allocator.AllocateRaw(numBytes)) T(std::forward<Args>(args)...));
	return std::move(ptr);
}

template <typename T, typename Resource>
void DeleteArenaPtr(Resource* resource, ion::ArenaPtr<T, Resource>& arenaPtr)
{
	ion::ArenaAllocator<T, Resource> allocator(resource);
	T* ptr = arenaPtr.Release();
	ptr->~T();
	allocator.deallocate(ptr, 1);
}

template <typename T, typename Resource, typename... Args>
ion::ArenaPtr<T, Resource> MakeArenaPtrArray(Resource* resource, size_t size, Args&&... args)
{
	ion::ArenaAllocator<T, Resource> allocator(resource);
	T* buffer = allocator.allocate(size);
	for (size_t i = 0; i < size; ++i)
	{
		new (&buffer[i]) T(std::forward<Args>(args)...);
	}

	ion::ArenaPtr<T, Resource> ptr(buffer);
	return std::move(ptr);
}

template <typename T, typename Resource>
void DeleteArenaPtrArray(Resource* resource, size_t s, ion::ArenaPtr<T, Resource>& arenaPtr)
{
	ion::ArenaAllocator<T, Resource> allocator(resource);
	T* ptr = arenaPtr.Release();
	for (size_t i = 0; i < s; ++i)
	{
		ptr[s - i - 1].~T();
	}
	allocator.deallocate(ptr, s);
}

template <typename T1, typename Source1, typename T2, typename Source2>
bool operator==(const ion::ArenaAllocator<T1, Source1>& a, const ion::ArenaAllocator<T2, Source2>& b)
{
	return a.GetSource() == b.GetSource();
}

template <typename T1, typename Source1, typename T2, typename Source2>
bool operator!=(const ion::ArenaAllocator<T1, Source1>& a, const ion::ArenaAllocator<T2, Source2>& b)
{
	return a.GetSource() != b.GetSource();
}

}  // namespace ion

