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
#include <type_traits>
#include <new>
#include <memory>

namespace ion
{
namespace details
{
template <class T>
void DefaultDelete(T* p) noexcept
{
	static_assert(sizeof(T) > 0, "Cannot delete incomplete type");
	static_assert(!std::is_void<T>::value, "Cannot delete incomplete type");
	delete p;
}

template <class T>
void DefaultDeleteNull(T*) noexcept
{
}

template <class Allocator, typename T = typename Allocator::value_type>
void DefaultAllocatorDelete(T* p) noexcept
{
	static_assert(sizeof(T) > 0, "Cannot delete incomplete type");
	static_assert(!std::is_void<T>::value, "Cannot delete incomplete type");
	p->~T();
	Allocator allocator;
	allocator.deallocate(p, 1);
}

template <class T>
void DefaultAlignedDelete(T* p) noexcept
{
	ION_ASSERT(p, "Trying to delete nullptr");	// #TODO: Check do we need this
	{
		static_assert(sizeof(T) > 0, "Cannot delete incomplete type");
		static_assert(!std::is_void<T>::value, "Cannot delete incomplete type");
		p->~T();
		ion::AlignedFree(p);
	}
}

template <class T>
void DefaultAlignedDeleteNull(T*) noexcept
{
}

template <class T>
struct DefaultDeleter
{
	constexpr DefaultDeleter() noexcept = default;

	template <class U>	// #TODO_ANDROID: commented out: std::enable_if_t<std::is_convertible<U*, T*>, int> = 0>
	DefaultDeleter(const DefaultDeleter<U>&) noexcept
	{
	}  // construct from another DefaultDeleter

	void operator()(T* ptr) const noexcept { DefaultDelete(ptr); }
};
}  // namespace details

template <class T, class Deleter = details::DefaultDeleter<T>>
using UniquePtr = std::unique_ptr<T, Deleter>;

template <class T>
inline UniquePtr<T> MakeUnique(T* t)
{
	return UniquePtr<T>(AssumeAligned<T>(t));
}

template <class T, class... Args>
inline UniquePtr<T> MakeUnique(Args&&... args)
{
	T* t = new T(std::forward<Args>(args)...);	// Use ION_ALIGN_CLASS if object is not aligned correctly
	return UniquePtr<T>(AssumeAligned<T>(t));
}

// Unique Opaque Ptr
// Similar as UniquePtr, but owner does not have to know pointer type.
// ---
// Adapted from original code: Smart PIMPL Version 1.1:
//   https://github.com/oliora/samples/blob/master/spimpl.h
//
// Rationale and description:
//	http://oliora.github.io/2015/12/29/pimpl-and-rule-of-zero.html
//
// Copyright (c) 2015 Andrey Upadyshev (oliora@gmail.com)
// Distributed under the Boost Software License, Version 1.0.
//    See http://www.boost.org/LICENSE_1_0.txt

// https://embeddedartistry.com/blog/2017/2/23/c-smart-pointers-with-aligned-mallocfree
template <class T, class Deleter = void (*)(T*)>
using UniqueOpaquePtr = UniquePtr<T, Deleter>;

template <class T, class... Args>
inline UniqueOpaquePtr<T> MakeUniqueOpaque(Args&&... args)
{
	static_assert(!std::is_array<T>::value, "UniqueOpaquePtr does not support arrays");
	return UniqueOpaquePtr<T>(new T(std::forward<Args>(args)...), &details::DefaultDelete<T>);
}

template <class T, class... Args>
inline UniqueOpaquePtr<T> MakeUniqueOpaqueAligned(Args&&... args)
{
	static_assert(!std::is_array<T>::value, "UniqueOpaquePtr does not support arrays");
	T* raw = static_cast<T*>(ion::AlignedMalloc(sizeof(T), alignof(T), __FILE__, __LINE__));
	T* instance = new (raw) T(std::forward<Args>(args)...);
	return UniqueOpaquePtr<T>(instance, &details::DefaultAlignedDelete<T>);
}

template <class T>
inline UniqueOpaquePtr<T> MakeUniqueOpaqueNull()
{
	return UniqueOpaquePtr<T>(nullptr, &details::DefaultDeleteNull<T>);
}

template <class T>
inline UniqueOpaquePtr<T> MakeUniqueOpaqueAlignedNull()
{
	return UniqueOpaquePtr<T>(nullptr, &details::DefaultAlignedDeleteNull<T>);
}

template <class T, class Deleter = void (*)(T*)>
using DomainOpaquePtr = UniquePtr<T, Deleter>;

template <class Allocator, typename T = typename Allocator::value_type, class... Args>
inline UniqueOpaquePtr<T> MakeUniqueOpaqueDomain(Args&&... args)
{
	static_assert(!std::is_array<T>::value, "UniqueOpaquePtr does not support arrays");
	Allocator a;
	auto* buffer = a.allocate(1);
	return UniqueOpaquePtr<T>(new (buffer) T(std::forward<Args>(args)...), &details::DefaultAllocatorDelete<Allocator>);
}

}  // namespace ion
