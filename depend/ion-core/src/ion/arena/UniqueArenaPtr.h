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
#include <ion/memory/UniquePtr.h>
#include <ion/arena/ArenaAllocator.h>
#include <ion/util/InplaceFunction.h>

namespace ion
{
template <class T>
using UniqueArenaPtr = std::unique_ptr<T, ion::InplaceFunction<void(T*), 64, 16>>; /*std::function<void(T*)>*/

template <typename Allocator, typename T = typename Allocator::value_type, typename... Args>
UniqueArenaPtr<T> MakeUniqueArena(Allocator& allocator, Args&&... args)
{
	auto* buffer = allocator.allocate(1);
	auto deleter = [](T* p, Allocator allocator)
	{
		p->~T();
		allocator.deallocate(p, 1);
	};
	return UniqueArenaPtr<T>(new (buffer) T(std::forward<Args>(args)...), std::bind(deleter, std::placeholders::_1, allocator));
}

template <typename T, typename Resource, typename... Args>
ion::UniqueArenaPtr<T> MakeUniqueArena(Resource* resource, Args&&... args)
{
	ion::ArenaAllocator<T, Resource> allocator(resource);
	auto* buffer = allocator.allocate(1);
	auto deleter = [](T* p, ion::ArenaAllocator<T, Resource> allocator)
	{
		p->~T();
		allocator.deallocate(p, 1);
	};
	return UniqueArenaPtr<T>(new (buffer) T(std::forward<Args>(args)...), std::bind(deleter, std::placeholders::_1, allocator));
}
}  // namespace ion
