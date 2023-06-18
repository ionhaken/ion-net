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
#include <ion/arena/ArenaVector.h>

namespace ion
{
namespace arena
{
template <typename T, uint32_t N, typename Resource>
void Resize(Resource& resource, ion::ArenaVector<T, N>& av, size_t s, size_t minAlloc)
{
	ion::ArenaAllocator<T, Resource> allocator(&resource);
	av.Resize(allocator, s, minAlloc);
	if (s == 0)
	{
		av.ShrinkToFit(allocator);
	}
}

template <typename T, uint32_t N, typename Resource>
void Resize(Resource& resource, ion::ArenaVector<T, N>& av, size_t s)
{
	Resize(resource, av, s, s);
}

template <typename Resource, typename ArenaVector>
void Clear(Resource& resource, ArenaVector& av)
{
	ion::ArenaAllocator<typename std::remove_pointer<decltype(av.Begin())>::type, Resource> allocator(&resource);
	av.Clear();
	av.ShrinkToFit(allocator);
}

template <typename Resource, typename ArenaVector>
void Resize(Resource& resource, ArenaVector& av, size_t s)
{
	ion::ArenaAllocator<typename std::remove_pointer<decltype(av.Begin())>::type, Resource> allocator(&resource);
	av.Resize(allocator, s);
}
}  // namespace arena
}  // namespace ion
