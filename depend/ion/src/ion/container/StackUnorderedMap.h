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
#include <ion/container/UnorderedMap.h>
#include <ion/memory/Memory.h>
#include <ion/arena/ArenaAllocator.h>
#include <ion/memory/MonotonicBufferResource.h>
#include <ion/container/StackContainer.h>
#include <ion/util/Hasher.h>

namespace ion
{
template <typename TKey, typename TValue, size_t ElementCount, typename THasher = Hasher<TKey>>
class StackUnorderedMap
  : public StackContainer<UnorderedMap<TKey, TValue, THasher, StackAllocator<Pair<const TKey, TValue>, ElementCount>>, ElementCount>
{
public:
	StackUnorderedMap()
	{
		StackContainer<UnorderedMap<TKey, TValue, THasher, StackAllocator<Pair<const TKey, TValue>, ElementCount>>, ElementCount>::Native()
		  .Reserve(sizeof(Pair<const TKey, TValue>) / ElementCount);
	}

	// Access unordered map via -> operator
};

}  // namespace ion
