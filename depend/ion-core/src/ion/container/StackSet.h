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
#include <ion/container/Set.h>
#include <ion/container/StackContainer.h>

namespace ion
{
template <typename TKey, size_t ElementCount, typename THasher = Hasher<TKey>>
class StackSet : public StackContainer<Set<TKey, StackAllocator<TKey, ElementCount>>, ElementCount>
{
	using Impl = Set<TKey, StackAllocator<TKey, ElementCount>>;
	using Super = StackContainer<Impl, ElementCount>;

public:
	StackSet() {}

	typename Impl::SetImplementation::iterator Begin() { return Super::Native().Begin(); }
	typename Impl::SetImplementation::iterator End() { return Super::Native().End(); }

	// Access set via -> operator
};

}  // namespace ion
