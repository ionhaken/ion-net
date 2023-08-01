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
#include <ion/memory/MonotonicBufferResource.h>
#include <ion/arena/ArenaAllocator.h>

namespace ion
{
template <typename T, size_t stack_capacity>
using StackAllocator = ArenaAllocator<T, StackMemoryBuffer<stack_capacity>>;

template <typename TContainerType, int stack_capacity>
class StackContainer
{
public:
	using ContainerType = TContainerType;

	StackContainer() : mSource(), mContainer(&mSource) {}

	ContainerType& Native() { return mContainer; }
	const ContainerType& Native() const { return mContainer; }

	// Access to container method always via -> operator.
	ContainerType* operator->() { return &mContainer; }
	const ContainerType* operator->() const { return &mContainer; }

protected:
	typename StackAllocator<typename ContainerType::ElementType, stack_capacity>::source mSource;
	ContainerType mContainer;

	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(StackContainer);
};

}  // namespace ion
