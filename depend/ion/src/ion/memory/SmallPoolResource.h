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
#include <ion/memory/SmallMultiPool.h>

namespace ion
{
// As MultiPoolResource, but supports only small objects
template <size_t NumBytesReserved, MemTag Tag = ion::tag::Unset>
class SmallPoolResource
{
	using Resource = ion::MonotonicBufferResource<NumBytesReserved, Tag>;

	Resource mResource;
	SmallMultiPool<Resource> mPool;
	ION_ACCESS_GUARD(mGuard);

public:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(SmallPoolResource);

	SmallPoolResource() : mPool(mResource) {}

	~SmallPoolResource() {}

	ION_RESTRICT_RETURN_VALUE inline void* Allocate(size_t count, size_t align) ION_ATTRIBUTE_MALLOC
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		return mPool.Allocate(count, align);
	}

	inline void Deallocate(void* p, size_t s)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		mPool.Deallocate(p, s);
	}
};
}  // namespace ion
