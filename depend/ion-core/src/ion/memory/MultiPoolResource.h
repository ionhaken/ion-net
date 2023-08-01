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
#include <ion/memory/TLSFResource.h>

namespace ion
{
// Memory is stored in TSLF, but small blocks are also cached in SmallMultiPool for fast use.
template <size_t NumBytesReserved, MemTag Tag = ion::tag::Unset>
class MultiPoolResource
{
#if ION_CONFIG_MEMORY_RESOURCES == 1
	ION_ACCESS_GUARD(mGuard);
	using Resource = TLSFResource<MonotonicBufferResource<NumBytesReserved, Tag>, Tag>;

public:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(MultiPoolResource);
	MultiPoolResource() : mResource(), mPool(mResource) {}

	~MultiPoolResource() {}

	ION_RESTRICT_RETURN_VALUE void* Allocate(size_t count, size_t align) ION_ATTRIBUTE_MALLOC
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		return count <= mPool.MaxSize() ? mPool.Allocate(count, align)
										: PoolBlock::Allocate<Resource>(mResource, count, align, PoolBlock::NoList);
	}

	void Deallocate(void* p, size_t s)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		uint8_t offset = 0;
		PoolBlock* block = nullptr;
		PoolBlock::GetInfo(p, block, offset);
		if (block->listId != 0xFF)
		{
			mPool.Deallocate(p, block->listId, offset);
		}
		else
		{
			mResource.Deallocate(block, s);
		}
	}

	void* Reallocate(void*, size_t)
	{
		ION_ASSERT_FMT_IMMEDIATE(false, "Not implemented");
		return nullptr;
	}

private:
	Resource mResource;
	SmallMultiPool<TLSFResource<MonotonicBufferResource<NumBytesReserved, Tag>, Tag>> mPool;
#endif
};
}  // namespace ion
