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
#include <ion/util/IdRangePool.h>

namespace ion
{
// #TODO: Replace these with proper memory allocators
template <typename TData, typename TContainerSize = uint32_t, typename TDataSize = uint8_t>
class ComponentDataVector
{
	ion::IdRangePool<TContainerSize> mIdGroupPool;
	ion::Vector<TData, GlobalAllocator<TData>, TContainerSize> mData;

public:
	ComponentDataVector() {}
	ComponentDataVector(TContainerSize reserve) { mData.Reserve(reserve); }

	struct AddResult
	{
		AddResult(TContainerSize aPos) : pos(aPos), isDirty(false) {}
		TContainerSize pos;
		bool isDirty;
	};

	AddResult Add(const TData* data, TDataSize size)
	{
		const auto offset = sizeof(TDataSize);
		AddResult result(mIdGroupPool.Reserve(size + offset));
		const auto requiredSize = result.pos + size + offset;
		if (mData.Size() < requiredSize)
		{
			if (mData.Capacity() < requiredSize)
			{
				mData.Reserve(requiredSize * 2);
				result.isDirty = true;
			}
			mData.Resize(requiredSize);
		}
		reinterpret_cast<TDataSize&>(mData[result.pos]) = size;
		if (size > 0)
		{
			memcpy(reinterpret_cast<char*>(&mData[result.pos + offset]), reinterpret_cast<const char*>(data), size * sizeof(TData));
		}
		return result;
	}

	void Remove(TContainerSize pos) { mIdGroupPool.Free(pos, GetSize(pos) + sizeof(TDataSize)); }

	inline const MultiData<TData, TContainerSize> Get(TContainerSize pos) const
	{
		const auto size = GetSize(pos);
		const auto* const data = size ? &mData[pos + sizeof(TDataSize)] : nullptr;
		return MultiData<TData, TContainerSize>(data, size);
	}

private:
	inline const TDataSize GetSize(TContainerSize pos) const { return reinterpret_cast<const TDataSize&>(mData[pos]); }
};
}  // namespace ion
