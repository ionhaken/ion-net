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

#include <ion/util/Math.h>
#include <ion/util/SafeRangeCast.h>

namespace ion
{
struct PoolBlock
{
	static constexpr const uint8_t NoList = 0xFF;
	uint8_t listId;
	// Padding as many bytes as required to match type alignment.
	uint8_t padding;
	// #TODO: have multiple items inside a block. block header is found from ptr & 0xFFFFF000. Keep atomic bitmap to track used items.

	template <typename Resource>
	static void* Allocate(Resource& resource, size_t count, size_t align, uint8_t listId)
	{
		size_t extraBytes = ion::Max(align, sizeof(PoolBlock));
		uint8_t* ptr = reinterpret_cast<uint8_t*>(resource.Allocate(count + extraBytes, align));
		if (ptr == nullptr)
		{
			return nullptr;
		}
		*(ptr) = listId;
		*(ptr + extraBytes - 1) = ion::SafeRangeCast<uint8_t>(extraBytes);
		return (ptr + extraBytes);
	}

	static void GetInfo(void* p, PoolBlock*& block, uint8_t& offset)
	{
		uint8_t* u8ptr = reinterpret_cast<uint8_t*>(p);
		uint8_t* offsetPtr = (u8ptr - 1);
		offset = *(offsetPtr);
		block = reinterpret_cast<PoolBlock*>(u8ptr - offset);
	}
};
class SmallMultiPoolBase
{
public:
	static constexpr size_t Align = 8;

protected:
	static constexpr size_t LowAlign = alignof(void*);
	static constexpr size_t MidAlign = 32;
	static constexpr size_t LowCount = 512;
	static constexpr size_t MidCount = 2048;

	static_assert(LowCount % LowAlign == 0, "Invalid low count");
	static constexpr size_t LowBuckets = LowCount / LowAlign;
	static_assert((MidCount - LowCount) % MidAlign == 0, "Invalid mid count");
	static constexpr size_t MidBuckets = (MidCount - LowCount) / MidAlign;

	// #TODO: Need to test params in practise. We have quite high bucket count which might cause
	// fragmentation in real scenarios.
	// #TODO: Check should we use 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096,... 16384 byte buckets instead of
	static constexpr size_t HighAlign = 1024;
	static constexpr size_t HighBuckets = 14;

	static constexpr size_t GroupCount = LowBuckets + MidBuckets + HighBuckets;
	static_assert(GroupCount < 256, "Invalid size");
	static constexpr size_t HighCount = HighAlign * HighBuckets + MidCount;
	static_assert((HighCount - MidCount) % HighAlign == 0, "Invalid mid count");

public:
	constexpr size_t MaxSize() const { return HighCount; }
};
}  // namespace ion
