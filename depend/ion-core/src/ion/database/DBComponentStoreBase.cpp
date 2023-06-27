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
#include <ion/database/DBComponentStoreBase.h>

ion::ComponentStoreBase::ComponentStoreBase() {}

ion::ComponentStoreBase::~ComponentStoreBase()
{
#if ION_COMPONENT_SUPPORT_CACHE_TRACKING
	// Combine stats for all threads
	Stats total;
	for (size_t i = 0; i < mStats.Size(); i++)
	{
		total.cacheHits += mStats[i].cacheHits;
		total.cacheMisses += mStats[i].cacheMisses;
		if (total.fields.Size() < mStats[i].fields.Size())
		{
			total.fields.Resize(mStats[i].fields.Size());
		}
		for (size_t j = 0; j < mStats[i].fields.Size(); j++)
		{
			total.fields[j].hits += mStats[i].fields[j].hits;
			total.fields[j].misses += mStats[i].fields[j].misses;
			total.fields[j].falseSharing += mStats[i].fields[j].falseSharing;
		}
	}

	if (total.cacheHits + total.cacheMisses > 0)
	{
		ION_LOG_INFO("Store '" << mName.CStr() << "' total accesses: " << total.cacheHits + total.cacheMisses);
		for (size_t i = 0; i < mStats.Size(); i++)
		{
			ION_LOG_INFO("\tThread " << i << " accessed " << mStats[i].cacheHits + mStats[i].cacheMisses << " times");
		}
		ION_LOG_INFO("\tCache hit rate: " << (100 * static_cast<float>(total.cacheHits) / (total.cacheHits + total.cacheMisses)) << " %");
		for (size_t i = 0; i < total.fields.Size(); i++)
		{
			float rate = total.fields[i].hits > 0 ? 100.0f * (total.fields[i].hits - total.fields[i].misses) / (total.fields[i].hits) : 0;
			ION_LOG_INFO("\t[" << i << "] " << total.fields[i].misses << " misses (" << rate << " %)"
					  << ", " << total.fields[i].falseSharing << " times false sharing");
		}
	}

#endif
#if ION_COMPONENT_READ_WRITE_CHECKS
	ION_CHECK(mStoreGuard.IsFree(), "Store deleted when in use");
	for (size_t i = 0; i < mFieldGuard.Size(); i++)
	{
		ION_CHECK(mFieldGuard[i].IsFree(), "Store deleted when components in use");
	}
#endif
}

#if ION_COMPONENT_SUPPORT_CACHE_TRACKING
void ion::ComponentStoreBase::TrackCache(size_t callIndex, const void* const anAddress, size_t sizeOfT, bool isWriting) const
{
	ion::AutoLock<Mutex> lock(mAccess);
	const auto threadId = Thread::GetId();
	if (threadId >= mStats.Size())
	{
		mStats.Resize(threadId + 1);
	}
	Stats& stats = mStats[threadId];
	const uint32_t NumLines = ComponentCacheSize / CacheLineSize;
	const size_t Address = reinterpret_cast<size_t>(anAddress) + sizeOfT;

	if (stats.fields.Size() <= callIndex)
	{
		stats.fields.Resize(callIndex + 1);
	}
	stats.fields[callIndex].hits++;

	for (size_t i = 0; i < NumLines; i++)
	{
		size_t CachePointer = reinterpret_cast<size_t>(stats.cachePointers[(i + stats.lastCachePointer) % NumLines]);
		if (Address >= CachePointer && Address - CachePointer <= CacheLineSize)
		{
			stats.cacheHits++;
			return;
		}
	}
	stats.fields[callIndex].misses++;
	stats.cacheMisses++;
	stats.lastCachePointer = stats.lastCachePointer != 0 ? (stats.lastCachePointer - 1) : (NumLines - 1);
	void* ptr = reinterpret_cast<void*>(Address - (Address % CacheLineSize));
	stats.cachePointers[stats.lastCachePointer] = ptr;
	if (isWriting)
	{
		// Invalidate cache
		for (size_t i = 0; i < mStats.Size(); i++)
		{
			if (i != threadId)
			{
				for (size_t j = 0; j < mStats[i].cachePointers.Size(); j++)
				{
					if (mStats[i].cachePointers[j] == ptr)
					{
						if (mStats[i].fields.Size() <= callIndex)
						{
							mStats[i].fields.Resize(callIndex + 1);
						}
						mStats[i].fields[callIndex].falseSharing++;
						mStats[i].cachePointers[j] = 0;
						break;
					}
				}
			}
		}
	}
}
#endif
