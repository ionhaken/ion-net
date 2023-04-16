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
#include <ion/database/DBComponentId.h>
#include <ion/database/DBComponent.h>
#include <ion/container/UnorderedMap.h>
#include <ion/container/Vector.h>

#if ION_COMPONENT_READ_WRITE_CHECKS
	#include <ion/debug/AccessGuard.h>
#endif
#if ION_COMPONENT_SUPPORT_CACHE_TRACKING
	#include <ion/string/String.h>
	#include <ion/jobs/ThreadPool.h>
#endif

namespace ion
{
class ComponentStoreBase
{
public:
	ComponentStoreBase();
	virtual ~ComponentStoreBase();

	//
	// Cache simulation
	//

#if ION_COMPONENT_SUPPORT_CACHE_TRACKING
	static const uint32_t CacheLineSize = 64;
	static const uint32_t ComponentCacheSize = 1024;
#endif

	template <typename T>
	void TrackCache(size_t callIndex, const T* const anAddress, bool isWriting = false) const
	{
#if ION_COMPONENT_SUPPORT_CACHE_TRACKING
		TrackCache(callIndex, anAddress, sizeof(T), isWriting);
#endif
	}

protected:
#if ION_COMPONENT_SUPPORT_CACHE_TRACKING
	void SetName(const char* name) { mName = name; }
#else
	void SetName(const char*) {}
#endif

#if ION_COMPONENT_READ_WRITE_CHECKS
	void LockProtection() { mStoreGuard.StartWriting(); }
	void LockProtection() const { mStoreGuard.StartReading(); }
	void UnlockProtection() { mStoreGuard.StopWriting(); }
	void UnlockProtection() const { mStoreGuard.StopReading(); }
#else
	inline void LockProtection() const {}
	inline void UnlockProtection() const {}
#endif

#if ION_COMPONENT_READ_WRITE_CHECKS
	Vector<AccessGuard> mFieldGuard;
	AccessGuard mStoreGuard;
#endif

#if ION_COMPONENT_SUPPORT_CACHE_TRACKING
	ion::String mName;
	mutable ion::Mutex mAccess;
	struct Stats
	{
		mutable ion::Array<void*, ComponentCacheSize / CacheLineSize> cachePointers;
		struct Field
		{
			size_t misses = 0;
			size_t hits = 0;
			size_t falseSharing = 0;
		};
		mutable ion::Vector<Field> fields;
		mutable size_t cacheHits = 0;
		mutable size_t cacheMisses = 0;
		mutable uint16_t lastCachePointer = 0;
	};

	// Stats per thread
	mutable ion::Vector<Stats> mStats;
#endif
private:
#if ION_COMPONENT_SUPPORT_CACHE_TRACKING
	void TrackCache(size_t callIndex, const void* const anAddress, size_t sizeOfT, bool isWriting) const;
#endif
};
}  // namespace ion
