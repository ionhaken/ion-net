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
#include <ion/memory/PolymorphicResource.h>

#include <ion/concurrency/Mutex.h>

namespace ion
{
template <typename Resource>
class ThreadSafeResource
#if ION_CONFIG_MEMORY_RESOURCES == 1

  : public PolymorphicResourceInterface
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(ThreadSafeResource);
	Resource mResource;

public:
	ThreadSafeResource() : mResource() {}

	ThreadSafeResource(size_t numReserved) : mResource(numReserved) {}

	ION_RESTRICT_RETURN_VALUE void* Allocate(size_t len, size_t align) ION_ATTRIBUTE_MALLOC
	{
		AutoLock<Mutex> lock(mMutex);
		return mResource.Allocate(len, align);
	}

	void Deallocate(void* p, size_t s)
	{
		AutoLock<Mutex> lock(mMutex);
		mResource.Deallocate(p, s);
	}

	void* Reallocate(void* p, size_t s, [[maybe_unused]] size_t oldSize, [[maybe_unused]] size_t alignment)
	{
		AutoLock<Mutex> lock(mMutex);
		return mResource.Reallocate(p, s);
	}

	void* PMRAllocate(size_t len, size_t align) final { return Allocate(len, align); }
	void* PMRReallocate(void* p, size_t s, size_t oldSize, size_t alignment) final { return Reallocate(p, s, oldSize, alignment); }
	void PMRDeallocate(void* p, size_t s) final { Deallocate(p, s); }

private:
	Mutex mMutex;
};
#else
{
public:
	ThreadSafeResource() {}
	ThreadSafeResource(size_t) {}
};
#endif
}  // namespace ion
