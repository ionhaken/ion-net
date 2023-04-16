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
#include <ion/util/IdPool.h>
#include <ion/database/DBComponentStoreBase.h>

namespace ion
{
template <typename T, typename Allocator = ion::GlobalAllocator<T>>
class ComponentStore : public ComponentStoreBase
{
public:
	typedef T Index;

	ComponentStore() {}

	template <typename Resource>
	ComponentStore(Resource* resource) : mIndexPool(resource)
	{
	}

	static constexpr T INVALID_INDEX = static_cast<T>(-1);

#if ION_COMPONENT_READ_WRITE_CHECKS
	void OnCreated(T index)
	{
		ION_CHECK(mStoreGuard.IsFree(), "Cannot use components when creating or deleting componets");
		mFieldGuard[index].StartWriting();
	}

	void OnDeleted(T index)
	{
		ION_CHECK(mStoreGuard.IsFree(), "Cannot use components when creating or deleting componets");
		mFieldGuard[index].StopWriting();
	}

	void OnCreated(T index) const
	{
		ION_CHECK(mStoreGuard.IsFree(), "Cannot use components when creating or deleting components");
		mFieldGuard[index].StartReading();
	}

	void OnDeleted(T index) const
	{
		ION_CHECK(mStoreGuard.IsFree(), "Cannot use components when creating or deleting components");
		mFieldGuard[index].StopReading();
	}

#else
	void OnCreated(T) {}
	void OneDeleted(T) {}
	void OnCreated(T) const {}
	void OnDeleted(T) const {}
#endif

protected:
#if ION_COMPONENT_READ_WRITE_CHECKS || ION_COMPONENT_VERSION_NUMBER
	void CloneProtection(const ComponentStore<T, Allocator>& other)
#else
	void CloneProtection(const ComponentStore<T, Allocator>&)
#endif
	{
#if ION_COMPONENT_READ_WRITE_CHECKS
		mFieldGuard.Resize(other.mFieldGuard.Size());
#endif
#if ION_COMPONENT_VERSION_NUMBER
		mVersions = other.mVersions;
#endif
	}

#if ION_COMPONENT_VERSION_NUMBER
	T GetVersion(T index) const { return mVersions[index]; }

	void IncreaseVersion(T index) { mVersions[index]++; }
#endif

#if ION_COMPONENT_READ_WRITE_CHECKS || ION_COMPONENT_VERSION_NUMBER
	void ResizeProtection(T index)
#else
	void ResizeProtection(T)
#endif
	{
#if ION_COMPONENT_READ_WRITE_CHECKS
		if (mFieldGuard.Size() <= index)
		{
			mFieldGuard.Resize(index + 1, (index + 1) * 2);
		}
#endif
#if ION_COMPONENT_VERSION_NUMBER
		if (mVersions.Size() <= index)
		{
			mVersions.Resize(index + 1, (index + 1) * 2);
		}
#endif
	}

	ion::IdPool<T, Allocator> mIndexPool;

private:
#if ION_COMPONENT_VERSION_NUMBER
	ion::Vector<T> mVersions;
#endif
};
}  // namespace ion
