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
#include <ion/debug/AccessGuard.h>
#include <ion/concurrency/Mutex.h>

namespace ion
{
// Abstraction for a data structure that is protected with a synchronization primitive.
template <typename T, typename MutexType = ion::Mutex>
class Synchronized
{
public:
	template <typename... Args>
	Synchronized(Args&&... args) : mInternalData(std::forward<Args>(args)...)
	{
	}

	// Concurrent write access, will block if already accessed
	template <typename Callback>
	inline void Access(Callback&& callback)
	{
		ion::AutoLock<MutexType> lock(mMutex);
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		callback(mInternalData);
	}

	// Concurrent read access, will block if already accessed
	// #TODO: Don't block other read accesses
	template <typename Callback>
	inline void Access(Callback&& callback) const
	{
		ion::AutoLock<const MutexType> lock(mMutex);
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		callback(mInternalData);
	}

	template <typename Callback>
	[[nodiscard]] inline bool TryAccess(Callback&& callback)
	{
		if (mMutex.TryLock())
		{
			{
				ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
				callback(mInternalData);
			}
			mMutex.Unlock();
			return true;
		}
		return false;
	}

	template <typename Callback>
	[[nodiscard]] inline bool TryAccess(Callback&& callback) const
	{
		if (mMutex.TryLock())
		{
			{
				ION_ACCESS_GUARD_READ_BLOCK(mGuard);
				callback(mInternalData);
			}
			mMutex.Unlock();
			return true;
		}
		return false;
	}

	// Assume thread safe write access, debug build will assert if accessed by other thread at the same time
	template <typename Callback>
	inline void AssumeThreadSafeAccess(Callback&& callback)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		callback(mInternalData);
	}

	// Assume thread safe read access, debug build will assert if write-accessed by other thread at the same time
	template <typename Callback>
	inline void AssumeThreadSafeAccess(Callback&& callback) const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		callback(mInternalData);
	}

	Synchronized(const Synchronized& other) : mInternalData(other.BeginAccess()) { other.EndAccess(); }
	Synchronized(Synchronized&& other) : mInternalData(std::move(other.BeginAccessWithMove())) { other.EndAccess(); }
	Synchronized(Synchronized const&& other) : mInternalData(std::move(other.BeginAccessWithMove())) { other.EndAccess(); }
	void operator=(Synchronized const& other)
	{
		BeginAccess();
		other.BeginAccess();
		mInternalData = other.mInternalData;
		other.EndAccess();
		EndAccess();
	}
	void operator=(Synchronized const&& other)
	{
		BeginAccess();
		other.BeginAccess();
		mInternalData = std::move(other.mInternalData);
		other.EndAccess();
		EndAccess();
	}

	void operator=(Synchronized&& other)
	{
		BeginAccess();
		other.BeginAccess();
		mInternalData = std::move(other.mInternalData);
		other.EndAccess();
		EndAccess();
	}

private:
	inline const T& BeginAccess() const
	{
		mMutex.Lock();
		return mInternalData;
	}

	inline T& BeginAccess()
	{
		mMutex.Lock();
		return mInternalData;
	}

	inline T&& BeginAccessWithMove()
	{
		mMutex.Lock();
		return std::move(mInternalData);
	}

	inline void EndAccess() const { mMutex.Unlock(); }

	ION_ACCESS_GUARD(mGuard);
	MutexType mMutex;
	T mInternalData;
};

}  // namespace ion
