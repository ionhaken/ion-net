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

namespace ion
{
// Locks synchronization primitive T until the end of AutoLock's life time.
template <typename T>
class AutoLock
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(AutoLock<T>);
	const T& mMutex;

public:
	AutoLock(const T& cs) : mMutex(cs) { mMutex.Lock(); }
	~AutoLock() { mMutex.Unlock(); }
};

template <typename T>
class AutoReadLock
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(AutoReadLock<T>);
	const T& mMutex;

public:
	AutoReadLock(const T& cs) : mMutex(cs) { mMutex.LockReadOnly(); }
	~AutoReadLock() { mMutex.UnlockReadOnly(); }
};

template <typename T>
class AutoDeferLock
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(AutoDeferLock);
	const T& mMutex;
	bool mIsLocked;

public:
	AutoDeferLock(const T& cs) : mMutex(cs), mIsLocked(mMutex.TryLock()) {}
	bool IsLocked() const { return mIsLocked; }
	~AutoDeferLock()
	{
		if (mIsLocked)
		{
			mMutex.Unlock();
		}
	}
};

template <typename T>
class AutoDeferReadLock
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(AutoDeferReadLock);
	const T& mMutex;
	bool mIsLocked;

public:
	AutoDeferReadLock(const T& cs) : mMutex(cs), mIsLocked(mMutex.TryLockReadOnly()) {}
	bool IsLocked() const { return mIsLocked; }
	~AutoDeferReadLock()
	{
		if (mIsLocked)
		{
			mMutex.UnlockReadOnly();
		}
	}
};
}  // namespace ion
