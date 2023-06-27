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
#include <ion/container/Array.h>
#include <ion/concurrency/SCThreadSynchronizer.h>
#include <ion/debug/AccessGuard.h>

// #ION_TODO: Remove
namespace ion
{
template <typename T>
class DoubleBuffer
{
public:
	template <typename Args>
	DoubleBuffer(Args&& a, Args&& b) : mFrontData(std::forward<Args>(a)), mBackData(std::forward<Args>(b))
	{
	}

	DoubleBuffer() {}

	T& Front()
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mFrontData;
	}

	const T& Front() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mFrontData;
	}

	T& Back()
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mBackData;
	}

	const T& Back() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mBackData;
	}

	void Swap()
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		std::swap(mFrontData, mBackData);
	}

	void LockFront() const { mFrontAccess.Lock(); }

	void UnlockFront() const { mFrontAccess.Unlock(); }

	void LockBack() const { mBackAccess.Lock(); }

	void UnlockBack() const { mBackAccess.Unlock(); }

private:
	ion::Mutex mFrontAccess;
	T mFrontData;
	ion::Mutex mBackAccess;
	T mBackData;
	ION_ACCESS_GUARD(mGuard);
};
}  // namespace ion
