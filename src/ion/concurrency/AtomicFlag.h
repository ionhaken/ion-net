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
#include <ion/tracing/Log.h>
#include <atomic>

namespace ion
{
// Synchronization primitive implemented using atomic flag.
class AtomicFlag
{
public:
	AtomicFlag() {}

	// Triyes to acquire a lock. Returns true only if successful.
	// Please don't use TryLock() for implementing a spinlock as spinlocking is especially harmful when cores are saturated.
	[[nodiscard]] inline bool TryLock() const { return !mIsLocked.test_and_set(std::memory_order_acquire); }

	// #TODO: Need CPP++20 support
	//[[nodiscard]] inline bool IsLocked() const { return mIsLocked.test(); }

	void Lock() const
	{
		[[maybe_unused]] bool isSuccess = TryLock();
		// Spinlocking is not supported as it's not useful in non-driver code and this is not driver library.
		// Instead of, we will just assert locking.
		ION_ASSERT(isSuccess, "Failed to acquire a lock.");
	}

	inline void Unlock() const { mIsLocked.clear(std::memory_order_release); }

private:
	mutable std::atomic_flag mIsLocked;
};

}  // namespace ion
