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
#include <ion/concurrency/Mutex.h>
#include <ion/concurrency/ThreadSynchronizer.h>

#include <atomic>

#if ION_PLATFORM_MICROSOFT
	#define ION_SC_THREAD_SYNCHRONIZER_USE_EVENT 0
#else
	#define ION_SC_THREAD_SYNCHRONIZER_USE_EVENT 0
#endif

namespace ion
{
// Single consumer thread synchronizer
class SCThreadSynchronizer
{
#if ION_SC_THREAD_SYNCHRONIZER_USE_EVENT == 1
	void* mEventList;
#else
	mutable ion::ThreadSynchronizer mSynchronizer;
	std::atomic<bool> mIsStarving;	// true only when consumer is waiting for signal
#endif

	std::atomic<bool> mIsRunning;

public:
	SCThreadSynchronizer();

	~SCThreadSynchronizer();

	bool TryWait();

	bool TryWaitUntil(TimeUS time);

	bool TryWaitFor(TimeUS time);

	UInt Signal();

	void Stop();

	bool IsActive() const;
};
}  // namespace ion
