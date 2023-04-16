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
#include <ion/debug/Profiling.h>

#include <ion/concurrency/SCThreadSynchronizer.h>

#include <ion/core/Core.h>

#if ION_SC_THREAD_SYNCHRONIZER_USE_EVENT == 1
#include <ion/hw/CPU.inl>
#include <ion/hw/TimeCaps.h>
#endif

ion::SCThreadSynchronizer::SCThreadSynchronizer() :
#if ION_SC_THREAD_SYNCHRONIZER_USE_EVENT == 0
	mIsStarving(true),
#endif
	mIsRunning(true)
{
#if ION_SC_THREAD_SYNCHRONIZER_USE_EVENT == 1
	mEventList = ::CreateEvent(0, false, false, 0);
#endif
}

ion::SCThreadSynchronizer::~SCThreadSynchronizer()
{
#if ION_SC_THREAD_SYNCHRONIZER_USE_EVENT == 1
	if (mEventList != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(mEventList);
		mEventList = INVALID_HANDLE_VALUE;
	}
#endif
}

bool ion::SCThreadSynchronizer::TryWait()
{
#if ION_SC_THREAD_SYNCHRONIZER_USE_EVENT == 1
	if (!mIsRunning.load(std::memory_order_acquire))
	{
		return false;
	}
	::WaitForSingleObjectEx(mEventList, INFINITE, FALSE);
#else
	AutoLock<ThreadSynchronizer> lock(mSynchronizer);
	if (mIsStarving.load(std::memory_order_acquire))
	{
		if (!mIsRunning)
		{
			return false;
		}
		lock.UnlockAndWait();
	}
	mIsStarving.store(true, std::memory_order_release);
#endif
	return true;
}

bool ion::SCThreadSynchronizer::TryWaitUntil(TimeUS time)
{
#if ION_SC_THREAD_SYNCHRONIZER_USE_EVENT == 1
	if (!mIsRunning.load(std::memory_order_acquire))
	{
		return false;
	}
	auto now = SteadyClock::GetTimeUS();
	TimeDeltaMS sleepTimeMS = DeltaTime(time, now) / 1000;
	if (sleepTimeMS > 0)
	{
		TimeCaps caps(sleepTimeMS);
		::WaitForSingleObjectEx(mEventList, TimeMS(sleepTimeMS), FALSE);
	}
#else
	AutoLock<ThreadSynchronizer> lock(mSynchronizer);
	if (mIsStarving.load(std::memory_order_acquire))
	{
		if (!mIsRunning)
		{
			return false;
		}
		lock.UnlockAndWaitUntil(time);
	}
	mIsStarving.store(true, std::memory_order_release);
#endif
	return true;
}

bool ion::SCThreadSynchronizer::TryWaitFor(TimeUS micros)
{
#if ION_SC_THREAD_SYNCHRONIZER_USE_EVENT == 1	
	if (!mIsRunning.load(std::memory_order_acquire))
	{
		return false;
	}
	TimeCaps caps(micros/1000);
	::WaitForSingleObjectEx(mEventList, micros / 1000, FALSE);
#else
	AutoLock<ThreadSynchronizer> lock(mSynchronizer);
	if (mIsStarving.load(std::memory_order_acquire))
	{
		if (!mIsRunning)
		{
			return false;
		}
		lock.UnlockAndWaitForMillis(micros / 1000);
	}
	mIsStarving.store(true, std::memory_order_release);
#endif
	return true;
}

ion::UInt ion::SCThreadSynchronizer::Signal()
{
#if ION_SC_THREAD_SYNCHRONIZER_USE_EVENT == 1
	::SetEvent(mEventList);
	return 1;
#else
	if (mIsStarving.load(std::memory_order_acquire))
	{
		AutoLock<ThreadSynchronizer> lock(mSynchronizer);
		mIsStarving.store(false, std::memory_order_release);
		return lock.NotifyOne();
	}
	return 0;
#endif
}

void ion::SCThreadSynchronizer::Stop()
{
#if ION_SC_THREAD_SYNCHRONIZER_USE_EVENT == 1
	mIsRunning.store(false, std::memory_order_release);
	Signal();
#else
	AutoLock<ThreadSynchronizer> lock(mSynchronizer);
	mIsRunning = false;
	lock.NotifyAll();
#endif
}

bool ion::SCThreadSynchronizer::IsActive() const
{
	return mIsRunning;
}
