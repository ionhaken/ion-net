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
#include <ion/concurrency/AutoLock.h>
#include <ion/container/ObjectWrapper.h>
#include <ion/concurrency/Mutex.h>
#include <ion/time/Clock.h>
#include <ion/util/Math.h>
#include <atomic>

namespace ion
{
// This class abstracts thread synchronization operations, i.e., thread waiting for waking up and waking up a thread.
class ThreadSynchronizer : public Mutex
{
	friend class ThreadSynchronizerLock;

public:
	ThreadSynchronizer();

	~ThreadSynchronizer();

	inline void Lock() { Mutex::Lock(); }

	inline bool TryLock() { return Mutex::TryLock(); }

	inline void Unlock() { Mutex::Unlock(); }

	void Wait(TimeMS time);

	inline UInt NumWaitingThreads() const { return ion::SafeRangeCast<UInt>(mWaitingThreads); }

private:
	void NotifyAll();

	void NotifyOne();

#if ION_PLATFORM_MICROSOFT
	using ConditionVariableWrapper = ObjectWrapper<sizeof(void*), ION_ARCH_DATA_UNIT>;
#else
	#if defined(ION_ARCH_ARM_64) || defined(ION_ARCH_X86_64)
		#if ION_PLATFORM_LINUX
	using ConditionVariableWrapper = ObjectWrapper<48, ION_ARCH_DATA_UNIT>;
		#else
	using ConditionVariableWrapper = ObjectWrapper<48, 4>;
		#endif
	#else
	using ConditionVariableWrapper = ObjectWrapper<4, 4>;
	#endif
#endif
	ConditionVariableWrapper mConditionVariable;
	std::atomic<size_t> mWaitingThreads = 0;
};

class ThreadPool;
class ThreadSynchronizerLock
{
	ThreadSynchronizer& mSynchronizer;
	UInt mNumThreadsToWake = 0;

	friend class AutoLock<ThreadSynchronizer>;
	friend class AutoDeferLock<ThreadSynchronizer>;
	ThreadSynchronizerLock(ThreadSynchronizer& aSynchronizer) : mSynchronizer(aSynchronizer) {}

public:

	ThreadSynchronizer& Synchronizer() { return mSynchronizer; }

	virtual ~ThreadSynchronizerLock() {}

	void UnlockAndWaitUntil(TimeUS time)
	{
		DoWakeUps();
		TimeDeltaMS sleepTimeMS = DeltaTime(time, SteadyClock::GetTimeUS()) / 1000;
		if (sleepTimeMS > 0)
		{
			UnlockAndWaitForMillis(ion::TimeMS(sleepTimeMS));
		}
	}

	void UnlockAndWaitForMillis(TimeMS sleepTime)
	{
		DoWakeUps();
		mSynchronizer.Wait(ion::Min(TimeMS(sleepTime), TimeMS(60 * 1000u)));
	}

	void UnlockAndWait()
	{
		DoWakeUps();
		mSynchronizer.Wait(0xFFFFFFFF);
	}

	// Unlock and wait, but also ensure that blocked workers have companion workers.
	void UnlockAndWaitEnsureWork(ThreadPool& threadPool);

	template <typename TPredicate>
	void UnlockAndWaitFor(TPredicate&& predicate)
	{
		DoWakeUps();
		while (!predicate())
		{
			mSynchronizer.Wait(0xFFFFFFFF);
		}
	}

	// Notifies other threads after lock has been exited
	inline UInt NotifyAll()
	{
		mNumThreadsToWake = mSynchronizer.NumWaitingThreads();
		return mNumThreadsToWake;
	}

	inline UInt Notify(UInt num)
	{
		UInt numThreadsToWake = ion::Min(num, mSynchronizer.NumWaitingThreads());	
		mNumThreadsToWake = numThreadsToWake;
		return numThreadsToWake;
	}

	inline UInt NotifyOne()
	{
		UInt numThreadsToWake = mSynchronizer.NumWaitingThreads() != 0 ? 1u : 0u;
		mNumThreadsToWake += numThreadsToWake;
		return numThreadsToWake;
	}

	inline UInt NumWaitingThreads()
	{
		return mSynchronizer.NumWaitingThreads();
	}

protected:
	void DoWakeUps()
	{
		if (mNumThreadsToWake > 0)
		{
			if (mNumThreadsToWake > 1)
			{
				mSynchronizer.NotifyAll();
			}
			else
			{
				mSynchronizer.NotifyOne();
			}
		}
	}
};

template <>
class AutoLock<ThreadSynchronizer> : public ThreadSynchronizerLock
{
public:
	AutoLock(ThreadSynchronizer& aSynchronizer) : ThreadSynchronizerLock(aSynchronizer) { Synchronizer().Lock(); }

	~AutoLock()
	{
		DoWakeUps();
		// Unlock mutex after notification for "predictable scheduling behavior"
		// https://linux.die.net/man/3/pthread_cond_signal
		Synchronizer().Unlock();
	}	
};

template <>
class AutoDeferLock<ThreadSynchronizer> : public ThreadSynchronizerLock
{
	bool mIsLocked;

public:
	AutoDeferLock(ThreadSynchronizer& aSynchronizer) : ThreadSynchronizerLock(aSynchronizer) { mIsLocked = Synchronizer().TryLock(); }
	bool IsLocked() const { return mIsLocked; }
	~AutoDeferLock()
	{
		if (mIsLocked)
		{
			DoWakeUps();
			// Unlock mutex after notification for "predictable scheduling behavior"
			// https://linux.die.net/man/3/pthread_cond_signal
			Synchronizer().Unlock();
		}
	}
};
}  // namespace ion
