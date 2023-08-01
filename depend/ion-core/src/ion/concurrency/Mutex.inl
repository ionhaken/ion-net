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
#include <ion/tweakables/Tweakables.h>

#if ION_MUTEX_CONTENTION_CHECKER
	#include <ion/concurrency/Thread.h>
	#include <ion/time/Clock.h>
#endif

namespace ion
{
// Set contention timelimit to find contention issues.
TWEAKABLE_UINT("core.contention.limitms", ContentionLimitMs, 0, 0, 5000);
TWEAKABLE_BOOL("core.contention.reportonce", ContentionReportOnce, true);

#if ION_MUTEX_CONTENTION_CHECKER
inline void CheckContention(ion::RunningTimerUs& contentionTimer, bool& contentionDetected)
{
	if (TWEAKABLE_VALUE(ContentionLimitMs) > 0 && ion::Thread::GetQueueIndex() != ion::Thread::NoQueueIndex &&
		contentionTimer.Elapsed() >= TWEAKABLE_VALUE(ContentionLimitMs))
	{
		if (!contentionDetected)
		{
			contentionDetected = TWEAKABLE_VALUE(ContentionReportOnce);
			ION_CHECK_FMT_IMMEDIATE(false, "Mutex contention time limit reached;Timer=%lu us", contentionTimer.Elapsed());
		}
	}
}
#endif

ION_PLATFORM_INLINING bool Mutex::TryLock() const
{
#if ION_PLATFORM_MICROSOFT
	return TryAcquireSRWLockExclusive(mMutex.Ptr<MutexType>());
#else
	int res = pthread_mutex_trylock(&mMutex.Ref<MutexType>().mutex);
	ION_ASSERT(res == EBUSY || res == 0, "pthread_mutex_lock - failed");
	return res == 0;
#endif
}

ION_PLATFORM_INLINING void Mutex::Lock() const
{
#if ION_MUTEX_CONTENTION_CHECKER
	ion::RunningTimerUs contentionTimer;
	static bool contentionDetected = false;
#endif

#if ION_PLATFORM_MICROSOFT
	AcquireSRWLockExclusive(mMutex.Ptr<MutexType>());
#else
	int res = pthread_mutex_lock(&mMutex.Ref<MutexType>().mutex);
	ION_ASSERT(res == 0, "pthread_mutex_lock - failed");
#endif

#if ION_MUTEX_CONTENTION_CHECKER
	CheckContention(contentionTimer, contentionDetected);
#endif
}

ION_PLATFORM_INLINING void Mutex::Unlock() const
{
#if ION_PLATFORM_MICROSOFT
	ReleaseSRWLockExclusive(mMutex.Ptr<MutexType>());
#else
	int res = pthread_mutex_unlock(&mMutex.Ref<MutexType>().mutex);
	ION_ASSERT(res == 0, "pthread_mutex_unlock - failed");
#endif
}

ION_PLATFORM_INLINING bool SharedMutex::TryLockReadOnly() const
{
#if ION_PLATFORM_MICROSOFT
	return TryAcquireSRWLockShared(mMutex.Ptr<SharedMutexType>());
#else
	int res = pthread_rwlock_tryrdlock(&mMutex.Ref<SharedMutexType>().mutex);
	ION_ASSERT(res == EBUSY || res == 0, "pthread_mutex_lock - failed");
	return res == 0;
#endif
}

ION_PLATFORM_INLINING void SharedMutex::LockReadOnly() const
{
#if ION_MUTEX_CONTENTION_CHECKER
	ion::RunningTimerUs contentionTimer;
	static bool contentionDetected = false;
#endif

#if ION_PLATFORM_MICROSOFT
	AcquireSRWLockShared(mMutex.Ptr<SharedMutexType>());
#else
	int res = pthread_rwlock_rdlock(&mMutex.Ref<SharedMutexType>().mutex);
	ION_ASSERT(res == 0, "pthread_mutex_lock - failed");
#endif

#if ION_MUTEX_CONTENTION_CHECKER
	CheckContention(contentionTimer, contentionDetected);
#endif
}

ION_PLATFORM_INLINING void SharedMutex::UnlockReadOnly() const
{
#if ION_PLATFORM_MICROSOFT
	ReleaseSRWLockShared(mMutex.Ptr<SharedMutexType>());
#else
	int res = pthread_rwlock_unlock(&mMutex.Ref<SharedMutexType>().mutex);
	ION_ASSERT(res == 0, "pthread_mutex_unlock - failed");
#endif
}
}  // namespace ion
