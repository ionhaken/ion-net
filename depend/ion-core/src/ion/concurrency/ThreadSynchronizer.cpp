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
#include <ion/concurrency/Thread.h>
#include <ion/concurrency/ThreadSynchronization.inl>
#include <ion/concurrency/ThreadSynchronizer.h>

#include <ion/jobs/ThreadPool.h>

#include <ion/hw/TimeCaps.h>
#include <ion/tracing/Log.h>
#if ION_PLATFORM_LINUX
	#include <sys/time.h>
	#include <errno.h>
#endif

namespace ion
{
ThreadSynchronizer::ThreadSynchronizer() : Mutex()
{
	ConditionVariableWrapper::Proxy<ConditionVariableType>::Construct(mConditionVariable);

#if ION_PLATFORM_MICROSOFT
	InitializeConditionVariable(mConditionVariable.Ptr<ConditionVariableType>());
#else
	pthread_condattr_t attr;
	int res = pthread_condattr_init(&attr);
	ION_ASSERT(res == 0, "pthread_condattr_init failed");
	res = pthread_cond_init(&mConditionVariable.Ptr<ConditionVariableType>()->cond, &attr);
	ION_ASSERT(res == 0, "pthread_cond_init failed");
	res = pthread_condattr_destroy(&attr);
	ION_ASSERT(res == 0, "pthread_condattr_destroy failed");
#endif
}

ThreadSynchronizer::~ThreadSynchronizer()
{
#if ION_PLATFORM_MICROSOFT
#else
	int res = pthread_cond_destroy(&mConditionVariable.Ptr<ConditionVariableType>()->cond);
	ION_ASSERT(res == 0, "pthread_cond_destroy failed");
#endif
	ConditionVariableWrapper::Proxy<ConditionVariableType>::Destroy(mConditionVariable);
}

void ThreadSynchronizer::NotifyAll()
{
#if ION_PLATFORM_MICROSOFT
	WakeAllConditionVariable(mConditionVariable.Ptr<ConditionVariableType>());
#else
	int res = pthread_cond_broadcast(&mConditionVariable.Ptr<ConditionVariableType>()->cond);
	ION_ASSERT(res == 0, "pthread_cond_broadcast failed");
#endif
}

void ThreadSynchronizer::NotifyOne()
{
#if ION_PLATFORM_MICROSOFT
	WakeConditionVariable(mConditionVariable.Ptr<ConditionVariableType>());
#else
	int res = pthread_cond_signal(&mConditionVariable.Ptr<ConditionVariableType>()->cond);
	ION_ASSERT(res == 0, "pthread_cond_signal failed");
#endif
}

void ThreadSynchronizer::Wait(TimeMS milliseconds)
{
	mWaitingThreads++;
#if ION_PLATFORM_MICROSOFT
	ion::TimeCaps caps(milliseconds);
	SleepConditionVariableSRW(mConditionVariable.Ptr<ConditionVariableType>(), mMutex.Ptr<MutexType>(), milliseconds, 0);
#else
	struct timespec ts;

	struct timeval tv;
	gettimeofday(&tv, NULL);

	uint64_t nanoseconds =
	  ((uint64_t)tv.tv_sec) * 1000 * 1000 * 1000 + (uint64_t)milliseconds * 1000 * 1000 + ((uint64_t)tv.tv_usec) * 1000;

	ts.tv_sec = (time_t)(nanoseconds / 1000 / 1000 / 1000);
	ts.tv_nsec = (long)(nanoseconds - ((uint64_t)ts.tv_sec) * 1000 * 1000 * 1000);

	int ret = pthread_cond_timedwait(&mConditionVariable.Ptr<ConditionVariableType>()->cond, &mMutex.Ptr<MutexType>()->mutex, &ts);
	ION_ASSERT(ret == 0 || ret == ETIMEDOUT || ret == EINTR, "Unexpected return value");
#endif
	mWaitingThreads--;
}

void ThreadSynchronizerLock::UnlockAndWaitEnsureWork(ThreadPool& threadPool)
{
	ION_ASSERT(ion::Thread::GetCurrentJob()->GetType() != BaseJob::Type::IOJob, "Workers only, IO work should not spawn companions");
	// Currently adding companion worker to do other tasks while we are waiting
	// I.e. when our job is done there's going to be more workers active than what's
	// optimal, but we are able to continue here as soon as possible.
	auto queueIndex = ion::Thread::GetQueueIndex();
	bool isMainThreadOrWorker = queueIndex != ion::Thread::NoQueueIndex;
	if (isMainThreadOrWorker)
	{
		if ION_LIKELY (threadPool.GetWorkerCount() > 0)
		{
			threadPool.AddCompanionWorker();
			UnlockAndWait();
			threadPool.RemoveCompanionWorker();
		}
		else
		{
			DoWakeUps();
			Synchronizer().Unlock();
			threadPool.WorkOnMainThreadNoBlock();
			Synchronizer().Lock();
		}
	}
	else
	{
		threadPool.AddCompanionWorker();
		UnlockAndWait();
		threadPool.RemoveCompanionWorker();
	}
}

}  // namespace ion
