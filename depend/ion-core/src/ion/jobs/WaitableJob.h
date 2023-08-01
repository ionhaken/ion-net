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
#include <ion/jobs/BaseJob.h>
#include <ion/concurrency/ThreadSynchronizer.h>

namespace ion
{
class ThreadPool;
class WaitableJob : public BaseJob
{
public:
	WaitableJob(ThreadPool& tp, ion::BaseJob* sourceJob, UInt initialTasks = 1)
	  : BaseJob(sourceJob), mThreadPool(tp), mNumTasksAvailable(initialTasks), mNumTasksInProgress(initialTasks)
	{
	}

	WaitableJob(const WaitableJob& other)
	  : mThreadPool(other.mThreadPool),
		mSynchronizer(),
		mNumTasksAvailable(other.mNumTasksAvailable.load()),
		mNumTasksInProgress(other.mNumTasksInProgress.load())
	{
	}

	virtual ~WaitableJob() { ION_ASSERT(mNumTasksInProgress == 0, "Destroying job before tasks complete"); }

	void Wait();

protected:
	inline void OnTaskStarted()
	{
		ION_ASSERT(mNumTasksAvailable > 0, "Invalid available task count");
		mNumTasksAvailable--;
	}

	void OnTaskDone()
	{
		AutoLock<ThreadSynchronizer> lock(mSynchronizer);
		ION_ASSERT(mNumTasksInProgress > 0, "Invalid task count");
		if (--mNumTasksInProgress == 0)
		{
			lock.NotifyAll();
		}
	}

	ThreadPool& GetThreadPool() { return mThreadPool; }
	const ThreadPool& GetThreadPool() const { return mThreadPool; }

	ion::ThreadSynchronizer& GetSynchronizer() { return mSynchronizer; }

	std::atomic<UInt>& NumTasksInProgress() { return mNumTasksInProgress; }
	std::atomic<UInt>& NumTasksAvailable() { return mNumTasksAvailable; }

private:
	bool BlockingWait(bool taskQueueEmpty);

	ThreadPool& mThreadPool;
	ion::ThreadSynchronizer mSynchronizer;
	std::atomic<UInt> mNumTasksAvailable;	// tasks not completed and not being processed
	std::atomic<UInt> mNumTasksInProgress;	// tasks not completed
};
}  // namespace ion
