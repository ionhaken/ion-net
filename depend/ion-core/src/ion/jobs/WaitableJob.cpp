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
#include <ion/core/Core.h>
#include <ion/jobs/WaitableJob.h>
#include <ion/jobs/ThreadPool.h>
#include <ion/debug/Profiling.h>

ION_CODE_SECTION(".jobs")
void ion::WaitableJob::Wait()
{
	// Wait for job completion and try to do tasks for this job when available.
	// Note: must have lock before exiting hence doing BlockingWait().
	// Otherwise other thread notifying this thread might access deleted task
	if (mNumTasksAvailable == 0)
	{
		if (BlockingWait(false))
		{
			return;
		}
	}
	UInt lastQueueIndex = ion::Thread::GetQueueIndex();
	if ION_UNLIKELY (lastQueueIndex == ion::Thread::NoQueueIndex)
	{
		lastQueueIndex = mThreadPool.RandomQueueIndex();
	}
	for (;;)
	{
		lastQueueIndex = mThreadPool.DoJobWork(lastQueueIndex, this);
		if (lastQueueIndex == ion::Thread::NoQueueIndex)
		{
			if (BlockingWait(true))
			{
				return;
			}
		}
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
bool ion::WaitableJob::BlockingWait(bool taskQueueEmpty)
{
	ION_PROFILER_SCOPE(Scheduler, "Block Until Job Done");
	AutoLock<ThreadSynchronizer> lock(mSynchronizer);
	if (mNumTasksAvailable > 0)	 // Check no tasks were added while locking
	{
		if (taskQueueEmpty)
		{
			// Tasks can be available when task queue is empty, but other thread did not
			// yet reduce task available count. Additionally, we could have received more tasks.
			ION_PROFILER_SCOPE(Scheduler, "Give time to other thread");
			lock.UnlockAndWaitForMillis(1);
			if (mNumTasksAvailable > 0)
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	// All tasks are already being processed: Wait until tasks complete

	if (mNumTasksInProgress == 0)
	{
		return true;
	}

	// Currently adding companion worker to do other tasks while we are waiting
	// I.e. when our job is done there's going to be more workers active than what's
	// optimal, but we are able to continue here as soon as possible.
	// #TODO: If we are companion worker, continue working on task pool instead of
	// spawning other companion workers.
	ION_ASSERT(mNumTasksAvailable == 0 && mNumTasksInProgress > 0, "Invalid state");
	bool spawnCompanion = ion::Thread::GetQueueIndex() != ion::Thread::NoQueueIndex;
	if (spawnCompanion)
	{
		if ION_LIKELY (mThreadPool.GetWorkerCount() > 0)
		{
			mThreadPool.AddCompanionWorker();
			lock.UnlockAndWait();
			mThreadPool.RemoveCompanionWorker();
		}
		else
		{
			mThreadPool.WorkOnMainThreadNoBlock();
		}
	}
	else
	{
		lock.UnlockAndWait();
	}

	return mNumTasksInProgress == 0 && mNumTasksAvailable == 0;
}
ION_SECTION_END
