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
#include <atomic>
#include <ion/container/Vector.h>
#include <ion/container/Algorithm.h>
#include <ion/jobs/JobQueue.h>
#include <ion/jobs/SchedulerConfig.h>

#define ION_MAIN_THREAD_IS_A_WORKER 1

namespace ion
{
class Runner;

class ThreadPool
{
	ThreadPool& operator=(const ThreadPool&) = delete;

public:
	ION_FORCE_INLINE const UInt GetWorkerCount() const { return mNumWorkers; }
	const UInt GetQueueCount() const { return mNumWorkerQueues; }

	void AddCompanionWorker(Thread::QueueIndex = Thread::NoQueueIndex);

	void RemoveCompanionWorker() { mCompanionWorkersNeeded--; }

	explicit ThreadPool(UInt hwConcurrency);

	void StopThreads();

	~ThreadPool();

	//	bool HasFreeWorkers() const { return mStats.joblessQueueIndex != Thread::NoQueueIndex; }

	// Returns index of jobless queue if available and it's not owned by current thread
	// Thread::NoQueueIndex is returned if no suitable index is found
	Thread::QueueIndex UseJoblessQueueIndexExceptThis()
	{
		const Thread::QueueIndex index = mStats.mJoblessQueueIndex;
		if (index != Thread::NoQueueIndex)
		{
			if (index == ion::Thread::GetQueueIndex())
			{
				return Thread::NoQueueIndex;
			}
			mStats.mJoblessQueueIndex = Thread::NoQueueIndex;
		}
		return index;
	}

	Thread::QueueIndex UseNextQueueIndexExceptThis()
	{
		Thread::QueueIndex index = UseJoblessQueueIndexExceptThis();
		if (index == Thread::NoQueueIndex)
		{
			index = RandomQueueIndexExceptThis();
		}
		return index;
	}

	ION_FORCE_INLINE void AddTaskWithoutWakeUp(ion::JobWork&& task, Thread::QueueIndex index)
	{
		ION_ASSERT(index < mNumWorkerQueues, "Invalid queue index " << index);
		mJobQueues[index].PushTask(std::move(task));
		ION_ASSERT(index != ion::Thread::GetQueueIndex() || GetWorkerCount() == 0, "Trying to notify own thread");
	}

	inline void AddTasks(Thread::QueueIndex firstQueueIndex, UInt count, BaseJob* job)
	{
		ion::Thread::QueueIndex nextIndex = firstQueueIndex;
		Int leftToWoken = Int(count);
		for (size_t i = 0;;)
		{
			AddTaskWithoutWakeUp(JobWork(job), nextIndex);

			++i;
			if (i >= count)
			{
				break;
			}
			nextIndex = (nextIndex + 1) % GetQueueCount();
			if (nextIndex == ion::Thread::GetQueueIndex())
			{
				nextIndex = (nextIndex + 1) % GetQueueCount();
			}
		}
		WakeUp(leftToWoken, firstQueueIndex);
	}

	inline UInt PushTask(ion::JobWork&& task)
	{
		UInt index = UseNextQueueIndexExceptThis();
		ION_ASSERT(index != ion::Thread::GetQueueIndex() || GetWorkerCount() == 0, "Trying to notify own thread");
		mJobQueues[index].PushTask(std::move(task));
		WakeUp(1, index);
		return index;
	}

	void PushDelayedTask(ion::JobWork&& task);

	void PushDelayedTasks(Vector<JobWork, ion::CoreAllocator<JobWork>>& tasks);

	void PushIOTask(ion::JobWork&& task);

	void PushBackgroundTask(ion::JobWork&& task);

	void AddMainThreadTask(ion::JobWork&& task);

	void WakeUp(Int numLeftToActivate, UInt index);

	Thread::QueueIndex DoJobWork(UInt target, BaseJob* currentJob);

	Thread::QueueIndex DoJobWork(UInt initialTarget);

	void WorkOnMainThread();
	void WorkOnMainThreadNoBlock();

	Thread::QueueIndex RandomQueueIndex() const;

private:
	Thread::QueueIndex RandomQueueIndexExceptThis();

	void Update(UInt index)
	{
		if (mStats.mJoblessQueueIndex == Thread::NoQueueIndex)
		{
			Thread::QueueIndex newIndex = FindFreeQueue(index);
			if (newIndex != Thread::NoQueueIndex && mStats.mJoblessQueueIndex == Thread::NoQueueIndex)
			{
				mStats.mJoblessQueueIndex = newIndex;
			}
		}
	}

	Thread::QueueIndex FindFreeQueue(UInt index)
	{
		for (Thread::QueueIndex i = 1; i < mNumWorkerQueues; i++)
		{
			UInt target = (i + index) % mNumWorkerQueues;
			if (mJobQueues[target].IsMaybeEmpty())
			{
				return Thread::QueueIndex(target);
			}
		}
		return Thread::NoQueueIndex;
	}

	bool Worker(Thread::QueueIndex index);
	bool CompanionWorker(Thread::QueueIndex index);
	ion::JobQueueStatus ProcessQueues(UInt index);

	JobQueueSingleOwner& MainThreadQueue() { return mNumWorkers > 0 ? mJobQueues[mNumWorkerQueues] : mJobQueues[0]; }


	struct LongJobPool
	{
		JobQueueMultiOwner mJobQueue;
		Vector<CorePtr<Runner>, ion::CoreAllocator<CorePtr<Runner>>> mThreads;
	};

	bool LongJobWorker(LongJobPool& pool);

	ION_ALIGN_CACHE_LINE ion::Array<JobQueueSingleOwner, MaxQueues> mJobQueues;
	JobQueueMultiOwner mCompanionJobQueue;
	JobQueueStats mStats;
	const UInt mNumWorkers;
	const UInt mNumWorkerQueues;
	const UInt mMaxBackgroundWorkers;
	std::atomic<Int> mCompanionWorkersNeeded;
	std::atomic<UInt> mCompanionWorkersActive;
	std::atomic<UInt> mNumAvailableBackgroundTasks = 0;
	std::atomic<UInt> mNumBackgroundWorkers = 0;
	std::atomic<bool> mAreCompanionsActive;
	
	// Cold data
	std::atomic<UInt> mNumAvailableIOTasks = 0;
	Vector<CorePtr<Runner>, ion::CoreAllocator<CorePtr<Runner>>> mCompanionThreads;
	LongJobPool mIoJobPool;
	Vector<Runner, ion::CoreAllocator<Runner>> mThreads;
	JOB_SCHEDULER_STATS(ion::StopClock mTimer);
};
}  // namespace ion
