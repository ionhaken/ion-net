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
#include <ion/jobs/TaskQueue.h>
#include <ion/jobs/SchedulerConfig.h>

#define ION_MAIN_THREAD_IS_A_WORKER 1

namespace ion
{
class Runner;

class ThreadPool
{
	ThreadPool& operator=(const ThreadPool&) = delete;
	const UInt mNumWorkers;
	const UInt mNumWorkerQueues;

	std::atomic<Int> mCompanionWorkersNeeded;
	std::atomic<UInt> mCompanionWorkersActive;
	ThreadSynchronizer mCompanionSynchronizer;
	TaskQueue::Stats mStats;

public:
	const UInt GetWorkerCount() const { return mNumWorkers; }
	const UInt GetQueueCount() const { return mNumWorkerQueues; }

	void AddCompanionWorker();

	void RemoveCompanionWorker() { mCompanionWorkersNeeded--; }

	explicit ThreadPool(UInt hwConcurrency);

	void StopThreads();

	~ThreadPool();

	//	bool HasFreeWorkers() const { return mStats.joblessQueueIndex != Thread::NoQueueIndex; }

	// Returns index of jobless queue if available and it's not owned by current thread
	// Thread::NoQueueIndex is returned if no suitable index is found
	Thread::QueueIndex UseJoblessQueueIndexExceptThis()
	{
		const Thread::QueueIndex index = mStats.joblessQueueIndex;
		if (index != Thread::NoQueueIndex)
		{
			if (index == ion::Thread::GetQueueIndex())
			{
				return Thread::NoQueueIndex;
			}
			mStats.joblessQueueIndex = Thread::NoQueueIndex;
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

	ION_FORCE_INLINE void AddTaskWithoutWakeUp(ion::Task&& task, Thread::QueueIndex index)
	{
		ION_ASSERT(index < mNumWorkerQueues, "Invalid queue index " << index);
		mTaskQueues[index].PushTask(std::move(task));
		ION_ASSERT(index != ion::Thread::GetQueueIndex() || GetWorkerCount() == 0, "Trying to notify own thread");
	}

	inline void AddTasks(Thread::QueueIndex firstQueueIndex, UInt count, BaseJob* job)
	{
		ion::Thread::QueueIndex nextIndex = firstQueueIndex;
		Int leftToWoken = Int(count);
		for (size_t i = 0;;)
		{
			AddTaskWithoutWakeUp(Task(job), nextIndex);

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

	inline UInt PushTask(ion::Task&& task)
	{
		UInt index = UseNextQueueIndexExceptThis();
		ION_ASSERT(index != ion::Thread::GetQueueIndex() || GetWorkerCount() == 0, "Trying to notify own thread");
		mTaskQueues[index].PushTask(std::move(task));
		WakeUp(1, index);
		return index;
	}

	void PushLongTask(ion::Task&& task);

	void AddMainThreadTask(ion::Task&& task);

	inline void WakeUp(Int numLeftToActivate, UInt index)
	{
		UInt wakeIndex = index;
		for (;;)
		{
			auto woken = mTaskQueues[wakeIndex].WakeUp();
			wakeIndex = (wakeIndex + 1) % mNumWorkerQueues;
			if (woken)
			{
				numLeftToActivate -= woken;
				if (numLeftToActivate <= 0)
				{
					break;
				}
			}
			else
			{
				if (wakeIndex == index || mStats.slackingWorkers <= 0)
				{
					break;
				}
			}
		}
		Update(index);
	}

	Thread::QueueIndex DoJobWork(UInt target, BaseJob* currentJob);

	Thread::QueueIndex DoJobWork(UInt initialTarget)
	{
		for (UInt i = 0; i < mNumWorkerQueues; i++)
		{
			UInt target = (i + initialTarget) % mNumWorkerQueues;
			auto status = mTaskQueues[target].Run();
			switch (status)
			{
			case TaskQueue::Status::Waiting:
				return Thread::QueueIndex(target);
			case TaskQueue::Status::Empty:
				return Thread::QueueIndex(target + 1);
			default:
				break;
			}
		}
		return ion::Thread::NoQueueIndex;
	}

	void WorkOnMainThread();
	void WorkOnMainThreadNoBlock();

	Thread::QueueIndex RandomQueueIndex() const;

private:
	Thread::QueueIndex RandomQueueIndexExceptThis();

	void Update(UInt index)
	{
		if (mStats.joblessQueueIndex == Thread::NoQueueIndex)
		{
			auto newIndex = FindFreeQueue(index);
			if (newIndex != Thread::NoQueueIndex && mStats.joblessQueueIndex == Thread::NoQueueIndex)
			{
				mStats.joblessQueueIndex = newIndex;
			}
		}
	}

	Thread::QueueIndex FindFreeQueue(UInt index)
	{
		for (Thread::QueueIndex i = 1; i < mNumWorkerQueues; i++)
		{
			UInt target = (i + index) % mNumWorkerQueues;
			if (mTaskQueues[target].IsMaybeEmpty())
			{
				return Thread::QueueIndex(target);
			}
		}
		return Thread::NoQueueIndex;
	}

	bool Worker(Thread::QueueIndex index);
	bool CompanionWorker();
	ion::TaskQueue::Status ProcessQueues(UInt index);

	ION_ALIGN_CACHE_LINE ion::Array<TaskQueue, MaxQueues> mTaskQueues;
	TaskQueue& MainThreadQueue() { return mNumWorkers > 0 ? mTaskQueues[mNumWorkerQueues] : mTaskQueues[0]; }

	TaskQueue mLongTaskQueue;
	std::atomic<UInt> mNumAvailableLongTasks;

	// Cold data
	Vector<CorePtr<Runner>, ion::CoreAllocator<CorePtr<Runner>>> mCompanionThreads;
	Vector<Runner, ion::CoreAllocator<Runner>> mThreads;
	std::atomic<bool> mAreCompanionsActive;
	JOB_SCHEDULER_STATS(ion::StopClock mTimer);
};
}  // namespace ion
