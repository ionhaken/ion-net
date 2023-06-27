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

#include <ion/core/Core.h>
#include <ion/debug/Profiling.h>
#include <ion/container/RingBuffer.h>
#include <ion/jobs/Task.h>
#include <ion/concurrency/Thread.h>
#include <ion/concurrency/SCThreadSynchronizer.h>

#define JOB_SCHEDULER_STATS(x)	// x

namespace ion
{
constexpr ion::Thread::Priority DispatcherPriority = ion::Thread::Priority::Highest;
constexpr ion::Thread::Priority MainThreadPriority = ion::Thread::Priority::AboveNormal;
constexpr ion::Thread::Priority WorkerDefaultPriority = ion::Thread::Priority::Normal;
// Note: Extra threads must have lower priority than main/main worker threads -
// otherwise calling main/worker threads will hang when notifying companions
// if system is out of hw threads
constexpr ion::Thread::Priority LongJobPriority = ion::Thread::Priority::BelowNormal;

class TaskQueue
{
public:
	struct Stats
	{
		Stats() : slackingWorkers(0), joblessQueueIndex(Thread::NoQueueIndex) {}
		// #TODO: need revisiting, slacking workers may be useless,
		// joblessQueueIndex is used for most of decision making
		// #TODO: ShortTask/LongTask worker management needs work.
		// Active long tasks should reduce short task workers,
		// but ending of long task should wake up short task workers.
		std::atomic<Int> slackingWorkers;
		std::atomic<Thread::QueueIndex> joblessQueueIndex;
	};

	enum class Status : u8
	{
		Inactive,  // Queue deactivated
		Empty,	   // Queue is currently empty
		Locked,	   // Queue is locked by other worker
		Waiting,   // Queue might not be empty, waiting for workers
		WentEmpty  // Queue emptied by current worker
	};

	static_assert(static_cast<size_t>(Status::Empty) == 1 && static_cast<size_t>(Status::Inactive) == 0, "Check enum usage");

	static_assert(static_cast<size_t>(Status::WentEmpty) == 4 && static_cast<size_t>(Status::Waiting) == 3, "Check enum usage");

	TaskQueue() { JOB_SCHEDULER_STATS(idleTime = 0); }

	TaskQueue(const TaskQueue&) {}

	~TaskQueue() {}

	Status LongTaskRun(/*Stats& stats*/ std::atomic<Int>& workersNeeded, std::atomic<UInt>& numLongTasks)
	{
		ION_PROFILER_SCOPE(Job, "Get LongTask");
		ION_ASSERT(Thread::GetQueueIndex() == ion::Thread::NoQueueIndex, "Invalid long task worker");
		Task task;
		{
			AutoLock<Mutex> lock(mMutex);
			if (!mTasks.IsEmpty())
			{
				task = std::move(mTasks.Front());
				mTasks.PopFront();
			}
			else
			{
				return Status::Empty;
			}
		}
		ION_ASSERT(numLongTasks > 0, "Invalid long task count");
		ION_ASSERT(workersNeeded > 0, "Invalid worker count");
		numLongTasks--;
		workersNeeded--;

		ion::Thread::SetPriority(LongJobPriority);
		task.Run();
		ion::Thread::SetPriority(WorkerDefaultPriority);

		return Status::Waiting;
	}

	inline Status Run()
	{
		ION_PROFILER_SCOPE(Job, "Get Task");
		Task task;
		{
			AutoLock<Mutex> lock(mMutex);
			if (!mTasks.IsEmpty())
			{
				task = std::move(mTasks.Front());
				mTasks.PopFront();
			}
			else
			{
				return Status::Empty;
			}
		}
		task.Run();
		return Status::Waiting;
	}

	inline Status RunBlocked(Stats& stats)
	{
		bool shouldSteal = false;
		for (;;)
		{
			for (;;)
			{
				ION_PROFILER_SCOPE(Job, "Get Task Own Queue");
				Task task;
				{
					AutoLock<Mutex> lock(mMutex);
					if (mTasks.IsEmpty())
					{
						if (!shouldSteal)
						{
							break;
						}
						else
						{
							return Status::Empty;
						}
					}
					JOB_SCHEDULER_STATS(runOwn++);
					task = std::move(mTasks.Front());
					mTasks.PopFront();
					if (mTasks.IsEmpty() && stats.joblessQueueIndex == Thread::NoQueueIndex)
					{
						ION_ASSERT(ion::Thread::GetQueueIndex() != Thread::NoQueueIndex, "Invalid worker");
						stats.joblessQueueIndex = ion::Thread::GetQueueIndex();
					}
				}
				task.Run();
			}

			if (!Wait(stats))
			{
				return Status::Inactive;
			}
			shouldSteal = true;
		}
	}

	inline bool Wait(Stats& stats)
	{
		JOB_SCHEDULER_STATS(condWait++);
		stats.slackingWorkers++;
		ION_ASSERT(ion::Thread::GetQueueIndex() != Thread::NoQueueIndex, "Invalid worker");
		stats.joblessQueueIndex = ion::Thread::GetQueueIndex();
		JOB_SCHEDULER_STATS(ion::StopClock idleTimer);
		if (!mSynchronizer.TryWait())
		{
			stats.slackingWorkers--;
			return false;
		}
		JOB_SCHEDULER_STATS(idleTime += idleTimer.GetSeconds());
		stats.slackingWorkers--;
		return true;
	}

	// Returns true if queue is empty, but queue is not locked, thus returned value is not accurate
	inline bool IsMaybeEmpty() const { return mTasks.IsEmpty(); }

	inline Status GetJobTask(BaseJob* job, const bool noSteal = true)
	{
		Task task;
		Status status = noSteal ? FindJobTask(task, job) : WeakFindJobTask(task, job);
		if (status != Status::Empty && (noSteal || status != Status::Locked))
		{
			task.Run();
		}
		return status;
	}

	inline Status Steal()
	{
		Status status;
		ION_PROFILER_SCOPE(Job, "Steal Task");
		Task task;
		{
			AutoDeferLock<Mutex> lock(mMutex);
			if (lock.IsLocked())
			{
				if (mTasks.IsEmpty())
				{
					JOB_SCHEDULER_STATS(stealFailed++);
					return Status::Empty;
				}
				task = std::move(mTasks.Back());
				mTasks.PopBack();
				// Status is 'WentEmpty' when queue is empty, otherwise 'Waiting'
				status = static_cast<Status>(static_cast<int>(Status::Waiting) + static_cast<int>(mTasks.IsEmpty()));
				JOB_SCHEDULER_STATS(stealSuccess++);
			}
			else
			{
				JOB_SCHEDULER_STATS(stealLocked++);
				return Status::Locked;
			}
		}
		task.Run();
		return status;
	}

	template <typename Callback>
	inline void AddTasks(UInt count, Callback&& callback)
	{
		AutoLock<Mutex> lock(mMutex);
		for (size_t i = 0; i < count; ++i)
		{
			mTasks.PushBack(callback());
		}
	}

	inline void PushTask(Task&& task)
	{
		ION_PROFILER_SCOPE(Job, "Add Task");
		AutoLock<Mutex> lock(mMutex);
		mTasks.PushBack(std::move(task));
	}

	inline UInt WakeUp() { return mSynchronizer.Signal(); }

	void Stop() { mSynchronizer.Stop(); }

	void Lock() { mMutex.Lock(); }

	void Unlock() { mMutex.Unlock(); }

private:
	Status FindJobTask(Task& task, const BaseJob* ION_RESTRICT const job)
	{
		AutoLock<Mutex> lock(mMutex);
		return FindJobTaskLocked(task, job);
	}

	Status WeakFindJobTask(Task& task, const BaseJob* ION_RESTRICT const job)
	{
		ION_PROFILER_SCOPE(Job, "Try Search Job Tasks");
		AutoDeferLock<Mutex> lock(mMutex);
		if (lock.IsLocked())
		{
			return FindJobTaskLocked(task, job);
		}
		else
		{
			return Status::Locked;
		}
	}

	Status FindJobTaskLocked(Task& task, const BaseJob* ION_RESTRICT const job)
	{
		ION_PROFILER_SCOPE(Job, "Search Job Tasks");
		auto num = mTasks.Size();
		for (size_t i = 0; i < num; i++)
		{
			size_t pos = i;
			if (mTasks[pos].IsMyJob(job))
			{
				task = mTasks[pos];
				mTasks.Erase(pos);
				// Status is 'Waiting' if 'i' is not last, otherwise 'WentEmpty'
				return static_cast<Status>(static_cast<int>(Status::Waiting) + static_cast<int>(i >= num - 1));
			}
		}
		return Status::Empty;
	}

	ION_ALIGN_CACHE_LINE SCThreadSynchronizer mSynchronizer;
	Mutex mMutex;
	DynamicRingBuffer<Task, 64, ion::CoreAllocator<Task>> mTasks;

	JOB_SCHEDULER_STATS(public:)
	JOB_SCHEDULER_STATS(double idleTime);
	JOB_SCHEDULER_STATS(std::atomic<unsigned int> runOwn = 0);
	JOB_SCHEDULER_STATS(std::atomic<unsigned int> condWait = 0);
	JOB_SCHEDULER_STATS(std::atomic<unsigned int> stealFailed = 0);
	JOB_SCHEDULER_STATS(std::atomic<unsigned int> stealSuccess = 0);
	JOB_SCHEDULER_STATS(std::atomic<unsigned int> stealLocked = 0);
};

}
