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

#include <ion/container/RingBuffer.h>

#include <ion/debug/Profiling.h>

#include <ion/concurrency/SCThreadSynchronizer.h>
#include <ion/concurrency/Thread.h>

#include <ion/jobs/JobWork.h>

#include <ion/core/Core.h>
#include <ion/hw/CPU.inl>

#define JOB_SCHEDULER_STATS(x)	// x

namespace ion
{
constexpr ion::Thread::Priority DispatcherPriority = ion::Thread::Priority::Highest;
constexpr ion::Thread::Priority MainThreadPriority = ion::Thread::Priority::Normal;
constexpr ion::Thread::Priority WorkerDefaultPriority = ion::Thread::Priority::AboveNormal;
constexpr ion::Thread::Priority IOJobPriority = ion::Thread::Priority::Highest;
// Note: Companion/Background threads must have lower priority than main/main worker threads -
// otherwise calling main/worker threads will hang when notifying companions
// if system is out of hw threads
constexpr ion::Thread::Priority BackgroundJobPriority = ion::Thread::Priority::BelowNormal;

struct JobQueueStats
{
	JobQueueStats() : mNumWaiting(0), mJoblessQueueIndex(Thread::NoQueueIndex) {}
	std::atomic<Int> mNumWaiting;
	std::atomic<Thread::QueueIndex> mJoblessQueueIndex;
};

using JobQueueTaskList = DynamicRingBuffer<JobWork, 63, ion::CoreAllocator<JobWork>>;

enum class JobQueueStatus : u8
{
	Inactive,  // Queue deactivated
	Empty,	   // Queue is currently empty
	Locked,	   // Queue is locked by other worker
	Waiting,   // Queue might not be empty, waiting for workers
	WentEmpty  // Queue emptied by current worker
};

struct JobQueueSynchronizationSingleOwner
{
	ION_ACCESS_GUARD(mGuard);
	SCThreadSynchronizer mSynchronizer;
	Mutex mMutex;

	ION_FORCE_INLINE bool Wait(JobQueueTaskList& /* taskList */) 
	{ 
		return mSynchronizer.TryWait();
	}

	ION_FORCE_INLINE bool Wait(JobQueueTaskList& /* taskList */, JobQueueStats& stats)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		JOB_SCHEDULER_STATS(condWait++);
		stats.mNumWaiting++;
		ION_ASSERT(ion::Thread::GetQueueIndex() != Thread::NoQueueIndex, "Invalid worker");
		stats.mJoblessQueueIndex = ion::Thread::GetQueueIndex();
		JOB_SCHEDULER_STATS(ion::StopClock idleTimer);
		if (!mSynchronizer.TryWait())
		{
			stats.mNumWaiting--;
			return false;
		}
		JOB_SCHEDULER_STATS(idleTime += idleTimer.GetSeconds());
		stats.mNumWaiting--;
		return true;
	}

	ION_FORCE_INLINE bool TryLock() const { return mMutex.TryLock(); }
	ION_FORCE_INLINE void Lock() { mMutex.Lock(); }
	ION_FORCE_INLINE void Unlock() { mMutex.Unlock(); }
	ION_FORCE_INLINE UInt WakeUp() { return mSynchronizer.Signal(); }
	ION_FORCE_INLINE void WakeUpAll() { mSynchronizer.Signal(); }
	ION_FORCE_INLINE void Stop() { mSynchronizer.Stop(); }

	ION_FORCE_INLINE UInt PushTaskAndWakeUp(JobQueueTaskList& taskList, JobWork&& task)
	{
		ION_PROFILER_SCOPE(Job, "Add Task");
		{
			AutoLock<Mutex> lock(mMutex);
			taskList.PushBack(std::move(task));
		}
		return mSynchronizer.Signal();
	}
};

struct JobQueueSynchronization
{
	ThreadSynchronizer mSynchronizer;
	std::atomic<bool> mIsRunning = true;

	ION_FORCE_INLINE bool Wait(JobQueueTaskList& taskList)
	{
		AutoLock<ThreadSynchronizer> lock(mSynchronizer);
		if (!taskList.IsEmpty())
		{
			return true;
		}
		if (!mIsRunning)
		{
			return false;
		}
		lock.UnlockAndWait();
		return true;
	}

	ION_FORCE_INLINE bool Wait(JobQueueTaskList& taskList, JobQueueStats& stats)
	{
		AutoLock<ThreadSynchronizer> lock(mSynchronizer);
		if (!taskList.IsEmpty())
		{
			return true;
		}
		if (!mIsRunning)
		{
			return false;
		}
		stats.mNumWaiting++;
		stats.mJoblessQueueIndex = ion::Thread::GetQueueIndex();
		lock.UnlockAndWait();
		stats.mNumWaiting--;
		return true;
	}

	ION_FORCE_INLINE bool TryLock() { return mSynchronizer.TryLock(); }
	ION_FORCE_INLINE void Lock() { mSynchronizer.Lock(); }
	ION_FORCE_INLINE void Unlock() { mSynchronizer.Unlock(); }

	ION_FORCE_INLINE UInt WakeUp()
	{
		AutoLock<ThreadSynchronizer> lock(mSynchronizer);
		return lock.NotifyOne();
	}

	ION_FORCE_INLINE void WakeUpAll()
	{
		AutoLock<ThreadSynchronizer> lock(mSynchronizer);
		lock.NotifyAll();
	}

	ION_FORCE_INLINE void Stop()
	{
		AutoLock<ThreadSynchronizer> lock(mSynchronizer);
		mIsRunning = false;
		lock.NotifyAll();
	}

	ION_FORCE_INLINE UInt PushTaskAndWakeUp(JobQueueTaskList& taskList, JobWork&& task)
	{
		ION_PROFILER_SCOPE(Job, "Add Task");
		AutoLock<ThreadSynchronizer> lock(mSynchronizer);
		taskList.PushBack(std::move(task));
		return lock.NotifyOne();
	}
};

template<typename Synchronization>
class JobQueue
{
public:

	static_assert(static_cast<size_t>(JobQueueStatus::Empty) == 1 && static_cast<size_t>(JobQueueStatus::Inactive) == 0,
				  "Check enum usage");

	static_assert(static_cast<size_t>(JobQueueStatus::WentEmpty) == 4 && static_cast<size_t>(JobQueueStatus::Waiting) == 3,
				  "Check enum usage");

	JobQueue() { JOB_SCHEDULER_STATS(idleTime = 0); }

	JobQueue(const JobQueue&) {}

	~JobQueue() {}

	JobQueueStatus LongTaskRun(std::atomic<UInt>& numAvailableTasks);

	ION_FORCE_INLINE JobQueueStatus Run();

	ION_FORCE_INLINE JobQueueStatus RunBlocked(JobQueueStats& stats);

	inline bool Wait() { return mSynchronization.Wait(mTasks); }

	inline bool Wait(JobQueueStats& stats) { return mSynchronization.Wait(mTasks, stats); }

	// Returns true if queue is empty, but queue is not locked, thus returned value is not accurate
	ION_FORCE_INLINE bool IsMaybeEmpty() const { return mTasks.IsEmpty(); }

	ION_FORCE_INLINE JobQueueStatus GetJobTask(BaseJob* job, const bool noSteal = true);

	ION_FORCE_INLINE JobQueueStatus Steal(bool force);

	template <typename Callback>
	inline void AddTasks(UInt count, Callback&& callback)
	{
		mSynchronization.Lock();
		for (size_t i = 0; i < count; ++i)
		{
			mTasks.PushBack(callback());
		}
		mSynchronization.Unlock();
	}

	inline void PushTask(JobWork&& task)
	{
		ION_PROFILER_SCOPE(Job, "Add Task");
		mSynchronization.Lock();
		mTasks.PushBack(std::move(task));
		mSynchronization.Unlock();
	}

	inline void PushTaskLocked(JobWork&& task)
	{
		ION_PROFILER_SCOPE(Job, "Add Task");
		mTasks.PushBack(std::move(task));
	}

	inline bool PushTaskAndWakeUp(JobWork&& task)
	{
		ION_PROFILER_SCOPE(Job, "Add Task and Wake Up");
		return mSynchronization.PushTaskAndWakeUp(mTasks, std::forward<JobWork&&>(task)) != 0;
	}

	inline UInt WakeUp() { return mSynchronization.WakeUp(); }

	inline void WakeUpAll() { mSynchronization.WakeUpAll(); }

	inline void Stop() { mSynchronization.Stop(); }

	inline void Lock() { mSynchronization.Lock(); }

	inline void Unlock() { mSynchronization.Unlock(); }

private:
	JobQueueStatus FindJobTask(JobWork& task, const BaseJob* const ION_RESTRICT job)
	{
		mSynchronization.Lock();
		JobQueueStatus result = FindJobTaskLocked(task, job);
		mSynchronization.Unlock();
		return result;
	}

	JobQueueStatus WeakFindJobTask(JobWork& task, const BaseJob* const ION_RESTRICT job)
	{
		ION_PROFILER_SCOPE(Job, "Try Search Job Tasks");
		JobQueueStatus result = JobQueueStatus::Locked;
		if (mSynchronization.TryLock())
		{
			result = FindJobTaskLocked(task, job);
			mSynchronization.Unlock();
		}
		return result;
	}

	JobQueueStatus FindJobTaskLocked(JobWork& task, const BaseJob* const ION_RESTRICT job);

public:
	ION_ALIGN_CACHE_LINE Synchronization mSynchronization;
	JobQueueTaskList mTasks;

	JOB_SCHEDULER_STATS(public:)
	JOB_SCHEDULER_STATS(double idleTime);
	JOB_SCHEDULER_STATS(std::atomic<unsigned int> runOwn = 0);
	JOB_SCHEDULER_STATS(std::atomic<unsigned int> condWait = 0);
	JOB_SCHEDULER_STATS(std::atomic<unsigned int> stealFailed = 0);
	JOB_SCHEDULER_STATS(std::atomic<unsigned int> stealSuccess = 0);
	JOB_SCHEDULER_STATS(std::atomic<unsigned int> stealLocked = 0);
};

// Only one thread can wait in JobQueueSingleOwner
using JobQueueSingleOwner = JobQueue<JobQueueSynchronizationSingleOwner>;
using JobQueueMultiOwner = JobQueue<JobQueueSynchronization>;
}  // namespace ion
