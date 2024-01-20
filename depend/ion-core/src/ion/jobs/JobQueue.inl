#pragma once

#include <ion/jobs/BaseJob.h>
#include <ion/jobs/JobQueue.h>

#include <ion/hw/CPU.inl>

namespace ion
{
namespace job_queue
{
inline void DoWork(JobWork& work)
{
	ion::platform::PreFetchL2(work.mJob);
	auto oldJob = ion::Thread::GetCurrentJob();
	ion::Thread::SetCurrentJob(work.mJob);
	work.mJob->DoWork();  // After this call mJob is not valid anymore
	ion::Thread::SetCurrentJob(oldJob);
}

inline bool IsMyJob(const JobWork& work, const BaseJob* const ION_RESTRICT job)
{
	if (job == work.mJob)
	{
		return true;
	}
	else if (work.mJob != nullptr)
	{
		if (job->GetRecursion() < work.mJob->GetRecursion())
		{
			return work.mJob->IsMyJob(job);
		}
	}
	return false;
}

}  // namespace job_queue

template <typename Synchronization>
ION_FORCE_INLINE JobQueueStatus JobQueue<Synchronization>::LongTaskRun(std::atomic<UInt>& numAvailableTasks)
{
	ION_PROFILER_SCOPE(Job, "Get LongTask");
	ION_ASSERT(Thread::GetQueueIndex() == ion::Thread::NoQueueIndex, "Invalid long task worker");
	JobWork work;
	{
		mSynchronization.Lock();
		if (!mTasks.IsEmpty())
		{
			work = std::move(mTasks.Front());
			mTasks.PopFront();
			numAvailableTasks--;
			mSynchronization.Unlock();
		}
		else
		{
			mSynchronization.Unlock();
			return JobQueueStatus::Empty;
		}
	}	
	job_queue::DoWork(work);
	return JobQueueStatus::Waiting;
}

template <typename Synchronization>
ION_FORCE_INLINE JobQueueStatus JobQueue<Synchronization>::Run()
{
	ION_PROFILER_SCOPE(Job, "Get Task");
	JobWork work;
	{
		mSynchronization.Lock();
		if (!mTasks.IsEmpty())
		{
			work = std::move(mTasks.Front());
			mTasks.PopFront();
			mSynchronization.Unlock();
		}
		else
		{
			mSynchronization.Unlock();
			return JobQueueStatus::Empty;
		}
	}
	job_queue::DoWork(work);
	return JobQueueStatus::Waiting;
}

template <typename Synchronization>
ION_FORCE_INLINE JobQueueStatus JobQueue<Synchronization>::RunBlocked(JobQueueStats& stats)
{
	bool shouldSteal = false;
	for (;;)
	{
		for (;;)
		{
			ION_PROFILER_SCOPE(Job, "Get Task Own Queue");
			JobWork work;
			{
				mSynchronization.Lock();
				if (mTasks.IsEmpty())
				{
					if (!shouldSteal)
					{
						mSynchronization.Unlock();
						break;
					}
					else
					{
						mSynchronization.Unlock();
						return JobQueueStatus::Empty;
					}
				}
				JOB_SCHEDULER_STATS(runOwn++);
				work = std::move(mTasks.Front());
				mTasks.PopFront();
				if (mTasks.IsEmpty() && stats.mJoblessQueueIndex == Thread::NoQueueIndex)
				{
					ION_ASSERT(ion::Thread::GetQueueIndex() != Thread::NoQueueIndex, "Invalid worker");
					stats.mJoblessQueueIndex = ion::Thread::GetQueueIndex();
				}
				mSynchronization.Unlock();
			}
			job_queue::DoWork(work);
		}

		if (!Wait(stats))
		{
			return JobQueueStatus::Inactive;
		}
		shouldSteal = true;
	}
}

template <typename Synchronization>
ION_FORCE_INLINE JobQueueStatus JobQueue<Synchronization>::GetJobTask(BaseJob* job, const bool noSteal)
{
	JobWork work;
	JobQueueStatus status = noSteal ? FindJobTask(work, job) : WeakFindJobTask(work, job);
	if (status != JobQueueStatus::Empty && (noSteal || status != JobQueueStatus::Locked))
	{
		job_queue::DoWork(work);
	}
	return status;
}

template <typename Synchronization>
ION_FORCE_INLINE JobQueueStatus JobQueue<Synchronization>::Steal(bool force)
{
	JobQueueStatus status;
	ION_PROFILER_SCOPE(Job, "Steal Task");
	JobWork work;
	{
		if (force)
		{
			mSynchronization.Lock();
		}
		else if (!mSynchronization.TryLock())
		{
			JOB_SCHEDULER_STATS(stealLocked++);
			return JobQueueStatus::Locked;
		}
		if (mTasks.IsEmpty())
		{
			JOB_SCHEDULER_STATS(stealFailed++);
			mSynchronization.Unlock();
			return JobQueueStatus::Empty;
		}
		work = std::move(mTasks.Back());
		mTasks.PopBack();
		// Status is 'WentEmpty' when queue is empty, otherwise 'Waiting'
		status = static_cast<JobQueueStatus>(static_cast<int>(JobQueueStatus::Waiting) + static_cast<int>(mTasks.IsEmpty()));
		JOB_SCHEDULER_STATS(stealSuccess++);
		mSynchronization.Unlock();
	}

	job_queue::DoWork(work);
	return status;
}

template <typename Synchronization>
ION_FORCE_INLINE JobQueueStatus JobQueue<Synchronization>::FindJobTaskLocked(JobWork& task, const BaseJob* const ION_RESTRICT job)
{
	ION_PROFILER_SCOPE(Job, "Search Job Tasks");
	auto num = mTasks.Size();
	for (size_t i = 0; i < num; i++)
	{
		size_t pos = i;
		if (job_queue::IsMyJob(mTasks[pos], job))
		{
			task = mTasks[pos];
			mTasks.Erase(pos);
			// Status is 'Waiting' if 'i' is not last, otherwise 'WentEmpty'
			return static_cast<JobQueueStatus>(static_cast<int>(JobQueueStatus::Waiting) + static_cast<int>(i >= num - 1));
		}
	}
	return JobQueueStatus::Empty;
}

}  // namespace ion
