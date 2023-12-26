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
#include <ion/container/Algorithm.h>

#include <ion/debug/Profiling.h>

#include <ion/concurrency/Runner.h>

#include <ion/jobs/JobQueue.inl>
#include <ion/jobs/ThreadPool.h>
#include <ion/jobs/TimedJob.h>

#include <ion/core/Core.h>
#include <ion/util/Random.h>

ION_CODE_SECTION(".jobs")
ion::ThreadPool::ThreadPool(UInt hwConcurrency)
  : mNumWorkers(ion::Min(hwConcurrency, MaxQueues - 1) - ION_MAIN_THREAD_IS_A_WORKER),
	mNumWorkerQueues(mNumWorkers + 1 /* 1 queue reserved for main thread */),
	mMaxBackgroundWorkers(mNumWorkers * 2),
	mCompanionWorkersNeeded(0),
	mCompanionWorkersActive(0),
	mAreCompanionsActive(true)
{
	ION_LOG_FMT_IMMEDIATE("hardware concurrency: %u, %d workers, %d queues", hwConcurrency, GetWorkerCount(), GetQueueCount());

	if (hwConcurrency > MaxQueues)
	{
		ION_LOG_IMMEDIATE("HW concurrency more than supported queues");
	}
	ION_ASSERT_FMT_IMMEDIATE(mNumWorkerQueues > 0, "Always have at least one queue");

	mThreads.Reserve(mNumWorkers);
	mCompanionThreads.Reserve(ion::Max((mNumWorkers + 1) * 2, mMaxBackgroundWorkers));

	ion::Thread::QueueIndex workerIndex = 0;

	// Reduce worker counts if spawning fails
	AutoLock<ThreadSynchronizer> lock(mCompanionJobQueue.mSynchronization.mSynchronizer);
	bool isAdding;
	CompanionWorker(ion::Thread::NoQueueIndex);
	do
	{
		isAdding = false;
		if (workerIndex < mNumWorkers)
		{
			ion::Thread::QueueIndex nextQueueIndex = (workerIndex % (mNumWorkerQueues - 1)) + 1;
			if (Worker(nextQueueIndex))
			{
				if (CompanionWorker(ion::Thread::NoQueueIndex))
				{
					workerIndex++;
					isAdding = true;
				}
			}
		}
	} while (isAdding);

	ION_ASSERT(mNumWorkers == workerIndex, "out of memory");
	while (workerIndex < ion::Max((mNumWorkers + 1) * 2, mMaxBackgroundWorkers))
	{
		CompanionWorker(ion::Thread::NoQueueIndex);
		workerIndex++;
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::ThreadPool::~ThreadPool()
{
	JOB_SCHEDULER_STATS(double totalIdleTime = 0; double totalTime = mTimer.GetSeconds(); for (int i = 0; i < mJobQueues.Size(); i++) {
		if (mJobQueues[i].runOwn > 0)
		{
			ION_LOG_FMT_IMMEDIATE(
			  "%i %.2f Own=%d CondWait=%d Steal empty=%d locked=%d success=%d idle=%f s", i,
			  static_cast<float>(mJobQueues[i].runOwn) / static_cast<float>(mJobQueues[i].stealSuccess + mJobQueues[i].runOwn),
			  ion::UInt(mJobQueues[i].runOwn), ion::UInt(mJobQueues[i].condWait), ion::UInt(mJobQueues[i].stealFailed),
			  ion::UInt(mJobQueues[i].stealLocked), ion::UInt(mJobQueues[i].stealSuccess), mJobQueues[i].idleTime);
			totalIdleTime += mJobQueues[i].idleTime;
		}
	} double idleTimePerWorker = totalIdleTime / mNumWorkers;
						ION_LOG_FMT_IMMEDIATE("Total idle time/worker " << idleTimePerWorker << " seconds ("
																		<< (1.0 - idleTimePerWorker / totalTime) * 100 << "%)"););
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::StopThreads()
{
	// Stop main threads
	{
		for (size_t i = 0; i < mNumWorkerQueues; i++)
		{
			ION_PROFILER_SCOPE(Scheduler, "Stopping pool");
			mJobQueues[i].Stop();
		}
	}
	MainThreadQueue().Stop();
	mIoJobPool.mJobQueue.Stop();
	for (ion::Runner& t : mThreads)
	{
		ION_PROFILER_SCOPE(Scheduler, "Stopping thread");
		t.Join();
	}
	mThreads.Clear();

	// Stop companion threads
	{
		AutoLock<ThreadSynchronizer> lock(mCompanionJobQueue.mSynchronization.mSynchronizer);
		mAreCompanionsActive = false;
		lock.NotifyAll();
	}
	std::atomic_thread_fence(std::memory_order_acquire);
	for (CorePtr<ion::Runner>& t : mCompanionThreads)
	{
		ION_PROFILER_SCOPE(Scheduler, "Stopping companion");
		t->Join();
		ion::DeleteCorePtr<ion::Runner>(t);
	}
	mCompanionThreads.Clear();

	// Stop IO Threads
	mIoJobPool.mJobQueue.Stop();
	std::atomic_thread_fence(std::memory_order_acquire);
	for (CorePtr<ion::Runner>& t : mIoJobPool.mThreads)
	{
		ION_PROFILER_SCOPE(Scheduler, "Stopping thread");
		t->Join();
		ion::DeleteCorePtr(t);
	}
	mIoJobPool.mThreads.Clear();
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
bool ion::ThreadPool::Worker(Thread::QueueIndex index)
{
	mThreads.AddKeepCapacity(ion::Runner(
	  [this, index]()
	  {
		  JobQueueStatus status;
		  while ((status = mJobQueues[index].RunBlocked(mStats)) != JobQueueStatus::Inactive)
		  {
			  ION_PROFILER_SCOPE(Job, "Steal tasks");
			  // true when checkHint information is not valid.
			  bool checkHintDirty;
			  do
			  {
				  checkHintDirty = false;
				  // true when corresponding other queue should be checked for stealing tasks.
				  ion::Array<bool, MaxQueues> checkHint;
				  memset(&checkHint[0], true, sizeof(bool) * mNumWorkerQueues);
				  bool otherHasMoreTasksLeft;
				  bool forceLocking = false;
				  do
				  {
					  otherHasMoreTasksLeft = false;
					  ION_ASSERT(index < mNumWorkerQueues, "Invalid index");
					  int32_t target = index;
					  for (UInt i = 1; i < mNumWorkerQueues; i++)
					  {
						  target = ion::IncrWrapped(target, mNumWorkerQueues);
						  if (checkHint[i])
						  {
							  auto steal = mJobQueues[target].Steal(forceLocking);
							  if (steal == JobQueueStatus::Waiting)
							  {
								  otherHasMoreTasksLeft = true;
								  checkHintDirty = true;
							  }
							  else if (steal == JobQueueStatus::Empty)
							  {
								  checkHint[i] = false;
							  }
							  else if (steal == JobQueueStatus::WentEmpty)
							  {
								  checkHintDirty = true;
							  }
							  else	// Queue was locked
							  {
								  // avoid always getting locked out, force locking after being locked once
								  forceLocking = true;
								  ION_ASSERT(steal == JobQueueStatus::Locked, "Invalid status");
							  }
						  }
					  }
				  } while (otherHasMoreTasksLeft);
			  } while (checkHintDirty);
		  }
	  }));
	return mThreads.Back().Start(Thread::DefaultStackSize, WorkerDefaultPriority, index);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::Thread::QueueIndex ion::ThreadPool::DoJobWork(UInt initialTarget, BaseJob* currentJob)
{
	ION_PROFILER_SCOPE(Scheduler, "Find Jobs");
	int32_t target = initialTarget < mNumWorkerQueues ? initialTarget : 0;
	for (UInt i = 0; i < mNumWorkerQueues; i++)
	{
		auto status = mJobQueues[target].GetJobTask(currentJob, true);
		switch (status)
		{
		case JobQueueStatus::Waiting:
			return ion::Thread::QueueIndex(target);
		case JobQueueStatus::WentEmpty:
			return i == mNumWorkerQueues - 1 ? ion::Thread::NoQueueIndex : ion::Thread::QueueIndex((target + 1) % mNumWorkerQueues);
		default:
			break;
		}
		target = ion::IncrWrapped(target, mNumWorkerQueues);
	}
	return ion::Thread::NoQueueIndex;
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::JobQueueStatus ion::ThreadPool::ProcessQueues(UInt index)
{
	if (mNumWorkers == 0)
	{
		// The only queue is mixed main thread and worker queue. Companion does not know which tasks are for main thread only, so it cannot
		// access the queue.
		ION_ASSERT(mNumWorkerQueues == 1, "Invalid queue config");
		return JobQueueStatus::Empty;
	}
	ION_PROFILER_SCOPE(Job, "Companion Task Queues");
	int32_t target = index;
	for (UInt i = 0; i < mNumWorkerQueues; i++)
	{
		auto status = mJobQueues[target].Run();
		if (status != JobQueueStatus::Empty)
		{
			return status;
		}
		target = ion::IncrWrapped(target, mNumWorkerQueues);
	}
	return JobQueueStatus::Empty;
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::Thread::QueueIndex ion::ThreadPool::RandomQueueIndexExceptThis()
{
	auto index = RandomQueueIndex();
	return ion::Thread::GetQueueIndex() != index ? index : (index + 1) % mNumWorkerQueues;
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::Thread::QueueIndex ion::ThreadPool::RandomQueueIndex() const
{
	return ion::Thread::QueueIndex(ion::Random::UInt32Tl() % mNumWorkerQueues);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::PushIOTask(ion::JobWork&& task)
{
	mNumAvailableIOTasks++;
	if (!mIoJobPool.mJobQueue.PushTaskAndWakeUp(std::forward<ion::JobWork&&>(task)))
	{
		if (mIoJobPool.mThreads.Size() < MaxIOThreads)
		{
			mIoJobPool.mJobQueue.Lock();
			if (mIoJobPool.mThreads.Size() < MaxIOThreads)
			{
				LongJobWorker(mIoJobPool);
			}
			mIoJobPool.mJobQueue.Unlock();
		}
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::PushBackgroundTask(ion::JobWork&& task)
{
	AutoLock<ThreadSynchronizer> lock(mCompanionJobQueue.mSynchronization.mSynchronizer);
	mCompanionJobQueue.PushTaskLocked(std::forward<ion::JobWork&&>(task));
	mNumAvailableBackgroundTasks++;
	if (mNumBackgroundWorkers < mMaxBackgroundWorkers)
	{
		lock.NotifyOne();
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::AddCompanionWorker(Thread::QueueIndex queueIndex)
{
	ION_ASSERT(mNumWorkers != 0, "Companions cannot work on main thread queue");
	AutoLock<ThreadSynchronizer> lock(mCompanionJobQueue.mSynchronization.mSynchronizer);
	++mCompanionWorkersNeeded;
	if (mCompanionWorkersNeeded + mMaxBackgroundWorkers  > int(mCompanionThreads.Size()))
	{
		CompanionWorker(queueIndex);
	}
	lock.NotifyOne();
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
bool ion::ThreadPool::LongJobWorker(LongJobPool& pool)
{
	pool.mThreads.Add(ion::MakeCorePtr<ion::Runner>(
	  [this, &pool]()
	  {
		  do
		  {
			  ION_PROFILER_SCOPE(Job, "IO Task Queue");		  
			  while (pool.mJobQueue.LongTaskRun(mNumAvailableIOTasks) != JobQueueStatus::Empty) {};
		  } while (pool.mJobQueue.Wait());
	  }));
	if (pool.mThreads.Back()->Start(Thread::DefaultStackSize, IOJobPriority))
	{
		return true;
	}
	ion::DeleteCorePtr<ion::Runner>(pool.mThreads.Back());
	pool.mThreads.PopBack();
	return false;
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
bool ion::ThreadPool::CompanionWorker(Thread::QueueIndex index)
{
	ION_ASSERT(index == ion::Thread::NoQueueIndex, "TODO: Not supported, remove companion needs to remove same index");
	{
		index = mCompanionThreads.Size() % mNumWorkerQueues;
	}

	mCompanionThreads.Add(ion::MakeCorePtr<ion::Runner>(
	  [this, index]()
	  {
		  mNumBackgroundWorkers++;
		  mCompanionWorkersActive++;
		  while (mAreCompanionsActive)
		  {
			  {
				  ION_PROFILER_SCOPE(Job, "Background Job Queue");
				  JobQueueStatus bgStatus = mCompanionJobQueue.LongTaskRun(mNumAvailableBackgroundTasks);
				  if (bgStatus != JobQueueStatus::Empty)
				  {
					  if (mNumBackgroundWorkers <= mMaxBackgroundWorkers)
					  {
						  continue;
					  }
				  }
			  }
			  --mNumBackgroundWorkers;
			  ion::Thread::SetPriority(WorkerDefaultPriority);
			  JobQueueStatus status = JobQueueStatus::Waiting;
			  while (mAreCompanionsActive)
			  {
				  {
					  AutoLock<ThreadSynchronizer> lock(mCompanionJobQueue.mSynchronization.mSynchronizer);
					  if (mNumAvailableBackgroundTasks > 0 && mNumBackgroundWorkers < mMaxBackgroundWorkers)
					  {
						  break;
					  }
					  if ((status == JobQueueStatus::Empty ||
						   mCompanionWorkersNeeded < static_cast<Int>(mCompanionWorkersActive + mStats.mNumWaiting)) &&
						  mAreCompanionsActive)
					  {
						  --mCompanionWorkersActive;
						  lock.UnlockAndWait();
						  ++mCompanionWorkersActive;
						  if (mCompanionWorkersNeeded < static_cast<Int>(mCompanionWorkersActive + mStats.mNumWaiting))
						  {
					  	      continue;
						  }
					  }
				  }
				  ION_PROFILER_SCOPE(Job, "Companion Job Queue");
				  status = ProcessQueues(index);
			  }
			  ++mNumBackgroundWorkers;
			  ion::Thread::SetPriority(BackgroundJobPriority);
		  };
		  --mNumBackgroundWorkers;
		  --mCompanionWorkersActive;
	  }));
	if (mCompanionThreads.Back()->Start(Thread::DefaultStackSize, BackgroundJobPriority))
	{
		return true;
	}
	ion::DeleteCorePtr<ion::Runner>(mCompanionThreads.Back());
	mCompanionThreads.PopBack();
	return false;
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::AddMainThreadTask(ion::JobWork&& task)
{
	auto& mainThreadQueue = MainThreadQueue();
	mainThreadQueue.PushTaskAndWakeUp(std::move(task));
}
ION_SECTION_END

// #TODO: Main thread is also queue 0 worker. Create separate worker for queue 0. Main thread should send to the worker when it is
// waiting...
ION_CODE_SECTION(".jobs")
void ion::ThreadPool::WorkOnMainThread()
{
	auto& mainThreadQueue = MainThreadQueue();
	if (mainThreadQueue.Run() == JobQueueStatus::Empty)
	{
#if ION_MAIN_THREAD_IS_A_WORKER
		AddCompanionWorker(); // Slacking workers is increased in next Wait() call.  
#endif
		mainThreadQueue.Wait(mStats);
#if ION_MAIN_THREAD_IS_A_WORKER
		RemoveCompanionWorker();
#endif
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::WorkOnMainThreadNoBlock()
{
	JobQueueStatus status = JobQueueStatus::Empty;
	auto& mainThreadQueue = MainThreadQueue();
	do
	{
		status = mainThreadQueue.Run();
		if (status == JobQueueStatus::Empty)
		{
			status = mJobQueues[0].Run();
		}
	} while (status != JobQueueStatus::Empty && status != JobQueueStatus::Inactive);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::WakeUp(Int numLeftToActivate, UInt index)
{
	UInt wakeIndex = index;
	do
	{
		auto woken = mJobQueues[wakeIndex].WakeUp();
		if (woken)
		{
			ION_ASSERT(woken == 1, "Unexpected");
			numLeftToActivate -= 1;
			if (numLeftToActivate <= 0)
			{
				Update(index);
				return;
			}
		}
		if (mStats.mNumWaiting == 0)
		{
			break;
		}
		wakeIndex = (wakeIndex + 1) % mNumWorkerQueues;
	} while (wakeIndex != index);
	ION_ASSERT_FMT_IMMEDIATE(numLeftToActivate > 0, "Invalid state");

	if (mCompanionWorkersNeeded > 0)
	{
		AutoLock<ThreadSynchronizer> lock(mCompanionJobQueue.mSynchronization.mSynchronizer);
		if (mCompanionWorkersNeeded - mCompanionWorkersActive > 0)
		{
			lock.Notify(numLeftToActivate);
		}
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::Thread::QueueIndex ion::ThreadPool::DoJobWork(UInt initialTarget)
{
	for (UInt i = 0; i < mNumWorkerQueues; i++)
	{
		UInt target = (i + initialTarget) % mNumWorkerQueues;
		auto status = mJobQueues[target].Run();
		switch (status)
		{
		case JobQueueStatus::Waiting:
			return Thread::QueueIndex(target);
		case JobQueueStatus::Empty:
			return Thread::QueueIndex(target + 1);
		default:
			break;
		}
	}
	return ion::Thread::NoQueueIndex;
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::PushDelayedTask(ion::JobWork&& task)
{
	if (GetWorkerCount() > 0)
	{
		PushTask(std::move(task));
	}
	else
	{
		ion::job_queue::DoWork(task);
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::PushDelayedTasks(Vector<ion::JobWork, ion::CoreAllocator<ion::JobWork>>& tasks)
{
	if (GetWorkerCount() > 0)
	{
		std::for_each(tasks.Begin(), tasks.End(), [&](ion::JobWork& task) { PushTask(std::move(task)); });
	}
	else
	{
		std::for_each(tasks.Begin(), tasks.End(), [&](ion::JobWork& task) { ion::job_queue::DoWork(task); });
	}
}
ION_SECTION_END
