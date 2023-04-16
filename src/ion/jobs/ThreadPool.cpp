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
#include <ion/jobs/ThreadPool.h>
#include <ion/util/Random.h>
#include <ion/debug/Profiling.h>
#include <ion/container/Algorithm.h>
#include <ion/hw/CPU.inl>
#include <ion/jobs/TimedJob.h>
#include <ion/concurrency/Runner.h>

ION_CODE_SECTION(".jobs")
ion::ThreadPool::ThreadPool(UInt hwConcurrency)
  : mNumWorkers(ion::Min(hwConcurrency
#if ION_MAIN_THREAD_IS_A_WORKER
						   - 1
#endif
						 ,
						 MaxThreads - 1)),
	mNumWorkerQueues(ion::Min(mNumWorkers + 1 /* 1 queue reserved for main thread */, MaxQueues - 1 /*For main thread*/)),
	mCompanionWorkersNeeded(0),
	mCompanionWorkersActive(0),
	mNumAvailableLongTasks(0),
	mAreCompanionsActive(true)
{
	ION_LOG_INFO_FMT("hardware concurrency: %u, %d workers, %d queues", hwConcurrency, GetWorkerCount(), GetQueueCount());

	if (hwConcurrency > MaxQueues)
	{
		ION_LOG_INFO("HW concurrency more than supported queues");
	}
	ION_ASSERT(mNumWorkerQueues > 0, "Always have at least one queue");

	mThreads.Reserve(mNumWorkers);
	mCompanionThreads.Reserve(2u * mNumWorkerQueues);

	ion::Thread::QueueIndex workerIndex = 0;
	ion::Thread::QueueIndex companionIndex = 0;

	// Reduce worker counts if spawning fails
	AutoLock<ThreadSynchronizer> lock(mCompanionSynchronizer);
	bool isAdding;
	do
	{
		isAdding = false;
		if (companionIndex < mNumWorkerQueues)
		{
			if (CompanionWorker())
			{
				companionIndex++;
				isAdding = true;
			}
		}
		if (workerIndex < mNumWorkers)
		{
			if (Worker((workerIndex % (mNumWorkerQueues - 1)) + 1))
			{
				workerIndex++;
				isAdding = true;
			}
		}
	} while (isAdding);

	ION_ASSERT(mNumWorkers == workerIndex, "TODO");
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::ThreadPool::~ThreadPool()
{
	JOB_SCHEDULER_STATS(double totalIdleTime = 0; double totalTime = mTimer.GetSeconds(); for (int i = 0; i < mTaskQueues.Size(); i++) {
		if (mTaskQueues[i].runOwn > 0)
		{
			ION_LOG_INFO_FMT("%i %.2f Own=%d CondWait=%d Steal empty=%d locked=%d success=%d idle=%f s", i,
					   static_cast<float>(mTaskQueues[i].runOwn) / static_cast<float>(mTaskQueues[i].stealSuccess + mTaskQueues[i].runOwn),
					   ion::UInt(mTaskQueues[i].runOwn), ion::UInt(mTaskQueues[i].condWait), ion::UInt(mTaskQueues[i].stealFailed),
					   ion::UInt(mTaskQueues[i].stealLocked), ion::UInt(mTaskQueues[i].stealSuccess), mTaskQueues[i].idleTime);
			totalIdleTime += mTaskQueues[i].idleTime;
		}
	} double idleTimePerWorker = totalIdleTime / mNumWorkers;
						ION_LOG_INFO("Total idle time/worker " << idleTimePerWorker << " seconds (" << (1.0 - idleTimePerWorker / totalTime) * 100
													  << "%)"););
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
			mTaskQueues[i].Stop();
		}
	}
	MainThreadQueue().Stop();
	std::atomic_thread_fence(std::memory_order_acquire);
	for (ion::Runner& t : mThreads)
	{
		ION_PROFILER_SCOPE(Scheduler, "Stopping thread");
		t.Join();
	}
	mThreads.Clear();

	// Stop companion threads
	{
		AutoLock<ThreadSynchronizer> lock(mCompanionSynchronizer);
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
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
bool ion::ThreadPool::Worker(Thread::QueueIndex index)
{
	mThreads.AddKeepCapacity(ion::Runner(
	  [this, index]()
	  {
		  TaskQueue::Status status;
		  while ((status = mTaskQueues[index].RunBlocked(mStats)) != TaskQueue::Status::Inactive)
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
							  auto steal = mTaskQueues[target].Steal();
							  if (steal == TaskQueue::Status::Waiting)
							  {
								  otherHasMoreTasksLeft = true;
								  checkHintDirty = true;
							  }
							  else if (steal == TaskQueue::Status::Empty)
							  {
								  checkHint[i] = false;
							  }
							  else if (steal == TaskQueue::Status::WentEmpty)
							  {
								  checkHintDirty = true;
							  }
							  else
							  {
								  ION_ASSERT(steal == TaskQueue::Status::Locked, "Invalid status");
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
		auto status = mTaskQueues[target].GetJobTask(currentJob, true);
		switch (status)
		{
		case TaskQueue::Status::Waiting:
			return ion::Thread::QueueIndex(target);
		case TaskQueue::Status::WentEmpty:
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
ion::TaskQueue::Status ion::ThreadPool::ProcessQueues(UInt index)
{
	if (mNumWorkers == 0)
	{
		// The only queue is mixed main thread and worker queue. Companion does not know which tasks are for main thread only, so it cannot
		// access the queue.
		ION_ASSERT(mNumWorkerQueues == 1, "Invalid queue config");
		return TaskQueue::Status::Empty;
	}
	ION_PROFILER_SCOPE(Job, "Companion Task Queues");
	int32_t target = index;
	for (UInt i = 0; i < mNumWorkerQueues; i++)
	{
		auto status = mTaskQueues[target].Run();
		if (status != TaskQueue::Status::Empty)
		{
			return status;
		}
		target = ion::IncrWrapped(target, mNumWorkerQueues);
	}
	return TaskQueue::Status::Empty;
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
void ion::ThreadPool::PushLongTask(ion::Task&& task)
{
	{  // #TODO: merge companion synchronizer and synchronizer of io task queue
		AutoLock<ThreadSynchronizer> lock(mCompanionSynchronizer);
		mNumAvailableLongTasks++;
		mCompanionWorkersNeeded++;
		mLongTaskQueue.PushTask(std::move(task));
		{
			if (mCompanionWorkersNeeded > int(mCompanionThreads.Size()) && mCompanionThreads.Size() < (mNumWorkerQueues * 2))
			{
				CompanionWorker();
			}
			lock.NotifyOne();
		}
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::AddCompanionWorker()
{
	ION_ASSERT(mNumWorkers != 0, "Companions cannot work on main thread queue");
	// #TODO: Use companion worker per queue. Will work until companion worker is not needed.
	// Does not wait in waitable job.
	Int need = ++mCompanionWorkersNeeded;
	if (need > 0 && need > static_cast<Int>(mStats.slackingWorkers + mCompanionWorkersActive))
	{
		AutoLock<ThreadSynchronizer> lock(mCompanionSynchronizer);
		if (mCompanionWorkersNeeded > int(mCompanionThreads.Size()))
		{
			CompanionWorker();
		}
		lock.NotifyOne();
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
bool ion::ThreadPool::CompanionWorker()
{
	const Thread::QueueIndex index = mCompanionThreads.Size() % mNumWorkerQueues;
	mCompanionThreads.Add(ion::MakeCorePtr<ion::Runner>(
	  [this, index]()
	  {
		  mCompanionWorkersActive++;
		  TaskQueue::Status status = TaskQueue::Status::Empty;
		  do
		  {
			  {
				  ION_PROFILER_SCOPE(Job, "LongTask Queue");
				  status = mLongTaskQueue.LongTaskRun(/*mStats*/ mCompanionWorkersNeeded, mNumAvailableLongTasks);
			  }
			  do
			  {
				  AutoLock<ThreadSynchronizer> lock(mCompanionSynchronizer);
				  if (mNumAvailableLongTasks > 0)
				  {
					  break;
				  }

				  if ((status == TaskQueue::Status::Empty ||
					   mCompanionWorkersNeeded < static_cast<Int>(mCompanionWorkersActive + mStats.slackingWorkers)) &&
					  mAreCompanionsActive)
				  {
					  mCompanionWorkersActive--;
					  lock.UnlockAndWait();
					  mCompanionWorkersActive++;
					  if (mNumAvailableLongTasks > 0)
					  {
						  break;
					  }
				  }
			  } while ((status = ProcessQueues(index)) != TaskQueue::Status::Empty /*&& mAreCompanionsActive*/);
		  } while (mAreCompanionsActive || mNumAvailableLongTasks > 0);
		  mCompanionWorkersActive--;
	  }));
	if (mCompanionThreads.Back()->Start(Thread::DefaultStackSize, LongJobPriority))
	{
		return true;
	}
	ion::DeleteCorePtr<ion::Runner>(mCompanionThreads.Back());
	mCompanionThreads.PopBack();
	return false;
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::AddMainThreadTask(ion::Task&& task)
{
	auto& mainThreadQueue = MainThreadQueue();
	mainThreadQueue.PushTask(std::move(task));
	mainThreadQueue.WakeUp();
}
ION_SECTION_END

// #TODO: Main thread is also queue 0 worker. Create separate worker for queue 0. Main thread should send to the worker when it is waiting...
ION_CODE_SECTION(".jobs")
void ion::ThreadPool::WorkOnMainThread()
{
	auto& mainThreadQueue = MainThreadQueue();
	if (mainThreadQueue.Run() == TaskQueue::Status::Empty)
	{
		mainThreadQueue.Wait(mStats);
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ThreadPool::WorkOnMainThreadNoBlock()
{
	TaskQueue::Status status = TaskQueue::Status::Empty;
	auto& mainThreadQueue = MainThreadQueue();
	do
	{
		status = mainThreadQueue.Run();
		if (status == TaskQueue::Status::Empty)
		{
			status = mTaskQueues[0].Run();
		}
	} while (status != TaskQueue::Status::Empty && status != TaskQueue::Status::Inactive);
}
ION_SECTION_END
