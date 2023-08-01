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
#include <ion/jobs/Job.h>

ION_CODE_SECTION(".jobs")
void ion::Job::Execute()
{
	ExecuteInternal(
	  [&]()
	  {
		  // NOTE: Cannnot Execute locally, always adding tasks.
		  if (GetThreadPool().GetWorkerCount() > 0)
		  {
			  GetThreadPool().PushTask(Task(this));
		  }
		  else
		  {
			  ExecuteOnQueue(Thread::QueueIndex(0));
		  }
	  });
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::Job::Execute(Thread::QueueIndex queue)
{
	ExecuteInternal([&]() { ExecuteOnQueue(queue); });
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::Job::ExecuteLong()
{
	ExecuteInternal(
	  [&]()
	  {
		  ION_PROFILER_SCOPE(Job, "Add long task");
		  GetThreadPool().PushLongTask(Task(this));
	  });
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::Job::ExecuteOnQueue(Thread::QueueIndex queue)
{
	GetThreadPool().AddTaskWithoutWakeUp(Task(this), queue);
	if (queue != ion::Thread::GetQueueIndex())
	{
		GetThreadPool().WakeUp(1, queue);
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::Job::RunTask()
{
	for (;;)
	{
		ION_PROFILER_SCOPE(Scheduler, "Job");
		{
			ION_ACCESS_GUARD_WRITE_BLOCK(mTaskGuard);
			OnTaskStarted();
			mFunction();
		}
		AutoLock<ThreadSynchronizer> lock(GetSynchronizer());
		ION_ASSERT(NumTasksInProgress() > 0, "Invalid task count");
		if (--NumTasksInProgress() == 0)
		{
			lock.NotifyAll();
			break;
		}
		else
		{
			ION_ASSERT(NumTasksInProgress() == 1, "Invalid number of tasks left");
			ION_ASSERT(NumTasksAvailable() <= 2, "Invalid number of available tasks");
			// GetThreadPool().PushTask(Task(this));
		}
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::RepeatableIOJob::RunTask()
{
	for (;;)
	{
		ION_ASSERT_FMT_IMMEDIATE(!mIsStarving, "RepeatableIOJob triggered when it was not starving");
		mIsStarving.store(true, std::memory_order_release);
		RunIOJob();
		AutoLock<Mutex> lock(mMutex);
		if (mIsStarving.load(std::memory_order_acquire))
		{
			mIsDone = true;
			break;
		}
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::RepeatableIOJob::Execute(ion::ThreadPool& tp)
{
	if (mIsStarving.load(std::memory_order_acquire))
	{
		AutoLock<Mutex> lock(mMutex);
		mIsStarving.store(false, std::memory_order_release);
		if (mIsDone)
		{
			mIsDone = false;
			tp.PushLongTask(ion::Task(this));
		}
	}
}
ION_SECTION_END
