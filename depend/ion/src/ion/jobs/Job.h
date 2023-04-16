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

#include <ion/jobs/WaitableJob.h>
#include <ion/debug/Profiling.h>
#include <ion/jobs/Task.h>
#include <ion/jobs/ThreadPool.h>
#include <ion/debug/AccessGuard.h>
#include <ion/memory/Memory.h>
#include <ion/util/InplaceFunction.h>

namespace ion
{
namespace task
{
template <typename T>
using Function = ion::InplaceFunction<T,

// If inplace function size is too small,
// move some of the lambda data inside a struct or use ParallelForIndex
#if ION_BUILD_DEBUG
									  sizeof(void*) * 12,
#else
									  sizeof(void*) * 8,
#endif
									  16>;

}  // namespace task

template <typename TData>
struct CriticalDataBasePadding
{
	TData data;
	// Avoid false-sharing, usually only needed when DefaultSize > 1
	char padding[ION_CONFIG_SAFE_CACHE_LINE_SIZE - (sizeof(TData) % ION_CONFIG_SAFE_CACHE_LINE_SIZE)];
};

template <typename TData>
struct CriticalDataBase
{
	TData data;
};

template <typename TData>
class CriticalData
  : public std::conditional<sizeof(TData) % ION_CONFIG_SAFE_CACHE_LINE_SIZE == 0, CriticalDataBase<TData>, CriticalDataBasePadding<TData>>::type
{
};

class Job : public WaitableJob
{
public:
	ION_ALIGN_CLASS(Job);

	Job(ThreadPool& tp, task::Function<void()>&& function, BaseJob* sourceJob = nullptr)
	  : WaitableJob(tp, sourceJob, 0), mFunction(std::move(function))
	{
	}

	~Job()
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mTaskGuard);
		ION_ASSERT(NumTasksInProgress() == 0, "Tasks in progress");
		ION_ASSERT(NumTasksAvailable() == 0, "Tasks available");
	}

	void Execute();

	void ExecuteLong();

	void Execute(Thread::QueueIndex queue);

	virtual void RunTask() final override;

private:
	void ExecuteOnQueue(Thread::QueueIndex queue);

	template <typename AddTaskCallback>
	inline void ExecuteInternal(AddTaskCallback&& addTask)
	{
		if (NumTasksInProgress() <= 1)
		{
			ION_PROFILER_SCOPE(Job, "Execute Job");
			AutoLock<ThreadSynchronizer> lock(GetSynchronizer());
			if (NumTasksInProgress() <= 1)
			{
				NumTasksAvailable()++;
				if (++NumTasksInProgress() == 1)
				{
					ION_ASSERT(NumTasksAvailable() == 1, "Invalid number of available tasks");
					addTask();
				}
			}
		}
	}

	ION_ALIGN_CACHE_LINE task::Function<void()> mFunction;
	ION_ACCESS_GUARD(mTaskGuard);
};

// #TODO: Currently no need for separate long task job.
class IOJob : public BaseJob
{
public:
	IOJob(ion::MemTag tag) : BaseJob(tag), mIsDone(false) {}

	bool IsDone() const { return mIsDone; }

	virtual void RunIOJob() = 0;

	void Wait()
	{
		if (!mIsDone)
		{
			ION_LOG_INFO("Waiting for IOJob to finish");
			while (!mIsDone)
			{
				ion::Thread::Sleep(100);
			}
		}
	}

	~IOJob()
	{
		// Owner should make sure IOJobs are done before
		// entering their destructors.
		ION_ASSERT(mIsDone, "IOJob not finished - Call Wait() first");
	}

private:
	virtual void RunTask() final override
	{
		ION_ASSERT(!mIsDone, "Cannot rerun IOJob. Please use RepeatedIOJob");
		RunIOJob();
		mIsDone = true;
	}
	std::atomic<bool> mIsDone;
};

// Repeatable job that is run as a long task. Repeated runs are always sequential.
// #TODO: This optimization of "Job" for single task. Probaly should be combined/renamed?
class RepeatableIOJob : public BaseJob
{
public:
	RepeatableIOJob(ion::MemTag tag) : BaseJob(tag), mIsStarving(true), mIsDone(true) {}

	bool IsDone() const { return mIsDone; }

	virtual void RunIOJob() = 0;

	void Wait()
	{
		if (!mIsDone)
		{
			ION_LOG_INFO("Waiting for RepeatableIOJob to finish");
			while (!mIsDone)
			{
				ion::Thread::Sleep(100);
			}
		}
	}

	void Execute(ion::ThreadPool& tp);

	~RepeatableIOJob()
	{
		// Owner should make sure RepeatabledIOJobs are done before
		// entering their destructors.
		ION_ASSERT(mIsDone, "RepeatableIOJob not finished - Call Wait() first");
	}

private:
	virtual void RunTask() final override;
	ion::Mutex mMutex;
	std::atomic<bool> mIsStarving;	// False only when there is undone work
	std::atomic<bool> mIsDone;		// True only when there is active job.
};

struct EmptyIntermediate
{
};

template <typename Parameter, class Function, class Intermediate>
inline void JobCall(Function&& function, Parameter& param, Intermediate* intermediate)
{
	ION_PROFILER_SCOPE(Job, "Task (Intermediate)");
	function(param, intermediate->GetMain());
}

template <typename Parameter, class Function>
inline void JobCall(Function&& function, Parameter& param, EmptyIntermediate*)
{
	ION_PROFILER_SCOPE(Job, "Task (EmptyIntermediate)");
	function(param);
}

template <typename Parameter, class Function>
inline void JobCall(Function&& function, Parameter& param)
{
	ION_PROFILER_SCOPE(Job, "Task");
	function(param);
}
}  // namespace ion
