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
#include <ion/jobs/ParallelForJob.h>

namespace ion
{
template <class Algorithm>
class ListJob : public ListJobBase
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(ListJob);

public:
	template <class TFunction, typename Iterator>
	ListJob(ThreadPool& tp, const Iterator& first, const Iterator& last, TFunction&& function, UInt batchSize)
	  : ListJobBase(tp, last - first, batchSize),
		mAlgorithm(size_t(last - first), batchSize),
		mFunction( // work moved inside lambda to reduce code size
		  [function, first,  this]()
		  {
			  ION_PROFILER_SCOPE(Job, "List iteration");
			  mAlgorithm.Run(first, function);
		  })
	{
	}

	void Wait(UInt firstQueueIndex, UInt partitionSize, UInt batchSize)
	{
		ION_ASSERT(partitionSize > 0, "Invalid partition size");
		ION_ASSERT(batchSize > 0, "Invalid batch size");
		size_t numTaskLists = ParallelForJob::CalcNumTaskLists(batchSize, mAlgorithm.TotalItems());
		mAlgorithm.CreatePartitions(partitionSize, numTaskLists);
		CreateTasksAndWait(firstQueueIndex, numTaskLists);
	}

	void Wait(UInt firstQueueIndex, UInt batchSize)
	{
		ION_ASSERT(batchSize > 0, "Invalid batch size");
		size_t numTaskLists = ParallelForJob::CalcNumTaskLists(batchSize, mAlgorithm.TotalItems());
		CreateTasksAndWait(firstQueueIndex, numTaskLists);
	}

protected:
	void CreateTasksAndWait(UInt firstQueueIndex, size_t numTaskLists)
	{
		if (numTaskLists > 1)
		{
			ParallelForJob::AddTaskLists(firstQueueIndex, numTaskLists);
		}
		ion::Thread::SetCurrentJob(this);
		mFunction();
		ion::Thread::SetCurrentJob(this->mSourceJob);
		WaitableJob::Wait();
	}

	virtual void RunTask() final override
	{
		ION_PROFILER_SCOPE_DETAIL(Scheduler, "Task List", size_t(ListJobBase::NumItems() - ListJobBase::Index()));
		this->OnTaskStarted();
		mFunction();
		this->OnTaskDone();
	}

private:
	ION_ALIGN_CACHE_LINE Algorithm mAlgorithm;
	const task::Function<void()> mFunction;
};
}  // namespace ion
