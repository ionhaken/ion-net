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

#include <ion/jobs/ListJob.h>

namespace ion
{
template <typename Iterator, class Function, class Intermediate>
class IntermediateListJob : public ListJobBase
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(IntermediateListJob);

public:
	IntermediateListJob(ThreadPool& tp, const Iterator& first, const Iterator& last, const Function&& function, UInt minBatchSize,
						Intermediate& intermediate)
	  : ListJobBase(tp, last - first, minBatchSize),
		mFunction(
		  [function, first, &intermediate, this](bool isCallingThread)
		  {
			  ION_PROFILER_SCOPE(Job, "List iteration (intermediate)");
			  size_t startIndex;
			  size_t endIndex;
			  if (isCallingThread)
			  {
				  while (ListJobBase::FindTasks(startIndex, endIndex))
				  {
					  for (size_t i = startIndex; i < endIndex; ++i)
					  {
						  ION_PROFILER_SCOPE_DETAIL(Job, "Task", i);
						  function(first[i], intermediate.GetMain());
					  }
				  }
			  }
			  else
			  {
				  typename Intermediate::Type* freeIntermediate;

				  if (ListJobBase::FindTasks(startIndex, endIndex))
				  {
					  freeIntermediate = &intermediate.GetFree();
					  do
					  {
						  for (size_t i = startIndex; i < endIndex; ++i)
						  {
							  ION_PROFILER_SCOPE_DETAIL(Job, "Task", i);
							  function(first[i], *freeIntermediate);
						  }
					  } while (ListJobBase::FindTasks(startIndex, endIndex));
				  }
			  }
		  })
	{
	}

	void Wait(UInt firstQueueIndex)
	{
		ListJobBase::AddTaskLists(firstQueueIndex);
		ion::Thread::SetCurrentJob(this);
		mFunction(true);
		ion::Thread::SetCurrentJob(this->mSourceJob);
		WaitableJob::Wait();
	}

protected:
	virtual void RunTask() final override
	{
		ION_PROFILER_SCOPE_DETAIL(Scheduler, "Task List intermediate", ListJobBase::NumItems());
		this->OnTaskStarted();
		mFunction(false);
		this->OnTaskDone();
	}

private:
	using MemberFunc = ion::InplaceFunction<void(bool)>;
	MemberFunc mFunction;
};
}  // namespace ion
