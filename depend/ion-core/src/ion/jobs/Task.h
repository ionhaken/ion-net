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
#include <ion/jobs/BaseJob.h>
#include <ion/concurrency/Thread.h>

namespace ion
{
class BaseJob;

class Task
{
public:
	Task() : mJob(nullptr) {}

	Task(BaseJob* aJob) : mJob(aJob) {}

	bool IsMyJob(const BaseJob* ION_RESTRICT job) const
	{
		ION_ASSERT(job != nullptr, "Must have a job to use this method");
		if (job == mJob)
		{
			return true;
		}
		else if (mJob != nullptr)
		{
			if (job->GetRecursion() < mJob->GetRecursion())
			{
				return mJob->IsMyJob(job);
			}
		}
		return false;
	}

	void Run()
	{
		auto oldJob = ion::Thread::GetCurrentJob();
		ion::Thread::SetCurrentJob(mJob);
		mJob->RunTask();  // After this call mJob is not valid anymore
		ion::Thread::SetCurrentJob(oldJob);
	}

private:
	BaseJob* ION_RESTRICT mJob;
};
}  // namespace ion
