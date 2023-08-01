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

#include <ion/concurrency/Thread.h>

#if ION_JOB_STATS == 1
	#include <ion/time/CoreTime.h>
#endif

namespace ion
{
class ThreadPool;
class BaseJob
{
public:
	BaseJob(BaseJob* sourceJob = nullptr)
	  : mSourceJob(sourceJob),
		mJobRecursion(mSourceJob ? mSourceJob->GetRecursion() + 1 : 0)
#if ION_MEMORY_TRACKER
		,
		mTag(mSourceJob ? mSourceJob->Tag() : ion::tag::Unset)
#endif
	{
	}

	BaseJob(MemTag
#if ION_MEMORY_TRACKER
			  tag
#endif
			)
	  : mSourceJob(nullptr),
		mJobRecursion(0)
#if ION_MEMORY_TRACKER
		,
		mTag(tag)
#endif
	{
	}

#if ION_MEMORY_TRACKER
	MemTag Tag() const { return mTag; }

	void SetTag(MemTag tag) { mTag = tag; }
#endif

	virtual ~BaseJob()
	{
#if ION_JOB_STATS == 1
		// Print warning if it had been faster to run job without parallel tasks.
		if (mStatSingleThreadTasks > 0 && mStatSingleThreadTasks != mStatsTotalTasks)
		{
			auto totalTime = mStatTimer.GetSeconds() * 1000 * 1000;
			auto localTimeEstimate = mStatSingleThreadTime * mStatsTotalTasks / mStatSingleThreadTasks * 1000 * 1000;
			if (localTimeEstimate < totalTime)
			{
				ION_LOG_INFO("Increase min parallel task: Tasks(local)=" << mStatsTotalTasks << "(" << mStatSingleThreadTasks << ")"
																<< ";Time=" << totalTime << ";LocalEst=" << localTimeEstimate);
			}
		}
#endif
	}

	inline UInt GetRecursion() const { return mJobRecursion; }

	inline const BaseJob* GetRootJob() const { return (mSourceJob == nullptr) ? this : mSourceJob->GetRootJob(); }

	inline bool IsMyJob(const BaseJob* job) const
	{
		ION_ASSERT(job != this, "Must check higher level");
		if (job == mSourceJob)
		{
			return true;
		}
		else if (mSourceJob != nullptr)
		{
			if (mSourceJob->GetRecursion() <= job->GetRecursion())
			{
				return false;
			}
			ION_ASSERT(mSourceJob != mSourceJob->mSourceJob, "Source job cannot be same");
			return mSourceJob->IsMyJob(job);
		}
		return false;
	}

	virtual void RunTask() = 0;

protected:
	BaseJob* const mSourceJob;
#if ION_JOB_STATS == 1
	ion::StopClock mStatTimer;
	size_t mStatSingleThreadTasks = 0;
	size_t mStatsTotalTasks = 0;
	double mStatSingleThreadTime;
#endif

private:
	const UInt mJobRecursion;
#if ION_MEMORY_TRACKER
	MemTag mTag;
#endif
	BaseJob& operator=(const BaseJob&) = delete;
	BaseJob(const BaseJob&) = delete;
};
}  // namespace ion
