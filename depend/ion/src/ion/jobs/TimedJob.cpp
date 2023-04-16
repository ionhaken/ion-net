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
#include <ion/jobs/JobDispatcher.h>
#include <ion/debug/Profiling.h>
#include <ion/jobs/ThreadPool.h>
#include <ion/jobs/TimedJob.h>
#include <ion/hw/CPU.inl>
#include <ion/core/Core.h>

#define ION_DEBUG_TIMED_JOB 0

ION_CODE_SECTION(".jobs")
ion::TimedJob::TimedJob(MemTag tag)
  : BaseJob(tag),
	mNumTasksInProgress(0),
	mDispatcherJob(ion::core::gSharedDispatcher->DispatcherJobPool().Acquire(this))
{
	ION_ASSERT(mDispatcherJob, "Out of memory");
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
bool ion::TimedJob::IsActive() const { return mDispatcherJob->IsActive(); }
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::TimedJob::Restore()
{
	ION_ASSERT(mDispatcherJob->mState == TimedJobState::Inactive, "Invalid state");
	ION_ASSERT(mNumTasksInProgress == 0, "Invalid state");
	mDispatcherJob->mState = TimedJobState::Active;
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::TimedJob::OnDispatched()
{
	AutoLock<ThreadSynchronizer> lock(mSynchronizer);
	ION_ASSERT(mDispatcherJob->mState == TimedJobState::Active, "Invalid state");
	mNumTasksInProgress++;
	ION_ASSERT(mNumTasksInProgress < 256, "Lots of tasks in progress");
	ION_ASSERT(
	  Timer().GetMicros(SteadyClock::GetTimeUS()) >= -30 * 1000 * 1000 && Timer().GetMicros(SteadyClock::GetTimeUS()) <= 30 * 1000 * 1000,
	  "Job has really long delay");
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::TimedJob::OnRemoved()
{
	AutoLock<ThreadSynchronizer> lock(mSynchronizer);
	ION_ASSERT(mNumTasksInProgress > 0, "Invalid task count");
	if (--mNumTasksInProgress == 0)
	{
		mDispatcherJob->mState = TimedJobState::Inactive;
		lock.NotifyAll();
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::TimedJob::RunTask()
{
#if ION_ABORT_ON_FAILURE && ION_DEBUG_TIMED_JOB
	if (mDispatcherJob->TimeLeft(SteadyClock::GetTimeUS()) < TimeDeltaUS(-5 * 1000))
	{
		ION_WRN("Running TimedJob " << ToString() << " with time left="
								<< static_cast<double>(mDispatcherJob->TimeLeft(SteadyClock::GetTimeUS()) / 1000) << "ms");
	}
#endif
	RunTimedTask();
	Reschedule();
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::TimedJob::Reschedule()
{
#if ION_ABORT_ON_FAILURE && ION_DEBUG_TIMED_JOB
	if (mDispatcherJob->TimeLeft(SteadyClock::GetTimeUS()) < TimeDeltaUS(-5 * 1000) && !mDispatcherJob->IsMainThread())
	{
		ION_WRN("Adding TimedJob " << ToString() << " with time left="
							   << static_cast<double>(mDispatcherJob->TimeLeft(SteadyClock::GetTimeUS())) / 1000 << "ms");
	}
#endif
	ion::core::gSharedDispatcher->Reschedule(this);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::TimeUS ion::TimedJob::RescheduleImmediately()
{
	ion::TimeUS now = Timer().Reset(0);
	ion::core::gSharedDispatcher->WakeUp();
	return now;
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
bool ion::TimedJob::Cancel()
{
	AutoLock<ThreadSynchronizer> lock(mSynchronizer);
	if (mNumTasksInProgress == 0)
	{
		mDispatcherJob->mState = TimedJobState::Inactive;
		return true;
	}
	else if (mDispatcherJob->mState == TimedJobState::Active)
	{
		mDispatcherJob->mState = TimedJobState::Stopping;
	}
	return false;
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::TimedJob::WaitUntilDone()
{
	for (;;)
	{
		if (Cancel())
		{
			return;
		}
		ION_ASSERT(!mDispatcherJob->mIsMainThread, "Can't wait for main thread jobs, try Cancel()");
		ion::core::gSharedDispatcher->Wait(
		  [&]() -> bool
		  {
			  AutoLock<ThreadSynchronizer> lock(mSynchronizer);
			  return mNumTasksInProgress == 0;
		  });
	}
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::TimedJob::~TimedJob()
{
	ION_ASSERT(mDispatcherJob->mState == TimedJobState::Inactive, "Still running. Call WaitUntilDone() in destructor");
	ION_ASSERT(mNumTasksInProgress == 0, "Still tasks left");
	ion::core::gSharedDispatcher->DispatcherJobPool().Release(mDispatcherJob);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::OneShotJob::OneShotJob(ion::MemTag tag, double delay) : TimedJob(tag)
{
	ION_ASSERT(delay >= 0, "Invalid delay");
	Timer().Advance(static_cast<double>(delay));
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::OneShotJob::~OneShotJob() { WaitUntilDone(); }
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::OneShotJob::RunTask()
{
	RunTimedTask();
	OnRemoved();
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::PeriodicJob::PeriodicJob(ion::MemTag tag, double interval, UInt extraIntervals, UInt maxIntervalsLate)
  : TimedJob(tag),
	mPeriod(static_cast<TimeUS>(interval * 1000.0 * 1000.0 + 0.5)),
	mExtraIntervals(extraIntervals),
	mMaxIntervalsLate(std::max(maxIntervalsLate, mExtraIntervals))
{
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::PeriodicJob::SetPreStart(TimeUS t)
{
	auto previousPreStart = mPreStartTime;
	mPreStartTime = t;
	TimeDeltaUS diff = ion::DeltaTime(mPreStartTime, previousPreStart);
	Timer().Update(diff);
}

ION_CODE_SECTION(".jobs")
void ion::PeriodicJob::SetInterval(double interval)
{
	auto previousInterval = mPeriod;
	mPeriod = static_cast<TimeUS>(interval * 1000.0 * 1000.0 + 0.5);
	TimeDeltaUS diff = ion::DeltaTime(mPeriod, previousInterval);
	Timer().Update(diff);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::PeriodicJob::RunTask()
{
	// Pre-start handling: Sleep/Busyloop until it's the actual time to run the task
	ION_ASSERT(TimeLeft() <= 0 || mPreStartTime > 0, "Pre-started although no pre-start time set");
	TimeDeltaUS timeLeft = Timer().PreciseWaitUntil(mPreStartTime);
	while (timeLeft <= 0)
	{
		RunTimedTask();
		Timer().Advance(mPeriod);
		timeLeft = TimeLeft();

		// Reset timer when too late
		if (timeLeft <= -TimeDeltaUS(mPeriod) * ion::Int(mMaxIntervalsLate))
		{
			ResetTimer();
			Timer().Withdraw(mExtraIntervals * mPeriod);
		}

		if (mSingleUpdatePerPeriod)
		{
			break;
		}
	}
	Reschedule();
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::PeriodicJob::ResetTimer()
{
	Timer().Reset();
	Timer().Advance(mPeriod);
	Timer().Withdraw(mPreStartTime);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::PeriodicJob::OnDispatched()
{
	ResetTimer();
	TimedJob::OnDispatched();
}
ION_SECTION_END
