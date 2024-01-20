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
#include <ion/concurrency/ThreadSynchronizer.h>
#include <ion/time/CoreTime.h>
#include <ion/memory/Memory.h>
#include <ion/string/String.h>
#include <ion/memory/UniquePtr.h>
#include <atomic>

namespace ion
{
class JobDispatcher;

class TimedJob;

enum class TimedJobState : uint8_t
{
	Active,
	Stopping,
	Inactive,
};

class DispatcherJob
{
public:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(DispatcherJob);
	DispatcherJob(TimedJob* job) : mJob(job), mState(TimedJobState::Inactive) {}

	// Return true if this task needs to be run in main thread
	bool IsMainThread() const { return mIsMainThread; }

	bool IsActive() const { return mState == TimedJobState::Active; }

	TimeDeltaUS TimeLeft(ion::TimeUS now) { return -mTimer.GetMicros(now); }

	TimedJob* mJob;
	AtomicStopClock mTimer;
	std::atomic<TimedJobState> mState;
	bool mIsMainThread = false;
};

// #TODO Rename as interval job
class TimedJob : public BaseJob
{
	friend class JobDispatcher;
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(TimedJob);

public:
	TimedJob(MemTag tag);

	virtual void RunTimedTask() = 0;

	void DoWork() override;

	virtual bool Cancel();

	ion::TimeUS RescheduleImmediately();

	virtual ~TimedJob();

	bool IsActive() const;

	virtual ion::String ToString() { return ion::String("Unknown"); }

	void WaitUntilDone();

	void Restore();

protected:
	AtomicStopClock& Timer() { return mDispatcherJob->mTimer; }
	const AtomicStopClock& Timer() const { return mDispatcherJob->mTimer; }

	void SetMainThread() { mDispatcherJob->mIsMainThread = true; }

	virtual void OnDispatched();

	void OnRemoved();

	void Reschedule();

private:
	std::atomic<UInt> mNumTasksInProgress;
	mutable ThreadSynchronizer mSynchronizer;
	DispatcherJob* mDispatcherJob;
};

class OneShotJob : public TimedJob
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(OneShotJob);

public:
	OneShotJob(ion::MemTag tag, double delay);

	void DoWork() final;

	~OneShotJob();
};

class PeriodicJob : public TimedJob
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(PeriodicJob);

public:
	// tag Memory tag
	// interval Length of interval
	// extraIntervals Extra intervals to run at start of job.
	// maxIntervalsLate Max intervals job is allowed to be late. Cannot be less than extra intervals.
	//		When job is consider late, extra intervals will be reset.
	PeriodicJob(ion::MemTag tag, double interval, UInt extraIntervals = 0, UInt maxIntervalsLate = 0);

	void DoWork() final;

	virtual void OnDispatched() override;

	void SetInterval(double interval);

	TimeUS Interval() const { return mPeriod; }

protected:
	void SetDontSkipMissedPeriods() { mSingleUpdatePerPeriod = false; }

	// Time to pre-schedule job to allow job execution to happen at the right time. Otherwise,
	// job scheduling will almost always delay job and it will start more or less late.
	// Note that although job might start too early, thread will be put to sleep/busyloop until actual execution time.
	void SetPreStart(TimeUS t);

private:
	void ResetTimer();

	TimeDeltaUS TimeLeft() const { return mPreStartTime - Timer().GetMicros(); }

	TimeUS mPreStartTime = 0;
	TimeUS mPeriod;
	UInt mExtraIntervals = 0;
	UInt mMaxIntervalsLate = 0;
	bool mSingleUpdatePerPeriod = true;
};

}  // namespace ion
