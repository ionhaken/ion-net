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
#include <ion/container/ForEach.h>
#include <ion/time/CoreTime.h>
#include <ion/jobs/JobDispatcher.h>
#include <ion/debug/Profiling.h>
#include <ion/jobs/ThreadPool.h>
#include <ion/jobs/TimedJob.h>
#include <cmath>

#define DEBUG_DISPATCHER(__text, ...)  // ION_LOG_INFO(__text, __VA_ARGS__);
#define MEASURE_DISPATCHER(__work)	   // __work

ION_CODE_SECTION(".jobs")
ion::JobDispatcher::JobDispatcher(UInt hwConcurrency)
  : mThreadPool(hwConcurrency),
	mThread((
	  [&]()
	  {
		  mNextUpdate = SteadyClock::GetTimeUS();
		  MEASURE_DISPATCHER(ion::TimeDeltaUS mTotalWorkTime = 0);
		  while (mSynchronizer.TryWaitUntil(mNextUpdate))
		  {
			  ION_PROFILER_SCOPE(Scheduler, "Dispatcher");
			  MEASURE_DISPATCHER(ion::StopClock mWorkTime);

			  mInQueue.DequeueAll(
				[&](DispatcherJob* job)
				{
					if (job->IsActive())
					{
						mTimedQueue.Add(job);
					}
					else
					{
						job->mJob->OnRemoved();
					}
				});

			  TimeDeltaUS duration = 1u * 60 * 1000 * 1000;
			  ion::TimeUS now = ion::SteadyClock::GetTimeUS();
			  DEBUG_DISPATCHER("Process timed jobs;now=" << now);
			  ion::ForEachEraseUnordered(
				mTimedQueue,
				[&](DispatcherJob* dJob)
				{
					bool isActive = dJob->IsActive();
					if (isActive)
					{
						auto timeLeft = dJob->TimeLeft(now);
						if (timeLeft <= 0)
						{
							JobWork work(dJob->mJob);
							DEBUG_DISPATCHER("Dispatch task " << dJob->mJob->ToString()
															  << ";timeLeft=" << static_cast<double>(timeLeft) / 1000 << "ms"
															  << ";now=" << now);
							if (dJob->IsMainThread())
							{
								mThreadPool.AddMainThreadTask(std::move(work));
							}
							else
							{
								mThreadPool.PushTask(std::move(work));
							}
						}
						else
						{
							if (timeLeft < duration)
							{
								duration = timeLeft;
								DEBUG_DISPATCHER("Worst duration " << dJob->mJob->ToString()
																   << ":timeLeft=" << static_cast<double>(timeLeft) / 1000 << "ms");
							}
							return ion::ForEachOp::Next;
						}
					}
					else
					{
						dJob->mJob->OnRemoved();
					}
					return ion::ForEachOp::Erase;
				});

			  TimeDeltaUS durationCapped = duration >= 2000 ? (duration - 500) : 1500;
			  DEBUG_DISPATCHER("Time to update;wait=" << durationCapped << "us"
													  << ";real=" << duration << "us;now=" << now);
			  mNextUpdate = now +  // Assuming timed queue update is so fast that there's no need to update clock
							(durationCapped);
			  MEASURE_DISPATCHER(mTotalWorkTime += mWorkTime.GetMicros());
		  }
		  MEASURE_DISPATCHER(ION_LOG_INFO("Total time spent in dispatcher=" << static_cast<double>(mTotalWorkTime) / 1000 << " ms; CPU used="
																   << static_cast<double>(mTotalWorkTime) / 1000 * 100 /
																		ion::SystemTimePoint::Current().MillisecondsSinceStart()
																   << " %"););

		  ION_ASSERT(ion::core::gSharedDispatcher == this, "Job dispatcher lost");
		  ion::core::gSharedDispatcher = nullptr;

		  mInQueue.DequeueAll([&](DispatcherJob* job) { job->mJob->OnRemoved(); });

		  ion::ForEach(mTimedQueue, [&](DispatcherJob* job) -> void { job->mJob->OnRemoved(); });
	  })),
	mDispatcherJobPool(256)
{
	ION_ASSERT(ion::core::gSharedDispatcher == nullptr, "Duplicate job dispatcher");
	ion::core::gSharedDispatcher = this;
	mThread.Start(32 * 1024, DispatcherPriority);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::JobDispatcher::Add(TimedJob* job)
{
	job->OnDispatched();
	Reschedule(job);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::UInt ion::JobDispatcher::DoJobWork(UInt queue) { return mThreadPool.DoJobWork(queue); }
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::JobDispatcher::Reschedule(TimedJob* job)
{
	ION_ASSERT(mSynchronizer.IsActive(), "Synchronized stopped");

	mInQueue.Enqueue(std::move(job->mDispatcherJob));
	DEBUG_DISPATCHER("Adding job " << job->ToString() << " with " << job->mDispatcherJob->TimeLeft(ion::SteadyClock::GetTimeUS())
								   << "us time left"
								   << ";now=" << ion::SteadyClock::GetTimeUS());
	// Wake-up dispatcher to handle mInQueue queue, althought there are no jobs to process
	mSynchronizer.Signal();
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::JobDispatcher::WakeUp() { mSynchronizer.Signal(); }
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::JobDispatcher::StopThreads()
{
	ION_PROFILER_SCOPE(Scheduler, "Stopping dispatcher");
	mSynchronizer.Stop();
	mThread.Join();
	mThreadPool.StopThreads();
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::JobDispatcher::~JobDispatcher()
{
}
ION_SECTION_END
