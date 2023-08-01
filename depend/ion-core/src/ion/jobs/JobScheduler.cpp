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
#include <ion/jobs/ThreadPool.h>
#include <ion/jobs/JobScheduler.h>
#include <ion/jobs/JobDispatcher.h>
#include <ion/memory/UniquePtr.h>
#include <ion/util/Random.h>
#include <ion/util/OsInfo.h>


ION_CODE_SECTION(".jobs")
ion::JobScheduler::JobScheduler(uint16_t hwConcurrency)
  : mDispatcher(hwConcurrency > 0 ? hwConcurrency : static_cast<uint16_t>(ion::Min(ion::OsHardwareConcurrency(), ion::MaxThreads)))
{
	ion::Thread::SetPriority(MainThreadPriority);
	if (ion::core::gSharedScheduler == nullptr)
	{
		ion::tracing::Flush();
		ion::core::gSharedScheduler = this;
	}
#if ION_PROFILER_BUFFER_SIZE_PER_THREAD > 0
	ion::profiling::OnBeginScheduling();
#endif
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
ion::JobScheduler::~JobScheduler()
{
#if ION_PROFILER_BUFFER_SIZE_PER_THREAD > 0
	ion::profiling::OnEndScheduling();
#endif
	mDispatcher.StopThreads();
	if (ion::core::gSharedScheduler == this)
	{
		ion::core::gSharedScheduler = nullptr;
		ion::tracing::FlushUntilEmpty();
	}
	ion::Thread::SetPriority(ion::Thread::Priority::Normal);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::JobScheduler::PushJob(TimedJob& job)
{
	job.Restore();
	mDispatcher.Add(&job);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::JobScheduler::PushMainThreadJob(BaseJob& job)
{
	Task task(&job);
	mDispatcher.ThreadPool().AddMainThreadTask(std::move(task));
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::JobScheduler::PushLongJob(BaseJob& job)
{
	Task task(&job);
	mDispatcher.ThreadPool().PushLongTask(std::move(task));
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::JobScheduler::UpdateOptimizer(double t)
{
	float volatilityMult = 1.01f;
	do
	{
		if (t <= mMeasurement.mLastTime)
		{
			if (t <= mMeasurement.mLastTime * 0.95f)
			{
				volatilityMult = 0.99f;
			}
			mMeasurement.mGoodResultCounter++;
			if (mMeasurement.mGoodResultCounter > 5)
			{
				mMeasurement.mBestCoefficientA = mMeasurement.mCoefficientA;
				float rnd = ion::Random::FastFloat() - 0.5f;
				mMeasurement.mCoefficientA = ion::Max(0.0f, mMeasurement.mBestCoefficientA + (0.25f * mMeasurement.mVolatility * rnd));
			}
			else
			{
				break;
			}
		}
		else
		{
			if (t >= mMeasurement.mLastTime * 1.05f)
			{
				volatilityMult = 0.99f;
			}
			mMeasurement.mCoefficientA = mMeasurement.mBestCoefficientA;
		}

		mMeasurement.mGoodResultCounter = 0;
		mMeasurement.mLastTime = t;
	} while (0);
	mMeasurement.mVolatility = ion::Clamp(mMeasurement.mVolatility * volatilityMult, 0.9f, 1.1f);
}
ION_SECTION_END
