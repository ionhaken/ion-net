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
#include <ion/container/Vector.h>

#include <ion/memory/TSObjectPool.h>

#include <ion/concurrency/MPSCQueue.h>
#include <ion/concurrency/Runner.h>
#include <ion/concurrency/SCThreadSynchronizer.h>

#include <ion/jobs/ThreadPool.h>
#include <ion/jobs/TimedJob.h>

#include <ion/core/Core.h>

namespace ion
{
class TimedJob;
class DispatcherJob;
class Task;

class JobDispatcher
{
	friend class TimedJob;

public:
	JobDispatcher(UInt hwConcurrency);

	void Add(TimedJob* job);

	~JobDispatcher();

	inline ion::ThreadPool& ThreadPool() { return mThreadPool; }

	ion::ThreadSafeObjectPool<DispatcherJob, ion::CoreAllocator<DispatcherJob>>& DispatcherJobPool() { return mDispatcherJobPool; }

	void WakeUp();

	void StopThreads();

private:
	ion::ThreadSafeObjectPool<DispatcherJob, ion::CoreAllocator<DispatcherJob>> mDispatcherJobPool;

	// Wait is called by TimedJob
	template <class Function>
	void Wait(Function&& func)
	{
		mSynchronizer.Signal();
		UInt queue = ion::Thread::QueueIndex();
		while (func() == false)
		{
			queue = DoJobWork(queue);
		}
	}

	std::atomic<TimeUS> mNextUpdate;

	UInt DoJobWork(UInt queue);
	void Reschedule(TimedJob* job);

	ion::ThreadPool mThreadPool;
	SCThreadSynchronizer mSynchronizer;
	MPSCQueue<DispatcherJob*, ion::CoreAllocator<DispatcherJob*>> mInQueue;
	Vector<DispatcherJob*, ion::CoreAllocator<DispatcherJob*>> mTimedQueue;	 // #TODO: Use priority queue
	Runner mThread;
};
}  // namespace ion
