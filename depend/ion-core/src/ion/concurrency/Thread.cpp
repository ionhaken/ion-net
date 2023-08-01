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
#include <ion/debug/Profiling.h>

#include <ion/memory/UniquePtr.h>

#include <ion/concurrency/Runner.h>
#include <ion/concurrency/Thread.h>

#include <ion/jobs/BaseJob.h>

#include <ion/temporary/TemporaryAllocator.h>
#include <ion/memory/GlobalMemoryPool.h>

#include <atomic>
#include <ion/core/Core.h>
#include <ion/hw/CPU.inl>
#include <ion/hw/FPControl.h>
#include <ion/string/String.h>
#include <ion/util/IdPool.h>
#include <ion/util/Random.h>

#if ION_PLATFORM_MICROSOFT
	#include <timeapi.h>
#else
#include <unistd.h>
#endif

class EmptyJob : public ion::BaseJob
{
public:
	void RunTask(){};
};

namespace ion
{
#if ION_PLATFORM_LINUX

int SchedulingPolicy = SCHED_FIFO;

#endif
namespace
{
std::atomic<int64_t> gSleepMinMicros;
EmptyJob gEmptyJob;
}  // namespace
thread_local Thread::ThreadLocalStore ion::Thread::mTLS;

#if ION_CONFIG_GLOBAL_MEMORY_POOL || ION_CONFIG_JOB_SCHEDULER
template <typename T>
class ThreadIdPool
{
public:
#if ION_THREAD_WAIT_AFTER_TERMINATE
	ion::ThreadSynchronizer mSynchronizer;
#endif
	ThreadIdPool()
	{
		ion::MemoryScope memoryScope(ion::tag::Core);
		gSleepMinMicros = 1000;
		mFreeingIds.Reserve(1024);
	}

	~ThreadIdPool() { ProcessFrees(); }

	T Reserve()
	{
		ion::MemoryScope memoryScope(ion::tag::Core);
		mMutex.Lock();

		// IdPool allocates memory only when freeing ids, so it's safe to reserve id before memory pool is ready
		T id = mIds.Reserve();
		ion::Thread::mTLS.mId = id;
#if ION_CONFIG_GLOBAL_MEMORY_POOL
		GlobalMemoryThreadInit(id);
#endif
		ProcessFreesInternal();
		mMutex.Unlock();
		return id;
	}

	void Free(T id)
	{
		ion::MemoryScope memoryScope(ion::tag::Core);
		mMutex.Lock();
		mFreeingIds.Add(id);
		ion::Thread::mTLS.mId = ~static_cast<UInt>(0);
		mMutex.Unlock();
	}

	bool ProcessFrees()
	{
		ion::MemoryScope memoryScope(ion::tag::Core);
		bool isEmpty;
		mMutex.Lock();
		isEmpty = ProcessFreesInternal();
		mMutex.Unlock();
		return isEmpty;
	}

private:
	bool ProcessFreesInternal()
	{
		bool isEmpty = false;
		for (size_t i = 0; i < mFreeingIds.Size(); ++i)
		{
			auto id = mFreeingIds[i];
			mIds.Free(id);
			if (id != 0)
			{
#if ION_CONFIG_GLOBAL_MEMORY_POOL
				GlobalMemoryThreadDeinit(id);
#endif
			}
		}
		mFreeingIds.Clear();
		if (mIds.Size() == 0)
		{
			mIds = IdPool<T>();
			isEmpty = true;
		}
		return isEmpty;
	}

	IdPool<T> mIds;
	Mutex mMutex;
	Vector<T> mFreeingIds;
};
#endif

#if ION_CONFIG_GLOBAL_MEMORY_POOL || ION_CONFIG_JOB_SCHEDULER
// Intentionally raw pointer to extend its scope
// We want to remove this only in FreeHeaps() - not in any dynamic destructor
std::atomic<ThreadIdPool<UInt>*> gThreadIdPool = nullptr;
#endif
}  // namespace ion

bool isInitialized = false;

bool ion::Thread::IsReady() { return isInitialized; }

bool ion::Thread::IsThreadInitialized() { return IsReady() && mTLS.mId != ~static_cast<UInt>(0); }

namespace ion
{
void InitThreadIdPool()
{
#if ION_CONFIG_GLOBAL_MEMORY_POOL || ION_CONFIG_JOB_SCHEDULER
	if (gThreadIdPool.load() == nullptr)
	{
		isInitialized = true;
		{
			ion::MemoryScope memoryScope(ion::tag::Core);
			gThreadIdPool.store(new ion::ThreadIdPool<UInt>());
		}
#if ION_PROFILER_BUFFER_SIZE_PER_THREAD > 0
		{
			ion::MemoryScope scope(ion::tag::Profiling);
			ion::ProfilingInit();
		}
#endif
	}
#endif
}
void FreeHeaps()
{
#if ION_CONFIG_GLOBAL_MEMORY_POOL || ION_CONFIG_JOB_SCHEDULER
	if (gThreadIdPool.load()->ProcessFrees())
	{
	#if ION_PROFILER_BUFFER_SIZE_PER_THREAD > 0
		{
			ion::MemoryScope scope(ion::tag::Profiling);
			ProfilingDeinit();
		}
	#endif
		ion::MemoryScope memoryScope(ion::tag::Core);
		delete gThreadIdPool.load();
		gThreadIdPool.store(nullptr);
	}
#endif
}

}  // namespace ion

void ion::Thread::OnEngineRestart()
{
	InitThreadIdPool();
	InitInternal(0, ion::Thread::Priority::Normal);
}

void ion::Thread::Init(ion::Thread::QueueIndex index, ion::Thread::Priority priority)
{
#if ION_CONFIG_GLOBAL_MEMORY_POOL || ION_CONFIG_JOB_SCHEDULER
	ION_ASSERT_FMT_IMMEDIATE(!IsThreadInitialized(), "Thread already initialized");
#endif
	InitThreadIdPool();
#if ION_CONFIG_JOB_SCHEDULER || ION_CONFIG_GLOBAL_MEMORY_POOL || ION_CONFIG_TEMPORARY_ALLOCATOR || ION_PROFILER_BUFFER_SIZE_PER_THREAD || \
  ION_MEMORY_TRACKER
	std::memset(&mTLS, 0x0, sizeof(ThreadLocalStore));
#endif
#if ION_CONFIG_JOB_SCHEDULER || ION_CONFIG_GLOBAL_MEMORY_POOL
	gThreadIdPool.load()->Reserve();
#endif
	InitInternal(index, priority);

}

void ion::Thread::Deinit()
{
#if ION_CONFIG_JOB_SCHEDULER
	ion::FPControl::Validate();
#endif
#if ION_CONFIG_JOB_SCHEDULER || ION_CONFIG_GLOBAL_MEMORY_POOL
	ION_ASSERT(mTLS.mId != ~static_cast<UInt>(0), "Thread not initialized");
	ION_ASSERT(isInitialized, "Threading not initialized");
#endif

#if ION_PROFILER_BUFFER_SIZE_PER_THREAD > 0
	mTLS.mProfiling = nullptr;
#endif
#if ION_CONFIG_JOB_SCHEDULER || ION_CONFIG_GLOBAL_MEMORY_POOL
	gThreadIdPool.load()->Free(mTLS.mId);
#endif
#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1
	if (mTLS.mTemporaryMemory)
	{
		ion::temporary::ThreadDeinit(mTLS.mTemporaryMemory);
		mTLS.mTemporaryMemory = nullptr;
	}
#endif
}

namespace ion
{
Int Thread::GetSchedulingPolicy()
{
#if ION_PLATFORM_LINUX
	return SchedulingPolicy;
#else
	return 0;
#endif
}

Int Thread::ThreadPriority(ion::Thread::Priority priority)
{
#if ION_PLATFORM_MICROSOFT
	return static_cast<Int>(priority) - 2;
#elif ION_PLATFORM_ANDROID
	// Special case for Android, we can use setpriority nice values
	switch (priority)
	{
	case Thread::Priority::Lowest:
		return 19;
	case Thread::Priority::BelowNormal:
		return 10;
	case Thread::Priority::Normal:
		return 0;
	case Thread::Priority::AboveNormal:
		return -10;
	case Thread::Priority::Highest:
		return -20;
	}
#else
	int minPriority = sched_get_priority_min(SchedulingPolicy);
	int maxPriority = sched_get_priority_max(SchedulingPolicy);

	switch (priority)
	{
	case Thread::Priority::Lowest:
		return minPriority;
	case Thread::Priority::BelowNormal:
		return (maxPriority + minPriority + minPriority) / 3;
	case Thread::Priority::Normal:
		return (maxPriority + minPriority) / 2;
	case Thread::Priority::AboveNormal:
		return (maxPriority + maxPriority + minPriority) / 3;
	case Thread::Priority::Highest:
		return maxPriority;
	}
#endif
}
}  // namespace ion

void ion::Thread::SetMainThreadPolicy()
{
#if ION_PLATFORM_LINUX
	pthread_t handle = pthread_self();
	int policy;
	struct sched_param param;
	pthread_getschedparam(handle, &policy, &param);
	if (policy != SchedulingPolicy)
	{
	#ifdef ION_UPDATE_SCHEDULING_POLICY
		ION_LOG_IMMEDIATE("Updating scheduling policy");
		auto err = pthread_setschedparam(handle, SchedulingPolicy, &param);
		if (err != 0)
	#endif
		{
	#ifdef ION_UPDATE_SCHEDULING_POLICY
			ION_LOG_FMT_IMMEDIATE("Cannot update main thread scheduling policy from %i to %i;error: %s", policy, SchedulingPolicy,
								  strerror(err));
	#endif
			SchedulingPolicy = policy;
		}
	}
#endif
}

void ion::Thread::SetPriority(ion::Thread::Priority priority)
{
	int targetThreadPriority = ion::Thread::ThreadPriority(priority);
#if ION_PLATFORM_MICROSOFT
	auto handle = GetCurrentThread();
	int currentThreadPriority = GetThreadPriority(handle);
#elif ION_PLATFORM_ANDROID
	errno = 0;
	int currentThreadPriority = getpriority(PRIO_PROCESS, 0);
	if (errno != 0)
	{
		ION_ABNORMAL("getpriority failed:" << strerror(errno));
		return;
	}
#else
	pthread_t handle = pthread_self();
	int policy;
	struct sched_param param;
	pthread_getschedparam(handle, &policy, &param);
	int currentThreadPriority = param.sched_priority;
#endif
	if (currentThreadPriority != targetThreadPriority)
	{
#if ION_PLATFORM_MICROSOFT
		constexpr BOOL ResultOK = TRUE;
		auto err = SetThreadPriority(handle, targetThreadPriority);
#elif ION_PLATFORM_ANDROID
		constexpr int ResultOK = 0;
		// Note that other systems than Android you must be running as superuser for setpriority to work.
		auto err = setpriority(PRIO_PROCESS, 0, targetThreadPriority);
#else
		constexpr int ResultOK = 0;
		param.sched_priority = targetThreadPriority;
		auto err = pthread_setschedparam(handle, SchedulingPolicy, &param);
#endif
		ION_ASSERT(err == ResultOK,
				   "Cannot change thread priority from " << currentThreadPriority << " to " << targetThreadPriority << ";err=" << err);
	}
}

void ion::Thread::InitInternal(ion::Thread::QueueIndex index, ion::Thread::Priority priority)
{
#if ION_CONFIG_JOB_SCHEDULER || ION_CONFIG_GLOBAL_MEMORY_POOL
	if (mTLS.mId == 0)
	{
		SetMainThreadPolicy();
	}
#endif

#if ION_CONFIG_JOB_SCHEDULER
	mTLS.mQueueIndex = index;
	mTLS.mJob = &gEmptyJob;
#endif
#if ION_PROFILER_BUFFER_SIZE_PER_THREAD > 0
	mTLS.mProfiling = profiling::Buffer(mTLS.mId, uint8_t(priority));
#endif
#if ION_CONFIG_JOB_SCHEDULER
	{
		time_t now;
		time(&now);
		ion::Random::Seed((static_cast<uint64_t>(std::hash<uint64_t>()(uint64_t(GetId()) ^ uint64_t(now)))), mTLS.mRandState);
	}
#endif

	// #TODO: High priority threads should have affinities
	SetPriority(priority);

	// Not enabled since there is not enough information for hand picking ideal processor for queue.
	// It's probably better not to restrict OS scheduler
#ifdef ION_USE_IDEAL_PROCESSOR
	// Use ideal processor when index is set, but let main thread (id 0) choose ideal processor itself
	if (index != NoQueueIndex && mTLS.mId != 0)
	{
		auto res = SetThreadIdealProcessor(handle, mTLS.mId);
		ION_ASSERT(res != -1, "Cannot set ideal processor for index " << index);
	}
#endif
#if ION_CONFIG_JOB_SCHEDULER
	FPControl::SetMode();
#endif
}

#if ION_CONFIG_JOB_SCHEDULER || ION_CONFIG_GLOBAL_MEMORY_POOL || ION_CONFIG_TEMPORARY_ALLOCATOR || ION_PROFILER_BUFFER_SIZE_PER_THREAD || \
  ION_MEMORY_TRACKER
ion::Thread::ThreadLocalStore::ThreadLocalStore() {}
#endif

#if ION_CONFIG_JOB_SCHEDULER || ION_CONFIG_GLOBAL_MEMORY_POOL || ION_CONFIG_TEMPORARY_ALLOCATOR || ION_PROFILER_BUFFER_SIZE_PER_THREAD || \
  ION_MEMORY_TRACKER
ion::Thread::ThreadLocalStore::~ThreadLocalStore() {}
#endif

#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1
ion::temporary::BytePool& ion::Thread::InitTemporaryMemory()
{
	mTLS.mTemporaryMemory = ion::temporary::ThreadInit();
	return *mTLS.mTemporaryMemory;
}
#endif

unsigned int ion::Thread::GetFPControlWord() { return FPControl::GetControlWord(); }

// http://stackoverflow.com/questions/13397571/precise-thread-sleep-needed-max-1ms-error
bool ion::Thread::Sleep(int64_t usec)
{
	bool isSuccess = true;
#if ION_PLATFORM_MICROSOFT
	UINT TARGET_RESOLUTION = static_cast<UINT>(ion::Max(1u, UINT(usec / 2000)));  // target in milliseconds
	TIMECAPS tc;
	UINT wTimerRes;
	if (timeGetDevCaps(&tc, sizeof(TIMECAPS)) == TIMERR_NOERROR)
#endif
	{
#if ION_PLATFORM_MICROSOFT
		wTimerRes = Min(Max(tc.wPeriodMin, TARGET_RESOLUTION), tc.wPeriodMax);
		timeBeginPeriod(wTimerRes);
		if (gSleepMinMicros != tc.wPeriodMin * 1000)
		{
			gSleepMinMicros = Max(static_cast<int64_t>(gSleepMinMicros), static_cast<int64_t>(tc.wPeriodMin * 1000));
		}
		HANDLE timer = CreateWaitableTimer(NULL, TRUE, NULL);
		LARGE_INTEGER li;
		if (timer)
		{
			usec -= tc.wPeriodMin * 1000;  // Windows timer granularity correction
			li.QuadPart = -usec * 10;	   // 1 = 100ns
			if (SetWaitableTimer(timer, &li, 0, NULL, NULL, FALSE))
			{
				WaitForSingleObject(timer, INFINITE);
			}
			else
			{
				ION_ASSERT(false, "SetWaitableTimer failed: " << ion::debug::GetLastErrorString());
				isSuccess = false;
			}
			CloseHandle(timer);
		}
		else
		{
			ION_ASSERT(false, "CreateWaitableTimer failed: " << ion::debug::GetLastErrorString());
			isSuccess = false;
		}
#else
		// Other options, probably worse resolution:
		// - usleep(usec)
		// - std::this_thread::sleep_for(std::chrono::microseconds(usec));
		/*struct timeval tv;
		auto usecs = static_cast<long>(usec) % 1000000;
		auto seconds = (static_cast<long>(usec) - usecs) / 1000000);

		tv.tv_sec = seconds;
		tv.tv_usec = seconds > 0 ? usecs : ion::Max(1, usecs);
		select(0, NULL, NULL, NULL, &tv);*/
		int res = usleep(ion::Max(useconds_t(1), useconds_t(usec)));
		ION_ASSERT(res == 0, "usleep failed(): " << ion::debug::GetLastErrorString());
#endif
#if ION_PLATFORM_MICROSOFT
		timeEndPeriod(wTimerRes);
#endif
	}
#if ION_PLATFORM_MICROSOFT
	else
	{
		ION_ASSERT(false, "timeGetDevCaps failed: " << ion::debug::GetLastErrorString());
		isSuccess = false;
	}
#endif
	return isSuccess;
}

bool ion::Thread::SleepMs(int64_t ms) { return Sleep(int64_t(1000) * ms); }

int64_t ion::Thread::MinSleepUsec()
{
	return 2 * gSleepMinMicros;  // 2x due to sampling rate
}

void ion::Thread::YieldCPU() { ion::platform::Yield(); }


#if ION_THREAD_WAIT_AFTER_TERMINATE
ion::ThreadSynchronizer& ion::Thread::Synchronizer() { return gThreadIdPool.load()->mSynchronizer; }
#endif


namespace ion::Thread
{
ION_ACCESS_GUARD_STATIC(gGuard);
std::atomic<int> gIsInitialized = 0;
}

void ion::Thread::InitMain()
{
	ION_ACCESS_GUARD_WRITE_BLOCK(gGuard);
	if (0 != gIsInitialized++)
	{
		return;
	}
#if ION_CONFIG_TEMPORARY_ALLOCATOR
	ion::TemporaryInit();
#endif
	ion::Thread::Init(0);
}

void ion::Thread::DeinitMain()
{
	ION_ACCESS_GUARD_WRITE_BLOCK(gGuard);
	if (1 != gIsInitialized--)
	{
		return;
	}
	ion::Thread::Deinit();
	FreeHeaps();
#if ION_CONFIG_TEMPORARY_ALLOCATOR
	ion::TemporaryDeinit();
#endif
}

#if ION_CONFIG_JOB_SCHEDULER == 0
uint64_t* ion::Thread::GetRandState()
{
	static thread_local uint64_t randState[2] = {uint64_t(rand()) | 1, uint64_t(rand()) | 1};
	return randState;
}
#endif
