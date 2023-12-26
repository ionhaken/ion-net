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
#include <ion/memory/Memory.h>

#define ION_THREAD_USE_SCHEDULING_POLICY 0

// Not enabled since there is not enough information for hand picking ideal processor for queue.
// It's probably better not to restrict OS scheduler
#define ION_THREAD_USE_IDEAL_PROCESSOR 0

#if ION_PLATFORM_MICROSOFT
	#define ION_THREAD_WAIT_AFTER_TERMINATE 0
#else
	#define ION_THREAD_WAIT_AFTER_TERMINATE 1
#endif

#include <limits>

namespace ion
{
class BaseJob;
class ProfilingBuffer;
class ThreadSynchronizer;
namespace temporary
{
struct BytePool;
}

namespace Thread
{

static constexpr const uint32_t DefaultStackSize = 256 * 1024;
static constexpr const uint32_t MinimumStackSize = 16384;

enum class Priority : uint8_t
{
	Lowest,
	BelowNormal,
	Normal,
	AboveNormal,
	Highest
};

using QueueIndex = ion::UInt;

static constexpr QueueIndex NoQueueIndex = (std::numeric_limits<QueueIndex>::max)();

#if ION_CONFIG_JOB_SCHEDULER || ION_CONFIG_GLOBAL_MEMORY_POOL || ION_CONFIG_TEMPORARY_ALLOCATOR || ION_PROFILER_BUFFER_SIZE_PER_THREAD || \
  ION_MEMORY_TRACKER
struct ThreadLocalStore
{
	ThreadLocalStore();
	#if ION_CONFIG_JOB_SCHEDULER
	BaseJob* mJob = nullptr;
	#endif
	#if ION_CONFIG_TEMPORARY_ALLOCATOR
	ion::temporary::BytePool* mTemporaryMemory = nullptr;
	#endif
	#if ION_CONFIG_JOB_SCHEDULER
	uint64_t mRandState[2] = {0};
	#endif
	#if ION_CONFIG_JOB_SCHEDULER || ION_CONFIG_GLOBAL_MEMORY_POOL
	UInt mId = ~static_cast<UInt>(0);
	#endif
	#if ION_CONFIG_JOB_SCHEDULER
	QueueIndex mQueueIndex = 0;
	#endif

	// Debug features
	#if ION_PROFILER_BUFFER_SIZE_PER_THREAD > 0
	ProfilingBuffer* mProfiling = nullptr;
	#endif
	#if ION_MEMORY_TRACKER
	ion::MemTag mMemoryTag = ion::tag::Unset;
	#endif
	~ThreadLocalStore();
};

extern thread_local ThreadLocalStore mTLS;
#endif

void Init(QueueIndex index = NoQueueIndex, Priority priority = Priority::Normal);

void Deinit();

inline QueueIndex GetQueueIndex()
{
#if ION_CONFIG_JOB_SCHEDULER
	return mTLS.mQueueIndex;
#else
	return 0;
#endif
}
inline BaseJob* GetCurrentJob()
{
#if ION_CONFIG_JOB_SCHEDULER
	return mTLS.mJob;
#else
	return nullptr;
#endif
}
#if ION_MEMORY_TRACKER
inline ion::MemTag& MemoryTag() { return Thread::mTLS.mMemoryTag; }
#endif

inline UInt GetId()
{
#if ION_CONFIG_JOB_SCHEDULER || ION_CONFIG_GLOBAL_MEMORY_POOL
	return mTLS.mId;
#else
	return 0;
#endif
}

#if ION_CONFIG_TEMPORARY_ALLOCATOR
ion::temporary::BytePool& InitTemporaryMemory();
#endif

#if ION_CONFIG_TEMPORARY_ALLOCATOR
inline ion::temporary::BytePool& GetTemporaryPool() { return mTLS.mTemporaryMemory ? *mTLS.mTemporaryMemory : InitTemporaryMemory(); }
#endif

bool IsReady();

bool IsThreadInitialized();

// TODO: Move to private
inline void SetCurrentJob([[maybe_unused]] BaseJob* const job)
{
#if ION_CONFIG_JOB_SCHEDULER
	ION_ASSERT(job == nullptr || mTLS.mJob != job ||
				 ion::Thread::GetQueueIndex() == ion::Thread::NoQueueIndex,	 // Companions can have same work recursively
			   "Job already set");
	mTLS.mJob = job;
#endif
}

#if ION_CONFIG_JOB_SCHEDULER
inline uint64_t* GetRandState()
{
	ION_ASSERT(mTLS.mRandState[0] != 0 && mTLS.mRandState[1] != 0, "Thread " << mTLS.mId << " not initialized");
	return mTLS.mRandState;
}
#else
uint64_t* GetRandState();
#endif

unsigned int GetFPControlWord();

#if ION_PROFILER_BUFFER_SIZE_PER_THREAD > 0
inline ProfilingBuffer& Profiling() { return *mTLS.mProfiling; }
inline bool IsProfilingEnabled() { return mTLS.mProfiling != nullptr; }
#endif

bool Sleep(int64_t usec);

bool SleepMs(int64_t ms);

int64_t MinSleepUsec();

static_assert(sizeof(ThreadLocalStore) <= 256, "TLS must have small size");

void YieldCPU();

void SetMainThreadPolicy();

void SetPriority(Priority priority);

void InitMain();

void DeinitMain();

void OnEngineRestart();

void InitInternal(QueueIndex index, Priority priority);

#if ION_THREAD_WAIT_AFTER_TERMINATE
ion::ThreadSynchronizer& Synchronizer();
#endif

Int ThreadPriority(ion::Thread::Priority priority);

Int GetSchedulingPolicy();

}  // namespace Thread

}  // namespace ion
