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

struct ThreadLocalStore
{
	ThreadLocalStore();
	BaseJob* mJob = nullptr;
#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1
	ion::temporary::BytePool* mTemporaryMemory = nullptr;
#endif
	uint64_t mRandState[2] = {0};
	UInt mId = ~static_cast<UInt>(0);
	QueueIndex mQueueIndex = 0;

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

void Init(QueueIndex index = NoQueueIndex, Priority priority = Priority::Normal);

void Deinit();

inline QueueIndex GetQueueIndex() { return mTLS.mQueueIndex; }
inline BaseJob* GetCurrentJob() { return mTLS.mJob; }
#if ION_MEMORY_TRACKER
inline ion::MemTag& MemoryTag() { return Thread::mTLS.mMemoryTag; }
#endif

inline UInt GetId() { return mTLS.mId; }

#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1
ion::temporary::BytePool& InitTemporaryMemory();
#endif

#if ION_CONFIG_TEMPORARY_ALLOCATOR == 1
inline ion::temporary::BytePool& GetTemporaryPool() { return mTLS.mTemporaryMemory ? *mTLS.mTemporaryMemory : InitTemporaryMemory(); }
#endif

bool IsReady();

// TODO: Move to private
inline void SetCurrentJob(BaseJob* const job)
{
	ION_ASSERT(job == nullptr || mTLS.mJob != job, "Job already set");
	mTLS.mJob = job;
}

inline uint64_t* GetRandState()
{
	ION_ASSERT(mTLS.mRandState[0] != 0 && mTLS.mRandState[1] != 0, "Thread " << mTLS.mId << " not initialized");
	return mTLS.mRandState;
}

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

void InitThreadIdPool();

#if ION_THREAD_WAIT_AFTER_TERMINATE
ion::ThreadSynchronizer& Synchronizer();
#endif

Int ThreadPriority(ion::Thread::Priority priority);

Int GetSchedulingPolicy();

}  // namespace Thread

}  // namespace ion
