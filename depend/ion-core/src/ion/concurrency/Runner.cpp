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
#include <ion/concurrency/Runner.h>

#include <ion/hw/CPU.inl>
#include <ion/string/String.h>
#include <ion/util/OsInfo.h>

namespace ion
{

#if ION_PLATFORM_MICROSOFT
using ThreadHandleType = HANDLE;
#else
struct ThreadHandleType
{
	pthread_t thread;
};
#endif

class ThreadWrapper
{
public:
#if ION_PLATFORM_MICROSOFT
	static unsigned long __stdcall Routine(void* pThread)
#else
	static void* Routine(void* pThread)
#endif
	{
		ion::Runner* self = reinterpret_cast<ion::Runner*>(pThread);
		ION_ASSERT(self->mState != Runner::State::Terminated, "Already terminated");
		Thread::Init(self->mIndex, self->mPriority);
		self->mFunction();
		Thread::Deinit();
		self->Stop();
		return 0;
	}
};

void Runner::InitThread() { ThreadHandleWrapper::Proxy<ThreadHandleType>::Init(mHandle); }

Runner::Runner(Runner&& other) noexcept
  : mFunction(std::move(other.mFunction)), mIndex(other.mIndex), mPriority(other.mPriority), mState(Runner::State(other.mState))
{
	mHandle.Ref<ThreadHandleType>() = std::move(other.mHandle.Ref<ThreadHandleType>());
	other.mState = Runner::State::Terminated;
#if ION_PLATFORM_MICROSOFT
	other.mHandle.Ref<ThreadHandleType>() = nullptr;
#else
	other.mHandle.Ref<ThreadHandleType>().thread = pthread_t();
#endif
}

bool Runner::Start(size_t stackSize, Thread::Priority priority, Thread::QueueIndex index)
{
	ION_ASSERT(stackSize >= Thread::MaxThreadLocalStoreSize + (8 * 1024) && stackSize >= Thread::MinimumStackSize,
			   "Stack size below recommended size");
	ION_ASSERT(mState == Runner::State::Terminated, "Thread was already started");
	mState = Runner::State::Running;
	mPriority = priority;
	mIndex = index;
	stackSize = stackSize + (stackSize % ion::OsMemoryPageSize());

#if ION_PLATFORM_MICROSOFT
	mHandle.Ref<ThreadHandleType>() = ::CreateThread(nullptr, stackSize, ion::ThreadWrapper::Routine, this, CREATE_SUSPENDED, nullptr);
	if (mHandle.Ref<ThreadHandleType>() == nullptr)
	{
		ION_ABNORMAL("Cannot start thread: " << ion::debug::GetLastErrorString());
		mState = Runner::State::Terminated;
		return false;
	}
	[[maybe_unused]] auto res = ::ResumeThread(mHandle.Ref<ThreadHandleType>());
	ION_ASSERT(res, "Thread resume failed " << ion::debug::GetLastErrorString());
	return true;
#else
	pthread_attr_t attr;
	pthread_attr_init(&attr);

	int res = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	ION_ASSERT_FMT_IMMEDIATE(res == 0, "Invalid detach state");

	ION_ASSERT_FMT_IMMEDIATE(stackSize >= PTHREAD_STACK_MIN * 2, "Stack size is too small");
	res = pthread_attr_setstacksize(&attr, stackSize);
	ION_ASSERT_FMT_IMMEDIATE(res == 0, "Invalid stack szie");

	// res = pthread_attr_setstack(&attr, sp, stack_size); // #TODO: Set stack address

	#if ION_THREAD_USE_SCHEDULING_POLICY
	res = pthread_attr_setschedpolicy(&attr, ion::Thread::GetSchedulingPolicy());
	ION_ASSERT_FMT_IMMEDIATE(res == 0, "Invalid scheduling policy");

	sched_param param;
	param.sched_priority = ion::Thread::ThreadPriority(priority);
	res = pthread_attr_setschedparam(&attr, &param);
	ION_ASSERT_FMT_IMMEDIATE(res == 0, "Invalid scheduling params");

	// PTHREAD_EXPLICIT_SCHED = Take scheduling attributes from the values specified by the attributes object.
	res = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
	ION_ASSERT_FMT_IMMEDIATE(res == 0, "Invalid scheduling");
	#endif

	bool isSuccess = true;
	int ret = pthread_create(&mHandle.Ref<ThreadHandleType>().thread, &attr, ion::ThreadWrapper::Routine, this);
	if (ret != 0)
	{
		isSuccess = false;
		ION_ABNORMAL("Cannot start thead: " << strerror(ret));
		mState = Runner::State::Terminated;
	}
	res = pthread_attr_destroy(&attr);
	ION_ASSERT_FMT_IMMEDIATE(res == 0, "pthread_attr_destroy failed:" << res);
	return isSuccess;
#endif
}

void Runner::Join()
{
#if !ION_PLATFORM_MICROSOFT
	void* threadStatus = nullptr;
	int err = pthread_join(mHandle.Ref<ThreadHandleType>().thread, &threadStatus);
	ION_ASSERT(err, "pthread join failed:" << err);
#endif

#if ION_THREAD_WAIT_AFTER_TERMINATE
	mState = State::Joined;
	{
		AutoLock<ThreadSynchronizer> lock(ion::Thread::Synchronizer());
		lock.NotifyAll();
		lock.UnlockAndWaitFor([&]() { return mState == Runner::State::Terminated; });
	}
#endif

#if ION_PLATFORM_MICROSOFT
	[[maybe_unused]] auto waitResult = WaitForSingleObject(mHandle.Ref<ThreadHandleType>(), INFINITE);
	ION_ASSERT(waitResult != (DWORD)0xFFFFFFFF, "Wait failed:" << ion::debug::GetLastErrorString());
	ION_ASSERT(mState == Runner::State::Terminated, "Thread has not finished");
	[[maybe_unused]] auto res = CloseHandle(mHandle.Ref<ThreadHandleType>());
	ION_ASSERT(res, "Thread close failed:" << ion::debug::GetLastErrorString());
	mHandle.Ref<ThreadHandleType>() = nullptr;
#endif
	ION_ASSERT(mState == Runner::State::Terminated, "Thread has not finished");
}

void Runner::Stop()
{
#if ION_THREAD_WAIT_AFTER_TERMINATE
	AutoLock<ThreadSynchronizer> lock(ion::Thread::Synchronizer());
	lock.UnlockAndWaitFor([&]() { return mState == Runner::State::Joined; });
#endif

	mState = Runner::State::Terminated;

#if ION_THREAD_WAIT_AFTER_TERMINATE
	lock.NotifyAll();
#endif
}

Runner::~Runner()
{
	ION_ASSERT(mState == Runner::State::Terminated, "Thread not terminated properly");
#if ION_PLATFORM_MICROSOFT
	ION_ASSERT(mHandle.Ref<ThreadHandleType>() == nullptr, "Thread not deleted");
#endif
}

}  // namespace ion
