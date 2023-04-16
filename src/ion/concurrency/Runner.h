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
#include <ion/container/ObjectWrapper.h>
// FIXME: Move these to thread synchronization. Correct debug.cpp
#include <ion/util/InplaceFunction.h>
#include <atomic>

#if ION_THREAD_WAIT_AFTER_TERMINATE
	#include <ion/concurrency/ThreadSynchronizer.h>
#endif

namespace ion
{
	class Runner
{
	friend class Engine;
	friend class ThreadWrapper;
	template <class T>
	std::decay_t<T> decay_copy(T&& v)
	{
		return std::forward<T>(v);
	}

public:

	using id = uint64_t;

	friend class TaskQueue;
	friend class BaseJob;

	ION_CLASS_NON_COPYABLE(Runner);

	Runner(Runner&& thread) noexcept;

	template <typename Func>
	Runner(Func&& func) : mFunction(std::forward<decltype(func)>(func)), mState(Runner::State::Terminated)
	{
		InitThread();
	}

	template <typename Func>
	void SetEntryPoint(Func&& func)
	{
		mFunction = std::move(func);
	}

	~Runner();

	using EntryPoint = ion::InplaceFunction<void(), 64, 16>;

	bool Start(size_t stackSize = Thread::DefaultStackSize, Thread::Priority priority = Thread::Priority::Normal,
			   Thread::QueueIndex index = Thread::NoQueueIndex);

	void Join();

private:
	void Stop();

	void InitThread();

	EntryPoint mFunction;

#if ION_PLATFORM_MICROSOFT
	#if defined(ION_ARCH_X86_64)
	using ThreadHandleWrapper = ObjectWrapper<8, 8>;
	#else
	using ThreadHandleWrapper = ObjectWrapper<4, 4>;
	#endif
#else
	#if defined(ION_ARCH_ARM_64) || defined(ION_ARCH_X86_64)
	using ThreadHandleWrapper = ObjectWrapper<8, 8>;
	#else
	using ThreadHandleWrapper = ObjectWrapper<4, 4>;
	#endif
#endif

	ThreadHandleWrapper mHandle;

	Thread::QueueIndex mIndex;
	Thread::Priority mPriority;
	enum class State : uint8_t
	{
		Terminated,
		Running,
		Joined
	};
	std::atomic<State> mState;
};

}  // namespace ion
