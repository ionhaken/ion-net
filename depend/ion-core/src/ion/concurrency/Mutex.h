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
#include <ion/concurrency/AutoLock.h>
#include <ion/container/ObjectWrapper.h>
#if ION_CONFIG_PLATFORM_WRAPPERS == 1
	#include <ion/concurrency/ThreadSynchronization.inl>
#endif

namespace ion
{
class ION_ALIGN(ION_ARCH_DATA_UNIT) Mutex
{
	friend class MutexWrapper;
	friend class SharedMutex;

public:
	Mutex();

	~Mutex();

	ION_PLATFORM_INLINING void Lock() const;

	ION_PLATFORM_INLINING bool TryLock() const;

	ION_PLATFORM_INLINING void Unlock() const;

protected:
#if ION_CONFIG_PLATFORM_WRAPPERS == 1
	using MutexWrapper = ObjectWrapperInline<MutexType>;
#elif ION_PLATFORM_MICROSOFT
	#if defined(ION_ARCH_ARM_64) || defined(ION_ARCH_X86_64)
	using MutexWrapper = ObjectWrapper<8, ION_ARCH_DATA_UNIT>;
	#else
	using MutexWrapper = ObjectWrapper<4, ION_ARCH_DATA_UNIT>;
	#endif
#else
	#if defined(ION_ARCH_ARM_64) || defined(ION_ARCH_X86_64)
		#if ION_PLATFORM_LINUX
	using MutexWrapper = ObjectWrapper<40, 8>;
		#else
	using MutexWrapper = ObjectWrapper<40, 4>;
		#endif
	#else
	using MutexWrapper = ObjectWrapper<4, 4>;
	#endif
#endif
	mutable MutexWrapper mMutex;
};

class ION_ALIGN(ION_ARCH_DATA_UNIT) SharedMutex
{
	friend class SharedMutexWrapper;

public:
	SharedMutex();

	~SharedMutex();

	ION_PLATFORM_INLINING void LockReadOnly() const;

	ION_PLATFORM_INLINING bool TryLockReadOnly() const;

	ION_PLATFORM_INLINING void UnlockReadOnly() const;

private:
#if ION_CONFIG_PLATFORM_WRAPPERS == 1
	using SharedMutexWrapper = ObjectWrapperInline<SharedMutexType>;
#elif ION_PLATFORM_MICROSOFT
	#if defined(ION_ARCH_ARM_64) || defined(ION_ARCH_X86_64)
	using SharedMutexWrapper = ObjectWrapper<8, ION_ARCH_DATA_UNIT>;
	#else
	using SharedMutexWrapper = ObjectWrapper<4, ION_ARCH_DATA_UNIT>;
	#endif
#else
	#if defined(ION_ARCH_ARM_64) || defined(ION_ARCH_X86_64)
		#if ION_PLATFORM_LINUX
	using SharedMutexWrapper = ObjectWrapper<56, 8>; // #TODO: Replace with pointer to shared array of mutexes
		#else
	using SharedMutexWrapper = ObjectWrapper<56, 4>;
		#endif
	#else
	using SharedMutexWrapper = ObjectWrapper<40, 4>;
	#endif
#endif
	mutable SharedMutexWrapper mMutex;
};

}  // namespace ion

#if ION_CONFIG_PLATFORM_WRAPPERS == 1
	#include <ion/concurrency/Mutex.inl>
#endif
