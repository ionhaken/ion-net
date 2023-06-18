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
#include <ion/concurrency/Mutex.h>
#include <ion/concurrency/ThreadSynchronization.inl>
#if ION_CONFIG_PLATFORM_WRAPPERS == 0
	#include <ion/concurrency/Mutex.inl>
#endif

namespace ion
{
Mutex::Mutex()
{
	MutexWrapper::Proxy<MutexType>::Construct(mMutex);
#if ION_PLATFORM_MICROSOFT
	InitializeSRWLock(mMutex.Ptr<MutexType>());
#else
	auto& mutex = mMutex.Ptr<MutexType>()->mutex;
	pthread_mutexattr_t attr;
	int res = pthread_mutexattr_init(&attr);
	ION_ASSERT(res == 0, "pthread_mutexattr_init - failed");

	res = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
	ION_ASSERT(res == 0, "pthread_mutexattr_settype - failed");

	res = pthread_mutex_init(&mutex, &attr);
	ION_ASSERT(res == 0, "pthread_mutex_init - failed");

	res = pthread_mutexattr_destroy(&attr);
	ION_ASSERT(res == 0, "pthread_mutexattr_destroy - failed");
#endif
}

Mutex::~Mutex()
{
#if ION_PLATFORM_MICROSOFT
#else
	auto& mutex = mMutex.Ptr<MutexType>()->mutex;
	int res = pthread_mutex_destroy(&mutex);
	ION_ASSERT(res == 0, "pthread_mutex_destroy - failed");
#endif
	MutexWrapper::Proxy<MutexType>::Destroy(mMutex);
}

SharedMutex::SharedMutex()
{
	SharedMutexWrapper::Proxy<SharedMutexType>::Construct(mMutex);
#if ION_PLATFORM_MICROSOFT
	InitializeSRWLock(mMutex.Ptr<SharedMutexType>());
#else
	auto& mutex = mMutex.Ptr<SharedMutexType>()->mutex;
	pthread_rwlockattr_t attr;
	int res = pthread_rwlockattr_init(&attr);
	ION_ASSERT(res == 0, "pthread_rwlockattr_init - failed");

	res = pthread_rwlock_init(&mutex, &attr);
	ION_ASSERT(res == 0, "pthread_rwlock_init - failed");
#endif
}

SharedMutex::~SharedMutex()
{
#if ION_PLATFORM_MICROSOFT
#else
	auto& mutex = mMutex.Ptr<SharedMutexType>()->mutex;
	int res = pthread_rwlock_destroy(&mutex);
	ION_ASSERT(res == 0, "pthread_rwlock_destroy - failed");
#endif
	SharedMutexWrapper::Proxy<SharedMutexType>::Destroy(mMutex);
}

}  // namespace ion
