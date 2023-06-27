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
#include <ion/hw/CPU.inl>
#if ION_PLATFORM_LINUX
	#include <errno.h>
#endif

namespace ion
{
#if ION_PLATFORM_MICROSOFT
using MutexType = SRWLOCK;
using SharedMutexType = SRWLOCK;
using ConditionVariableType = CONDITION_VARIABLE;
#else
struct MutexType
{
	pthread_mutex_t mutex;
};
struct SharedMutexType
{
	pthread_rwlock_t mutex;
};
struct ConditionVariableType
{
	pthread_cond_t cond;
};
#endif
}  // namespace ion
