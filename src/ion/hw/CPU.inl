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
#include <ion/Base.h>

// Include CPU.inl only from cpp files to keep compile times small
#if ION_PLATFORM_MICROSOFT
	#ifndef WIN32_LEAN_AND_MEAN
		#define WIN32_LEAN_AND_MEAN
	#endif
	#define NOLIMITS
	#define NOMINMAX
	#include <Windows.h>
	#undef Yield
	#include <intrin.h>
#else
	#include <sched.h>
	#include <pthread.h>
	#if ION_PLATFORM_ANDROID
		#include <errno.h>

	#endif
	#include <sys/resource.h>
#endif

namespace ion
{
namespace platform
{
static inline void Yield()
{
#if ION_PLATFORM_MICROSOFT
	SwitchToThread();
#else
	sched_yield();
#endif
}

// The PAUSE instruction is x86 specific. It's sole use is in spin-lock wait loops
static inline void RelaxCPU()
{
#if ION_PLATFORM_MICROSOFT
	YieldProcessor();  //_mm_pause();
#elif ION_PLATFORM_ANDROID
	sched_yield();	// #TODO: sched_yield() does not work in multicore
#else
	asm("pause");
#endif
}

static inline void Nop()
{
#if ION_PLATFORM_MICROSOFT
	__nop();
#else
	asm("nop");
#endif
}

enum PreFetchLocality : int
{
	None,
	Level1,
	Level2,
	Level3
};

template <PreFetchLocality locality>
static void PreFetch(const void* addr)
{
#if ION_PLATFORM_MICROSOFT
	PreFetchCacheLine(0, addr);
#else
	__builtin_prefetch(addr, 0, locality);
#endif
}

static inline void PreFetchForWrite(const void* addr)
{
#if ION_PLATFORM_MICROSOFT
	_m_prefetchw(addr);
#else
	__builtin_prefetch(addr, 1);
#endif
}
};	// namespace platform
}  // namespace ion
