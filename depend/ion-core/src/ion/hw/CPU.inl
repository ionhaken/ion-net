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
	#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_I86))
		#include <mmintrin.h>
	#endif

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
inline void Yield()
{
#if ION_PLATFORM_MICROSOFT
	SwitchToThread();
#else
	sched_yield();
#endif
}

// The PAUSE instruction is x86 specific. It's sole use is in spin-lock wait loops
inline void RelaxCPU()
{
#if ION_PLATFORM_MICROSOFT
	YieldProcessor();  //_mm_pause();
#elif ION_PLATFORM_ANDROID
	sched_yield();	// #TODO: sched_yield() does not work in multicore
#else
	asm("pause");
#endif
}

inline void Nop()
{
#if ION_PLATFORM_MICROSOFT
	__nop();
#else
	asm("nop");
#endif
}

inline void PreFetchL1(const void* ptr)
{
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_I86))
	_mm_prefetch((const char*)(ptr), _MM_HINT_T0);
#elif defined(__GNUC__) && ((__GNUC__ >= 4) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1)))
	__builtin_prefetch((ptr), 0 /* rw==read */, 3 /* locality */);
#elif defined(ION_ARCH_ARM_64)
	__asm__ __volatile__("prfm PLDL1KEEP, %0" ::"Q"(*(ptr)))
#else
	(void)(ptr);
#endif
}

inline void PreFetchL2(const void* ptr)
{
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_I86))
	_mm_prefetch((const char*)(ptr), _MM_HINT_T1);
#elif defined(__GNUC__) && ((__GNUC__ >= 4) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1)))
	__builtin_prefetch((ptr), 0 /* read */, 2 /* locality */);
#elif defined(ION_ARCH_ARM_64)
	__asm__ __volatile__("prfm PLDL2KEEP, %0" ::"Q"(*(ptr)))
#else
	(void)(ptr);
#endif
}

inline void PreFetchL1ForWrite(const void* ptr)
{
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_I86))
	_m_prefetchw(ptr);
#elif defined(__GNUC__) && ((__GNUC__ >= 4) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1)))
	__builtin_prefetch(ptr, 1 /* write */, 3 /* locality */);
#elif defined(ION_ARCH_ARM_64)
	__asm__ __volatile__("prfm PSTL1STRM, %0" ::"Q"(*(ptr)))
#else
	(void)(ptr);
#endif
}

};	// namespace platform
}  // namespace ion
