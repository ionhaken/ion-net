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

// No include guard - include only via Base.h

// ----------------------------------------------------------------------------------------------------------
// Ion library configuration
// ----------------------------------------------------------------------------------------------------------

// Please check below for specifics. Released products should set ION_CONFIG_ERROR_CHECKING=0 and ION_CONFIG_DEV_TOOLS=0

// ----------------------------------------------------------------------------------------------------------
// General Settings
// ----------------------------------------------------------------------------------------------------------

// Controls error checking and memory leak detection.
#ifndef ION_CONFIG_ERROR_CHECKING
	#ifdef _RETAIL
		#define ION_CONFIG_ERROR_CHECKING 0
	#else
		#define ION_CONFIG_ERROR_CHECKING 1
	#endif
#endif

// Controls development tools.
#ifndef ION_CONFIG_DEV_TOOLS
	#ifdef _FINAL
		#define ION_CONFIG_DEV_TOOLS 0
	#else
		#define ION_CONFIG_DEV_TOOLS 1
	#endif
#endif

// Maximum size of contiguous memory to promote true sharing
#ifndef ION_CONFIG_CACHE_LINE_SIZE
	#define ION_CONFIG_CACHE_LINE_SIZE 64
#endif

// Minimum offset between two objects to avoid false sharing
#ifndef ION_CONFIG_SAFE_CACHE_LINE_SIZE
	#define ION_CONFIG_SAFE_CACHE_LINE_SIZE 64
#endif

// Faster but less precise math
#ifndef ION_CONFIG_FAST_MATH
	#define ION_CONFIG_FAST_MATH 0
#endif

// ----------------------------------------------------------------------------------------------------------
// Ion Features
// ----------------------------------------------------------------------------------------------------------

// Enables memory arena resources. To get accurate MSVC memory diagnostics you should disable this, ION_CONFIG_GLOBAL_MEMORY_POOL and
// ION_CONFIG_TEMPORARY_ALLOCATOR as both features store blocks to their own memory pages.
#ifndef ION_CONFIG_MEMORY_RESOURCES
	#ifndef __SANITIZE_ADDRESS__
		#define ION_CONFIG_MEMORY_RESOURCES 1
	#else
		#define ION_CONFIG_MEMORY_RESOURCES 0
	#endif
#endif

// Enables thread-local temporary memory allocator
#ifndef ION_CONFIG_TEMPORARY_ALLOCATOR
	#ifndef __SANITIZE_ADDRESS__
		#define ION_CONFIG_TEMPORARY_ALLOCATOR 1
	#else
		#define ION_CONFIG_TEMPORARY_ALLOCATOR 0
	#endif
#endif

// Enables global memory pool
#ifndef ION_CONFIG_GLOBAL_MEMORY_POOL
	#ifndef __SANITIZE_ADDRESS__
		#define ION_CONFIG_GLOBAL_MEMORY_POOL 1
	#else
		#define ION_CONFIG_GLOBAL_MEMORY_POOL 0
	#endif
#endif

// Enables Job Scheduler
#ifndef ION_CONFIG_JOB_SCHEDULER
	#define ION_CONFIG_JOB_SCHEDULER 1
#endif

// Enable to disable platform type compile time optimization by making platform wrappers non-opaque.
// Experimental: Enabling does not currently seem to give performance benefits.
#ifndef ION_CONFIG_PLATFORM_WRAPPERS
	#define ION_CONFIG_PLATFORM_WRAPPERS 0
#endif

// Real value is implemented as a fixed-point to enforce cross platform determinism
#ifndef ION_CONFIG_REAL_IS_FIXED_POINT
	#define ION_CONFIG_REAL_IS_FIXED_POINT 0
#endif

// ----------------------------------------------------------------------------------------------------------
// External code with license requirements
// ----------------------------------------------------------------------------------------------------------
// Please check that the respective licenses are suitable for your needs

// CPU features - Assuming Avx/Neon support if disabled
#ifndef ION_EXTERNAL_CPU_INFO
	#define ION_EXTERNAL_CPU_INFO 1
#endif

// xxHash - Use STL if disabled
#ifndef ION_EXTERNAL_HASH
	#define ION_EXTERNAL_HASH 1
#endif

// RapidJSON - No JSON support if disabled
#ifndef ION_EXTERNAL_JSON
	#define ION_EXTERNAL_JSON 1
#endif

// TSLF - No TLSF if disabled
#ifndef ION_EXTERNAL_MEMORY_POOL
	#define ION_EXTERNAL_MEMORY_POOL 1
#endif

// https://github.com/cameron314/concurrentqueue - MPMC queue uses locks if disabled
#ifndef ION_EXTERNAL_MPMC_QUEUE
	#define ION_EXTERNAL_MPMC_QUEUE 1
#endif

// XSIMD used for batch types internally
#ifndef ION_EXTERNAL_SIMD
	#if ION_COMPILER_CLANG
		// Using Clang, batched types are faster without XSIMD when -Ofast is enabled
		#define ION_EXTERNAL_SIMD 0
	#else
		#define ION_EXTERNAL_SIMD 1
	#endif
#endif

// https://github.com/cameron314/readerwriterqueue - SPSC queue has locks if disabled
#ifndef ION_EXTERNAL_SPSC_QUEUE
	#define ION_EXTERNAL_SPSC_QUEUE 1
#endif

// jeaiii/itoa - Use sprintf for string conversions if disabled
#ifndef ION_EXTERNAL_STRING_CONVERSIONS
	#define ION_EXTERNAL_STRING_CONVERSIONS 1
#endif

#ifndef ION_EXTERNAL_UNORDERED_MAP
	#define ION_EXTERNAL_UNORDERED_MAP 0
#endif

// ----------------------------------------------------------------------------------------------------------
// Error checking
// ----------------------------------------------------------------------------------------------------------

#ifndef ION_ASSERTS_ENABLED
	#define ION_ASSERTS_ENABLED ION_CONFIG_ERROR_CHECKING
#endif

// Abort on failure, otherwise silently ignoring errors. Fatal errors (ION_CHECK_FATAL) will abort execution in any case
#ifndef ION_ABORT_ON_FAILURE
	#define ION_ABORT_ON_FAILURE ION_CONFIG_ERROR_CHECKING
#endif

// Enable output to debug console
#ifndef ION_DEBUGGER_OUTPUT
	#if ION_PLATFORM_MICROSOFT
		#define ION_DEBUGGER_OUTPUT ION_CONFIG_ERROR_CHECKING
	#else
		#define ION_DEBUGGER_OUTPUT 0
	#endif
#endif

// Show file names and line numbers in logs
#ifndef ION_DEBUG_LOG_FILE
	#define ION_DEBUG_LOG_FILE ION_CONFIG_ERROR_CHECKING
#endif

// Enables memory leak tracking
#ifndef ION_MEMORY_TRACKER
	#define ION_MEMORY_TRACKER ION_CONFIG_ERROR_CHECKING
#endif

// Clean exit expects program to be correctly destructed before exit.
// Otherwise program will assume it can exit early without full destruction.
#ifndef ION_CLEAN_EXIT
	#define ION_CLEAN_EXIT ION_CONFIG_ERROR_CHECKING
#endif

// ----------------------------------------------------------------------------------------------------------
// Dev tools
// ----------------------------------------------------------------------------------------------------------

// Profiling
#ifndef ION_PROFILER_BUFFER_SIZE_PER_THREAD
	#if ION_CONFIG_DEV_TOOLS && ION_EXTERNAL_JSON && ION_CONFIG_JOB_SCHEDULER
		#if ION_PLATFORM_ANDROID
			#define ION_PROFILER_BUFFER_SIZE_PER_THREAD 32 * 1024
		#else
			#define ION_PROFILER_BUFFER_SIZE_PER_THREAD 128 * 1024
		#endif
	#else
		#define ION_PROFILER_BUFFER_SIZE_PER_THREAD 0
	#endif
#endif

// Command line configurable parameters aka tweakables. Disabling will hardcode all tweakable values.
#ifndef ION_TWEAKABLES
	#define ION_TWEAKABLES ION_CONFIG_DEV_TOOLS
#endif

// Enables mutex contetion checker support
#ifndef ION_MUTEX_CONTENTION_CHECKER
	#define ION_MUTEX_CONTENTION_CHECKER ION_CONFIG_DEV_TOOLS
#endif

// ----------------------------------------------------------------------------------------------------------
// Other utils
// ----------------------------------------------------------------------------------------------------------

// Logging level.
#ifndef ION_DEBUG_LOG_ENABLED
	#define ION_DEBUG_LOG_ENABLED ION_BUILD_DEBUG
#endif

// Job statistics
#ifndef ION_JOB_STATS
	#define ION_JOB_STATS 0
#endif

// ----------------------------------------------------------------------------------------------------------
// Config validation
// ----------------------------------------------------------------------------------------------------------

#if ION_BUILD_DEBUG
	#ifdef NDEBUG
		#error Debug configuration has no-debug enabled.
	#endif
#else
	#ifndef NDEBUG
		#error No-debug configuration does not have no-debug enabled.
	#endif
#endif

#if ION_BUILD_FINAL || ION_BUILD_RETAIL
	#if ION_BUILD_DEBUG
		#error Retail/Final configuration has debug enabled
	#endif
#endif

#if (ION_PLATFORM_MICROSOFT + ION_PLATFORM_LINUX + ION_PLATFORM_ANDROID + ION_PLATFORM_APPLE) != 1
	#error Unknown target platform
#endif

#if (ION_COMPILER_MSVC + ION_COMPILER_CLANG + ION_COMPILER_GNUC) != 1
	#error Unknown compiler
#endif
