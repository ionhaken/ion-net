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

//
// Ion minimal include. This should be included, either directly or via Types.h, by all compilation units that have Ion includes.
//

#include "targetver.h"

#if defined(__pnacl__) || defined(__CLR_VER)
	#define ION_ARCH_VM
#else
	#if (defined(_M_IX86) || defined(__i386__))
		#define ION_ARCH_X86_32
		#define ION_ARCH_DATA_UNIT 4
	#endif
	#if (defined(_M_X64) || defined(__x86_64__))
		#define ION_ARCH_X86_64
		#define ION_ARCH_DATA_UNIT 8
	#endif

	#if defined(ION_ARCH_X86_32) || defined(ION_ARCH_X86_64)
		#define ION_ARCH_X86
	#endif
#endif

#if (defined(__arm__) || defined(_M_ARM))
	#define ION_ARCH_ARM_32
	#define ION_ARCH_DATA_UNIT 4
#endif

#if defined(__aarch64__)
	#define ION_ARCH_ARM_64
	#define ION_ARCH_DATA_UNIT 8
#endif

#if (defined(ION_ARCH_ARM_64) || defined(ION_ARCH_ARM_32))
	#define ION_ARCH_ARM
#endif

#if (defined(_WIN64) || defined(_WIN32))
	#define ION_PLATFORM_MICROSOFT 1
#else
	#define ION_PLATFORM_MICROSOFT 0
#endif

#if defined(__ANDROID__)
	#define ION_PLATFORM_ANDROID 1
#else
	#define ION_PLATFORM_ANDROID 0
#endif

#if defined(__linux__) && !defined(__ANDROID__)
	#define ION_PLATFORM_LINUX 1
#else
	#define ION_PLATFORM_LINUX 0
#endif

#if defined(__APPLE__)
	#define ION_PLATFORM_APPLE 1
#else
	#define ION_PLATFORM_APPLE 0
#endif

#if defined(__clang__)
	#define ION_COMPILER_CLANG 1
#else
	#define ION_COMPILER_CLANG 0
#endif

#ifdef _MSC_VER
	#define ION_COMPILER_MSVC 1
#else
	#define ION_COMPILER_MSVC 0
#endif

#if defined(__GNUC__) && !ION_COMPILER_CLANG
	#define ION_COMPILER_GNUC 1
#else
	#define ION_COMPILER_GNUC 0
#endif

#if ION_COMPILER_CLANG
	#pragma clang diagnostic ignored "-Wassume"
	#pragma clang diagnostic error "-Wundef"
#endif

#ifdef _DEBUG
	#define ION_BUILD_DEBUG 1
#else
	#define ION_BUILD_DEBUG 0
#endif

#ifdef _FINAL
	#define ION_BUILD_FINAL 1
#else
	#define ION_BUILD_FINAL 0
#endif

#ifdef _RETAIL
	#define ION_BUILD_RETAIL 1
#else
	#define ION_BUILD_RETAIL 0
#endif

#include <ion/Config.h>

#if ION_COMPILER_MSVC
	#define ION_PURE inline
	/* http://msdn.microsoft.com/en-us/library/dabb5z75%28v=vs.90%29.aspx
	 * (not as strict as GNU attr const, but more strict than GNU attr pure) */
	// noalias means that a function call does not modify or reference visible global state and
	// only modifies the memory pointed to directly by pointer parameters (first-level indirections).
	#define ION_NOALIAS __declspec(noalias)
#else
	#define ION_PURE			__attribute__((pure))
	#define ION_ATTRIBUTE_CONST __attribute__((const))
#endif

#if ION_COMPILER_MSVC
	#define ION_LIKELY(__cond)	 (__cond) [[likely]]
	#define ION_UNLIKELY(__cond) (__cond) [[unlikely]]
#else
	#define ION_LIKELY(__cond)	 (__builtin_expect(!!(__cond), 1))
	#define ION_UNLIKELY(__cond) (__builtin_expect(!!(__cond), 0))
#endif

#if ION_COMPILER_MSVC
	#define ION_ASSUME(__expr) __assume(__expr)
#else
	#define ION_ASSUME(__expr) __builtin_assume(__expr)
#endif

//
// Non copyable nor movable class
//

#define ION_CLASS_NON_ASSIGNABLE(T)    \
	void operator=(const T&) = delete; \
	void operator=(T&) = delete;

#define ION_CLASS_NON_COPYABLE(T) \
	ION_CLASS_NON_ASSIGNABLE(T)   \
	T(const T&) = delete;         \
	T(T&) = delete;

#define ION_CLASS_NON_COPYABLE_NOR_MOVABLE(T) \
	ION_CLASS_NON_COPYABLE(T)                 \
	void operator=(const T&&) = delete;       \
	void operator=(T&&) = delete;             \
	T(const T&&) = delete;                    \
	T(T&&) = delete;

#define ION_INLINE __inline // Inlining hint
#if ION_PLATFORM_MICROSOFT
	#define ION_FORCE_INLINE __forceinline
	#define ION_NO_INLINE	 __declspec(noinline)
#else
	#define ION_FORCE_INLINE __attribute__((always_inline)) inline
	#define ION_NO_INLINE __attribute__ ((noinline))
#endif
#if ION_CONFIG_PLATFORM_WRAPPERS == 1
	#define ION_PLATFORM_INLINING ION_FORCE_INLINE
#else
	#define ION_PLATFORM_INLINING
#endif

#define ION_CONCATENATE_DIRECT(s1, s2) s1##s2
#define ION_STRINGIFY(__str)		   #__str
#define ION_CONCATENATE(s1, s2)		   ION_CONCATENATE_DIRECT(s1, s2)
#if ION_PLATFORM_MICROSOFT  // Necessary for edit & continue in MS Visual C++.
	#define ION_ANONYMOUS_VARIABLE(str) ION_CONCATENATE(str, __COUNTER__)
#else
	#define ION_ANONYMOUS_VARIABLE(str) ION_CONCATENATE(str, __LINE__)
#endif

#define ION_ALIGN(x) alignas(x)
#define ION_ALIGN_CACHE_LINE ION_ALIGN(ION_CONFIG_CACHE_LINE_SIZE)

#if ION_COMPILER_CLANG || defined(__GNUC__)
	#define ION_ATTRIBUTE_MALLOC __attribute__((__malloc__))
	#define ION_RESTRICT_RETURN_VALUE
#elif ION_COMPILER_MSVC
	#define ION_ATTRIBUTE_MALLOC
	#define ION_RESTRICT_RETURN_VALUE __declspec(restrict)
#else
	#define ION_ATTRIBUTE_MALLOC
	#define ION_RESTRICT_RETURN_VALUE
#endif
#define ION_RESTRICT __restrict

#if defined(__cpp_exceptions) && (__cpp_exceptions == 1)
	#define ION_EXCEPTIONS_ENABLED 1
#else
	#define ION_EXCEPTIONS_ENABLED 0
#endif

#if __cplusplus > 201703L
	#define ION_CONSTEVAL consteval
#else
	#define ION_CONSTEVAL constexpr
#endif

#if ION_CONFIG_DEV_TOOLS
	#define ION_PRAGMA_OPTIMIZE_OFF __pragma(optimize("", off))
#else
	#define ION_PRAGMA_OPTIMIZE_OFF please_remove_optimize_off
#endif
#if ION_COMPILER_MSVC
	#define ION_PRAGMA_WRN_PUSH								   __pragma(warning(push))
	#define ION_PRAGMA_WRN_IGNORE_SIGNED_UNSIGNED_MISMATCH	   __pragma(warning(disable : 4389))
	#define ION_PRAGMA_WRN_IGNORE_CONVERSION_LOSS_OF_DATA	   __pragma(warning(disable : 4244))
	#define ION_PRAGMA_WRN_IGNORE_UNARY_MINUS_TO_UNSIGNED_TYPE __pragma(warning(disable : 4146))
	#define ION_PRAGMA_WRN_IGNORE_UNREACHABLE_CODE			   __pragma(warning(disable : 4702))
	#define ION_PRAGMA_WRN_POP								   __pragma(warning(pop))
#else
	#define ION_PRAGMA_WRN_PUSH _Pragma("clang diagnostic push")
	#define ION_PRAGMA_WRN_IGNORE_SIGNED_UNSIGNED_MISMATCH
	#define ION_PRAGMA_WRN_IGNORE_CONVERSION_LOSS_OF_DATA
	#define ION_PRAGMA_WRN_IGNORE_UNARY_MINUS_TO_UNSIGNED_TYPE
	#define ION_PRAGMA_WRN_IGNORE_UNREACHABLE_CODE
	#define ION_PRAGMA_WRN_POP _Pragma("clang diagnostic pop")
#endif

#if ION_COMPILER_MSVC
	#define ION_SECTION_PUSH		 __pragma(code_seg(push)) __pragma(data_seg(push)) __pragma(const_seg(push)) __pragma(bss_seg(push))
	#define ION_SECTION_POP			 __pragma(code_seg(pop)) __pragma(data_seg(pop)) __pragma(const_seg(pop)) __pragma(bss_seg(pop))
	#define ION_CODE_SECTION(__name) ION_SECTION_PUSH __pragma(code_seg(__name))
	#define ION_SECTION_END			 ION_SECTION_POP
#else
	#define ION_CODE_SECTION(__name) __attribute__((section(__name)))
	#define ION_SECTION_END
#endif

#if ION_PLATFORM_ANDROID  // Android logging does not need line breaks
	#define ION_LOG_FMT_IMMEDIATE_CALL(__type, __format, ...) ion::tracing::PrintFormatted(__type, __format, __VA_ARGS__);
	#define ION_LOG_IMMEDIATE_CALL(__type, __format)		  ion::tracing::Print(__type, __format);
#elif ION_PLATFORM_LINUX
	#define ION_LOG_FMT_IMMEDIATE_CALL(__type, __format, ...) ion::tracing::PrintFormatted(__type, __format "\n", __VA_ARGS__);
	#define ION_LOG_IMMEDIATE_CALL(__type, __format)		  ion::tracing::PrintFormatted(__type, __format "\n");
#else
	#define ION_LOG_FMT_IMMEDIATE_CALL(__type, __format, ...) ion::tracing::PrintFormatted(__type, __format##"\n", __VA_ARGS__);
	#define ION_LOG_IMMEDIATE_CALL(__type, __format)		  ion::tracing::Print(__type, __format##"\n");
#endif

#ifndef ION_NONSTATIC
	#define ION_EXPORT
#else
	#if ION_PLATFORM_MICROSOFT
		#ifdef ION_DLL_EXPORT
			#define ION_EXPORT __declspec(dllexport)
		#else
			#define ION_EXPORT __declspec(dllimport)
		#endif
	#else
		#define ION_EXPORT __attribute__((visibility("default")))
	#endif
#endif
