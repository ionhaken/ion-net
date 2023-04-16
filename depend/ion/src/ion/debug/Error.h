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

#include <ion/tracing/Tracing.h>

namespace ion
{
class String;
}
namespace ion::debug
{
bool IsDebugging();
void FatalErrorHandler();
ion::String GetLastErrorString();
#if (ION_ABORT_ON_FAILURE == 1)
bool IsErrorDebugBreak();
void HiddenDebugBreak();
bool IsBreakingOnAbnormalError();
#endif
}  // namespace ion::debug
#if (ION_ABORT_ON_FAILURE == 1)
namespace ion::debug
{
enum class ErrorMode : uint8_t
{
	Break,
	#if (ION_EXCEPTIONS_ENABLED == 1)
	Throw,
	#endif
	Abort,
	Ignore
};
extern ErrorMode errorMode;
extern bool allowAbnormalCondition;
}  // namespace ion::debug
	#if ION_COMPILER_MSVC
		#define ION_DEBUG_BREAK				 __debugbreak();
		#define THROW_EXCEPTION(__exception) throw __exception
	#elif ION_COMPILER_CLANG
		#define ION_DEBUG_BREAK __builtin_debugtrap()
		#define THROW_EXCEPTION(__exception)
	#else
		#define ION_DEBUG_BREAK __builtin_trap()
		#define THROW_EXCEPTION(__exception)
	#endif

	#define ION_ERROR_HANDLER                      \
		do                                         \
		{                                          \
			if (::ion::debug::IsErrorDebugBreak()) \
			{                                      \
				ION_DEBUG_BREAK;                   \
			}                                      \
		} while (0)
	#define ION_ERROR_HANDLER_IMMEDIATE            \
		do                                         \
		{                                          \
			if (::ion::debug::IsErrorDebugBreak()) \
			{                                      \
				::ion::debug::HiddenDebugBreak();  \
			}                                      \
		} while (0)
#else
	#define ION_ERROR_HANDLER \
		do                    \
		{                     \
		} while (0)

	#define ION_ERROR_HANDLER_IMMEDIATE \
		do                              \
		{                               \
		} while (0)
#endif

#define ION_CHECK_FAILED(__msg, ...)                                                 \
	do                                                                               \
	{                                                                                \
		if (::ion::TracingIsInitialized())                                           \
		{                                                                            \
			::ion::tracing::Flush();                                                 \
			ION_LOG_CALL(::ion::tracing::EventType::EventError, __msg, __VA_ARGS__); \
		}                                                                            \
		ION_ERROR_HANDLER;                                                           \
	} while (0)

#define ION_CHECK_FAILED_FATAL(__format)                                       \
	do                                                                         \
	{                                                                          \
		ION_LOG_IMMEDIATE_CALL(ion::tracing::EventType::EventError, __format); \
		abort();                                                               \
	} while (0)

#if ION_PLATFORM_MICROSOFT
	#define ION_CHECK_FAILED_FMT_IMMEDIATE(__format, ...)                                           \
		do                                                                                          \
		{                                                                                           \
			ION_LOG_FMT_IMMEDIATE_CALL(ion::tracing::EventType::EventError, __format, __VA_ARGS__); \
			ION_ERROR_HANDLER_IMMEDIATE;                                                            \
		} while (0)
#else
	#define ION_CHECK_FAILED_FMT_IMMEDIATE(__msg, ...) ION_ERROR_HANDLER
#endif

#define ION_CHECK(__expr, __msg, ...)             \
	do                                            \
	{                                             \
		if ION_LIKELY (__expr) {}                 \
		else                                      \
		{                                         \
			ION_CHECK_FAILED(__msg, __VA_ARGS__); \
		}                                         \
	} while (0)

#define ION_CHECK_FATAL(__expr, __msg)     \
	do                                     \
	{                                      \
		if ION_LIKELY (__expr) {}          \
		else                               \
		{                                  \
			ION_CHECK_FAILED_FATAL(__msg); \
		}                                  \
	} while (0)

#define ION_CHECK_FMT_IMMEDIATE(__expr, __format, ...)             \
	do                                                             \
	{                                                              \
		if ION_LIKELY (__expr) {}                                  \
		else                                                       \
		{                                                          \
			ION_CHECK_FAILED_FMT_IMMEDIATE(__format, __VA_ARGS__); \
		}                                                          \
	} while (0)

#if (ION_ASSERTS_ENABLED == 1)
	#define ION_ASSERT(__expr, __msg, ...) ION_CHECK(__expr, __msg, __VA_ARGS__)
	#define ION_VERIFY(__expr, __msg, ...) ION_CHECK(__expr, __msg, __VA_ARGS__)
	#define ION_UNREACHABLE(__msg, ...)	   ION_CHECK_FAILED(__msg, __VA_ARGS__)
   // constexpr confirmant assert
	#define ION_ASSERT_FMT_IMMEDIATE(__expr, __format, ...) ION_CHECK_FMT_IMMEDIATE(__expr, __format, __VA_ARGS__)
#else
	#define ION_ASSERT_FMT_IMMEDIATE(__expr, __msg, ...) ION_ASSUME(__expr)
	#define ION_ASSERT(__expr, __msg, ...)				 ION_ASSUME(__expr)
	#define ION_VERIFY(__expr, __msg, ...)				 __expr
	#if ION_COMPILER_MSVC
		#define ION_UNREACHABLE(__msg, ...) __assume(0)
	#else
		#define ION_UNREACHABLE(__msg, ...) __builtin_unreachable()
	#endif
#endif

// Abnormal is an error due to user, network or some other external condition
#if (ION_ABORT_ON_FAILURE == 1)
	#define ION_ABNORMAL(__msg, ...)                     \
		do                                               \
		{                                                \
			if (ion::debug::IsBreakingOnAbnormalError()) \
			{                                            \
				ION_CHECK_FAILED(__msg, __VA_ARGS__);    \
			}                                            \
			else                                         \
			{                                            \
				ION_WRN(__msg, __VA_ARGS__);             \
			}                                            \
		} while (0)
#else
	#define ION_ABNORMAL(__msg, ...) ION_WRN(__msg, __VA_ARGS__);
#endif

// Abnormal triggered once every [frequency] seconds
#define ION_ABNORMAL_ONCE(__frequency, __msg)                                  \
	do                                                                         \
	{                                                                          \
		static ion::SystemTimer ION_CONCATENATE(timer, __LINE__)(__frequency); \
		if (ION_CONCATENATE(timer, __LINE__).ElapsedSeconds() >= __frequency)  \
		{                                                                      \
			ION_CONCATENATE(timer, __LINE__).Reset();                          \
			ION_ABNORMAL(__msg);                                               \
		}                                                                      \
	} while (0)
