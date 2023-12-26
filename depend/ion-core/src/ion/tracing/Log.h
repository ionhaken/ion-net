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

#include <ion/string/StringSerialization.h>
#include <ion/string/StringUtil.h>

namespace ion::tracing
{

inline void LogEvent::Write(const char* text) { Write(text, ion::StringLen(text)); }

template <typename T, typename Logger>
inline void Handler(Logger& logger, const T& value)
{
	if (logger.Available() >= 127)
	{
		auto pos = &logger.mWriteBuffer[logger.mNumWritten];
		StringWriter writer(pos, 127);
		logger.mNumWritten += serialization::Serialize(value, writer);
	}
}
}  // namespace ion::tracing

#if ION_DEBUG_LOG_FILE == 1
	#define ION_LOG_EVENT_BEGIN_CALL(__name, __type) \
		{                                            \
			::ion::tracing::LogEvent __name(__type, __FILE__, __LINE__)
#else
	#define ION_LOG_EVENT_BEGIN_CALL(__name, __type) \
		{                                            \
			::ion::tracing::LogEvent __name(__type)
#endif
#define ION_LOG_EVENT_BEGIN(__name)		 ION_LOG_EVENT_BEGIN_CALL(__name, ::ion::tracing::EventType::EventInfo)
#define ION_LOG_EVENT_ADD(__name, __msg) __name << __msg
#define ION_LOG_EVENT_END()				 }

#define ION_LOG_CALL(__type, __msg, ...)                        \
	ION_LOG_EVENT_BEGIN_CALL(logEvent, __type);                 \
	ION_LOG_EVENT_ADD(logEvent, __msg);                         \
	__VA_ARGS__ /* Trigger compiler error if formatting used */ \
	ION_LOG_EVENT_END();

#if ION_DEBUG_LOG_FILE == 1
	#define ION_LOG_FMT_CALL(__type, __format, ...)                                                 \
		{                                                                                           \
			::ion::tracing::LogEvent __logEvent(__type, __FILE__, __LINE__, __format, __VA_ARGS__); \
		}
#else
	#define ION_LOG_FMT_CALL(__type, __format, ...)                             \
		{                                                                       \
			::ion::tracing::LogEvent __logEvent(__type, __format, __VA_ARGS__); \
		}
#endif

#if (ION_DEBUG_LOG_ENABLED == 1)
	#define ION_DBG(__msg, ...) ION_LOG_CALL(::ion::tracing::EventType::EventDebug, __msg, __VA_ARGS__);
	#define ION_DBG_TAG(__tag, __msg, ...) \
		ION_LOG_CALL(/*ion::logging::tag::__tag,*/ ion::tracing::EventType::EventDebug, __msg, __VA_ARGS__);
	#define ION_DBG_FMT(__format, ...) ION_LOG_FMT_CALL(::ion::tracing::EventType::EventDebug, __format, __VA_ARGS__);

#else
	#define ION_DBG_TAG(__tag, __msg, ...) \
		do                                 \
		{                                  \
		} while (0)
	#define ION_DBG_FMT(__format, ...) \
		do                             \
		{                              \
		} while (0)
	#define ION_DBG(__msg) \
		do                 \
		{                  \
		} while (0)
#endif

#define ION_LOG_INFO(__msg, ...)		ION_LOG_CALL(::ion::tracing::EventType::EventInfo, __msg, __VA_ARGS__);
#define ION_LOG_INFO_FMT(__format, ...) ION_LOG_FMT_CALL(::ion::tracing::EventType::EventInfo, __format, __VA_ARGS__);
#define ION_WRN(__msg, ...)				ION_LOG_CALL(::ion::tracing::EventType::EventWarning, __msg, __VA_ARGS__);
#define ION_WRN_FMT(__format, ...)		ION_LOG_FMT_CALL(::ion::tracing::EventType::EventWarning, __format, __VA_ARGS__);

#define ION_LOG_FMT_IMMEDIATE(__format, ...)                                                   \
	do                                                                                         \
	{                                                                                          \
		ION_LOG_FMT_IMMEDIATE_CALL(ion::tracing::EventType::EventInfo, __format, __VA_ARGS__); \
	} while (0)

#define ION_LOG_IMMEDIATE(__format)                                           \
	do                                                                        \
	{                                                                         \
		ION_LOG_IMMEDIATE_CALL(ion::tracing::EventType::EventInfo, __format); \
	} while (0)
