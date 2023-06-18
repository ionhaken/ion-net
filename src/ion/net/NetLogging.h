#pragma once

#include <ion/net/NetSdk.h>

#include <ion/debug/Error.h>

#if (ION_ABORT_ON_FAILURE == 1)
	#define ION_NET_LOG_ABNORMAL(__msg, ...) ION_ABNORMAL(__msg, __VA_ARGS__)
#else
	#define ION_NET_LOG_ABNORMAL(__msg, ...)                                        \
		if (ion::NetManager::mLoggingLevel > 0)                                        \
		{                                                                              \
			ION_LOG_CALL(::ion::tracing::EventType::EventWarning, __msg, __VA_ARGS__); \
		}
#endif

#define ION_NET_LOG_INFO(__msg, ...)                                            \
	if (ion::NetManager::mLoggingLevel > 1)                                     \
	{                                                                           \
		ION_LOG_CALL(::ion::tracing::EventType::EventInfo, __msg, __VA_ARGS__); \
	}

#define ION_NET_LOG_VERBOSE(__msg, ...)                                         \
	if (ion::NetManager::mLoggingLevel > 2)                                     \
	{                                                                           \
		ION_LOG_CALL(::ion::tracing::EventType::EventInfo, __msg, __VA_ARGS__); \
	}

#if ION_NET_FEATURE_SECURITY && ION_NET_FEATURE_SECURITY_AUDIT
	#define ION_NET_LOG_SECURITY_AUDIT(__msg, ...) ION_NET_LOG_INFO(__msg, __VA_ARGS__)
#elif ION_BUILD_DEBUG
	#define ION_NET_LOG_SECURITY_AUDIT(__msg, ...) \
		if (ion::NetManager::mLoggingLevel > 3)       \
		{                                             \
			ION_NET_LOG_INFO(__msg, __VA_ARGS__);     \
		}
#else
	#define ION_NET_LOG_SECURITY_AUDIT(__msg, ...)
#endif

#if ION_BUILD_DEBUG
	#define ION_NET_LOG_VERBOSE_MSG(__msg, ...)                                     \
		if (ion::NetManager::mLoggingLevel > 3)                                     \
		{                                                                           \
			ION_LOG_CALL(::ion::tracing::EventType::EventInfo, __msg, __VA_ARGS__); \
		}
	#define ION_NET_LOG_VERBOSE_CHANNEL(__msg, ...)                                 \
		if (ion::NetManager::mLoggingLevel > 4)                                     \
		{                                                                           \
			ION_LOG_CALL(::ion::tracing::EventType::EventInfo, __msg, __VA_ARGS__); \
		}
	#define ION_NET_LOG_VERBOSE_CHANNEL_TUNER(__msg, ...)                           \
		if (ion::NetManager::mLoggingLevel > 5)                                     \
		{                                                                           \
			ION_LOG_CALL(::ion::tracing::EventType::EventInfo, __msg, __VA_ARGS__); \
		}
#else
	#define ION_NET_LOG_VERBOSE_MSG(__msg, ...)
	#define ION_NET_LOG_VERBOSE_CHANNEL(__msg, ...)
	#define ION_NET_LOG_VERBOSE_CHANNEL_TUNER(__msg, ...)
#endif
