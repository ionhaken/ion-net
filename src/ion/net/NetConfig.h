#pragma once

#include <ion/Base.h>

#ifndef ION_NET_FEATURE_SECURITY
	#define ION_NET_FEATURE_SECURITY 1
#endif

#if ION_NET_FEATURE_SECURITY
	#ifndef ION_NET_FEATURE_SECURITY_AUDIT
		#define ION_NET_FEATURE_SECURITY_AUDIT 0
	#endif
#endif

#ifndef ION_NET_FEATURE_STREAMSOCKET
	#define ION_NET_FEATURE_STREAMSOCKET 0
#endif

#define ION_NET_KCP_STREAMING ION_NET_FEATURE_STREAMSOCKET

#ifndef ION_NET_FEATURE_IPV6
	#define ION_NET_FEATURE_IPV6 1
#endif

#define ION_NET_SIMULATOR ION_CONFIG_DEV_TOOLS

#ifndef ION_NET_WORK_INTERVAL
	#define ION_NET_WORK_INTERVAL 10
#endif

#ifndef ION_NET_API_STRICT
	#define ION_NET_API_STRICT 1
#endif

#if ION_NET_API_STRICT
	#define ION_NET_API_CHECK(__expr, __code, __msg, ...) ION_ASSERT(__expr, __msg, __VA_ARGS__)
#else
	#define ION_NET_API_CHECK(__expr, __code, __msg, ...) \
		do                                                \
		{                                                 \
			if ION_LIKELY (__expr) {}                     \
			else                                          \
			{                                             \
				return __code;                            \
			}                                             \
		} while (0)
#endif

#ifndef ION_NET_ASSERT
	#define ION_NET_ASSERT(x) ION_ASSERT(x, "Net failure");
#endif
