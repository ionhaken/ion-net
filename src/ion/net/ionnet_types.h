#ifndef ION_NET_TYPES_H
#define ION_NET_TYPES_H

#include <ion/net/NetConfig.h>

#if ION_PLATFORM_MICROSOFT
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <sys/socket.h>
	#if ION_PLATFORM_ANDROID
		#include <arpa/inet.h>
	#endif
	#include <netdb.h>
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

	union ion_net_socket_address_t
	{
#if ION_NET_FEATURE_IPV6 == 1
		struct sockaddr_storage sa_stor;
		sockaddr_in6 addr6;
#endif
		sockaddr_in addr4;
	};

	struct ion_net_connect_target_t
	{
		const char* host;
		unsigned short remote_port;
		ion_net_socket_address_t resolved_address;
	};


#if defined(__cplusplus)
}
#endif

#endif
