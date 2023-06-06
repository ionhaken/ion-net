#pragma once

#include <ion/net/NetConfig.h>
#include <ion/net/NetSocket.h>

#if ION_PLATFORM_MICROSOFT
#else
	#include <unistd.h>
	#include <fcntl.h>
	#include <arpa/inet.h>
	#include <errno.h>	// error numbers
	#if !ION_PLATFORM_ANDROID
		#include <ifaddrs.h>
	#endif
	#include <netinet/in.h>
	#include <net/if.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <sys/ioctl.h>

	#if (defined(__GNUC__) || defined(__GCCXML__))
		#include <netdb.h>
	#endif
#endif

#define ION_NET_SOCKET_LOG(__msg, ...)	// ION_NET_LOG_INFO(__msg, __VA_ARGS__)

namespace ion
{

struct NetCommand;
struct NetConnections;
struct NetControl;
struct NetReception;
struct NetStartupParameters;

namespace SocketLayer
{

void InitSocket(NetSocket& socket);

#if ION_NET_SIMULATOR
void ConfigureNetworkSimulator(NetSocket& socket, const NetworkSimulatorSettings& simSettings);
#endif

void DeinitSocket(NetSocket& socket);

int CloseSocket(NetSocket& socket);

void SendTo(NetSocket& socket, NetSocketSendParameters* bsp);

NetBindResult BindSocket(NetSocket& socketLayer, NetBindParameters& bindParameters);

ION_FORCE_INLINE int SendTo(NetNativeSocket nativeSocket, const NetSocketSendParameters& sendParameters)
{
	return sendto(nativeSocket, sendParameters.data, sendParameters.length, 0, (const sockaddr*)&sendParameters.mAddress,
#if ION_NET_FEATURE_IPV6 == 1
				  sendParameters.mAddress.addr4.sin_family == AF_INET ?
#endif
																	  sizeof(sockaddr_in)
#if ION_NET_FEATURE_IPV6 == 1
																	  : sizeof(sockaddr_in6)
#endif
	);
}

void SendTo(NetSocket& socketLayer, NetCommand& command, const NetSocketAddress& address);

inline bool CanDoBlockingSend([[maybe_unused]] NetSocket& socketLayer)
{
#if ION_NET_SIMULATOR
	return false;
#else
	return socketLayer.mSendThreadState != NetSocket::ThreadState::Active;
#endif
}

inline int SendBlocking(NetSocket& socket, const NetSocketSendParameters& sendParameters)
{
	ION_NET_SOCKET_LOG("Socket out: sending: size=" << sendParameters.length);
	int len = 0;
	do
	{
		if (!sendParameters.optional.mask)
		{
			len = SendTo(socket.mNativeSocket, sendParameters);
		}
		else  // Set options, send, reset options
		{
			int oldTTL = -1;
			if (sendParameters.optional.options.ttl > 0)
			{
				socklen_t opLen = sizeof(oldTTL);
				// Get the current TTL
				if (getsockopt(socket.mNativeSocket, sendParameters.mAddress.GetIPPROTO(), IP_TTL, (char*)&oldTTL, &opLen) != -1)
				{
					int newTTL = sendParameters.optional.options.ttl;
					setsockopt(socket.mNativeSocket, sendParameters.mAddress.GetIPPROTO(), IP_TTL, (char*)&newTTL, sizeof(newTTL));
				}
			}
#if defined(IP_DONTFRAGMENT)
			if (sendParameters.optional.options.doNotFragment)
			{
	#if ION_PLATFORM_MICROSOFT && !ION_BUILD_DEBUG
				// If this assert hit you improperly linked against WSock32.h
				static_assert(IP_DONTFRAGMENT == 14);
	#endif
				int opt = 1;
				setsockopt(socket.mNativeSocket, sendParameters.mAddress.GetIPPROTO(), IP_DONTFRAGMENT, (char*)&opt, sizeof(opt));
			}
#endif

			len = SendTo(socket.mNativeSocket, sendParameters);

			// Keep first to get error code from sendto__
			if (len != 0 && sendParameters.optional.options.storeSocketSendResult)
			{
#if ION_PLATFORM_MICROSOFT
				int returnCode = len;
				if (len < 0)
				{
					returnCode = -WSAGetLastError();
					if (returnCode >= 0)
					{
						returnCode = -1;
					}
				}
#else
				int returnCode = len;
#endif
				socket.mSocketSendResults.Set(sendParameters.mAddress, returnCode);
			}

			if (oldTTL != -1)
			{
				setsockopt(socket.mNativeSocket, sendParameters.mAddress.GetIPPROTO(), IP_TTL, (char*)&oldTTL, sizeof(oldTTL));
			}
#if defined(IP_DONTFRAGMENT)
			if (sendParameters.optional.options.doNotFragment)
			{
	#if ION_PLATFORM_MICROSOFT && !ION_BUILD_DEBUG
				// If this assert hit you improperly linked against WSock32.h
				static_assert(IP_DONTFRAGMENT == 14);
	#endif
				int opt = 0;
				setsockopt(socket.mNativeSocket, sendParameters.mAddress.GetIPPROTO(), IP_DONTFRAGMENT, (char*)&opt, sizeof(opt));
			}
#endif
		}
	} while (len == 0);
	return len;
}

inline void SendToNetwork(NetSocket& socket, NetSocketSendParameters* bsp)
{
	if (socket.mSendThreadState == NetSocket::ThreadState::Active)
	{
		socket.Send(bsp);
	}
	else
	{
		SendBlocking(socket, *bsp);
		socket.DeallocateSend(bsp);
	}
}

inline void SendTo(NetSocket& socket, NetSocketSendParameters* bsp)
{
#if ION_NET_SIMULATOR
	socket.mNetworkSimulator.Send(bsp, socket);
#else
	SendToNetwork(socket, bsp);
#endif
}

void SetNonBlocking(NetSocket& socket, unsigned long nonblocking);

int ConnectSocket(NetSocket& socketLayer, NetSocketAddress& systemAddress);

int ListenSocket(NetSocket& socketLayer, unsigned int maxConnections);

void GetInternalAddresses(Array<NetSocketAddress, NetMaximumNumberOfInternalIds>& addresses);

void RecvFromBlocking(const NetSocket& socketLayer, NetSocketReceiveData& recvFromStruct);

bool StartThreads(NetSocket& socket, NetConnections& connections, NetReception& reception, NetControl& control,
				  const NetStartupParameters& parameters);

void CancelThreads(NetSocket& socket);

void StopThreads(NetSocket& socket);

}  // namespace SocketLayer
}  // namespace ion
