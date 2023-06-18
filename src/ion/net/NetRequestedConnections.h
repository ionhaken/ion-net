#pragma once

#include <ion/container/Vector.h>
#include <ion/container/UnorderedMap.h>
#include <ion/memory/UniquePtr.h>

#include <ion/net/NetSecureTypes.h>
#include <ion/net/NetSdk.h>

namespace ion
{
class NetSocket;
}

namespace ion
{
struct RequestedConnection
{
	NetSocket* socket;
#if ION_NET_FEATURE_SECURITY
	ion::Array<unsigned char, ion::NetSecure::NonceLength> mNonce;
#endif
	ion::TinyVector<uint8_t> mPassword;
	ion::NetSocketAddress systemAddress;
	ion::Time nextRequestTime;
	unsigned int timeoutTimeMs;
	unsigned int socketIndex;
	unsigned int extraData;
	unsigned int sendConnectionAttemptCount;
	unsigned int timeBetweenSendConnectionAttemptsMS;
	uint8_t requestsMade;

	enum
	{
		CONNECT = 1,
		WAIT_FOR_SOCKET_RESULT
	} actionToTake;
};

struct RequestedConnections
{
	template <typename TKey, typename TValue>
	using Map = UnorderedMap<TKey, TValue, Hasher<TKey>, NetAllocator<Pair<TKey const, TValue>>>;

	Map<ion::NetSocketAddress, RequestedConnection> mRequests;
	ion::SmallVector<ion::NetSocketAddress, 1, NetAllocator<ion::NetSocketAddress>> mCancels;
};
}  // namespace ion
