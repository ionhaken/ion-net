#pragma once

#include <ion/net/NetInternalTypes.h>
#include <ion/net/NetOffline.h>
#include <ion/net/NetRequestedConnections.h>
#include <ion/net/NetSdk.h>

#include <ion/concurrency/Synchronized.h>
#if ION_NET_SIMULATOR
	#include <ion/net/NetSimulatorSettings.h>
#endif
namespace ion
{
class NetSocket;
}

namespace ion
{

template <typename T>
using NetVector = Vector<T, NetAllocator<T>>;

struct NetConnectTarget
{
	const char* host;
	unsigned short remote_port;
	NetSocketAddress resolved_address;
};

struct NetConnections
{
	Mutex mSocketListMutex;
	NetVector<NetSocket*> mSocketList;

	NetSocketAddress mSocketListFirstBoundAddress = NetUnassignedSocketAddress;  // Cached for fast access

	Offline mOffline;

	Synchronized<RequestedConnections> mRequestedConnections;

#if ION_NET_SIMULATOR
	NetworkSimulatorSettings mDefaultNetworkSimulatorSettings;
#endif
	Array<NetSocketAddress, NetMaximumNumberOfInternalIds> mIpList;
	NetSocketAddress mFirstExternalID;
};
}  // namespace ion
