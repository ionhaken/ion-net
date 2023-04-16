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

struct NetConnections
{
	ion::Mutex mSocketListMutex;
	NetVector<NetSocket*> mSocketList;

	ion::NetSocketAddress mSocketListFirstBoundAddress = NetUnassignedSocketAddress;	 // Cached for fast access

	ion::Offline mOffline;

	ion::Synchronized<ion::RequestedConnections> mRequestedConnections;

#if ION_NET_SIMULATOR
	ion::NetworkSimulatorSettings mDefaultNetworkSimulatorSettings;
#endif
};
}  // namespace ion
