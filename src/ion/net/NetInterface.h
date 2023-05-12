#pragma once

#include <ion/net/NetConnections.h>
#include <ion/net/NetControl.h>
#include <ion/net/NetReception.h>
#include <ion/net/NetRemote.h>
#include <ion/net/NetRemoteStore.h>
#include <ion/net/NetSecurity.h>

#include <ion/container/UnorderedMap.h>

#include <ion/concurrency/MPSCQueue.h>

#include <atomic>

namespace ion
{
class RakNetSocket2;

class JobScheduler;

struct NetInterface
{
public:
	NetInterface(NetInterfaceResource& pool) : mControl(&pool) {}

	NetControl mControl;
	NetReception mReception;
	NetConnections mConnections;
	NetRemoteStore mRemoteStore;
	NetSecurity mSecurity;

};

}  // namespace ion
