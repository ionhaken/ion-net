#pragma once

#include <ion/net/NetConnections.h>
#include <ion/net/NetControl.h>
#include <ion/net/NetExchange.h>
#include <ion/net/NetReception.h>
#include <ion/net/NetSecurity.h>

namespace ion
{
class JobScheduler;

struct NetInterface
{
public:
	NetInterface(NetInterfaceResource& pool) : mControl(&pool) {}

	NetControl mControl;
	NetReception mReception;
	NetConnections mConnections;
	NetExchange mExchange;
	NetSecurity mSecurity;
};

}  // namespace ion
