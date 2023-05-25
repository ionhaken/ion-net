#pragma once

#include <ion/net/NetFwd.h>
#include <ion/net/NetInternalTypes.h>
#include <ion/net/NetMemory.h>

#include <ion/time/CoreTime.h>

static constexpr unsigned int MAX_OFFLINE_DATA_LENGTH =
  400;	// I set this because I limit NetMessageId::ConnectionRequest to 512 bytes, and the password is appended to that packet.

namespace ion
{

namespace NetConnectionLayer
{
void SendOpenConnectionRequests(ion::NetConnections& connections, NetControl& control, NetExchange& exchange, ion::TimeMS now);

bool ProcessOfflineNetworkPacket(ion::NetConnections& connections, NetControl& control, NetExchange& exchange,
								 ion::NetSocketReceiveData& recvFromStruct, ion::TimeMS timeRead);

void DerefAllSockets(ion::NetConnections& connections, NetInterfaceResource& resource);

NetBindResult BindSockets(ion::NetConnections& connections, NetInterfaceResource& resource, const NetStartupParameters& startupParameters);

bool StartThreads(NetConnections& connections, NetReception& reception, NetControl& control, const NetStartupParameters& parameters);

void StopThreads(NetConnections& connections);

void Reset(ion::NetConnections& connections, NetInterfaceResource& memory);

void ClearConnectionRequest(ion::NetConnections& connections, const ion::RequestedConnection& rcs);

#if ION_NET_SIMULATOR
void UpdateNetworkSim(ion::NetConnections& connections, ion::TimeMS timeMS);
#endif

}  // namespace NetConnectionLayer

}  // namespace ion
