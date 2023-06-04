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

NetBindResult BindSockets(ion::NetConnections& connections, NetInterfaceResource& resource, const NetStartupParameters& startupParameters);

bool StartThreads(NetConnections& connections, NetReception& reception, NetControl& control, const NetStartupParameters& parameters);

void CancelThreads(NetConnections& connections);

void StopThreads(NetConnections& connections);

void Reset(ion::NetConnections& connections, NetInterfaceResource& memory);

void ClearConnectionRequest(ion::NetConnections& connections, const ion::RequestedConnection& rcs);

void FillIPList(NetConnections& connections);

unsigned GetNumberOfAddresses(const NetConnections& connections);

bool IsIPV6Only(const NetConnections& connections);

#if ION_NET_SIMULATOR
void UpdateNetworkSim(ion::NetConnections& connections, ion::TimeMS timeMS);
#endif

void GetInternalID(const NetConnections& connections, NetSocketAddress& out, const int index);

void SetInternalID(NetConnections& connections, const NetSocketAddress& address, int index);

void GetExternalID(const NetConnections& connections, NetSocketAddress& out);

void SetExternalID(NetConnections& connections, const NetSocketAddress& address);

const NetSocketAddress& GetLoopbackAddress(const NetConnections& connections);

bool IsLoopbackAddress(const NetConnections& connections, const NetAddressOrRemoteRef& remoteRef, bool matchPort);

}  // namespace NetConnectionLayer

}  // namespace ion
