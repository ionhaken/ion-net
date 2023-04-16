#pragma once

#include <ion/net/NetInternalTypes.h>

#include <ion/time/CoreTime.h>

namespace ion
{
class BasePeer;
class BitStream;
struct NetControl;
struct NetRemoteSystem;
struct NetRemoteStore;
struct NetReception;
struct NetConnections;
class JobScheduler;
enum class NetBanStatus : uint8_t;

namespace NetReceptionLayer
{

ion::NetSocketReceiveData* Receive(NetReception& reception, NetControl& control, ion::NetSocketReceiveData* recvStruct);

void ProcessBufferedPackets(ion::NetReception& reception, NetControl& control, NetRemoteStore& remoteStore,
							ion::NetConnections& connections, JobScheduler* js, const TimeMS now);

void Reset(NetReception& reception, NetControl& control);

NetBanStatus IsBanned(NetReception& reception, NetControl& control, const char* IP, ion::TimeMS now);

NetBanStatus IsBanned(NetReception& reception, NetControl& control, const ion::NetSocketAddress& systemAddress, ion::TimeMS now);

void AddToBanList(NetReception& reception, NetControl& control, const char* IP, ion::TimeMS milliseconds);

void RemoveFromBanList(NetReception& reception, NetControl& control, const char* IP);

void ClearBanList(NetReception& reception, NetControl& control);

}  // namespace NetReceptionLayer

}  // namespace ion
