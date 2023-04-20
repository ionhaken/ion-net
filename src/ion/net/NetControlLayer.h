#pragma once

#include <ion/net/NetFwd.h>
#include <ion/net/NetInternalTypes.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetPacketPriority.h>

#include <ion/time/CoreTime.h>

namespace ion
{

namespace NetControlLayer
{
void Init(NetInterface& net, const NetStartupParameters& pars);
bool StartUpdating(NetControl& control, NetReception& reception, ion::Thread::Priority priority);
void Trigger(NetControl& control);
void StopUpdating(NetControl& control);
void Deinit(NetControl& control);

void ClearBufferedCommands(NetControl& control);

void Process(NetControl& control, NetRemoteStore& remoteStore, const NetConnections& connections, ion::TimeMS now);

void CloseConnectionInternal(NetControl& control, NetRemoteStore& remoteStore, const NetConnections& connections,
							 const NetAddressOrRemoteRef& systemIdentifier, bool sendDisconnectionNotification, bool performImmediate,
							 unsigned char orderingChannel, NetPacketPriority disconnectionNotificationPriority);

void SendBuffered(NetControl& control, NetCommandPtr&& cmd);

void SendBuffered(NetControl& control, const char* data, size_t numberOfBytesToSend, NetPacketPriority priority,
				  NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier, bool broadcast,
				  NetMode connectionMode);

void PingInternal(NetControl& control, NetRemoteStore& remoteStore, const NetSocketAddress& target, bool performImmediate,
				  NetPacketReliability reliability, ion::TimeMS now);

int Send(NetControl& control, const NetRemoteStore& remoteStore, const char* data, const int length, NetPacketPriority priority,
		 NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier, bool broadcast);

void SendLoopback(NetControl& control, const NetRemoteStore& remoteStore, const char* data, const int length);

ion::NetSocketReceiveData* AllocateReceiveBuffer(NetControl& control);

void DeallocateReceiveBuffer(NetControl& control, ion::NetSocketReceiveData* const rcv);

ion::NetPacket* AllocateUserPacket(NetControl& control, size_t size);

void DeallocateUserPacket(NetControl& control, NetPacket* packet);

void DeallocateSegment(NetControl& control, NetRemoteSystem& remote, NetDownstreamSegment* seg);

void ClearCommand(NetControl& control, NetUpstreamSegment* seg);

void AddPacketToProducer(NetControl& control, ion::NetPacket* p);

}  // namespace NetControlLayer
}  // namespace ion
