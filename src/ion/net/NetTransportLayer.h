#pragma once

#include <ion/net/NetConfig.h>
#include <ion/net/NetMessages.h>
#include <ion/net/NetPacketPriority.h>
#include <ion/net/NetTime.h>

namespace ion
{
struct NetControl;
struct NetTransport;

namespace NetTransportLayer
{

void Init(NetTransport& transport);

void Deinit(NetTransport& transport);

void Reset(NetTransport& transport, NetControl& control, NetRemoteSystem& remote);

bool Input(NetTransport& transport, NetControl& control, NetRemoteSystem& remoteSystem, uint32_t conversation,
		   NetSocketReceiveData& recvFromStruct, TimeMS now);

bool Send(NetTransport& transport, NetControl& control, TimeMS time, NetRemoteSystem& remoteSystem, NetCommand& command);

TimeMS Update(NetTransport& transport, NetControl& control, NetRemoteSystem& remoteSystem, TimeMS now);

}  // namespace NetTransportLayer

}  // namespace ion
