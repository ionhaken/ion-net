#pragma once

#include <ion/net/NetConfig.h>
#include <ion/net/NetMessages.h>
#include <ion/net/NetPacketPriority.h>
#include <ion/net/NetTime.h>
#include <ion/net/NetTransport.h>

namespace ion
{
struct NetControl;

namespace NetTransportLayer
{

void Init(NetTransport& transport);

void Deinit(NetTransport& transport);

void Reset(NetTransport& transport, NetControl& control, NetRemoteSystem& remote);

bool Input(NetTransport& transport, NetControl& control, NetRemoteSystem& remoteSystem, uint32_t conversation,
		   ion::NetSocketReceiveData& recvFromStruct, ion::TimeMS now);


bool Send(NetTransport& transport, NetControl& control, TimeMS time, NetRemoteSystem& remoteSystem, NetCommand& command,
		  uint32_t conversation);
void Update(NetTransport& transport, NetControl& control, NetRemoteSystem& remoteSystem, ion::TimeMS now);


}  // namespace NetTransportLayer

}  // namespace ion
