#pragma once

#include <ion/Types.h>
#include <ion/byte/ByteSerialization.h>

namespace ion
{

enum NetMessageId : byte
{
	//
	// Local events: Never sent to network, only sent locally to user
	//

	Invalid = 0,
	ConnectionAttemptFailed,
	AsyncStartupOk,
	AsyncStartupFailed,
	AsyncStopOk,
	// InvalidSecretKey,
	LastInternal,

	//
	// Reliable messages sent to user
	//

	ConnectionRequest = LastInternal,
	ConnectionRequestAccepted,
	InvalidPassword,
	NewIncomingConnection,
	CannotProcessRequest,

	//
	// Internal reliable messages
	//
	ChannelReconfiguration,

	//
	// Internal Unreliable messages. These types are never returned to the user.
	// #TODO: Some types generate events like unconnected ping
	//

	ConnectedPing,
	UnconnectedPing,
	UnconnectedPingOpenConnections,
	ConnectedPong,
	OpenConnectionRequest1,
	OpenConnectionReply1,
	OpenConnectionRequest2,
	OpenConnectionReply2,

	// Same as AdvertiseSystem, but intended for internal use rather than being passed to the user.
	OutOfBandInternal,

	//
	// User unreliable messages
	//

	AlreadyConnected,
	GuidReserved,
	NoFreeIncomingConnections,
	DisconnectionNotification,
	ConnectionLost,
	ConnectionBanned,

	IncompatibleProtocolVersion,
	IpRecentlyConnected,

	UnconnectedPong,
	AdvertiseSystem,

	// #TODO: Full-mesh support
	RemoteDisconnectionNotification,
	RemoteConnectionLost,
	RemoteNewIncomingConnection,

	// First user packet id
	UserPacket
	// ...
	// Next user packet id
	// ...
	//-------------------------------------------------------------------------------------------------------------

};

namespace serialization
{

template <>
inline void Serialize(const NetMessageId& id, ion::ByteWriter& writer)
{
	return writer.Write(id);
}

template <>
inline bool Deserialize(NetMessageId& id, ion::ByteReader& reader)
{
	return reader.Read(id);
}

}  // namespace serialization

}  // namespace ion
