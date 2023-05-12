/*
 *  Copyright (c) 2014, Oculus VR, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

// \file
//


#include <ion/net/NetControlLayer.h>
#include <ion/net/NetConfig.h>
#include <ion/net/NetConnectionLayer.h>
#include <ion/net/NetGlobalClock.h>
#include <ion/net/NetMessageIdentifiers.h>
#include <ion/net/NetPayload.h>
#include <ion/net/NetRawSendCommand.h>
#include <ion/net/NetReceptionLayer.h>
#include <ion/net/NetRemoteStoreLayer.h>
#include <ion/net/NetSecure.h>
#include <ion/net/NetSocketLayer.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/arena/UniqueArenaPtr.h>

#include <ion/time/CoreTime.h>

#include <ion/container/ForEach.h>

#include <ion/debug/Profiling.h>

#include <ion/concurrency/Thread.h>

#include <ion/jobs/JobScheduler.h>

#include <ctype.h>	// toupper
#include <ion/BasePeer.h>

#include <string.h>
#include <time.h>
#ifndef _WIN32
	#include <unistd.h>
#endif

namespace ion
{



NetPacket* BasePeer::AllocPacket(unsigned dataSize)
{
	ion::NetPacket* p = ion::NetControlLayer::AllocateUserPacket(mPeer->mControl, dataSize);
	p->mSource = nullptr;
	p->mLength = dataSize;
	p->mGUID = NetGuidUnassigned;
	p->mRemoteId = NetRemoteId();
	return p;
}



void BasePeer::SetMaximumIncomingConnections(unsigned int numberAllowed)
{
	mPeer->mRemoteStore.mMaximumIncomingConnections = SafeRangeCast<uint16_t>(numberAllowed);
}

void BasePeer::SetSocketBigDataKeyCode(unsigned int idx, const unsigned char* data)
{
	memcpy(mPeer->mConnections.mSocketList[idx]->mBigDataKey.data, data, 32);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Returns the maximum number of incoming connections, which is always <= maxConnections
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int BasePeer::GetMaximumIncomingConnections(void) const { return mPeer->mRemoteStore.mMaximumIncomingConnections; }

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Sets the password incoming connections must match in the call to Connect (defaults to none)
// Pass 0 to passwordData to specify no password
//
// Parameters:
// passwordData: A data block that incoming connections must match.  This can be just a password, or can be a stream of data.
// - Specify 0 for no password data
// passwordDataLength: The length in bytes of passwordData
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------




// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------






// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Sends a block of data to the specified system that you are connected to.
// This function only works while the client is connected (Use the Connect function).
// The first byte should be a message identifier starting at NetMessageId::UserPacket
//
// Parameters:
// data: The block of data to send
// length: The size in bytes of the data to send
// bitStream: The bitstream to send
// priority: What priority level to send on.
// reliability: How reliability to send this data
// orderingChannel: When using ordered or sequenced packets, what channel to order these on.
// - Packets are only ordered relative to other packets on the same stream
// systemAddress: Who to send this packet to, or in the case of broadcasting who not to send it to. Use NetUnassignedSocketAddress to
// specify none broadcast: True to send this packet to all connected systems.  If true, then systemAddress specifies who not to send the
// packet to. Returns: \return 0 on bad input. Otherwise a number that identifies this message.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

void BasePeer::SetPacketDataMaxSize([[maybe_unused]] ion::UInt size, [[maybe_unused]] const NetAddressOrRemoteRef& systemIdentifier) {}


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Call this to deallocate a packet returned by Receive
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::DeallocatePacket(NetPacket* packet)
{
	// #TODO: Test cases need this
	if (packet == nullptr)
	{
		return;
	}
	ion::NetControlLayer::DeallocateUserPacket(mPeer->mControl, packet);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Return the total number of connections we are allowed
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int BasePeer::GetMaximumNumberOfPeers(void) const { return mPeer->mRemoteStore.mMaximumNumberOfPeers; }

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Close the connection to another host (if we initiated the connection it will disconnect, if they did it will kick them out).
//
// Parameters:
// target: Which connection to close
// sendDisconnectionNotification: True to send NetMessageId::DisconnectionNotification to the recipient. False to close it silently.
// channel: If blockDuration > 0, the disconnect packet will be sent on this channel
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::CloseConnection(const NetAddressOrRemoteRef& target, bool sendDisconnectionNotification, unsigned char orderingChannel,
							   NetPacketPriority disconnectionNotificationPriority)
{
	if (target.IsUndefined())
	{
		return;
	}

	NetControlLayer::CloseConnectionInternal(mPeer->mControl, mPeer->mRemoteStore, mPeer->mConnections, target,
											 sendDisconnectionNotification, false, orderingChannel,
											  disconnectionNotificationPriority);

	if (sendDisconnectionNotification == false && GetConnectionState(target) == IS_CONNECTED)
	{
		// Dead connection
		NetPacket* packet = AllocPacket(sizeof(char));
		packet->Data()[0] = NetMessageId::ConnectionLost;

		const NetRemoteSystem* remote = NetRemoteStoreLayer::GetRemoteSystem(mPeer->mRemoteStore, target, true, false);
		packet->mAddress = remote->mAddress;
		packet->mGUID = remote->guid;
		packet->mRemoteId = remote->mId;

		AddPacketToProducer(packet);
	}
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Cancel a pending connection attempt
// If we are already connected, the connection stays open
// \param[in] target Which system to cancel
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::CancelConnectionAttempt(const NetSocketAddress& address)
{
	mPeer->mConnections.mRequestedConnections.Access([&](ion::RequestedConnections& data) { data.mCancels.Add(address); });
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef _MSC_VER
	#pragma warning(disable : 4702)	 // warning C4702: unreachable code
#endif
ConnectionState BasePeer::GetConnectionState(const NetAddressOrRemoteRef& systemIdentifier)
{
	ION_ASSERT(!systemIdentifier.IsUndefined(), "Invalid connection");
	if (systemIdentifier.mAddress != NetUnassignedSocketAddress)
	{
		bool isPending;
		mPeer->mConnections.mRequestedConnections.Access(
		  [&](const ion::RequestedConnections& data)
		  { isPending = data.mRequests.Find(systemIdentifier.mAddress) != data.mRequests.End(); });
		if (isPending)
		{
			return IS_PENDING;
		}
	}

	NetRemoteSystem* remote = ion::NetRemoteStoreLayer::GetRemoteSystem(mPeer->mRemoteStore, systemIdentifier, false, false);

	if (remote == nullptr)
		return IS_NOT_CONNECTED;

	switch (remote->mMode)
	{
	case NetMode::Disconnected:
		return IS_DISCONNECTED;
	case NetMode::DisconnectAsapSilently:
		return IS_SILENTLY_DISCONNECTING;
	case NetMode::DisconnectAsap:
	case NetMode::DisconnectAsapMutual:
	case NetMode::DisconnectOnNoAck:
		return IS_DISCONNECTING;
	case NetMode::RequestedConnection:
		return IS_CONNECTING;
	case NetMode::HandlingConnectionRequest:
		return IS_CONNECTING;
	case NetMode::UnverifiedSender:
		return IS_CONNECTING;
	case NetMode::Connected:
		return IS_CONNECTED;
	default:
		return IS_NOT_CONNECTED;
	}

	return IS_NOT_CONNECTED;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Same as calling GetSystemAddressFromIndex and GetGUIDFromIndex for all systems, but more efficient
// Indices match each other, so \a addresses[0] and \a guids[0] refer to the same system
// \param[out] addresses All system addresses. Size of the list is the number of connections. Size of the list will match the size of the \a
// guids list. \param[out] guids All guids. Size of the list is the number of connections. Size of the list will match the size of the \a
// addresses list.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

bool BasePeer::IsBanned(const char* IP) { return IsBanned(IP, ion::SteadyClock::GetTimeMS()) != NetBanStatus::NotBanned; }







void BasePeer::SetTimeSynchronization(const NetAddressOrRemoteRef& systemIdentifier, ion::GlobalClock* srcClock)
{
	NetRemoteId remoteId = systemIdentifier.mRemoteId;
	if (!remoteId.IsValid())
	{
		remoteId = NetRemoteStoreLayer::GetRemoteIdThreadSafe(mPeer->mRemoteStore, systemIdentifier.mAddress);
		if (!remoteId.IsValid())
		{
			return;
		}
	}

	auto bcs(ion::MakeArenaPtrRaw<ion::NetCommand>(&mPeer->mControl.mMemoryResource, NetCommandHeaderSize + sizeof(void*), remoteId));
	bcs->mCommand = srcClock ? NetCommandType::EnableTimeSync : NetCommandType::DisableTimeSync;
	if (srcClock)
	{
		memcpy(&bcs->mData, reinterpret_cast<char*>(&srcClock), sizeof(ion::GlobalClock*));
	}

	mPeer->mControl.mBufferedCommands.Enqueue(std::move(bcs));
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Length should be under 400 bytes, as a security measure against flood attacks
// Sets the data to send with an  (LAN server discovery) /(offline ping) response
// See the Ping sample project for how this is used.
// data: a block of data to store, or 0 for none
// length: The length of data in bytes, or 0 for none
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool BasePeer::SetOfflinePingResponse(const char* data, const unsigned int length)
{
	ION_NET_API_CHECK(length < 400, false, "Too large response");

	memcpy(mPeer->mConnections.mOffline.mResponse.Data(), data, length);
	mPeer->mConnections.mOffline.mResponseLength = ion::SafeRangeCast<uint16_t>(length);
	return true;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Returns pointers to a copy of the data passed to SetOfflinePingResponse
// \param[out] data A pointer to a copy of the data passed to \a SetOfflinePingResponse()
// \param[out] length A pointer filled in with the length parameter passed to SetOfflinePingResponse()
// \sa SetOfflinePingResponse
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::GetOfflinePingResponse(char** data, unsigned int* length)
{
	*data = mPeer->mConnections.mOffline.mResponse.Data();
	*length = mPeer->mConnections.mOffline.mResponseLength;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Return the unique address identifier that represents you on the the network and is based on your external
// IP / port (the IP / port the specified player uses to communicate with you)
// Note that unlike in previous versions, this is a struct and is not sequential
//
// Parameters:
// target: Which remote system you are referring to for your external ID
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
NetSocketAddress BasePeer::GetExternalID(const NetSocketAddress& target) const
{
	NetSocketAddress inactiveExternalId;

	inactiveExternalId = NetUnassignedSocketAddress;

	if (target == NetUnassignedSocketAddress)
	{
		return mPeer->mRemoteStore.mFirstExternalID;
	}

	// First check for active connection with this systemAddress
	for (unsigned int i = 1; i <= mPeer->mRemoteStore.mMaximumNumberOfPeers; i++)
	{
		if (mPeer->mRemoteStore.mRemoteSystemList[i].mAddress == target)
		{
			if (mPeer->mRemoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				return mPeer->mRemoteStore.mSystemAddressDetails[i].mExternalSystemAddress;
			}
			else if (mPeer->mRemoteStore.mSystemAddressDetails[i].mExternalSystemAddress != NetUnassignedSocketAddress)
			{
				inactiveExternalId = mPeer->mRemoteStore.mSystemAddressDetails[i].mExternalSystemAddress;
			}
		}
	}

	return inactiveExternalId;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

const NetGUID BasePeer::GetMyGUID() const { return mPeer->mRemoteStore.mGuid; }

NetSocketAddress BasePeer::GetMyBoundAddress(const int socketIndex) const
{
	ion::AutoLock<ion::Mutex> lock(mPeer->mConnections.mSocketListMutex);
	return socketIndex < int(mPeer->mConnections.mSocketList.Size()) ? mPeer->mConnections.mSocketList[socketIndex]->mBoundAddress
																	 : NetUnassignedSocketAddress;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

const NetGUID BasePeer::GetGuidFromSystemAddress(const NetSocketAddress& address)
{
	if (!address.IsAssigned())
	{
		return mPeer->mRemoteStore.mGuid;
	}

	NetRemoteId id = NetRemoteStoreLayer::GetRemoteIdThreadSafe(mPeer->mRemoteStore, address, false);
	return NetRemoteStoreLayer::GetGUIDThreadSafe(mPeer->mRemoteStore, id);

	/*if (input.systemIndex != ion::NetGUID::InvalidNetRemoteIndex && input.systemIndex <= mPeer->mRemoteStore.mMaximumNumberOfPeers &&
		mPeer->mRemoteStore.mRemoteSystemList[input.systemIndex].systemAddress == input)
		return mPeer->mRemoteStore.mRemoteSystemList[input.systemIndex].guid;

	for (unsigned int i = 1; i <= mPeer->mRemoteStore.mMaximumNumberOfPeers; i++)
	{
		if (mPeer->mRemoteStore.mRemoteSystemList[i].systemAddress == input)
		{
			// Set the systemIndex so future lookups will be fast
			mPeer->mRemoteStore.mRemoteSystemList[i].guid.systemIndex = (NetRemoteIndex)i;

			return mPeer->mRemoteStore.mRemoteSystemList[i].guid;
		}
	}
	*/

	// return NetGuidUnassigned;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Returns the current MTU size
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int BasePeer::GetMTUSize(const NetSocketAddress& target)
{
	if (target != NetUnassignedSocketAddress)
	{
		ion::NetRemoteSystem* rss = GetRemoteFromSocketAddress(target, false, true);
		if (rss)
			return rss->MTUSize;
	}
	return NetPreferedMtuSize[NetNumMtuSizes - 1];
}


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Returns an IP address at index 0 to GetNumberOfAddresses-1
// \param[in] index index into the list of IP addresses
// \return The local IP address at this index
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
const char* BasePeer::GetLocalIP(unsigned int index)
{
	if (!ion_net_is_active((ion_net_peer)mPeer.Get()))
	{		
		NetRemoteStoreLayer::FillIPList(mPeer->mRemoteStore);
	}

	static char str[128];
	mPeer->mRemoteStore.mIpList[index].ToString(str, 128, false);
	return str;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Is this a local IP?
// \param[in] An IP address to check
// \return True if this is one of the IP addresses returned by GetLocalIP
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool BasePeer::IsLocalIP(const char* ip)
{
	if (ip == 0 || ip[0] == 0)
		return false;

	if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "localhost") == 0)
		return true;

	int num = GetNumberOfAddresses();
	int i;
	for (i = 0; i < num; i++)
	{
		if (strcmp(ip, GetLocalIP(i)) == 0)
			return true;
	}

	return false;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Allow or disallow connection responses from any IP. Normally this should be false, but may be necessary
// when connection to servers with multiple IP addresses
//
// Parameters:
// allow - True to allow this behavior, false to not allow.  Defaults to false.  Value persists between connections
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::AllowConnectionResponseIPMigration(bool allow) { mPeer->mReception.mAllowConnectionResponseIPMigration = allow; }

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Sends a message NetMessageId::AdvertiseSystem to the remote unconnected system.
// This will tell the remote system our external IP outside the LAN, and can be used for NAT punch through
//
// Requires:
// The sender and recipient must already be started via a successful call to Initialize
//
// host: Either a dotted IP address or a domain name
// remotePort: Which port to connect to on the remote machine.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool BasePeer::AdvertiseSystem(const char* host, unsigned short remotePort, const char* data, int dataLength,
							   unsigned connectionSocketIndex)
{
	ByteBuffer<> bs;
	{
		ByteWriter writer(bs);
		writer.Write(NetMessageId::AdvertiseSystem);
		writer.WriteArray((const unsigned char*)data, dataLength);
	}
	return SendOutOfBand(host, remotePort, (const char*)bs.Begin(), bs.Size(), connectionSocketIndex);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Controls how often to return ID_DOWNLOAD_PROGRESS for large message downloads.
// ID_DOWNLOAD_PROGRESS is returned to indicate a new partial message chunk, roughly the MTU size, has arrived
// As it can be slow or cumbersome to get this notification for every chunk, you can set the interval at which it is returned.
// Defaults to 0 (never return this notification)
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::SetSplitMessageProgressInterval([[maybe_unused]] int interval) {}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Returns what was passed to SetSplitMessageProgressInterval()
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int BasePeer::GetSplitMessageProgressInterval(void) const { return 0; }

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Set how long to wait before giving up on sending an unreliable message
// Useful if the network is clogged up.
// Set to 0 or less to never timeout.  Defaults to 0.
// timeoutMS How many ms to wait before simply not sending an unreliable message.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::SetUnreliableTimeout([[maybe_unused]] ion::TimeMS timeoutMS) { ION_UNREACHABLE("Not supported"); }

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Send a message to host, with the IP socket option TTL set to 3
// This message will not reach the host, but will open the router.
// Used for NAT-Punchthrough
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::SendTTL(const char* host, unsigned short remotePort, int ttl, unsigned connectionSocketIndex)
{
	unsigned int realIndex = ion_net_user_index_to_socket_index((ion_net_peer)mPeer.Get(), connectionSocketIndex);
	NetRawSendCommand ttlMessage(*mPeer->mConnections.mSocketList[realIndex]);
	{
		ByteWriter writer(ttlMessage.Writer());
		writer.WriteKeepCapacity(uint16_t(0)); // fake data
	}
	ttlMessage.Parameters().TTL(ttl);
	ttlMessage.Dispatch(NetSocketAddress(host, remotePort, mPeer->mConnections.mSocketList[realIndex]->mBoundAddress.GetIPVersion()));
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Put a packet back at the end of the receive queue in case you don't want to deal with it immediately
//
// packet The packet you want to push back.
// pushAtHead True to push the packet so that the next receive call returns it.  False to push it at the end of the queue (obviously pushing
// it at the end makes the packets out of order)
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::PushBackPacket(NetPacket* packet, bool pushAtHead)
{
	if (packet == 0)
		return;

	ION_ASSERT(!pushAtHead, "Not supported");
	AddPacketToProducer(std::move(packet));
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::ChangeSystemAddress(NetRemoteId remoteId, const NetSocketAddress& systemAddress)
{
	auto bcs(ion::MakeArenaPtrRaw<ion::NetCommand>(&mPeer->mControl.mMemoryResource, NetCommandHeaderSize + sizeof(NetRemoteId), systemAddress));
	bcs->mCommand = NetCommandType::ChangeSystemAddress;
	*reinterpret_cast<NetRemoteId*>(&bcs->mData) = remoteId;
	mPeer->mControl.mBufferedCommands.Enqueue(std::move(bcs));
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
NetPacket* BasePeer::AllocatePacket(unsigned dataSize) { return AllocPacket(dataSize); }
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Adds simulated ping and packet loss to the outgoing data flow.
// To simulate bi-directional ping and packet loss, you should call this on both the sender and the recipient, with half the total ping and
// maxSendBPS value on each.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::ApplyNetworkSimulator([[maybe_unused]] const ion::NetworkSimulatorSettings& settings)
{
#if ION_NET_SIMULATOR
	mPeer->mConnections.mDefaultNetworkSimulatorSettings = settings;
	// ion::Vector<RakNetSocket2*> sockets;
	ION_ASSERT(mPeer->mConnections.mSocketList.Size() == 0, "Too late to configure network simulator");
	// GetSockets(sockets);
	/*for (unsigned int i = 0; i < socketList.Size(); ++i)
	{
		socketList[i]->ConfigureSimulator(settings);
	}*/
#endif
}



// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Returns if you previously called ApplyNetworkSimulator
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool BasePeer::IsNetworkSimulatorActive()
{
#if ION_NET_SIMULATOR
	return true;
#else
	return false;
#endif
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::WriteOutOfBandHeader(ByteWriter& writer)
{
	writer.Process(NetMessageId::OutOfBandInternal);
	writer.Process(NetUnconnectedHeader);
	writer.Process(mPeer->mRemoteStore.mGuid);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool BasePeer::SendOutOfBand(const char* host, unsigned short remotePort, const char* data, uint32_t dataLength,
							 unsigned connectionSocketIndex)
{
	if (!ion_net_is_active((ion_net_peer)mPeer.Get()))
	{
		return false;
	}

	if (host == 0 || host[0] == 0)
		return false;

	// If this assert hits then Startup wasn't called or the call failed.
	ION_NET_ASSERT(connectionSocketIndex < mPeer->mConnections.mSocketList.Size());

	// This is a security measure.  Don't send data longer than this value
	ION_NET_ASSERT(dataLength <=
				   (MAX_OFFLINE_DATA_LENGTH + sizeof(unsigned char) + sizeof(ion::Time) + NetGUID::size() + sizeof(NetUnconnectedHeader)));

	if (host == 0)
		return false;

	// 34 bytes

	unsigned int realIndex = ion_net_user_index_to_socket_index((ion_net_peer)mPeer.Get(),connectionSocketIndex);
	NetRawSendCommand cmd(*mPeer->mConnections.mSocketList[realIndex], dataLength + 16);

	// ion::BitStream bitStream;
	{
		auto writer(cmd.Writer());
		WriteOutOfBandHeader(writer);
		if (dataLength > 0)
		{
			writer.WriteArray((u8*)data, dataLength);
		}
	}

	NetSocketAddress systemAddress(host, remotePort, mPeer->mConnections.mSocketList[realIndex]->mBoundAddress.GetIPVersion());
	cmd.Dispatch(systemAddress);
	//NetSocketAddress systemAddress(host, remotePort, mPeer->mConnections.mSocketList[realIndex]->mBoundAddress.GetIPVersion());
	//ion::SocketLayer::SendTo(*mPeer->mConnections.mSocketList[realIndex], bitStream, systemAddress);
	return true;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int BasePeer::GetReceiveBufferSize(void) { return static_cast<unsigned int>(mPeer->mControl.mPacketReturnQueue.Size()); }

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------





unsigned BasePeer::GetNumberOfAddresses()
{
	if (!ion_net_is_active((ion_net_peer)mPeer.Get()))
	{
		NetRemoteStoreLayer::FillIPList(mPeer->mRemoteStore);
	}
	return NetRemoteStoreLayer::GetNumberOfAddresses(mPeer->mRemoteStore);
}

bool BasePeer::IsIPV6Only()
{
	if (!ion_net_is_active((ion_net_peer)mPeer.Get()))
	{
		NetRemoteStoreLayer::FillIPList(mPeer->mRemoteStore);
	}
	return NetRemoteStoreLayer::IsIPV6Only(mPeer->mRemoteStore);
}


void BasePeer::ClearConnectionRequest(const ion::RequestedConnection& rcs)
{
	ion::NetConnectionLayer::ClearConnectionRequest(mPeer->mConnections, rcs);
}

ion::NetRemoteId BasePeer::GetNetRemoteId(const ion::NetSocketAddress& sa) const
{
	return ion::NetRemoteStoreLayer::RemoteId(mPeer->mRemoteStore, sa);
}

}  // namespace ion
