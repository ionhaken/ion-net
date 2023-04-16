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

bool ResolveTarget(ion::ConnectTarget& target, NetSocket& socket)
{
	bool isOk = true;
	if (!target.mResolvedAddress.IsAssigned() || target.mResolvedAddress.GetIPVersion() != socket.mBoundAddress.GetIPVersion())
	{
		target.mResolvedAddress = NetSocketAddress(target.mHost, target.mRemotePort, socket.mBoundAddress.GetIPVersion());
		isOk = target.mResolvedAddress.IsAssigned();
	}
#if ION_PLATFORM_ANDROID && !defined(_FINAL)
	// https://developer.android.com/studio/run/emulator-networking.html
	// Special alias to your host loopback interface
	if (isOk && target.mResolvedAddress.IsLoopback())
	{
		target.mResolvedAddress = NetSocketAddress("10.0.2.2", target.mResolvedAddress.GetPort());
	}
#endif
	return isOk;
}

NetPacket* BasePeer::AllocPacket(unsigned dataSize)
{
	ion::NetPacket* p = ion::NetControlLayer::AllocateUserPacket(mPeer->mControl, dataSize);
	p->mSource = nullptr;
	p->mLength = dataSize;
	p->mGUID = NetGuidUnassigned;
	p->mRemoteId = NetRemoteId();
	return p;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Constructor
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
BasePeer::BasePeer() {}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Destructor
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
BasePeer::~BasePeer() {}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// \brief Starts the network threads, opens the listen port.
// You must call this before calling Connect().
// Multiple calls while already active are ignored.  To call this function again with different settings, you must first call Shutdown().
// \note Call SetMaximumIncomingConnections if you want to accept incoming connections
// \param[in] maxConnections The maximum number of connections between this instance of NetBasePeer and another instance of NetBasePeer. Required so
// the network can preallocate and for thread safety. A pure client would set this to 1.  A pure server would set it to the number of
// allowed clients.- A hybrid would set it to the sum of both types of connections \param[in] localPort The port to listen for connections
// on. \param[in] _threadSleepTimer How many ms to Sleep each internal update cycle. With new congestion control, the best results will be
// obtained by passing 10. \param[in] socketDescriptors An array of NetSocketDescriptor structures to force RakNet to listen on a particular IP
// address or port (or both).  Each NetSocketDescriptor will represent one unique socket.  Do not pass redundant structures.  To listen on a
// specific port, you can pass &socketDescriptor, 1NetSocketDescriptor(mPort,0); such as for a server.  For a client, it is usually OK to just
// pass NetSocketDescriptor(); \param[in] socketDescriptorCount The size of the \a socketDescriptors array.  Pass 1 if you are not sure what to
// pass. \return False on failure (can't create socket or thread), true on success.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
StartupResult BasePeer::Startup(const ion::NetStartupParameters& parameters)
{
	ION_NET_API_CHECK(parameters.mNetSocketDescriptors && parameters.mNetSocketDescriptorCount >= 1, INVALID_SOCKET_DESCRIPTORS,
					  "Invalid socket descriptors");
	ION_NET_API_CHECK(parameters.mMaxConnections > 0, INVALID_MAX_CONNECTIONS, "Invalid max connection count");
	if (mPeer->mControl.mIsActive)
	{
		return RAKNET_ALREADY_STARTED;
	}

	memset(mPeer->mSecretKey.data, 0xAA, ion::NetSecure::SecretKeyLength);
	ion::NetControlLayer::Init(*mPeer.Get(), parameters);

	NetRemoteStoreLayer::Init(mPeer->mRemoteStore, parameters, mPeer->mControl.mMemoryResource);
	NetRemoteStoreLayer::FillIPList(mPeer->mRemoteStore);
	mPeer->mRemoteStore.mFirstExternalID = NetUnassignedSocketAddress;

	ClearBufferedCommands();
	ion::NetReceptionLayer::Reset(mPeer->mReception, mPeer->mControl);

	StartupResult result = RAKNET_STARTED;
	switch (ion::NetConnectionLayer::BindSockets(mPeer->mConnections, mPeer->mControl.mMemoryResource, parameters))
	{
	case NetBindResult::Success:
	{
		for (unsigned i = 0; i < NetMaximumNumberOfInternalIds; i++)
		{
			if (mPeer->mRemoteStore.mIpList[i] == NetUnassignedSocketAddress)
			{
				break;
			}
			unsigned short port = mPeer->mConnections.mSocketList[0]->mBoundAddress.GetPort();
			mPeer->mRemoteStore.mIpList[i].SetPortHostOrder(port);
		}
		if (!NetControlLayer::StartUpdating(mPeer->mControl, mPeer->mReception, parameters.mUpdateThreadPriority))
		{
			result = FAILED_TO_CREATE_NETWORK_THREAD;
		}
		else if (!NetConnectionLayer::StartThreads(mPeer->mConnections, mPeer->mReception, mPeer->mControl, parameters))
		{
			result = FAILED_TO_CREATE_NETWORK_THREAD;
		}
		break;
	}
	case NetBindResult::FailedToBind:
		result = SOCKET_FAILED_TO_BIND;
		break;
	case NetBindResult::FailedToSendTest:
		result = SOCKET_FAILED_TEST_SEND;
		break;
	}

	if (result != RAKNET_STARTED)
	{
		Shutdown(1);
	}
	return result;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::AddToSecurityExceptionList(const char* ip)
{
	securityExceptionMutex.Lock();
	securityExceptionList.Add(ion::String(ip));
	securityExceptionMutex.Unlock();
}

bool IPAddressMatch(ion::String& string, const char* IP)
{
	if (IP == nullptr)
	{
		return false;
	}

	unsigned characterIndex = 0;

	while (characterIndex < string.Length())
	{
		if (string.Data()[characterIndex] == IP[characterIndex])
		{
			characterIndex++;  // Equal characters
		}
		else
		{
			if (IP[characterIndex] == 0)
			{
				return false;  // End of one of the strings
			}

			// Characters do not match
			if (string.Data()[characterIndex] == '*')
			{
				return true;  // Domain is banned.
			}
			return false;  // Characters do not match and it is not a *
		}
	}

	if (IP[characterIndex] == 0)
	{
		return true;  // End of the string and the strings match
	}

	// No match found.
	return false;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::RemoveFromSecurityExceptionList(const char* ip)
{
	if (securityExceptionList.Size() == 0)
	{
		return;
	}

	if (ip == 0)
	{
		securityExceptionMutex.Lock();
		securityExceptionList.Clear();
		securityExceptionMutex.Unlock();
	}
	else
	{
		unsigned i = 0;
		securityExceptionMutex.Lock();
		while (i < securityExceptionList.Size())
		{
			if (IPAddressMatch(securityExceptionList[i], ip))
			{
				securityExceptionList[i] = securityExceptionList[securityExceptionList.Size() - 1];
				securityExceptionList.Erase(securityExceptionList.Size() - 1);
			}
			else
			{
				i++;
			}
		}
		securityExceptionMutex.Unlock();
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool BasePeer::IsInSecurityExceptionList(const char* ip)
{
	if (securityExceptionList.Size() == 0)
		return false;

	unsigned i = 0;
	securityExceptionMutex.Lock();
	for (; i < securityExceptionList.Size(); i++)
	{
		if (IPAddressMatch(securityExceptionList[i], ip))
		{
			securityExceptionMutex.Unlock();
			return true;
		}
	}
	securityExceptionMutex.Unlock();
	return false;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Sets how many incoming connections are allowed.  If this is less than the number of players currently connected, no
// more players will be allowed to connect.  If this is greater than the maximum number of peers allowed, it will be reduced
// to the maximum number of peers allowed.  Defaults to 0.
//
// Parameters:
// numberAllowed - Maximum number of incoming connections allowed.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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
void BasePeer::SetIncomingPassword(const char* passwordData, int passwordDataLength)
{
	// if (passwordDataLength > MAX_OFFLINE_DATA_LENGTH)
	//	passwordDataLength=MAX_OFFLINE_DATA_LENGTH;

	if (passwordDataLength > 255)
		passwordDataLength = 255;

	if (passwordData == 0)
		passwordDataLength = 0;

	// Not threadsafe but it's not important enough to lock.  Who is going to change the password a lot during runtime?
	// It won't overflow at least because incomingPasswordLength is an unsigned char
	if (passwordDataLength > 0)
		memcpy(mPeer->mReception.mIncomingPassword, passwordData, passwordDataLength);
	mPeer->mReception.mIncomingPasswordLength = (unsigned char)passwordDataLength;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::GetIncomingPassword(char* passwordData, int* passwordDataLength)
{
	if (passwordData == 0)
	{
		*passwordDataLength = mPeer->mReception.mIncomingPasswordLength;
		return;
	}

	if (*passwordDataLength > mPeer->mReception.mIncomingPasswordLength)
		*passwordDataLength = mPeer->mReception.mIncomingPasswordLength;

	if (*passwordDataLength > 0)
		memcpy(passwordData, mPeer->mReception.mIncomingPassword, *passwordDataLength);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Call this to connect to the specified host (ip or domain name) and server port.
// Calling Connect and not calling SetMaximumIncomingConnections acts as a dedicated client.  Calling both acts as a true peer.
// This is a non-blocking connection.  You know the connection is successful when IsConnected() returns true
// or receive gets a packet with the type identifier NetMessageId::ConnectionRequestAccepted.  If the connection is not
// successful, such as rejected connection or no response then neither of these things will happen.
// Requires that you first call Initialize
//
// Parameters:
// host: Either a dotted IP address or a domain name
// remotePort: Which port to connect to on the remote machine.
// passwordData: A data block that must match the data block on the server.  This can be just a password, or can be a stream of data
// passwordDataLength: The length in bytes of passwordData
//
// Returns:
// True on successful initiation. False on incorrect parameters, internal error, or too many existing peers
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ConnectionAttemptResult BasePeer::Connect(ion::ConnectTarget& target, const char* passwordData, int passwordDataLength,
										  ion::NetSecure::PublicKey* publicKey, unsigned connectionSocketIndex,
										  unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS,
										  ion::TimeMS timeoutTime)
{
	ION_NET_API_CHECK(IsActive(), INVALID_PARAMETER, "Invalid state");
	ION_NET_API_CHECK(target.mHost != 0, INVALID_PARAMETER, "Invalid host");
	ION_NET_API_CHECK(connectionSocketIndex < mPeer->mConnections.mSocketList.Size(), INVALID_PARAMETER, "Invalid socket");
	ION_NET_API_CHECK(target.mRemotePort != 0, INVALID_PARAMETER, "Invalid port");

	connectionSocketIndex = GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);

	if (passwordDataLength > 255)
		passwordDataLength = 255;

	if (passwordData == 0)
		passwordDataLength = 0;

	// Not threadsafe but it's not important enough to lock.  Who is going to change the password a lot during runtime?
	// It won't overflow at least because outgoingPasswordLength is an unsigned char
	//	if (passwordDataLength>0)
	//		memcpy(outgoingPassword, passwordData, passwordDataLength);
	//	outgoingPasswordLength=(unsigned char) passwordDataLength;

	// 04/02/09 - Can't remember why I disabled connecting to self, but it seems to work
	// Connecting to ourselves in the same instance of the program?
	//	if ( ( strcmp( host, "127.0.0.1" ) == 0 || strcmp( host, "0.0.0.0" ) == 0 ) && remotePort == mSystemAddress[0].port )
	//		return false;

	return SendConnectionRequest(target, passwordData, passwordDataLength, publicKey, connectionSocketIndex, 0, sendConnectionAttemptCount,
								 timeBetweenSendConnectionAttemptsMS, timeoutTime);
}

ConnectionAttemptResult BasePeer::Connect(const char* host, unsigned short remotePort, const char* passwordData, int passwordDataLength,
										  ion::NetSecure::PublicKey* publicKey, unsigned connectionSocketIndex,
										  unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS,
										  ion::TimeMS timeoutTime)
{
	ion::ConnectTarget target{host, remotePort};
	return Connect(target, passwordData, passwordDataLength, publicKey, connectionSocketIndex, sendConnectionAttemptCount,
				   timeBetweenSendConnectionAttemptsMS, timeoutTime);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

ConnectionAttemptResult BasePeer::ConnectWithSocket(const char* host, unsigned short remotePort, const char* passwordData,
													int passwordDataLength, NetSocket* socket, ion::NetSecure::PublicKey* publicKey,
													unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS,
													ion::TimeMS timeoutTime)
{
	ION_ASSERT(IsActive(), "Not active");
	if (host == 0 || socket == 0)
		return INVALID_PARAMETER;

	if (passwordDataLength > 255)
		passwordDataLength = 255;

	if (passwordData == 0)
		passwordDataLength = 0;
	ion::ConnectTarget target{host, remotePort};
	return SendConnectionRequest(target, passwordData, passwordDataLength, publicKey, 0, 0, sendConnectionAttemptCount,
								 timeBetweenSendConnectionAttemptsMS, timeoutTime, socket);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Stops the network threads and close all connections.  Multiple calls are ok.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::Shutdown(unsigned int blockDuration, unsigned char orderingChannel, NetPacketPriority disconnectionNotificationPriority)
{
	bool IsUpdateThreadRunning = mPeer->mControl.mUpdateMode != NetPeerUpdateMode::User;
	const unsigned int systemListSize = mPeer->mRemoteStore.mMaximumNumberOfPeers;

	// This needs to be done first to make sure all disconnects are sent and acked before shutdown can continue
	ion::TimeMS now = ion::SteadyClock::GetTimeMS();
	if (blockDuration > 0)
	{
		for (unsigned int i = 1; i <= systemListSize; i++)
		{
			// remoteSystemList in user thread
			if (mPeer->mRemoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				NetControlLayer::CloseConnectionInternal(mPeer->mControl, mPeer->mRemoteStore, mPeer->mConnections,
														 mPeer->mRemoteStore.mRemoteSystemList[i].mId.load(), true, !IsUpdateThreadRunning,
														 orderingChannel, disconnectionNotificationPriority);
			}
		}

		bool anyActive = false;
		ion::TimeMS startWaitingTime = now;
		while (TimeSince(now, startWaitingTime) < blockDuration)
		{
			anyActive = false;
			for (unsigned int j = 1; j <= systemListSize; j++)
			{
				// remoteSystemList in user thread
				if (mPeer->mRemoteStore.mRemoteSystemList[j].mMode != NetMode::Disconnected)
				{
					anyActive = true;
					break;
				}
			}

			// If this system is out of packets to send, then stop waiting
			if (anyActive == false)
				break;

			if (IsUpdateThreadRunning)
			{
				ion::NetControlLayer::Trigger(mPeer->mControl);
				ion::Thread::Sleep(ion::NetUpdateInterval * 1000);
			}
			else
			{
				PreUpdate(*mPeer.Get());
				PostUpdate(*mPeer.Get());
			}
			now = ion::SteadyClock::GetTimeMS();
		}
		if (anyActive)
		{
			ION_DBG("Could not disconnect all remotes gracefully in " << blockDuration << "ms");
		}
	}

	ion::NetControlLayer::StopUpdating(mPeer->mControl);

	// Send thread might leak memory if stopping while there's active data sending, thus,
	// update threads must be stopped before socket threads.
	ion::NetConnectionLayer::StopThreads(mPeer->mConnections);

	ion::NetConnectionLayer::Reset(mPeer->mConnections, mPeer->mControl.mMemoryResource);

	ion::NetRemoteStoreLayer::Deinit(mPeer->mRemoteStore, mPeer->mControl, now);
	ion::NetReceptionLayer::Reset(mPeer->mReception, mPeer->mControl);
	ClearBufferedCommands();

	ion::NetControlLayer::Deinit(mPeer->mControl);

	// Free any packets the user didn't deallocate
	mPeer->mControl.mPacketReturnQueue.DequeueAll([&](NetPacket* packet) { DeallocatePacket(packet); });

	NetReceptionLayer::ClearBanList(mPeer->mReception, mPeer->mControl);
}

//-----------------------------------------------------------------------------
// Description:
// Fills the array remoteSystems with the systemAddress of all the systems we are connected to
//
// Parameters:
// remoteSystems (out): An array of SystemAddress structures to be filled with the SystemAddresss of the systems we are connected to
// - pass 0 to remoteSystems to only get the number of systems we are connected to
// numberOfSystems (int, out): As input, the size of remoteSystems array.  As output, the number of elements put into the array
// ----------------------------------------------------------------------------
bool BasePeer::GetConnectionList(NetSocketAddress* remoteSystems, unsigned short* numberOfSystems) const
{
	ION_ASSERT(IsActive(), "Not active");
	if (numberOfSystems == 0)
		return false;

	if (mPeer->mRemoteStore.mRemoteSystemList == nullptr)
	{
		if (numberOfSystems)
			*numberOfSystems = 0;
		return false;
	}

	NetVector<NetSocketAddress> addresses;
	NetVector<NetGUID> guids;
	GetSystemListInternal(addresses, guids);
	if (remoteSystems)
	{
		unsigned short i;
		for (i = 0; i < *numberOfSystems && i < addresses.Size(); i++)
			remoteSystems[i] = addresses[i];
		*numberOfSystems = i;
	}
	else
	{
		*numberOfSystems = (unsigned short)addresses.Size();
	}
	return true;
}

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
// Sends multiple blocks of data, concatenating them automatically.
//
// This is equivalent to:
// ion::BitStream bs;
// bs.WriteAlignedBytes(block1, blockLength1);
// bs.WriteAlignedBytes(block2, blockLength2);
// bs.WriteAlignedBytes(block3, blockLength3);
// Send(&bs, ...)
//
// This function only works while connected
// \param[in] data An array of pointers to blocks of data
// \param[in] lengths An array of integers indicating the length of each block of data
// \param[in] numParameters Length of the arrays data and lengths
// \param[in] priority What priority level to send on.  See NetPacketPriority.h
// \param[in] reliability How reliability to send this data.  See NetPacketPriority.h
// \param[in] orderingChannel When using ordered or sequenced messages, what channel to order these on. Messages are only ordered relative
// to other messages on the same stream \param[in] systemIdentifier Who to send this packet to, or in the case of broadcasting who not to
// send it to. Pass either a SystemAddress structure or a NetGUID structure. Use NetUnassignedSocketAddress or to specify none \param[in]
// broadcast True to send this packet to all connected systems. If true, then systemAddress specifies who not to send the packet to. \return
// False if we are not connected to the specified recipient.  True otherwise
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int BasePeer::SendList(const char** data, const int* lengths, const int numParameters, NetPacketPriority priority,
					   NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier, bool broadcast)
{
	ION_NET_API_CHECK(data, -1, "invalid data");
	ION_NET_API_CHECK(lengths, -1, "invalid data");
	ION_NET_API_CHECK(numParameters, -1, "invalid data");
	ION_ASSERT(IsActive(), "Not active");

	if (mPeer->mRemoteStore.mRemoteSystemList == nullptr)
		return 0;

	if (broadcast == false && systemIdentifier.IsUndefined())
		return 0;

	SendBufferedList(data, lengths, numParameters, priority, reliability, orderingChannel, systemIdentifier, broadcast,
					 NetMode::Disconnected);

	return 1;
}

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
void BasePeer::GetSystemList(NetVector<NetSocketAddress>& addresses, NetVector<NetGUID>& guids) const
{
	ION_ASSERT(IsActive(), "Not active");

	if (mPeer->mRemoteStore.mRemoteSystemList == nullptr)
		return;
	addresses.Clear();
	guids.Clear();
	GetSystemListInternal(addresses, guids);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::GetSystemListInternal(NetVector<NetSocketAddress>& addresses, NetVector<NetGUID>& guids) const
{
	ION_ASSERT(IsActive(), "Not active");
	addresses.Clear();
	guids.Clear();

	if (mPeer->mRemoteStore.mRemoteSystemList == nullptr)
		return;

	unsigned int i;
	// NOTE: activeSystemListSize might be changed by network update
	for (i = 0; i < mPeer->mRemoteStore.mActiveSystemListSize; i++)
	{
		auto* system = &mPeer->mRemoteStore.mRemoteSystemList[mPeer->mRemoteStore.mActiveSystems[i]];
		if (system->mMode == NetMode::Connected)
		{
			addresses.Add((system)->mAddress);
			guids.Add((system)->guid);
		}
	}
}

bool BasePeer::IsBanned(const char* IP) { return IsBanned(IP, ion::SteadyClock::GetTimeMS()) != NetBanStatus::NotBanned; }


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Send a ping to the specified connected system.
//
// Parameters:
// target - who to ping
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::Ping(const NetSocketAddress& address)
{
	// Need to go as buffered command due to ping tracker
	auto bcs(ion::MakeArenaPtr<ion::NetCommand>(&mPeer->mControl.mMemoryResource, address));
	if (bcs.Get() == nullptr)
	{
		ion::NotifyOutOfMemory();
		return;
	}
	bcs->mCommand = ion::NetCommandType::PingAddress;
	mPeer->mControl.mBufferedCommands.Enqueue(std::move(bcs));
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Send a ping to the specified unconnected system.
// The remote system, if it is Initialized, will respond with NetMessageId::UnconnectedPong.
// The final ping time will be encoded in the following sizeof(ion::TimeMS) bytes.  (Default is 4 bytes - See __GET_TIME_64BIT in
// RakNetTypes.h
//
// Parameters:
// host: Either a dotted IP address or a domain name.  Can be 255.255.255.255 for LAN broadcast.
// remotePort: Which port to connect to on the remote machine.
// onlyReplyOnAcceptingConnections: Only request a reply if the remote system has open connections
// connectionSocketIndex Index into the array of socket descriptors passed to socketDescriptors in BasePeer::Startup() to send on.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool BasePeer::Ping(const char* host, unsigned short remotePort, bool onlyReplyOnAcceptingConnections, unsigned connectionSocketIndex)
{
	ion::ConnectTarget target{host, remotePort};
	return Ping(target, onlyReplyOnAcceptingConnections, connectionSocketIndex);
}


bool BasePeer::Ping(ion::ConnectTarget& target, bool onlyReplyOnAcceptingConnections, unsigned connectionSocketIndex)
{
	ION_NET_API_CHECK(target.mHost != 0, false, "Invalid host");
	ION_NET_API_CHECK(target.mRemotePort != 0, false, "Invalid host");
	ION_NET_API_CHECK(connectionSocketIndex < mPeer->mConnections.mSocketList.Size(), false, "Invalid socket");

	// No timestamp for 255.255.255.255
	unsigned int realIndex = GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);
	if (!ResolveTarget(target, *mPeer->mConnections.mSocketList[realIndex]))
	{
		return false;
	}
	NetRawSendCommand pingMessage(*mPeer->mConnections.mSocketList[realIndex]);
	{
		ByteWriter writer(pingMessage.Writer());
		writer.Process(onlyReplyOnAcceptingConnections ? NetMessageId::UnconnectedPingOpenConnections : NetMessageId::UnconnectedPing);
		writer.Process(NetUnconnectedHeader);
		ion::Time time = ion::SteadyClock::GetTimeMS();
		writer.Process(time);
		writer.Process(GetMyGUID());
	}
	pingMessage.Dispatch(target.mResolvedAddress);
	
	return true;
}

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
	if (!IsActive())
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
	unsigned int realIndex = GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);
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
	if (IsActive() == false)
		return false;

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

	unsigned int realIndex = GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);
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

ConnectionAttemptResult BasePeer::SendConnectionRequest(ion::ConnectTarget& target, const char* passwordData, int passwordDataLength,
														ion::NetSecure::PublicKey* /* #TODO Support sharing public key before connection */,
														unsigned connectionSocketIndex, unsigned int extraData,
														unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS,
														ion::TimeMS timeoutTime, NetSocket* socket)
{
	ION_NET_API_CHECK(timeoutTime <= ion::NetFailureConditionTimeout, INVALID_PARAMETER,
					  "Request connection timeout will be limited to remote failure condition timeout");
	ION_NET_API_CHECK((passwordDataLength > 0 && passwordDataLength <= 256) || (passwordDataLength == 0 && passwordData == nullptr),
					  INVALID_PARAMETER, "Invalid password");
	ION_NET_API_CHECK(target.mRemotePort != 0, INVALID_PARAMETER, "Invalid port");
	if (!ResolveTarget(target, *mPeer->mConnections.mSocketList[connectionSocketIndex]))
	{
		ION_DBG("Cannot resolve domain name;host="
				<< target.mHost << ";port=" << target.mRemotePort
				<< ";IPv=" << mPeer->mConnections.mSocketList[connectionSocketIndex]->mBoundAddress.GetIPVersion()
												   << ";bound=" << mPeer->mConnections.mSocketList[connectionSocketIndex]->mBoundAddress);
		return CANNOT_RESOLVE_DOMAIN_NAME;
	}

	// Already connected?
	bool hasFreeConnections = false;
	for (unsigned int i = 1; i <= mPeer->mRemoteStore.mMaximumNumberOfPeers; i++)
	{
		if (mPeer->mRemoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected)
		{
			if (mPeer->mRemoteStore.mRemoteSystemList[i].mAddress == target.mResolvedAddress)
			{
				return ALREADY_CONNECTED_TO_ENDPOINT;
			}
		}
		else
		{
			hasFreeConnections = true;
		}
	}

	if (!hasFreeConnections)
	{
		return NO_FREE_CONNECTIONS;
	}

	ConnectionAttemptResult result = CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS;
#if ION_NET_FEATURE_STREAMSOCKET
	if (((RNS2_Berkley*)(socketList[connectionSocketIndex]))->binding.type == SOCK_STREAM)
	{
		auto* socketLayer = (RNS2_Berkley*)socketList[connectionSocketIndex];
		if (socketLayer->streamSocket)
		{
			return ALREADY_CONNECTED_TO_ENDPOINT;
		}
		ION_LOG_INFO("Started connecting to " << systemAddress);
		if (ion::SocketLayer::ConnectSocket(*socketLayer, systemAddress))
		{
			socketLayer->streamSocket = socketLayer->mNativeSocket;
			socketLayer->ConnectingThread(*this, *socketLayer, systemAddress);
			return CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS;
		}
		return CANNOT_RESOLVE_DOMAIN_NAME;
	}
#endif
	mPeer->mConnections.mRequestedConnections.Access(
	  [&](ion::RequestedConnections& data)
	  {
		  if (data.mRequests.Find(target.mResolvedAddress) == data.mRequests.End())
		  {
			  ion::RequestedConnection rcs;

			  rcs.systemAddress = target.mResolvedAddress;
			  rcs.nextRequestTime = ion::SteadyClock::GetTimeMS();
			  rcs.requestsMade = 0;
			  rcs.socket = socket;
			  rcs.extraData = extraData;
			  rcs.socketIndex = connectionSocketIndex;
			  rcs.actionToTake = ion::RequestedConnection::CONNECT;
			  rcs.sendConnectionAttemptCount = sendConnectionAttemptCount;
			  rcs.timeBetweenSendConnectionAttemptsMS = timeBetweenSendConnectionAttemptsMS;
			  rcs.mPassword.Resize(passwordDataLength);
			  ion::NetSecure::Random(rcs.mNonce.Data(), rcs.mNonce.ElementCount);
			  memcpy(rcs.mPassword.Data(), passwordData, passwordDataLength);
			  rcs.timeoutTimeMs = timeoutTime;
			  data.mRequests.Insert(rcs.systemAddress, rcs);
			  result = CONNECTION_ATTEMPT_STARTED;
		  }
	  });
	return result;
}


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void BasePeer::SendBufferedList(const char** data, const int* lengths, const int numParameters, NetPacketPriority priority,
								NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier,
								bool broadcast, NetMode connectionMode)
{
	ION_ASSERT(broadcast || !systemIdentifier.IsUndefined(), "Invalid system");

	unsigned int totalLength = 0;
	unsigned int lengthOffset;
	int i;
	for (i = 0; i < numParameters; i++)
	{
		if (lengths[i] > 0)
			totalLength += lengths[i];
	}
	if (totalLength == 0)
		return;

	
	NetSendCommand cmd(CreateSendCommand(systemIdentifier, totalLength,  broadcast));
	char* dataAggregate = &cmd.Parameters().mData;

	for (i = 0, lengthOffset = 0; i < numParameters; i++)
	{
		if (lengths[i] > 0)
		{
			memcpy(dataAggregate + lengthOffset, data[i], lengths[i]);
			lengthOffset += lengths[i];
		}
	}
	

	auto ptr = cmd.Release();
	ptr->mNumberOfBytesToSend = totalLength;
	ptr->mConnectionMode = connectionMode;
	ptr->mChannel = orderingChannel;
	ptr->mPriority = priority;
	ptr->mReliability = reliability;
	if (broadcast == false && ion::NetRemoteStoreLayer::IsLoopbackAddress(mPeer->mRemoteStore, systemIdentifier, true))
	{
		SendLoopback(dataAggregate, totalLength);		
		DeleteArenaPtr(&mPeer->mControl.mMemoryResource, ptr);
		return;
	}

	NetControlLayer::SendBuffered(mPeer->mControl, std::move(ptr));
}


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int BasePeer::GetRakNetSocketFromUserConnectionSocketIndex(unsigned int userIndex) const
{
	unsigned int i;
	for (i = 0; i < mPeer->mConnections.mSocketList.Size(); i++)
	{
		if (mPeer->mConnections.mSocketList[i]->userConnectionSocketIndex == userIndex)
		{
			return i;
		}
	}
	ION_NET_ASSERT("GetRakNetSocketFromUserConnectionSocketIndex failed" && 0);
	return (unsigned int)-1;
}


void BasePeer::PreUpdate(NetInterface& net, ion::JobScheduler* js)
{
	ion::MemoryScope memoryScope(ion::tag::Network);
	ION_PROFILER_SCOPE(Network, "NetPre");
	const ion::TimeMS now = ion::SteadyClock::GetTimeMS();
#if ION_NET_SIMULATOR
	NetConnectionLayer::UpdateNetworkSim(net.mConnections, now);
#endif

	ion::NetReceptionLayer::ProcessBufferedPackets(net.mReception, net.mControl, net.mRemoteStore, net.mConnections, js, now);
}

bool BasePeer::PostUpdate(NetInterface& net, ion::JobScheduler* js)
{
	ion::MemoryScope memoryScope(ion::tag::Network);
	ION_PROFILER_SCOPE(Network, "NetPost");
	const ion::TimeMS now = ion::SteadyClock::GetTimeMS();
	ion::NetControlLayer::Process(net.mControl, net.mRemoteStore, net.mConnections, now);
	ion::NetConnectionLayer::SendOpenConnectionRequests(net.mConnections, net.mControl, net.mRemoteStore, now);
	ion::NetRemoteStoreLayer::Update(net.mRemoteStore, net.mControl, now, js);
#if ION_NET_SIMULATOR
	NetConnectionLayer::UpdateNetworkSim(net.mConnections, now);
#endif
	return true;
}

unsigned BasePeer::GetNumberOfAddresses()
{
	if (!IsActive())
	{
		NetRemoteStoreLayer::FillIPList(mPeer->mRemoteStore);
	}
	return NetRemoteStoreLayer::GetNumberOfAddresses(mPeer->mRemoteStore);
}

bool BasePeer::IsIPV6Only()
{
	if (!IsActive())
	{
		NetRemoteStoreLayer::FillIPList(mPeer->mRemoteStore);
	}
	return NetRemoteStoreLayer::IsIPV6Only(mPeer->mRemoteStore);
}

void BasePeer::ClearBufferedCommands()
{
	mPeer->mControl.mBufferedCommands.DequeueAll([&](ion::NetCommandPtr& bcs)
												 { ion::DeleteArenaPtr(&mPeer->mControl.mMemoryResource, bcs); });
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
