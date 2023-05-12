/*
 *  Copyright (c) 2014, Oculus VR, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

/// \file
/// \brief Declares NetBasePeer class.
///

// TODO - RakNet 4 - Enable disabling flow control per connections

#pragma once

#include <ion/net/NetControlLayer.h>
#include <ion/net/NetInterface.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetReceptionLayer.h>
#include <ion/net/NetRemote.h>
#include <ion/net/NetRemoteStoreLayer.h>
#include <ion/net/NetRequestedConnections.h>
#include <ion/net/NetSendCommand.h>
#include <ion/net/NetTimeSync.h>
#include <ion/net/ionnet.h>

#include <ion/debug/AccessGuard.h>

#include <ion/concurrency/Mutex.h>
#include <ion/concurrency/Synchronized.h>

#include <atomic>
#include <ion/BasePeer.h>

namespace ion
{
enum class NetConnectionAttemptResult : int
{
	CannotResolveDomainName = ION_NET_CODE_CANNOT_RESOLVE_DOMAIN_NAME,
	AlreadyConnectedToEndpoint = ION_NET_CODE_ALREADY_CONNECTED_TO_ENDPOINT,
	NoFreeConnections = ION_NET_CODE_NO_FREE_CONNECTIONS,
	InvalidParameter = ION_NET_CODE_INVALID_PARAMETER,
	Started = ION_NET_CODE_CONNECTION_ATTEMPT_STARTED,
	AlreadyInProgress = ION_NET_CODE_CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS
};

enum class NetStartupResult : int
{
	InvalidSocketDescriptors = ION_NET_CODE_INVALID_SOCKET_DESCRIPTORS,
	InvalidMaxConnections = ION_NET_CODE_INVALID_MAX_CONNECTIONS,
	SocketFailedToBind = ION_NET_CODE_SOCKET_FAILED_TO_BIND,
	SocketFailedTestSend = ION_NET_CODE_SOCKET_FAILED_TEST_SEND,
	FailedToCreateNetworkThread = ION_NET_CODE_FAILED_TO_CREATE_NETWORK_THREAD,
	Started = ION_NET_CODE_STARTED,
	AlreadyStarted = ION_NET_CODE_ALREADY_STARTED,
};

/// Returned from BasePeer::GetConnectionState()
enum ConnectionState
{
	/// Connect() was called, but the process hasn't started yet
	IS_PENDING,
	/// Processing the connection attempt
	IS_CONNECTING,
	/// Is connected and able to communicate
	IS_CONNECTED,
	/// Was connected, but will disconnect as soon as the remaining messages are delivered
	IS_DISCONNECTING,
	/// A connection attempt failed and will be aborted
	IS_SILENTLY_DISCONNECTING,
	/// No longer connected
	IS_DISCONNECTED,
	/// Was never connected, or else was disconnected long enough ago that the entry has been discarded
	IS_NOT_CONNECTED
};

class BitStream;

class TimedJob;
class GlobalClock;
struct NetStats;

struct ConnectTarget
{
	const char* mHost;
	unsigned short mRemotePort;
	ion::NetSocketAddress mResolvedAddress;
};

class ION_EXPORT BasePeer
{
public:
	/// Constructor
	BasePeer() {}
	// Read messages from incoming message queue. Returns null when out of messages
	ion::NetPacket* Receive()
	{
		ion::NetPacket* packet = nullptr;
		mPeer->mControl.mPacketReturnQueue.Dequeue(packet);
		ION_ASSERT(packet == nullptr || packet->Data(), "Invalid packet");
		return packet;
	}
	/// Destructor
	virtual ~BasePeer() {}

	void DisableSecurity() { mPeer->mRemoteStore.mDataTransferSecurity = NetDataTransferSecurity::ReplayProtectionAndChecksum; }

	/// \brief This is useful if you have a fixed-address internal server behind a LAN.
	///
	///  Secure connections are determined by the recipient of an incoming connection. This has no effect if called on the system attempting
	///  to connect.
	/// \note If secure connections are on, do not use secure connections for a specific IP address.
	/// \param[in] ip IP address to add. * wildcards are supported.



	/// \brief Sets the maximum number of incoming connections allowed.
	/// \details If the number of incoming connections is less than the number of players currently connected,
	/// no more players will be allowed to connect.  If this is greater than the maximum number of peers allowed,
	/// it will be reduced to the maximum number of peers allowed.
	///
	/// Defaults to 0, meaning by default, nobody can connect to you
	/// \param[in] numberAllowed Maximum number of incoming connections allowed.
	void SetMaximumIncomingConnections(unsigned int numberAllowed);
	void SetSocketBigDataKeyCode(unsigned int idx, const unsigned char* data);

	/// \brief Returns the value passed to SetMaximumIncomingConnections().
	/// \return Maximum number of incoming connections, which is always <= maxConnections
	unsigned int GetMaximumIncomingConnections(void) const;

	/// \brief Sets the password for the incoming connections.
	/// \details  The password must match in the call to Connect (defaults to none).
	/// Pass 0 to passwordData to specify no password.
	/// This is a way to set a low level password for all incoming connections.  To selectively reject connections, implement your own
	/// scheme using CloseConnection() to remove unwanted connections. \param[in] passwordData A data block that incoming connections must
	/// match.  This can be just a password, or can be a stream of data. Specify 0 for no password data \param[in] passwordDataLength The
	/// length in bytes of passwordData
	
	void SetPacketDataMaxSize(ion::UInt size, const NetAddressOrRemoteRef& systemIdentifier);

	/// \brief Gets the password passed to SetIncomingPassword
	/// \param[out] passwordData  Should point to a block large enough to hold the password data you passed to SetIncomingPassword()
	/// \param[in,out] passwordDataLength Maximum size of the passwordData array.  Modified to hold the number of bytes actually written.


	/* /// \brief Connect to the specified network ID (Platform specific console function)
	/// \details Does built-in NAT traversal
	/// \param[in] networkServiceId Network ID structure for the online service
	/// \param[in] passwordData A data block that must match the data block on the server passed to SetIncomingPassword().  This can be a
	string or can be a stream of data.  Use 0 for no password.
	/// \param[in] passwordDataLength The length in bytes of passwordData.
	//bool Console2LobbyConnect( void *networkServiceId, const char *passwordData, int passwordDataLength );*/

	/// \brief Stops the network threads and closes all connections.
	/// \param[in] blockDuration Wait time(milli seconds) for all remaining messages to go out, including
	/// NetMessageId::DisconnectionNotification.  If 0, it doesn't wait at all. \param[in] orderingChannel Channel on which
	/// NetMessageId::DisconnectionNotification will be sent, if blockDuration > 0. \param[in] disconnectionNotificationPriority Priority of
	/// sending NetMessageId::DisconnectionNotification. If set to 0, the disconnection notification won't be sent.

	/// \brief Returns true if the network thread is running.
	/// \return True if the network thread is running, False otherwise
	

	/// \brief Fills the array remoteSystems with the SystemAddress of all the systems we are connected to.
	/// \param[out] remoteSystems An array of SystemAddress structures, to be filled with the SystemAddresss of the systems we are connected
	/// to. Pass 0 to remoteSystems to get the number of systems we are connected to. \param[in, out] numberOfSystems As input, the size of
	/// remoteSystems array.  As output, the number of elements put into the array.

	/// \brief Sends a block of data to the specified system that you are connected to.
	/// \note This function only works while connected.
	/// \note The first byte should be a message identifier starting at NetMessageId::UserPacket.
	/// \param[in] data Block of data to send.
	/// \param[in] length Size in bytes of the data to send.
	/// \param[in] priority Priority level to send on.  See NetPacketPriority.h
	/// \param[in] reliability How reliably to send this data.  See NetPacketPriority.h
	/// \param[in] orderingChannel When using ordered or sequenced messages, the channel to order these on. Messages are only ordered
	/// relative to other messages on the same stream. \param[in] systemIdentifier Who to send this packet to, or in the case of
	/// broadcasting who not to send it to. Pass either a SystemAddress structure or a NetGUID structure. Use NetUnassignedSocketAddress
	/// or to specify none \param[in] broadcast True to send this packet to all connected systems. If true, then systemAddress specifies who
	/// not to send the packet to. \param[in] forceReceipt If 0, will automatically determine the receipt number to return. If non-zero,
	/// will return what you give it. \return 0 on bad input. Otherwise a number that identifies this message.
	inline int Send(const char* data, const int length, NetPacketPriority priority, NetPacketReliability reliability, char orderingChannel,
					const NetAddressOrRemoteRef& systemIdentifier = NetRemoteId(), bool broadcast = false)
	{
		return ion::NetControlLayer::Send(mPeer->mControl, mPeer->mRemoteStore, data, length, priority, reliability, orderingChannel,
										  systemIdentifier, broadcast);
	}

	/// \brief "Send" to yourself rather than a remote system.
	/// \details The message will be processed through the plugins and returned to the game as usual.
	/// This function works anytime
	/// \note The first byte should be a message identifier starting at NetMessageId::UserPacket
	/// \param[in] data Block of data to send.
	/// \param[in] length Size in bytes of the data to send.
	inline void SendLoopback(const char* data, const int length)
	{
		return ion::NetControlLayer::SendLoopback(mPeer->mControl, mPeer->mRemoteStore, data, length);
	}


	/// \brief Sends multiple blocks of data, concatenating them automatically.
	///
	/// This is equivalent to:
	/// ion::BitStream bs;
	/// bs.WriteAlignedBytes(block1, blockLength1);
	/// bs.WriteAlignedBytes(block2, blockLength2);
	/// bs.WriteAlignedBytes(block3, blockLength3);
	/// Send(&bs, ...)
	///
	/// This function only works when connected.
	/// \param[in] data An array of pointers to blocks of data
	/// \param[in] lengths An array of integers indicating the length of each block of data
	/// \param[in] numParameters Length of the arrays data and lengths
	/// \param[in] priority Priority level to send on.  See NetPacketPriority.h
	/// \param[in] reliability How reliably to send this data.  See NetPacketPriority.h
	/// \param[in] orderingChannel Channel to order the messages on, when using ordered or sequenced messages. Messages are only ordered
	/// relative to other messages on the same stream. \param[in] systemIdentifier System Address or NetGUID to send this packet to, or
	/// in the case of broadcasting, the address not to send it to.  Use NetUnassignedSocketAddress to specify none. \param[in] broadcast
	/// True to send this packet to all connected systems. If true, then systemAddress specifies who not to send the packet to. \param[in]
	/// forceReceipt If 0, will automatically determine the receipt number to return. If non-zero, will return what you give it. \return 0
	/// on bad input. Otherwise a number that identifies this message. If \a reliability is a type that returns a receipt, on a later call
	/// to Receive() you will get ID_SND_RECEIPT_ACKED or ID_SND_RECEIPT_LOSS with bytes 1-4 inclusive containing this number
	int SendList(const char** data, const int* lengths, const int numParameters, NetPacketPriority priority,
				 NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier, bool broadcast);

	/// \brief Call this to deallocate a message returned by Receive() when you are done handling it.
	/// \param[in] packet Message to deallocate.
	void DeallocatePacket(NetPacket* packet);

	/// \brief Return the total number of connections we are allowed.
	/// \return Total number of connections allowed.
	unsigned int GetMaximumNumberOfPeers(void) const;

	// -------------------------------------------------------------------------------------------- Connection Management
	// Functions--------------------------------------------------------------------------------------------
	/// \brief Close the connection to another host (if we initiated the connection it will disconnect, if they did it will kick them out).
	/// \details This method closes the connection irrespective of who initiated the connection.
	/// \param[in] target Which system to close the connection to.
	/// \param[in] sendDisconnectionNotification True to send NetMessageId::DisconnectionNotification to the recipient.  False to close it
	/// silently. \param[in] channel Which ordering channel to send the disconnection notification on, if any \param[in]
	/// disconnectionNotificationPriority Priority to send NetMessageId::DisconnectionNotification on.
	void CloseConnection(const NetAddressOrRemoteRef& target, bool sendDisconnectionNotification, unsigned char orderingChannel = 0,
						 NetPacketPriority disconnectionNotificationPriority = NetPacketPriority::Low);

	/// \brief Cancel a pending connection attempt.
	/// \details If we are already connected, the connection stays open
	/// \param[in] target Target system to cancel.
	void CancelConnectionAttempt(const NetSocketAddress& address);
	/// Returns if a system is connected, disconnected, connecting in progress, or various other states
	/// \param[in] systemIdentifier The system we are referring to
	/// \note This locks a mutex, do not call too frequently during connection attempts or the attempt will take longer and possibly even
	/// timeout \return What state the remote system is in
	ConnectionState GetConnectionState(const NetAddressOrRemoteRef& systemIdentifier);

	inline const NetSocketAddress GetSystemAddressFromIndex(NetRemoteId remoteId) const
	{
		return ion::NetRemoteStoreLayer::GetSocketAddressThreadSafe(mPeer->mRemoteStore, remoteId);
	}

	/*inline const NetSocketAddress& GetSystemAddressFromIndexUnchecked(unsigned int index) const
	{
		ION_ASSERT(
		  index <= mPeer->mRemoteStore.mMaximumNumberOfPeers && mPeer->mRemoteStore.mRemoteSystemList[index].mMode == NetMode::Connected,
		  "Invalid peer");
		return mPeer->mRemoteStore.mRemoteSystemList[index].mAddress;
	}*/

	NetGUID GetGUIDFromIndex(NetRemoteId remoteId) const
	{
		return ion::NetRemoteStoreLayer::GetGUIDThreadSafe(mPeer->mRemoteStore, remoteId);
	}

	/*inline NetGUID GetGUIDFromIndexUnchecked(unsigned int index) const
	{
		ION_ASSERT(
		  index <= mPeer->mRemoteStore.mMaximumNumberOfPeers && mPeer->mRemoteStore.mRemoteSystemList[index].mMode == NetMode::Connected,
		  "Invalid peer");
		return mPeer->mRemoteStore.mRemoteSystemList[index].guid;
	}*/

	/// \brief Same as calling GetSystemAddressFromIndex and GetGUIDFromIndex for all systems, but more efficient
	/// Indices match each other, so \a addresses[0] and \a guids[0] refer to the same system
	/// \param[out] addresses All system addresses. Size of the list is the number of connections. Size of the \a addresses list will match
	/// the size of the \a guids list. \param[out] guids All guids. Size of the list is the number of connections. Size of the list will
	/// match the size of the \a addresses list.
	///

	/// \brief Bans an IP from connecting.
	/// \details Banned IPs persist between connections but are not saved on shutdown nor loaded on startup.
	/// \param[in] IP Dotted IP address. You can use * for a wildcard address, such as 128.0.0. * will ban all IP addresses starting with
	/// 128.0.0. \param[in] milliseconds Gives time in milli seconds for a temporary ban of the IP address.  Use 0 for a permanent ban.
	void AddToBanList(const char* IP, ion::TimeMS milliseconds = 0)
	{
		NetReceptionLayer::AddToBanList(mPeer->mReception, mPeer->mControl, IP, milliseconds);
	}

	/// \brief Allows a previously banned IP to connect.
	/// param[in] Dotted IP address. You can use * as a wildcard. An IP such as 128.0.0.* will ban all IP addresses starting with 128.0.0.
	void RemoveFromBanList(const char* IP) { NetReceptionLayer::RemoveFromBanList(mPeer->mReception, mPeer->mControl, IP); }

	/// \brief Allows all previously banned IPs to connect.
	void ClearBanList(void) { NetReceptionLayer::ClearBanList(mPeer->mReception, mPeer->mControl); }

	/// \brief Returns true or false indicating if a particular IP is banned.
	/// \param[in] IP Dotted IP address.
	/// \return True if IP matches any IPs in the ban list, accounting for any wildcards. False otherwise.

	bool IsBanned(const char* IP);

	NetBanStatus IsBanned(const char* IP, ion::TimeMS now)
	{
		return ion::NetReceptionLayer::IsBanned(mPeer->mReception, mPeer->mControl, IP, now);
	}

	/// \brief Enable or disable allowing frequent connections from the same IP adderss
	/// \details This is a security measure which is disabled by default, but can be set to true to prevent attackers from using up all
	/// connection slots. \param[in] b True to limit connections from the same ip to at most 1 per 100 milliseconds.
	inline void SetLimitIPConnectionFrequency(bool b) { mPeer->mRemoteStore.mLimitConnectionFrequencyFromTheSameIP = b; }




	/// \brief Returns the average of all ping times read for the specific system or -1 if none read yet
	/// \param[in] systemAddress Which system we are referring to
	/// \return The ping time for this system, or -1
	int GetAveragePing(const NetAddressOrRemoteRef& systemIdentifier)
	{
		return ion::NetRemoteStoreLayer::GetAverageRtt(mPeer->mRemoteStore, systemIdentifier);
	}

	/// \brief Returns the last ping time read for the specific system or -1 if none read yet.
	/// \param[in] systemAddress Which system we are referring to
	/// \return The last ping time for this system, or -1.
	int GetLastPing(const NetAddressOrRemoteRef& systemIdentifier) const
	{
		return ion::NetRemoteStoreLayer::GetLastRtt(mPeer->mRemoteStore, systemIdentifier);
	}

	/// \brief Returns the lowest ping time read or -1 if none read yet.
	/// \param[in] systemIdentifier Which system we are referring to
	/// \return The lowest ping time for this system, or -1.
	int GetLowestPing(const NetAddressOrRemoteRef& systemIdentifier) const
	{
		return ion::NetRemoteStoreLayer::GetLowestRtt(mPeer->mRemoteStore, systemIdentifier);
	}

	void SetTimeSynchronization(const NetAddressOrRemoteRef& systemIdentifier, ion::GlobalClock* clock);

	void SetOccasionalPing(TimeMS time) { ion::NetRemoteStoreLayer::SetOccasionalPing(mPeer->mRemoteStore, time); }

	// --------------------------------------------------------------------------------------------Static Data Functions - Functions dealing
	// with API defined synchronized memory--------------------------------------------------------------------------------------------
	/// \brief Sets the data to send along with a LAN server discovery or offline ping reply.
	/// \param[in] data Block of data to send, or 0 for none
	/// \param[in] length Length of the data in bytes, or 0 for none
	/// \note \a length should be under 400 bytes, as a security measure against flood attacks
	/// \sa Ping.cpp
	bool SetOfflinePingResponse(const char* data, const unsigned int length);

	/// \brief Returns pointers to a copy of the \a data passed to SetOfflinePingResponse.
	/// \param[out] data A pointer to a copy of the data passed to SetOfflinePingResponse()
	/// \param[out] length A pointer filled in with the length parameter passed to SetOfflinePingResponse()
	/// \sa SetOfflinePingResponse
	void GetOfflinePingResponse(char** data, unsigned int* length);

	//--------------------------------------------------------------------------------------------Network Functions - Functions dealing with
	// the network in general--------------------------------------------------------------------------------------------
	/// \brief Returns the unique address identifier that represents you or another system on the the network
	/// \note Not supported by the XBOX
	/// \param[in] systemAddress Use NetUnassignedSocketAddress to get your behind-LAN address. Use a connected system to get their
	/// behind-LAN address. This does not return the port. \param[in] index When you have multiple internal IDs, which index to return?
	/// Currently limited to NetMaximumNumberOfInternalIds (so the maximum value of this variable is NetMaximumNumberOfInternalIds-1)
	/// \return Identifier of your system internally, which may not be how other systems see if you if you are behind a NAT or proxy.
	inline const NetSocketAddress GetInternalID(const NetSocketAddress& systemAddress = NetUnassignedSocketAddress, const int index = 0)
	{
		return ion::NetRemoteStoreLayer::GetInternalID(mPeer->mRemoteStore, systemAddress, index);
	}

	/// \brief Returns the unique address identifier that represents the target on the the network and is based on the target's external IP
	/// / port. \param[in] target The SystemAddress of the remote system. Usually the same for all systems, unless you have two or more
	/// network cards.
	NetSocketAddress GetExternalID(const NetSocketAddress& target) const;

	/// Return my own GUID
	const NetGUID GetMyGUID(void) const;

	/// Return the address bound to a socket at the specified index
	NetSocketAddress GetMyBoundAddress(const int socketIndex) const;

	// Return the address bound to first socket in socket list.
	NetSocketAddress GetMyBoundAddress() const { return mPeer->mConnections.mSocketListFirstBoundAddress; }

	/// \brief  Given a connected system address, this method gives the unique GUID representing that instance of NetBasePeer.
	/// This will be the same on all systems connected to that instance of NetBasePeer, even if the external system addresses are different.
	/// Complexity is O(log2(n)).
	/// If \a input is NetUnassignedSocketAddress, will return your own GUID
	/// \pre Call Startup() first, or the function will return NetGuidUnassigned
	/// \param[in] input The system address of the target system we are connected to.
	const NetGUID GetGuidFromSystemAddress(const NetSocketAddress& input);

	/// \brief Gives the system address of a connected system, given its GUID.
	/// The GUID will be the same on all systems connected to that instance of NetBasePeer, even if the external system addresses are
	/// different. Currently O(log(n)), but this may be improved in the future If \a input is NetGuidUnassigned, NetUnassignedSocketAddress
	/// is returned. \param[in] input The NetGUID of the target system.
	NetSocketAddress GetSystemAddressFromGuid(const NetGUID& input)
	{
		return NetRemoteStoreLayer::GetSocketAddressThreadSafe(mPeer->mRemoteStore, input);
	}

	/// Set the time, in MS, to use before considering ourselves disconnected after not being able to deliver a reliable message.
	/// Default time is 10,000 or 10 seconds in release and 30,000 or 30 seconds in debug.
	/// Do not set different values for different computers that are connected to each other, or you won't be able to reconnect after
	/// NetMessageId::ConnectionLost \param[in] timeMS Time, in MS \param[in] target SystemAddress structure of the target system. Pass
	/// NetUnassignedSocketAddress for all systems.
	void SetTimeoutTime(ion::TimeMS timeMS, const NetSocketAddress& target)
	{
		ion::NetRemoteStoreLayer::SetTimeoutTime(mPeer->mRemoteStore, timeMS, target);
	}

	/// \brief Returns the Timeout time for the given system.
	/// \param[in] target Target system to get the TimeoutTime for. Pass NetUnassignedSocketAddress to get the default value.
	/// \return Timeout time for a given system.
	ion::TimeMS GetTimeoutTime(const NetSocketAddress& target)
	{
		return ion::NetRemoteStoreLayer::GetTimeoutTime(mPeer->mRemoteStore, target);
	}

	/// \brief Returns the current MTU size
	/// \param[in] target Which system to get MTU for.  NetUnassignedSocketAddress to get the default
	/// \return The current MTU size of the target system.
	int GetMTUSize(const NetSocketAddress& target);

	/// \brief Returns the number of IP addresses this system has internally.
	/// \details Get the actual addresses from GetLocalIP()
	unsigned GetNumberOfAddresses();

	bool IsIPV6Only();

	/// Returns an IP address at index 0 to GetNumberOfAddresses-1 in ipList array.
	/// \param[in] index index into the list of IP addresses
	/// \return The local IP address at this index
	const char* GetLocalIP(unsigned int index);

	/// Is this a local IP?
	/// Checks if this ip is in the ipList array.
	/// \param[in] An IP address to check, excluding the port.
	/// \return True if this is one of the IP addresses returned by GetLocalIP
	bool IsLocalIP(const char* ip);

	/// \brief Allow or disallow connection responses from any IP.
	/// \details Normally this should be false, but may be necessary when connecting to servers with multiple IP addresses.
	/// \param[in] allow - True to allow this behavior, false to not allow. Defaults to false. Value persists between connections.
	void AllowConnectionResponseIPMigration(bool allow);

	/// \brief Sends a one byte message NetMessageId::AdvertiseSystem to the remote unconnected system.
	/// This will send our external IP outside the LAN along with some user data to the remote system.
	/// \pre The sender and recipient must already be started via a successful call to Initialize
	/// \param[in] host Either a dotted IP address or a domain name
	/// \param[in] remotePort Which port to connect to on the remote machine.
	/// \param[in] data Optional data to append to the packet.
	/// \param[in] dataLength Length of data in bytes.  Use 0 if no data.
	/// \param[in] connectionSocketIndex Index into the array of socket descriptors passed to socketDescriptors in NetBasePeer::Startup() to
	/// send on. \return False if IsActive()==false or the host is unresolvable. True otherwise.
	bool AdvertiseSystem(const char* host, unsigned short remotePort, const char* data, int dataLength, unsigned connectionSocketIndex = 0);

	/// \brief Controls how often to return ID_DOWNLOAD_PROGRESS for large message downloads.
	/// \details ID_DOWNLOAD_PROGRESS is returned to indicate a new partial message chunk, roughly the MTU size, has arrived.
	/// As it can be slow or cumbersome to get this notification for every chunk, you can set the interval at which it is returned.
	/// Defaults to 0 (never return this notification).
	/// \param[in] interval How many messages to use as an interval before a download progress notification is returned.
	void SetSplitMessageProgressInterval(int interval);

	/// \brief Returns what was passed to SetSplitMessageProgressInterval().
	/// \return Number of messages to be recieved before a download progress notification is returned. Default to 0.
	int GetSplitMessageProgressInterval(void) const;

	/// \brief Set how long to wait before giving up on sending an unreliable message.
	/// Useful if the network is clogged up.
	/// Set to 0 or less to never timeout.  Defaults to 0.
	/// \param[in] timeoutMS How many ms to wait before simply not sending an unreliable message.
	void SetUnreliableTimeout(ion::TimeMS timeoutMS);

	/// \brief Send a message to a host, with the IP socket option TTL set to 3.
	/// \details This message will not reach the host, but will open the router.
	/// \param[in] host The address of the remote host in dotted notation.
	/// \param[in] remotePort The port number to send to.
	/// \param[in] ttl Max hops of datagram, set to 3
	/// \param[in] connectionSocketIndex userConnectionSocketIndex.
	/// \remarks Used for NAT-Punchthrough
	void SendTTL(const char* host, unsigned short remotePort, int ttl, unsigned connectionSocketIndex = 0);

	// --------------------------------------------------------------------------------------------Miscellaneous
	// Functions--------------------------------------------------------------------------------------------
	/// \brief Puts a message back in the receive queue in case you don't want to deal with it immediately.
	/// \param[in] packet The pointer to the packet you want to push back.
	/// \param[in] pushAtHead True to push the packet at the start of the queue so that the next receive call returns it.  False to push it
	/// at the end of the queue. \note Setting pushAtHead to false end makes the packets out of order.
	void PushBackPacket(NetPacket* packet, bool pushAtHead);

	/// \internal
	/// \brief For a given system identified by \a guid, change the SystemAddress to send to.
	/// \param[in] guid The connection we are referring to
	/// \param[in] systemAddress The new address to send to
	void ChangeSystemAddress(NetRemoteId remoteId, const NetSocketAddress& systemAddress);

	/// \brief Returns a packet for you to write to if you want to create a Packet for some reason.
	/// You can add it to the receive buffer with PushBackPacket
	/// \param[in] dataSize How many bytes to allocate for the buffer
	/// \return A packet.
	NetPacket* AllocatePacket(unsigned dataSize);

	class SocketListAccess
	{
		ion::NetConnections& mNetConnections;

	public:
		SocketListAccess(ion::NetConnections& connections) : mNetConnections(connections) { mNetConnections.mSocketListMutex.Lock(); }
		~SocketListAccess() { mNetConnections.mSocketListMutex.Unlock(); }

		const NetVector<NetSocket*>& Get() const { return mNetConnections.mSocketList; }

	private:
	};

	SocketListAccess GetSockets() { return SocketListAccess(mPeer->mConnections); }

	/// \internal
	void WriteOutOfBandHeader(ByteWriter& writer);

	// --------------------------------------------------------------------------------------------Network Simulator
	// Functions--------------------------------------------------------------------------------------------
	/// Adds simulated ping and packet loss to the outgoing data flow.
	/// To simulate bi-directional ping and packet loss, you should call this on both the sender and the recipient, with half the total ping
	/// and packetloss value on each. You can exclude network simulator code with the _RELEASE #define to decrease code size \deprecated Use
	/// http://www.jenkinssoftware.com/forum/index.php?topic=1671.0 instead. \note Doesn't work past version 3.6201 \param[in] packetloss
	/// Chance to lose a packet. Ranges from 0 to 1. \param[in] minExtraPing The minimum time to delay sends. \param[in] extraPingVariance
	/// The additional random time to delay sends.
	void ApplyNetworkSimulator(const ion::NetworkSimulatorSettings& settings);

	/// Returns if you previously called ApplyNetworkSimulator
	/// \return If you previously called ApplyNetworkSimulator
	bool IsNetworkSimulatorActive(void);

	// --------------------------------------------------------------------------------------------Statistical Functions - Functions dealing
	// with API performance--------------------------------------------------------------------------------------------

	/// \brief Returns a structure containing a large set of network statistics for the specified system.
	/// You can map this data to a string using the C style StatisticsToString() function
	/// \param[in] systemAddress Which connected system to get statistics for.
	/// \param[in] rns If you supply this structure,the network statistics will be written to it. Otherwise the method uses a static struct
	/// to write the data, which is not threadsafe. \return 0 if the specified system can't be found. Otherwise a pointer to the struct
	/// containing the specified system's network statistics. \sa NetStats.h
	bool GetStatistics(const NetSocketAddress& systemAddress, NetStats& rns)
	{
		return NetRemoteStoreLayer::GetStatistics(mPeer->mRemoteStore, mPeer->mControl.mMemoryResource, systemAddress, rns);
	}
	/// \brief Returns the network statistics of the system at the given index in the remoteSystemList.
	///	\return True if the index is less than the maximum number of peers allowed and the system is active. False otherwise.
	bool GetStatistics(NetRemoteId remoteId, NetStats& rns)
	{
		return NetRemoteStoreLayer::GetStatistics(mPeer->mRemoteStore, mPeer->mControl.mMemoryResource, remoteId, rns);
	}
	/// \brief Returns the list of systems, and statistics for each of those systems
	/// Each system has one entry in each of the lists, in the same order
	/// \param[out] addresses SystemAddress for each connected system
	/// \param[out] guids NetGUID for each connected system
	/// \param[out] statistics Calculated NetStats for each connected system
	void GetStatisticsList(NetVector<NetSocketAddress>& addresses, NetVector<NetGUID>& guids, NetVector<NetStats>& statistics)
	{
		return NetRemoteStoreLayer::GetStatisticsList(mPeer->mRemoteStore, mPeer->mControl.mMemoryResource, addresses, guids, statistics);
	}

	/// \Returns how many messages are waiting when you call Receive()
	unsigned int GetReceiveBufferSize(void);

	// --------------------------------------------------------------------------------------------EVERYTHING AFTER THIS COMMENT IS FOR
	// INTERNAL USE ONLY--------------------------------------------------------------------------------------------

	/// \internal
	bool SendOutOfBand(const char* host, unsigned short remotePort, const char* data, uint32_t dataLength,
					   unsigned connectionSocketIndex = 0);

	// void SetReceiveTriggerJob(ion::TimedJob* job);

	// ion::NetRemoteSystem* GetRemoteSystemFromGUID(const NetGUID guid, bool onlyActive) const;

	// Private methods are unprotected as data is being moved to systems


	ion::NetRemoteSystem* GetRemoteFromSocketAddress(const ion::NetSocketAddress& systemAddress, bool calledFromNetworkThread,
													 bool onlyActive)
	{
		return ion::NetRemoteStoreLayer::GetRemoteFromSocketAddress(mPeer->mRemoteStore, systemAddress, calledFromNetworkThread,
																	onlyActive);
	}
	ion::NetRemoteSystem* GetRemoteSystem(const NetAddressOrRemoteRef& systemIdentifier, bool calledFromNetworkThread, bool onlyActive)
	{
		return ion::NetRemoteStoreLayer::GetRemoteSystem(mPeer->mRemoteStore, systemIdentifier, calledFromNetworkThread, onlyActive);
	}

	ion::NetRemoteId GetRemoteId(const NetGUID guid) { return ion::NetRemoteStoreLayer::GetRemoteIdThreadSafe(mPeer->mRemoteStore, guid); }

	/// Returns how many remote systems initiated a connection to us


	ion::NetRemoteId GetNetRemoteId(const ion::NetSocketAddress& sa) const;



	void AddPacketToProducer(ion::NetPacket* p) { mPeer->mControl.mPacketReturnQueue.Enqueue(std::move(p)); }

	NetPacket* AllocPacket(unsigned dataSize);

	void ClearConnectionRequest(const ion::RequestedConnection& rcs);

protected:
	ion::NetPtr<ion::NetInterface> mPeer;
};

}  // namespace ion
