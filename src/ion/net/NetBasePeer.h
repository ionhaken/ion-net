#pragma once

#include <ion/net/NetInterface.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetPacketPriority.h>
#include <ion/net/NetSendCommand.h>
#include <ion/net/NetGUID.h>
#include <ion/net/ionnet.h>

#include <ion/string/String.h>

namespace ion
{
class JobScheduler;
}
namespace ion
{

enum class NetConnectionAttemptResult : int
{
	CannotResolveDomainName = ION_NET_CODE_CANNOT_RESOLVE_DOMAIN_NAME,
	NoFreeConnections = ION_NET_CODE_NO_FREE_CONNECTIONS,
	InvalidParameter = ION_NET_CODE_INVALID_PARAMETER,
	Started = ION_NET_CODE_CONNECTION_ATTEMPT_STARTED,
	AlreadyInProgress = ION_NET_CODE_CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS,
	AlreadyConnectedToEndpoint = ION_NET_CODE_ALREADY_CONNECTED_TO_ENDPOINT
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

enum class NetConnectionState
{
	Pending = ION_NET_CODE_STATE_PENDING,
	Connecting = ION_NET_CODE_STATE_CONNECTING,
	Connected = ION_NET_CODE_STATE_CONNECTED,
	Disconnecting = ION_NET_CODE_STATE_DISCONNECTING,
	SilentlyDisconnecting = ION_NET_CODE_STATE_SILENTLY_DISCONNECTING,
	Disconnected = ION_NET_CODE_STATE_DISCONNECTED,
	NotConnected = ION_NET_CODE_STATE_NOT_CONNECTED
};

class NetSocket;
struct NetStartupParameters;
struct NetStats;
struct NetConnectTarget;
struct NetAddressOrRemoteRef;
union NetSocketAddress;
struct NetworkSimulatorSettings;
class GlobalClock;

namespace NetSecure
{
struct PublicKey;
}

class NetBasePeer
{
public:
	NetBasePeer(ion::NetInterfaceResource& resource);
	NetBasePeer();

	~NetBasePeer();

	inline void PreUpdate() { ion_net_preupdate((ion_net_peer)mPeer.Get(), nullptr); }

	inline void PostUpdate() { ion_net_postupdate((ion_net_peer)mPeer.Get(), nullptr); }

	inline NetStartupResult Startup(const ion::NetStartupParameters& pars)
	{
		return (NetStartupResult)ion_net_startup((ion_net_peer)mPeer.Get(), (ion_net_startup_parameters)&pars);
	}

	inline void Shutdown(unsigned int blockDuration, unsigned char orderingChannel = 0,
						 NetPacketPriority disconnectionNotificationPriority = NetPacketPriority::Low)
	{
		ion_net_shutdown((ion_net_peer)mPeer.Get(), blockDuration, orderingChannel, (unsigned int)disconnectionNotificationPriority);
	}

	inline NetConnectionAttemptResult ConnectWithSocket(const char* host, unsigned short remotePort, const char* passwordData,
														int passwordDataLength, NetSocket* socket, ion::NetSecure::PublicKey* publicKey = 0,
														unsigned sendConnectionAttemptCount = 6,
														unsigned timeBetweenSendConnectionAttemptsMS = 1000, ion::TimeMS timeoutTime = 0)
	{
		return (NetConnectionAttemptResult)ion_net_connect_with_socket(
		  (ion_net_peer)mPeer.Get(), host, remotePort, passwordData, passwordDataLength, (ion_net_socket)socket,
		  (ion_net_public_key)publicKey, sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime);
	}

	inline NetConnectionAttemptResult Connect(ion::NetConnectTarget& target, const char* passwordData, int passwordDataLength,
											  ion::NetSecure::PublicKey* publicKey = 0, unsigned connectionSocketIndex = 0,
											  unsigned sendConnectionAttemptCount = 6, unsigned timeBetweenSendConnectionAttemptsMS = 1000,
											  ion::TimeMS timeoutTime = 0)
	{
		return (NetConnectionAttemptResult)ion_net_connect((ion_net_peer)mPeer.Get(), (ion_net_connect_target)&target, passwordData,
														   passwordDataLength, (ion_net_public_key)publicKey, connectionSocketIndex,
														   sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime);
	}

	NetConnectionAttemptResult Connect(const char* host, unsigned short remotePort, const char* passwordData = nullptr, int passwordDataLength = 0,
									   ion::NetSecure::PublicKey* publicKey = 0, unsigned connectionSocketIndex = 0,
									   unsigned sendConnectionAttemptCount = 6, unsigned timeBetweenSendConnectionAttemptsMS = 1000,
									   ion::TimeMS timeoutTime = 0);

	inline void CloseConnection(const NetAddressOrRemoteRef& remoteRef, bool sendDisconnectionNotification = true,
								unsigned char orderingChannel = 0,
								NetPacketPriority disconnectionNotificationPriority = NetPacketPriority::Immediate)
	{
		ion_net_close_connection((ion_net_peer)mPeer.Get(), (ion_net_remote_ref)&remoteRef, sendDisconnectionNotification, orderingChannel,
								 (uint8_t)disconnectionNotificationPriority);
	}

	NetConnectionState GetConnectionState(const NetAddressOrRemoteRef& remoteRef)
	{
		return (NetConnectionState)ion_net_connection_state((ion_net_peer)mPeer.Get(), (ion_net_remote_ref)&remoteRef);
	}

	inline bool Ping(ion::NetConnectTarget& target, bool onlyReplyOnAcceptingConnections, unsigned connectionSocketIndex = 0)
	{
		ion_net_ping((ion_net_peer)mPeer.Get(), (ion_net_connect_target)&target, onlyReplyOnAcceptingConnections, connectionSocketIndex);
	}

	bool Ping(const char* host, unsigned short remotePort, bool onlyReplyOnAcceptingConnections, unsigned connectionSocketIndex = 0);

	inline void Ping(const NetSocketAddress& address) { ion_net_ping_address((ion_net_peer)mPeer.Get(), (ion_net_socket_address)&address); }

	inline void AddToSecurityExceptionList(const char* ip) { ion_net_add_to_security_exceptions_list((ion_net_peer)mPeer.Get(), ip); }

	inline void RemoveFromSecurityExceptionList(const char* ip)
	{
		ion_net_remove_from_security_exceptions_list((ion_net_peer)mPeer.Get(), ip);
	}

	inline bool IsInSecurityExceptionList(const char* ip) { return ion_net_is_in_security_exception_list((ion_net_peer)mPeer.Get(), ip); }

	inline void GetIncomingPassword(char* passwordData, int* passwordDataLength)
	{
		ion_net_get_incoming_password((ion_net_peer)mPeer.Get(), passwordData, passwordDataLength);
	}

	inline void SetIncomingPassword(const char* passwordData, int passwordDataLength)
	{
		ion_net_set_incoming_password((ion_net_peer)mPeer.Get(), passwordData, passwordDataLength);
	}

	inline bool IsBanned(const char* IP) { return ion_net_is_banned((ion_net_peer)mPeer.Get(), IP); }

	inline NetSendCommand CreateBroadcastCommand(size_t reservedSize, NetRemoteId remoteId = NetRemoteId())
	{
		return NetSendCommand(mPeer->mControl, remoteId, reservedSize, NetCommand::Targets::Exclude);
	}

	inline NetSendCommand CreateBroadcastCommand(const NetSocketAddress& address, size_t reservedSize)
	{
		return NetSendCommand(mPeer->mControl, address, reservedSize, NetCommand::Targets::Exclude);
	}

	inline NetSendCommand CreateSendCommand(NetRemoteId remoteId, size_t reservedSize)
	{
		return NetSendCommand(mPeer->mControl, remoteId, reservedSize);
	}

	inline NetSendCommand CreateMulticastCommand(const ArrayView<NetRemoteId>& remotes, size_t reservedSize)
	{
		return NetSendCommand(mPeer->mControl, reservedSize, remotes);
	}

	inline NetSendCommand CreateSendCommand(const NetSocketAddress& address, size_t reservedSize)
	{
		return NetSendCommand(mPeer->mControl, address, reservedSize);
	}

	inline NetSendCommand CreateSendCommand(const NetAddressOrRemoteRef& ref, size_t reservedSize, bool broadcast = false)
	{
		if (ref.mAddress.IsValid())
		{
			return NetSendCommand(mPeer->mControl, ref.mAddress, reservedSize,
								  broadcast ? NetCommand::Targets::Exclude : NetCommand::Targets::Include);
		}
		return NetSendCommand(mPeer->mControl, ref.mRemoteId, reservedSize,
							  broadcast ? NetCommand::Targets::Exclude : NetCommand::Targets::Include);
	}

	inline NetSendCommand CreateBroadcastCommand(const NetAddressOrRemoteRef& ref, size_t reservedSize)
	{
		if (ref.mAddress.IsValid())
		{
			return NetSendCommand(mPeer->mControl, ref.mAddress, reservedSize, NetCommand::Targets::Exclude);
		}
		return NetSendCommand(mPeer->mControl, ref.mRemoteId, reservedSize, NetCommand::Targets::Exclude);
	}

	int SendList(const char** data, const int* lengths, const int numParameters, NetPacketPriority priority,
				 NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier, bool broadcast);

	inline bool IsActive() const { return ion_net_is_active((ion_net_peer)mPeer.Get()); }

	inline unsigned int NumberOfRemoteInitiatedConnections() const
	{
		return ion_net_number_of_remote_initiated_connections((ion_net_peer)mPeer.Get());
	}

	inline unsigned int NumberOfConnections() const { return ion_net_number_of_connections((ion_net_peer)mPeer.Get()); }

	inline bool GetConnectionList(NetRemoteId* remote_ids, unsigned int* numberOfSystems) const
	{
		return ion_net_get_connection_list((ion_net_peer)mPeer.Get(), (ion_net_remote_id)remote_ids, numberOfSystems);
	}

	inline bool GetSystemList(NetVector<NetRemoteId>& outRemoteIds) const
	{
		unsigned int numSystems = mPeer.Get()->mRemoteStore.mActiveSystemListSize;
		outRemoteIds.Resize(numSystems);
		int result = ion_net_get_connection_list((ion_net_peer)mPeer.Get(), (ion_net_remote_id)outRemoteIds.Data(), &numSystems);
		outRemoteIds.Resize(numSystems);
		return result > 0;
	}

	inline unsigned int GetMTUSize(const NetAddressOrRemoteRef& target)
	{
		return ion_net_mtu_size((ion_net_peer)mPeer.Get(), (ion_net_remote_ref)&target);
	}

	inline bool AdvertiseSystem(const char* host, unsigned short remotePort, const char* data, int dataLength,
								unsigned connectionSocketIndex = 0)
	{
		return ion_net_advertise_system((ion_net_peer)mPeer.Get(), host, remotePort, data, dataLength, connectionSocketIndex);
	}

	inline NetPacket* AllocatePacket(unsigned dataSize) { return (NetPacket*)ion_net_allocate_packet((ion_net_peer)mPeer.Get(), dataSize); }

	inline void DeallocatePacket(NetPacket* packet) { ion_net_deallocate_packet((ion_net_peer)mPeer.Get(), (ion_net_packet)packet); }

	inline void PushPacket(NetPacket* packet) { ion_net_push_packet((ion_net_peer)mPeer.Get(), (ion_net_packet)packet); }

	inline NetSocketAddress GetExternalID(const NetSocketAddress& in) const
	{
		NetSocketAddress out;
		ion_net_external_id((ion_net_peer)mPeer.Get(), (ion_net_socket_address)&in, (ion_net_socket_address)&out);
		return out;
	}

	inline NetSocketAddress GetInternalID(const NetSocketAddress& in = NetUnassignedSocketAddress, const int index = 0)
	{
		NetSocketAddress out;
		ion_net_internal_id((ion_net_peer)mPeer.Get(), (ion_net_socket_address)&in, index, (ion_net_socket_address)&out);
		return out;
	}

	inline void DisableSecurity()
	{
		ion_net_set_data_transfer_security_level((ion_net_peer)mPeer.Get(), uint8_t(NetDataTransferSecurity::ReplayProtectionAndChecksum));
	}

	inline void SetMaximumIncomingConnections(unsigned int numberAllowed)
	{
		ion_net_set_maximum_incoming_connections((ion_net_peer)mPeer.Get(), numberAllowed);
	}

	inline void SetSocketBigDataKeyCode(unsigned int idx, const unsigned char* data)
	{
		ion_net_set_socket_big_data_key_code((ion_net_peer)mPeer.Get(), idx, data);
	}

	inline unsigned int GetMaximumIncomingConnections() const { return ion_net_maximum_incoming_connections((ion_net_peer)mPeer.Get()); }

	inline unsigned int GetMaximumNumberOfPeers(void) const { return ion_net_maximum_number_of_peers((ion_net_peer)mPeer.Get()); }

	inline void CancelConnectionAttempt(const NetSocketAddress& address)
	{
		ion_net_cancel_connection_attempt((ion_net_peer)mPeer.Get(), (ion_net_socket_address)&address);
	}

	inline bool SetOfflinePingResponse(const char* data, const unsigned int length)
	{
		return ion_net_set_offline_ping_response((ion_net_peer)mPeer.Get(), data, length);
	}

	inline void GetOfflinePingResponse(char** data, unsigned int* length)
	{
		ion_net_offline_ping_response((ion_net_peer)mPeer.Get(), data, length);
	}

	inline void SetTimeSynchronization(const NetAddressOrRemoteRef& remoteRef, ion::GlobalClock* clock)
	{
		ion_net_set_time_synchronization((ion_net_peer)mPeer.Get(), (ion_net_remote_ref)&remoteRef, (ion_net_global_clock)clock);
	}

	inline NetGUID GetMyGUID() const { return (NetGUID)ion_net_my_guid((ion_net_peer)mPeer.Get()); }

	inline NetSocketAddress GetMyBoundAddress() const
	{
		NetSocketAddress out;
		ion_net_socket_first_bound_address((ion_net_peer)mPeer.Get(), (ion_net_socket_address)(&out));
		return out;
	}

	inline NetSocketAddress GetMyBoundAddress(const int socketIndex) const
	{
		NetSocketAddress out;
		ion_net_socket_bound_address((ion_net_peer)mPeer.Get(), socketIndex, (ion_net_socket_address)(&out));
		return out;
	}

	inline unsigned GetNumberOfAddresses() { return ion_net_number_of_addresses((ion_net_peer)mPeer.Get()); }

	inline bool IsIPV6Only() { return ion_net_is_ipv6_only((ion_net_peer)mPeer.Get()); };

	inline String GetLocalIP(unsigned int index)
	{
		char str[128];
		ion_net_local_ip((ion_net_peer)mPeer.Get(), index, str);
		return str;
	}

	inline bool IsLocalIP(const char* ip) { return ion_net_is_local_ip((ion_net_peer)mPeer.Get(), ip); }

	inline void AllowConnectionResponseIPMigration(bool allow)
	{
		ion_net_allow_connection_response_ip_migration((ion_net_peer)mPeer.Get(), allow);
	}

	inline void SendTTL(const char* host, unsigned short remotePort, int ttl, unsigned connectionSocketIndex = 0)
	{
		ion_net_send_ttl((ion_net_peer)mPeer.Get(), host, remotePort, ttl, connectionSocketIndex);
	}

	inline void ChangeSystemAddress(NetRemoteId remoteId, const NetSocketAddress& address)
	{
		ion_net_change_system_address((ion_net_peer)mPeer.Get(), (ion_net_remote_id_t)remoteId.UInt32(), (ion_net_socket_address)&address);
	}

	inline void ApplyNetworkSimulator(const ion::NetworkSimulatorSettings& settings)
	{
		ion_net_apply_network_simulator((ion_net_peer)mPeer.Get(), (ion_net_simulator_settings)&settings);
	}

	inline bool IsNetworkSimulatorActive() { return ion_net_is_network_simulator_active(); }

	inline ion::NetRemoteId GetRemoteId(const NetGUID guid) const
	{
		return NetRemoteId(ion_net_guid_to_remote_id((ion_net_peer)mPeer.Get(), guid.Raw()));
	}

	inline NetGUID GetGuid(const NetSocketAddress& address)
	{
		return (NetGUID)ion_net_address_to_guid((ion_net_peer)mPeer.Get(), (ion_net_socket_address)&address);
	}

	inline NetGUID GetGuid(NetRemoteId remoteId) const
	{
		return (NetGUID)ion_net_remote_id_to_guid((ion_net_peer)mPeer.Get(), remoteId.UInt32());
	}

	inline NetSocketAddress GetAddress(NetGUID input)
	{
		NetSocketAddress out;
		ion_net_guid_to_address((ion_net_peer)mPeer.Get(), input.Raw(), (ion_net_socket_address)&out);
		return out;
	}

	inline NetSocketAddress GetAddress(NetRemoteId input)
	{
		NetSocketAddress out;
		ion_net_remote_id_to_address((ion_net_peer)mPeer.Get(), input.UInt32(), (ion_net_socket_address)&out);
		return out;
	}

	inline int Send(const char* data, const int length, NetPacketPriority priority, NetPacketReliability reliability, char orderingChannel,
					const NetAddressOrRemoteRef& remoteRef = NetRemoteId(), bool broadcast = false)
	{
		return ion_net_send((ion_net_peer)mPeer.Get(), data, length, (uint8_t)priority, (uint8_t)reliability, orderingChannel,
							(ion_net_remote_ref)&remoteRef, broadcast);
	}

	inline void SendLoopback(const char* data, const int length)
	{
		return ion_net_send_loopback((ion_net_peer)mPeer.Get(), data, length);
	}

	void AddToBanList(const char* IP, ion::TimeMS milliseconds = 0)
	{
		ion_net_add_to_ban_list((ion_net_peer)mPeer.Get(), IP, milliseconds);
	}

	void RemoveFromBanList(const char* IP) { ion_net_remove_from_ban_list((ion_net_peer)mPeer.Get(), IP); }

	void ClearBanList() { ion_net_clear_ban_list((ion_net_peer)mPeer.Get()); }

	inline void SetLimitIPConnectionFrequency(bool b) { mPeer->mRemoteStore.mLimitConnectionFrequencyFromTheSameIP = b; }

	int GetAveragePing(const NetAddressOrRemoteRef& remoteRef) { return ion_net_average_ping((ion_net_peer)mPeer.Get(), (ion_net_remote_ref)&remoteRef); }

	int GetLastPing(const NetAddressOrRemoteRef& remoteRef) const
	{
		return ion_net_last_ping((ion_net_peer)mPeer.Get(), (ion_net_remote_ref)&remoteRef);
	}

	int GetLowestPing(const NetAddressOrRemoteRef& remoteRef) const
	{
		return ion_net_lowest_ping((ion_net_peer)mPeer.Get(), (ion_net_remote_ref)&remoteRef);
	}

	void SetOccasionalPing(TimeMS time) { ion_net_set_occasional_ping((ion_net_peer)mPeer.Get(), time); }

	void SetTimeoutTime(ion::TimeMS timeMS, const NetSocketAddress& target)
	{
		ion_net_set_timeout_time((ion_net_peer)mPeer.Get(), timeMS, (ion_net_socket_address)&target);
	}

	ion::TimeMS GetTimeoutTime(const NetSocketAddress& target)
	{
		return ion_net_timeout_time((ion_net_peer)mPeer.Get(), (ion_net_socket_address)&target);		
	}

	bool GetStatistics(const NetSocketAddress& address, NetStats& rns)
	{
		return ion_net_statistics_for_address((ion_net_peer)mPeer.Get(), (ion_net_socket_address)&address, (ion_net_statistics)&rns);
	}

	bool GetStatistics(NetRemoteId remoteId, NetStats& rns)
	{
		return ion_net_statistics_for_remote_id((ion_net_peer)mPeer.Get(), remoteId.UInt32(), (ion_net_statistics)&rns);
	}

	/*void GetStatisticsList(NetVector<NetSocketAddress>& addresses, NetVector<NetGUID>& guids, NetVector<NetStats>& statistics)
	{
		return NetRemoteStoreLayer::GetStatisticsList(mPeer->mRemoteStore, mPeer->mControl.mMemoryResource, addresses, guids, statistics);
	}*/


protected:
	static constexpr unsigned int ShutdownWaitTimeMs = 500;
	void Init(ion::NetInterfaceResource& resource);
	void Deinit(unsigned int blockingTime = ShutdownWaitTimeMs);

	// #TODO: Convert to custom command
	void SendBufferedList(const char** data, const int* lengths, const int numParameters, NetPacketPriority priority,
						  NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier,
						  bool broadcast, NetMode connectionMode);
	ion::NetPtr<ion::NetInterface> mPeer;
};
}  // namespace ion
