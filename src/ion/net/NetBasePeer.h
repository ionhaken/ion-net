#pragma once

#include <ion/net/ionnet.h>

#include <ion/BasePeer.h>

namespace ion
{
class JobScheduler;
}
namespace ion
{
class NetBasePeer : public BasePeer
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

	inline NetConnectionAttemptResult Connect(ion::ConnectTarget& target, const char* passwordData, int passwordDataLength,
											  ion::NetSecure::PublicKey* publicKey = 0, unsigned connectionSocketIndex = 0,
											  unsigned sendConnectionAttemptCount = 6, unsigned timeBetweenSendConnectionAttemptsMS = 1000,
											  ion::TimeMS timeoutTime = 0)
	{
		return (NetConnectionAttemptResult)ion_net_connect((ion_net_peer)mPeer.Get(), (ion_net_connect_target)&target, passwordData,
														   passwordDataLength, (ion_net_public_key)publicKey, connectionSocketIndex,
														   sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime);
	}

	inline NetConnectionAttemptResult Connect(const char* host, unsigned short remotePort, const char* passwordData, int passwordDataLength,
											  ion::NetSecure::PublicKey* publicKey = 0, unsigned connectionSocketIndex = 0,
											  unsigned sendConnectionAttemptCount = 6, unsigned timeBetweenSendConnectionAttemptsMS = 1000,
											  ion::TimeMS timeoutTime = 0)
	{
		ConnectTarget target{
		  host,
		  remotePort,
		};
		return Connect(target, passwordData, passwordDataLength, publicKey, connectionSocketIndex, sendConnectionAttemptCount,
					   timeBetweenSendConnectionAttemptsMS, timeoutTime);
	}

	inline NetConnectionAttemptResult SendConnectionRequest(ion::ConnectTarget& target, const char* passwordData, int passwordDataLength,
															ion::NetSecure::PublicKey* publicKey, unsigned connectionSocketIndex,
															unsigned int extraData, unsigned sendConnectionAttemptCount,
															unsigned timeBetweenSendConnectionAttemptsMS, ion::TimeMS timeoutTime,
															NetSocket* socket = nullptr)
	{
		ion_net_send_connection_request((ion_net_peer)mPeer.Get(), (ion_net_connect_target)&target, passwordData, passwordDataLength,
										(ion_net_public_key)publicKey, connectionSocketIndex, extraData, sendConnectionAttemptCount,
										timeBetweenSendConnectionAttemptsMS, timeoutTime, (ion_net_socket)socket);
	}

	inline bool Ping(ion::ConnectTarget& target, bool onlyReplyOnAcceptingConnections, unsigned connectionSocketIndex = 0)
	{
		ion_net_ping((ion_net_peer)mPeer.Get(), (ion_net_connect_target)&target, onlyReplyOnAcceptingConnections, connectionSocketIndex);
	}

	inline bool Ping(const char* host, unsigned short remotePort, bool onlyReplyOnAcceptingConnections, unsigned connectionSocketIndex = 0)
	{
		ion::ConnectTarget target{host, remotePort};
		return ion_net_ping((ion_net_peer)mPeer.Get(), (ion_net_connect_target)&target, onlyReplyOnAcceptingConnections,
							connectionSocketIndex);
	}

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

	unsigned int NumberOfRemoteInitiatedConnections() const
	{
		return ion_net_number_of_remote_initiated_connections((ion_net_peer)mPeer.Get());
	}

	unsigned int NumberOfConnections() const { return ion_net_number_of_connections((ion_net_peer)mPeer.Get()); }

	bool GetConnectionList(NetRemoteId* remote_ids, unsigned int* numberOfSystems) const
	{
		return ion_net_get_connection_list((ion_net_peer)mPeer.Get(), (ion_net_remote_id)remote_ids, numberOfSystems);
	}

	bool GetSystemList(NetVector<NetRemoteId>& outRemoteIds) const
	{
		unsigned int numSystems = mPeer.Get()->mRemoteStore.mActiveSystemListSize;
		outRemoteIds.Resize(numSystems);
		int result = ion_net_get_connection_list((ion_net_peer)mPeer.Get(), (ion_net_remote_id)outRemoteIds.Data(), &numSystems);
		outRemoteIds.Resize(numSystems);
		return result > 0;
	}

protected:
	static constexpr unsigned int ShutdownWaitTimeMs = 500;
	void Init(ion::NetInterfaceResource& resource);
	void Deinit(unsigned int blockingTime = ShutdownWaitTimeMs);

private:
	// #TODO: Convert to custom command
	void SendBufferedList(const char** data, const int* lengths, const int numParameters, NetPacketPriority priority,
						  NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier,
						  bool broadcast, NetMode connectionMode);
};
}  // namespace ion
