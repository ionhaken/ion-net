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

	NetConnectionAttemptResult ConnectWithSocket(const char* host, unsigned short remotePort, const char* passwordData,
												 int passwordDataLength, NetSocket* socket, ion::NetSecure::PublicKey* publicKey = 0,
												 unsigned sendConnectionAttemptCount = 6,
												 unsigned timeBetweenSendConnectionAttemptsMS = 1000, ion::TimeMS timeoutTime = 0)
	{
		return (NetConnectionAttemptResult)ion_net_connect_with_socket(
		  (ion_net_peer)mPeer.Get(), host, remotePort, passwordData, passwordDataLength, (ion_net_socket)socket,
		  (ion_net_public_key)publicKey, sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime);
	}

	NetConnectionAttemptResult Connect(ion::ConnectTarget& target, const char* passwordData, int passwordDataLength,
									   ion::NetSecure::PublicKey* publicKey = 0, unsigned connectionSocketIndex = 0,
									   unsigned sendConnectionAttemptCount = 6, unsigned timeBetweenSendConnectionAttemptsMS = 1000,
									   ion::TimeMS timeoutTime = 0)
	{
		return (NetConnectionAttemptResult)ion_net_connect((ion_net_peer)mPeer.Get(), (ion_net_connect_target)&target, passwordData,
														   passwordDataLength, (ion_net_public_key)publicKey, connectionSocketIndex,
														   sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime);
	}

	NetConnectionAttemptResult Connect(const char* host, unsigned short remotePort, const char* passwordData, int passwordDataLength,
									   ion::NetSecure::PublicKey* publicKey = 0, unsigned connectionSocketIndex = 0,
									   unsigned sendConnectionAttemptCount = 6, unsigned timeBetweenSendConnectionAttemptsMS = 1000,
									   ion::TimeMS timeoutTime = 0)
	{
		ConnectTarget target{host, remotePort, };
		return Connect(target, passwordData, passwordDataLength, publicKey, connectionSocketIndex, sendConnectionAttemptCount,
					   timeBetweenSendConnectionAttemptsMS, timeoutTime);
	}

	NetConnectionAttemptResult SendConnectionRequest(ion::ConnectTarget& target, const char* passwordData, int passwordDataLength,
													 ion::NetSecure::PublicKey* publicKey, unsigned connectionSocketIndex,
													 unsigned int extraData, unsigned sendConnectionAttemptCount,
													 unsigned timeBetweenSendConnectionAttemptsMS, ion::TimeMS timeoutTime,
													 NetSocket* socket = nullptr)
	{
		ion_net_send_connection_request((ion_net_peer)mPeer.Get(), (ion_net_connect_target)&target, passwordData, passwordDataLength,
										(ion_net_public_key)publicKey, connectionSocketIndex, extraData, sendConnectionAttemptCount,
										timeBetweenSendConnectionAttemptsMS, timeoutTime, (ion_net_socket)socket);
	}

	bool Ping(ion::ConnectTarget& target, bool onlyReplyOnAcceptingConnections, unsigned connectionSocketIndex = 0)
	{
		ion_net_ping((ion_net_peer)mPeer.Get(), (ion_net_connect_target)&target, onlyReplyOnAcceptingConnections, connectionSocketIndex);
	}

	bool Ping(const char* host, unsigned short remotePort, bool onlyReplyOnAcceptingConnections, unsigned connectionSocketIndex = 0)
	{
		ion::ConnectTarget target{host, remotePort};
		return ion_net_ping((ion_net_peer)mPeer.Get(), (ion_net_connect_target)&target, onlyReplyOnAcceptingConnections,
							connectionSocketIndex);
	}

	void Ping(const NetSocketAddress& address) { ion_net_ping_address((ion_net_peer)mPeer.Get(), (ion_net_socket_address)&address); }

protected:
	static constexpr unsigned int ShutdownWaitTimeMs = 1500;
	void Init(ion::NetInterfaceResource& resource);
	void Deinit(unsigned int blockingTime = ShutdownWaitTimeMs);
};
}  // namespace ion
