#include "ionnet.h"

#include <ion/net/NetConnectionLayer.h>
#include <ion/net/NetControlLayer.h>
#include <ion/net/NetExchangeLayer.h>
#include <ion/net/NetGenericPeer.h>
#include <ion/net/NetInterface.h>
#include <ion/net/NetRawSendCommand.h>
#include <ion/net/NetReceptionLayer.h>
#include <ion/net/NetSdk.h>
#include <ion/net/NetSecurityLayer.h>
#include <ion/net/NetSocket.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/memory/MemoryScope.h>

using namespace ion;

static bool ion_net_resolve_target(ion_net_connect_target target_ptr, ion_net_socket socket_ptr)
{
	ion::NetConnectTarget& target = *(ion::NetConnectTarget*)target_ptr;
	ion::NetSocket& socket = *(NetSocket*)socket_ptr;
	bool isOk = true;
	if (!target.resolved_address.IsAssigned() || target.resolved_address.GetIPVersion() != socket.mBoundAddress.GetIPVersion())
	{
		target.resolved_address = NetSocketAddress(target.host, target.remote_port, socket.mBoundAddress.GetIPVersion());
		isOk = target.resolved_address.IsValid();
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

static bool ion_net_send_out_of_band(ion_net_peer handle, const char* host, unsigned short remotePort, const char* data,
									 uint32_t dataLength, unsigned connectionSocketIndex)
{
	if (!ion_net_is_active(handle))
	{
		return false;
	}

	if (host == 0 || host[0] == 0)
	{
		return false;
	}

	NetInterface& net = *(NetInterface*)handle;

	ION_ASSERT(connectionSocketIndex < net.mConnections.mSocketList.Size(), "Not started up");
	ION_ASSERT(
	  dataLength <= (MAX_OFFLINE_DATA_LENGTH + sizeof(unsigned char) + sizeof(ion::Time) + NetGUID::size() + sizeof(NetUnconnectedHeader)),
	  "Size not supported");

	// 34 bytes
	unsigned int realIndex = ion_net_user_index_to_socket_index(handle, connectionSocketIndex);
	NetRawSendCommand cmd(*net.mConnections.mSocketList[realIndex], dataLength + 16);

	{
		auto writer(cmd.Writer());
		writer.Process(NetMessageId::OutOfBandInternal);
		writer.Process(NetUnconnectedHeader);
		writer.Process(net.mExchange.mGuid);
		if (dataLength > 0)
		{
			writer.WriteArray((u8*)data, dataLength);
		}
	}

	NetSocketAddress systemAddress(host, remotePort, net.mConnections.mSocketList[realIndex]->mBoundAddress.GetIPVersion());
	cmd.Dispatch(systemAddress);
	return true;
}

static int ion_net_send_connection_request(ion_net_peer handle, ion_net_connect_target target_ptr, const char* passwordData,
										   int passwordDataLength,
										   ion_net_public_key /* #TODO Support sharing public key before connection */,
										   unsigned connectionSocketIndex, unsigned int extraData, unsigned sendConnectionAttemptCount,
										   unsigned timeBetweenSendConnectionAttemptsMS, uint32_t timeoutTime, ion_net_socket socket_ptr)
{
	NetInterface& net = *(NetInterface*)handle;
	NetConnectTarget& target = *(NetConnectTarget*)target_ptr;

	ION_NET_API_CHECK(timeoutTime <= ion::NetFailureConditionTimeout, INVALID_PARAMETER,
					  "Request connection timeout will be limited to remote failure condition timeout");
	ION_NET_API_CHECK((passwordDataLength > 0 && passwordDataLength <= 256) || (passwordDataLength == 0 && passwordData == nullptr),
					  INVALID_PARAMETER, "Invalid password");
	ION_NET_API_CHECK(target.remote_port != 0, INVALID_PARAMETER, "Invalid port");
	if (!ion_net_resolve_target(target_ptr, (ion_net_socket)net.mConnections.mSocketList[connectionSocketIndex]))
	{
		ION_NET_LOG_VERBOSE("Cannot resolve domain name;host="
							<< target.host << ";port=" << target.remote_port
							<< ";IPv=" << net.mConnections.mSocketList[connectionSocketIndex]->mBoundAddress.GetIPVersion()
							<< ";bound=" << net.mConnections.mSocketList[connectionSocketIndex]->mBoundAddress);
		return ION_NET_CODE_CANNOT_RESOLVE_DOMAIN_NAME;
	}

	// Already connected?
	bool hasFreeConnections = false;
	for (unsigned int i = 1; i <= net.mExchange.mMaximumNumberOfPeers; i++)
	{
		if (net.mExchange.mRemoteSystemList[i].mMode != NetMode::Disconnected)
		{
			if (net.mExchange.mRemoteSystemList[i].mAddress == target.resolved_address)
			{
				return ION_NET_CODE_ALREADY_CONNECTED_TO_ENDPOINT;
			}
		}
		else
		{
			hasFreeConnections = true;
		}
	}

	if (!hasFreeConnections)
	{
		return ION_NET_CODE_NO_FREE_CONNECTIONS;
	}

	int result = ION_NET_CODE_CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS;
#if ION_NET_FEATURE_STREAMSOCKET
	if (((RNS2_Berkley*)(socketList[connectionSocketIndex]))->binding.type == SOCK_STREAM)
	{
		auto* socketLayer = (RNS2_Berkley*)socketList[connectionSocketIndex];
		if (socketLayer->streamSocket)
		{
			return NetConnectionAttemptResult::AlreadyConnectedToEndpoint;
		}
		ION_NET_LOG_INFO("Started connecting to " << systemAddress);
		if (ion::SocketLayer::ConnectSocket(*socketLayer, systemAddress))
		{
			socketLayer->streamSocket = socketLayer->mNativeSocket;
			socketLayer->ConnectingThread(*this, *socketLayer, systemAddress);
			return CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS;
		}
		return CANNOT_RESOLVE_DOMAIN_NAME;
	}
#endif
	net.mConnections.mRequestedConnections.Access(
	  [&](ion::RequestedConnections& data)
	  {
		  if (data.mRequests.Find(target.resolved_address) == data.mRequests.End())
		  {
			  ion::RequestedConnection rcs;

			  rcs.systemAddress = target.resolved_address;
			  rcs.nextRequestTime = ion::SteadyClock::GetTimeMS();
			  rcs.requestsMade = 0;
			  rcs.socket = (NetSocket*)socket_ptr;
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
			  result = ION_NET_CODE_CONNECTION_ATTEMPT_STARTED;
		  }
	  });
	return result;
}

void ion_net_init() { NetInit(); }
void ion_net_deinit() { NetDeinit(); }

ion_net_memory_resource ion_net_create_memory_resource() { return (ion_net_memory_resource)(new NetInterfaceResource(64 * 1024)); }
void ion_net_destroy_memory_resource(ion_net_memory_resource resource) { delete ((NetInterfaceResource*)(resource)); }

ion_net_peer ion_net_create_peer(ion_net_memory_resource resource)
{
	ION_MEMORY_SCOPE(tag::Network);
	NetPtr<NetInterface> net(MakeNetPtr<NetInterface>((NetInterfaceResource&)*resource));
	return (ion_net_peer)net.Release();
}

void ion_net_destroy_peer(ion_net_peer handle)
{
	NetPtr<NetInterface> net((NetInterface*)handle);
	DeleteNetPtr(net);
}

void ion_net_send_loopback(ion_net_peer handle, const char* data, const int length)
{
	NetInterface& net = *(NetInterface*)handle;
	return ion::NetControlLayer::SendLoopback(net.mControl, net.mExchange, data, length);
}

void ion_net_add_to_ban_list(ion_net_peer handle, const char* IP, uint32_t milliseconds)
{
	NetInterface& net = *(NetInterface*)handle;
	NetReceptionLayer::AddToBanList(net.mReception, net.mControl, IP, milliseconds);
}

void ion_net_remove_from_ban_list(ion_net_peer handle, const char* IP)
{
	NetInterface& net = *(NetInterface*)handle;
	NetReceptionLayer::RemoveFromBanList(net.mReception, net.mControl, IP);
}

void ion_net_clear_ban_list(ion_net_peer handle)
{
	NetInterface& net = *(NetInterface*)handle;
	NetReceptionLayer::ClearBanList(net.mReception, net.mControl);
}

void ion_net_set_limit_ip_connection_frequency(ion_net_peer handle, bool b)
{
	NetInterface& net = *(NetInterface*)handle;
	net.mExchange.mLimitConnectionFrequencyFromTheSameIP = b;
}

int ion_net_average_ping(ion_net_peer handle, ion_net_remote_ref remote_ref)
{
	NetInterface& net = *(NetInterface*)handle;
	return NetExchangeLayer::GetAverageRtt(net.mExchange, *(NetAddressOrRemoteRef*)remote_ref);
}

int ion_net_last_ping(ion_net_peer handle, ion_net_remote_ref remote_ref)
{
	NetInterface& net = *(NetInterface*)handle;
	return ion::NetExchangeLayer::GetLastRtt(net.mExchange, *(NetAddressOrRemoteRef*)remote_ref);
}

int ion_net_lowest_ping(ion_net_peer handle, ion_net_remote_ref remote_ref)
{
	NetInterface& net = *(NetInterface*)handle;
	return ion::NetExchangeLayer::GetLowestRtt(net.mExchange, *(NetAddressOrRemoteRef*)remote_ref);
}

void ion_net_set_occasional_ping(ion_net_peer handle, uint32_t time)
{
	NetInterface& net = *(NetInterface*)handle;
	ion::NetExchangeLayer::SetOccasionalPing(net.mExchange, time);
}

void ion_net_set_timeout_time(ion_net_peer handle, uint32_t timeMS, ion_net_socket_address target)
{
	NetInterface& net = *(NetInterface*)handle;
	ion::NetExchangeLayer::SetTimeoutTime(net.mExchange, timeMS, *(NetSocketAddress*)target);
}

uint32_t ion_net_timeout_time(ion_net_peer handle, ion_net_socket_address target)
{
	NetInterface& net = *(NetInterface*)handle;
	return ion::NetExchangeLayer::GetTimeoutTime(net.mExchange, *(NetSocketAddress*)target);
}

bool ion_net_statistics_for_address(ion_net_peer handle, ion_net_socket_address address, ion_net_statistics stats)
{
	NetInterface& net = *(NetInterface*)handle;
	return NetExchangeLayer::GetStatistics(net.mExchange, net.mControl.mMemoryResource, *(NetSocketAddress*)address, *(NetStats*)stats);
}

bool ion_net_statistics_for_remote_id(ion_net_peer handle, ion_net_remote_id_t remote, ion_net_statistics stats)
{
	NetInterface& net = *(NetInterface*)handle;
	return NetExchangeLayer::GetStatistics(net.mExchange, net.mControl.mMemoryResource, NetRemoteId(remote), *(NetStats*)stats);
}

/*void ion_net_statistics_list(ion_net_peer handle, NetVector<NetSocketAddress>& addresses, NetVector<NetGUID>& guids,
							 NetVector<NetStats>& statistics)
{
	NetPtr<NetInterface> net((NetInterface*)handle);
	return NetExchangeLayer::GetStatisticsList(net.mExchange, net.mControl.mMemoryResource, addresses, guids, statistics);
}*/

void ion_net_preupdate(ion_net_peer handle, ion_job_scheduler scheduler)
{
	NetInterface& net = *(NetInterface*)handle;

	MemoryScope memoryScope(tag::Network);
	ION_PROFILER_SCOPE(Network, "NetPre");
	const TimeMS now = SteadyClock::GetTimeMS();
#if ION_NET_SIMULATOR
	NetConnectionLayer::UpdateNetworkSim(net.mConnections, now);
#endif
	NetReceptionLayer::ProcessBufferedPackets(net.mReception, net.mControl, net.mExchange, net.mConnections, (JobScheduler*)(scheduler),
											  now);
}

void ion_net_postupdate(ion_net_peer handle, ion_job_scheduler scheduler)
{
	NetInterface& net = *(NetInterface*)handle;

	ion::MemoryScope memoryScope(ion::tag::Network);
	ION_PROFILER_SCOPE(Network, "NetPost");
	const ion::TimeMS now = ion::SteadyClock::GetTimeMS();
	ion::NetControlLayer::Process(net.mControl, net.mExchange, net.mConnections, now);
	ion::NetConnectionLayer::SendOpenConnectionRequests(net.mConnections, net.mControl, net.mExchange, now);
	ion::NetExchangeLayer::Update(net.mExchange, net.mControl, now, (JobScheduler*)(scheduler));
#if ION_NET_SIMULATOR
	NetConnectionLayer::UpdateNetworkSim(net.mConnections, now);
#endif
}

int ion_net_startup(ion_net_peer handle, const ion_net_startup_parameters pars)
{
	NetInterface& net = *(NetInterface*)handle;
	const ion::NetStartupParameters& parameters(*((const ion::NetStartupParameters*)pars));

	ION_NET_API_CHECK(parameters.mNetSocketDescriptors && parameters.mNetSocketDescriptorCount >= 1,
					  ION_NET_CODE_INVALID_SOCKET_DESCRIPTORS, "Invalid socket descriptors");
	ION_NET_API_CHECK(parameters.mMaxConnections > 0, ION_NET_CODE_INVALID_MAX_CONNECTIONS, "Invalid max connection count");
	if (net.mControl.mIsActive)
	{
		return ION_NET_CODE_ALREADY_STARTED;
	}

	memset(net.mSecurity.mSecretKey.data, 0xAA, ion::NetSecure::SecretKeyLength);
	ion::NetControlLayer::Init(net, parameters);

	NetExchangeLayer::Init(net.mExchange, parameters, net.mControl.mMemoryResource);
	NetExchangeLayer::FillIPList(net.mExchange);
	net.mExchange.mFirstExternalID = NetUnassignedSocketAddress;

	ion::NetControlLayer::ClearBufferedCommands(net.mControl);
	ion::NetReceptionLayer::Reset(net.mReception, net.mControl);

	int result = ION_NET_CODE_STARTED;
	switch (ion::NetConnectionLayer::BindSockets(net.mConnections, net.mControl.mMemoryResource, parameters))
	{
	case NetBindResult::Success:
	{
		for (unsigned i = 0; i < NetMaximumNumberOfInternalIds; i++)
		{
			if (net.mExchange.mIpList[i] == NetUnassignedSocketAddress)
			{
				break;
			}
			unsigned short port = net.mConnections.mSocketList[0]->mBoundAddress.GetPort();
			net.mExchange.mIpList[i].SetPortHostOrder(port);
		}
		if (!NetControlLayer::StartUpdating(net.mControl, net.mReception, parameters.mUpdateThreadPriority))
		{
			result = ION_NET_CODE_FAILED_TO_CREATE_NETWORK_THREAD;
		}
		else if (!NetConnectionLayer::StartThreads(net.mConnections, net.mReception, net.mControl, parameters))
		{
			result = ION_NET_CODE_FAILED_TO_CREATE_NETWORK_THREAD;
		}
		break;
	}
	case NetBindResult::FailedToBind:
		result = ION_NET_CODE_SOCKET_FAILED_TO_BIND;
		break;
	case NetBindResult::FailedToSendTest:
		result = ION_NET_CODE_SOCKET_FAILED_TEST_SEND;
		break;
	}

	if (result != ION_NET_CODE_STARTED)
	{
		ion_net_shutdown(handle, 1, 0, (unsigned int)NetPacketPriority::Low);
	}
	return result;
}

void ion_net_shutdown(ion_net_peer handle, unsigned int blockDuration, unsigned char orderingChannel,
					  unsigned int disconnectionNotificationPriority)
{
	NetInterface& net = *(NetInterface*)handle;
	bool IsUpdateThreadRunning = net.mControl.mUpdateMode != NetPeerUpdateMode::User;
	const unsigned int systemListSize = net.mExchange.mMaximumNumberOfPeers;

	// This needs to be done first to make sure all disconnects are sent and acked before shutdown can continue
	ion::TimeMS now = ion::SteadyClock::GetTimeMS();
	if (blockDuration > 0)
	{
		for (unsigned int i = 1; i <= systemListSize; i++)
		{
			// remoteSystemList in user thread
			if (net.mExchange.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				ION_NET_LOG_VERBOSE("[" << net.mExchange.mGuid << "] Shutdown: Closing connection to "
										<< net.mExchange.mRemoteSystemList[i].guid);
				NetControlLayer::CloseConnectionInternal(net.mControl, net.mExchange, net.mConnections,
														 net.mExchange.mRemoteSystemList[i].mId.load(), true, !IsUpdateThreadRunning,
														 orderingChannel, (NetPacketPriority)disconnectionNotificationPriority);
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
				if (net.mExchange.mRemoteSystemList[j].mMode != NetMode::Disconnected)
				{
					anyActive = true;
					break;
				}
			}

			// If this system is out of packets to send, then stop waiting
			if (anyActive == false)
			{
				break;
			}

			if (IsUpdateThreadRunning)
			{
				ion::NetControlLayer::Trigger(net.mControl);
				ion::Thread::Sleep(ion::NetUpdateInterval * 1000);
			}
			else
			{
				ion_net_preupdate(handle, nullptr);
				ion_net_postupdate(handle, nullptr);
			}
			now = ion::SteadyClock::GetTimeMS();
		}
		if (anyActive)
		{
			ION_NET_LOG_VERBOSE("[" << net.mExchange.mGuid << "] Shutdown: Could not disconnect all remotes gracefully in "
									<< blockDuration << "ms");
		}
	}

	ion::NetControlLayer::StopUpdating(net.mControl);

	// Send thread might leak memory if stopping while there's active data sending, thus,
	// update threads must be stopped before socket threads.
	ion::NetConnectionLayer::StopThreads(net.mConnections);

	ion::NetConnectionLayer::Reset(net.mConnections, net.mControl.mMemoryResource);

	ion::NetExchangeLayer::Deinit(net.mExchange, net.mControl, now);
	ion::NetReceptionLayer::Reset(net.mReception, net.mControl);

	ion::NetControlLayer::Deinit(net.mControl);

	// Free any packets the user didn't deallocate
	net.mControl.mPacketReturnQueue.DequeueAll([&](NetPacket* packet)
											   { ion::NetControlLayer::DeallocateUserPacket(net.mControl, packet); });

	ion::NetControlLayer::ClearBufferedCommands(net.mControl);

	NetReceptionLayer::ClearBanList(net.mReception, net.mControl);
}

int ion_net_connect_with_socket(ion_net_peer handle, const char* host, unsigned short remotePort, const char* passwordData,
								int passwordDataLength, ion_net_socket socket, ion_net_public_key publicKey,
								unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, uint32_t timeoutTime)
{
	NetInterface& net = *(NetInterface*)handle;
	ION_NET_API_CHECK(host != 0 && socket != 0, ION_NET_CODE_INVALID_PARAMETER, "Invalid parameters");
	passwordDataLength = passwordData == nullptr ? 0 : Min(passwordDataLength, 255);
	ion::NetConnectTarget target{host, remotePort};
	return ion_net_send_connection_request(handle, (ion_net_connect_target)&target, passwordData, passwordDataLength, publicKey, 0, 0,
										   sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime, socket);
}

int ion_net_connect(ion_net_peer handle, ion_net_connect_target target_ptr, const char* passwordData, int passwordDataLength,
					ion_net_public_key publicKey, unsigned connectionSocketIndex, unsigned sendConnectionAttemptCount,
					unsigned timeBetweenSendConnectionAttemptsMS, uint32_t timeoutTime)
{
	NetInterface& net = *(NetInterface*)handle;
	NetConnectTarget& target = *(NetConnectTarget*)target_ptr;

	ION_NET_API_CHECK(target.host != 0, ION_NET_CODE_INVALID_PARAMETER, "Invalid host");
	ION_NET_API_CHECK(connectionSocketIndex < net.mConnections.mSocketList.Size(), ION_NET_CODE_INVALID_PARAMETER, "Invalid socket");
	ION_NET_API_CHECK(target.remote_port != 0, ION_NET_CODE_INVALID_PARAMETER, "Invalid port");
	connectionSocketIndex = ion_net_user_index_to_socket_index(handle, connectionSocketIndex);
	passwordDataLength = passwordData == nullptr ? 0 : Min(passwordDataLength, 255);
	return ion_net_send_connection_request(handle, target_ptr, passwordData, passwordDataLength, publicKey, connectionSocketIndex, 0,
										   sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime, nullptr);
}

unsigned int ion_net_user_index_to_socket_index(ion_net_peer handle, unsigned int userIndex)
{
	NetInterface& net = *(NetInterface*)handle;
	unsigned int i;
	for (i = 0; i < net.mConnections.mSocketList.Size(); i++)
	{
		if (net.mConnections.mSocketList[i]->userConnectionSocketIndex == userIndex)
		{
			return i;
		}
	}
	return (unsigned int)-1;
}

bool ion_net_ping(ion_net_peer handle, ion_net_connect_target target_ptr, bool onlyReplyOnAcceptingConnections,
				  unsigned connectionSocketIndex)
{
	NetInterface& net = *(NetInterface*)handle;
	NetConnectTarget& target = *(NetConnectTarget*)target_ptr;
	ION_NET_API_CHECK(target.host != 0, false, "Invalid host");
	ION_NET_API_CHECK(target.remote_port != 0, false, "Invalid host");
	ION_NET_API_CHECK(connectionSocketIndex < net.mConnections.mSocketList.Size(), false, "Invalid socket");

	// No timestamp for 255.255.255.255
	unsigned int realIndex = ion_net_user_index_to_socket_index(handle, connectionSocketIndex);
	if (!ion_net_resolve_target(target_ptr, (ion_net_socket)net.mConnections.mSocketList[realIndex]))
	{
		return false;
	}
	ion::NetRawSendCommand pingMessage(*net.mConnections.mSocketList[realIndex]);
	{
		ByteWriter writer(pingMessage.Writer());
		writer.Process(onlyReplyOnAcceptingConnections ? NetMessageId::UnconnectedPingOpenConnections : NetMessageId::UnconnectedPing);
		writer.Process(NetUnconnectedHeader);
		ion::Time time = ion::SteadyClock::GetTimeMS();
		writer.Process(time);
		writer.Process(net.mExchange.mGuid);
	}
	pingMessage.Dispatch(target.resolved_address);

	return true;
}
void ion_net_ping_address(ion_net_peer handle, ion_net_socket_address address)
{
	NetInterface& net = *(NetInterface*)handle;
	auto bcs(ion::MakeArenaPtr<ion::NetCommand>(&net.mControl.mMemoryResource, *(ion::NetSocketAddress*)address));
	if (bcs.Get() == nullptr)
	{
		ion::NotifyOutOfMemory();
		return;
	}
	bcs->mCommand = ion::NetCommandType::PingAddress;
	net.mControl.mBufferedCommands.Enqueue(std::move(bcs));
}

void ion_net_add_to_security_exceptions_list(ion_net_peer handle, const char* str)
{
	NetInterface& net = *(NetInterface*)handle;
	ion::NetSecurityLayer::AddToSecurityExceptionList(net.mSecurity, str);
}

void ion_net_remove_from_security_exceptions_list(ion_net_peer handle, const char* str)
{
	NetInterface& net = *(NetInterface*)handle;
	ion::NetSecurityLayer::RemoveFromSecurityExceptionList(net.mSecurity, str);
}

bool ion_net_is_in_security_exception_list(ion_net_peer handle, const char* str)
{
	NetInterface& net = *(NetInterface*)handle;
	return ion::NetSecurityLayer::IsInSecurityExceptionList(net.mSecurity, str);
}

void ion_net_get_incoming_password(ion_net_peer handle, char* passwordData, int* passwordDataLength)
{
	NetInterface& net = *(NetInterface*)handle;
	ion::NetReceptionLayer::GetIncomingPassword(net.mReception, passwordData, passwordDataLength);
}

void ion_net_set_incoming_password(ion_net_peer handle, const char* passwordData, int passwordDataLength)
{
	NetInterface& net = *(NetInterface*)handle;
	ion::NetReceptionLayer::SetIncomingPassword(net.mReception, passwordData, passwordDataLength);
}

bool ion_net_is_active(ion_net_peer handle) { return handle != nullptr && (*(NetInterface*)handle).mControl.mIsActive; }

int ion_net_get_connection_list(ion_net_peer handle, ion_net_remote_id remote_ids_ptr, unsigned int* numberOfSystems)
{
	ION_NET_API_CHECK(ion_net_is_active(handle), ION_NET_CODE_NOT_ACTIVE, "Not Active");
	ION_NET_API_CHECK(numberOfSystems != nullptr, ION_NET_CODE_FAIL, "Number of systems must be valid");

	NetInterface& net = *(NetInterface*)handle;
	ion::NetRemoteId* remoteIds = (ion::NetRemoteId*)remote_ids_ptr;

	unsigned int outIndex = 0;
	if (remoteIds)
	{
		if (net.mExchange.mRemoteSystemList != nullptr)
		{
			// NOTE: activeSystemListSize might be changed by network update, but invalid remote ids will be ignored anyway if used later.
			*numberOfSystems = ion::Min(*numberOfSystems, net.mExchange.mActiveSystemListSize);
			for (unsigned int i = 0; i < *numberOfSystems; i++)
			{
				auto& system = net.mExchange.mRemoteSystemList[net.mExchange.mActiveSystems[i]];
				if (system.mMode == NetMode::Connected)
				{
					remoteIds[outIndex] = system.mId;
					outIndex++;
				}
			}
		}
	}
	else
	{
		outIndex = net.mExchange.mNumberOfConnectedSystems;
	}
	*numberOfSystems = outIndex;
	return ION_NET_CODE_OK;
}

unsigned int ion_net_number_of_remote_initiated_connections(ion_net_peer handle)
{
	NetInterface& net = *(NetInterface*)handle;
	return net.mExchange.mNumberOfIncomingConnections;
}

unsigned int ion_net_number_of_connections(ion_net_peer handle)
{
	NetInterface& net = *(NetInterface*)handle;
	return net.mExchange.mNumberOfConnectedSystems;
}

unsigned int ion_net_mtu_size(ion_net_peer handle, ion_net_remote_ref remote_ref)
{
	NetInterface& net = *(NetInterface*)handle;
	const NetAddressOrRemoteRef& target = *(NetAddressOrRemoteRef*)remote_ref;
	const ion::NetRemoteSystem* rss = NetExchangeLayer::GetRemoteSystem(net.mExchange, target, false, true);
	if (rss)
	{
		return rss->MTUSize;
	}
	return NetPreferedMtuSize[NetNumMtuSizes - 1];
}

bool ion_net_advertise_system(ion_net_peer handle, const char* host, unsigned short remotePort, const char* data, int dataLength,
							  unsigned connectionSocketIndex)
{
	ByteBuffer<> bs;
	{
		ByteWriter writer(bs);
		writer.Write(NetMessageId::AdvertiseSystem);
		writer.WriteArray((const unsigned char*)data, dataLength);
	}
	return ion_net_send_out_of_band(handle, host, remotePort, (const char*)bs.Begin(), bs.Size(), connectionSocketIndex);
}

ion_net_packet ion_net_allocate_packet(ion_net_peer handle, unsigned dataSize)
{
	NetInterface& net = *(NetInterface*)handle;
	ion::NetPacket* p = ion::NetControlLayer::AllocateUserPacket(net.mControl, dataSize);
	p->mSource = nullptr;
	p->mLength = dataSize;
	p->mGUID = NetGuidUnassigned;
	p->mRemoteId = NetRemoteId();
	return (ion_net_packet)p;
}

void ion_net_deallocate_packet(ion_net_peer handle, ion_net_packet packet)
{
	if (packet == nullptr)
	{
		return;
	}
	NetInterface& net = *(NetInterface*)handle;
	ion::NetControlLayer::DeallocateUserPacket(net.mControl, (NetPacket*)packet);
}

int ion_net_connection_state(ion_net_peer handle, ion_net_remote_ref remote_ref_ptr)
{
	const NetAddressOrRemoteRef& remoteRef = *(NetAddressOrRemoteRef*)(remote_ref_ptr);
	ION_ASSERT(!remoteRef.IsUndefined(), "Invalid connection");

	NetInterface& net = *(NetInterface*)handle;
	if (remoteRef.mAddress != NetUnassignedSocketAddress)
	{
		bool isPending;
		net.mConnections.mRequestedConnections.Access([&](const ion::RequestedConnections& data)
													  { isPending = data.mRequests.Find(remoteRef.mAddress) != data.mRequests.End(); });
		if (isPending)
		{
			return ION_NET_CODE_STATE_PENDING;
		}
	}

	NetRemoteSystem* remote = ion::NetExchangeLayer::GetRemoteSystem(net.mExchange, remoteRef, false, false);

	if (remote == nullptr)
		return ION_NET_CODE_STATE_NOT_CONNECTED;

	switch (remote->mMode)
	{
	case NetMode::Disconnected:
		return ION_NET_CODE_STATE_DISCONNECTED;
	case NetMode::DisconnectAsapSilently:
		return ION_NET_CODE_STATE_SILENTLY_DISCONNECTING;
	case NetMode::DisconnectAsap:
	case NetMode::DisconnectAsapMutual:
	case NetMode::DisconnectOnNoAck:
		return ION_NET_CODE_STATE_DISCONNECTING;
	case NetMode::RequestedConnection:
		return ION_NET_CODE_STATE_CONNECTING;
	case NetMode::HandlingConnectionRequest:
		return ION_NET_CODE_STATE_CONNECTING;
	case NetMode::UnverifiedSender:
		return ION_NET_CODE_STATE_CONNECTING;
	case NetMode::Connected:
		return ION_NET_CODE_STATE_CONNECTED;
	default:
		return ION_NET_CODE_STATE_NOT_CONNECTED;
	}

	return ION_NET_CODE_STATE_NOT_CONNECTED;
}

void ion_net_close_connection(ion_net_peer handle, ion_net_remote_ref remote_ref, bool sendDisconnectionNotification,
							  unsigned char orderingChannel, int disconnectionNotificationPriority)
{
	const NetAddressOrRemoteRef& target = *(NetAddressOrRemoteRef*)(remote_ref);
	if (target.IsUndefined())
	{
		return;
	}

	NetInterface& net = *(NetInterface*)handle;
	NetControlLayer::CloseConnectionInternal(net.mControl, net.mExchange, net.mConnections, target, sendDisconnectionNotification, false,
											 orderingChannel, (NetPacketPriority)disconnectionNotificationPriority);

	if (sendDisconnectionNotification == false && ion_net_connection_state(handle, remote_ref) == ION_NET_CODE_STATE_CONNECTED)
	{
		// Dead connection
		NetPacket* packet = (NetPacket*)ion_net_allocate_packet(handle, sizeof(char));
		packet->Data()[0] = NetMessageId::ConnectionLost;

		const NetRemoteSystem* remote = NetExchangeLayer::GetRemoteSystem(net.mExchange, target, true, false);
		packet->mAddress = remote->mAddress;
		packet->mGUID = remote->guid;
		packet->mRemoteId = remote->mId;

		ion_net_push_packet(handle, (ion_net_packet)packet);
	}
}

void ion_net_push_packet(ion_net_peer handle, ion_net_packet packet)
{
	NetInterface& net = *(NetInterface*)handle;
	net.mControl.mPacketReturnQueue.Enqueue(std::move((NetPacket*)packet));
}

int ion_net_is_banned(ion_net_peer handle, const char* IP)
{
	NetInterface& net = *(NetInterface*)handle;
	return ion::NetReceptionLayer::IsBanned(net.mReception, net.mControl, IP, ion::SteadyClock::GetTimeMS()) != NetBanStatus::NotBanned;
}

void ion_net_external_id(ion_net_peer handle, ion_net_socket_address in, ion_net_socket_address out)
{
	NetInterface& net = *(NetInterface*)handle;
	ion::NetExchangeLayer::GetExternalID(net.mExchange, *(ion::NetSocketAddress*)in, *(ion::NetSocketAddress*)out);
}

void ion_net_internal_id(ion_net_peer handle, ion_net_socket_address in, const int index, ion_net_socket_address out)
{
	NetInterface& net = *(NetInterface*)handle;
	ion::NetExchangeLayer::GetInternalID(net.mExchange, *(ion::NetSocketAddress*)out, *(ion::NetSocketAddress*)in, index);
}

void ion_net_set_data_transfer_security_level(ion_net_peer handle, uint8_t level)
{
	NetInterface& net = *(NetInterface*)handle;
	net.mExchange.mDataTransferSecurity = NetDataTransferSecurity(level);
}

void ion_net_set_maximum_incoming_connections(ion_net_peer handle, unsigned int numberAllowed)
{
	NetInterface& net = *(NetInterface*)handle;
	net.mExchange.mMaximumIncomingConnections = SafeRangeCast<uint16_t>(numberAllowed);
}

void ion_net_set_socket_big_data_key_code(ion_net_peer handle, unsigned int idx, const unsigned char* data)
{
	NetInterface& net = *(NetInterface*)handle;
	memcpy(net.mConnections.mSocketList[idx]->mBigDataKey.data, data, 32);
}

unsigned int ion_net_maximum_incoming_connections(ion_net_peer handle)
{
	NetInterface& net = *(NetInterface*)handle;
	return net.mExchange.mMaximumIncomingConnections;
}

unsigned int ion_net_maximum_number_of_peers(ion_net_peer handle)
{
	NetInterface& net = *(NetInterface*)handle;
	return net.mExchange.mMaximumNumberOfPeers;
}

void ion_net_cancel_connection_attempt(ion_net_peer handle, ion_net_socket_address address_ptr)
{
	NetInterface& net = *(NetInterface*)handle;
	net.mConnections.mRequestedConnections.Access([&](ion::RequestedConnections& data)
												  { data.mCancels.Add(*(NetSocketAddress*)address_ptr); });
}

void ion_net_set_time_synchronization(ion_net_peer handle, ion_net_remote_ref remote, ion_net_global_clock srcClock)
{
	NetInterface& net = *(NetInterface*)handle;
	NetAddressOrRemoteRef& systemIdentifier = *(NetAddressOrRemoteRef*)remote;
	NetRemoteId remoteId = systemIdentifier.mRemoteId;
	if (!remoteId.IsValid())
	{
		remoteId = NetExchangeLayer::GetRemoteIdThreadSafe(net.mExchange, systemIdentifier.mAddress);
		if (!remoteId.IsValid())
		{
			return;
		}
	}

	auto bcs(ion::MakeArenaPtrRaw<ion::NetCommand>(&net.mControl.mMemoryResource, NetCommandHeaderSize + sizeof(void*), remoteId));
	bcs->mCommand = srcClock ? NetCommandType::EnableTimeSync : NetCommandType::DisableTimeSync;
	if (srcClock)
	{
		memcpy(&bcs->mData, reinterpret_cast<char*>(&srcClock), sizeof(ion::GlobalClock*));
	}

	net.mControl.mBufferedCommands.Enqueue(std::move(bcs));
}

bool ion_net_set_offline_ping_response(ion_net_peer handle, const char* data, const unsigned int length)
{
	ION_NET_API_CHECK(length < 400, false, "Too large response");

	NetInterface& net = *(NetInterface*)handle;
	memcpy(net.mConnections.mOffline.mResponse.Data(), data, length);
	net.mConnections.mOffline.mResponseLength = ion::SafeRangeCast<uint16_t>(length);
	return true;
}

void ion_net_offline_ping_response(ion_net_peer handle, char** data, unsigned int* length)
{
	NetInterface& net = *(NetInterface*)handle;
	*data = net.mConnections.mOffline.mResponse.Data();
	*length = net.mConnections.mOffline.mResponseLength;
}

ion_net_guid_t ion_net_my_guid(ion_net_peer handle)
{
	NetInterface& net = *(NetInterface*)handle;
	return net.mExchange.mGuid.Raw();
}

void ion_net_socket_bound_address(ion_net_peer handle, const int socketIndex, ion_net_socket_address out)
{
	NetInterface& net = *(NetInterface*)handle;
	ion::AutoLock<ion::Mutex> lock(net.mConnections.mSocketListMutex);
	NetSocketAddress& outAddress = *(NetSocketAddress*)out;
	outAddress = socketIndex < int(net.mConnections.mSocketList.Size()) ? net.mConnections.mSocketList[socketIndex]->mBoundAddress
																		: NetUnassignedSocketAddress;
}

void ion_net_socket_first_bound_address(ion_net_peer handle, ion_net_socket_address out)
{
	NetInterface& net = *(NetInterface*)handle;
	NetSocketAddress& outAddress = *(NetSocketAddress*)out;
	outAddress = net.mConnections.mSocketListFirstBoundAddress;
}

ion_net_remote_id_t ion_net_guid_to_remote_id(ion_net_peer handle, ion_net_guid_t guid)
{
	NetInterface& net = *(NetInterface*)handle;
	return (ion_net_remote_id_t)ion::NetExchangeLayer::GetRemoteIdThreadSafe(net.mExchange, (NetGUID)guid).UInt32();
}

ion_net_guid_t ion_net_remote_id_to_guid(ion_net_peer handle, ion_net_remote_id_t remote)
{
	NetInterface& net = *(NetInterface*)handle;
	NetRemoteId& remoteId = *(NetRemoteId*)&remote;
	return ion::NetExchangeLayer::GetGUIDThreadSafe(net.mExchange, remoteId).Raw();
}

void ion_net_guid_to_address(ion_net_peer handle, ion_net_guid_t input, ion_net_socket_address out)
{
	NetInterface& net = *(NetInterface*)handle;
	NetExchangeLayer::GetSocketAddressThreadSafe(net.mExchange, (NetGUID)input, *(NetSocketAddress*)out);
}

void ion_net_remote_id_to_address(ion_net_peer handle, ion_net_remote_id_t remote, ion_net_socket_address out)
{
	NetInterface& net = *(NetInterface*)handle;
	NetRemoteId& remoteId = *(NetRemoteId*)&remote;
	ion::NetExchangeLayer::GetSocketAddressThreadSafe(net.mExchange, remoteId, *(NetSocketAddress*)out);
}

ion_net_guid_t ion_net_address_to_guid(ion_net_peer handle, ion_net_socket_address address_ptr)
{
	NetInterface& net = *(NetInterface*)handle;
	NetSocketAddress& address = *(NetSocketAddress*)address_ptr;
	if (!address.IsAssigned())
	{
		return net.mExchange.mGuid.Raw();
	}

	NetRemoteId id = NetExchangeLayer::GetRemoteIdThreadSafe(net.mExchange, address, false);
	return NetExchangeLayer::GetGUIDThreadSafe(net.mExchange, id).Raw();
}

void ion_net_local_ip(ion_net_peer handle, unsigned int index, char* strOut)
{
	if (!handle || index >= ion_net_number_of_addresses(handle))
	{
		strOut[0] = 0;
		return;
	}
	if (!ion_net_is_active(handle))
	{
		NetInterface& net = *(NetInterface*)handle;
		NetExchangeLayer::FillIPList(net.mExchange);
	}
	NetInterface& net = *(NetInterface*)handle;
	net.mExchange.mIpList[index].ToString(strOut, 128, false);
}

bool ion_net_is_local_ip(ion_net_peer handle, const char* ip)
{
	if (ip == 0 || ip[0] == 0)
	{
		return false;
	}

	if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "localhost") == 0)
	{
		return true;
	}

	NetInterface& net = *(NetInterface*)handle;
	int num = ion_net_number_of_addresses(handle);
	int i;
	char str[128];
	for (i = 0; i < num; i++)
	{
		net.mExchange.mIpList[i].ToString(str, 128, false);
		if (strcmp(ip, str) == 0)
			return true;
	}

	return false;
}

void ion_net_allow_connection_response_ip_migration(ion_net_peer handle, bool allow)
{
	NetInterface& net = *(NetInterface*)handle;
	net.mReception.mAllowConnectionResponseIPMigration = allow;
}

void ion_net_send_ttl(ion_net_peer handle, const char* host, unsigned short remotePort, int ttl, unsigned connectionSocketIndex)
{
	unsigned int realIndex = ion_net_user_index_to_socket_index(handle, connectionSocketIndex);

	NetInterface& net = *(NetInterface*)handle;
	NetRawSendCommand ttlMessage(*net.mConnections.mSocketList[realIndex]);
	{
		ByteWriter writer(ttlMessage.Writer());
		writer.WriteKeepCapacity(uint16_t(0));	// fake data
	}
	ttlMessage.Parameters().TTL(ttl);
	ttlMessage.Dispatch(NetSocketAddress(host, remotePort, net.mConnections.mSocketList[realIndex]->mBoundAddress.GetIPVersion()));
}

void ion_net_change_system_address(ion_net_peer handle, ion_net_remote_id_t remote_id, ion_net_socket_address address_ptr)
{
	NetInterface& net = *(NetInterface*)handle;
	NetSocketAddress& address = *(NetSocketAddress*)address_ptr;
	auto bcs(ion::MakeArenaPtrRaw<ion::NetCommand>(&net.mControl.mMemoryResource, NetCommandHeaderSize + sizeof(NetRemoteId), address));
	bcs->mCommand = NetCommandType::ChangeSystemAddress;
	*reinterpret_cast<NetRemoteId*>(&bcs->mData) = *(NetRemoteId*)&remote_id;
	net.mControl.mBufferedCommands.Enqueue(std::move(bcs));
}

void ion_net_set_logging_level(int level) { NetManager::mLoggingLevel = level; }

void ion_net_apply_network_simulator([[maybe_unused]] ion_net_peer handle, [[maybe_unused]] ion_net_simulator_settings settings)
{
#if ION_NET_SIMULATOR
	NetInterface& net = *(NetInterface*)handle;
	net.mConnections.mDefaultNetworkSimulatorSettings = *(NetworkSimulatorSettings*)settings;
	ion::AutoLock<ion::Mutex> lock(net.mConnections.mSocketListMutex);
	ion::ForEach(net.mConnections.mSocketList,
				 [&](ion::NetSocket* socket) { socket->mNetworkSimulator.Configure(net.mConnections.mDefaultNetworkSimulatorSettings); });
#endif
}

bool ion_net_is_network_simulator_active()
{
#if ION_NET_SIMULATOR
	return true;
#else
	return false;
#endif
}

unsigned ion_net_number_of_addresses(ion_net_peer handle)
{
	if (!handle)
	{
		return 0;
	}
	if (!ion_net_is_active(handle))
	{
		NetInterface& net = *(NetInterface*)handle;
		NetExchangeLayer::FillIPList(net.mExchange);
	}
	NetInterface& net = *(NetInterface*)handle;
	return NetExchangeLayer::GetNumberOfAddresses(net.mExchange);
}

bool ion_net_is_ipv6_only(ion_net_peer handle)
{
	if (!handle)
	{
		return false;
	}
	if (!ion_net_is_active(handle))
	{
		NetInterface& net = *(NetInterface*)handle;
		NetExchangeLayer::FillIPList(net.mExchange);
	}
	NetInterface& net = *(NetInterface*)handle;
	return NetExchangeLayer::IsIPV6Only(net.mExchange);
}

int ion_net_send(ion_net_peer handle, const char* data, const int length, uint8_t priority, uint8_t reliability, char orderingChannel,
				 ion_net_remote_ref remote_ref, bool broadcast)
{
	NetInterface& net = *(NetInterface*)handle;
	return ion::NetControlLayer::Send(net.mControl, net.mExchange, data, length, (NetPacketPriority)priority,
									  (NetPacketReliability)reliability, orderingChannel, *(NetAddressOrRemoteRef*)remote_ref, broadcast);
}
