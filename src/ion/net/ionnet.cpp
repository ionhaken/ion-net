#include "ionnet.h"

#include <ion/net/NetConnectionLayer.h>
#include <ion/net/NetGeneralPeer.h>
#include <ion/net/NetRawSendCommand.h>
#include <ion/net/NetSdk.h>
#include <ion/net/NetSecurityLayer.h>
#include <ion/net/NetSocket.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/memory/MemoryScope.h>

using namespace ion;
namespace ion
{
struct NetConnectTarget
{
	const char* host;
	unsigned short remote_port;
	ion::NetSocketAddress resolved_address;
};

}  // namespace ion

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

void ion_net_preupdate(ion_net_peer handle, ion_job_scheduler scheduler)
{
	NetInterface& net = *(NetInterface*)handle;

	MemoryScope memoryScope(tag::Network);
	ION_PROFILER_SCOPE(Network, "NetPre");
	const TimeMS now = SteadyClock::GetTimeMS();
#if ION_NET_SIMULATOR
	NetConnectionLayer::UpdateNetworkSim(net.mConnections, now);
#endif
	NetReceptionLayer::ProcessBufferedPackets(net.mReception, net.mControl, net.mRemoteStore, net.mConnections, (JobScheduler*)(scheduler),
											  now);
}

void ion_net_postupdate(ion_net_peer handle, ion_job_scheduler scheduler)
{
	NetInterface& net = *(NetInterface*)handle;

	ion::MemoryScope memoryScope(ion::tag::Network);
	ION_PROFILER_SCOPE(Network, "NetPost");
	const ion::TimeMS now = ion::SteadyClock::GetTimeMS();
	ion::NetControlLayer::Process(net.mControl, net.mRemoteStore, net.mConnections, now);
	ion::NetConnectionLayer::SendOpenConnectionRequests(net.mConnections, net.mControl, net.mRemoteStore, now);
	ion::NetRemoteStoreLayer::Update(net.mRemoteStore, net.mControl, now, (JobScheduler*)(scheduler));
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

	NetRemoteStoreLayer::Init(net.mRemoteStore, parameters, net.mControl.mMemoryResource);
	NetRemoteStoreLayer::FillIPList(net.mRemoteStore);
	net.mRemoteStore.mFirstExternalID = NetUnassignedSocketAddress;

	ion::NetControlLayer::ClearBufferedCommands(net.mControl);
	ion::NetReceptionLayer::Reset(net.mReception, net.mControl);

	int result = ION_NET_CODE_STARTED;
	switch (ion::NetConnectionLayer::BindSockets(net.mConnections, net.mControl.mMemoryResource, parameters))
	{
	case NetBindResult::Success:
	{
		for (unsigned i = 0; i < NetMaximumNumberOfInternalIds; i++)
		{
			if (net.mRemoteStore.mIpList[i] == NetUnassignedSocketAddress)
			{
				break;
			}
			unsigned short port = net.mConnections.mSocketList[0]->mBoundAddress.GetPort();
			net.mRemoteStore.mIpList[i].SetPortHostOrder(port);
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
	const unsigned int systemListSize = net.mRemoteStore.mMaximumNumberOfPeers;

	// This needs to be done first to make sure all disconnects are sent and acked before shutdown can continue
	ion::TimeMS now = ion::SteadyClock::GetTimeMS();
	if (blockDuration > 0)
	{
		for (unsigned int i = 1; i <= systemListSize; i++)
		{
			// remoteSystemList in user thread
			if (net.mRemoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				NetControlLayer::CloseConnectionInternal(net.mControl, net.mRemoteStore, net.mConnections,
														 net.mRemoteStore.mRemoteSystemList[i].mId.load(), true, !IsUpdateThreadRunning,
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
				if (net.mRemoteStore.mRemoteSystemList[j].mMode != NetMode::Disconnected)
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
			ION_DBG("Could not disconnect all remotes gracefully in " << blockDuration << "ms");
		}
	}

	ion::NetControlLayer::StopUpdating(net.mControl);

	// Send thread might leak memory if stopping while there's active data sending, thus,
	// update threads must be stopped before socket threads.
	ion::NetConnectionLayer::StopThreads(net.mConnections);

	ion::NetConnectionLayer::Reset(net.mConnections, net.mControl.mMemoryResource);

	ion::NetRemoteStoreLayer::Deinit(net.mRemoteStore, net.mControl, now);
	ion::NetReceptionLayer::Reset(net.mReception, net.mControl);

	ion::NetControlLayer::Deinit(net.mControl);

	// Free any packets the user didn't deallocate
	net.mControl.mPacketReturnQueue.DequeueAll([&](NetPacket* packet)
											   { ion::NetControlLayer::DeallocateUserPacket(net.mControl, packet); });

	ion::NetControlLayer::ClearBufferedCommands(net.mControl);

	NetReceptionLayer::ClearBanList(net.mReception, net.mControl);
}

int ion_net_send_connection_request(ion_net_peer handle, ion_net_connect_target target_ptr, const char* passwordData,
									int passwordDataLength, ion_net_public_key /* #TODO Support sharing public key before connection */,
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
		ION_DBG("Cannot resolve domain name;host=" << target.mHost << ";port=" << target.mRemotePort << ";IPv="
												   << mPeer->mConnections.mSocketList[connectionSocketIndex]->mBoundAddress.GetIPVersion()
												   << ";bound=" << mPeer->mConnections.mSocketList[connectionSocketIndex]->mBoundAddress);
		return ION_NET_CODE_CANNOT_RESOLVE_DOMAIN_NAME;
	}

	// Already connected?
	bool hasFreeConnections = false;
	for (unsigned int i = 1; i <= net.mRemoteStore.mMaximumNumberOfPeers; i++)
	{
		if (net.mRemoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected)
		{
			if (net.mRemoteStore.mRemoteSystemList[i].mAddress == target.resolved_address)
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

int ion_net_connect_with_socket(ion_net_peer handle, const char* host, unsigned short remotePort, const char* passwordData,
								int passwordDataLength, ion_net_socket socket, ion_net_public_key publicKey,
								unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, uint32_t timeoutTime)
{
	NetInterface& net = *(NetInterface*)handle;
	ION_NET_API_CHECK(host != 0 && socket != 0, ION_NET_CODE_INVALID_PARAMETER, "Invalid parameters");

	if (passwordDataLength > 255)
		passwordDataLength = 255;

	if (passwordData == 0)
		passwordDataLength = 0;
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

	if (passwordDataLength > 255)
		passwordDataLength = 255;

	if (passwordData == 0)
		passwordDataLength = 0;

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
	ION_ASSERT(false, "Cannot find user " << userIndex);
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
		writer.Process(net.mRemoteStore.mGuid);
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
		if (net.mRemoteStore.mRemoteSystemList != nullptr)
		{
			// NOTE: activeSystemListSize might be changed by network update, but invalid remote ids will be ignored anyway if used later.
			*numberOfSystems = ion::Min(*numberOfSystems, net.mRemoteStore.mActiveSystemListSize);
			for (unsigned int i = 0; i < *numberOfSystems; i++)
			{
				auto& system = net.mRemoteStore.mRemoteSystemList[net.mRemoteStore.mActiveSystems[i]];
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
		outIndex = net.mRemoteStore.mNumberOfConnectedSystems;
	}
	*numberOfSystems = outIndex;
	return ION_NET_CODE_OK;
}

unsigned int ion_net_number_of_remote_initiated_connections(ion_net_peer handle)
{
	NetInterface& net = *(NetInterface*)handle;
	return net.mRemoteStore.mNumberOfIncomingConnections;
}

unsigned int ion_net_number_of_connections(ion_net_peer handle)
{
	NetInterface& net = *(NetInterface*)handle;
	return net.mRemoteStore.mNumberOfConnectedSystems;
}
