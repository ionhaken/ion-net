#include <ion/net/NetCommand.h>
#include <ion/net/NetConnectionLayer.h>
#include <ion/net/NetConnections.h>
#include <ion/net/NetControl.h>
#include <ion/net/NetControlLayer.h>
#include <ion/net/NetExchangeLayer.h>
#include <ion/net/NetGlobalClock.h>
#include <ion/net/NetRemote.h>
#include <ion/net/NetSecure.h>
#include <ion/net/NetSendCommand.h>
#include <ion/net/NetSocketLayer.h>
#include <ion/net/NetStartupParameters.h>
#include <ion/net/NetTransportLayer.h>

#include <ion/arena/ArenaAllocator.h>

#include <ion/container/ForEach.h>
#include <ion/container/Sort.h>
#include <ion/container/Vector.h>

#include <ion/debug/Profiling.h>

#include <ion/jobs/JobIntermediate.h>
#include <ion/jobs/JobScheduler.h>

#include <ion/string/Hex.h>

namespace ion::NetExchangeLayer
{

namespace
{

// Checks has any channel waiting to relay data - Used for checking disconnects, no need to cache
bool IsOutgoingDataWaiting(const NetTransport& transport)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(transport.mGuard);
	for (auto iter = transport.mOrderedChannels.begin(); iter != transport.mOrderedChannels.end(); ++iter)
	{
		/*
		 * https://github-com.translate.goog/skywind3000/kcp/wiki?_x_tr_sl=zh-CN&_x_tr_tl=en&_x_tr_hl=fi
		 * https://github-com.translate.goog/skywind3000/kcp/wiki/Flow-Control-for-Users?_x_tr_sl=zh-CN&_x_tr_tl=en&_x_tr_hl=fi
		 * when ikcp_waitsnd returns a value above a certain limit, you should disconnect the remotes as they don't have the ability to
		 * receive them. .*/
		if (iter->WaitSend() > 0)
		{
			return true;
		}
	}
	return false;
}

// Checks has any channel waiting to receive data - Used for checking disconnects, no need to cache
bool AreAcksWaiting(const NetTransport& transport)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(transport.mGuard);
	for (auto iter = transport.mOrderedChannels.begin(); iter != transport.mOrderedChannels.end(); ++iter)
	{
		if (iter->WaitRcv() > 0)
		{
			return true;
		}
	}
	return false;
}

ion::NetGUID GenerateGUID(const NetExchange& exchange)
{
	ion::NetGUID guid;
	do
	{
		ion::NetSecure::Random((unsigned char*)&guid.Raw(), sizeof(guid.Raw()));
	} while (guid == NetGuidUnassigned || guid == NetGuidAuthority ||
			 GetRemoteSystemFromGUID(exchange, guid, false) != NetGUID::InvalidNetRemoteIndex || (guid == exchange.mGuid));
	return guid;
}

void DataMetricsSnapshot(ion::NetInterfaceResource& pool, NetRemoteSystem& system, NetStats& rns)
{
	if (!system.mMetrics)
	{
		if (!system.mResource)
		{
			rns = NetStats();
			return;
		}

		ion::AutoLock lock(system.mMetrixInitMutex);
		if (system.mMetrics == nullptr)
		{
			system.mMetrics = ion::MakeArenaPtr<ion::DataMetrics>(&pool);
		}
	}
	system.mMetrics->Snapshot(rns);
}

inline Op NextOperation(NetExchange& exchange, NetRemoteSystem& remoteSystem, ion::TimeMS currentTime)
{
	switch (remoteSystem.mMode)
	{
	case NetMode::Disconnected:
		ION_UNREACHABLE("Unexpected state");
		break;
	case NetMode::Connected:
		if (ion::TimeSince(currentTime, remoteSystem.timeLastDatagramArrived) <= remoteSystem.timeoutTime)
		{
			if (ion::TimeSince(currentTime, remoteSystem.lastReliableSend) >= remoteSystem.timeoutTime / 2 &&
				!AreAcksWaiting(remoteSystem.mTransport))
			{
				// If no reliable packets are waiting for an ack, do a one byte reliable send so that disconnections are
				// noticed

				return Op::KeepAliveReliable;
			}
			else
			{
				ion::NetRoundTripTime pingFreq =
				  remoteSystem.timeSync.IsActive() ? remoteSystem.timeSync.GetPingFrequency() : exchange.mOccasionalPing;
				if (!remoteSystem.mIsRemoteInitiated &&
					ion::TimeSince(currentTime, remoteSystem.timeLastDatagramArrived) > remoteSystem.timeoutTime / 2)
				{
					// Ping to keep connection alive.
					pingFreq = ion::Min(pingFreq, ion::NetKeepAlivePingInterval);
				}

				if (TimeSince(currentTime, remoteSystem.pingTracker.GetLastPingTime()) > pingFreq)
				{
					return Op::KeepAliveUnreliable;
				}
			}
			return Op::None;
		}
		break;
	case NetMode::DisconnectAsapSilently:  // As disconnect ASAP, but do not inform user.
		if (!IsOutgoingDataWaiting(remoteSystem.mTransport) ||
			ion::TimeSince(currentTime, remoteSystem.lastReliableSend) > remoteSystem.timeoutTime)
		{
			return Op::ConnectionLostSilent;
		}
		return Op::None;
	case NetMode::DisconnectAsap:  // We wanted to disconnect
		if (IsOutgoingDataWaiting(remoteSystem.mTransport) &&
			ion::TimeSince(currentTime, remoteSystem.lastReliableSend) <= remoteSystem.timeoutTime)
		{
			return Op::None;
		}
		break;
	case NetMode::DisconnectAsapMutual:
		if ((AreAcksWaiting(remoteSystem.mTransport) || IsOutgoingDataWaiting(remoteSystem.mTransport)) &&
			ion::TimeSince(currentTime, remoteSystem.lastReliableSend) <= remoteSystem.timeoutTime)
		{
			return Op::None;
		}
		break;
	case NetMode::DisconnectOnNoAck:  // They wanted to disconnect
		if (AreAcksWaiting(remoteSystem.mTransport) &&
			ion::TimeSince(currentTime, remoteSystem.timeLastDatagramArrived) <= remoteSystem.timeoutTime)
		{
			return Op::None;
		}
		break;
	case NetMode::RequestedConnection:
		if (ion::TimeSince(currentTime, remoteSystem.connectionTime) <= remoteSystem.timeoutTime)
		{
			return Op::None;
		}
		break;
	case NetMode::UnverifiedSender:
		if (ion::TimeSince(currentTime, remoteSystem.connectionTime) > ion::NetFailureConditionTimeout)
		{
			return Op::ConnectionLostSilent;
		}
		return Op::None;
	case NetMode::HandlingConnectionRequest:  // This is on reliable link
		if (ion::TimeSince(currentTime, remoteSystem.timeLastDatagramArrived) > remoteSystem.timeoutTime)
		{
			return Op::ConnectionLostSilent;
		}
		return Op::None;
	}
	return Op::ConnectionLost;
}

void UpdateRemote(NetControl& control, NetExchange& exchange, ion::TimeMS currentTime, ion::NetRemoteIndex systemIndex,
				  Operations& operations)
{
	ION_PROFILER_SCOPE(Network, "Remote System");
	NetRemoteSystem& remoteSystem = exchange.mRemoteSystemList[systemIndex];
	ION_ASSERT(remoteSystem.mAddress != NetUnassignedSocketAddress, "Invalid system");
	currentTime = NetTransportLayer::Update(remoteSystem.mTransport, control, remoteSystem, currentTime);

	if (remoteSystem.mMetrics)
	{
		remoteSystem.mMetrics->Update(currentTime);
	}

	Op op = NextOperation(exchange, remoteSystem, currentTime);
	if (op != Op::None)
	{
		operations.list.Add({systemIndex, op});
	}
}
}  // namespace

void Update(NetExchange& exchange, NetControl& control, ion::TimeMS now, ion::JobScheduler* js)
{
	ion::JobIntermediate<Operations> operations;
	if (js)
	{
		js->ParallelFor(exchange.mActiveSystems.Get(), exchange.mActiveSystems.Get() + exchange.mActiveSystemListSize, operations,
						[&](ion::NetRemoteIndex systemIndex, Operations& outOperations)
						{ UpdateRemote(control, exchange, now, systemIndex, outOperations); });
	}
	else
	{
		ion::ForEachPartial(exchange.mActiveSystems.Get(), exchange.mActiveSystems.Get() + exchange.mActiveSystemListSize,
							[&](ion::NetRemoteIndex systemIndex)
							{ UpdateRemote(control, exchange, now, systemIndex, operations.GetMain()); });
	}
	now = SteadyClock::GetTimeMS();

	bool sortActiveSystems = false;
	operations.ForEachContainer(
	  [&](Operations& operations)
	  {
		  ion::ForEach(
			operations.list,
			[&](SystemOp& systemOp)
			{
				NetRemoteSystem& remoteSystem = exchange.mRemoteSystemList[systemOp.system];
				switch (systemOp.op)
				{
				case Op::None:
					ION_UNREACHABLE("No op");
					break;
				case Op::KeepAliveReliable:
					remoteSystem.pingTracker.OnPing(now);
					NetControlLayer::PingInternal(control, exchange, remoteSystem.mAddress, true, NetPacketReliability::Reliable, now);
					break;

				case Op::KeepAliveUnreliable:
					remoteSystem.pingTracker.OnPing(now);
					NetControlLayer::PingInternal(control, exchange, remoteSystem.mAddress, true, NetPacketReliability::Unreliable, now);
					break;

				case Op::ConnectionLost:
				{
					NetPacket* packet = ion::NetControlLayer::AllocateUserPacket(control, sizeof(char));
					packet->mSource = nullptr;
					packet->mLength = sizeof(char);

					if (remoteSystem.mMode == NetMode::RequestedConnection)
					{
						packet->Data()[0] = NetMessageId::ConnectionAttemptFailed;
					}
					else if (remoteSystem.mMode == NetMode::Connected)
					{
						// Stopped receiving datagrams. Could be connection issue or
						// remote dropped the connection without notification or
						// disconnect notification was lost due to packet loss.
						packet->Data()[0] = NetMessageId::ConnectionLost;
					}
					else
					{
						packet->Data()[0] = NetMessageId::DisconnectionNotification;
					}

					ION_NET_LOG_VERBOSE(
					  "[" << exchange.mGuid << "] Connection lost to [" << remoteSystem.guid
						  << "];Initiated:" << (remoteSystem.mIsRemoteInitiated ? "remote" : "local") << ";mMode=" << remoteSystem.mMode
						  << ";Time since last datagram : " << ion::TimeSince(now, remoteSystem.timeLastDatagramArrived)
						  << "ms;Connection time:" << ion::TimeSince(now, remoteSystem.connectionTime)
						  << "ms;Since last ping request:" << ion::TimeSince(now, remoteSystem.pingTracker.GetLastPingTime()));
					packet->mGUID = remoteSystem.guid;
					packet->mAddress = remoteSystem.mAddress;
					packet->mRemoteId = remoteSystem.mId;

					NetControlLayer::PushPacket(control, packet);
				}
					// else connection shutting down, don't bother telling the user
					[[fallthrough]];
				case Op::ConnectionLostSilent:
					ResetRemoteSystem(exchange, control, control.mMemoryResource, systemOp.system, now);
					RemoveFromActiveSystemList(exchange, systemOp.system);
					sortActiveSystems = true;
					break;
				}
			});
	  });

	if (sortActiveSystems)
	{
		ion::Sort(exchange.mActiveSystems.Get(), exchange.mActiveSystems.Get() + exchange.mActiveSystemListSize);
	}
}

ConnectionResult AssignRemote(NetExchange& exchange, const NetConnections& connections, NetInterfaceResource& memoryResource, const ion::NetSocketAddress& connectAddress,
							  const ion::NetSocketAddress& bindingAddress, NetSocket* netSocket, ion::NetGUID guid,
							  NetDataTransferSecurity dataTransferSecurity, uint16_t mtu)
{
	ConnectionResult result;
	NetRemoteIndex rssIndexFromSA = GetRemoteIdFromSocketAddress(exchange, connectAddress, true).RemoteIndex();
	result.rssFromSA = rssIndexFromSA != NetGUID::InvalidNetRemoteIndex ? &exchange.mRemoteSystemList[rssIndexFromSA] : nullptr;
	bool IPAddrInUse = result.rssFromSA != 0 && result.rssFromSA->mMode != ion::NetMode::Disconnected;
	auto rssIndexFromGUID = GetRemoteSystemFromGUID(exchange, guid, true);
	ion::NetRemoteSystem* rssFromGuid =
	  rssIndexFromGUID != NetGUID::InvalidNetRemoteIndex ? &exchange.mRemoteSystemList[rssIndexFromGUID] : nullptr;
	bool GUIDInUse = rssFromGuid != 0 && rssFromGuid->mMode != ion::NetMode::Disconnected;
	if (IPAddrInUse)
	{
		if (GUIDInUse)
		{
			if (result.rssFromSA == rssFromGuid)
			{
				// Do this with all connection modes in case there was some kind of problem with established connection.
				result.outcome = ConnectionResponse::RepeatAnswer;
				return result;
			}
			if (exchange.mGuid != NetGuidAuthority)
			{
				ION_NET_LOG_VERBOSE("GUID collision: Connected with this IP, but GUID was taken by someone else");
				result.outcome = ConnectionResponse::GUIDReserved;
				return result;
			}
		}
		else
		{
			// No disconnection notification was received and user has new GUID. Potentially a spoofed IP?
			// If legit request, user should retry connection after old connection is dropped.
			ION_NET_LOG_ABNORMAL("Already connected with different GUID");
			result.outcome = ConnectionResponse::AlreadyConnected;
			return result;
		}
	}
	else if (GUIDInUse == true || guid == ion::NetGuidUnassigned || guid == exchange.mGuid)
	{
		if (exchange.mGuid != ion::NetGuidAuthority)
		{
			ION_NET_LOG_VERBOSE("GUID collision with GUID: " << exchange.mGuid << "): Someone else took the guid " << guid
															 << ";connectAddres=" << connectAddress);
			result.outcome = ConnectionResponse::GUIDReserved;
			return result;
		}
		GUIDInUse = true;
	}

	if (!AllowIncomingConnections(exchange))
	{
		ION_NET_LOG_VERBOSE("No incoming connections allowed");
		return result;
	}
	else if (GUIDInUse)
	{
		// Authority can give new GUID to replace reserved
		guid = GenerateGUID(exchange);
		ION_NET_LOG_VERBOSE("GUID collision: authority generated new GUID:" << guid);
	}

	RemoteSystemParameters rsp;

	// Generate 32-bit conversation id
	uint32_t conversationId;
	{
		do
		{
			conversationId = Random::UInt32Tl();
		} while (NetIsUnconnectedId(conversationId) ||
				 exchange.mAuthorityConversations.FindRemote(conversationId) != NetGUID::InvalidNetRemoteIndex);
	}

	rsp.mConversationId = conversationId;
	rsp.guid = guid;
	rsp.incomingMTU = mtu;
	rsp.incomingNetSocket = netSocket;
	rsp.mDataTransferSecurity = dataTransferSecurity;

	bool thisIPConnectedRecently = false;
	result.rssFromSA =
	  AssignSystemAddressToRemoteSystemList(exchange, connections, memoryResource, rsp, connectAddress, bindingAddress, &thisIPConnectedRecently);
	if (thisIPConnectedRecently)
	{
		ION_NET_LOG_ABNORMAL("IP recently connected");
		result.outcome = ConnectionResponse::IPConnectedRecently;
		exchange.mAuthorityConversations.RemoveKey(rsp.mConversationId);
	}
	return result;
}
void Init(NetExchange& exchange, const ion::NetStartupParameters& parameters, NetInterfaceResource& memoryResource)
{
	ION_ASSERT(exchange.mGuid == ion::NetGuidUnassigned, "Invalid state");
	ION_ASSERT(exchange.mMaximumNumberOfPeers == 0, "Duplicate init");
	ION_ASSERT(parameters.mMaxConnections > 0, "Peer must be connectable");
	ION_ASSERT(parameters.mMaxConnections <= UINT16_MAX, "Too many connections");
	exchange.mGuid = parameters.mIsMainAuthority ? NetGuidAuthority : GenerateGUID(exchange);

	// Don't allow more incoming connections than we have peers.
	exchange.mMaximumIncomingConnections = ion::SafeRangeCast<uint16_t>(parameters.mMaxIncomingConnections);
	if (exchange.mMaximumIncomingConnections > parameters.mMaxConnections)
	{
		exchange.mMaximumIncomingConnections = ion::SafeRangeCast<uint16_t>(parameters.mMaxConnections);
	}

	exchange.mMaximumNumberOfPeers = ion::SafeRangeCast<uint16_t>(parameters.mMaxConnections);
	{
		exchange.mSystemAddressDetails =
		  ion::MakeArenaPtrArray<ion::NetExchange::SystemAddressDetails>(&memoryResource, exchange.mMaximumNumberOfPeers + 1);
		exchange.mRemoteSystemList = ion::MakeArenaPtrArray<ion::NetRemoteSystem>(&memoryResource, exchange.mMaximumNumberOfPeers + 1);
		ION_ASSERT(exchange.mActiveSystemListSize == 0, "Invalid state");
		exchange.mActiveSystems = ion::MakeArenaPtrArray<ion::NetRemoteIndex>(&memoryResource, exchange.mMaximumNumberOfPeers + 1);
		for (uint16_t i = 0; i <= exchange.mMaximumNumberOfPeers; i++)
		{
			// remoteSystemList in Single thread
			exchange.mRemoteSystemList[i].connectionTime = 0;
			exchange.mRemoteSystemList[i].mAddress = NetUnassignedSocketAddress;
			exchange.mRemoteSystemList[i].guid = NetGuidUnassigned;
			exchange.mSystemAddressDetails[i].mExternalSystemAddress = NetUnassignedSocketAddress;
			exchange.mRemoteSystemList[i].mMode = NetMode::Disconnected;
			exchange.mRemoteSystemList[i].mId = NetRemoteId(0, uint16_t(i));
		}

		// Default active systems to invalid remote system
		for (unsigned int i = 1; i <= exchange.mMaximumNumberOfPeers; i++)
		{
			exchange.mActiveSystems[i - 1] = ion::NetGUID::InvalidNetRemoteIndex;
		}
	}
}

void Deinit(NetExchange& exchange, NetControl& control, ion::TimeMS now)
{
	const unsigned int systemListSize = exchange.mMaximumNumberOfPeers;
	if (systemListSize == 0)
	{
		return;
	}
	exchange.mActiveSystemListSize = 0;

	// Setting maximumNumberOfPeers to 0 allows remoteSystemList to be reallocated in Initialize.
	// Setting mMaximumNumberOfPeers prevent threads from accessing the reliability layer
	exchange.mMaximumNumberOfPeers = 0;

	ION_ASSERT(exchange.mRemoteSystemList[0].mMetrics == nullptr, "Metrics set");
	ION_ASSERT(exchange.mRemoteSystemList[0].mResource == nullptr, "Resource set");

	for (NetRemoteIndex i = 1; i <= systemListSize; i++)
	{
		if (exchange.mRemoteSystemList[i].mMode != NetMode::Disconnected)
		{
			ResetRemoteSystem(exchange, control, control.mMemoryResource, i, now);
			auto iter = exchange.mGuidToRemoteIndex.Find(exchange.mRemoteSystemList[i].guid.Raw());
			ION_ASSERT(iter != exchange.mGuidToRemoteIndex.End(), "Invalid system " << exchange.mRemoteSystemList[i].guid);
			exchange.mGuidToRemoteIndex.Erase(iter);
		}
		DereferenceRemoteSystem(exchange, exchange.mRemoteSystemList[i].mAddress);

		ion::AutoLock lock(exchange.mRemoteSystemList[i].mMetrixInitMutex);
		if (exchange.mRemoteSystemList[i].mMetrics)
		{
			ion::DeleteArenaPtr(&control.mMemoryResource, exchange.mRemoteSystemList[i].mMetrics);
		}
	}

	// Clear out the reliability layer list in case we want to reallocate it in a successive call to Init.
	ion::NetInterfacePtr<ion::NetRemoteSystem> temp = std::move(exchange.mRemoteSystemList);
	ion::DeleteArenaPtrArray<ion::NetRemoteSystem>(&control.mMemoryResource, systemListSize + 1, temp);

	ion::NetInterfacePtr<ion::NetRemoteIndex> activeTemp = std::move(exchange.mActiveSystems);
	ion::DeleteArenaPtrArray<ion::NetRemoteIndex>(&control.mMemoryResource, systemListSize + 1, activeTemp);

	ion::NetInterfacePtr<ion::NetExchange::SystemAddressDetails> detailsTemp = std::move(exchange.mSystemAddressDetails);
	ion::DeleteArenaPtrArray<ion::NetExchange::SystemAddressDetails>(&control.mMemoryResource, systemListSize + 1, detailsTemp);

	exchange.mGuid = ion::NetGuidUnassigned;
}

void ResetRemoteSystem(NetExchange& exchange, NetControl& control, NetInterfaceResource& memoryResource, NetRemoteIndex remoteIndex,
					   [[maybe_unused]] ion::TimeMS currentTime)
{
	ion::NetRemoteSystem& remote = exchange.mRemoteSystemList[remoteIndex];
	ION_ASSERT(remote.mResource, "Invalid remote");
	// Reserve this reliability layer for ourselves
	if (exchange.mGuid == NetGuidAuthority)
	{
		exchange.mAuthorityConversations.RemoveKey(remote.mConversationId);
	}
	remote.mConversationId = 0;
	remote.mAllowFastReroute = false;

	// Note! Do not reset these - can be used for lookups later when system is removed
	// remoteSystem.guid = NetGuidUnassigned;
	// remoteSystem.systemAddress

	ION_ASSERT(remote.MTUSize <= NetIpMaxMtuSize, "Unsupported mtu");

	if (remote.timeSync.IsActive())
	{
		if (exchange.mGlobalClock)
		{
			exchange.mGlobalClock->OnOutOfSync();
			exchange.mGlobalClock = nullptr;
		}
		else
		{
			ION_NET_LOG_ABNORMAL("Time sync was active without global clock. Trying to timesync with multiple peers?");
		}
		remote.timeSync.SetActive(false);
	}

	{
		ion::AutoLock lock(remote.mMetrixInitMutex);
		if (remote.mMetrics)
		{
			ion::DeleteArenaPtr(&memoryResource, remote.mMetrics);
		}
	}
	NetTransportLayer::Reset(remote.mTransport, control, remote);
	ion::DeleteArenaPtr(&memoryResource, remote.mResource);

	// Not using this socket
	remote.netSocket = 0;

	SetMode(exchange, remote, ion::NetMode::Disconnected);
	SetRemoteInitiated(exchange, remote, false);
#if ION_NET_FEATURE_SECURITY == 1
	ion::NetSecure::MemZero(remote.mSharedKey);
	ion::NetSecure::MemZero(remote.mNonceOffset);
#endif
	NetTransportLayer::Deinit(remote.mTransport);
}

void AddToActiveSystemList(NetExchange& exchange, ion::NetRemoteIndex systemIdx)
{
	ION_ASSERT(exchange.mRemoteSystemList[systemIdx].mAddress != NetUnassignedSocketAddress, "Remote is not active");
	exchange.mActiveSystems[exchange.mActiveSystemListSize] = systemIdx;
	exchange.mActiveSystemListSize++;
	exchange.mGuidToRemoteIndex.Insert(exchange.mRemoteSystemList[systemIdx].guid.Raw(), systemIdx);
}

void RemoveFromActiveSystemList(NetExchange& exchange, ion::NetRemoteIndex systemIdx)
{
	auto iter = exchange.mGuidToRemoteIndex.Find(exchange.mRemoteSystemList[systemIdx].guid.Raw());
	ION_ASSERT(iter != exchange.mGuidToRemoteIndex.End(), "Invalid system " << exchange.mRemoteSystemList[systemIdx].guid);
	exchange.mGuidToRemoteIndex.Erase(iter);

	for (unsigned int i = 0, n = exchange.mActiveSystemListSize - 1; i < n; ++i)
	{
		if (exchange.mActiveSystems[i] == systemIdx)
		{
			exchange.mActiveSystems[i] = exchange.mActiveSystems[exchange.mActiveSystemListSize - 1];
			exchange.mActiveSystems[exchange.mActiveSystemListSize - 1] = systemIdx;
			break;
		}
	}

	exchange.mActiveSystemListSize--;
	ION_ASSERT(exchange.mActiveSystems[exchange.mActiveSystemListSize] == systemIdx, "Invalid remove");
}
NetRemoteIndex GetRemoteSystemFromGUID(const NetExchange& exchange, const NetGUID guid, bool onlyActive)
{
	if (guid != NetGuidUnassigned)
	{
		for (unsigned int i = 1; i <= exchange.mMaximumNumberOfPeers; i++)
		{
			if (exchange.mRemoteSystemList[i].guid == guid &&
				(onlyActive == false || (exchange.mRemoteSystemList[i].mMode != NetMode::Disconnected)))
			{
				return NetRemoteIndex(i);
			}
		}
	}
	else
	{
		ION_NET_LOG_ABNORMAL("Invalid GUID");
	}
	return ion::NetGUID::InvalidNetRemoteIndex;
}

ion::NetRemoteId GetAddressedRemoteId(const NetExchange& exchange, const NetAddressOrRemoteRef& ref, bool calledFromNetworkThread)
{
	if (ref.mAddress == NetUnassignedSocketAddress)
	{
		return NetRemoteId();
	}

	if (ref.mRemoteId.IsValid() && ref.mRemoteId.RemoteIndex() <= exchange.mMaximumNumberOfPeers &&
		exchange.mRemoteSystemList[ref.mRemoteId.RemoteIndex()].mAddress == ref.mAddress &&
		exchange.mRemoteSystemList[ref.mRemoteId.RemoteIndex()].mMode != NetMode::Disconnected)
	{
		return ref.mRemoteId;
	}

	if (calledFromNetworkThread)
	{
		NetRemoteIndex index = RemoteIndex(exchange, ref.mAddress);
		return exchange.mRemoteSystemList[index].mId;
	}
	else
	{
		// remoteSystemList in user and network thread
		for (unsigned int i = 1; i <= exchange.mMaximumNumberOfPeers; i++)
		{
			if (exchange.mRemoteSystemList[i].mMode != NetMode::Disconnected && exchange.mRemoteSystemList[i].mAddress == ref.mAddress)
			{
				return exchange.mRemoteSystemList[i].mId;
			}
		}

		// If no active results found, try previously active results.
		for (unsigned int i = 1; i <= exchange.mMaximumNumberOfPeers; i++)
		{
			if (exchange.mRemoteSystemList[i].mAddress == ref.mAddress)
			{
				return exchange.mRemoteSystemList[i].mId;
			}
		}
	}

	return NetRemoteId();
}

ion::NetRemoteSystem* AssignSystemAddressToRemoteSystemList(NetExchange& exchange, const NetConnections& connections, NetInterfaceResource& memoryResource,
															const RemoteSystemParameters& rsp, const ion::NetSocketAddress& connectAddress,
															ion::NetSocketAddress bindingAddress, bool* thisIPConnectedRecently)
{
	ion::NetRemoteSystem* remoteSystem;
	ion::TimeMS time = ion::SteadyClock::GetTimeMS();
	ION_ASSERT(connectAddress.IsAssigned(), "Invalid address");

	if (exchange.mLimitConnectionFrequencyFromTheSameIP)
	{
		if (NetConnectionLayer::IsLoopbackAddress(connections, connectAddress, false) == false)
		{
			for (unsigned int i = 1; i <= exchange.mMaximumNumberOfPeers; i++)
			{
				if (exchange.mRemoteSystemList[i].mMode != NetMode::Disconnected &&
					exchange.mRemoteSystemList[i].mAddress.EqualsExcludingPort(connectAddress) &&
					TimeSince(time, exchange.mRemoteSystemList[i].connectionTime) < ion::NetConnectFloodTimeout)
				{
					ION_NET_LOG_ABNORMAL("Connection flood");
					// 4/13/09 Attackers can flood ID_OPEN_CONNECTION_REQUEST and use up all available connection slots
					// Ignore connection attempts if this IP address connected within the last [NetConnectFloodTimeout] milliseconds
					*thisIPConnectedRecently = true;
					return 0;
				}
			}
		}
	}

	// Don't use a different port than what we received on
	bindingAddress.CopyPort(rsp.incomingNetSocket->mBoundAddress);

	*thisIPConnectedRecently = false;
	for (uint16_t assignedIndex = 1; assignedIndex <= exchange.mMaximumNumberOfPeers; assignedIndex++)
	{
		if (exchange.mRemoteSystemList[assignedIndex].mMode == NetMode::Disconnected)
		{
			remoteSystem = exchange.mRemoteSystemList.Get() + assignedIndex;
			ION_ASSERT(remoteSystem->mId.load().RemoteIndex() == assignedIndex, "Invalid system index");
			remoteSystem->mId = NetRemoteId(remoteSystem->mId.load().Generation() + 1, assignedIndex);
			NetTransportLayer::Init(remoteSystem->mTransport);

			ReferenceRemoteSystem(exchange, connectAddress, ion::SafeRangeCast<NetRemoteIndex>(assignedIndex));
			remoteSystem->MTUSize = rsp.incomingMTU;
			remoteSystem->mConversationId = rsp.mConversationId;
			if (exchange.mGuid == NetGuidAuthority)
			{
				remoteSystem->mAllowFastReroute = rsp.mDataTransferSecurity == NetDataTransferSecurity::Secure &&
												  exchange.mDataTransferSecurity == NetDataTransferSecurity::Secure;
				exchange.mAuthorityConversations.StoreKey(rsp.mConversationId, static_cast<ion::NetRemoteIndex>(assignedIndex));
			}
			remoteSystem->guid = rsp.guid;

			SetMode(exchange, *remoteSystem, NetMode::UnverifiedSender);
			SetRemoteInitiated(exchange, *remoteSystem, rsp.mIsRemoteInitiated);

			remoteSystem->pingTracker = ion::NetRttTracker(time);
			remoteSystem->timeLastDatagramArrived = time;
			remoteSystem->lastReliableSend = remoteSystem->timeLastDatagramArrived;
			remoteSystem->timeoutTime = exchange.mDefaultTimeoutTime;
			remoteSystem->mDataTransferSecurity = rsp.mDataTransferSecurity;
			remoteSystem->mResource =
			  ion::MakeArenaPtr<NetRemoteSystemResource, ion::NetInterfaceResource>(&memoryResource, &memoryResource);

			if (exchange.mIsStatsEnabledByDefault)
			{
				NetStats stats;
				DataMetricsSnapshot(memoryResource, *remoteSystem, stats);
			}

			AddToActiveSystemList(exchange, ion::NetRemoteIndex(assignedIndex));
			if (rsp.incomingNetSocket->mBoundAddress != bindingAddress)
			{
				ION_DBG("Bound address of incoming socket " << rsp.incomingNetSocket->mBoundAddress << " does not match with incoming address "
															<< bindingAddress);
			}
			remoteSystem->netSocket = rsp.incomingNetSocket;

			remoteSystem->timeSync = ion::NetTimeSync();
			remoteSystem->connectionTime = time;
			exchange.mSystemAddressDetails[assignedIndex].mExternalSystemAddress = NetUnassignedSocketAddress;
			ION_ASSERT(RemoteIndex(exchange, connectAddress) == assignedIndex, "Invalid system index");
			return remoteSystem;
		}
	}
	return 0;
}

bool RegenerateGuid(NetExchange& exchange)
{
	if (exchange.mActiveSystemListSize == 0 && exchange.mGuid != NetGuidAuthority)
	{
		exchange.mGuid = GenerateGUID(exchange);
		return true;
	}
	return false;
}

bool GetStatistics(NetExchange& exchange, NetInterfaceResource& memoryResource, const NetSocketAddress& systemAddress,
				   NetStats& systemStats)
{
	if (systemAddress == NetUnassignedSocketAddress)
	{
		bool firstWrite = false;
		// Return a crude sum
		for (unsigned int i = 1; i <= exchange.mMaximumNumberOfPeers; i++)
		{
			if (exchange.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				NetStats rnsTemp;
				if (firstWrite == false)
				{
					firstWrite = true;
					DataMetricsSnapshot(memoryResource, exchange.mRemoteSystemList[i], systemStats);
				}
				else
				{
					DataMetricsSnapshot(memoryResource, exchange.mRemoteSystemList[i], rnsTemp);
					systemStats += rnsTemp;
				}
			}
		}
		return true;
	}
	else
	{
		NetRemoteId remoteId = GetRemoteIdThreadSafe(exchange, systemAddress, false);
		if (exchange.mRemoteSystemList[remoteId.RemoteIndex()].mResource)
		{
			DataMetricsSnapshot(memoryResource, exchange.mRemoteSystemList[remoteId.RemoteIndex()], systemStats);
			return true;
		}
	}
	return false;
}

void GetStatisticsList(NetExchange& exchange, NetInterfaceResource& memoryResource, NetVector<ion::NetSocketAddress>& addresses,
					   NetVector<NetGUID>& guids, NetVector<NetStats>& statistics)
{
	ION_ASSERT(exchange.mRemoteSystemList, "Invalid state");

	addresses.Clear();
	guids.Clear();
	statistics.Clear();

	unsigned int i;
	// NOTE: activeSystemListSize might be change by network update
	for (i = 0; i < exchange.mActiveSystemListSize; i++)
	{
		auto* system = &exchange.mRemoteSystemList[exchange.mActiveSystems[i]];
		if (system->mMode == NetMode::Connected)
		{
			addresses.Add((system)->mAddress);
			guids.Add((system)->guid);
			NetStats rns;
			DataMetricsSnapshot(memoryResource, *system, rns);
			statistics.Add(rns);
		}
	}
}

bool GetStatistics(NetExchange& exchange, NetInterfaceResource& memoryResource, NetRemoteId remoteId, NetStats& stats)
{
	if (!remoteId.IsValid())
	{
		GetStatistics(exchange, memoryResource, NetUnassignedSocketAddress, stats);
		return true;
	}

	if (exchange.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId &&
		exchange.mRemoteSystemList[remoteId.RemoteIndex()].mMode != NetMode::Disconnected)
	{
		DataMetricsSnapshot(memoryResource, exchange.mRemoteSystemList[remoteId.RemoteIndex()], stats);
		return true;
	}
	return false;
}

void SetTimeoutTime(NetExchange& exchange, ion::TimeMS timeMS, const NetAddressOrRemoteRef& target)
{
	if (target.IsUndefined())
	{
		exchange.mDefaultTimeoutTime = timeMS;

		for (unsigned int i = 1; i <= exchange.mMaximumNumberOfPeers; i++)
		{
			if (exchange.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				exchange.mRemoteSystemList[i].timeoutTime = timeMS;
			}
		}
	}
	else
	{
		NetRemoteId id = target.mRemoteId;
		if (!id.IsValid())
		{
			id = GetRemoteIdThreadSafe(exchange, target.mAddress, true);
		}
		if (id.IsValid())
		{
			exchange.mRemoteSystemList[id.RemoteIndex()].timeoutTime = timeMS;
		}
	}
}

ion::TimeMS GetTimeoutTime(const NetExchange& exchange, const NetAddressOrRemoteRef& target)
{
	if (!target.IsUndefined())
	{
		ion::NetRemoteId id = target.mRemoteId;
		if (!id.IsValid())
		{
			id = GetRemoteIdThreadSafe(exchange, target.mAddress, true);
		}
		if (id.IsValid())
		{
			ion::TimeMS timeoutTime = exchange.mRemoteSystemList[id.RemoteIndex()].timeoutTime;

			// Check address was not altered
			if (exchange.mRemoteSystemList[id.RemoteIndex()].mId.load() == id)
			{
				return timeoutTime;
			}
		}
	}
	return exchange.mDefaultTimeoutTime;
}

void GetInternalID(const NetExchange& exchange, NetSocketAddress& out, const NetSocketAddress& address, const int index)
{
	ION_ASSERT(address != NetUnassignedSocketAddress, "Invalid address");
	ion::NetRemoteId id = GetRemoteIdThreadSafe(exchange, address, true);
	if (id.IsValid())
	{
		NetSocketAddress addres = exchange.mSystemAddressDetails[id.RemoteIndex()].mTheirInternalSystemAddress[index];

		// Check address was not altered
		if (exchange.mRemoteSystemList[id.RemoteIndex()].mAddress == address)
		{
			out = address;
			return;
		}
	}

	out = NetUnassignedSocketAddress;
}

void ReferenceRemoteSystem(NetExchange& exchange, const ion::NetSocketAddress& sa, ion::NetRemoteIndex remoteSystemListIndex)
{
	const NetSocketAddress oldAddress = exchange.mRemoteSystemList[remoteSystemListIndex].mAddress;
	if (oldAddress != NetUnassignedSocketAddress)
	{
		// The system might be active if rerouting
		//		ION_NET_ASSERT(remoteSystemList[remoteSystemListIndex].isActive==false);

		// Remove the reference if the reference is pointing to this inactive system
		if (GetRemoteSystem(exchange, oldAddress) == &exchange.mRemoteSystemList[remoteSystemListIndex])
		{
			DereferenceRemoteSystem(exchange, oldAddress);
		}
	}
	DereferenceRemoteSystem(exchange, sa);

	exchange.mRemoteSystemList[remoteSystemListIndex].mAddress = sa;
	exchange.mAddressToRemoteIndex.Insert(sa, remoteSystemListIndex);

	ION_ASSERT(RemoteIndex(exchange, sa) == remoteSystemListIndex, "Invalid index");
}

void SetConnected(NetExchange& exchange, NetRemoteSystem& remoteSystem, const NetSocketAddress& address)
{
	ION_ASSERT(remoteSystem.mMode != NetMode::Connected, "Cannot reconnect");
	exchange.mSystemAddressDetails[remoteSystem.mId.load().RemoteIndex()].mExternalSystemAddress = address;
	exchange.mNumberOfConnectedSystems++;
	ION_ASSERT(exchange.mNumberOfConnectedSystems <= exchange.mMaximumNumberOfPeers, "Invalid state");
	remoteSystem.mMode = NetMode::Connected;
}

void SetMode(NetExchange& exchange, NetRemoteSystem& remoteSystem, NetMode mode)
{
	ION_ASSERT(mode != NetMode::Connected, "Cannot set connected without address");
	if (remoteSystem.mMode == NetMode::Connected)
	{
		ION_ASSERT(exchange.mNumberOfConnectedSystems > 0, "Invalid state");
		exchange.mNumberOfConnectedSystems--;
	}
	remoteSystem.mMode = mode;
}

void SetRemoteInitiated(NetExchange& exchange, NetRemoteSystem& remoteSystem, bool isRemoteIniated)
{
	if (isRemoteIniated)
	{
		if (!remoteSystem.mIsRemoteInitiated)
		{
			remoteSystem.mIsRemoteInitiated = true;
			exchange.mNumberOfIncomingConnections++;
			ION_ASSERT(exchange.mNumberOfIncomingConnections <= exchange.mMaximumNumberOfPeers, "Invalid state");
		}
	}
	else
	{
		if (remoteSystem.mIsRemoteInitiated)
		{
			remoteSystem.mIsRemoteInitiated = false;
			ION_ASSERT(exchange.mNumberOfIncomingConnections > 0, "Invalid state");
			exchange.mNumberOfIncomingConnections--;
		}
	}
}

NetRemoteId GetRemoteIdFromSocketAddress(const NetExchange& exchange, const ion::NetSocketAddress& address, bool calledFromNetworkThread,
										 bool onlyActive)
{
	if (!address.IsAssigned())
	{
		return NetRemoteId();
	}

	if (calledFromNetworkThread)
	{
		return GetRemoteIdFromSocketAddress(exchange, address, onlyActive);
	}
	else
	{
		return GetRemoteIdThreadSafe(exchange, address, onlyActive);
	}
}

NetRemoteId GetRemoteIdThreadSafe(const NetExchange& exchange, const NetSocketAddress& address, bool onlyActive)
{
	NetRemoteId remoteId;

	// Active connections take priority.  But if there are no active connections, return the first systemAddress match found
	for (unsigned int i = 1; i <= exchange.mMaximumNumberOfPeers; i++)
	{
		if (exchange.mRemoteSystemList[i].mAddress == address)
		{
			if (exchange.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				remoteId = exchange.mRemoteSystemList[i].mId;
			}
			else if (!onlyActive)
			{
				remoteId = exchange.mRemoteSystemList[i].mId;
			}
			break;
		}
	}

	// Check remote was not altered by other thread
	if (exchange.mRemoteSystemList[remoteId.RemoteIndex()].mAddress == address)
	{
		return remoteId;
	}
	return NetRemoteId();
}

NetRemoteId GetRemoteIdThreadSafe(const NetExchange& exchange, const NetGUID input)
{
	if (input != NetGuidUnassigned)
	{
		NetRemoteId remoteId;
		for (unsigned int i = 1; i <= exchange.mMaximumNumberOfPeers; i++)
		{
			if (exchange.mRemoteSystemList[i].guid == input && exchange.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				remoteId = exchange.mRemoteSystemList[i].mId;
				break;
			}
		}

		// If no active results found, try previously active results.
		if (!remoteId.IsValid())
		{
			for (unsigned int i = 1; i <= exchange.mMaximumNumberOfPeers; i++)
			{
				if (exchange.mRemoteSystemList[i].guid == input)
				{
					remoteId = exchange.mRemoteSystemList[i].mId;
					break;
				}
			}
		}

		// Check remote was not altered by other thread
		if (exchange.mRemoteSystemList[remoteId.RemoteIndex()].guid == input)
		{
			return remoteId;
		}
	}
	return NetRemoteId();
}

void GetSocketAddressThreadSafe(const NetExchange& exchange, NetGUID guid, NetSocketAddress& out)
{
	ION_ASSERT(guid != NetGuidUnassigned, "Invalid GUID");
	ION_ASSERT(guid != exchange.mGuid, "Should read internal id");
	NetRemoteId remoteId = GetRemoteIdThreadSafe(exchange, guid);
	GetSocketAddressThreadSafe(exchange, remoteId, out);

	// Check address was not altered by other thread
	if (exchange.mRemoteSystemList[remoteId.RemoteIndex()].guid != guid)
	{
		out = NetUnassignedSocketAddress;
	}
}

void GetSocketAddressThreadSafe(const NetExchange& exchange, NetRemoteId remoteId, NetSocketAddress& out)
{
	ION_ASSERT(remoteId.RemoteIndex() <= exchange.mMaximumNumberOfPeers, "Invalid remote id");

	// Don't give the user players that aren't fully connected, since sends will fail
	if (exchange.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId &&
		exchange.mRemoteSystemList[remoteId.RemoteIndex()].mMode == NetMode::Connected)
	{
		NetSocketAddress address = exchange.mRemoteSystemList[remoteId.RemoteIndex()].mAddress;

		// Check address was not altered by other thread
		if (exchange.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId)
		{
			out = address;
			return;
		}
	}
	out = NetUnassignedSocketAddress;
}

NetGUID GetGUIDThreadSafe(const NetExchange& exchange, NetRemoteId remoteId)
{
	ION_ASSERT(remoteId.RemoteIndex() <= exchange.mMaximumNumberOfPeers,
			   "Invalid remote id;generation=" << remoteId.Generation() << ";index=" << remoteId.RemoteIndex());

	if (exchange.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId)
	{
		NetGUID guid = exchange.mRemoteSystemList[remoteId.RemoteIndex()].guid;

		// Check guid was not altered by other thread
		if (exchange.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId)
		{
			return guid;
		}
	}
	return NetGuidUnassigned;
}

void LogUnreachable([[maybe_unused]] const NetSocketAddress& address)
{
#if (ION_DEBUG_LOG_ENABLED == 1)
	char buffer[128];
	address.ToString(buffer, 128, true);
	ION_NET_LOG_INFO("Remote unreachable: " << buffer << ".");
#endif
}

void SendImmediate(NetExchange& exchange, NetControl& control, NetCommandPtr command, ion::TimeMS now)
{
	SmallVector<NetRemoteIndex, 16, NetAllocator<NetRemoteIndex>> remoteIndices;
	SendImmediate(exchange, control, std::move(command), now, remoteIndices);
}

void SendImmediate(NetExchange& exchange, NetControl& control, NetCommandPtr command, ion::TimeMS now,
				   SmallVector<NetRemoteIndex, 16, NetAllocator<NetRemoteIndex>>& outRemoteIndices)
{
	ION_ASSERT(command->mRefCount == 0, "Duplicate command dispatch");
	ION_ASSERT(command->mChannel < NetNumberOfChannels, "Invalid channel");
	ION_ASSERT(command->mNumberOfBytesToSend > 0, "Not enough data");

	bool isExcluding = false;
	switch (command->mCommand)
	{
	case NetCommandType::SendExcludingRemote:
		isExcluding = true;
		[[fallthrough]];
	case NetCommandType::SendRemote:
	{
		ION_ASSERT(command->mTarget.mRemoteId.RemoteIndex() <= exchange.mMaximumNumberOfPeers, "Invalid remote id");
		auto& remoteSystem = exchange.mRemoteSystemList[command->mTarget.mRemoteId.RemoteIndex()];
		if (command->mTarget.mRemoteId.IsValid() && remoteSystem.mId.load() == command->mTarget.mRemoteId)
		{
			if (NetModeIsOpen(remoteSystem.mMode))
			{
				outRemoteIndices.AddKeepCapacity(command->mTarget.mRemoteId.RemoteIndex());
			}
			else if (!isExcluding)
			{
				LogUnreachable(remoteSystem.mAddress);
			}
		}
		break;
	}
	case NetCommandType::SendExcludingAddresses:
		isExcluding = true;
		[[fallthrough]];
	case NetCommandType::SendAddresses:
	{
		ion::ForEach(command->mTarget.mAddressList,
					 [&](const NetSocketAddress& address)
					 {
						 auto remoteIndex = ion::NetExchangeLayer::GetRemoteIdFromSocketAddress(exchange, address, true).RemoteIndex();
						 if (remoteIndex && NetModeIsOpen(exchange.mRemoteSystemList[remoteIndex].mMode))
						 {
							 outRemoteIndices.Add(remoteIndex);
						 }
						 else if (!isExcluding)
						 {
							 LogUnreachable(address);
						 }
					 });

		break;
	}
	case NetCommandType::SendExcludingRemotes:
		isExcluding = true;
		[[fallthrough]];
	case NetCommandType::SendRemotes:
		ion::ForEach(command->mTarget.mRemoteList,
					 [&](NetRemoteId remoteId)
					 {
						 ION_ASSERT(remoteId.IsValid(), "Invalid remote");
						 ION_ASSERT(remoteId.RemoteIndex() <= exchange.mMaximumNumberOfPeers, "Invalid remote id");
						 auto& remoteSystem = exchange.mRemoteSystemList[remoteId.RemoteIndex()];
						 if (remoteSystem.mId.load() == remoteId)
						 {
							 if (NetModeIsOpen(remoteSystem.mMode))
							 {
								 outRemoteIndices.Add(remoteId.RemoteIndex());
							 }
							 else if (!isExcluding)
							 {
								 LogUnreachable(remoteSystem.mAddress);
							 }
						 }
					 });
		break;
	default:
		ION_UNREACHABLE("Not a send command");
	}

	UInt idx = 1;
	UInt lastIdx = exchange.mMaximumNumberOfPeers;
	if (!isExcluding)
	{
		if (outRemoteIndices.IsEmpty())
		{
			DeleteArenaPtr(&control.mMemoryResource, command);
			return;
		}
		else
		{
			idx = 0;
			lastIdx = outRemoteIndices.Size() - 1;
		}
	}

	constexpr size_t MaxSafeUnrealiablePayloadSize =  // Can send for all targets for sure
	  NetConnectedProtocolSafePayloadSize(true, false);
	if (command->mReliability != NetPacketReliability::Reliable && command->mNumberOfBytesToSend > MaxSafeUnrealiablePayloadSize)
	{
		// If single target, compare remote MTU.
		constexpr uint32_t UnrealiableOverhead =
		  NetConnectedProtocolHeaderSize + NetSegmentHeaderUnrealiableSize + NetSegmentHeaderDataLengthSize;

		if (isExcluding || outRemoteIndices.Size() != 1 ||
			command->mNumberOfBytesToSend > exchange.mRemoteSystemList[outRemoteIndices.Front()].PayloadSize() - UnrealiableOverhead)
		{
			ION_NET_LOG_VERBOSE("Packet reliability changed to 'Reliable'. Too large packet to be unreliable;Size="
								<< (command->mNumberOfBytesToSend) << ";Max="
								<< ((isExcluding || outRemoteIndices.Size() != 1)
									  ? MaxSafeUnrealiablePayloadSize
									  : exchange.mRemoteSystemList[outRemoteIndices.Front()].PayloadSize() - UnrealiableOverhead));
			command->mReliability = NetPacketReliability::Reliable;
		}
	}

	for (; idx <= lastIdx; idx++)
	{
		UInt remoteIndex;
		if (!isExcluding)
		{
			remoteIndex = outRemoteIndices[idx];
		}
		else
		{
			if (!NetModeIsOpen(exchange.mRemoteSystemList[idx].mMode) || Find(outRemoteIndices, idx) != outRemoteIndices.End())
			{
				continue;  // Exclude remote index
			}
			remoteIndex = idx;
		}

		auto& remoteSystem = exchange.mRemoteSystemList[remoteIndex];
		ION_ASSERT(NetModeIsOpen(exchange.mRemoteSystemList[remoteIndex].mMode), "Remote not reachable");
		ION_ASSERT(remoteSystem.mMode != NetMode::Disconnected, "Invalid state to send reliable data");
		ION_NET_LOG_VERBOSE_MSG("Msg: Sending id=" << Hex<uint8_t>(command.Get()->mData) << "h");
		NetTransportLayer::Send(remoteSystem.mTransport, control, now, remoteSystem, *command.Get());
		if (remoteSystem.mMetrics)
		{
			remoteSystem.mMetrics->OnSent(
			  now,
			  command->mReliability == NetPacketReliability::Reliable ? ion::PacketType::UserReliable : ion::PacketType::UserUnreliable,
			  size_t(command->mNumberOfBytesToSend));
		}
	}
	if (command->mRefCount == 0)
	{
		DeleteArenaPtr(&control.mMemoryResource, command);
	}
	else
	{
		command.Release();
	}
}

void SendConnectionRequestAccepted(NetExchange& exchange, const NetConnections& connections, NetControl& control,
								   ion::NetRemoteSystem& remote, ion::Time incomingTimestamp, ion::TimeMS now)
{
	NetSendCommand cmd(control, remote.mId, NetMaximumNumberOfInternalIds * sizeof(NetSocketAddress) + 256);
	if (cmd.HasBuffer())
	{
		cmd.Parameters().mPriority = NetPacketPriority::Immediate;
		{
			ByteWriter writer(cmd.Writer());

			writer.Process(NetMessageId::ConnectionRequestAccepted);
			writer.Process(remote.mAddress);
			ION_ASSERT(remote.mId.load().RemoteIndex() != ion::NetGUID::InvalidNetRemoteIndex, "Invalid system");
			writer.Process(remote.mId.load().RemoteIndex());
			for (unsigned int i = 0; i < NetMaximumNumberOfInternalIds; i++)
			{
				writer.Process(connections.mIpList[i]);
			}
			remote.pingTracker.OnPing(now);
			writer.Process(now);
			writer.Process(incomingTimestamp);
		}
		NetExchangeLayer::SendImmediate(exchange, control, std::move(cmd.Release()), now);
	}
}

void OnConnectedPong(NetExchange& exchange, ion::Time now, ion::Time sentPingTime, ion::Time remoteTime, ion::NetRemoteSystem& remote)
{
	remote.pingTracker.OnPong(now, sentPingTime, remoteTime);
	if (remote.timeSync.IsActive() && remote.pingTracker.HasSamples())
	{
		remote.timeSync.Update(remote.pingTracker);
		exchange.mGlobalClock->OnTimeSync(remote.timeSync.GetClock(), remote.timeSync.SyncState());
	}
}

void GetExternalID(const NetExchange& exchange, const NetSocketAddress& target, NetSocketAddress& inactiveExternalId)
{
	ION_ASSERT(target != NetUnassignedSocketAddress, "Invalid address");
	// First check for active connection with this systemAddress
	inactiveExternalId = NetUnassignedSocketAddress;
	for (unsigned int i = 1; i <= exchange.mMaximumNumberOfPeers; i++)
	{
		if (exchange.mRemoteSystemList[i].mAddress == target)
		{
			if (exchange.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				inactiveExternalId = exchange.mSystemAddressDetails[i].mExternalSystemAddress;
				break;
			}
			else if (exchange.mSystemAddressDetails[i].mExternalSystemAddress != NetUnassignedSocketAddress)
			{
				inactiveExternalId = exchange.mSystemAddressDetails[i].mExternalSystemAddress;
			}
		}
	}
}

}  // namespace ion::NetExchangeLayer
