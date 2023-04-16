#include <ion/net/NetConnectionLayer.h>
#include <ion/net/NetGlobalClock.h>
#include <ion/net/NetRemote.h>
#include <ion/net/NetRemoteStoreLayer.h>
#include <ion/net/NetSecure.h>
#include <ion/net/NetStartupParameters.h>
#include <ion/net/NetSocketLayer.h>

#include <ion/arena/ArenaAllocator.h>

#include <ion/container/ForEach.h>
#include <ion/container/Sort.h>
#include <ion/container/Vector.h>

#include <ion/debug/Profiling.h>

#include <ion/jobs/JobIntermediate.h>
#include <ion/jobs/JobScheduler.h>

#include <ion/BasePeer.h>

namespace ion::NetRemoteStoreLayer
{

namespace
{

ion::NetGUID GenerateGUID(const NetRemoteStore& remoteStore)
{
	ion::NetGUID guid;
	do
	{
		ion::NetSecure::Random((unsigned char*)&guid.Raw(), sizeof(guid.Raw()));
	} while (guid == NetGuidUnassigned || guid == NetGuidAuthority ||
			 GetRemoteSystemFromGUID(remoteStore, guid, false) != NetGUID::InvalidNetRemoteIndex || (guid == remoteStore.mGuid));
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

inline Op NextOperation(NetRemoteStore& remoteStore, NetRemoteSystem& remoteSystem, ion::TimeMS currentTime)
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
				!remoteSystem.reliableChannels.AreAcksWaiting())
			{
				// If no reliable packets are waiting for an ack, do a one byte reliable send so that disconnections are
				// noticed

				return Op::KeepAliveReliable;
			}
			else
			{
				ion::NetRoundTripTime pingFreq =
				  remoteSystem.timeSync.IsActive() ? remoteSystem.timeSync.GetPingFrequency() : remoteStore.mOccasionalPing;
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
		if (!remoteSystem.reliableChannels.IsOutgoingDataWaiting() ||
			ion::TimeSince(currentTime, remoteSystem.lastReliableSend) > remoteSystem.timeoutTime)
		{
			return Op::ConnectionLostSilent;
		}
		return Op::None;
	case NetMode::DisconnectAsap:  // We wanted to disconnect
		if ((remoteSystem.reliableChannels.IsOutgoingDataWaiting()) &&
			ion::TimeSince(currentTime, remoteSystem.lastReliableSend) <= remoteSystem.timeoutTime)
		{
			return Op::None;
		}
		break;
	case NetMode::DisconnectAsapMutual:
		if ((remoteSystem.reliableChannels.AreAcksWaiting() || remoteSystem.reliableChannels.IsOutgoingDataWaiting()) &&
			ion::TimeSince(currentTime, remoteSystem.lastReliableSend) <= remoteSystem.timeoutTime)
		{
			return Op::None;
		}
		break;
	case NetMode::DisconnectOnNoAck:  // They wanted to disconnect
		if ((remoteSystem.reliableChannels.AreAcksWaiting()) &&
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

void UpdateRemote(NetControl& control, NetRemoteStore& remoteStore, ion::TimeMS currentTime, ion::NetRemoteIndex systemIndex,
				  Operations& operations)
{
	ION_PROFILER_SCOPE(Network, "Remote System");
	NetRemoteSystem& remoteSystem = remoteStore.mRemoteSystemList[systemIndex];
	ION_ASSERT(remoteSystem.mAddress != NetUnassignedSocketAddress, "Invalid system");
	remoteSystem.reliableChannels.Update(control, remoteSystem, currentTime);

	if (remoteSystem.mMetrics)
	{
		remoteSystem.mMetrics->Update(currentTime);
	}

	Op op = NextOperation(remoteStore, remoteSystem, currentTime);
	if (op != Op::None)
	{
		operations.list.Add({systemIndex, op});
	}
}
}  // namespace

void Update(NetRemoteStore& remoteStore, NetControl& control, ion::TimeMS now, ion::JobScheduler* js)
{
	ion::JobIntermediate<Operations> operations;
	if (js)
	{
		js->ParallelFor(remoteStore.mActiveSystems.Get(), remoteStore.mActiveSystems.Get() + remoteStore.mActiveSystemListSize, operations,
						[&](ion::NetRemoteIndex systemIndex, Operations& outOperations)
						{ UpdateRemote(control, remoteStore, now, systemIndex, outOperations); });
	}
	else
	{
		ion::ForEachPartial(remoteStore.mActiveSystems.Get(), remoteStore.mActiveSystems.Get() + remoteStore.mActiveSystemListSize,
							[&](ion::NetRemoteIndex systemIndex) { UpdateRemote(control, remoteStore, now, systemIndex, operations.GetMain()); });
	}

	bool sortActiveSystems = false;
	operations.ForEachContainer(
	  [&](Operations& operations)
	  {
		  ion::ForEach(operations.list,
					   [&](SystemOp& systemOp)
					   {
						   NetRemoteSystem& remoteSystem = remoteStore.mRemoteSystemList[systemOp.system];
						   switch (systemOp.op)
						   {
						   case Op::None:
							   ION_UNREACHABLE("No op");
							   break;
						   case Op::KeepAliveReliable:
							   remoteSystem.pingTracker.OnPing(now);
							   NetControlLayer::PingInternal(control, remoteStore, remoteSystem.mAddress, true,
															 NetPacketReliability::Reliable, now);
							   break;

						   case Op::KeepAliveUnreliable:
							   remoteSystem.pingTracker.OnPing(now);
							   NetControlLayer::PingInternal(control, remoteStore, remoteSystem.mAddress, true,
															 NetPacketReliability::Unreliable, now);
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

							   ION_DBG("Connection lost;Initiated:"
									   << (remoteSystem.mIsRemoteInitiated ? "remote" : "local") << ";mMode=" << remoteSystem.mMode
									   << ";Time since last datagram : " << ion::TimeSince(now, remoteSystem.timeLastDatagramArrived)
									   << "ms;Connection time:" << ion::TimeSince(now, remoteSystem.connectionTime)
									   << "ms;Since last ping request:" << ion::TimeSince(now, remoteSystem.pingTracker.GetLastPingTime()));
							   packet->mGUID = remoteSystem.guid;
							   packet->mAddress = remoteSystem.mAddress;
							   packet->mRemoteId = remoteSystem.mId;

							   NetControlLayer::AddPacketToProducer(control, packet);
						   }
							   // else connection shutting down, don't bother telling the user
							   [[fallthrough]];
						   case Op::ConnectionLostSilent:
							   ResetRemoteSystem(remoteStore, control, control.mMemoryResource, systemOp.system,
												 now);
							   RemoveFromActiveSystemList(remoteStore, systemOp.system);
							   sortActiveSystems = true;
							   break;
						   }
					   });
	  });

	if (sortActiveSystems)
	{
		ion::Sort(remoteStore.mActiveSystems.Get(), remoteStore.mActiveSystems.Get() + remoteStore.mActiveSystemListSize);
	}
}

ConnectionResult AssignRemote(NetRemoteStore& remoteStore, NetInterfaceResource& memoryResource, const ion::NetSocketAddress& connectAddress, const ion::NetSocketAddress& bindingAddress,
							  NetSocket* rakNetSocket, ion::NetGUID guid, NetDataTransferSecurity dataTransferSecurity, uint16_t mtu)
{
	ConnectionResult result;
	NetRemoteIndex rssIndexFromSA = GetRemoteIdFromSocketAddress(remoteStore, connectAddress, true).RemoteIndex();
	result.rssFromSA = rssIndexFromSA != NetGUID::InvalidNetRemoteIndex ? &remoteStore.mRemoteSystemList[rssIndexFromSA] : nullptr;
	bool IPAddrInUse = result.rssFromSA != 0 && result.rssFromSA->mMode != ion::NetMode::Disconnected;
	auto rssIndexFromGUID = GetRemoteSystemFromGUID(remoteStore, guid, true);
	ion::NetRemoteSystem* rssFromGuid =
	  rssIndexFromGUID != NetGUID::InvalidNetRemoteIndex ? &remoteStore.mRemoteSystemList[rssIndexFromGUID] : nullptr;
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
			if (remoteStore.mGuid != NetGuidAuthority)
			{
				ION_DBG("GUID collision: Connected with this IP, but GUID was taken by someone else");
				result.outcome = ConnectionResponse::GUIDReserved;
				return result;
			}
		}
		else
		{
			// No disconnection notification was received and user has new GUID. Potentially a spoofed IP?
			// If legit request, user should retry connection after old connection is dropped.
			ION_ABNORMAL("Already connected with different GUID");
			result.outcome = ConnectionResponse::AlreadyConnected;
			return result;
		}
	}
	else if (GUIDInUse == true || guid == ion::NetGuidUnassigned || guid == remoteStore.mGuid)
	{
		ION_ASSERT(remoteStore.mIpList[0] != connectAddress, "Connecting to self");

		if (remoteStore.mGuid != ion::NetGuidAuthority)
		{
			ION_DBG("GUID collision at " << remoteStore.mIpList[0] << "(" << remoteStore.mGuid << "): Someone else took the guid "
										 << guid << ";connectAddres=" << connectAddress);
			result.outcome = ConnectionResponse::GUIDReserved;
			return result;
		}
		GUIDInUse = true;
	}

	if (!AllowIncomingConnections(remoteStore))
	{
		ION_DBG("No incoming connections allowed");
		return result;
	}
	else if (GUIDInUse)
	{
		// Authority can give new GUID to replace reserved
		guid = GenerateGUID(remoteStore);
		ION_DBG("GUID collision: authority generated new GUID:" << guid);
	}

	RemoteSystemParameters rsp;

	// Generate 32-bit conversation id
	uint32_t conversationId;
	{
		do
		{
			conversationId = Random::UInt32Tl();
		} while (NetIsUnconnectedId(conversationId) ||
				 remoteStore.mAuthorityConversations.FindRemote(conversationId) != NetGUID::InvalidNetRemoteIndex);
	}

	rsp.mConversationId = conversationId;
	rsp.guid = guid;
	rsp.incomingMTU = mtu;
	rsp.incomingRakNetSocket = rakNetSocket;
	rsp.mDataTransferSecurity = dataTransferSecurity;

	bool thisIPConnectedRecently = false;
	result.rssFromSA =
	  AssignSystemAddressToRemoteSystemList(remoteStore, memoryResource, rsp, connectAddress, bindingAddress, &thisIPConnectedRecently);
	if (thisIPConnectedRecently)
	{
		ION_ABNORMAL("IP recently connected");
		result.outcome = ConnectionResponse::IPConnectedRecently;
		remoteStore.mAuthorityConversations.RemoveKey(rsp.mConversationId);
	}
	return result;
}
void Init(NetRemoteStore& remoteStore, const ion::NetStartupParameters& parameters, NetInterfaceResource& memoryResource)
{
	ION_ASSERT(remoteStore.mGuid == ion::NetGuidUnassigned, "Invalid state");
	ION_ASSERT(remoteStore.mMaximumNumberOfPeers == 0, "Duplicate init");
	ION_ASSERT(parameters.mMaxConnections > 0, "Peer must be connectable");
	ION_ASSERT(parameters.mMaxConnections <= UINT16_MAX, "Too many connections");
	remoteStore.mGuid = parameters.mIsMainAuthority ? NetGuidAuthority : GenerateGUID(remoteStore);

	for (unsigned int i = 0; i < NetMaximumNumberOfInternalIds; i++)
	{
		remoteStore.mIpList[i] = NetUnassignedSocketAddress;
	}
	remoteStore.mFirstExternalID = NetUnassignedSocketAddress;

	// Don't allow more incoming connections than we have peers.
	remoteStore.mMaximumIncomingConnections = ion::SafeRangeCast<uint16_t>(parameters.mMaxIncomingConnections);
	if (remoteStore.mMaximumIncomingConnections > parameters.mMaxConnections)
	{
		remoteStore.mMaximumIncomingConnections = ion::SafeRangeCast<uint16_t>(parameters.mMaxConnections);
	}

	remoteStore.mMaximumNumberOfPeers = ion::SafeRangeCast<uint16_t>(parameters.mMaxConnections);
	{
		remoteStore.mSystemAddressDetails =
		  ion::MakeArenaPtrArray<ion::NetRemoteStore::SystemAddressDetails>(&memoryResource, remoteStore.mMaximumNumberOfPeers + 1);
		remoteStore.mRemoteSystemList =
		  ion::MakeArenaPtrArray<ion::NetRemoteSystem>(&memoryResource, remoteStore.mMaximumNumberOfPeers + 1);
		ION_ASSERT(remoteStore.mActiveSystemListSize == 0, "Invalid state");
		remoteStore.mActiveSystems = ion::MakeArenaPtrArray<ion::NetRemoteIndex>(&memoryResource, remoteStore.mMaximumNumberOfPeers + 1);
		for (uint16_t i = 0; i <= remoteStore.mMaximumNumberOfPeers; i++)
		{
			// remoteSystemList in Single thread
			remoteStore.mRemoteSystemList[i].connectionTime = 0;
			remoteStore.mRemoteSystemList[i].mAddress = NetUnassignedSocketAddress;
			remoteStore.mRemoteSystemList[i].guid = NetGuidUnassigned;
			remoteStore.mSystemAddressDetails[i].mExternalSystemAddress = NetUnassignedSocketAddress;
			remoteStore.mRemoteSystemList[i].mMode = NetMode::Disconnected;
			remoteStore.mRemoteSystemList[i].mId = NetRemoteId(0, uint16_t(i));
		}

		// Default active systems to invalid remote system
		for (unsigned int i = 1; i <= remoteStore.mMaximumNumberOfPeers; i++)
		{
			remoteStore.mActiveSystems[i - 1] = ion::NetGUID::InvalidNetRemoteIndex;
		}
	}
}

void Deinit(NetRemoteStore& remoteStore, NetControl& control, ion::TimeMS now)
{
	const unsigned int systemListSize = remoteStore.mMaximumNumberOfPeers;
	if (systemListSize == 0)
	{
		return;
	}
	remoteStore.mActiveSystemListSize = 0;

	// Setting maximumNumberOfPeers to 0 allows remoteSystemList to be reallocated in Initialize.
	// Setting mMaximumNumberOfPeers prevent threads from accessing the reliability layer
	remoteStore.mMaximumNumberOfPeers = 0;

	ION_ASSERT(remoteStore.mRemoteSystemList[0].mMetrics == nullptr, "Metrics set");
	ION_ASSERT(remoteStore.mRemoteSystemList[0].mResource == nullptr, "Resource set");
	
	for (NetRemoteIndex i = 1; i <= systemListSize; i++)
	{
		if (remoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected)
		{
			ResetRemoteSystem(remoteStore, control, control.mMemoryResource, i, now);
			auto iter = remoteStore.mGuidToRemoteIndex.Find(remoteStore.mRemoteSystemList[i].guid.Raw());
			ION_ASSERT(iter != remoteStore.mGuidToRemoteIndex.End(), "Invalid system " << remoteStore.mRemoteSystemList[i].guid);
			remoteStore.mGuidToRemoteIndex.Erase(iter);
		}
		DereferenceRemoteSystem(remoteStore, remoteStore.mRemoteSystemList[i].mAddress);

		ion::AutoLock lock(remoteStore.mRemoteSystemList[i].mMetrixInitMutex);
		if (remoteStore.mRemoteSystemList[i].mMetrics)
		{
			ion::DeleteArenaPtr(&control.mMemoryResource, remoteStore.mRemoteSystemList[i].mMetrics);
		}
	}

	// Clear out the reliability layer list in case we want to reallocate it in a successive call to Init.
	ion::NetInterfacePtr<ion::NetRemoteSystem> temp = std::move(remoteStore.mRemoteSystemList);
	ion::DeleteArenaPtrArray<ion::NetRemoteSystem>(&control.mMemoryResource, systemListSize + 1, temp);

	ion::NetInterfacePtr<ion::NetRemoteIndex> activeTemp = std::move(remoteStore.mActiveSystems);
	ion::DeleteArenaPtrArray<ion::NetRemoteIndex>(&control.mMemoryResource, systemListSize + 1, activeTemp);

	ion::NetInterfacePtr<ion::NetRemoteStore::SystemAddressDetails> detailsTemp = std::move(remoteStore.mSystemAddressDetails);
	ion::DeleteArenaPtrArray<ion::NetRemoteStore::SystemAddressDetails>(&control.mMemoryResource, systemListSize + 1, detailsTemp);

	remoteStore.mGuid = ion::NetGuidUnassigned;
}

void ResetRemoteSystem(NetRemoteStore& remoteStore, NetControl& control, NetInterfaceResource& memoryResource,
					   NetRemoteIndex remoteIndex, [[maybe_unused]] ion::TimeMS currentTime)
{
	ion::NetRemoteSystem& remote = remoteStore.mRemoteSystemList[remoteIndex];
	ION_ASSERT(remote.mResource, "Invalid remote");
	// Reserve this reliability layer for ourselves
	if (remoteStore.mGuid == NetGuidAuthority)
	{
		remoteStore.mAuthorityConversations.RemoveKey(remote.mConversationId);
	}
	remote.mConversationId = 0;
	remote.mAllowFastReroute = false;

	// Note! Do not reset these - can be used for lookups later when system is removed
	// remoteSystem.guid = NetGuidUnassigned;
	// remoteSystem.systemAddress

	ION_ASSERT(remote.MTUSize <= NetIpMaxMtuSize, "Unsupported mtu");

	if (remote.timeSync.IsActive())
	{
		if (remoteStore.mGlobalClock)
		{
			remoteStore.mGlobalClock->OnOutOfSync();
			remoteStore.mGlobalClock = nullptr;
		}
		else
		{
			// #TODO: Time sync active, but no global clock found
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
	remote.reliableChannels.Reset(control, remote);
	ion::DeleteArenaPtr(&memoryResource, remote.mResource);

	// Not using this socket
	remote.rakNetSocket = 0;

	SetMode(remoteStore, remote, ion::NetMode::Disconnected);
	SetRemoteInitiated(remoteStore, remote, false);
#if ION_NET_FEATURE_SECURITY == 1
	ion::NetSecure::MemZero(remote.mSharedKey);
	ion::NetSecure::MemZero(remote.mNonceOffset);
#endif
}

void AddToActiveSystemList(NetRemoteStore& remoteStore, ion::NetRemoteIndex systemIdx)
{
	ION_ASSERT(remoteStore.mRemoteSystemList[systemIdx].mAddress != NetUnassignedSocketAddress, "Remote is not active");
	remoteStore.mActiveSystems[remoteStore.mActiveSystemListSize] = systemIdx;
	remoteStore.mActiveSystemListSize++;
	remoteStore.mGuidToRemoteIndex.Insert(remoteStore.mRemoteSystemList[systemIdx].guid.Raw(), systemIdx);
}

void RemoveFromActiveSystemList(NetRemoteStore& remoteStore, ion::NetRemoteIndex systemIdx)
{
	auto iter = remoteStore.mGuidToRemoteIndex.Find(remoteStore.mRemoteSystemList[systemIdx].guid.Raw());
	ION_ASSERT(iter != remoteStore.mGuidToRemoteIndex.End(), "Invalid system " << remoteStore.mRemoteSystemList[systemIdx].guid);
	remoteStore.mGuidToRemoteIndex.Erase(iter);

	for (unsigned int i = 0, n = remoteStore.mActiveSystemListSize - 1; i < n; ++i)
	{
		if (remoteStore.mActiveSystems[i] == systemIdx)
		{
			remoteStore.mActiveSystems[i] = remoteStore.mActiveSystems[remoteStore.mActiveSystemListSize - 1];
			remoteStore.mActiveSystems[remoteStore.mActiveSystemListSize - 1] = systemIdx;
			break;
		}
	}

	remoteStore.mActiveSystemListSize--;
	ION_ASSERT(remoteStore.mActiveSystems[remoteStore.mActiveSystemListSize] == systemIdx, "Invalid remove");
}
NetRemoteIndex GetRemoteSystemFromGUID(const NetRemoteStore& remoteStore, const NetGUID guid, bool onlyActive)
{
	if (guid != NetGuidUnassigned)
	{
		for (unsigned int i = 1; i <= remoteStore.mMaximumNumberOfPeers; i++)
		{
			if (remoteStore.mRemoteSystemList[i].guid == guid &&
				(onlyActive == false || (remoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected)))
			{
				return NetRemoteIndex(i);
			}
		}
	}
	else
	{
		ION_ABNORMAL("Invalid GUID");
	}
	return ion::NetGUID::InvalidNetRemoteIndex;
}

ion::NetRemoteId GetAddressedRemoteId(const NetRemoteStore& remoteStore, const NetAddressOrRemoteRef& ref, bool calledFromNetworkThread)
{
	if (ref.mAddress == NetUnassignedSocketAddress)
		return NetRemoteId();

	if (ref.mRemoteId.IsValid() && ref.mRemoteId.RemoteIndex() <= remoteStore.mMaximumNumberOfPeers &&
		remoteStore.mRemoteSystemList[ref.mRemoteId.RemoteIndex()].mAddress == ref.mAddress &&
		remoteStore.mRemoteSystemList[ref.mRemoteId.RemoteIndex()].mMode != NetMode::Disconnected)
	{
		return ref.mRemoteId;
	}

	if (calledFromNetworkThread)
	{
		NetRemoteIndex index = RemoteIndex(remoteStore, ref.mAddress);
		return remoteStore.mRemoteSystemList[index].mId;
	}
	else
	{
		// remoteSystemList in user and network thread
		for (unsigned int i = 1; i <= remoteStore.mMaximumNumberOfPeers; i++)
		{
			if (remoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected &&
				remoteStore.mRemoteSystemList[i].mAddress == ref.mAddress)
			{
				return remoteStore.mRemoteSystemList[i].mId;
			}
		}

		// If no active results found, try previously active results.
		for (unsigned int i = 1; i <= remoteStore.mMaximumNumberOfPeers; i++)
		{
			if (remoteStore.mRemoteSystemList[i].mAddress == ref.mAddress)
			{
				return remoteStore.mRemoteSystemList[i].mId;
			}
		}
	}

	return NetRemoteId();
}

ion::NetRemoteSystem* AssignSystemAddressToRemoteSystemList(NetRemoteStore& remoteStore, NetInterfaceResource& memoryResource,
															const RemoteSystemParameters& rsp, const ion::NetSocketAddress& connectAddress,
															ion::NetSocketAddress bindingAddress, bool* thisIPConnectedRecently)
{
	ion::NetRemoteSystem* remoteSystem;
	ion::TimeMS time = ion::SteadyClock::GetTimeMS();
	ION_ASSERT(connectAddress.IsAssigned(), "Invalid address");

	if (remoteStore.mLimitConnectionFrequencyFromTheSameIP)
	{
		if (IsLoopbackAddress(remoteStore, connectAddress, false) == false)
		{
			for (unsigned int i = 1; i <= remoteStore.mMaximumNumberOfPeers; i++)
			{
				if (remoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected &&
					remoteStore.mRemoteSystemList[i].mAddress.EqualsExcludingPort(connectAddress) &&
					TimeSince(time, remoteStore.mRemoteSystemList[i].connectionTime) < ion::NetConnectFloodTimeout)
				{
					ION_ABNORMAL("Connection flood");
					// 4/13/09 Attackers can flood ID_OPEN_CONNECTION_REQUEST and use up all available connection slots
					// Ignore connection attempts if this IP address connected within the last [NetConnectFloodTimeout] milliseconds
					*thisIPConnectedRecently = true;
					return 0;
				}
			}
		}
	}

	// Don't use a different port than what we received on
	bindingAddress.CopyPort(rsp.incomingRakNetSocket->mBoundAddress);

	*thisIPConnectedRecently = false;
	for (uint16_t assignedIndex = 1; assignedIndex <= remoteStore.mMaximumNumberOfPeers; assignedIndex++)
	{
		if (remoteStore.mRemoteSystemList[assignedIndex].mMode == NetMode::Disconnected)
		{
			remoteSystem = remoteStore.mRemoteSystemList.Get() + assignedIndex;
			ION_ASSERT(remoteSystem->mId.load().RemoteIndex() == assignedIndex, "Invalid system index");
			remoteSystem->mId = NetRemoteId(remoteSystem->mId.load().Generation() + 1, assignedIndex);

			ReferenceRemoteSystem(remoteStore, connectAddress, ion::SafeRangeCast<NetRemoteIndex>(assignedIndex));
			remoteSystem->MTUSize = rsp.incomingMTU;
			remoteSystem->mConversationId = rsp.mConversationId;
			if (remoteStore.mGuid == NetGuidAuthority)
			{
				remoteSystem->mAllowFastReroute =
				  rsp.mDataTransferSecurity == NetDataTransferSecurity::EncryptionAndReplayProtection &&
				  remoteStore.mDataTransferSecurity == NetDataTransferSecurity::EncryptionAndReplayProtection;
				remoteStore.mAuthorityConversations.StoreKey(rsp.mConversationId, static_cast<ion::NetRemoteIndex>(assignedIndex));
			}
			remoteSystem->guid = rsp.guid;

			SetMode(remoteStore, *remoteSystem, NetMode::UnverifiedSender);
			SetRemoteInitiated(remoteStore, *remoteSystem, rsp.mIsRemoteInitiated);

			remoteSystem->pingTracker = ion::NetRttTracker(time);
			remoteSystem->timeLastDatagramArrived = time;
			remoteSystem->lastReliableSend = remoteSystem->timeLastDatagramArrived;
			remoteSystem->timeoutTime = remoteStore.mDefaultTimeoutTime;
			remoteSystem->mDataTransferSecurity = rsp.mDataTransferSecurity;
			remoteSystem->mResource =
			  ion::MakeArenaPtr<NetRemoteSystemResource, ion::NetInterfaceResource>(&memoryResource, &memoryResource);

			if (remoteStore.mIsStatsEnabledByDefault)
			{
				NetStats stats;
				DataMetricsSnapshot(memoryResource, *remoteSystem, stats);
			}

			AddToActiveSystemList(remoteStore, ion::NetRemoteIndex(assignedIndex));
			if (rsp.incomingRakNetSocket->mBoundAddress == bindingAddress)
			{
				remoteSystem->rakNetSocket = rsp.incomingRakNetSocket;
			}
			else
			{
				char str[256];
				bindingAddress.ToString(str, 256);
				// See if this is an internal IP address.
				// If so, force binding on it so we reply on the same IP address as they sent to.
				unsigned int ipListIndex, foundIndex = (unsigned int)-1;

				for (ipListIndex = 0; ipListIndex < NetMaximumNumberOfInternalIds; ipListIndex++)
				{
					if (remoteStore.mIpList[ipListIndex] == NetUnassignedSocketAddress)
						break;

					if (bindingAddress.EqualsExcludingPort(remoteStore.mIpList[ipListIndex]))
					{
						foundIndex = ipListIndex;
						break;
					}
				}

				remoteSystem->rakNetSocket = rsp.incomingRakNetSocket;
			}

			remoteSystem->timeSync = ion::NetTimeSync();
			remoteSystem->connectionTime = time;
			remoteStore.mSystemAddressDetails[assignedIndex].mExternalSystemAddress = NetUnassignedSocketAddress;
			ION_ASSERT(RemoteIndex(remoteStore, connectAddress) == assignedIndex, "Invalid system index");
			return remoteSystem;
		}
	}
	return 0;
}

bool RegenerateGuid(NetRemoteStore& remoteStore)
{
	if (remoteStore.mActiveSystemListSize == 0 && remoteStore.mGuid != NetGuidAuthority)
	{
		remoteStore.mGuid = GenerateGUID(remoteStore);
		return true;
	}
	return false;
}

bool GetStatistics(NetRemoteStore& remoteStore, NetInterfaceResource& memoryResource, const NetSocketAddress& systemAddress,
						NetStats& systemStats)
{

	if (systemAddress == NetUnassignedSocketAddress)
	{
		bool firstWrite = false;
		// Return a crude sum
		for (unsigned int i = 1; i <= remoteStore.mMaximumNumberOfPeers; i++)
		{
			if (remoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				NetStats rnsTemp;
				if (firstWrite == false)
				{
					firstWrite = true;
					DataMetricsSnapshot(memoryResource, remoteStore.mRemoteSystemList[i], systemStats);
				}
				else
				{
					DataMetricsSnapshot(memoryResource, remoteStore.mRemoteSystemList[i], rnsTemp);
					systemStats += rnsTemp;
				}
			}
		}
		return true;
	}
	else
	{
		NetRemoteId remoteId = GetRemoteIdThreadSafe(remoteStore, systemAddress,  false);
		if (remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mResource)
		{
			DataMetricsSnapshot(memoryResource, remoteStore.mRemoteSystemList[remoteId.RemoteIndex()], systemStats);
			return true;
		}
	}
	return false;
}

void GetStatisticsList(NetRemoteStore& remoteStore, NetInterfaceResource& memoryResource, NetVector<ion::NetSocketAddress>& addresses,
					   NetVector<NetGUID>& guids, NetVector<NetStats>& statistics)
{
	ION_ASSERT(remoteStore.mRemoteSystemList, "Invalid state");

	addresses.Clear();
	guids.Clear();
	statistics.Clear();

	unsigned int i;
	// NOTE: activeSystemListSize might be change by network update
	for (i = 0; i < remoteStore.mActiveSystemListSize; i++)
	{
		auto* system = &remoteStore.mRemoteSystemList[remoteStore.mActiveSystems[i]];
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

bool GetStatistics(NetRemoteStore& remoteStore, NetInterfaceResource& memoryResource, NetRemoteId remoteId, NetStats& stats)
{
	if (!remoteId.IsValid()) 
	{
		GetStatistics(remoteStore, memoryResource, NetUnassignedSocketAddress, stats);
		return true;
	}

	if (remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId &&
		remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mMode != NetMode::Disconnected)
	{
		DataMetricsSnapshot(memoryResource, remoteStore.mRemoteSystemList[remoteId.RemoteIndex()], stats);
		return true;
	}
	return false;
}

void SetTimeoutTime(NetRemoteStore& remoteStore, ion::TimeMS timeMS, const NetSocketAddress& target)
{
	if (target == NetUnassignedSocketAddress)
	{
		remoteStore.mDefaultTimeoutTime = timeMS;

		for (unsigned int i = 1; i <= remoteStore.mMaximumNumberOfPeers; i++)
		{
			if (remoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				remoteStore.mRemoteSystemList[i].timeoutTime = timeMS;
			}
		}
	}
	else
	{
		NetRemoteId id = GetRemoteIdThreadSafe(remoteStore, target, true);
		if (id.IsValid())
		{
			remoteStore.mRemoteSystemList[id.RemoteIndex()].timeoutTime = timeMS;
		}
	}
}

ion::TimeMS GetTimeoutTime(const NetRemoteStore& remoteStore, const NetSocketAddress& target)
{
	if (target != NetUnassignedSocketAddress)
	{
		ion::NetRemoteId id= GetRemoteIdThreadSafe(remoteStore, target, true);
		ion::TimeMS timeoutTime = remoteStore.mRemoteSystemList[id.RemoteIndex()].timeoutTime;

		// Check address was not altered
		if (remoteStore.mRemoteSystemList[id.RemoteIndex()].mAddress == target)
		{
			return timeoutTime;
		}
	}
	return remoteStore.mDefaultTimeoutTime;
}

NetSocketAddress GetInternalID(const NetRemoteStore& remoteStore, const NetSocketAddress& address, const int index)
{
	if (address == NetUnassignedSocketAddress)
	{
		return remoteStore.mIpList[index];
	}
	else
	{
		ion::NetRemoteId id = GetRemoteIdThreadSafe(remoteStore, address, true);
		if (id.IsValid())
		{
			NetSocketAddress addres = remoteStore.mSystemAddressDetails[id.RemoteIndex()].mTheirInternalSystemAddress[index];

			// Check address was not altered
			if (remoteStore.mRemoteSystemList[id.RemoteIndex()].mAddress == address)
			{
				return address;
			}
		}
	}
	return NetUnassignedSocketAddress;
}

void SetInternalID(NetRemoteStore& remoteStore, const NetSocketAddress& systemAddress, int index)
{
	ION_ASSERT(index >= 0 && index < NetMaximumNumberOfInternalIds, "invalid id index");
	remoteStore.mIpList[index] = systemAddress;
}

bool IsLoopbackAddress(const NetRemoteStore& remoteStore, const NetAddressOrRemoteRef& systemIdentifier, bool matchPort)
{
	if (systemIdentifier.mRemoteId.IsValid())
	{
		return false;
	}

	for (int i = 0; i < NetMaximumNumberOfInternalIds && remoteStore.mIpList[i] != NetUnassignedSocketAddress; i++)
	{
		if (matchPort)
		{
			if (remoteStore.mIpList[i] == systemIdentifier.mAddress)
			{
				return true;
			}
		}
		else
		{
			if (remoteStore.mIpList[i].EqualsExcludingPort(systemIdentifier.mAddress))
			{
				return true;
			}
		}
	}

	return (matchPort == true && systemIdentifier.mAddress == remoteStore.mFirstExternalID) ||
		   (matchPort == false && systemIdentifier.mAddress.EqualsExcludingPort(remoteStore.mFirstExternalID));
}

void ReferenceRemoteSystem(NetRemoteStore& remoteStore, const ion::NetSocketAddress& sa, ion::NetRemoteIndex remoteSystemListIndex)
{
	const NetSocketAddress oldAddress = remoteStore.mRemoteSystemList[remoteSystemListIndex].mAddress;
	if (oldAddress != NetUnassignedSocketAddress)
	{
		// The system might be active if rerouting
		//		ION_NET_ASSERT(remoteSystemList[remoteSystemListIndex].isActive==false);

		// Remove the reference if the reference is pointing to this inactive system
		if (GetRemoteSystem(remoteStore, oldAddress) == &remoteStore.mRemoteSystemList[remoteSystemListIndex])
		{
			DereferenceRemoteSystem(remoteStore, oldAddress);
		}
	}
	DereferenceRemoteSystem(remoteStore, sa);

	remoteStore.mRemoteSystemList[remoteSystemListIndex].mAddress = sa;
	remoteStore.mAddressToRemoteIndex.Insert(sa, remoteSystemListIndex);

	ION_ASSERT(RemoteIndex(remoteStore, sa) == remoteSystemListIndex, "Invalid index");
}

void SetConnected(NetRemoteStore& remoteStore, NetRemoteSystem& remoteSystem, const NetSocketAddress& address)
{
	ION_ASSERT(remoteSystem.mMode != NetMode::Connected, "Cannot reconnect");
	remoteStore.mSystemAddressDetails[remoteSystem.mId.load().RemoteIndex()].mExternalSystemAddress = address;
	remoteStore.mNumberOfConnectedSystems++;
	ION_ASSERT(remoteStore.mNumberOfConnectedSystems <= remoteStore.mMaximumNumberOfPeers, "Invalid state");
	remoteSystem.mMode = NetMode::Connected;
}

void SetMode(NetRemoteStore& remoteStore, NetRemoteSystem& remoteSystem, NetMode mode)
{
	ION_ASSERT(mode != NetMode::Connected, "Cannot set connected without address");
	if (remoteSystem.mMode == NetMode::Connected)
	{
		ION_ASSERT(remoteStore.mNumberOfConnectedSystems > 0, "Invalid state");
		remoteStore.mNumberOfConnectedSystems--;
	}
	remoteSystem.mMode = mode;
}

void SetRemoteInitiated(NetRemoteStore& remoteStore, NetRemoteSystem& remoteSystem, bool isRemoteIniated)
{
	if (isRemoteIniated)
	{
		if (!remoteSystem.mIsRemoteInitiated)
		{
			remoteSystem.mIsRemoteInitiated = true;
			remoteStore.mNumberOfIncomingConnections++;
			ION_ASSERT(remoteStore.mNumberOfIncomingConnections <= remoteStore.mMaximumNumberOfPeers, "Invalid state");
		}
	}
	else
	{
		if (remoteSystem.mIsRemoteInitiated)
		{
			remoteSystem.mIsRemoteInitiated = false;
			ION_ASSERT(remoteStore.mNumberOfIncomingConnections > 0, "Invalid state");
			remoteStore.mNumberOfIncomingConnections--;
		}
	}
}

NetRemoteId GetRemoteIdFromSocketAddress(const NetRemoteStore& remoteStore, const ion::NetSocketAddress& address,
													   bool calledFromNetworkThread, bool onlyActive)
{
	if (!address.IsAssigned())
	{
		return NetRemoteId();
	}

	if (calledFromNetworkThread)
	{
		return GetRemoteIdFromSocketAddress(remoteStore, address, onlyActive);
	}
	else
	{
		return GetRemoteIdThreadSafe(remoteStore, address, onlyActive);
	}
}

NetRemoteId GetRemoteIdThreadSafe(const NetRemoteStore& remoteStore, const NetSocketAddress& address, bool onlyActive)
{
	NetRemoteId remoteId;

	// Active connections take priority.  But if there are no active connections, return the first systemAddress match found
	for (unsigned int i = 1; i <= remoteStore.mMaximumNumberOfPeers; i++)
	{
		if (remoteStore.mRemoteSystemList[i].mAddress == address)
		{
			if (remoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				remoteId = remoteStore.mRemoteSystemList[i].mId;
			}
			else if (!onlyActive)
			{
				remoteId = remoteStore.mRemoteSystemList[i].mId;
			}
			break;
		}
	}

	// Check remote was not altered by other thread
	if (remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mAddress == address)
	{
		return remoteId;
	}
	return NetRemoteId();
}

NetRemoteId GetRemoteIdThreadSafe(const NetRemoteStore& remoteStore, const NetGUID input)
{
	if (input != NetGuidUnassigned)
	{
		NetRemoteId remoteId;
		for (unsigned int i = 1; i <= remoteStore.mMaximumNumberOfPeers; i++)
		{
			if (remoteStore.mRemoteSystemList[i].guid == input && remoteStore.mRemoteSystemList[i].mMode != NetMode::Disconnected)
			{
				remoteId = remoteStore.mRemoteSystemList[i].mId;
				break;
			}
		}

		// If no active results found, try previously active results.
		if (!remoteId.IsValid())
		{
			for (unsigned int i = 1; i <= remoteStore.mMaximumNumberOfPeers; i++)
			{
				if (remoteStore.mRemoteSystemList[i].guid == input)
				{
					remoteId = remoteStore.mRemoteSystemList[i].mId;
					break;
				}
			}
		}

		// Check remote was not altered by other thread
		if (remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].guid == input)
		{
			return remoteId;
		}
	}
	return NetRemoteId();
}

NetSocketAddress GetSocketAddressThreadSafe(const NetRemoteStore& remoteStore, NetGUID guid)
{
	if (guid == NetGuidUnassigned)
	{
		return NetUnassignedSocketAddress;
	}

	if (guid == remoteStore.mGuid)
	{
		return GetInternalID(remoteStore, NetUnassignedSocketAddress);
	}
	NetRemoteId remoteId = GetRemoteIdThreadSafe(remoteStore, guid);
	NetSocketAddress address = GetSocketAddressThreadSafe(remoteStore, remoteId);

	// Check address was not altered by other thread
	if (remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].guid == guid)
	{
		return address;
	}
	return NetUnassignedSocketAddress;
}

NetSocketAddress GetSocketAddressThreadSafe(const NetRemoteStore& remoteStore, NetRemoteId remoteId)
{
	ION_ASSERT(remoteId.RemoteIndex() <= remoteStore.mMaximumNumberOfPeers, "Invalid remote id");

	// Don't give the user players that aren't fully connected, since sends will fail
	if (remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId &&
		remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mMode == NetMode::Connected)
	{
		NetSocketAddress address = remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mAddress;

		// Check address was not altered by other thread
		if (remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId)
		{
			return address;
		}
	}
	return NetUnassignedSocketAddress;
}

NetGUID GetGUIDThreadSafe(const NetRemoteStore& remoteStore, NetRemoteId remoteId)
{
	ION_ASSERT(remoteId.RemoteIndex() <= remoteStore.mMaximumNumberOfPeers, "Invalid remote id");

	if (remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId)
	{
		NetGUID guid = remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].guid;

		// Check guid was not altered by other thread
		if (remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId)
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
	ION_LOG_INFO("Remote unreachable: " << buffer << ".");
#endif
}

void SendImmediate(NetRemoteStore& remoteStore, NetControl& control, NetCommandPtr command, ion::TimeMS now)
{
	SmallVector<NetRemoteIndex, 16, NetAllocator<NetRemoteIndex>> remoteIndices;
	SendImmediate(remoteStore, control, std::move(command), now, remoteIndices);
}

void SendImmediate(NetRemoteStore& remoteStore, NetControl& control, NetCommandPtr command, ion::TimeMS now,
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
		auto& remoteSystem = remoteStore.mRemoteSystemList[command->mTarget.mRemoteId.RemoteIndex()];
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
						 auto remoteIndex =
						   ion::NetRemoteStoreLayer::GetRemoteIdFromSocketAddress(remoteStore, address, true).RemoteIndex();
						 if (remoteIndex && NetModeIsOpen(remoteStore.mRemoteSystemList[remoteIndex].mMode))
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
						 auto& remoteSystem = remoteStore.mRemoteSystemList[remoteId.RemoteIndex()];
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
	}

	UInt idx = 1;
	UInt lastIdx = remoteStore.mMaximumNumberOfPeers;
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
			lastIdx = outRemoteIndices.Size()-1;
		}
	}

	constexpr const size_t MaxUnrealiablePayloadSize =
	  NetUdpPayloadSize(NetIpMinimumReassemblyBufferSize - ion::NetConnectedProtocolOverHead - ion::NetSecure::AuthenticationTagLength);
	if (command->mReliability != NetPacketReliability::Reliable && command->mNumberOfBytesToSend > MaxUnrealiablePayloadSize)
	{
		// If single target, compare remote MTU.
		if (isExcluding || outRemoteIndices.Size() != 1 ||
			(ion::NetMtuSize(command->mNumberOfBytesToSend + ion::NetConnectedProtocolOverHead + ion::NetSecure::AuthenticationTagLength) >
			 remoteStore.mRemoteSystemList[outRemoteIndices.Front()].MTUSize))
		{
			ION_DBG("Packet reliability changed to 'Reliable'. Too large packet to be unreliable;Size=" << command->mNumberOfBytesToSend);
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
			if (!NetModeIsOpen(remoteStore.mRemoteSystemList[idx].mMode) ||
				Find(outRemoteIndices, idx) != outRemoteIndices.End())
			{
				continue; // Exclude remote index
			}
			remoteIndex = idx;
		}

		auto& remoteSystem = remoteStore.mRemoteSystemList[remoteIndex];
		ION_ASSERT(NetModeIsOpen(remoteStore.mRemoteSystemList[remoteIndex].mMode), "Remote not reachable");
		ION_ASSERT(remoteSystem.mMode != NetMode::Disconnected, "Invalid state to send reliable data");
		remoteSystem.reliableChannels.Send(control, now, remoteSystem, *command.Get(),
										   (remoteSystem.mConversationId << 8) | uint32_t(command->mChannel));
		if (remoteSystem.mMetrics)
		{
			remoteSystem.mMetrics->OnSent(
			  now,
			  command->mReliability == NetPacketReliability::Reliable ? ion::PacketType::UserReliable : ion::PacketType::UserUnreliable,
			  command->mNumberOfBytesToSend);
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

void SendConnectionRequestAccepted(NetRemoteStore& remoteStore, NetControl& control, ion::NetRemoteSystem* remoteSystem, ion::Time incomingTimestamp,
								   ion::TimeMS now)
{
	NetSendCommand cmd(control, remoteSystem->mId, NetMaximumNumberOfInternalIds * sizeof(NetSocketAddress) + 256);
	if (cmd.HasBuffer())
	{
		{			
			ByteWriter writer(cmd.Writer());

			writer.Process(NetMessageId::ConnectionRequestAccepted);
			writer.Process(remoteSystem->mAddress);
			ION_ASSERT(remoteSystem->mId.load().RemoteIndex() != ion::NetGUID::InvalidNetRemoteIndex, "Invalid system");
			writer.Process(remoteSystem->mId.load().RemoteIndex());
			for (unsigned int i = 0; i < NetMaximumNumberOfInternalIds; i++)
			{
				writer.Process(remoteStore.mIpList[i]);
			}
			remoteSystem->pingTracker.OnPing(now);
			writer.Process(now);
			writer.Process(incomingTimestamp);			
		}
		cmd.Parameters().mPriority = NetPacketPriority::Immediate;

		NetRemoteStoreLayer::SendImmediate(remoteStore, control, std::move(cmd.Release()), now);
	}
}

void OnConnectedPong(NetRemoteStore& remoteStore, ion::Time now, ion::Time sentPingTime, ion::Time remoteTime, ion::NetRemoteSystem* remoteSystem)
{
	remoteSystem->pingTracker.OnPong(now, sentPingTime, remoteTime);
	if (remoteSystem->timeSync.IsActive() && remoteSystem->pingTracker.HasSamples())
	{
		remoteSystem->timeSync.Update(remoteSystem->pingTracker);
		remoteStore.mGlobalClock->OnTimeSync(remoteSystem->timeSync.GetClock(), remoteSystem->timeSync.SyncState());
	}
}

void FillIPList(NetRemoteStore& remoteStore)
{
	if (remoteStore.mIpList[0] != NetUnassignedSocketAddress)
		return;

	// Fill out ipList structure
	ion::SocketLayer::GetInternalAddresses(remoteStore.mIpList);

	// Sort the addresses from lowest to highest
	int startingIdx = 0;
	while (startingIdx < NetMaximumNumberOfInternalIds - 1 && remoteStore.mIpList[startingIdx] != NetUnassignedSocketAddress)
	{
		int lowestIdx = startingIdx;
		for (int curIdx = startingIdx + 1;
			 curIdx < NetMaximumNumberOfInternalIds - 1 && remoteStore.mIpList[curIdx] != NetUnassignedSocketAddress; curIdx++)
		{
			if (remoteStore.mIpList[curIdx] < remoteStore.mIpList[startingIdx])
			{
				lowestIdx = curIdx;
			}
		}
		if (startingIdx != lowestIdx)
		{
			NetSocketAddress temp = remoteStore.mIpList[startingIdx];
			remoteStore.mIpList[startingIdx] = remoteStore.mIpList[lowestIdx];
			remoteStore.mIpList[lowestIdx] = temp;
		}
		++startingIdx;
	}
}

unsigned int GetNumberOfAddresses(const NetRemoteStore& remoteStore)
{
	unsigned int i = 0;

	while (i < remoteStore.mIpList.Size() && remoteStore.mIpList[i] != NetUnassignedSocketAddress)
	{
		i++;
	}

	return i;
}

bool IsIPV6Only(const NetRemoteStore& remoteStore)
{
	auto num = GetNumberOfAddresses(remoteStore);
	for (size_t i = 0; i < num; ++i)
	{
		if (remoteStore.mIpList[i].GetIPVersion() != 6)
		{
			return false;
		}
	}
	return num != 0;  // True only when IPV6 adresses are available.
}

}  // namespace ion::NetRemoteStoreLayer
