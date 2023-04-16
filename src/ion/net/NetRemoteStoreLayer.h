#pragma once

#include <ion/net/NetGUID.h>
#include <ion/net/NetRemoteStore.h>
#include <ion/net/NetSdk.h>
#include <ion/net/NetSocketAddress.h>

#include <ion/time/CoreTime.h>

#include <ion/jobs/JobIntermediate.h>

#include <ion/tracing/Log.h>

namespace ion
{
class JobScheduler;
class BasePeer;
union NetSocketAddress;
struct NetStartupParameters;

template <typename T>
using NetVector = Vector<T, NetAllocator<T>>;

namespace NetRemoteStoreLayer
{

enum class ConnectionResponse : int
{
	Ok,
	AlreadyConnected,
	RepeatAnswer,
	GUIDReserved,
	IPConnectedRecently
};
struct ConnectionResult
{
	ion::NetRemoteSystem* rssFromSA = nullptr;
	ConnectionResponse outcome = ConnectionResponse::Ok;
};

ConnectionResult AssignRemote(NetRemoteStore& remoteStore, NetInterfaceResource& memoryResource,
							  const ion::NetSocketAddress& connectAddress, const ion::NetSocketAddress& bindingAddress,
							  NetSocket* rakNetSocket, ion::NetGUID guid, NetDataTransferSecurity dataTransferSecurity, uint16_t mtu);

enum class Op : uint8_t
{
	None,
	KeepAliveUnreliable,
	KeepAliveReliable,
	ConnectionLost,
	ConnectionLostSilent
};
struct SystemOp
{
	ion::NetRemoteIndex system;
	Op op;
};
struct Operations
{
	ion::SmallVector<SystemOp, 4, NetAllocator<SystemOp>> list;
};

void Update(NetRemoteStore& remoteStore, NetControl& control, ion::TimeMS now, ion::JobScheduler* js);

void SendConnectionRequestAccepted(NetRemoteStore& remoteStore, NetControl& control, ion::NetRemoteSystem* remoteSystem,
								   ion::Time incomingTimestamp, ion::TimeMS now);

inline ion::NetRemoteIndex RemoteIndex(const NetRemoteStore& remoteStore, const ion::NetSocketAddress& sa)
{
	if (remoteStore.mRemoteSystemList == nullptr)
	{
		return ion::NetGUID::InvalidNetRemoteIndex;
	}

	ION_ASSERT(sa.IsAssigned(), "Invalid address");
	auto iter = remoteStore.mAddressToRemoteIndex.Find(sa);
	return iter != remoteStore.mAddressToRemoteIndex.End() ? iter->second : ion::NetGUID::InvalidNetRemoteIndex;
}

inline ion::NetRemoteSystem* GetRemoteSystem(NetRemoteStore& remoteStore, const NetSocketAddress& address)
{
	unsigned int mRemoteIndex = RemoteIndex(remoteStore, address);
	return mRemoteIndex == ion::NetGUID::InvalidNetRemoteIndex ? nullptr : &remoteStore.mRemoteSystemList[mRemoteIndex];
}

inline const ion::NetRemoteSystem* GetRemoteSystem(const NetRemoteStore& remoteStore, const NetSocketAddress& sa)
{
	unsigned int remoteIndex = RemoteIndex(remoteStore, sa);
	return remoteIndex == ion::NetGUID::InvalidNetRemoteIndex ? nullptr : &remoteStore.mRemoteSystemList[remoteIndex];
}

inline NetRemoteId GetRemoteIdFromSocketAddress(const NetRemoteStore& remoteStore, const ion::NetSocketAddress& address, bool onlyActive)
{
	if (address.IsAssigned())
	{
		auto index = RemoteIndex(remoteStore, address);
		if (index != ion::NetGUID::InvalidNetRemoteIndex)
		{
			if (onlyActive == false || remoteStore.mRemoteSystemList[index].mMode != ion::NetMode::Disconnected)
			{
				ION_ASSERT(remoteStore.mRemoteSystemList[index].mAddress == address, "Invalid remote index");
				return remoteStore.mRemoteSystemList[index].mId;
			}
		}
	}
	return NetRemoteId();
}

NetRemoteId GetRemoteIdFromSocketAddress(const NetRemoteStore& remoteStore, const ion::NetSocketAddress& address,
										 bool calledFromNetworkThread, bool onlyActive);

inline NetRemoteSystem* GetRemoteFromSocketAddress(NetRemoteStore& remoteStore, const ion::NetSocketAddress& address,
												   bool calledFromNetworkThread, bool onlyActive)
{
	auto remoteId = GetRemoteIdFromSocketAddress(remoteStore, address, calledFromNetworkThread, onlyActive);
	return remoteId.IsValid() ? &remoteStore.mRemoteSystemList[remoteId.RemoteIndex()] : nullptr;
}

inline const NetRemoteSystem* const GetRemoteFromSocketAddress(const NetRemoteStore& remoteStore, const ion::NetSocketAddress& address,
															   bool calledFromNetworkThread, bool onlyActive)
{
	auto remoteId = GetRemoteIdFromSocketAddress(remoteStore, address, calledFromNetworkThread, onlyActive);
	return remoteId.IsValid() ? &remoteStore.mRemoteSystemList[remoteId.RemoteIndex()] : nullptr;
}

void Init(NetRemoteStore& remoteStore, const ion::NetStartupParameters& parameters, NetInterfaceResource& memoryResource);

void ResetRemoteSystem(NetRemoteStore& remoteStore, NetControl& control, NetInterfaceResource& memoryResource, NetRemoteIndex remoteIndex,
					   ion::TimeMS currentTime);

void Deinit(NetRemoteStore& remoteStore, NetControl& control, ion::TimeMS currentTime);

void AddToActiveSystemList(NetRemoteStore& remoteStore, ion::NetRemoteIndex systemIdx);
void RemoveFromActiveSystemList(NetRemoteStore& remoteStore, ion::NetRemoteIndex systemIdx);

NetRemoteIndex GetRemoteSystemFromGUID(const NetRemoteStore& remoteStore, const NetGUID guid, bool onlyActive);

inline bool AllowIncomingConnections(const NetRemoteStore& remoteStore)
{
	return remoteStore.mNumberOfIncomingConnections < remoteStore.mMaximumIncomingConnections;
}
ion::NetRemoteId GetAddressedRemoteId(const NetRemoteStore& remoteStore, const NetAddressOrRemoteRef& systemAddress,
									  bool calledFromNetworkThread);

inline ion::NetRemoteId GetAddressedRemoteId(const NetRemoteStore& remoteStore, const NetAddressOrRemoteRef& systemAddress)
{
	return GetAddressedRemoteId(remoteStore, systemAddress, false);
}

bool RegenerateGuid(NetRemoteStore& remoteStore);

struct RemoteSystemParameters
{
	NetSocket* incomingRakNetSocket = nullptr;
	uint16_t incomingMTU;
	NetGUID guid;
	uint32_t mConversationId;
	NetDataTransferSecurity mDataTransferSecurity;
	bool mIsRemoteInitiated = true;
};

ion::NetRemoteSystem* AssignSystemAddressToRemoteSystemList(NetRemoteStore& remoteStore, NetInterfaceResource& memoryResource,
															const RemoteSystemParameters& rsp, const ion::NetSocketAddress& connectAddress,
															ion::NetSocketAddress bindingAddress, bool* thisIPConnectedRecently);

inline void DereferenceRemoteSystem(NetRemoteStore& remoteStore, const ion::NetSocketAddress& sa)
{
	auto iter = remoteStore.mAddressToRemoteIndex.Find(sa);
	if (iter != remoteStore.mAddressToRemoteIndex.End())
	{
		remoteStore.mAddressToRemoteIndex.Erase(iter);
	}
}

void ReferenceRemoteSystem(NetRemoteStore& remoteStore, const ion::NetSocketAddress& sa, ion::NetRemoteIndex remoteSystemListIndex);

bool GetStatistics(NetRemoteStore& remoteStore, NetInterfaceResource& memoryResource, const NetSocketAddress& systemAddress,
						NetStats& stats);

bool GetStatistics(NetRemoteStore& remoteStore, NetInterfaceResource& memoryResource, NetRemoteId remoteId, NetStats& stats);

void GetStatisticsList(NetRemoteStore& remoteStore, NetInterfaceResource& memoryResource, NetVector<ion::NetSocketAddress>& addresses,
					   NetVector<NetGUID>& guids, NetVector<NetStats>& statistics);

void SetTimeoutTime(NetRemoteStore& remoteStore, ion::TimeMS timeMS, const NetSocketAddress& target);

ion::TimeMS GetTimeoutTime(const NetRemoteStore& remoteStore, const NetSocketAddress& target);

NetSocketAddress GetInternalID(const NetRemoteStore& remoteStore, const NetSocketAddress& systemAddress = NetUnassignedSocketAddress,
							   const int index = 0);

void SetInternalID(NetRemoteStore& remoteStore, const NetSocketAddress& systemAddress, int index);

inline ion::NetRemoteSystem* GetRemoteSystemFromAuthorityConversation(NetRemoteStore& remoteStore, uint32_t conversation)
{
	auto index = remoteStore.mAuthorityConversations.FindRemote(conversation);
	if (index != ion::NetGUID::InvalidNetRemoteIndex)
	{
		if (remoteStore.mRemoteSystemList[index].mMode == NetMode::Connected)
		{
			return &remoteStore.mRemoteSystemList[index];
		}
	}
	return nullptr;
}

bool IsLoopbackAddress(const NetRemoteStore& remoteStore, const NetAddressOrRemoteRef& systemIdentifier, bool matchPort);

inline const NetSocketAddress& GetLoopbackAddress(const NetRemoteStore& remoteStore) { return remoteStore.mIpList[0]; }

void SetConnected(NetRemoteStore& remoteStore, NetRemoteSystem& remoteSystem, const NetSocketAddress& address);
void SetMode(NetRemoteStore& remoteStore, NetRemoteSystem& remoteSystem, NetMode mode = NetMode::Disconnected);
void SetRemoteInitiated(NetRemoteStore& remoteStore, NetRemoteSystem& remoteSystem, bool isRemoteIniated);

inline ion::NetRemoteSystem* GetRemoteSystem(NetRemoteStore& remoteStore, const NetAddressOrRemoteRef& systemIdentifier,
											 bool calledFromNetworkThread, bool onlyActive)
{
	if (systemIdentifier.mRemoteId.IsValid())
	{
		ion::NetRemoteSystem* remote = remoteStore.mRemoteSystemList.Get() + systemIdentifier.mRemoteId.RemoteIndex();
		if (remote->mId.load() == systemIdentifier.mRemoteId)
		{
			if (remote->mMode != NetMode::Disconnected || !onlyActive)
			{
				return remote;
			}
		}
		return nullptr;
	}
	else
	{
		NetRemoteId remoteId = GetRemoteIdFromSocketAddress(remoteStore, systemIdentifier.mAddress, calledFromNetworkThread, onlyActive);
		return remoteId.IsValid() ? &remoteStore.mRemoteSystemList[remoteId.RemoteIndex()] : nullptr;
	}
}

inline const ion::NetRemoteSystem* const GetRemoteSystem(const NetRemoteStore& remoteStore, const NetAddressOrRemoteRef& systemIdentifier,
														 bool calledFromNetworkThread, bool onlyActive)
{
	if (systemIdentifier.mRemoteId.IsValid())
	{
		const ion::NetRemoteSystem* remote = remoteStore.mRemoteSystemList.Get() + systemIdentifier.mRemoteId.RemoteIndex();
		if (remote->mId.load() == systemIdentifier.mRemoteId)
		{
			return remote;
		}
		return nullptr;
	}
	else
	{
		NetRemoteId remoteId = GetRemoteIdFromSocketAddress(remoteStore, systemIdentifier.mAddress, calledFromNetworkThread, onlyActive);
		return remoteId.IsValid() ? &remoteStore.mRemoteSystemList[remoteId.RemoteIndex()] : nullptr;
	}
}

inline int GetAverageRtt(const NetRemoteStore& remoteStore, const NetAddressOrRemoteRef& systemIdentifier)
{
	const ion::NetRemoteSystem* remoteSystem = GetRemoteSystem(remoteStore, systemIdentifier, false, false);
	return remoteSystem ? remoteSystem->pingTracker.GetAvgPing() : -1;
}

inline int GetLastRtt(const NetRemoteStore& remoteStore, const NetAddressOrRemoteRef& systemIdentifier)
{
	const ion::NetRemoteSystem* remoteSystem = GetRemoteSystem(remoteStore, systemIdentifier, false, false);
	return remoteSystem ? remoteSystem->pingTracker.GetLatestPing() : -1;
}

inline int GetLowestRtt(const NetRemoteStore& remoteStore, const NetAddressOrRemoteRef& systemIdentifier)
{
	const ion::NetRemoteSystem* remoteSystem = GetRemoteSystem(remoteStore, systemIdentifier, false, false);
	return remoteSystem ? remoteSystem->pingTracker.GetLowestPing() : -1;
}

inline void SetOccasionalPing(NetRemoteStore& remoteStore, TimeMS time)
{
	remoteStore.mOccasionalPing = time != 0 ? ion ::SafeRangeCast<ion::NetRoundTripTime>(time) : ion::NetRoundTripTime(-1);
}

inline const NetSocketAddress& GetSocketAddress(const NetRemoteStore& remoteStore, NetRemoteId remoteId)
{
	if (remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() != remoteId)
	{
		return NetUnassignedSocketAddress;
	}
	return remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mAddress;
}

NetRemoteId GetRemoteIdThreadSafe(const NetRemoteStore& remoteStore, const NetGUID input);

inline NetRemoteId RemoteId(const NetRemoteStore& remoteStore, const ion::NetSocketAddress& sa)
{
	ion::NetRemoteIndex index = RemoteIndex(remoteStore, sa);
	return remoteStore.mRemoteSystemList[index].mId;
}

NetRemoteId GetRemoteIdThreadSafe(const NetRemoteStore& remoteStore, const NetSocketAddress& address, bool onlyActive);

NetSocketAddress GetSocketAddressThreadSafe(const NetRemoteStore& remoteStore, NetGUID guid);

NetSocketAddress GetSocketAddressThreadSafe(const NetRemoteStore& remoteStore, NetRemoteId remoteId);

NetGUID GetGUIDThreadSafe(const NetRemoteStore& remoteStore, NetRemoteId remoteId);

inline NetRemoteId GetRemoteIdThreadSafe(const NetRemoteStore& remoteStore, const NetAddressOrRemoteRef& systemIdentifier)
{
	return systemIdentifier.mRemoteId.IsValid() ? systemIdentifier.mRemoteId
												: GetRemoteIdThreadSafe(remoteStore, systemIdentifier.mAddress, false);
}

// Not thread-safe. Need to make sure reliable layer update is not ongoing when calling this.
void SendImmediate(NetRemoteStore& remoteStore, NetControl& control, NetCommandPtr command, ion::TimeMS now);

void SendImmediate(NetRemoteStore& remoteStore, NetControl& control, NetCommandPtr command, ion::TimeMS now,
				   SmallVector<NetRemoteIndex, 16, NetAllocator<NetRemoteIndex>>& outRemoteIndices);

void OnConnectedPong(NetRemoteStore& remoteStore, ion::Time now, ion::Time sentPingTime, ion::Time remoteTime,
					 ion::NetRemoteSystem* remoteSystem);

void FillIPList(NetRemoteStore& remoteStore);

unsigned GetNumberOfAddresses(const NetRemoteStore& remoteStore);

bool IsIPV6Only(const NetRemoteStore& remoteStore);

}  // namespace NetRemoteStoreLayer
}  // namespace ion
