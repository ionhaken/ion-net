#pragma once

#include <ion/net/NetExchange.h>
#include <ion/net/NetGUID.h>
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

namespace NetExchangeLayer
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

ConnectionResult AssignRemote(NetExchange& exchange, const NetConnections& connections, NetInterfaceResource& memoryResource,
							  const ion::NetSocketAddress& connectAddress, const ion::NetSocketAddress& bindingAddress,
							  NetSocket* netSocket, ion::NetGUID guid, NetDataTransferSecurity dataTransferSecurity, uint16_t mtu);

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

void Update(NetExchange& exchange, NetControl& control, ion::TimeMS now, ion::JobScheduler* js);

void SendConnectionRequestAccepted(NetExchange& exchange, const NetConnections& connections, NetControl& control,
								   ion::NetRemoteSystem& remote, ion::Time incomingTimestamp, ion::TimeMS now);

inline ion::NetRemoteIndex RemoteIndex(const NetExchange& exchange, const ion::NetSocketAddress& sa)
{
	if (exchange.mRemoteSystemList == nullptr)
	{
		return ion::NetGUID::InvalidNetRemoteIndex;
	}

	ION_ASSERT(sa.IsAssigned(), "Invalid address");
	auto iter = exchange.mAddressToRemoteIndex.Find(sa);
	return iter != exchange.mAddressToRemoteIndex.End() ? iter->second : ion::NetGUID::InvalidNetRemoteIndex;
}

inline ion::NetRemoteSystem* GetRemoteSystem(NetExchange& exchange, const NetSocketAddress& address)
{
	unsigned int mRemoteIndex = RemoteIndex(exchange, address);
	return mRemoteIndex == ion::NetGUID::InvalidNetRemoteIndex ? nullptr : &exchange.mRemoteSystemList[mRemoteIndex];
}

inline const ion::NetRemoteSystem* GetRemoteSystem(const NetExchange& exchange, const NetSocketAddress& sa)
{
	unsigned int remoteIndex = RemoteIndex(exchange, sa);
	return remoteIndex == ion::NetGUID::InvalidNetRemoteIndex ? nullptr : &exchange.mRemoteSystemList[remoteIndex];
}

inline NetRemoteId GetRemoteIdFromSocketAddress(const NetExchange& exchange, const ion::NetSocketAddress& address, bool onlyActive)
{
	if (address.IsAssigned())
	{
		auto index = RemoteIndex(exchange, address);
		if (index != ion::NetGUID::InvalidNetRemoteIndex)
		{
			if (onlyActive == false || exchange.mRemoteSystemList[index].mMode != ion::NetMode::Disconnected)
			{
				ION_ASSERT(exchange.mRemoteSystemList[index].mAddress == address, "Invalid remote index");
				return exchange.mRemoteSystemList[index].mId;
			}
		}
	}
	return NetRemoteId();
}

NetRemoteId GetRemoteIdFromSocketAddress(const NetExchange& exchange, const ion::NetSocketAddress& address, bool calledFromNetworkThread,
										 bool onlyActive);

inline NetRemoteSystem* GetRemoteFromSocketAddress(NetExchange& exchange, const ion::NetSocketAddress& address,
												   bool calledFromNetworkThread, bool onlyActive)
{
	auto remoteId = GetRemoteIdFromSocketAddress(exchange, address, calledFromNetworkThread, onlyActive);
	return remoteId.IsValid() ? &exchange.mRemoteSystemList[remoteId.RemoteIndex()] : nullptr;
}

inline const NetRemoteSystem* const GetRemoteFromSocketAddress(const NetExchange& exchange, const ion::NetSocketAddress& address,
															   bool calledFromNetworkThread, bool onlyActive)
{
	auto remoteId = GetRemoteIdFromSocketAddress(exchange, address, calledFromNetworkThread, onlyActive);
	return remoteId.IsValid() ? &exchange.mRemoteSystemList[remoteId.RemoteIndex()] : nullptr;
}

void Init(NetExchange& exchange, const ion::NetStartupParameters& parameters, NetInterfaceResource& memoryResource);

void ResetRemoteSystem(NetExchange& exchange, NetControl& control, NetInterfaceResource& memoryResource, NetRemoteIndex remoteIndex,
					   ion::TimeMS currentTime);

void Deinit(NetExchange& exchange, NetControl& control, ion::TimeMS currentTime);

void AddToActiveSystemList(NetExchange& exchange, ion::NetRemoteIndex systemIdx);
void RemoveFromActiveSystemList(NetExchange& exchange, ion::NetRemoteIndex systemIdx);

NetRemoteIndex GetRemoteSystemFromGUID(const NetExchange& exchange, const NetGUID guid, bool onlyActive);

inline bool AllowIncomingConnections(const NetExchange& exchange)
{
	return exchange.mNumberOfIncomingConnections < exchange.mMaximumIncomingConnections;
}
ion::NetRemoteId GetAddressedRemoteId(const NetExchange& exchange, const NetAddressOrRemoteRef& systemAddress,
									  bool calledFromNetworkThread);

inline ion::NetRemoteId GetAddressedRemoteId(const NetExchange& exchange, const NetAddressOrRemoteRef& systemAddress)
{
	return GetAddressedRemoteId(exchange, systemAddress, false);
}

bool RegenerateGuid(NetExchange& exchange);

struct RemoteSystemParameters
{
	NetSocket* incomingNetSocket = nullptr;
	uint16_t incomingMTU;
	NetGUID guid;
	uint32_t mConversationId;
	NetDataTransferSecurity mDataTransferSecurity;
	bool mIsRemoteInitiated = true;
};

ion::NetRemoteSystem* AssignSystemAddressToRemoteSystemList(NetExchange& exchange, const NetConnections& connections,
															NetInterfaceResource& memoryResource, const RemoteSystemParameters& rsp,
															const ion::NetSocketAddress& connectAddress,
															ion::NetSocketAddress bindingAddress, bool* thisIPConnectedRecently);

inline void DereferenceRemoteSystem(NetExchange& exchange, const ion::NetSocketAddress& sa)
{
	auto iter = exchange.mAddressToRemoteIndex.Find(sa);
	if (iter != exchange.mAddressToRemoteIndex.End())
	{
		exchange.mAddressToRemoteIndex.Erase(iter);
	}
}

void ReferenceRemoteSystem(NetExchange& exchange, const ion::NetSocketAddress& sa, ion::NetRemoteIndex remoteSystemListIndex);

bool GetStatistics(NetExchange& exchange, NetInterfaceResource& memoryResource, const NetSocketAddress& systemAddress, NetStats& stats);

bool GetStatistics(NetExchange& exchange, NetInterfaceResource& memoryResource, NetRemoteId remoteId, NetStats& stats);

void GetStatisticsList(NetExchange& exchange, NetInterfaceResource& memoryResource, NetVector<ion::NetSocketAddress>& addresses,
					   NetVector<NetGUID>& guids, NetVector<NetStats>& statistics);

void SetTimeoutTime(NetExchange& exchange, ion::TimeMS timeMS, const NetSocketAddress& target);

ion::TimeMS GetTimeoutTime(const NetExchange& exchange, const NetSocketAddress& target);

void SetInternalID(NetExchange& exchange, const NetSocketAddress& systemAddress, int index);

inline ion::NetRemoteSystem* GetRemoteSystemFromAuthorityConversation(NetExchange& exchange, uint32_t conversation)
{
	auto index = exchange.mAuthorityConversations.FindRemote(conversation);
	if (index != ion::NetGUID::InvalidNetRemoteIndex)
	{
		if (exchange.mRemoteSystemList[index].mMode == NetMode::Connected)
		{
			return &exchange.mRemoteSystemList[index];
		}
	}
	return nullptr;
}

void SetConnected(NetExchange& exchange, NetRemoteSystem& remoteSystem, const NetSocketAddress& address);
void SetMode(NetExchange& exchange, NetRemoteSystem& remoteSystem, NetMode mode = NetMode::Disconnected);
void SetRemoteInitiated(NetExchange& exchange, NetRemoteSystem& remoteSystem, bool isRemoteIniated);

inline ion::NetRemoteSystem* GetRemoteSystem(NetExchange& exchange, const NetAddressOrRemoteRef& systemIdentifier,
											 bool calledFromNetworkThread, bool onlyActive)
{
	if (systemIdentifier.mRemoteId.IsValid())
	{
		ion::NetRemoteSystem* remote = exchange.mRemoteSystemList.Get() + systemIdentifier.mRemoteId.RemoteIndex();
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
		NetRemoteId remoteId = GetRemoteIdFromSocketAddress(exchange, systemIdentifier.mAddress, calledFromNetworkThread, onlyActive);
		return remoteId.IsValid() ? &exchange.mRemoteSystemList[remoteId.RemoteIndex()] : nullptr;
	}
}

inline const ion::NetRemoteSystem* const GetRemoteSystem(const NetExchange& exchange, const NetAddressOrRemoteRef& systemIdentifier,
														 bool calledFromNetworkThread, bool onlyActive)
{
	if (systemIdentifier.mRemoteId.IsValid())
	{
		const ion::NetRemoteSystem* remote = exchange.mRemoteSystemList.Get() + systemIdentifier.mRemoteId.RemoteIndex();
		if (remote->mId.load() == systemIdentifier.mRemoteId)
		{
			return remote;
		}
		return nullptr;
	}
	else
	{
		NetRemoteId remoteId = GetRemoteIdFromSocketAddress(exchange, systemIdentifier.mAddress, calledFromNetworkThread, onlyActive);
		return remoteId.IsValid() ? &exchange.mRemoteSystemList[remoteId.RemoteIndex()] : nullptr;
	}
}

inline int GetAverageRtt(const NetExchange& exchange, const NetAddressOrRemoteRef& systemIdentifier)
{
	const ion::NetRemoteSystem* remoteSystem = GetRemoteSystem(exchange, systemIdentifier, false, false);
	return remoteSystem ? remoteSystem->pingTracker.GetAvgPing() : -1;
}

inline int GetLastRtt(const NetExchange& exchange, const NetAddressOrRemoteRef& systemIdentifier)
{
	const ion::NetRemoteSystem* remoteSystem = GetRemoteSystem(exchange, systemIdentifier, false, false);
	return remoteSystem ? remoteSystem->pingTracker.GetLatestPing() : -1;
}

inline int GetLowestRtt(const NetExchange& exchange, const NetAddressOrRemoteRef& systemIdentifier)
{
	const ion::NetRemoteSystem* remoteSystem = GetRemoteSystem(exchange, systemIdentifier, false, false);
	return remoteSystem ? remoteSystem->pingTracker.GetLowestPing() : -1;
}

inline void SetOccasionalPing(NetExchange& exchange, TimeMS time)
{
	exchange.mOccasionalPing = time != 0 ? ion ::SafeRangeCast<ion::NetRoundTripTime>(time) : ion::NetRoundTripTime(-1);
}

NetRemoteId GetRemoteIdThreadSafe(const NetExchange& exchange, const NetGUID input);

inline NetRemoteId RemoteId(const NetExchange& exchange, const ion::NetSocketAddress& sa)
{
	ion::NetRemoteIndex index = RemoteIndex(exchange, sa);
	return exchange.mRemoteSystemList[index].mId;
}

NetRemoteId GetRemoteIdThreadSafe(const NetExchange& exchange, const NetSocketAddress& address, bool onlyActive);

void GetSocketAddressThreadSafe(const NetExchange& exchange, NetGUID guid, NetSocketAddress& out);

void GetSocketAddressThreadSafe(const NetExchange& exchange, NetRemoteId remoteId, NetSocketAddress& out);

NetGUID GetGUIDThreadSafe(const NetExchange& exchange, NetRemoteId remoteId);

inline NetRemoteId GetRemoteIdThreadSafe(const NetExchange& exchange, const NetSocketAddress& address)
{
	return GetRemoteIdThreadSafe(exchange, address, false);
}

// Not thread-safe. Need to make sure reliable layer update is not ongoing when calling this.
void SendImmediate(NetExchange& exchange, NetControl& control, NetCommandPtr command, ion::TimeMS now);

void SendImmediate(NetExchange& exchange, NetControl& control, NetCommandPtr command, ion::TimeMS now,
				   SmallVector<NetRemoteIndex, 16, NetAllocator<NetRemoteIndex>>& outRemoteIndices);

void OnConnectedPong(NetExchange& exchange, ion::Time now, ion::Time sentPingTime, ion::Time remoteTime,
					 ion::NetRemoteSystem& remoteSystem);

void GetInternalID(const NetExchange& exchange, NetSocketAddress& out, const NetSocketAddress& systemAddress = NetUnassignedSocketAddress,
				   const int index = 0);

void GetExternalID(const NetExchange& exchange, const NetSocketAddress& in, NetSocketAddress& out);

}  // namespace NetExchangeLayer
}  // namespace ion
