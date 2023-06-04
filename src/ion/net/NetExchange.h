#pragma once

#include <ion/net/NetInternalTypes.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetRemote.h>
#include <ion/net/NetSdk.h>

#include <ion/arena/ArenaAllocator.h>

#include <ion/container/UnorderedMap.h>

#include <ion/util/Random.h>

namespace ion
{
template <typename TKey, typename TValue>
using NetMap = UnorderedMap<TKey, TValue, Hasher<TKey>, NetAllocator<Pair<TKey const, TValue>>>;

class GlobalClock;

struct NetExchange
{
	~NetExchange()
	{
		ION_ASSERT(mAddressToRemoteIndex.IsEmpty(), "Address to remote index mapping leaking");
		ION_ASSERT(mGuidToRemoteIndex.IsEmpty(), "Guid to remote index mapping leaking");
	}

	NetMap<NetSocketAddress, NetRemoteIndex> mAddressToRemoteIndex;
	NetMap<uint64_t, NetRemoteIndex> mGuidToRemoteIndex;

	struct SystemAddressDetails
	{
		NetSocketAddress mExternalSystemAddress; // our address seen by them
		NetSocketAddress mTheirInternalSystemAddress[NetMaximumNumberOfInternalIds];
	};
	NetInterfacePtr<SystemAddressDetails> mSystemAddressDetails;

	NetInterfacePtr<NetRemoteSystem> mRemoteSystemList;

	// #TODO: Revisit how user thread gets remote system for e.g. checking pings
	NetInterfacePtr<NetRemoteIndex> mActiveSystems;	 // #TODO: Need double buffering for user access
	unsigned int mActiveSystemListSize = 0;			 // #TODO: Create user thread list of active systems

	GlobalClock* mGlobalClock = nullptr;
	TimeMS mDefaultTimeoutTime = NetDefaultTimeout;
	NetRoundTripTime mOccasionalPing = NetOccasionalPingInterval;

	NetGUID mGuid;

	std::atomic<uint16_t> mNumberOfConnectedSystems = 0;
	std::atomic<uint16_t> mNumberOfIncomingConnections = 0;
	std::atomic<uint16_t> mMaximumIncomingConnections = 0;
	std::atomic<uint16_t> mMaximumNumberOfPeers = 0;

#if ION_NET_FEATURE_SECURITY == 1
	NetDataTransferSecurity mDataTransferSecurity = NetDataTransferSecurity::Secure;
#else
	NetDataTransferSecurity mDataTransferSecurity = NetDataTransferSecurity::Protected;
#endif
	bool mLimitConnectionFrequencyFromTheSameIP = false;
	bool mIsStatsEnabledByDefault = true;

	// Conversation bookkeeping for authority only.
	struct AuthorityConversations
	{
	public:
		// Authority can store keys for fast rerouting
		void StoreKey(uint32_t key, NetRemoteIndex index) { mKeys.Insert(key, index); }
		void RemoveKey(uint32_t key)
		{
			auto iter = mKeys.Find(key);
			if (iter != mKeys.End())
			{
				mKeys.Erase(iter);
			}
		}

		NetRemoteIndex FindRemote(uint32_t key) const
		{
			auto iter = mKeys.Find(key);
			return iter != mKeys.End() ? iter->second : NetGUID::InvalidNetRemoteIndex;
		}
		~AuthorityConversations() { ION_ASSERT(mKeys.IsEmpty(), "Old conversations left"); }

	private:
		NetMap<uint32_t, NetRemoteIndex> mKeys;
	};
	AuthorityConversations mAuthorityConversations;
};
}  // namespace ion
