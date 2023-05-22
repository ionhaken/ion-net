#pragma once

#include <ion/net/NetMemory.h>
#include <ion/net/NetSdk.h>

#include <ion/arena/ArenaAllocator.h>

#include <ion/container/Vector.h>

#include <ion/concurrency/SPSCQueue.h>

#include <ion/util/InplaceFunction.h>

namespace ion
{
struct NetBanStruct
{
	ion::Array<char, 16> IP;
	ion::TimeMS timeout;  // 0 for infinite ban
	ion::TimeMS mNextResponse;
};

enum class NetBanStatus : uint8_t
{
	NotBanned,
	Banned,
	BannedRecentlyNotified
};

template <typename T>
using NetVector = Vector<T, NetAllocator<T>>;

using NetBanListVector = ion::NetVector<ion::NetInterfacePtr<NetBanStruct>>;

struct NetReception
{
	~NetReception() { ION_ASSERT(mNumBufferedBytes == 0, "Call clear buffer"); }

	ion::InplaceFunction<void()> mDataBufferedCallback;
	ion::SPSCQueue<ion::NetSocketReceiveData*> mReceiveBuffer;
	std::atomic<size_t> mNumBufferedBytes;

	ion::Synchronized<NetBanListVector> mBanList;

	std::atomic<bool> mIsAnyoneBanned = false;

	// Allow or disallow connection responses from any IP.Normally this should be false, but may be necessary
	// when connection to servers with multiple IP addresses
	bool mAllowConnectionResponseIPMigration = false;

	unsigned char mIncomingPasswordLength = 0;
	char mIncomingPassword[256];
};
}  // namespace ion
