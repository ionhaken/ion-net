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
	/// True to allow connection accepted packets from anyone.  False to only allow these packets from servers we requested a connection
	/// to.
	bool mAllowConnectionResponseIPMigration = false;

	unsigned char mIncomingPasswordLength = 0;
	char mIncomingPassword[256];
};
}  // namespace ion
