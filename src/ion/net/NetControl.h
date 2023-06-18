#pragma once

#include <ion/net/NetInternalTypes.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetPacketPriority.h>
#include <ion/net/NetTypes.h>

#include <ion/concurrency/MPSCQueue.h>
namespace ion
{

namespace detail
{
class NetUpdateWorker;
class NetUpdateJob;
}  // namespace detail

struct NetCommand;

using NetCommandPtr = ArenaPtr<NetCommand, NetInterfaceResource>;

// #TODO: Replace with lock-free object pool
using NetReceiveAllocator = ArenaAllocator<NetSocketReceiveData, NetInterfaceResource>;

typedef void (*NetPacketPushFunction)(void*, ion::NetPacket*);
typedef ion::NetPacket* (*NetPacketPopFunction)(void*);

struct NetControl
{
	NetControl(NetInterfaceResource* pool)
	  : mMemoryResource(*pool), mReceiveAllocator(pool), mBufferedCommands(pool)
	{
	}
	~NetControl()
	{
#if ION_ASSERTS_ENABLED
		ION_ASSERT(mUserPacketCount == 0, "Free user packets");
#endif
	}
	NetInterfaceResource& mMemoryResource;
	NetReceiveAllocator mReceiveAllocator;

	Vector<std::pair<void*, NetPacketPushFunction>> mPacketPushPlugins;
	Vector<std::pair<void*, NetPacketPopFunction>> mPacketPopPlugins;

	MPSCQueue<NetCommandPtr, NetInterfaceAllocator<NetCommandPtr>> mBufferedCommands;
	union Updater
	{
		Updater() : mUpdateWorker(nullptr) {}
		~Updater() {}
		NetInterfacePtr<detail::NetUpdateWorker> mUpdateWorker;
		NetInterfacePtr<detail::NetUpdateJob> mUpdateJob;
	} mUpdater;
	NetPeerUpdateMode mUpdateMode = NetPeerUpdateMode::User;
	std::atomic<bool> mIsReceiving = false;	 // True only when new data incoming from socket
	std::atomic<bool> mIsActive = false;
	TimeMS mLastUpdate;
	uint32_t mResendExtraDelay = 0; // If peer has heavy load use this to avoid resending and make load even worse
	
	// Startup/Shutdown
	std::atomic<int> mNumActiveThreads = 0;
	int mNumTargetActiveThreads = 0;

#if (ION_ASSERTS_ENABLED == 1)
	std::atomic<uint64_t> mUserPacketCount = 0;
#endif
};



}  // namespace ion

