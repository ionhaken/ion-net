#pragma once

#include <ion/net/NetInternalTypes.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetSecure.h>
#include <ion/net/NetSimulator.h>
#include <ion/net/NetSocketSendResultList.h>

#include <ion/time/CoreTime.h>

#include <ion/container/Array.h>

#include <ion/debug/Profiling.h>

#include <ion/memory/AllocatorTraits.h>

#include <ion/concurrency/Delegate.h>
#include <ion/concurrency/Thread.h>

#include <ion/jobs/TaskQueue.h>

#if ION_PLATFORM_APPLE
	#import <CoreFoundation/CoreFoundation.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
#endif

namespace ion
{
#if ION_PLATFORM_APPLE
using NetNativeSocket = CFSocketRef;
static constexpr const NetNativeSocket = -1;
#else

#if ION_PLATFORM_MICROSOFT
using NetNativeSocket = SOCKET;
static constexpr NetNativeSocket NetInvalidSocket = INVALID_SOCKET;
	#else
using NetNativeSocket = int;
static constexpr NetNativeSocket NetInvalidSocket = -1;
	#endif
#endif

enum class NetBindResult
{
	Success,
	FailedToBind,
	FailedToSendTest
};

struct NetBindParameters
{
	// Input parameters
	unsigned short port;
	char* hostAddress;
	unsigned short addressFamily;  // AF_INET or AF_INET6
	int type;					   // SOCK_DGRAM
	int protocol;				   // 0
	bool nonBlockingSocket;
	int setBroadcast;
	int setIPHdrIncl;
	int doNotFragment;
};

class NetSocket
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(NetSocket);

public:
	NetSocket(NetInterfaceResource* resource);

	virtual ~NetSocket() {}

	void StopSendThread()
	{
		mSendThreadEnabled = false;
		mDelegate.Shutdown();
	}

	bool mSendThreadEnabled;

	void Send(ion::NetSocketSendParameters* sendParameters);

	inline ion::NetSocketSendParameters* AllocateSend()
	{
		ion::NetSocketSendParameters* ptr = ion::Construct(mSendAllocator);
		ION_ASSERT(ptr->optional.mask == 0, "Invalid defaults");
		return ptr;
	}
	void DeallocateSend(ion::NetSocketSendParameters* sp) { ion::Destroy(mSendAllocator, sp); }

	[[nodiscard]] bool StartSendThread(ion::Thread::Priority threadPriority);

	NetNativeSocket mNativeSocket;
	ion::NetSendAllocator mSendAllocator;
#if ION_NET_FEATURE_SECURITY
	ion::NetSecure::CryptoKeys mCryptoKeys;
	ion::Array<unsigned char, ion::NetSecure::NonceLength - NetUnencryptedProtocolBytes> mNonceOffset;
#endif

	ion::Delegate<NetSocketSendParameters*, 16> mDelegate;
	ion::Runner mReceiveThread;
	std::atomic<bool> mIsReceiveThreadActive;

	// Cold data
	NetSocketAddress mBoundAddress;
	ion::NetSecure::SecretKey mBigDataKey;
	ion::NetSocketSendResultList mSocketSendResults;
	NetBindParameters mBindParameters;
	unsigned int userConnectionSocketIndex = unsigned(-1);
#if ION_NET_SIMULATOR
	ion::NetworkSimulator mNetworkSimulator;
#endif

private:
	void SendDataFromThread(ion::NetSocketSendParameters* sendParameters);
#if ION_NET_FEATURE_STREAMSOCKET

	void StreamSendData(RNS2_SendParameters* sendParameters);
#endif
};

#if ION_NET_FEATURE_STREAMSOCKET
void NetSocket::StreamSendData(RNS2_SendParameters* sendParameters)
{
	ION_PROFILER_SCOPE(Network, "Socket Send");
	// int result = ion::SocketLayer::SendTo(mNativeSocket, *sendParameters, mSocketSendResults);
	// ION_ASSERT(result >= 0, "Send failed: errorcode:" << result);
	int ret = send(streamSocket, sendParameters->data, sendParameters->length, 0);
	ION_ASSERT(ret >= 0, "Send failed:" << ion::debug::GetLastErrorString());
	Deallocate(sendParameters);
}
#endif

}  // namespace ion
