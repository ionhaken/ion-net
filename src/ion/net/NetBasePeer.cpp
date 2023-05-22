#include <ion/net/NetBasePeer.h>
#include <ion/net/NetControlLayer.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetRemoteStoreLayer.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/concurrency/Runner.h>

#include <ion/jobs/JobScheduler.h>

#include <ion/core/Core.h>

namespace ion
{
NetBasePeer::NetBasePeer(ion::NetInterfaceResource& resource) { Init(resource); }
NetBasePeer::NetBasePeer(){};

void NetBasePeer::Init(ion::NetInterfaceResource& resource)
{
	ION_MEMORY_SCOPE(tag::Network);
	mPeer = ion::MakeNetPtr<ion::NetInterface>(resource);
}

void NetBasePeer::Deinit(unsigned int blockingTime)
{
	Shutdown(blockingTime, 0, NetPacketPriority::Low);
	DeleteNetPtr(mPeer);
}

NetBasePeer::~NetBasePeer()
{
	if (mPeer)
	{
		Deinit();
	}
}

int NetBasePeer::SendList(const char** data, const int* lengths, const int numParameters, NetPacketPriority priority,
						  NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier,
						  bool broadcast)
{
	ION_NET_API_CHECK(data, -1, "invalid data");
	ION_NET_API_CHECK(lengths, -1, "invalid data");
	ION_NET_API_CHECK(numParameters, -1, "invalid data");
	ION_ASSERT(IsActive(), "Not active");

	if (mPeer->mRemoteStore.mRemoteSystemList == nullptr)
		return 0;

	if (broadcast == false && systemIdentifier.IsUndefined())
		return 0;

	SendBufferedList(data, lengths, numParameters, priority, reliability, orderingChannel, systemIdentifier, broadcast,
					 NetMode::Disconnected);

	return 1;
}

void NetBasePeer::SendBufferedList(const char** data, const int* lengths, const int numParameters, NetPacketPriority priority,
								   NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier,
								   bool broadcast, NetMode connectionMode)
{
	ION_ASSERT(broadcast || !systemIdentifier.IsUndefined(), "Invalid system");

	unsigned int totalLength = 0;
	unsigned int lengthOffset;
	int i;
	for (i = 0; i < numParameters; i++)
	{
		if (lengths[i] > 0)
			totalLength += lengths[i];
	}
	if (totalLength == 0)
		return;

	NetSendCommand cmd(CreateSendCommand(systemIdentifier, totalLength, broadcast));
	char* dataAggregate = &cmd.Parameters().mData;

	for (i = 0, lengthOffset = 0; i < numParameters; i++)
	{
		if (lengths[i] > 0)
		{
			memcpy(dataAggregate + lengthOffset, data[i], lengths[i]);
			lengthOffset += lengths[i];
		}
	}

	auto ptr = cmd.Release();
	ptr->mNumberOfBytesToSend = totalLength;
	ptr->mConnectionMode = connectionMode;
	ptr->mChannel = orderingChannel;
	ptr->mPriority = priority;
	ptr->mReliability = reliability;
	if (broadcast == false && ion::NetRemoteStoreLayer::IsLoopbackAddress(mPeer->mRemoteStore, systemIdentifier, true))
	{
		SendLoopback(dataAggregate, totalLength);
		DeleteArenaPtr(&mPeer->mControl.mMemoryResource, ptr);
		return;
	}

	NetControlLayer::SendBuffered(mPeer->mControl, std::move(ptr));
}

NetConnectionAttemptResult NetBasePeer::Connect(const char* host, unsigned short remotePort, const char* passwordData,
												int passwordDataLength, ion::NetSecure::PublicKey* publicKey,
												unsigned connectionSocketIndex, unsigned sendConnectionAttemptCount,
												unsigned timeBetweenSendConnectionAttemptsMS, ion::TimeMS timeoutTime)
{
	NetConnectTarget target{
	  host,
	  remotePort,
	};
	return Connect(target, passwordData, passwordDataLength, publicKey, connectionSocketIndex, sendConnectionAttemptCount,
				   timeBetweenSendConnectionAttemptsMS, timeoutTime);
}

bool NetBasePeer::Ping(const char* host, unsigned short remotePort, bool onlyReplyOnAcceptingConnections,
					   unsigned connectionSocketIndex)
{
	ion::NetConnectTarget target{host, remotePort};
	return ion_net_ping((ion_net_peer)mPeer.Get(), (ion_net_connect_target)&target, onlyReplyOnAcceptingConnections, connectionSocketIndex);
}

}  // namespace ion
