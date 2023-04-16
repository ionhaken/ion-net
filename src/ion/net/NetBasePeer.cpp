#include <ion/net/NetBasePeer.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/concurrency/Runner.h>

#include <ion/jobs/JobScheduler.h>

#include <ion/core/Core.h>

namespace ion
{
NetBasePeer::NetBasePeer(ion::NetInterfaceResource& resource) : BasePeer() { Init(resource); }
NetBasePeer::NetBasePeer() : BasePeer(){};

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
}  // namespace ion
