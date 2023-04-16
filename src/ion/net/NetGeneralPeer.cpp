#include <ion/net/NetGeneralPeer.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/concurrency/Runner.h>

#include <ion/jobs/JobScheduler.h>

#include <ion/core/Core.h>

namespace ion
{
NetGeneralPeer::NetGeneralPeer() : NetBasePeer(), mResource(128 * 1024) { Init(mResource); }

inline NetPtr<ion::NetInterface> NetGeneralPeer::Create(ion::NetInterfaceResource& memoryResource)
{
	ION_MEMORY_SCOPE(tag::Network);
	NetPtr<ion::NetInterface> net(ion::MakeNetPtr<ion::NetInterface>(memoryResource));
	return net;
}

void NetGeneralPeer::Destroy(NetPtr<ion::NetInterface>&& net) { DeleteNetPtr(net); }

NetGeneralPeer::~NetGeneralPeer() { Deinit(1); }

}  // namespace ion
