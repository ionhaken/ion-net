#include <ion/net/NetGenericPeer.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/concurrency/Runner.h>

#include <ion/jobs/JobScheduler.h>

#include <ion/core/Core.h>

namespace ion
{
NetGenericPeer::NetGenericPeer() : NetBasePeer(), mResource(128 * 1024), mReceptionPlugin(&mResource)
{
	Init(mResource);
	RegisterPlugin(mReceptionPlugin);
}

inline NetPtr<ion::NetInterface> NetGenericPeer::Create(ion::NetInterfaceResource& memoryResource)
{
	ION_MEMORY_SCOPE(tag::Network);
	NetPtr<ion::NetInterface> net(ion::MakeNetPtr<ion::NetInterface>(memoryResource));
	return net;
}

void NetGenericPeer::Destroy(NetPtr<ion::NetInterface>&& net) { DeleteNetPtr(net); }

NetGenericPeer::~NetGenericPeer() { Deinit(); }

}  // namespace ion
