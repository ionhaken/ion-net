#pragma once

#include <ion/net/NetBasePeer.h>

namespace ion
{
class JobScheduler;
}
namespace ion
{
class NetGeneralPeer : public NetBasePeer
{
	ion::NetInterfaceResource mResource;

public:
	NetGeneralPeer();

	[[nodiscard]] static NetPtr<ion::NetInterface> Create(ion::NetInterfaceResource& memoryResource);

	static void Destroy(NetPtr<ion::NetInterface>&& ptr);

	static ion::NetGeneralPeer* CreateInstance()
	{
		ION_MEMORY_SCOPE(tag::Network);
		return new NetGeneralPeer();
	};

	static void DestroyInstance(ion::NetGeneralPeer* instance) { delete instance; }

	~NetGeneralPeer();
};
}  // namespace ion
