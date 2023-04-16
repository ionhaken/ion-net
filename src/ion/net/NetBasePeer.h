#pragma once

#include <ion/BasePeer.h>

namespace ion
{
class JobScheduler;
}
namespace ion
{
class NetBasePeer : public BasePeer
{
public:
	NetBasePeer(ion::NetInterfaceResource& resource);
	NetBasePeer();

	~NetBasePeer();

	void PreUpdate() { BasePeer::PreUpdate(*mPeer.Get()); }

	void PostUpdate() { BasePeer::PostUpdate(*mPeer.Get()); }

protected:
	static constexpr unsigned int ShutdownWaitTimeMs = 1500;
	void Init(ion::NetInterfaceResource& resource);
	void Deinit(unsigned int blockingTime = ShutdownWaitTimeMs);
};
}  // namespace ion
