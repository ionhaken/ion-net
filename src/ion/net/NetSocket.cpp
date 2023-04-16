
#include <ion/net/NetSocket.h>
#include <ion/net/NetSocketLayer.h>

namespace ion
{
NetSocket::NetSocket(NetInterfaceResource* resource)
  : mSendThreadEnabled(false),
	mNativeSocket(NetInvalidSocket),
	mSendAllocator(resource),
	mDelegate(0),
	mReceiveThread([] { ION_ASSERT(false, "Invalid socket"); })
{
}

[[nodiscard]] bool NetSocket::StartSendThread(ion::Thread::Priority threadPriority)
{
	mSendThreadEnabled = true;
	return mDelegate.Execute(threadPriority, std::bind(&NetSocket::SendDataFromThread, this, std::placeholders::_1));
}

void NetSocket::SendDataFromThread(ion::NetSocketSendParameters* bsp)
{
	ION_PROFILER_SCOPE(Network, "Socket Send");
	SocketLayer::SendBlocking(*this, *bsp);
	DeallocateSend(bsp);
}

void NetSocket::Send(ion::NetSocketSendParameters* sendParameters)
{
	ION_ASSERT(mSendThreadEnabled, "Send thread not enable");
	mDelegate.Enqueue(std::move(sendParameters));
}

}  // namespace ion
