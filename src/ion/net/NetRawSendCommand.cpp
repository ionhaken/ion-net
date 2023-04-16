#include <ion/net/NetRawSendCommand.h>
#include <ion/net/NetSocketLayer.h>

namespace ion
{
namespace
{
NetSocketSendParameters* SelectBuffer(size_t reservedSize, NetSocket& socket, NetUpstreamPacket<128>& local)
{
	return (reservedSize > NetRawSendCommand::StaticSize || !ion::SocketLayer::CanDoBlockingSend(socket))
			 ? socket.AllocateSend()
			 : reinterpret_cast<NetSocketSendParameters*>(&local);
}
}  // namespace

NetRawSendCommand::NetRawSendCommand(NetSocket& socket, size_t reservedSize)
  : mSocket(socket),
	mSendParams(SelectBuffer(reservedSize, socket, mStaticBuffer)),
	mBufferView(mSendParams ? reinterpret_cast<byte*>(mSendParams->data) : nullptr, reservedSize)
{
	ION_ASSERT(mSendParams == nullptr || mSendParams->optional.mask == 0, "Invalid mask");
	if ION_UNLIKELY (!mSendParams)
	{
		NotifyOutOfMemory();
	}
}

NetRawSendCommand::~NetRawSendCommand() { ION_ASSERT(mSendParams == nullptr, "Message was never sent"); }

void NetRawSendCommand::Dispatch(const NetSocketAddress& address)
{
	mSendParams->length = mBufferView.Size();
	ION_ASSERT(mSendParams->length, "Message writing did not complete");
	mSendParams->SetAddress(address);
	if (SocketLayer::CanDoBlockingSend(mSocket))
	{
		SocketLayer::SendBlocking(mSocket, *mSendParams);
		if (mSendParams != reinterpret_cast<NetSocketSendParameters*>(&mStaticBuffer))
		{
			mSocket.DeallocateSend(mSendParams);
		}
	}
	else
	{
		SocketLayer::SendTo(mSocket, mSendParams);
	}
	mSendParams = nullptr;
}

}  // namespace ion
