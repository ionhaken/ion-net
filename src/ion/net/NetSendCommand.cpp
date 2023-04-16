#include <ion/net/NetControlLayer.h>
#include <ion/net/NetRemoteStoreLayer.h>
#include <ion/net/NetSendCommand.h>

#include <ion/arena/ArenaAllocator.h>

namespace ion
{
namespace
{
size_t CalculateCapacity(size_t reservedSize)
{
	return ByteAlignPosition(NetCommandHeaderSize + reservedSize, alignof(NetCommand)) - NetCommandHeaderSize;
}

}  // namespace

NetCommandFacade::NetCommandFacade(NetControl& control, NetRemoteId remoteId, size_t reservedSize, NetCommand::Targets targets)
  : mControl(control),
	mCapacity(CalculateCapacity(reservedSize)),
	mCommand(MakeArenaPtrRaw<NetCommand>(&control.mMemoryResource, NetCommandHeaderSize + mCapacity, remoteId, targets))

{
}

NetCommandFacade::NetCommandFacade(NetControl& control, size_t reservedSize, const ArrayView<NetRemoteId>& remotes)
  : mControl(control),
	mCapacity(CalculateCapacity(reservedSize)),
	mCommand(MakeArenaPtrRaw<NetCommand>(&control.mMemoryResource, NetCommandHeaderSize + mCapacity, remotes))
{
}

NetCommandFacade::NetCommandFacade(NetControl& control, const NetSocketAddress& address, size_t reservedSize, NetCommand::Targets targets)
  : mControl(control),
	mCapacity(CalculateCapacity(reservedSize)),
	mCommand(MakeArenaPtrRaw<NetCommand>(&control.mMemoryResource, NetCommandHeaderSize + mCapacity, address, targets))
{
}

void NetCommandFacade::Reserve(ByteSizeType reservedSize)
{
	if (mCommand)
	{
		size_t newCapacity = CalculateCapacity(reservedSize);
		NetCommandPtr newCmd =
		  MakeArenaPtrRaw<NetCommand>(&mControl.mMemoryResource, NetCommandHeaderSize + newCapacity, mCommand, mCapacity);
		if (newCmd)
		{
			DeleteArenaPtr(&mControl.mMemoryResource, mCommand);
			mCommand = std::move(newCmd);
			mCapacity = newCapacity;
		}
	}
}

NetSendCommand::NetSendCommand(NetControl& control, NetRemoteId remoteId, size_t reservedSize, NetCommand::Targets targets)
  : mFacade(control, remoteId, reservedSize, targets), mBufferView(mFacade, reservedSize)
{
	if ION_UNLIKELY (!mFacade.mCommand.Get())
	{
		NotifyOutOfMemory();
	}
}

NetSendCommand::NetSendCommand(NetControl& control, const NetSocketAddress& address, size_t reservedSize, NetCommand::Targets targets)
  : mFacade(control, address, reservedSize, targets), mBufferView(mFacade, reservedSize)
{
	if ION_UNLIKELY (!mFacade.mCommand.Get())
	{
		NotifyOutOfMemory();
	}
}

NetSendCommand::NetSendCommand(NetControl& control, size_t reservedSize, const ArrayView<NetRemoteId>& remotes)
  : mFacade(control, reservedSize, remotes), mBufferView(mFacade, reservedSize)
{
	if ION_UNLIKELY (!mFacade.mCommand.Get())
	{
		NotifyOutOfMemory();
	}
}

void NetSendCommand::Dispatch()
{
	mFacade.mCommand->mNumberOfBytesToSend = mBufferView.Size();
	ION_ASSERT(mFacade.mCommand->mNumberOfBytesToSend, "Message writing did not complete");
	return NetControlLayer::SendBuffered(mFacade.mControl, std::move(mFacade.mCommand));
}

void NetSendCommand::Cancel() { DeleteArenaPtr(&mFacade.mControl.mMemoryResource, mFacade.mCommand); }

NetSendCommand::~NetSendCommand() { ION_ASSERT(mFacade.mCommand == nullptr, "Message was never sent"); }

}  // namespace ion
