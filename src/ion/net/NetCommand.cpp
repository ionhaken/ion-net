#include <ion/net/NetCommand.h>

#include <ion/container/ForEach.h>

namespace ion
{
NetCommand::NetCommand() : mCommand(NetCommandType::SendExcludingRemote) {}
NetCommand::NetCommand(const NetSocketAddress& address) : mTarget(address), mCommand(NetCommandType::SendAddresses) {}
NetCommand::NetCommand(const NetSocketAddress& address, Targets targets)
  : mTarget(address), mCommand(targets == Targets::Include ? NetCommandType::SendAddresses : NetCommandType::SendExcludingAddresses)
{
}
NetCommand::NetCommand(const ArrayView<NetRemoteId>& remotes) : mTarget(remotes), mCommand(NetCommandType::SendRemotes) {}
NetCommand::NetCommand(const ArrayView<NetSocketAddress>& addresses) : mTarget(addresses), mCommand(NetCommandType::SendAddresses) {}

NetCommand::NetCommand(NetCommandPtr& other, size_t capacity)
  : mTarget(std::move(other->mTarget), other->mCommand),
	mNumberOfBytesToSend(other->mNumberOfBytesToSend),
	mRefCount(other->mRefCount.load()),
	mChannel(other->mChannel),
	mCommand(other->mCommand),
	mPriority(other->mPriority),
	mReliability(other->mReliability),
	mConnectionMode(other->mConnectionMode)
{
	memcpy((char*)this + NetCommandHeaderSize, (char*)other.Get() + NetCommandHeaderSize, capacity);
}

NetCommand ::~NetCommand()
{
	if (mCommand == NetCommandType::SendRemotes)
	{
		mTarget.mRemoteList.~Vector();
	}
	else if (mCommand == NetCommandType::SendAddresses || mCommand == NetCommandType::SendExcludingAddresses ||
			 mCommand == ion::NetCommandType::PingAddress || mCommand == NetCommandType::ChangeSystemAddress)
	{
		mTarget.mAddressList.~Vector();
	}
}

NetCommand::Target::Target(Target&& other, NetCommandType cmd) : mRemoteId(other.mRemoteId)
{
	if (cmd == NetCommandType::SendRemotes)
	{
		new (&mRemoteList) NetVector<NetRemoteId>();
		mRemoteList = std::move(other.mRemoteList);
	}
	else if (cmd == NetCommandType::SendAddresses || cmd == NetCommandType::SendExcludingAddresses ||
			 cmd == ion::NetCommandType::PingAddress || cmd == NetCommandType::ChangeSystemAddress)
	{
		new (&mAddressList) NetVector<NetSocketAddress>();
		mAddressList = std::move(other.mAddressList);
	}
	else
	{
		mRemoteId = other.mRemoteId;
	}
}

NetCommand::Target::Target() : mRemoteId() {}

NetCommand::Target::Target(const NetSocketAddress& address) : mAddressList() { mAddressList.Add(address); }

NetCommand::Target::Target(const ArrayView<NetRemoteId>& remotes) : mRemoteList()
{
	mRemoteList.Reserve(remotes.Size());
	ForEach(remotes, [&](auto& elem) { mRemoteList.AddKeepCapacity(elem); });
}

NetCommand::Target::Target(const ArrayView<NetSocketAddress>& addresses) : mAddressList()
{
	mAddressList.Reserve(addresses.Size());
	ForEach(addresses, [&](auto& elem) { mAddressList.AddKeepCapacity(elem); });
}

}  // namespace ion
