#pragma once

#include <ion/net/NetFwd.h>
#include <ion/net/NetPacketPriority.h>
#include <ion/net/NetSdk.h>
#include <ion/net/NetTypes.h>

#include <ion/container/ArrayView.h>
#include <ion/container/Vector.h>

namespace ion
{

template <typename T>
using NetVector = Vector<T, NetAllocator<T>>;

enum class NetCommandType : uint8_t
{
	SendExcludingRemote,
	SendRemote,
	SendExcludingAddresses,
	SendAddresses,
	SendExcludingRemotes,
	SendRemotes,
	CloseConnection,
	ChangeSystemAddress,
	EnableTimeSync,
	DisableTimeSync,
	PingAddress
};

struct NetCommand
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(NetCommand);

	enum class Targets
	{
		Include,
		Exclude
	};

	// Send to remote
	NetCommand(NetRemoteId remoteId) : mTarget(remoteId), mCommand(NetCommandType::SendRemote) {}

	// Broadcast to all remotes
	NetCommand();

	// Send to address
	explicit NetCommand(const NetSocketAddress& address);

	// Call with Targets::Exclude to send all remotes except given remote
	explicit NetCommand(NetRemoteId remoteId, Targets targets)
	  : mTarget(remoteId), mCommand(targets == Targets::Include ? NetCommandType::SendRemote : NetCommandType::SendExcludingRemote)
	{
	}

	// Call with Targets::Exclude to send all address excluding given address
	explicit NetCommand(const NetSocketAddress& address, Targets targets);

	// Send to remotes
	explicit NetCommand(const ArrayView<NetRemoteId>& remotes);

	// Send to addresses
	explicit NetCommand(const ArrayView<NetSocketAddress>& addresses);

	explicit NetCommand(NetCommandPtr& other, size_t capacity);

	~NetCommand();
	union Target
	{
		Target();
		Target(Target&& other, NetCommandType cmd);
		explicit Target(NetRemoteId remoteId) : mRemoteId(remoteId) {}
		explicit Target(const NetSocketAddress& address);
		explicit Target(const ArrayView<NetSocketAddress>& addresses);
		explicit Target(const ArrayView<NetRemoteId>& remotes);
		~Target() {}
		NetRemoteId mRemoteId;
		NetVector<NetSocketAddress> mAddressList;
		NetVector<NetRemoteId> mRemoteList;
	};


	Target mTarget;
	uint64_t mNumberOfBytesToSend = 0;
	// Reference count - Needs to support large value. E.g. for broadcasting a large file there's 1 ref per each segment for every target.
	std::atomic<uint64_t> mRefCount = 0; 
	uint8_t mChannel = 0;
	NetPacketPriority mPriority = NetPacketPriority::Medium;
	NetPacketReliability mReliability = NetPacketReliability::Reliable;
	NetCommandType mCommand = NetCommandType::SendRemote;
	NetMode mConnectionMode = NetMode::Disconnected;	
	// padding reserved for future use
	uint8_t mPadding1 = 0;			
	uint8_t mPadding2 = 0;			
	uint8_t mPadding3 = 0;
	alignas(void*) char mData = 0;	// Keep last - Marks payload start trailing the command.
};
static constexpr size_t NetCommandHeaderSize = offsetof(NetCommand, mData);

class NetCustomMessageInterface
{
public:
	virtual void OnSent() {}
	virtual void OnDone() {}
	virtual void* Request(size_t) { return nullptr; }
	virtual size_t Size() const { return 0; }
	virtual ~NetCustomMessageInterface(){};
};

class NetVariableSizeMessage : public NetCustomMessageInterface
{
public:
	virtual ~NetVariableSizeMessage(){};

private:
	Vector<uint8_t> mData;
};

}  // namespace ion
