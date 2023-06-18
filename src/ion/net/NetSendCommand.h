#pragma once

#include <ion/net/NetCommand.h>
#include <ion/net/NetControl.h>

#include <ion/byte/ByteBuffer.h>

namespace ion
{

struct NetCommandFacade
{
	NetCommandFacade(NetControl& control, NetRemoteId remoteId, size_t reservedSize, NetCommand::Targets targets);
	NetCommandFacade(NetControl& control, const NetSocketAddress& address, size_t reservedSize, NetCommand::Targets targets);
	NetCommandFacade(NetControl& control, size_t reservedSize, const ArrayView<NetRemoteId>& remotes);
	void Reserve(ByteSizeType);
	NetControl& mControl;
	size_t mCapacity;
	NetCommandPtr mCommand;
};

template <>
class ByteBufferView<NetCommandFacade> : public ByteBufferBase
{
public:
	ION_CLASS_NON_COPYABLE(ByteBufferView<NetCommandFacade>);

	ByteBufferView(NetCommandFacade& facade, size_t size) : mFacade(facade)
	{
		SetBuffer((byte*)&mFacade.mCommand->mData, SafeRangeCast<ByteSizeType>(size));
		Rewind(0);
	}

	~ByteBufferView() {}

protected:
	void SetSize(ByteSizeType s) final
	{
		mFacade.Reserve(s);
		SetBuffer((byte*)&mFacade.mCommand->mData, s);
	}

private:
	NetCommandFacade& mFacade;
};

class NetSendCommand
{
public:
	ION_CLASS_NON_COPYABLE(NetSendCommand);

	explicit NetSendCommand(NetControl& control, NetRemoteId remote, size_t reservedSize,
							NetCommand::Targets target = NetCommand::Targets::Include);

	explicit NetSendCommand(NetControl& control, const NetSocketAddress& address, size_t reservedSize,
							NetCommand::Targets target = NetCommand::Targets::Include);

	explicit NetSendCommand(NetControl& control, size_t reservedSize, const ArrayView<NetRemoteId>& remotes);

	inline ByteWriter Writer() { return ByteWriter(mBufferView); }

	inline ByteWriterUnsafe WriterUnsafe() { return ByteWriterUnsafe(mBufferView.Begin(), mBufferView.Begin() + mBufferView.Size()); }

	void Dispatch();

	void Cancel();

	inline bool HasBuffer() const { return mBufferView.Capacity() > 0; }

	inline bool IsValid() const { return mBufferView.Size() > 0; }

	~NetSendCommand();

	inline NetCommand& Parameters() { return *mFacade.mCommand.Get(); }

	inline NetCommandPtr Release()
	{
		mFacade.mCommand->mNumberOfBytesToSend = mBufferView.Size();
		return mFacade.mCommand.Release();
	}

private:
	NetCommandFacade mFacade;
	ByteBufferView<NetCommandFacade> mBufferView;
};

}  // namespace ion
