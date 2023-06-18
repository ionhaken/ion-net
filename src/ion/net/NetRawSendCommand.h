#pragma once

#include <ion/net/NetInternalTypes.h>

#include <ion/byte/ByteBuffer.h>

namespace ion
{
class NetSocket;

class NetRawSendCommand
{
public:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(NetRawSendCommand);

	static constexpr size_t StaticSize = 128;

	// Allocates message buffer. If reserving more than static size caller must check allocation was successful with HasBuffer()
	NetRawSendCommand(NetSocket& socket, size_t reservedSize = StaticSize);

	NetSocketSendParameters& Parameters() { return *mSendParams; }

	inline ByteWriter Writer() { return ByteWriter(mBufferView); }

	size_t Size() const { return mBufferView.Size(); }

	bool HasBuffer() const { return mBufferView.Capacity() > 0; }

	void Dispatch(const NetSocketAddress& address);

	~NetRawSendCommand();

private:
	NetSocket& mSocket;
	NetUpstreamPacket<StaticSize> mStaticBuffer;
	NetSocketSendParameters* mSendParams;
	ByteBufferView<byte*> mBufferView;
};
}  // namespace ion
