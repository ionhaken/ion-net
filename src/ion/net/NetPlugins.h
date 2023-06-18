#pragma once

#include <ion/net/NetControlLayer.h>
#include <ion/net/NetInterface.h>

namespace ion
{

class NetPacketReceivePlugin
{
public:
	NetPacketReceivePlugin(NetInterfaceResource* resource) : mPacketReturnQueue(resource) {}

	inline ion::NetPacket* Receive()
	{
		ion::NetPacket* packet = nullptr;
		mPacketReturnQueue.Dequeue(packet);
		return packet;
	}

	inline unsigned int GetReceiveBufferSize() { return static_cast<unsigned int>(mPacketReturnQueue.Size()); }

	inline void Push(ion::NetPacket* packet) { Enqueue(this, packet); }

	static inline void Enqueue(void* plugin, ion::NetPacket* packet);
	static inline ion::NetPacket* Dequeue(void* plugin);
	static void Register(void* plugin, NetInterface& iface);

private:
	MPSCQueueCounted<NetPacket*, NetInterfaceAllocator<NetPacket*>> mPacketReturnQueue;
};

void NetPacketReceivePlugin::Enqueue(void* plugin, ion::NetPacket* packet)
{
	reinterpret_cast<NetPacketReceivePlugin*>(plugin)->mPacketReturnQueue.Enqueue(std::move(packet));
}

ion::NetPacket* NetPacketReceivePlugin::Dequeue(void* plugin) { return reinterpret_cast<NetPacketReceivePlugin*>(plugin)->Receive(); }

}  // namespace ion
