#pragma once

#include <ion/net/NetConnections.h>
#include <ion/net/NetControl.h>
#include <ion/net/NetExchange.h>
#include <ion/net/NetReception.h>
#include <ion/net/NetSecurity.h>

namespace ion
{
class JobScheduler;

struct NetInterface
{
public:
	NetInterface(NetInterfaceResource& pool) : mControl(&pool) {}

	NetControl mControl;
	NetReception mReception;
	NetConnections mConnections;
	NetExchange mExchange;
	NetSecurity mSecurity;
};

}  // namespace ion

#include <ion/net/NetControlLayer.h>

namespace ion {

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

	void Free(ion::NetPacket* packet) { ion::NetControlLayer::DeallocateUserPacket(mNet->mControl, packet); }

	inline unsigned int GetReceiveBufferSize() { return static_cast<unsigned int>(mPacketReturnQueue.Size()); }

	inline void Push(ion::NetPacket* packet) { Enqueue(this, packet); }

	static inline void Enqueue(void* plugin, ion::NetPacket* packet);
	static inline ion::NetPacket* Dequeue(void* plugin);
	static inline void Register(void* plugin, NetInterface& iface);

private:
	NetInterface* mNet;
	MPSCQueueCounted<NetPacket*, NetInterfaceAllocator<NetPacket*>> mPacketReturnQueue;
};

void NetPacketReceivePlugin::Enqueue(void* plugin, ion::NetPacket* packet)
{
	reinterpret_cast<NetPacketReceivePlugin*>(plugin)->mPacketReturnQueue.Enqueue(std::move(packet));
}

ion::NetPacket* NetPacketReceivePlugin::Dequeue(void* plugin) { return reinterpret_cast<NetPacketReceivePlugin*>(plugin)->Receive(); }

void NetPacketReceivePlugin::Register(void* plugin, NetInterface& iface)
{
	iface.mControl.mPacketPushPlugins.Add(std::pair<void*, NetPacketPushFunction>(plugin, &NetPacketReceivePlugin::Enqueue));
	iface.mControl.mPacketPopPlugins.Add(std::pair<void*, NetPacketPopFunction>(plugin, &NetPacketReceivePlugin::Dequeue));
}

}  // namespace ion
