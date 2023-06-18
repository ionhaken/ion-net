#pragma once

#include <ion/net/NetBasePeer.h>
#include <ion/net/NetPlugins.h>

namespace ion
{
class JobScheduler;
}
namespace ion
{
class NetGenericPeer : public NetBasePeer
{
	ion::NetInterfaceResource mResource;
	NetPacketReceivePlugin mReceptionPlugin;

public:
	NetGenericPeer();

	[[nodiscard]] static NetPtr<ion::NetInterface> Create(ion::NetInterfaceResource& memoryResource);

	static void Destroy(NetPtr<ion::NetInterface>&& ptr);

	static ion::NetGenericPeer* CreateInstance()
	{
		ION_MEMORY_SCOPE(tag::Network);
		return new NetGenericPeer();
	};

	static void DestroyInstance(ion::NetGenericPeer* instance) { delete instance; }

	~NetGenericPeer();

	inline ion::NetPacket* Receive() { return mReceptionPlugin.Receive(); }

	inline unsigned int GetReceiveBufferSize() { return mReceptionPlugin.GetReceiveBufferSize(); }

	class SocketListAccess
	{
		ion::NetConnections& mNetConnections;

	public:
		SocketListAccess(ion::NetConnections& connections) : mNetConnections(connections) { mNetConnections.mSocketListMutex.Lock(); }
		~SocketListAccess() { mNetConnections.mSocketListMutex.Unlock(); }

		const NetVector<NetSocket*>& Get() const { return mNetConnections.mSocketList; }

	private:
	};

	SocketListAccess GetSockets() { return SocketListAccess(mPeer->mConnections); }
};
}  // namespace ion
