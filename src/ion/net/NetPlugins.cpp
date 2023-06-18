#include <ion/net/NetPlugins.h>

namespace ion
{

void NetPacketReceivePlugin::Register(void* plugin, NetInterface& iface)
{
	iface.mControl.mPacketPushPlugins.Add(std::pair<void*, NetPacketPushFunction>(plugin, &NetPacketReceivePlugin::Enqueue));
	iface.mControl.mPacketPopPlugins.Add(std::pair<void*, NetPacketPopFunction>(plugin, &NetPacketReceivePlugin::Dequeue));
}
}  // namespace ion
