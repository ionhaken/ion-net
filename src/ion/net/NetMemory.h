#pragma once

#include <ion/net/NetPayload.h>

#include <ion/arena/ArenaAllocator.h>

#include <ion/memory/TSMultiPoolResource.h>
#include <ion/memory/VirtualMemoryBuffer.h>

#include <ion/temporary/TemporaryAllocator.h>

namespace ion
{
struct NetRemoteSystem;
}
namespace ion
{

enum class NetPeerUpdateMode : uint8_t
{
	Job,
	Worker,
	User
};

template <size_t PayloadSize>
struct NetUpstreamPacket;

using NetSocketSendParameters = NetUpstreamPacket<ion::NetMaxUdpPayloadSize()>;

// #TODO: Have max memory allocation size for network core, so lots of packets will never drain whole system out of memory.
// Basically there should be 2 pools. One for user data and one for internal data. Internal data size is fixed to user value.
// Internal data pool is used only for allocating send/receive packets or any intermediate transfer data (NetTransferAllocator)

// #TODO: There needs to be separate sizes for server and client!
// using FrameResource = ion::MonotonicBufferResource<1024 * 64, ion::tag::Network>;
using NetInterfaceResource = ion::TSMultiPoolResource<VirtualMemoryBuffer, ion::tag::Network>;

using NetSendAllocator =
  ion::TemporaryAllocator<ion::NetSocketSendParameters, ion::ArenaAllocator<ion::NetSocketSendParameters, NetInterfaceResource>>;

template <typename T>
using NetInterfaceAllocator = ion::ArenaAllocator<T, ion::NetInterfaceResource>;

template <typename T>
using NetInterfacePtr = ion::ArenaPtr<T, NetInterfaceResource>;

}  // namespace ion
