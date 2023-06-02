#pragma once

#include <ion/net/NetSecureTypes.h>

#include <ion/util/Math.h>
#include <ion/util/SafeRangeCast.h>

namespace ion
{

// IPv4 and IPv6 define a minimum reassembly buffer size, the minimum datagram size that we are guaranteed any implementation must support.
// For IPv4, this is 576 bytes. IPv6 raises this to 1,500 bytes. With IPv4, for example, we have no idea whether a given destination can
// accept a 577-byte datagram or not. Therefore, many IPv4 applications that use UDP (e.g., DNS, RIP, TFTP, BOOTP, SNMP) prevent
// applications from generating IP datagrams that exceed this size.
constexpr uint16_t NetIpMinimumReassemblyBufferSize = 576;

constexpr uint16_t NetUdpHeaderSize = 8;
constexpr uint16_t NetIpV6HeaderSize = 40;
constexpr uint16_t NetIpV4MinHeaderSize = 20;
// Note: If ipv4 options are enabled IP v4 header can be larger, but we do not use IP v4 options.
// constexpr uint16_t NetIpV4MaxHeaderSize = 60;

// Calculate Udp payload size that is suitable for any protocol
constexpr uint16_t NetUdpPayloadSize(uint16_t mtuSize) { return mtuSize - NetIpV6HeaderSize - NetUdpHeaderSize; }

// Estimate MTU size for payload that works for any protocol
constexpr size_t NetMtuSize(uint64_t payloadSize) { return size_t(payloadSize + NetIpV6HeaderSize + NetUdpHeaderSize); }

// Calculate payload size from MTU for given protocol
constexpr uint16_t NetUdpPayloadSize(uint16_t mtuSize, char ipVersion)
{
	return mtuSize - ((ipVersion == 6) ? NetIpV6HeaderSize : NetIpV4MinHeaderSize) - NetUdpHeaderSize;
}

// Estimate MTU size from payload for given protocol
constexpr size_t NetMtuSize(uint64_t payloadSize, char ipVersion)
{
	return size_t(payloadSize + ((ipVersion == 6) ? NetIpV6HeaderSize : NetIpV4MinHeaderSize) - NetUdpHeaderSize);
}

#ifdef ION_NET_MAXIMUM_MTU_SIZE
constexpr uint16_t NetIpMaxMtuSize = ION_NET_MAXIMUM_MTU_SIZE;
#else
	#if ION_PLATFORM_MICROSOFT
// https://docs.microsoft.com/en-us/gaming/gdk/_content/gc/networking/overviews/game-mesh/qos-networking
// "The default maximum UDP payload per packet is 1,384 bytes for Microsoft Game Development Kit (GDK)
// titles on Xbox consoles and Windows 10. Packets exceeding the MTU are likely to be fragmented,
// which can lead to additional latency or dropped packets."

constexpr uint16_t NetIpMaxMtuSize = SafeRangeCast<uint16_t>(NetMtuSize(1384));
	#else
// It is generally recommended that the MTU for a WAN interface connected to a PPPoE DSL
// network be 1492. In fact, with auto MTU discovery, 1492 is discovered to be the maximum allowed MTU.
constexpr uint16_t NetIpMaxMtuSize = 1492;
	#endif
#endif

constexpr uint16_t NetMaxUdpPayloadSize() { return NetUdpPayloadSize(NetIpMaxMtuSize, 4); }

// Connected protocol header: [conv (4 bytes)][packet sequence number (4 bytes)]
constexpr uint32_t NetConnectedProtocolHeaderSize = 8;
// Segment header: [cmd (1 byte)][frg (1 byte)[wnd (2 bytes)][sn (4 bytes)][una (4 bytes)][ts (4 bytes)]
constexpr uint32_t NetSegmentHeaderSize = 16;
// Unreliable Segment header: [cmd (1 byte)][wnd (2 bytes)][una (4 bytes)]
constexpr uint32_t NetSegmentHeaderUnrealiableSize = 7;

constexpr uint32_t NetSegmentHeaderDataLengthSize = 2;

constexpr uint32_t NetConnectedProtocolMinOverHead =
  NetSegmentHeaderUnrealiableSize + NetConnectedProtocolHeaderSize + NetSegmentHeaderDataLengthSize;
constexpr uint32_t NetConnectedProtocolOverHead = NetConnectedProtocolHeaderSize + NetSegmentHeaderSize + NetSegmentHeaderDataLengthSize;

constexpr uint16_t NetConnectedProtocolPayloadSize(bool useEncryption = true, bool isAckedData = true)
{
	return NetUdpPayloadSize(NetIpMaxMtuSize) - uint16_t(ion::NetConnectedProtocolHeaderSize) -
		   (isAckedData ? uint16_t(NetSegmentHeaderSize) : uint16_t(NetSegmentHeaderUnrealiableSize)) -
		   (useEncryption ? uint16_t(ion::NetSecure::AuthenticationTagLength) : 0) - NetSegmentHeaderDataLengthSize;
}

constexpr uint16_t NetConnectedProtocolSafePayloadSize(bool useEncryption = true, bool isAckedData = true)
{
	return NetUdpPayloadSize(NetIpMinimumReassemblyBufferSize) - uint16_t(ion::NetConnectedProtocolHeaderSize) -
		   (isAckedData ? uint16_t(NetSegmentHeaderSize) : uint16_t(NetSegmentHeaderUnrealiableSize)) -
		   (useEncryption ? uint16_t(ion::NetSecure::AuthenticationTagLength) : 0) - NetSegmentHeaderDataLengthSize;
}

constexpr uint16_t NetPreferedMtuSize[] = {ion::NetIpMaxMtuSize, 1200, ion::NetIpMinimumReassemblyBufferSize};
constexpr int NetNumMtuSizes = sizeof(NetPreferedMtuSize) / sizeof(uint16_t);
static_assert(NetIpMaxMtuSize > 1200, "Update prefered MTU list");
static_assert(1200 > ion::NetIpMinimumReassemblyBufferSize, "Update prefered MTU list");

}  // namespace ion
