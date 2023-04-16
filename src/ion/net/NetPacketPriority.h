#pragma once
#include <ion/net/NetConfig.h>

namespace ion
{
// Message packet priorities.
//
// Note that if channel has unacknowledged packets, channel will use packet priority of unacknowledged packet
// with highest priority. Thus, e.g. low priority will be used only when you are sending low priority message and there are no medium or
// higher priority messages waiting for acknowledgement.
//
// See NetChannelPriorityConfig how each priority is configured.
enum class NetPacketPriority : uint8_t
{
	Immediate,
	High,
	Medium,
	Low,
	Count  // Internal number of priorities
};

struct NetChannelPriorityConfig
{
	// Protocol internal work interval in milliseconds. Work interval allows protocol to
	// aggregate multiple messages to single datagram. It will also affect how often packets are
	// resent and acknowledged.
	// Having workInterval set to 0 has special meaning of triggering immediate network update on send and reception of immediate packet
	// will also trigger immediate flush to send acks.
	uint16_t workInterval = NetUpdateInterval;
	// Number of ACK spans result in direct retransmission, should be at least 2 or 0 to disable fast retransmission
	int resendAckSpans = 2;
	// No-delay: Lowers min retransmission timeout
	int nodelay = 1;
	// 1 = Non-concessional Flow Control [ignore packet loss concession and slow start]
	int nc = 1;
};

const NetChannelPriorityConfig NetChannelPriorityConfigs[size_t(NetPacketPriority::Count)] = {

  {.workInterval = 0},																	 // Immediate
  {.workInterval = NetUpdateInterval},													 // High
  {.workInterval = NetUpdateInterval * 2, .resendAckSpans = 0, .nodelay = 0},			 // Medium
  {.workInterval = NetUpdateInterval * 4, .resendAckSpans = 0, .nodelay = 0, .nc = 0}};	 // Low

/// How packets are delivered.
enum class NetPacketReliability : uint8_t
{
	// Reliable and ordered packet. Reliable packet will be resent until remote acknowledges it.
	Reliable,
	// Unreliable - Unreliable packet will be sent only once. Ignores congestion control.	
	// If you are sending more than MTU number of bytes, data will be automatically converted to reliable.
	Unreliable,
	// Unrealiable Ordered as unrealiable but respects channel packet order and has congestion control.
	UnrealibleOrdered,
	Count  // Internal number of reliabilities
};
}  // namespace ion
