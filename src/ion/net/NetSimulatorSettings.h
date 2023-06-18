#pragma once

#include <ion/net/NetConfig.h>
#include <ion/net/NetPayload.h>

#include <cstdint>

namespace ion
{
struct NetworkSimulatorSettings
{
	double corruptRate = 0.0;		   // Chance to corrup a packet. Ranges from 0 to 1.
	double packetloss = 0.0;		   // Chance to lose a packet. Ranges from 0 to 1.
	double duplicates = 0.0;		   // Chance to duplicate a packet. Ranges from 0 to 1.
	double bandwidthMBps = 0.0;		   // Bandwidth limitation
	double maxBufferedMBytes = 0.512;  // Max Mbytes in send buffer until start dropping packets if no bandwidth available
	uint16_t mtu = NetIpMaxMtuSize;	   // Maximum MTU
	uint16_t minExtraPing = 0;		   //  The minimum time to delay sends.
	uint16_t extraPingVariance = 0;	   //  Jitter
};
}  // namespace ion
