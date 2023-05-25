#pragma once

#include <ion/net/NetChannel.h>
#include <ion/net/NetMessages.h>

#include <ion/container/Vector.h>

#include <ion/debug/AccessGuard.h>

#include <array>

namespace ion
{
struct NetTransport
{
	Vector<NetChannel, NetAllocator<NetChannel>> mOrderedChannels;  // #TODO: Move to NetExchange
	Deque<NetPacket*, NetAllocator<NetPacket*>> mRcvQueue; // #TODO: Move to NetReception
	std::array<uint8_t, NetNumberOfChannels> mIdToChannel;

	// Channel tuner for channel that has most traffic. It is used to change channel parameters to optimize the channel bandwidth.
	struct ChannelTuner
	{
		enum class State : uint8_t
		{
			ScalingUpFast,	// Scale window size up fast
			ScalingUpSlow,
			Waiting	 // Wait until congestion, Let KCP do the window scaling.
		};
		double mLastDataPerMillis = 0;
		uint32_t mPeriodTotalBytesAcked = 0;
		ion::TimeMS mPeriodStart;
		// Minimum number of packets in channel to use Channel Tuner
		static constexpr uint32_t MinThreshold = MinSndWindowSize / 2;
		// Packet threshold, number of packets in channel. Channel tuner is enabled only if value is more than MinThreshold.
		// If an other channel has more packets than the threshold, that channel will changed as the priority channel.
		uint32_t mThreshold = MinThreshold;
		uint32_t mGoodWindowSize = 0;
		uint8_t mPriorityChannel = NetNumberOfChannels;
		State mState = State::ScalingUpFast;
		void FinishPeriod(ion::TimeMS now, double lastDataPerMillis = 0)
		{
			mLastDataPerMillis = lastDataPerMillis;
			mPeriodTotalBytesAcked = 0;
			mPeriodStart = now;
		}

	} mChannelTuner;
	ION_ACCESS_GUARD(mGuard);
};

}  // namespace ion
