#pragma once

#include <ion/net/NetChannel.h>
#include <ion/net/NetMessages.h>

#include <ion/container/Vector.h>

#include <ion/debug/AccessGuard.h>

#include <array>

namespace ion
{
// 0...31 KCP channel reservation
constexpr uint8_t NetNumberOfChannels = 32;

struct NetTransport
{
	Vector<NetChannel, NetAllocator<NetChannel>> mOrderedChannels;	// #TODO: Move to NetExchange
	Deque<NetPacket*, NetAllocator<NetPacket*>> mRcvQueue;			// #TODO: Move to NetReception
	std::array<uint8_t, NetNumberOfChannels> mIdToChannel;

	// Filters out duplicate packets. It's also needed for security reasons to prevent malicious users replaying old packets to break
	// connected protocol. See. https://en.wikipedia.org/wiki/Replay_attack
	struct DuplicateProtection
	{
		static constexpr uint32_t NumSequences = 512;
		UniquePtr<Array<uint32_t, NumSequences>> mReceivedSequences;
		uint32_t mLatestSequence = 0;

		DuplicateProtection() {}

		bool OnSequenceReceived(uint32_t sequence)
		{
			int32_t deltaToLatestSequence = int32_t(mLatestSequence - sequence);
			
			if (mReceivedSequences == nullptr) 
			{
				if (deltaToLatestSequence == -1) 
				{
					mLatestSequence = sequence;
					return true;
				}
				ION_NET_LOG_VERBOSE("First out of sequence packet detected");
				mReceivedSequences = MakeUnique<Array<uint32_t, NumSequences>>();
				ion::ForEach(*mReceivedSequences, [&](auto& item) { item = mLatestSequence; });
			}

			size_t index = sequence % NumSequences;
			if (deltaToLatestSequence < 0)
			{
				mLatestSequence = sequence;
			}
			else if (deltaToLatestSequence >= NumSequences)
			{
				return false;
			}
			else
			{
				int32_t deltaToCurrentSequence = int32_t((*mReceivedSequences)[index] - sequence);
				if (deltaToCurrentSequence > 0)
				{
					return false;
				}
			}
			(*mReceivedSequences)[index] = sequence;
			return true;
		}
	};

	DuplicateProtection mDuplicateProtection;

	uint32_t mNextSequence = 1;

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
