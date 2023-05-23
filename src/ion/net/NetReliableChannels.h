#pragma once
#include <ion/net/NetChannel.h>
#include <ion/net/NetConfig.h>
#include <ion/net/NetMessages.h>
#include <ion/net/NetPacketPriority.h>
#include <ion/net/NetTime.h>

#include <ion/container/Vector.h>

#include <ion/debug/AccessGuard.h>

#include <array>

namespace ion
{
class BitStream;
struct NetControl;
}  // namespace ion

namespace ion
{

using BitStream = ion::BitStream;
using TimeMS = ion::TimeMS;
// #TODO: Rename as TransportLayer, because it needs to pass itself and also route unreliable data
class NetReliableChannels
{
public:
	NetReliableChannels();
	~NetReliableChannels();
	//void Flush(NetControl& control, NetRemoteSystem& remote, ion::TimeMS currentTime);
	void Reset(NetControl& control, NetRemoteSystem& remote);
	bool Input(NetControl& control, NetRemoteSystem& remoteSystem, uint32_t conversation, ion::NetSocketReceiveData& recvFromStruct,
			   ion::TimeMS now);
	inline NetPacket* Receive()
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		if (!mRcvQueue.IsEmpty())
		{
			NetPacket* p = mRcvQueue.Front();
			mRcvQueue.PopFront();
			return p;
		}
		return nullptr;
	}
	
	bool Send(NetControl& control, TimeMS time, NetRemoteSystem& remoteSystem, NetCommand& command, uint32_t conversation);
	void Update(NetControl& control, NetRemoteSystem& remoteSystem, ion::TimeMS now);
	bool IsOutgoingDataWaiting(void) const;
	bool AreAcksWaiting(void) const;




private:
	ION_ACCESS_GUARD(mGuard);
	NetPacket* Receive(NetChannel& channel, NetControl& control, NetRemoteSystem& remote);
	NetChannel* EnsureChannel(uint32_t channel, NetRemoteSystem& remoteSystem, ion::TimeMS now);
	bool ReconfigureUpstreamChannel(NetChannel& channel, float windowSizeMod = 0);
	void ReconfigureDownstreamChannel(NetChannel& channel);

	Vector<NetChannel, NetAllocator<NetChannel>> mOrderedChannels;
	Deque<NetPacket*, NetAllocator<NetPacket*>> mRcvQueue;
	std::array<uint8_t, NetNumberOfChannels> mIdToChannel;



	void UpdatePriorityChannelOnInput(NetChannel* stream, uint32_t conversation, ion::TimeMS now);
	void UpdatePriorityChannelOnSend(NetChannel* stream, uint32_t conversation, ion::TimeMS now);
	void ResetChannelTuner(ion::TimeMS now, uint8_t newPriorityChannel);
	void UpdateChannelTuner(NetRemoteSystem& remoteSystem, ion::TimeMS now);
	NetChannel& IdToChannel(uint8_t id);

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
};

}  // namespace ion
