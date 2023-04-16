#include <ion/net/NetSimulator.h>

#if ION_NET_SIMULATOR

	
	#include <ion/net/NetRemote.h>
	#include <ion/util/Random.h>

	#include <memory>
	#include <ion/net/NetSocketLayer.h>

namespace ion
{
struct DelayedSend
{
	DelayedSend(NetSocket& socket, NetSocketSendParameters* ssp) : mSocket(socket), mSsp(ssp) {}
	NetSocket& mSocket;
	NetSocketSendParameters* mSsp;
	ion::Time sendTime;
	int32_t runningIndex;
};
bool NetworkSimulator::EarlierSendTime::operator()(std::unique_ptr<DelayedSend>& a, std::unique_ptr<DelayedSend>& b)
{
	if (a->sendTime == b->sendTime)
	{
		return static_cast<int32_t>(a->runningIndex - b->runningIndex) > 0;
	}
	return static_cast<int>(a->sendTime - b->sendTime) > 0;
}

NetworkSimulator::NetworkSimulator() {}
void NetworkSimulator::Clear()
{
	while (!mDelayList.empty())
	{
		auto& delayedSend = mDelayList.top();
		delayedSend->mSocket.DeallocateSend(delayedSend->mSsp);
		mDelayList.pop();
	}
	while (!mBandwidthLimitedList.IsEmpty()) 
	{
		auto& delayedSend = mBandwidthLimitedList.Back();
		delayedSend->mSocket.DeallocateSend(delayedSend->mSsp);
		mBandwidthLimitedList.PopBack();
	}
	mTotalBufferedBytes = 0;
}

NetworkSimulator::~NetworkSimulator()
{
	ION_ASSERT(mBandwidthLimitedList.IsEmpty(), "Simulator data left");
	ION_ASSERT(mDelayList.empty(), "Simulator data left");
}

void NetworkSimulator::Configure(const NetworkSimulatorSettings& settings) { mSettings = settings; }

bool NetworkSimulator::IsActive() const
{
	return mSettings.duplicates > 0.0f || mSettings.packetloss > 0.0f || mSettings.extraPingVariance > 0 || mSettings.minExtraPing > 0 ||
		   mSettings.mtu != NetIpMaxMtuSize || mSettings.bandwidthMBps > 0.0;
}

void NetworkSimulator::Send(NetSocketSendParameters* ssp, NetSocket& socket)
{
	uint16_t length = uint16_t(ssp->length);
	if (ion::NetMtuSize(length, socket.mBoundAddress.GetIPVersion()) > mSettings.mtu)
	{
		if (ssp->optional.options.storeSocketSendResult)
		{
			socket.mSocketSendResults.Set(ssp->mAddress, -10040);
		}
		socket.DeallocateSend(ssp);
		return;
	}

	const size_t numCopies = mSettings.duplicates > 0.0f && ion::Random::FastFloat() < mSettings.duplicates ? 2 : 1;
	NetSocketSendParameters* sspOriginal = ssp;
	for (size_t copyIndex = 0; copyIndex < numCopies; ++copyIndex)
	{
		ssp = socket.AllocateSend();
		*ssp = *sspOriginal;

		if (mSettings.packetloss > 0.0f)
		{
			if (ion::Random::FastFloat() < mSettings.packetloss)
			{
				if (ssp->optional.options.storeSocketSendResult)
				{
					socket.mSocketSendResults.Set(ssp->mAddress, ssp->length);
				}
				socket.DeallocateSend(ssp);
				continue;
			}
		}

		if (mSettings.minExtraPing > 0 || mSettings.extraPingVariance > 0 || mSettings.bandwidthMBps > 0)
		{
			uint16_t delay =
			  mSettings.minExtraPing + (mSettings.extraPingVariance ? (ion::Random::UInt32Tl() % mSettings.extraPingVariance) : 0) / 2;
			if (delay > 0 || mSettings.bandwidthMBps > 0)
			{
				ion::AutoLock<ion::Mutex> lock(mMutex);
				auto delayedSend = std::make_unique<DelayedSend>(socket, ssp);
				ION_NET_ASSERT(delayedSend->mSsp->length <= NetIpMaxMtuSize);
				delayedSend->sendTime = ion::SteadyClock::GetTimeMS() + delay;
				delayedSend->runningIndex = mRunningIndex++;
				mDelayList.push(std::move(delayedSend));
				continue;
			}
		}

		SocketLayer::SendToNetwork(socket, ssp);
	}
	socket.DeallocateSend(sspOriginal);
}

void NetworkSimulator::Update(ion::Time now)
{
	constexpr const uint32_t BandwidthBurstPeriodMillis = 250;

	ion::AutoLock<ion::Mutex> lock(mMutex);
	while (!mDelayList.empty() && ion::DeltaTime(now, mDelayList.top()->sendTime) >= 0)
	{
		auto& delayedSend = mDelayList.top();
		auto packetsize = ion::NetMtuSize(delayedSend->mSsp->length, delayedSend->mSsp->mAddress.GetIPVersion());
		mTotalBufferedBytes += packetsize;
		mBandwidthLimitedList.PushBack(std::make_unique<DelayedSend>(*delayedSend));
		mDelayList.pop();
	}
	while (!mBandwidthLimitedList.IsEmpty()) 
	{
		auto& delayedSend = mBandwidthLimitedList.Front();		
		auto packetsize = ion::NetMtuSize(delayedSend->mSsp->length, delayedSend->mSsp->mAddress.GetIPVersion());
		if (mSettings.bandwidthMBps > 0)
		{
			ion::TimeDeltaMS millis = BandwidthBurstPeriodMillis;
			if (ion::NetIsTimeInRange(mLastBandwidthUpdate, now, BandwidthBurstPeriodMillis))
			{
				millis = ion::DeltaTime(now, mLastBandwidthUpdate);
				if (millis < 0)
				{
					millis = 0;
				}
			}
			mAvailableBandwidth += mSettings.bandwidthMBps * double(millis) / 1000.0;
			mLastBandwidthUpdate = now;

			if (mAvailableBandwidth < 0)
			{
				if (double(mTotalBufferedBytes)/(1000.0*1000.0) > mSettings.maxBufferedMBytes)
				{
					mTotalBufferedBytes -= packetsize;
					delayedSend->mSocket.DeallocateSend(delayedSend->mSsp);
					mBandwidthLimitedList.PopFront();
				}
				break;
			}
			else
			{
				mAvailableBandwidth -= double(packetsize) / (1024 * 1024) * 8;
			}
		}

		mTotalBufferedBytes -= packetsize;
		SocketLayer::SendToNetwork(delayedSend->mSocket, delayedSend->mSsp);
		mBandwidthLimitedList.PopFront();
	}
	if (mAvailableBandwidth > 0)
	{
		mAvailableBandwidth = 0;
	}
}


}  // namespace ion

#endif
