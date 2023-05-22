#pragma once

#include <ion/net/NetInternalConfig.h>

#include <ion/container/Array.h>
#include <ion/container/RingBuffer.h>

#include <ion/debug/AccessGuard.h>

#include <atomic>
#include <ion/Base.h>

#define ION_TIMESYNC_DBG(__msg, ...)  // ION_DBG(__msg, __VA_ARGS__);

namespace ion
{
class NetRttTracker
{
public:
	static constexpr NetRoundTripTime MaxPingTime = UINT16_MAX;

	// Samples older than this will marked invalid on reception of Pong.
	static constexpr TimeMS SampleDeprecationAge = 60 * 1000;

	// Max sample age when updating lowest/average/highest ping.
	static constexpr TimeMS MaxUpdateSampleAge = 5 * 1000;

	static constexpr size_t MaxSamples = 8;

	struct Sample
	{
		Time receiveTime;
		TimeDeltaMS offset;
		NetRoundTripTime ping = MaxPingTime;

		bool IsValid() const { return ping != MaxPingTime; }

		void Reset() { ping = MaxPingTime; }
	};

	using SampleBuffer = ion::Array<Sample, MaxSamples>;

	NetRttTracker() {}
	NetRttTracker(TimeMS now);

	TimeDeltaMS GetLatestOffset() const { return mShared.mLatestOffset; }

	NetRoundTripTime GetAvgPing() const { return mShared.mAvgPing; }

	NetRoundTripTime GetLatestPing() const { return mShared.mLatestPing; }

	NetRoundTripTime GetLowestPing() const { return mShared.mLowestPing; }

	const SampleBuffer Samples() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mSamples;
	}

	const Sample GetLastSample() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mSamples[mLastSample];
	}

	TimeMS GetLastPingTime() const { return mLastPingTime; }

	void OnPing(TimeMS now);

	void OnPong(TimeMS now, TimeMS sentPingTime, TimeMS remoteTime);

	bool HasSamples() const { return mShared.mLowestPing != MaxPingTime; }

	double CalculatePacketLoss(TimeMS now);

private:
	ION_ACCESS_GUARD(mGuard);

	// Deprecates old samples and returns index to next sample slot
	uint8_t DeprecateOldSamples(TimeMS now);

	ion::DynamicRingBuffer<TimeMS, 2> mActivePings;
	SampleBuffer mSamples;
	TimeMS mLastPingTime;
	struct Shared
	{
		Shared() {}
		Shared(const Shared& other)
		  : mLatestOffset(TimeDeltaMS(other.mLatestOffset)),
			mLowestPing(NetRoundTripTime(other.mLowestPing)),
			mAvgPing(NetRoundTripTime(other.mAvgPing)),
			mLatestPing(NetRoundTripTime(other.mLatestPing))
		{
		}
		Shared& operator=(const Shared& other)
		{
			mLatestOffset = TimeDeltaMS(other.mLatestOffset);
			mLowestPing = NetRoundTripTime(other.mLowestPing);
			mAvgPing = NetRoundTripTime(other.mAvgPing);
			mLatestPing = NetRoundTripTime(other.mLatestPing);
			return *this;
		}

		std::atomic<TimeDeltaMS> mLatestOffset = 0;
		std::atomic<NetRoundTripTime> mLowestPing = MaxPingTime;
		std::atomic<NetRoundTripTime> mAvgPing = MaxPingTime;
		std::atomic<NetRoundTripTime> mLatestPing = MaxPingTime;
	} mShared;

	uint16_t mPingsReceived = 0;
	uint16_t mPingsMissed = 0;
	float mRollingPingsReceived = 0;
	float mRollingPingsMissed = 0;
	uint8_t mLastSample = UINT8_MAX;
};
}  // namespace ion
