#pragma once

#include <ion/net/NetRttTracker.h>
#include <ion/util/Math.h>
#include <ion/debug/AccessGuard.h>
#include <ion/net/NetSynchronizedClock.h>

namespace ion
{
// Time synchronization
// - Supports sync also for TCP/IP or other reliable connections
// http://www.mine-control.com/zack/timesync/timesync.html
class NetTimeSync
{
	static constexpr TimeMS ExcellentSyncLimit = 3;

	static constexpr TimeMS GoodSyncLimit = ExcellentSyncLimit * 3;

	static constexpr TimeMS BadSyncLimit = GoodSyncLimit * 2;

	// Max change in clock differential until out of sync is consider.
	// Should be set to maximum time remote can hang without disconnection + RTT.
	static constexpr TimeMS ClockOutOfSyncLimit = ion::NetDefaultTimeout * 2;

	class Clock : public SynchronizedClock
	{
	public:
		Clock() : SynchronizedClock() {}
		void SetLastRemoteSendTime(TimeMS t) { SynchronizedClock::SetLastRemoteSendTime(t); }
		void SetClockDifferential(Time t) { SynchronizedClock::SetClockDifferential(t); }
	};

public:
	// Max sample offset difference to latest sample to consider sample in clock update.
	static constexpr TimeMS MaxSampleOffsetDiff = 2000;

	static constexpr NetRoundTripTime TimeSyncDefaultPingFrequency = 500;

	static constexpr NetRoundTripTime MaxPingFrequency = 15 * 1000;

	static constexpr NetRoundTripTime MinPingFrequency = 100;

	static_assert(MaxPingFrequency <= NetRttTracker::SampleDeprecationAge / 4, "Too infrequent pings");

	NetTimeSync() {}

	~NetTimeSync() { ION_ASSERT(!mIsActive, "Time synchronization was not canceled"); }

	// #NET_TODO: Use Last remote send time to detect packet loss and increase frequency.
	NetRoundTripTime GetPingFrequency() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mPingFrequency;
	}

	void Update(const NetRttTracker& tracker);

	void SetActive(bool flag)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		mIsActive = flag;
		mPingFrequency = TimeSyncDefaultPingFrequency;
	}

	bool IsActive() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mIsActive;
	}

	NetTimeSyncState SyncState() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mState;
	}

	Time GetTime(TimeMS now) const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mSynchronizedClock.GetTime(now);
	}

	SynchronizedClock GetClock() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mSynchronizedClock;
	}

	bool IsInSync() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return IsInSyncInternal();
	}

private:
	ION_ACCESS_GUARD(mGuard);

	bool IsInSyncInternal() const { return mState != NetTimeSyncState::NoSync && mState != NetTimeSyncState::InitialSync; }

	TimeDeltaMS GetAdjustedOffset(TimeMS now, const NetRttTracker::Sample& sample)
	{
		return mSynchronizedClock.GetAdjustedOffset(now, sample.receiveTime - (sample.ping / 2), sample.offset);
	}

	void Update(NetRttTracker::SampleBuffer& samples, TimeMS latestSendTime, TimeDeltaMS latestOffset);

	void SetInitialSync();

	double mCorrectionRate = 1.0;

	Clock mSynchronizedClock;

	TimeDeltaMS mSlewUpdateAccu = 0;

	NetRoundTripTime mPingFrequency = TimeSyncDefaultPingFrequency;
	NetTimeSyncState mState = NetTimeSyncState::NoSync;
	uint8_t mPreciseSyncCount = 0;
	bool mIsActive = false;
};
}  // namespace ion
