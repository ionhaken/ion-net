#pragma once

#include <ion/net/NetSynchronizedClock.h>
#include <ion/net/NetTime.h>

#include <ion/time/Clock.h>

namespace ion
{
class GlobalClock : public ion::IClock
{
public:
	GlobalClock() { OnOutOfSync(); }

	virtual ~GlobalClock() {}

	virtual ion::TimeMS GetTimeMS() const final override { return Time(ion::SteadyClock::GetTimeMS()); }

	ion::TimeMS Time(Time now) const
	{
		ion::AutoLock<ion::Mutex> mLock(mThreadSync);
		return mSynchronizedClock.GetTime(now);
	}

	void OnOutOfSync()
	{
		ion::AutoLock<ion::Mutex> mLock(mThreadSync);
		mSynchronizedClock.SetSlewRate(0);
		mSyncState = ion::NetTimeSyncState::NoSync;
	}

	void OnTimeSync(const SynchronizedClock& clock, ion::NetTimeSyncState state)
	{
		ion::AutoLock<ion::Mutex> mLock(mThreadSync);
		mSynchronizedClock = clock;
		mSyncState = state;
	}

	NetTimeSyncState State() const { return mSyncState; }

private:
	mutable ion::Mutex mThreadSync;
	SynchronizedClock mSynchronizedClock;
	std::atomic<NetTimeSyncState> mSyncState;
};

}  // namespace ion
