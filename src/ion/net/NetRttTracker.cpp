#include <ion/net/NetRttTracker.h>


ion::NetRttTracker::NetRttTracker(TimeMS now)
{
	for (size_t i = 0; i < mSamples.Size(); i++)
	{
		mSamples[i].Reset();
	}
	mLastPingTime = now;
}

void ion::NetRttTracker::OnPing(TimeMS now)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
	mLastPingTime = now;
	while(!mActivePings.IsEmpty() && ion::DeltaTime(now, mActivePings.Front()) > ion::NetDefaultTimeout)
	{
		mPingsMissed++;
		mActivePings.PopFront();
	}
	mActivePings.PushBack(now);
}

double ion::NetRttTracker::CalculatePacketLoss(TimeMS now)
{
	mRollingPingsReceived += mPingsReceived;
	mRollingPingsMissed += mPingsMissed;
	mRollingPingsReceived *= 0.99f;
	mRollingPingsMissed *= 0.99f;
	mPingsReceived = 0;	
	mPingsMissed = 0;

	uint32_t missed = uint32_t(mRollingPingsMissed + 0.5f);
	uint32_t received = uint32_t(mRollingPingsReceived + 0.5f);
	for (size_t i = 0; i < mActivePings.Size(); ++i)
	{
		if (ion::DeltaTime(now, mActivePings[i]) < mShared.mAvgPing * 2)
		{
			received++;
		}
		else
		{
			missed++;
		}
	}
	uint32_t total = received + missed;
	return total > 0 ? double(missed) / double(total) : 0.0;
}

void ion::NetRttTracker::OnPong(TimeMS now, TimeMS sentPingTime, TimeMS remoteTime)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
	auto ClearActivePing = [&]() -> bool
	{
		for (size_t i = 0; i < mActivePings.Size(); ++i)
		{
			if (mActivePings[i] == sentPingTime)
			{
				mActivePings.Erase(i);
				return true;
			}
		}
		return false;
	};
		
	if (!ClearActivePing())
	{
		ION_NET_LOG_ABNORMAL("Ping not found from active list;ts=" << sentPingTime << ";last=" << mLastPingTime);
		return;
	}
	mPingsReceived++;
	if (!NetIsTimeInRange(now, sentPingTime, MaxPingTime))
	{
		ION_NET_LOG_ABNORMAL("Invalid ping time");
		return;
	}
	
	TimeDeltaMS deltaTime = DeltaTime(now, sentPingTime);
	mLastSample = DeprecateOldSamples(now);

	NetRoundTripTime ping = 0;
	if (deltaTime >= 0)
	{
		ping = static_cast<NetRoundTripTime>(deltaTime);
	}
	else
	{
		ION_NET_LOG_ABNORMAL("Negative ping;" << deltaTime << "ms");
	}

	mSamples[mLastSample].ping = ping;
	mSamples[mLastSample].receiveTime = now;

	{
		TimeMS estimatedRemoteTime = remoteTime + (ping / 2);
		mSamples[mLastSample].offset = static_cast<TimeDeltaMS>(estimatedRemoteTime - now);
	}
	mShared.mLatestOffset = mSamples[mLastSample].offset;

	NetRoundTripTime lowestPing = MaxPingTime;
	double avgPing = 0.0;
	size_t count = 0;
	TimeDeltaMS timeOffset = mSamples[mLastSample].offset;
	for (size_t i = 0; i < mSamples.Size(); i++)
	{
		if (mSamples[i].IsValid() &&
			NetIsTimeInRange(mSamples[i].receiveTime, now, MaxUpdateSampleAge))
		{
			count++;
			avgPing += static_cast<double>(mSamples[i].ping);
			if (mSamples[i].ping < lowestPing)
			{
				lowestPing = mSamples[i].ping;
				timeOffset = mSamples[i].offset;
			}
		}
	}

	mShared.mLatestPing = ping;
	mShared.mLowestPing = lowestPing;
	mShared.mAvgPing = static_cast<NetRoundTripTime>(avgPing / count);

	ION_TIMESYNC_DBG("Ping Tracker: low=" << int(mShared.mLowestPing) << " avg=" << int(mShared.mAvgPing)
		<< " latest=" << int(mShared.mLatestPing) << "(" << count << " samples)");
}

uint8_t ion::NetRttTracker::DeprecateOldSamples(TimeMS now)
{
	uint8_t nextIndex = UINT8_MAX;
	TimeMS biggestDiff = 0;
	for (uint8_t i = 0; i < mSamples.Size(); i++)
	{
		if (!mSamples[i].IsValid())
		{
			biggestDiff = SampleDeprecationAge;
			nextIndex = i;
		}
		else
		{
			auto diff = TimeSince(now, mSamples[i].receiveTime);
			if (diff > SampleDeprecationAge)
			{
				biggestDiff = SampleDeprecationAge;
				mSamples[i].Reset();
				nextIndex = i;
			}
			else if (diff >= biggestDiff)
			{
				biggestDiff = diff;
				nextIndex = i;
			}
		}
	}
	ION_ASSERT(nextIndex != UINT8_MAX, "No slot found");
	return nextIndex;
}
