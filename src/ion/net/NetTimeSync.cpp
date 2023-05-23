
#include <ion/util/Stats.h>
#include <ion/net/NetTimeSync.h>

namespace
{
constexpr double PingFrequencyUpdateRatioBase = 0.05;
constexpr double PingFrequencyUpdateRatioQuality = 0.05;
constexpr double BadStandardDeviationLimit = 50.0;
constexpr double MinStandardDeviation = 0.5;
constexpr uint8_t PreciseSyncCount = 8;
}  // namespace

void ion::NetTimeSync::Update(const NetRttTracker& tracker)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
	NetRttTracker::SampleBuffer samples = tracker.Samples();

	const auto latestOffset = tracker.GetLastSample().offset;

	size_t validCount = 0;
	size_t inRange = 0;
	for (size_t i = 0; i < samples.Size(); i++)
	{
		if (samples[i].IsValid())
		{
			validCount++;
			if (NetIsTimeInRange(samples[i].offset, latestOffset, MaxSampleOffsetDiff))
			{
				inRange++;
			}
		}
	}
	if (validCount > 0 && inRange >= validCount / 2)
	{
		auto ping = tracker.GetLastSample().ping / 2;
		auto latestSendTime = tracker.GetLastSample().receiveTime - ping;
		if (!IsInSyncInternal())
		{
			mSynchronizedClock.SetLastRemoteSendTime(latestSendTime - TimeSyncDefaultPingFrequency);
		}
		auto delta = DeltaTime(latestSendTime, mSynchronizedClock.LastRemoteSendTime());
		if (delta >= 0)
		{
			Update(samples, latestSendTime, latestOffset);
			mSynchronizedClock.SetLastRemoteSendTime(latestSendTime);
		}
		else if (delta >= -ping)
		{
			// Ping variation, but rtt is decreasing
			mSynchronizedClock.SetLastRemoteSendTime(latestSendTime);
		}
		else
		{
			ION_NET_LOG_ABNORMAL("Remote ping is older than latest received"
					 << ";delta=" << delta << ";latestSendTime=" << latestSendTime << ";Ping=" << ping
					 << ";IsInSync=" << (IsInSyncInternal() ? "true" : "false"));
		}
	}
	else
	{
		mPingFrequency = MinPingFrequency;
		ION_NET_LOG_VERBOSE("Invalid clock sample;in range=" << inRange << ";valid=" << validCount << ";rtt=" << tracker.GetLastSample().ping);
	}
}

void ion::NetTimeSync::Update(NetRttTracker::SampleBuffer& samples, TimeMS latestSendTime, TimeDeltaMS latestOffset)
{
	std::sort(samples.Begin(), samples.End(),
			  [&](const NetRttTracker::Sample& a, const NetRttTracker::Sample& b)
			  {
				  if (NetIsTimeInRange(a.offset, latestOffset, MaxSampleOffsetDiff))
				  {
					  if (!NetIsTimeInRange(b.offset, latestOffset, MaxSampleOffsetDiff))
					  {
						  return true;
					  }
				  }
				  else if (NetIsTimeInRange(b.offset, latestOffset, MaxSampleOffsetDiff))
				  {
					  return false;
				  }
				  return (a.ping < b.ping);
			  });

	size_t numSamples;
	for (numSamples = 0; numSamples < samples.Size(); numSamples++)
	{
		if (!samples[numSamples].IsValid() || !NetIsTimeInRange(samples[numSamples].offset, latestOffset, MaxSampleOffsetDiff))
		{
			break;
		}
	}

	double standardDeviation =
	  ion::CalcStandardDeviation(samples.Begin(), samples.Begin() + numSamples, [&](const auto& sample) { return sample.ping; }) +
	  MinStandardDeviation;

	// Samples above one standard deviation above the median are discarded.
	// The purpose of this is to eliminate packets that were retransmitted by TCP.
	size_t avgSampleCount = 0;
	TimeDeltaMS offsetDelta = 0;
	double slewMsPerSecond = 0.0;
	size_t slewSampleCount = 0;
	double medianPing = static_cast<double>(samples[numSamples / 2].ping);
	for (size_t i = 0; i < numSamples; i++)
	{
		if (std::abs(static_cast<double>(samples[i].ping) - medianPing) <= standardDeviation)
		{
			TimeDeltaMS offset = GetAdjustedOffset(latestSendTime, samples[i]);
			offsetDelta += /*samples[i].offset*/ offset - latestOffset;
			avgSampleCount++;
			if (samples[i].offset != latestOffset)
			{
				auto sendTime = samples[i].receiveTime - (samples[i].ping / 2);
				auto delta = static_cast<double>(DeltaTime(latestSendTime, sendTime)) / 1000.0;
				slewSampleCount++;
				slewMsPerSecond += static_cast<double>(latestOffset - samples[i].offset) / delta;
			}
		}
	}

	if (slewSampleCount > 0)
	{
		slewMsPerSecond /= slewSampleCount;
	}

	offsetDelta = static_cast<TimeDeltaMS>(static_cast<double>(offsetDelta) / avgSampleCount);

	TimeDeltaMS newClockDiff = latestOffset + offsetDelta;

	if (mState != NetTimeSyncState::NoSync && NetIsTimeInRange(mSynchronizedClock.ClockDifferential(), newClockDiff, ClockOutOfSyncLimit))
	{
		auto delta = newClockDiff - mSynchronizedClock.ClockDifferential();

		TimeMS diff = std::abs(delta);
		ion::NetRoundTripTime targetPingFrequency;

		if (mState == NetTimeSyncState::Precise || mState == NetTimeSyncState::Sync)
		{
			if (diff < BadSyncLimit)
			{
				// Small changes to clock differential
				mState = NetTimeSyncState::Precise;
				if (diff <= ExcellentSyncLimit)
				{
					double quality = 1.0 - ion::Min(1.0, (standardDeviation - MinStandardDeviation) / BadStandardDeviationLimit);
					auto ratio = PingFrequencyUpdateRatioBase + quality * PingFrequencyUpdateRatioQuality;
					targetPingFrequency = static_cast<NetRoundTripTime>(static_cast<double>(mPingFrequency) * (1.0 - ratio) +
																static_cast<double>(MaxPingFrequency) * ratio);
					mCorrectionRate = 0.02;
				}
				else
				{
					targetPingFrequency = TimeSyncDefaultPingFrequency;
					mCorrectionRate = 0.05;
				}
			}
			else
			{
				// Medium changes to clock differential
				mState = NetTimeSyncState::Sync;
				targetPingFrequency = TimeSyncDefaultPingFrequency;
				mCorrectionRate = 0.1;
			}
		}
		else
		{
			// Large changes to clock differential
			targetPingFrequency = MinPingFrequency;
			ION_ASSERT(mState == NetTimeSyncState::InitialSync, "Invalid state");
			if (diff < BadSyncLimit)
			{
				mCorrectionRate = (0.1 + mCorrectionRate) / 2.0;
				if (mPreciseSyncCount < PreciseSyncCount)
				{
					mPreciseSyncCount++;
				}
				if (mPreciseSyncCount == PreciseSyncCount)
				{
					mState = NetTimeSyncState::Sync;
				}
			}
			else
			{
				mCorrectionRate = 1.0;
				if (mPreciseSyncCount > 0)
				{
					mPreciseSyncCount--;
				}
			}
		}

		if (NetIsTimeInRange(mSynchronizedClock.LastRemoteSendTime(), latestSendTime, MaxPingFrequency * 2))
		{
			unsigned int multiplier = 0;
			mSlewUpdateAccu += DeltaTime(latestSendTime, mSynchronizedClock.LastRemoteSendTime());
			while (mSlewUpdateAccu > 250)
			{
				mSlewUpdateAccu -= 250;
				multiplier += 1;
			}
			auto smoothedDelta = static_cast<TimeDeltaMS>(static_cast<double>(delta) * ion::Min(1.0, mCorrectionRate * multiplier));
			auto smoothedSlew = (slewMsPerSecond - mSynchronizedClock.SlewRate()) * ion::Min(1.0, mCorrectionRate * 0.04 * multiplier);

			auto smoothedPing =
			  static_cast<NetRoundTripTime>((targetPingFrequency - mPingFrequency) * ion::Min(1.0, mCorrectionRate * multiplier));

			if (smoothedDelta == 0)
			{
				if (delta > 0)
				{
					smoothedDelta = 1;
				}
				else if (delta < -1)
				{
					smoothedDelta = -1;
				}
			}
			mSynchronizedClock.SetSlewRate(mSynchronizedClock.SlewRate() + (smoothedSlew));
			newClockDiff = mSynchronizedClock.ClockDifferential() + smoothedDelta + mSynchronizedClock.GetSkew(latestSendTime);
			mPingFrequency = mPingFrequency + smoothedPing;
		}
		else
		{
			mSynchronizedClock.SetSlewRate(slewMsPerSecond);
			mSlewUpdateAccu = 0;
			newClockDiff = mSynchronizedClock.ClockDifferential() + delta;
			mPingFrequency = MinPingFrequency;
		}
	}
	else
	{
		// Large changes to clock differential
		if (mState != NetTimeSyncState::NoSync)
		{
			ION_NET_LOG_INFO("Clock differential resync: Differential: "
				<< "prev=" << mSynchronizedClock.ClockDifferential() << ";latest=" << latestOffset << " (" << offsetDelta << "ms offset)"
				<< ";next=" << newClockDiff);
		}
		SetInitialSync();
	}

	ION_TIMESYNC_DBG("Clock Updated: " << mSynchronizedClock.ClockDifferential() << "->" << newClockDiff << " NumSamples=" << avgSampleCount
									 << "/"
							<< numSamples << " Ping:"
							<< " low=" << samples[0].ping << " high=" << samples[ion::Max(static_cast<size_t>(1), numSamples) - 1].ping
							<< " median=" << medianPing << " deviation=" << standardDeviation << " ping freq=" << mPingFrequency
							<< " correction=" << mCorrectionRate << " slew=" << mSynchronizedClock.GetSkew(1000, 0) << "/s");

	mSynchronizedClock.SetClockDifferential(newClockDiff);
}

void ion::NetTimeSync::SetInitialSync()
{
	mCorrectionRate = 1.0;
	mState = NetTimeSyncState::InitialSync;
	mPingFrequency = MinPingFrequency;
	mSynchronizedClock.SetSlewRate(0.0);
	mPreciseSyncCount = PreciseSyncCount / 2;
}
