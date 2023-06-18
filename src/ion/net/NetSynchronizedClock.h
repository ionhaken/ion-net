#pragma once

#include <ion/container/Algorithm.h>


namespace ion
{
	class SynchronizedClock
	{
		static constexpr TimeDeltaMS MaxSlewMsPerSecond = 16;

	public:

		Time GetTime(TimeMS now) const
		{
			return now + (mClockDifferential + 
				(mIsLastRemoteSendSet ? 
				GetSkew(now, LastRemoteSendTime(), mSlewMsPerSec) : 0));
		}

		TimeDeltaMS GetAdjustedOffset(TimeMS now, TimeMS t, TimeDeltaMS delta)
		{
			return delta + GetSkew(now, t, mSlewMsPerSec);
		}

		TimeDeltaMS GetSkew(TimeMS now) const
		{
			return GetSkew(now, LastRemoteSendTime(), mSlewMsPerSec);
		}

		TimeDeltaMS GetSkew(TimeMS now, TimeMS last) const
		{
			return GetSkew(now, last, mSlewMsPerSec);
		}

		TimeDeltaMS ClockDifferential() const { return mClockDifferential; }

		TimeMS LastRemoteSendTime() const 
		{ 
			ION_ASSERT(mIsLastRemoteSendSet, "Last remote send time not set");
			return mLastRemoteSendTime; 
		}

		double SlewRate() const { return mSlewMsPerSec; }

		void SetSlewRate(double rate) { mSlewMsPerSec = rate;}

	protected:
		void SetClockDifferential(TimeDeltaMS t) { mClockDifferential = t; }

		void SetLastRemoteSendTime(TimeMS t) 
		{ 
			mIsLastRemoteSendSet = true;
			mLastRemoteSendTime = t; 
		}

	private:

		static TimeDeltaMS GetSkew(TimeMS now, TimeMS t, double rate)
		{
			double delta = static_cast<double>(DeltaTime(now, t)) / 1000.0;
			TimeDeltaMS skew = static_cast<TimeDeltaMS>(rate * delta);
			TimeDeltaMS MaxSkew = static_cast<TimeDeltaMS>(ion::Abs(delta) * MaxSlewMsPerSecond);
			skew = ion::MinMax(-MaxSkew, skew, MaxSkew);
			return skew;
		}

		static TimeDeltaMS GetAdjustedOffset(TimeMS now, TimeMS t, TimeDeltaMS delta, double slew)
		{
			return delta + GetSkew(now, t, slew);
		}

	private:
		double mSlewMsPerSec = 0.0;
		TimeDeltaMS mClockDifferential = 0;
		TimeMS mLastRemoteSendTime;
		bool mIsLastRemoteSendSet = false;
	};
}
