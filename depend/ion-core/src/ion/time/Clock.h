/*
 * Copyright 2023 Markus Haikonen, Ionhaken
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <ion/time/CoreTime.h>
#include <ion/util/Wider.h>
#include <atomic>

namespace ion
{
namespace timing
{
namespace detail
{
template <typename ScaleType, typename InType = ScaleType>
constexpr ScaleType ScaleTime(InType value, ScaleType frequency, ScaleType scale)
{
	ScaleType quadPart = ScaleType(value);
	ScaleType quotient = quadPart / frequency;
	ScaleType remainder = quadPart % frequency;
	return quotient * ion::SafeRangeCast<ScaleType>(scale) + (remainder * ion::SafeRangeCast<ScaleType>(scale) / frequency);
}
template <>
constexpr double ScaleTime<double, double>(double value, double frequency, double scale)
{
	return value / frequency * scale;
}
ion::TimeSecs GetTimeSeconds();
}  // namespace detail

struct ReadableTimeInfo
{
	uint8_t mYear;
	uint8_t mMon;
	uint8_t mDay;
	uint8_t mHour;
	uint8_t mMin;
	uint8_t mSec;
	uint16_t mMilliSeconds;
};

// Do not use time info as timepoint.
union TimeInfo
{
	TimeInfo() {}
	TimeInfo(uint64_t stamp) : mStamp(stamp) {}
	ReadableTimeInfo mReadable;
	uint64_t mStamp;  // For storing only, cannot convert to time units.
};

// #TODO: Hide behind TimePoints

ion::TimeUS GetTimeUS();
ion::TimeMS GetTimeMS();
ion::TimeNS GetTimeNS();

// Note: WaitUntil will use sleep and busy loop until given time.
// This should be used sparingly if you really want something to happen at very specific time.
// If you can allow some timing error you should always just use sleep.
// Returns time left when time left is equal or less than 0.
ion::TimeDeltaUS PreciseWaitUntil(ion::TimeUS t);
}  // namespace timing

// StedyClock returns discrete timestamps that are comparable as per DeltaTime() rules.
class SteadyClock
{
public:
	static TimeUS GetTimeUS() { return timing::GetTimeUS(); }
	static TimeMS GetTimeMS() { return timing::GetTimeMS(); }
	static TimeNS GetTimeNS() { return timing::GetTimeNS(); }
};

template <typename TimePoint, typename DifferenceType = typename ion::DeltaType<typename TimePoint::TimeType>::type>
class TimeDelta
{
public:
	constexpr TimeDelta(const TimePoint& end, const TimePoint& start) : mEnd(end), mStart(start) {}

	[[nodiscard]] constexpr DifferenceType Milliseconds() const { return TimeDifference<1000u>(); }

	[[nodiscard]] constexpr DifferenceType Microseconds() const { return TimeDifference<1000u * 1000u>(); }

	[[nodiscard]] constexpr DifferenceType Nanoseconds() const { return TimeDifference<1000u * 1000u * 1000u>(); }

	[[nodiscard]] constexpr double Seconds() const
	{
		return timing::detail::ScaleTime<double>(double(mEnd.TimeStamp() - mStart.TimeStamp()), double(TimePoint::TimeFrequency()), 1.0);
	}

protected:
	using DeltaType = typename ion::DeltaType<typename TimePoint::TimeType>::type;
	constexpr DeltaType Delta() const { return DeltaType(mEnd.TimeStamp() - mStart.TimeStamp()); }

	template <size_t Scale>
	constexpr DifferenceType TimeDifference() const
	{
		if constexpr (TimePoint::FixedFrequencyScale == Scale)
		{
			return static_cast<DifferenceType>(mEnd.TimeStamp() - mStart.TimeStamp());
		}
		else
		{
			return timing::detail::ScaleTime<DifferenceType>(mEnd.TimeStamp() - mStart.TimeStamp(), TimePoint::TimeFrequency(), Scale);
		}
	}

private:
	TimePoint mEnd;
	TimePoint mStart;
};

template <typename TimePoint>
class TimeDuration : public TimeDelta<TimePoint, typename TimePoint::TimeType>
{
public:
	constexpr TimeDuration(TimePoint end, TimePoint start) : TimeDelta<TimePoint, typename TimePoint::TimeType>(end, start)
	{
		ION_ASSERT_FMT_IMMEDIATE((TimeDelta<TimePoint, typename TimePoint::TimeType>::Delta() >= 0),
								 "Negative duration, use time delta instead?");
	}
};

// Time point stored in system native format.
// It should be prefered for tracking longer time periods especially when more precise timing is needed. Otherwise 32-bit time point is
// adequate.
class SystemTimePoint
{
	friend class TimeDelta<SystemTimePoint, SystemTimeUnitDelta>;
	friend class TimeDelta<SystemTimePoint, SystemTimeUnit>;

public:
	using ContainerType = SystemTimeUnit;
	using TimeType = SystemTimeUnit;
	static SystemTimePoint Current();
	// SystemTimePoint() : mTimeStamp(Now()) {}
	explicit SystemTimePoint(ContainerType units) : mTimeStamp(units) {}
	SystemTimePoint(const SystemTimePoint& other) : mTimeStamp(other.mTimeStamp) {}
	static constexpr size_t FixedFrequencyScale = 0;
	static size_t TimeFrequency();
	uint64_t MillisecondsSinceStart() const;
	uint64_t MicrosecondsSinceStart() const;
	uint64_t NanosecondsSinceStart() const;
	double SecondsSinceStart() const;

protected:
	inline ContainerType& InitialTimePoint() { return mTimeStamp; }
	inline const ContainerType& InitialTimePoint() const { return mTimeStamp; }
	SystemTimeUnit Now() const;
	TimeType TimeStamp() const { return TimeType(mTimeStamp); }

private:
	ContainerType mTimeStamp;
};

using SystemTimeDelta = TimeDelta<SystemTimePoint>;
using SystemTimeDuration = TimeDuration<SystemTimePoint>;

namespace timing
{
// Local time in ReadableTimeInfo format. Needs to be converted to time units until it can be used as a timepoint
timing::TimeInfo LocalTime();
}  // namespace timing

// Time point that has been scaled from system time point to 32-bit millisecond type
class TimePointMS
{
	friend class TimeDelta<TimePointMS, ion::TimeDeltaMS>;
	friend class TimeDelta<TimePointMS, ion::TimeMS>;

public:
	using ContainerType = ion::TimeMS;
	using TimeType = ion::TimeMS;
	TimePointMS() : mStart(Now()) {}
	TimePointMS(const TimePointMS& other) : mStart(other.mStart) {}
	TimePointMS(TimeMS startTime) : mStart(startTime) {}
	static constexpr size_t FixedFrequencyScale = 1000u;
	static constexpr size_t TimeFrequency() { return FixedFrequencyScale; };
	const TimePointMS& AddMilliseconds(size_t millis)
	{
		mStart += static_cast<ContainerType>(millis);
		return *this;
	}
	const TimePointMS& SubtractMilliseconds(size_t millis)
	{
		mStart -= static_cast<ContainerType>(millis);
		return *this;
	}

protected:
	inline ContainerType& InitialTimePoint() { return mStart; }
	inline const ContainerType& InitialTimePoint() const { return mStart; }
	TimeMS Now() const { return SteadyClock::GetTimeMS(); }
	constexpr TimeType TimeStamp() const { return TimeType(mStart); }

private:
	ContainerType mStart;
};

// Time point that has been scaled from system time point to 32-bit microsecond type
class TimePointUS
{
	friend class TimeDelta<TimePointUS, ion::TimeDeltaUS>;
	friend class TimeDelta<TimePointUS, ion::TimeUS>;

public:
	using ContainerType = ion::TimeUS;
	using TimeType = ion::TimeUS;
	static constexpr size_t FixedFrequencyScale = 1000u * 1000u;
	static constexpr size_t TimeFrequency() { return FixedFrequencyScale; }
	TimePointUS() : mStart(Now()) {}
	TimePointUS(TimeUS startTime) : mStart(startTime) {}

protected:
	inline ContainerType& InitialTimePoint() { return mStart; }
	inline const ContainerType& InitialTimePoint() const { return mStart; }
	TimeUS Now() const { return SteadyClock::GetTimeUS(); }
	constexpr TimeType TimeStamp() const { return TimeType(mStart); }

private:
	ContainerType mStart;
};

// Atomic version of TimePointUS
class AtomicTimePointUS
{
public:
	using ContainerType = std::atomic<ion::TimeUS>;
	using TimeType = ion::TimeUS;
	static constexpr size_t FixedFrequencyScale = 1000u * 1000u;
	static constexpr size_t TimeFrequency() { return FixedFrequencyScale; }
	AtomicTimePointUS() : mStart(Now()) {}
	AtomicTimePointUS(const std::atomic<TimeUS>& startTime) { mStart.store(startTime); }
	AtomicTimePointUS(const TimeUS& startTime) : mStart(startTime) {}
	AtomicTimePointUS(const AtomicTimePointUS& other) { mStart.store(other.InitialTimePoint()); }
	AtomicTimePointUS& operator=(const AtomicTimePointUS& other)
	{
		InitialTimePoint().store(other.InitialTimePoint());
		return *this;
	}

protected:
	inline ContainerType& InitialTimePoint() { return mStart; }
	inline const ContainerType& InitialTimePoint() const { return mStart; }
	TimeUS Now() const { return SteadyClock::GetTimeUS(); }
	TimeType TimeStamp() const { return TimeType(mStart); }

private:
	ContainerType mStart;
};

// Local time in seconds
class TimePointSeconds
{
	friend class TimeDelta<TimePointSeconds, ion::TimeDeltaSecs>;
	friend class TimeDelta<TimePointSeconds, ion::TimeSecs>;

public:
	using ContainerType = ion::TimeSecs;
	using TimeType = ion::TimeSecs;
	static constexpr size_t FixedFrequencyScale = 1u;
	static constexpr size_t TimeFrequency() { return FixedFrequencyScale; }
	TimePointSeconds() : mStart(Now()) {}
	TimePointSeconds(TimeType startTime) : mStart(startTime) {}
	uint32_t SecondsSinceEpoch() const;
	constexpr TimeType TimeStamp() const { return TimeType(mStart); }

protected:
	inline ContainerType& InitialTimePoint() { return mStart; }
	inline const ContainerType& InitialTimePoint() const { return mStart; }
	TimeSecs Now() const { return ion::timing::detail::GetTimeSeconds(); }

private:
	ContainerType mStart;
};

template <>
class TimeDuration<TimePointSeconds>
{
public:
	constexpr TimeDuration(const TimePointSeconds& end, const TimePointSeconds& start) : mEnd(end), mStart(start) {}
	[[nodiscard]] constexpr TimeSecs Seconds() const { return TimeSecs(mEnd.TimeStamp() - mStart.TimeStamp()); }
	[[nodiscard]] constexpr size_t Milliseconds() const { return size_t(mEnd.TimeStamp() - mStart.TimeStamp()) * 1000; }

	// using DeltaType = typename ion::DeltaType<TimeSecs>::type;
	// constexpr DeltaType Delta() const { return ion::DeltaTimeUnchecked(mEnd.TimeStamp(), mStart.TimeStamp()); }

private:
	TimePointSeconds mEnd;
	TimePointSeconds mStart;
};

// Timer type that supports only reset operation
template <typename Type>
class BaseTimer : public Type
{
public:
	BaseTimer() : Type() {}

	BaseTimer(double initialTime) : Type(Type::Current())
	{
		Type::InitialTimePoint() -= static_cast<typename Type::TimeType>(initialTime * Type::TimeFrequency());
	}

	// Time elapsed in timer units
	[[nodiscard]] inline typename Type::TimeType Elapsed() const
	{
		auto now = Type::Now();
		return ion::TimeSince(now, typename Type::TimeType(Type::InitialTimePoint()));
	}

	//[[nodiscard]] inline typename Type::TimeType ElapsedMillis() const { return ion::TimeDuration<Type>(Type(), *this).Milliseconds(); }

	[[nodiscard]] inline typename Type::TimeType ResetGetDelta()
	{
		auto now = Type::Now();
		auto since = ion::TimeSince(now, typename Type::TimeType(Type::InitialTimePoint()));
		Type::InitialTimePoint() = now;
		return since;
	}

	inline void Reset() { Type::InitialTimePoint() = Type::Now(); }

	[[nodiscard]] inline double ElapsedSeconds() const { return static_cast<double>(Elapsed()) / Type::TimeFrequency(); }
};

template <typename Type>
class TimerUS : public BaseTimer<Type>
{
public:
	TimerUS() {}

	[[nodiscard]] double ResetGetDelta(double time)
	{
		auto now = SteadyClock::GetTimeUS() + TimeUS(time * 1000.0 * 1000.0);
		auto prev = TimeUS(Type::InitialTimePoint());
		Type::InitialTimePoint() = now;
		return static_cast<double>(now - prev) / (1000.0 * 1000.0);
	}

	inline ion::TimeUS Reset(double time)
	{
		auto now = SteadyClock::GetTimeUS() + TimeUS(time * 1000.0 * 1000.0);
		Type::InitialTimePoint() = now;
		return now;
	}

	void ResetToTimepoint(ion::TimeUS tp)
	{
		Type::InitialTimePoint() = tp;
	}

	[[nodiscard]] inline double ResetGetDelta() { return ResetGetDelta(0.0); }

	inline ion::TimeUS Reset() { return Reset(0.0); }

	inline void Update(TimeDeltaUS timeUS) { Type::InitialTimePoint() += timeUS; }
	inline TimeUS Advance(TimeUS timeUS)
	{
		Type::InitialTimePoint() += timeUS;
		return Type::InitialTimePoint();
	}
	inline void Withdraw(TimeUS timeUS) { Type::InitialTimePoint() -= timeUS; }

	inline void Advance(double time) { Type::InitialTimePoint() += static_cast<TimeUS>(time * 1000.0 * 1000.0); }

	[[nodiscard]] inline double GetSeconds() const
	{
		auto now = SteadyClock::GetTimeUS();
		return static_cast<double>(ion::DeltaTime(now, TimeUS(Type::InitialTimePoint()))) / (1000.0 * 1000.0);
	}

	[[nodiscard]] inline TimeDeltaMS GetMillis() const
	{
		auto now = SteadyClock::GetTimeUS();
		return static_cast<TimeDeltaMS>(ion::DeltaTime(now, TimeUS(Type::InitialTimePoint()))) / (1000);
	}

	[[nodiscard]] inline ion::TimeDeltaUS GetMicros(ion::TimeUS now) const
	{
		return static_cast<TimeDeltaUS>(ion::DeltaTime(now, TimeUS(Type::InitialTimePoint())));
	}

	[[nodiscard]] inline ion::TimeDeltaUS GetMicros() const
	{
		auto now = SteadyClock::GetTimeUS();
		return GetMicros(now);
	}

	[[nodiscard]] inline ion::TimeDeltaNS GetNanos() const
	{
		auto now = SteadyClock::GetTimeUS();
		using WiderType = typename ion::Wider<TimeDeltaUS>::type;
		return WiderType(ion::DeltaTime(now, TimeUS(Type::InitialTimePoint()))) * 1000;
	}

	// Busyloop until
	inline double PreciseWaitUntil(double t) const
	{
		return static_cast<double>(PreciseWaitUntil(static_cast<ion::TimeUS>(t * 1000.0 * 1000.0))) / (1000.0 * 1000.0);
	}

	// Sleep/Busyloop until. Returns time left when time left is equal or less than 0.
	inline ion::TimeDeltaUS PreciseWaitUntil(ion::TimeUS usec) const
	{
		ion::TimeUS time = TimeUS(Type::InitialTimePoint()) + usec;
		return ion::timing::PreciseWaitUntil(time);
	}
};

// #TODO: Needs refactoring, "stop clock" is not really stop clock, but a precise clock used for e.g. busy waiting
// Use RunningTimerUs for short time periods, for long time periods use 'RunningTimerMs'
// 'StopClock' should probably used only for busy waiting atm. We should
// merge current stop clock and running timer code.
//
// We should have (?)
// - simple timer with no operations
// - simple timer with reset only (current base timer)
// - more complex timer with all edit options
using RunningSecondTimer = BaseTimer<TimePointSeconds>;
using RunningTimerMs = BaseTimer<TimePointMS>;
using RunningTimerUs = BaseTimer<TimePointUS>;
using StopClock = TimerUS<TimePointUS>;
using AtomicStopClock = TimerUS<AtomicTimePointUS>;
using SystemTimer = BaseTimer<SystemTimePoint>;

class IClock
{
public:
	virtual TimeMS GetTimeMS() const = 0;
	virtual ~IClock() {}
};

}  // namespace ion
