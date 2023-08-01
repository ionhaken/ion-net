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
#include <ion/time/Clock.h>
#include <ion/core/Core.h>
#include <ion/time/CoreTime.h>
#include <ion/core/StaticInstance.h>
#include <ion/concurrency/Thread.h>
#include <ion/util/Wider.h>
#include <ion/hw/CPU.inl>
#if ION_PLATFORM_LINUX
	#include <sys/time.h>
#endif
#include <ctime>

namespace ion
{
constexpr int64_t WaitMaxMicros = 2000 * 1000;
constexpr int64_t OversleepMicros = 1000;

namespace timing
{
namespace detail
{
ion::TimeSecs GetTimeSeconds()
{
	time_t seconds = time(NULL);
	return ion::TimeSecs(seconds);
}
}  // namespace detail
ion::SystemTimeUnit GetSystemTime();

const ion::SystemTimePoint gSystemStartTime = SystemTimePoint(GetSystemTime());

ion::SystemTimeUnit GetSystemTimeFrequency();

#if ION_PLATFORM_MICROSOFT
LARGE_INTEGER GetClockFrequency()
{
	LARGE_INTEGER clockFrequency;
	QueryPerformanceFrequency(&clockFrequency);
	return clockFrequency;
}

ion::SystemTimeUnit GetSystemTimeFrequency() { return ion::SystemTimeUnit(GetClockFrequency().QuadPart); }

template <typename Units, Units scale>
Units GetTime()
{
	// https://docs.microsoft.com/en-us/windows/win32/dxtecharts/game-timing-and-multicore-processors?redirectedfrom=MSDN
	// Call QueryPerformanceFrequency only once, because the frequency will not change while the system is running.
	// Note: Must do it inside GetTime() to handle dynamic init correctly.
	static const LARGE_INTEGER gClockFrequency = GetClockFrequency();

	LARGE_INTEGER PerfVal;
	QueryPerformanceCounter(&PerfVal);

	using WiderType = typename ion::Wider<Units>::type;

	// 10Mhz performance optimization from MSVC <chrono>
	constexpr long long _TenMHz = 10'000'000;
	if (_TenMHz == GetSystemTimeFrequency())
	{
		const long long _Multiplier = 1000u * 1000u * 1000u / _TenMHz;
		return Units(PerfVal.QuadPart * _Multiplier / (1000u * 1000u * 1000u / scale));
	}
	return Units(timing::detail::ScaleTime<LONGLONG, WiderType>(PerfVal.QuadPart, gClockFrequency.QuadPart, scale));
}

ion::TimeMS GetTimeMS() { return GetTime<ion::TimeMS, 1000u>(); }

ion::TimeUS GetTimeUS() { return GetTime<ion::TimeUS, 1000u * 1000u>(); }

ion::TimeNS GetTimeNS() { return GetTime<ion::TimeNS, 1000u * 1000u * 1000u>(); }

ion::SystemTimeUnit GetSystemTime()
{
	LARGE_INTEGER PerfVal;
	QueryPerformanceCounter(&PerfVal);
	static_assert(sizeof(ion::SystemTimeUnit) == sizeof(PerfVal.QuadPart), "Invalid system time unit size");
	auto systemTime = ion::SystemTimeUnit(PerfVal.QuadPart);
	return systemTime;
}

#else

ion::TimeMS GetTimeMS()
{
	timeval tp;
	gettimeofday(&tp, 0);
	using WiderType = typename ion::Wider<ion::TimeMS>::type;
	return ion::TimeMS(WiderType(tp.tv_sec) * 1000u + WiderType(tp.tv_usec / 1000u));
}

ion::TimeUS GetTimeUS()
{
	timeval tp;
	gettimeofday(&tp, 0);
	using WiderType = typename ion::Wider<ion::TimeUS>::type;
	return ion::TimeUS(WiderType(tp.tv_sec) * (1000u * 1000u) + WiderType(tp.tv_usec));
}

ion::TimeNS GetTimeNS()
{
	timeval tp;
	gettimeofday(&tp, 0);
	using WiderType = typename ion::Wider<ion::TimeNS>::type;
	return ion::TimeNS(WiderType(tp.tv_sec) * (1000u * 1000u * 1000u) + WiderType(tp.tv_usec) * 1000u);
}

ion::SystemTimeUnit GetSystemTime()
{
	timeval tp;
	gettimeofday(&tp, 0);
	auto systemTime = ion::SystemTimeUnit(tp.tv_sec) * (1000u * 1000u) + tp.tv_usec;
	return systemTime;
}

ion::SystemTimeUnit GetSystemTimeFrequency()
{
	return 1000u * 1000u;  // microseconds
}
#endif
ion::TimeDeltaUS PreciseWaitUntil(ion::TimeUS time)
{
	ion::TimeDeltaUS delta;
	while ((delta = ion::DeltaTime(time, SteadyClock::GetTimeUS())) > 0)
	{
		ION_ASSERT(delta < WaitMaxMicros, "Use timed tasks instead of long waits");
		if (delta > ion::Thread::MinSleepUsec())
		{
			ion::Thread::Sleep(delta / 2);	// Division due to timing sampling rate
		}
		else if (delta >= OversleepMicros)
		{
			ion::platform::Yield();
		}
		else
		{
			ion::platform::Nop();
		}
	}
	return delta;
}

timing::TimeInfo LocalTime()
{
	timing::TimeInfo info;
#if ION_PLATFORM_MICROSOFT
	SYSTEMTIME st;
	GetLocalTime(&st);

	#if 0  // Adjustment
	union WindowsTime
	{
		FILETIME mFileTime;
		ULARGE_INTEGER mInteger;
	} windowsTime;
	SystemTimeToFileTime(&st, &windowsTime.mFileTime);
	windowsTime.mInteger.QuadPart += int64_t(1000) * 1000 *1000* 60;
	FileTimeToSystemTime(&windowsTime.mFileTime, &st);
	#endif

	info.mReadable = {
	  static_cast<uint8_t>(st.wYear),		  static_cast<uint8_t>(st.wMonth - 1 /* For compability with unix timestamps */),
	  static_cast<uint8_t>(st.wDay),		  static_cast<uint8_t>(st.wHour),
	  static_cast<uint8_t>(st.wMinute),		  static_cast<uint8_t>(st.wSecond),
	  static_cast<uint16_t>(st.wMilliseconds)};

#else
	struct timeval tv;
	gettimeofday(&tv, NULL);

	struct tm timeinfo;
	std::tm* tm = localtime_r(&tv.tv_sec, &timeinfo);
	info.mReadable = {
	  static_cast<uint8_t>(tm->tm_year),		static_cast<uint8_t>(tm->tm_mon), static_cast<uint8_t>(tm->tm_mday),
	  static_cast<uint8_t>(tm->tm_hour),		static_cast<uint8_t>(tm->tm_min), static_cast<uint8_t>(tm->tm_sec),
	  static_cast<uint16_t>(tv.tv_usec / 1000),
	};
#endif
	return info;
}

}  // namespace timing

SystemTimePoint SystemTimePoint::Current() { return SystemTimePoint(timing::GetSystemTime()); }

size_t SystemTimePoint::TimeFrequency() { return ion::SafeRangeCast<size_t>(timing::GetSystemTimeFrequency()); }

uint64_t SystemTimePoint::MillisecondsSinceStart() const
{
	return TimeDuration<SystemTimePoint>(*this, timing::gSystemStartTime).Milliseconds();
}

uint64_t SystemTimePoint::MicrosecondsSinceStart() const
{
	return TimeDuration<SystemTimePoint>(*this, timing::gSystemStartTime).Microseconds();
}

uint64_t SystemTimePoint::NanosecondsSinceStart() const
{
	return TimeDuration<SystemTimePoint>(*this, timing::gSystemStartTime).Nanoseconds();
}

double SystemTimePoint::SecondsSinceStart() const { return TimeDuration<SystemTimePoint>(*this, timing::gSystemStartTime).Seconds(); }

uint32_t TimePointSeconds::SecondsSinceEpoch() const { return TimeDuration<TimePointSeconds>(*this, TimePointSeconds(0)).Seconds(); }

ion::SystemTimeUnit SystemTimePoint::Now() const { return ion::timing::GetSystemTime(); }

}  // namespace ion
