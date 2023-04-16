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

#include <ion/debug/Error.h>
#include <ion/util/SafeRangeCast.h>
#include <limits>

namespace ion
{
using TimeSecs = uint32_t;
using TimeMS = uint32_t;
using TimeUS = uint32_t;
using TimeNS = uint32_t;
using SystemTimeUnit = uint64_t;

using TimeDeltaSecs = std::make_signed<TimeSecs>::type;
using TimeDeltaMS = std::make_signed<TimeMS>::type;
using TimeDeltaUS = std::make_signed<TimeUS>::type;
using TimeDeltaNS = std::make_signed<TimeNS>::type;
using SystemTimeUnitDelta = std::make_signed<SystemTimeUnit>::type;

template <typename T>
struct DeltaType
{
	static_assert(std::numeric_limits<T>::lowest() < 0 && std::numeric_limits<T>::max() > 0, "Type needs specialization");
	using type = T;
};

template <>
struct DeltaType<uint32_t>
{
	using type = int32_t;
};
template <>
struct DeltaType<uint64_t>
{
	using type = int64_t;
};

template <typename Time, typename DeltaTimeType = typename DeltaType<Time>::type>
constexpr DeltaTimeType DeltaTime(Time a, Time b)
{
	auto delta = static_cast<DeltaTimeType>(a - b);
	ION_ASSERT_FMT_IMMEDIATE(  // Check values are in safe range for compare
	  delta <= std::numeric_limits<DeltaTimeType>::max() / 2 && delta >= std::numeric_limits<DeltaTimeType>::lowest() / 2,
	  "Too large delta");
	return delta;
}

template <typename Time, typename DeltaTimeType = typename DeltaType<Time>::type>
constexpr DeltaTimeType DeltaTime(Time a, DeltaTimeType b)
{
	return DeltaTime(ion::SafeRangeCast<DeltaTimeType>(a), b);
}

template <typename T>
constexpr T TimeToFrequency(TimeMS time, T hz)
{
	const TimeMS timeMod = time % 1000;
	return hz * ((time - timeMod) / 1000) + (hz * timeMod / 1000);
}

template <typename T>
constexpr TimeMS FrequencyToTime(T ticks, size_t hz)
{
	uint64_t fractions = (ticks % hz);
	uint64_t seconds = (ticks - fractions) / hz;
	return static_cast<TimeMS>(seconds * static_cast<uint64_t>(1000) + (fractions * static_cast<uint64_t>(1000)) / hz);
}

template <typename TTime = TimeMS>
constexpr TTime TimeSince(TTime a, TTime b)
{
	auto delta = DeltaTime(a, b);
	ION_ASSERT_FMT_IMMEDIATE(delta >= 0, "Negative delta");
	return static_cast<TTime>(delta);
}
};	// namespace ion
