#pragma once

#include <ion/net/NetConfig.h>

#include <ion/time/CoreTime.h>

namespace ion
{
enum class NetTimeSyncState : uint8_t
{
	NoSync,
	InitialSync,
	Sync,
	Precise
};
using Time = uint32_t;
constexpr bool NetIsTimeInRange(TimeMS a, TimeMS b, TimeDeltaMS range)
{
	auto delta = static_cast<TimeDeltaMS>(a - b);
	return delta < 0 ? ((-delta) < range) : (delta < range);
}
}  // namespace ion
