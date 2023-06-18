#pragma once

#include <ion/net/NetLogging.h>
#include <ion/net/NetTime.h>

namespace ion
{

constexpr uint8_t NetProtocolVersion = 1;

// Maximum number of local IP addresses supported
constexpr size_t NetMaximumNumberOfInternalIds = 25;

constexpr ion::TimeMS NetConnectFloodTimeout = 100;

constexpr ion::TimeMS NetFailureConditionTimeout = 20 * 1000;

constexpr ion::TimeMS NetDefaultTimeout = 10 * 1000;

constexpr ion::TimeMS NetBanNotificationInterval = 1 * 1000;

constexpr ion::TimeMS NetUpdateInterval = ION_NET_WORK_INTERVAL;

constexpr ion::TimeMS NetMaxResendAlleviation = 5 * 1000;

using NetRoundTripTime = uint16_t;

// How often we'll ping remote when we are not receiving any messages from remote.
constexpr NetRoundTripTime NetKeepAlivePingInterval = 1000;

constexpr NetRoundTripTime NetOccasionalPingInterval = 30 * 1000;

// Socket options
constexpr int NetDefaultReceiveBufferSizeBytes = 1024 * 256;
constexpr int NetDefaultSendBufferSizeBytes = 1024 * 16;
constexpr long NetDefaultReceiveTimeoutMicros = 500 * 1000;
constexpr long NetDefaultSendTimeoutMicros = 500 * 1000;

// Data reception
constexpr uint64_t NetTheoreticalMaxBytesPerSecond = uint64_t(64) * 1024u / 8 * 1024u * 1024u;	// 64Gbps
constexpr uint64_t NetMaxBufferedReceiveBytes = NetTheoreticalMaxBytesPerSecond / 1000 * ion::NetUpdateInterval;
}  // namespace ion
