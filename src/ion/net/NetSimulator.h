#pragma once
#include <ion/net/NetMemory.h>
#include <ion/net/NetSimulatorSettings.h>
#include <ion/net/NetTime.h>

#include <ion/container/Deque.h>

#include <ion/concurrency/Mutex.h>

#include <memory>
#include <queue>
#include <unordered_map>

namespace ion
{
class NetSocket;
struct DelayedSend;
class NetworkSimulator
{
public:
	NetworkSimulator();
#if ION_NET_SIMULATOR
	NetworkSimulator(const NetworkSimulator& other) = delete;
	~NetworkSimulator();

	bool IsActive() const;

	void Send(NetSocketSendParameters* bsp, NetSocket& socket);

	void Update(ion::Time now);

	void Configure(const NetworkSimulatorSettings& other);

	const NetworkSimulatorSettings& Settings() const { return mSettings; }

	void Clear();

private:
	struct EarlierSendTime
	{
		bool operator()(std::unique_ptr<DelayedSend>& a, std::unique_ptr<DelayedSend>& b);
	};

	std::priority_queue<std::unique_ptr<DelayedSend>, std::deque<std::unique_ptr<DelayedSend>>, EarlierSendTime> mDelayList;
	Deque<std::unique_ptr<DelayedSend>> mBandwidthLimitedList;
	NetworkSimulatorSettings mSettings;
	ion::TimeMS mLastBandwidthUpdate = 0;
	ion::Mutex mMutex;
	int32_t mRunningIndex = 0;
	double mAvailableBandwidth = 0;
	uint64_t mTotalBufferedBytes = 0;
#endif
};
}  // namespace ion
