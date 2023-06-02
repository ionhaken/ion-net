#pragma once

#include <ion/net/NetSdk.h>
#include <ion/net/NetTime.h>

#include <ion/container/Deque.h>

#include <algorithm>
#include <atomic>

namespace ion
{
class MetricsCounters
{
public:
	struct Sample
	{
		TimeMS time;
		uint64_t value;
	};

	void Add(TimeMS now, uint64_t count)
	{
		mTotal += count;
		mTotalInPeriod += count;
		samples.PushBack(Sample{now, count});
		UpdateInternal(now);
	}

	inline uint64_t Total() const { return mTotal; }

	inline double CalcPerSecond() const
	{
		auto interval = TimeMS(mInterval);
		return interval > 0 ? (static_cast<double>(mTotalInPeriod) / (static_cast<double>(interval) / 1000)) : 0;
	}

	void Clear()
	{ 
		mInterval = 0;
		mTotal = 0;
		mTotalInPeriod = 0;
		samples.Clear();
	}

	void Update(TimeMS now) 
	{
		if (samples.IsEmpty()) 
		{
			return;
		}
		UpdateInternal(now);
	}

private:
	static constexpr TimeMS MaxAge = 1000;

	void UpdateInternal(TimeMS now)
	{
		size_t totalRemoved = 0;
		while (DeltaTime(now, samples.Front().time) > MaxAge)
		{
			totalRemoved += samples.Front().value;
			samples.PopFront();
			if (samples.IsEmpty())
			{
				mTotalInPeriod -= totalRemoved;
				mInterval = 0;
				return;
			}
		}
		mTotalInPeriod -= totalRemoved;
		mInterval = TimeSince(samples.Back().time, samples.Front().time);
	}

	std::atomic<uint64_t> mTotal = 0;
	std::atomic<uint64_t> mTotalInPeriod = 0;
	std::atomic<TimeMS> mInterval = 0;
	ion::Deque<Sample, NetAllocator<Sample>> samples;
};

enum class PacketType : uint8_t
{
	Raw,			 // Data sent to socket.
	UserReliable,	 // Data sent to reliable layer
	UserUnreliable,	 // Data sent to unreliable layer
	Count
};

enum class DataType : uint8_t
{
	Packets,
	Bytes,
	Count
};

enum class DirectionType : uint8_t
{
	Sent,
	Received,
	Resent,
	Count
};

struct NetStats
{
	NetStats()
	{
		for (size_t i = 0; i < static_cast<size_t>(PacketType::Count); ++i)
		{
			for (size_t j = 0; j < static_cast<size_t>(DataType::Count); ++j)
			{
				for (size_t k = 0; k < static_cast<size_t>(DirectionType::Count); ++k)
				{
					mUnitsPerSecond[i][j][k] = 0;
					mUnitsTotal[i][j][k] = 0;
				}
			}
		}
	}

	double PerSecond(PacketType packetType, DataType dataType, DirectionType directionType) const
	{
		return mUnitsPerSecond[static_cast<size_t>(packetType)][static_cast<size_t>(dataType)][static_cast<size_t>(directionType)];
	}

	double RawBytesPerSecondSent() const { return PerSecond(ion::PacketType::Raw, ion::DataType::Bytes, ion::DirectionType::Sent); }

	double RawBytesPerSecondReceived() const { return PerSecond(ion::PacketType::Raw, ion::DataType::Bytes, ion::DirectionType::Received); }

	uint64_t RawBytesSent() const { return Total(ion::PacketType::Raw, ion::DataType::Bytes, ion::DirectionType::Sent); }

	// Note: resent raw data is counted for packet even if only part of it is data that is being resent
	uint64_t RawBytesResent() const { return Total(ion::PacketType::Raw, ion::DataType::Bytes, ion::DirectionType::Resent); }

	uint64_t UserBytesSent() const { return UserReliableBytesSent() + UserReliableBytesReceived(); }

	uint64_t UserBytesReceived() const { return UserUnreliableBytesReceived() + UserReliableBytesReceived(); }

	uint64_t UserUnreliableBytesSent() const
	{
		return Total(ion::PacketType::UserUnreliable, ion::DataType::Bytes, ion::DirectionType::Sent);
	}

	uint64_t UserUnreliableBytesReceived() const
	{
		return Total(ion::PacketType::UserUnreliable, ion::DataType::Bytes, ion::DirectionType::Received);
	}

	uint64_t UserReliableBytesSent() const { return Total(ion::PacketType::UserReliable, ion::DataType::Bytes, ion::DirectionType::Sent); }

	uint64_t UserReliableBytesReceived() const
	{
		return Total(ion::PacketType::UserReliable, ion::DataType::Bytes, ion::DirectionType::Received);
	}

	uint64_t RawBytesReceived() const { return Total(ion::PacketType::Raw, ion::DataType::Bytes, ion::DirectionType::Received); }

	double PacketLossPerSecond() const
	{
		auto totalPackets = PerSecond(ion::PacketType::Raw, ion::DataType::Packets, ion::DirectionType::Sent);
		if (totalPackets > 0)
		{
			auto totalLostPackets = PerSecond(ion::PacketType::Raw, ion::DataType::Packets, ion::DirectionType::Resent);
			return totalLostPackets / totalPackets;
		}
		return 0.0;
	}

	uint64_t Total(PacketType packetType, DataType dataType, DirectionType directionType) const
	{
		return mUnitsTotal[static_cast<size_t>(packetType)][static_cast<size_t>(dataType)][static_cast<size_t>(directionType)];
	}

	NetStats& operator+=(const NetStats& other)
	{
		for (size_t i = 0; i < static_cast<size_t>(PacketType::Count); ++i)
		{
			for (size_t j = 0; j < static_cast<size_t>(DataType::Count); ++j)
			{
				for (size_t k = 0; k < static_cast<size_t>(DirectionType::Count); ++k)
				{
					mUnitsPerSecond[i][j][k] += other.mUnitsPerSecond[i][j][k];
					mUnitsTotal[i][j][k] += other.mUnitsTotal[i][j][k];
				}
			}
		}
		return *this;
	}

	double mUnitsPerSecond[static_cast<size_t>(PacketType::Count)][static_cast<size_t>(DataType::Count)]
						  [static_cast<size_t>(DirectionType::Count)];
	uint64_t mUnitsTotal[static_cast<size_t>(PacketType::Count)][static_cast<size_t>(DataType::Count)]
						[static_cast<size_t>(DirectionType::Count)];
};

struct DataMetrics
{
	DataMetrics() {}

	void Clear()
	{
		for (size_t i = 0; i < static_cast<size_t>(PacketType::Count); ++i)
		{
			for (size_t j = 0; j < static_cast<size_t>(DataType::Count); ++j)
			{
				for (size_t k = 0; k < static_cast<size_t>(DirectionType::Count); ++k)
				{
					counters[i][j][k].Clear();
				}
			}
		}
	}

	void OnReceived(TimeMS now, PacketType packetType, size_t byteCount, size_t packetCount = 1)
	{
		Add(now, DirectionType::Received, packetType, byteCount, packetCount);
	}

	void OnSent(TimeMS now, PacketType packetType, size_t byteCount, size_t packetCount = 1)
	{
		Add(now, DirectionType::Sent, packetType, byteCount, packetCount);
	}

	void OnResent(TimeMS now, PacketType packetType, size_t byteCount, size_t packetCount = 1)
	{
		Add(now, DirectionType::Resent, packetType, byteCount, packetCount);
	}

	void Update(TimeMS now) 
	{
		for (size_t i = 0; i < static_cast<size_t>(PacketType::Count); ++i)
		{
			for (size_t j = 0; j < static_cast<size_t>(DataType::Count); ++j)
			{
				for (size_t k = 0; k < static_cast<size_t>(DirectionType::Count); ++k)
				{
					counters[i][j][k].Update(now);
				}
			}
		}
	}

	void Snapshot(NetStats& stats)
	{
		for (size_t i = 0; i < static_cast<size_t>(PacketType::Count); ++i)
		{
			for (size_t j = 0; j < static_cast<size_t>(DataType::Count); ++j)
			{
				for (size_t k = 0; k < static_cast<size_t>(DirectionType::Count); ++k)
				{
					stats.mUnitsPerSecond[i][j][k] = counters[i][j][k].CalcPerSecond();
					stats.mUnitsTotal[i][j][k] = counters[i][j][k].Total();
				}
			}
		}
	}


private:
	void Add(TimeMS now, DirectionType directionType, PacketType packetType, size_t byteCount, size_t packetCount = 1)
	{
		counters[static_cast<size_t>(packetType)][static_cast<size_t>(DataType::Bytes)][static_cast<size_t>(directionType)].Add(now,
																																byteCount);
		counters[static_cast<size_t>(packetType)][static_cast<size_t>(DataType::Packets)][static_cast<size_t>(directionType)].Add(
		  now, packetCount);
	}

	MetricsCounters counters[static_cast<size_t>(PacketType::Count)][static_cast<size_t>(DataType::Count)]
							  [static_cast<size_t>(DirectionType::Count)];
};
}  // namespace ion
