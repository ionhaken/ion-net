#pragma once

//
// KCP protocol, modified from https://github.com/skywind3000/kcp:
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
//
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//

#include <ion/net/NetInternalTypes.h>
#include <ion/net/NetPacketPriority.h>
#include <ion/net/NetPayload.h>
#include <ion/net/NetSdk.h>
#include <ion/net/NetTime.h>

#include <ion/container/Array.h>
#include <ion/container/RingBuffer.h>

namespace ion
{
struct NetRemoteSystem;
}

namespace ion
{

constexpr const uint32_t MinSndWindowSize = 32;
constexpr const uint32_t MaxNumberOfFragments = 127;
constexpr const uint32_t MinRcvWindowSize = MaxNumberOfFragments + 1;
constexpr const uint32_t MaxRcvWindowSize = 0xFFFFFFF;

struct NetDownstreamSegment;
template <size_t PayloadSize>
struct NetDownstreamPacket;
using NetSocketReceiveData = NetDownstreamPacket<ion::NetMaxUdpPayloadSize()>;

struct NetControl;
struct NetCommand;
struct NetPacket;

struct NetUpstreamSegment;

struct NetChannelWriteContext
{
	~NetChannelWriteContext();
	NetControl& mControl;
	NetRemoteSystem& mRemote;
	ion::TimeMS mCurrentTime;
	NetSocketSendParameters* mSsp = nullptr;
	ByteWriterUnsafe mWriter;
};

class NetChannel
{
public:
	NetChannel(uint32_t conv, ion::TimeMS currentTime, int payloadSize);
	~NetChannel()
	{
		ION_ASSERT(mSndQueue.IsEmpty(), "Send queu left");
		ION_ASSERT(mSndBuf.IsEmpty(), "Send buf left");
		ION_ASSERT(mRcvQueue.IsEmpty(), "Rcv que left");
		ION_ASSERT(mRcvBuf.IsEmpty(), "Rcv buf left");
	}
	void Reset(NetControl& control, NetRemoteSystem& user);
	ION_CLASS_NON_COPYABLE(NetChannel);
	NetChannel(NetChannel&& other);

	void Update(NetChannelWriteContext& context);
	void Flush(NetChannelWriteContext& context);
	bool Input(NetControl& control, NetRemoteSystem& remoteSystem, NetSocketReceiveData& packet, ion::TimeMS currentTime, size_t dataLen,
			   uint32_t& outAckedBytes, Deque<NetPacket*, NetAllocator<NetPacket*>>& recvQ);
	int PeekSize(ion::NetControl& control, ion::NetRemoteSystem& remote);
	NetPacket* Receive(NetControl& control, ion::NetRemoteSystem& remote);
	int Receive(NetControl& control, NetRemoteSystem& remote, unsigned char* buffer, int len);
	int Send(NetRemoteSystem& remote, NetCommand& command, uint64_t pos, uint64_t segmentSize);

	// Number of segments and acknowledges waiting to be sent.
	inline uint32_t WaitSend() const { return ion::SafeRangeCast<uint32_t>(mSndBuf.Size() + mSndQueue.Size() + mState.ackcount); }

	// Number of segments received partially or have acknowledges left to be sent.
	uint32_t WaitRcv() const { return ion::SafeRangeCast<uint32_t>(mRcvBuf.Size() + mState.ackcount); }

	void ReconfigureChannelPriority(NetPacketPriority priority);
	void SndWndSize(uint32_t sndwnd);
	void RcvWndSize(uint32_t sndwnd);

	// #TODO: Replace with ArenaDeque and use peer resource
	ion::Deque<NetUpstreamSegment*, NetAllocator<NetUpstreamSegment*>> mSndQueue;
	ion::Deque<NetUpstreamSegment*, NetAllocator<NetUpstreamSegment*>> mSndBuf;
	ion::Deque<NetDownstreamSegment*, NetAllocator<NetDownstreamSegment*>> mRcvQueue;
	ion::Deque<NetDownstreamSegment*, NetAllocator<NetDownstreamSegment*>> mRcvBuf;

	// Queues for unreliable unordered data
	ion::Deque<NetDownstreamSegment*, NetAllocator<NetDownstreamSegment*>> mUnreliableRcvQueue;
	ion::Deque<NetCommand*, NetAllocator<NetCommand*>> mUnrealiableSndQueue;

	uint32_t* acklist;

	struct State
	{
		uint32_t conv, mtu, mss;
		// Next serial number to be confirmed
		uint32_t snd_una;
		// The next one to be sent packet serial number
		uint32_t snd_nxt;
		// Serial number of the message to be received.
		uint32_t rcv_nxt;
		uint32_t ts_recent, ts_lastack;
		// threshold of congestion window
		uint32_t ssthresh;
		int32_t rx_rttval;
		int32_t rx_srtt;  // smoothed rtt average
		int32_t rx_rto, rx_minrto;
		// maximum sending window size
		uint32_t snd_wnd;
		// maximum receiving window size
		uint32_t rcv_wnd;
		// number of unused packets in remote receiving window
		uint32_t rmt_wnd;
		// Congestion window indicates how many packets can be sent by the sender related to the
		// receiver window and network status
		uint32_t cwnd;
		uint32_t probe;
		uint32_t interval, ts_flush, xmit;
		uint32_t nodelay;
		uint32_t ts_probe, probe_wait;
		uint32_t dead_link, incr;
		uint32_t ackcount;
		uint32_t ackblock;
		int fastresend;
		int fastlimit;
		int nocwnd;
#if ION_NET_KCP_STREAMING
		int stream;	 // streaming mode, currently unused
#endif
		ion::Array<uint32_t, size_t(NetPacketPriority::Count)> bufferedPriorities;
		NetPacketPriority currentPriority = NetPacketPriority::Low;

		struct BigDataBuffer
		{
			NetPacket* mBuffer = nullptr;
			size_t mTotalReceived = 0;
		};

		BigDataBuffer mBigDataBuffer;
		bool mIsBigDataActive = false;
	} mState;

private:
	void ClearCommand(NetUpstreamSegment* seg, NetControl& control);
	uint32_t FreeSendSegment(NetUpstreamSegment* seg, NetRemoteSystem& remote, NetControl& control);
	int FindRcvIndex(uint32_t sn);
	[[nodiscard]] uint32_t ParseUna(NetRemoteSystem& remote, uint32_t una, NetControl& control);
	[[nodiscard]] uint32_t ParseAck(NetRemoteSystem& remote, uint32_t sn, NetControl& control);
	bool IsReceiveRecovering() const;
	void ReceivePost(bool isRecover);
};

}  // namespace ion
