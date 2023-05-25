#include <ion/net/NetChannel.h>
#include <ion/net/NetCommand.h>
#include <ion/net/NetControl.h>
#include <ion/net/NetControlLayer.h>
#include <ion/net/NetRemote.h>
#include <ion/net/NetSecure.h>
#include <ion/net/NetSocketLayer.h>

#include <ion/arena/ArenaAllocator.h>
#include <ion/memory/Memory.h>


#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
namespace ion
{

	
#define ION_NET_CHANNEL_LOG(__msg, ...)	ION_NET_LOG_VERBOSE_CHANNEL(__msg, __VA_ARGS__)
	

// Changes to original KCP code:
// 1) Reduce KCP buffer size to max MTU size
// https://github.com/skywind3000/kcp/issues/264
// 3) Optimize ikcp_check to consider fast resend for update intervals
// 4) API for how many packets is waiting to be received
// 5) Custom malloc/alloc
// 6) No logging
// 7) ikcp_recv assumes buffer length equals ikcp_peeksize()

//---------------------------------------------------------------------
// BYTE ORDER & ALIGNMENT
//---------------------------------------------------------------------
#ifndef IWORDS_BIG_ENDIAN
	#ifdef _BIG_ENDIAN_
		#if _BIG_ENDIAN_
			#define IWORDS_BIG_ENDIAN 1
		#endif
	#endif
	#ifndef IWORDS_BIG_ENDIAN
		#if defined(__hppa__) || defined(__m68k__) || defined(mc68000) || defined(_M_M68K) ||                          \
		  (defined(__MIPS__) && defined(__MIPSEB__)) || defined(__ppc__) || defined(__POWERPC__) || defined(_M_PPC) || \
		  defined(__sparc__) || defined(__powerpc__) || defined(__mc68000__) || defined(__s390x__) || defined(__s390__)
			#define IWORDS_BIG_ENDIAN 1
		#endif
	#endif
	#ifndef IWORDS_BIG_ENDIAN
		#define IWORDS_BIG_ENDIAN 0
	#endif
#endif


//=====================================================================
// KCP BASIC
//=====================================================================
const uint32_t IKCP_RTO_NDL = 30;	// no delay min rto
const uint32_t IKCP_RTO_MIN = 100;	// normal min rto
const uint32_t IKCP_RTO_DEF = 200;
const uint32_t IKCP_RTO_MAX = 60000;

const uint32_t IKCP_CMD_PUSH = 81;		 // cmd: push data
const uint32_t IKCP_CMD_ACK = 82;		 // cmd: ack
const uint32_t IKCP_CMD_WASK = 83;		 // cmd: window probe (ask)
const uint32_t IKCP_CMD_WINS = 84;		 // cmd: window size (tell)
const uint32_t IKCP_CMD_IMMEDIATE = 85;	 // cmd: push immediate data - expect immediate ack
const uint32_t IKCP_CMD_UNRELIABLE_NO_ACK = 86;	 // cmd: push unrealiable data without ack

const uint32_t IKCP_ASK_SEND = 1;  // need to send IKCP_CMD_WASK
const uint32_t IKCP_ASK_TELL = 2;  // need to send IKCP_CMD_WINS
const uint32_t IKCP_WND_SND = MinSndWindowSize;
const uint32_t IKCP_WND_RCV = MaxNumberOfFragments + 1;	 // must >= max fragment size
const uint32_t IKCP_ACK_FAST = 3;
const uint32_t IKCP_INTERVAL = 100;
const uint32_t IKCP_DEADLINK = 20;
const uint32_t IKCP_THRESH_INIT = 2;
const uint32_t IKCP_THRESH_MIN = 2;
const uint32_t IKCP_PROBE_INIT = 7000;	   // 7 secs to probe window size
const uint32_t IKCP_PROBE_LIMIT = 120000;  // up to 120 secs to probe window
const uint32_t IKCP_FASTACK_LIMIT = 5;	   // max times to trigger fastack

//---------------------------------------------------------------------
// encode / decode
//---------------------------------------------------------------------

static ION_FORCE_INLINE uint32_t _ibound_(uint32_t lower, uint32_t middle, uint32_t upper) { return Min(Max(lower, middle), upper); }

//static ION_FORCE_INLINE long _itimediff(uint32_t later, uint32_t earlier) { return ((int32_t)(later - earlier)); }
/* decode 8 bits unsigned int */
static ION_FORCE_INLINE char* ikcp_decode8u(char* p, unsigned char* c)
{
	*c = *(unsigned char*)p++;
	return p;
}
/* decode 16 bits unsigned int (lsb) */
static ION_FORCE_INLINE char* ikcp_decode16u(char* p, unsigned short* w)
{
#if IWORDS_BIG_ENDIAN
	*w = *(unsigned char*)(p + 1);
	*w = *(unsigned char*)(p + 0) + (*w << 8);
#else
	memcpy(w, p, 2);
#endif
	p += 2;
	return p;
}
/* decode 32 bits unsigned int (lsb) */
static ION_FORCE_INLINE char* ikcp_decode32u(char* p, uint32_t* l)
{
#if IWORDS_BIG_ENDIAN
	*l = *(const unsigned char*)(p + 3);
	*l = *(const unsigned char*)(p + 2) + (*l << 8);
	*l = *(const unsigned char*)(p + 1) + (*l << 8);
	*l = *(const unsigned char*)(p + 0) + (*l << 8);
#else
	memcpy(l, p, 4);
#endif
	p += 4;
	return p;
}


//---------------------------------------------------------------------
// create a new kcpcb
//---------------------------------------------------------------------
NetChannel::NetChannel(uint32_t conv, ion::TimeMS currentTime, int payloadSizeWithoutAuthenticantionTag)
{
	mState.conv = conv;
	mState.snd_una = 0;
	mState.snd_nxt = 0;
	mState.rcv_nxt = 0;
	mState.ts_recent = 0;
	mState.ts_lastack = 0;
	mState.ts_probe = 0;
	mState.probe_wait = 0;
	mState.snd_wnd = MinSndWindowSize;
	mState.rcv_wnd = IKCP_WND_RCV;
	mState.rmt_wnd = IKCP_WND_RCV;
	mState.cwnd = 1;
	mState.incr = 0;
	mState.probe = 0;
	mState.mtu = payloadSizeWithoutAuthenticantionTag;
	mState.mss = mState.mtu - NetConnectedProtocolOverHead; // #TODO: Support optimized MSS (separate CMD for segments without length)

#if ION_NET_KCP_STREAMING
	mState.stream = 0;
#endif

	acklist = NULL;
	mState.ackblock = 0;
	mState.ackcount = 0;
	mState.rx_srtt = 0;
	mState.rx_rttval = 0;
	mState.rx_rto = IKCP_RTO_DEF;
	mState.rx_minrto = IKCP_RTO_MIN;
	mState.interval = IKCP_INTERVAL;
	mState.ts_flush = currentTime + IKCP_INTERVAL;
	mState.nodelay = 0;
	mState.ssthresh = IKCP_THRESH_INIT;
	mState.fastresend = 0;
	mState.fastlimit = IKCP_FASTACK_LIMIT;
	mState.nocwnd = 0;
	mState.xmit = 0;
	mState.dead_link = IKCP_DEADLINK;

	for (size_t i = 0; i < size_t(NetPacketPriority::Count); ++i)
	{
		mState.bufferedPriorities[i] = 0;
	}
	ReconfigureChannelPriority(NetPacketPriority(size_t(NetPacketPriority::Count) - 1));
}

void NetChannel::Reset(NetControl& control, NetRemoteSystem& remote)
{
	while (!mSndQueue.IsEmpty())
	{
		FreeSendSegment(mSndQueue.Front(), remote, control);
		mSndQueue.PopFront();
	}
	while (!mSndBuf.IsEmpty())
	{
		FreeSendSegment(mSndBuf.Front(), remote, control);
		mSndBuf.PopFront();
	}
	while (!mUnrealiableSndQueue.IsEmpty())
	{
		NetUpstreamSegment tmp;
		ClearCommand(mUnrealiableSndQueue.Front(), control);
		mUnrealiableSndQueue.PopFront();
	}

	while (!mRcvBuf.IsEmpty())
	{
		ion::NetControlLayer::DeallocateSegment(control, remote, mRcvBuf.Front());
		mRcvBuf.PopFront();
	}
	while (!mRcvQueue.IsEmpty())
	{
		ion::NetControlLayer::DeallocateSegment(control, remote, mRcvQueue.Front());
		mRcvQueue.PopFront();
	}

	if (acklist)
	{
		remote.Deallocate(acklist);
		acklist = nullptr;
	}


#if (ION_ASSERTS_ENABLED == 1)
	ION_ASSERT(mState.currentPriority == NetPacketPriority::Low, "Current packet priorioty not reset");
	ion::ForEach(mState.bufferedPriorities,
				 [](const size_t bufferedCount)
				 {
					 ION_ASSERT(bufferedCount == 0, "Buffered priorities not reset");
				 });
#endif
}


bool NetChannel::IsReceiveRecovering() const { return mRcvQueue.Size() >= mState.rcv_wnd; }

NetPacket* NetChannel::Receive(ion::NetControl& control, ion::NetRemoteSystem& remote)
{
	NetPacket* packet = nullptr;
	if (!mRcvQueue.IsEmpty())
	{
		auto* seg = mRcvQueue.Front();
		if (seg->frg == 0 && seg->mOffset != 0 && seg->len > 0)
		{
			bool isRecover = IsReceiveRecovering();
			packet = reinterpret_cast<NetPacket*>(seg->data - seg->mOffset);
			ION_ASSERT(packet->mAddress == remote.mAddress, "Invalid address"); // Set by socket layer
			packet->mGUID = remote.guid;
			packet->mRemoteId = remote.mId.load();
			packet->mLength = seg->len;
			packet->mInternalPacketType = NetInternalPacketType::DownstreamSegment;
			packet->mDataPtr = seg->data;
			mRcvQueue.PopFront();
			ReceivePost(isRecover);
			ION_NET_CHANNEL_LOG("Channel in: Packet " << seg->len << " bytes;GUID=" << packet->mGUID);
		}
		else
		{
			uint32_t size = PeekSize(control, remote);
			if (size > 0)
			{
				packet = NetControlLayer::AllocateUserPacket(control, size);
				auto ret = Receive(control, remote, NetPacketHeader(packet), size);
				ION_ASSERT(ret == int(size), "Invalid reception");
				packet->mAddress = remote.mAddress;
				packet->mGUID = remote.guid;
				packet->mRemoteId = remote.mId.load();
				packet->mLength = size;
				ION_NET_CHANNEL_LOG("Channel in: Packet " << size << " bytes;GUID=" << packet->mGUID);
			}
		}
	}
	return packet;
}


//---------------------------------------------------------------------
// user/upper level recv: returns size, returns below zero for EAGAIN
//---------------------------------------------------------------------
int NetChannel::Receive(ion::NetControl& control, NetRemoteSystem& remote, unsigned char* buffer, int len)
{
	ION_ASSERT(buffer, "No buffer");
	ION_ASSERT(PeekSize(control, remote) == len, "Invalid buffer length");
	ION_ASSERT(!mRcvQueue.IsEmpty(), "Invalid receive state");

	bool isRecover = IsReceiveRecovering();

	// merge fragment
	len = 0;
	do
	{
		int fragment;
		NetDownstreamSegment* seg = mRcvQueue.Front();
		memcpy(buffer, seg->data, seg->len);
		buffer += seg->len;
		len += seg->len;
		fragment = seg->frg;
		ION_NET_CHANNEL_LOG("Channel in: fragment;sn=" << seg->sn << ";frg=" << seg->frg);
		NetControlLayer::DeallocateSegment(control, remote, seg);
		mRcvQueue.PopFront();

		if (fragment == 0)
			break;
	} while (!mRcvQueue.IsEmpty());

	ReceivePost(isRecover);
	return len;
}
void NetChannel::ReceivePost(bool isRecover)
{
	// move available data from rcv_buf -> rcv_queue
	while (!mRcvBuf.IsEmpty())
	{
		NetDownstreamSegment* seg = mRcvBuf.Front();
		if (seg->sn == mState.rcv_nxt && mRcvQueue.Size() < mState.rcv_wnd)
		{
			mRcvBuf.PopFront();
			mRcvQueue.PushBack(seg);
			mState.rcv_nxt++;
		}
		else
		{
			break;
		}
	}

	// fast recover
	if (mRcvQueue.Size() < mState.rcv_wnd && isRecover)
	{
		// ready to send back IKCP_CMD_WINS in ikcp_flush
		// tell remote my window size
		mState.probe |= IKCP_ASK_TELL;
	}
}

//---------------------------------------------------------------------
// peek data size
//---------------------------------------------------------------------
int NetChannel::PeekSize(ion::NetControl& control, ion::NetRemoteSystem& remote)
{
	for (;;)
	{
		if (mRcvQueue.IsEmpty())
		{
			return 0;
		}

		if (mRcvQueue.Front()->frg == 0)
		{
			if (mRcvQueue.Front()->len == 0) // Unreliable segment was lost
			{
				ion::NetControlLayer::DeallocateSegment(control, remote, mRcvQueue.Front());
				mRcvQueue.PopFront();
				continue;
			}
			return mRcvQueue.Front()->len;
		}

		if (mRcvQueue.Size() < mRcvQueue.Front()->frg + 1)
		{
			return 0;
		}

		int length = 0;
		for (auto seg = mRcvQueue.Begin(); seg != mRcvQueue.End(); ++seg)
		{
			length += (*seg)->len;
			if ((*seg)->frg == 0)
			{
				break;
			}
		}

		return length;
	}
}

void NetChannel::ClearCommand(NetCommand*& command, NetControl& control)
{
	const auto packetPriority = command->mPriority;
	ION_ASSERT(mState.bufferedPriorities[int(packetPriority)], "Invalid buffered priority count");
	ION_ASSERT(int(mState.currentPriority) <= int(packetPriority), "Invalid priority");
	mState.bufferedPriorities[int(packetPriority)]--;
	if (mState.bufferedPriorities[int(packetPriority)] == 0 && mState.currentPriority == packetPriority &&
		int(mState.currentPriority) < (int(NetPacketPriority::Count) - 1))
	{
		int nextPriority = int(packetPriority) + 1;
		for (; nextPriority < int(NetPacketPriority::Count) - 1; ++nextPriority)
		{
			if (mState.bufferedPriorities[nextPriority] > 0)
			{
				break;
			}
		}
		ReconfigureChannelPriority(NetPacketPriority(nextPriority));
	}
	NetControlLayer::ClearCommand(control, command);
}

uint32_t NetChannel::FreeSendSegment(NetUpstreamSegment* seg, NetRemoteSystem& remote, NetControl& control)
{
	const uint32_t ackedBytes = seg->mHeader.len;
	if (seg->mCommand)
	{
		ClearCommand(seg->mCommand, control);
	}
	remote.Deallocate<NetUpstreamSegment>(seg);
	return ackedBytes;
}

//---------------------------------------------------------------------
// user/upper level send, returns below zero for error
//---------------------------------------------------------------------
int NetChannel::Send(NetRemoteSystem& remote, NetCommand& command, uint64_t dataPos, uint64_t len)
{
	ION_NET_CHANNEL_LOG("Channel out: packet;size=" << len << " bytes");
	NetUpstreamSegment* seg;

	ION_ASSERT(mState.mss > 0, "Invalid MSS");
	ION_ASSERT(len > 0, "Invalid data");

#if ION_NET_KCP_STREAMING
	// append to previous segment in streaming mode (if possible)
	if (mState.stream != 0)
	{
		if (!mSndQueue.IsEmpty())
		{
			IKCPSEG* old = mSndQueue.Back();
			if (old->len < kcp->mState.mss)
			{
				int capacity = kcp->mState.mss - old->len;
				int extend = (len < capacity) ? len : capacity;
				seg = remote.Allocate<IKCPSEG>(sizeof(IKCPSEG) - 1 + old->len + extend);
				assert(seg);
				if (seg == NULL)
				{
					return -2;
				}
				mSndQueue.PushBack(seg);
				memcpy(seg->data, old->data, old->len);
				ION_ASSERT(buffer, "Nothing to send");
				{
					memcpy(seg->data + old->len, buffer, extend);
					buffer += extend;
				}
				seg->len = old->len + extend;
				seg->frg = 0;
				len -= extend;
				mSndQueue.PopBack();
				remote.Deallocate(old);
			}
		}
		if (len <= 0)
		{
			return 0;
		}
	}
#endif

	uint32_t count;
	if (len <= (int)mState.mss)
	{
		count = 1;
	}
	else
	{
		count = SafeRangeCast<uint32_t>((len + mState.mss - 1) / mState.mss);
	}

	if (count > (int)MaxNumberOfFragments)
	{
		return -2; /* max number of fragments */
	}

	if (count == 0)
	{
		count = 1;
	}

	// fragment
	for (uint32_t i = 0; i < count; i++)
	{
		uint32_t size = SafeRangeCast<uint32_t>(len > (int)mState.mss ? (int)mState.mss : len);
		ION_ASSERT(size > 0, "Invalid segment");
		if (command.mReliability != NetPacketReliability::Unreliable)
		{
			// Reliable and unreliable ordered use send window
			seg = remote.Allocate<NetUpstreamSegment>(sizeof(NetUpstreamSegment));
			if (seg == NULL)
			{
				ION_NET_LOG_ABNORMAL("Out of KCP memory");
				return -2;
			}
			seg->mCommand = &command;
			seg->mPos = dataPos;
			seg->mHeader.len = size;
#if ION_NET_KCP_STREAMING
			seg->frg = (mState.stream == 0) ? (count - i - 1) : 0;
#else
			seg->mHeader.frg = count - i - 1;
#endif
			mSndQueue.PushBack(seg);
		}
		else
		{
			ION_ASSERT(count == 1 && len == size, "Invalid unrealiable segment");
			mUnrealiableSndQueue.PushBack(&command);
		}
		mState.bufferedPriorities[int(command.mPriority)]++;
		command.mRefCount++;
		dataPos += size;
		len -= size;
	}
	return 0;
}

static void ikcp_update_ack(NetChannel* kcp, uint32_t rtt)
{
	int32_t rto = 0;
	if (kcp->mState.rx_srtt == 0)
	{
		kcp->mState.rx_srtt = rtt;
		kcp->mState.rx_rttval = rtt / 2;
	}
	else
	{
		long delta = rtt - kcp->mState.rx_srtt;
		if (delta < 0)
		{
			delta = -delta;
		}
		kcp->mState.rx_rttval = (3 * kcp->mState.rx_rttval + uint32_t(delta)) / 4;
		kcp->mState.rx_srtt = (7 * kcp->mState.rx_srtt + rtt) / 8;
		if (kcp->mState.rx_srtt < 1)
		{
			kcp->mState.rx_srtt = 1;
		}
	}
	rto = kcp->mState.rx_srtt + Max(kcp->mState.interval, 4 * kcp->mState.rx_rttval);
	kcp->mState.rx_rto = _ibound_(kcp->mState.rx_minrto, rto, IKCP_RTO_MAX);
}

static void ikcp_shrink_buf(NetChannel* kcp)
{
	if (!kcp->mSndBuf.IsEmpty())
	{
		kcp->mState.snd_una = kcp->mSndBuf.Front()->mHeader.sn;
	}
	else
	{
		kcp->mState.snd_una = kcp->mState.snd_nxt;
	}
}

uint32_t NetChannel::ParseAck(NetRemoteSystem& remote, uint32_t sn, NetControl& control)
{
	if (DeltaTime(sn, mState.snd_una) < 0 || DeltaTime(sn, mState.snd_nxt) >= 0)
	{
		return 0;
	}

	uint32_t ackedBytes = 0;
	for (auto iter = mSndBuf.Begin(); iter != mSndBuf.End(); ++iter)
	{
		NetUpstreamSegment* seg = *iter;
		if (sn == seg->mHeader.sn)
		{
			ackedBytes += FreeSendSegment(seg, remote, control);
			mSndBuf.Erase(iter);
			break;
		}
		if (DeltaTime(sn, seg->mHeader.sn) < 0)
		{
			break;
		}
	}
	return ackedBytes;
}

uint32_t NetChannel::ParseUna(NetRemoteSystem& remote, uint32_t una, NetControl& control)
{
	uint32_t ackedBytes = 0;
	while (!mSndBuf.IsEmpty())
	{
		NetUpstreamSegment* seg = mSndBuf.Back();
		if (DeltaTime(una, seg->mHeader.sn) > 0)
		{
			ackedBytes += FreeSendSegment(seg, remote, control);
			mSndBuf.PopBack();
		}
		else
		{
			break;
		}
	}
	return ackedBytes;
}

static void ikcp_parse_fastack(NetChannel* kcp, uint32_t sn, uint32_t ts)
{
	(void)(ts);

	if (DeltaTime(sn, kcp->mState.snd_una) < 0 || DeltaTime(sn, kcp->mState.snd_nxt) >= 0)
		return;

	for (NetUpstreamSegment* seg : kcp->mSndBuf)
	{
		if (DeltaTime(sn, seg->mHeader.sn) < 0)
		{
			break;
		}
		else if (sn != seg->mHeader.sn)
		{
#ifndef IKCP_FASTACK_CONSERVE
			seg->mHeader.fastack++;
#else
			if (DeltaTime(ts, seg->ts) >= 0)
				seg->fastack++;
#endif
		}
	}
}

//---------------------------------------------------------------------
// ack append
//---------------------------------------------------------------------
static void ikcp_ack_push(NetRemoteSystem& remote, NetChannel* kcp, uint32_t sn, uint32_t ts)
{
	uint32_t newsize = kcp->mState.ackcount + 1;
	uint32_t* ptr;

	if (newsize > kcp->mState.ackblock)
	{
		uint32_t* acklist;
		uint32_t newblock;

		for (newblock = 8; newblock < newsize; newblock <<= 1)
			;

		acklist = remote.Allocate<uint32_t>(newblock * sizeof(uint32_t) * 2);

		if (acklist == nullptr)
		{
			ion::NotifyOutOfMemory();
			return;
		}

		if (kcp->acklist != NULL)
		{
			uint32_t x;
			for (x = 0; x < kcp->mState.ackcount; x++)
			{
				acklist[x * 2 + 0] = kcp->acklist[x * 2 + 0];
				acklist[x * 2 + 1] = kcp->acklist[x * 2 + 1];
			}
			remote.Deallocate(kcp->acklist);
		}

		kcp->acklist = acklist;
		kcp->mState.ackblock = newblock;
	}

	ptr = &kcp->acklist[kcp->mState.ackcount * 2];
	ptr[0] = sn;
	ptr[1] = ts;
	kcp->mState.ackcount++;
}



int NetChannel::FindRcvIndex(uint32_t sn)
{
	ION_ASSERT(DeltaTime(sn, mState.rcv_nxt + mState.rcv_wnd) < 0 && DeltaTime(sn, mState.rcv_nxt) >= 0, "Invalid serial number");

	int index = int(mRcvBuf.Size()) - 1;
	for (; index >= 0; --index)
	{
		NetDownstreamSegment* seg = mRcvBuf[index];
		if (seg->sn == sn)
		{
			return -1;
		}
		if (DeltaTime(sn, seg->sn) > 0)
		{
			break;
		}
	}
	return index + 1;
}

bool NetChannel::Input(ion::NetControl& control, NetRemoteSystem& remote, ion::NetSocketReceiveData& packet, ion::TimeMS currentTime,
					   size_t size, uint32_t& outAckedBytes, Deque<NetPacket*, NetAllocator<NetPacket*>>& recvQ)
{
	ION_NET_CHANNEL_LOG("Channel in: receive;size=" << size << " bytes;GUID=" << remote.guid);

	bool packetMoved = false;
	uint32_t prev_una = mState.snd_una;
	uint32_t maxack = 0, latest_ts = 0;
	int flag = 0;

	char* data = (char*)packet.mPayload;
	ION_ASSERT((uintptr_t(data) % alignof(NetPacket) == 0), "Invalid allocation");

	do
	{
		ION_ASSERT(size >= (int)NetConnectedProtocolMinOverHead, "Invalid data");
		uint32_t sn, una, conv;
		uint16_t wnd, len = 0;
		uint8_t cmd, frg;

		data = ikcp_decode32u(data, &conv);
		if (conv != mState.conv)
		{
			ION_NET_LOG_ABNORMAL("Invalid conversation at " << size_t((byte*)data - packet.mPayload));
			break;
		}

		data = ikcp_decode32u(data, &sn);
		TimeMS ts;
		data = ikcp_decode32u(data, &ts);
		data = ikcp_decode8u(data, &frg);
		data = ikcp_decode8u(data, &cmd);
		data = ikcp_decode16u(data, &wnd);
		data = ikcp_decode32u(data, &una);

		if (cmd == IKCP_CMD_PUSH || cmd == IKCP_CMD_IMMEDIATE || cmd == IKCP_CMD_UNRELIABLE_NO_ACK)
		{
			data = ikcp_decode16u(data, &len);
			size -= NetConnectedProtocolOverHead;
		}
		else
		{			
			size -= NetConnectedProtocolMinOverHead;
		}

		if ((long)size < (long)len)
		{
			ION_NET_LOG_ABNORMAL("Invalid segment length");
			break;
		}

		if (cmd != IKCP_CMD_UNRELIABLE_NO_ACK)
		{
			mState.rmt_wnd = wnd;
			outAckedBytes += ParseUna(remote, una, control);
			ikcp_shrink_buf(this);
		}

		if (cmd == IKCP_CMD_ACK)
		{
			// ts is our sent time on IKCP_CMD_ACK
			auto delta = DeltaTime(currentTime, ts);
			if (delta >= 0)
			{
				ikcp_update_ack(this, uint32_t(delta));
			}
			outAckedBytes += ParseAck(remote, sn, control);
			ikcp_shrink_buf(this);
			if (flag == 0)
			{
				flag = 1;
				maxack = sn;
				latest_ts = ts;
			}
			else
			{
				if (DeltaTime(sn, maxack) > 0)
				{
#ifndef IKCP_FASTACK_CONSERVE
					maxack = sn;
					latest_ts = ts;
#else
					if (DeltaTime(ts, latest_ts) > 0)
					{
						maxack = sn;
						latest_ts = ts;
					}
#endif
				}
			}
			ION_NET_CHANNEL_LOG("Channel in: ack;conv=" << conv << ";sn=" << sn << ";rtt=" << delta << ";rto=" << mState.rx_rto);
		}
		else if (cmd == IKCP_CMD_PUSH || cmd == IKCP_CMD_IMMEDIATE)
		{
			ION_NET_CHANNEL_LOG("Channel in: data;sn=" << sn << ";ts=" << ts << ";len=" << len);			
			if (DeltaTime(sn, mState.rcv_nxt + mState.rcv_wnd) < 0)
			{
				// ts is their sent time on IKCP_CMD_PUSH or IKCP_CMD_IMMEDIATE
				ikcp_ack_push(remote, this, sn, ts);
				if (DeltaTime(sn, mState.rcv_nxt) >= 0)
				{
					int rcvIndex = FindRcvIndex(sn);
					if (rcvIndex != -1) // Not duplicate
					{
						NetDownstreamSegment* seg;
						char* segPtr = data - (sizeof(NetDownstreamSegmentHeader));
						if (!packetMoved && (uintptr_t(segPtr) % alignof(NetDownstreamSegment)) == 0)
						{
							packetMoved = true;
							seg = ion::AssumeAligned<NetDownstreamSegment>(reinterpret_cast<NetDownstreamSegment*>(segPtr));
							seg->mOffset = uint32_t((byte*)data - (byte*)&packet);
							ION_ASSERT(seg->mOffset > sizeof(NetDownstreamSegmentHeader),
									   "Offset cannot differiante locally allocated packet");
						}
						else
						{
							seg = remote.Allocate<NetDownstreamSegment>(
							  ByteAlignPosition(sizeof(NetDownstreamSegment) - 1 + len, alignof(NetDownstreamSegment)));
							seg->mOffset = 0;
							memcpy(seg->data, (byte*)data, len);
						}

						seg->conv = conv;
						seg->frg = frg;
						seg->wnd = wnd;
						seg->ts = ts;
						seg->sn = sn;
						seg->una = una;
						seg->len = len;

						mRcvBuf.Insert(rcvIndex, seg);

						// Received new message.
						do 
						{
							NetDownstreamSegment* rcvSeg = mRcvBuf.Front();
							if (rcvSeg->sn == mState.rcv_nxt && mRcvQueue.Size() < mState.rcv_wnd)
							{
								mRcvBuf.PopFront();
								mRcvQueue.PushBack(rcvSeg);
								mState.rcv_nxt++;
							}
							else
							{
								break;
							}
						} while (!mRcvBuf.IsEmpty());

						// Force immediate ack
						if (cmd == IKCP_CMD_IMMEDIATE)
						{
							mState.ts_flush = currentTime;
						}
					}
				}
			}
		}
		else if (cmd == IKCP_CMD_UNRELIABLE_NO_ACK)
		{
			ION_NET_CHANNEL_LOG("Channel in: Unrealiable packet;Len=" << len);
			NetPacket* p = NetControlLayer::AllocateUserPacket(control, len);
			p->mAddress = remote.mAddress;
			p->mGUID = remote.guid;
			p->mRemoteId = remote.mId.load();
			p->mLength = len;
			memcpy(p->mDataPtr, (byte*)data, len);
			recvQ.PushBack(p);
		}
		else if (cmd == IKCP_CMD_WASK)
		{
			// ready to send back IKCP_CMD_WINS in ikcp_flush
			// tell remote my window size
			mState.probe |= IKCP_ASK_TELL;
			ION_NET_CHANNEL_LOG("Channel in: probe");
		}
		else if (cmd == IKCP_CMD_WINS)
		{
			// do nothing
			ION_NET_CHANNEL_LOG("Channel in: window size" << wnd);
		}
		else
		{
			ION_NET_LOG_ABNORMAL("Channel in: invalid cmd:" << cmd);
			break;
		}

		data += len;
		size -= len;
		
	} while (size >= NetConnectedProtocolMinOverHead);

	if (size != 0)
	{
		ION_NET_LOG_ABNORMAL("Unprocessed data in packet");
	}

	if (flag != 0)
	{
		ikcp_parse_fastack(this, maxack, latest_ts);
	}

	if (DeltaTime(mState.snd_una, prev_una) > 0)
	{
		if (mState.cwnd < mState.rmt_wnd)
		{
			uint32_t mss = mState.mss;
			if (mState.cwnd < mState.ssthresh)
			{
				mState.cwnd++;
				mState.incr += mss;
			}
			else
			{
				if (mState.incr < mss)
				{
					mState.incr = mss;
				}
				mState.incr += (mss * mss) / mState.incr + (mss / 16);
				if ((mState.cwnd + 1) * mss <= mState.incr)
				{
#if 1
					mState.cwnd = (mState.incr + mss - 1) / ((mss > 0) ? mss : 1);
#else
					mState.cwnd++;
#endif
				}
			}
			if (mState.cwnd > mState.rmt_wnd)
			{
				mState.cwnd = mState.rmt_wnd;
				mState.incr = mState.rmt_wnd * mss;
			}
		}
	}
	if (!packetMoved)
	{
		NetControlLayer::DeallocateReceiveBuffer(control, &packet);
	}
	return !mRcvQueue.IsEmpty();
}
NetChannelWriteContext ::~NetChannelWriteContext()
{
	if (mSsp)
	{
		mRemote.netSocket->DeallocateSend(mSsp);
	}
}

int SendKCPPacket(NetChannelWriteContext& context, int len)
{
	context.mRemote.lastReliableSend = context.mCurrentTime;
#if ION_NET_FEATURE_SECURITY
	if (context.mRemote.mDataTransferSecurity == NetDataTransferSecurity::EncryptionAndReplayProtection)
	{
		ION_ASSERT(len >= NetUnencryptedProtocolBytes, "Too small packet");
		ION_ASSERT(len + ion::NetSecure::AuthenticationTagLength <= ion::NetMaxUdpPayloadSize(), "Too large packet");

		unsigned char nonce[ion::NetSecure::NonceLength];
		memcpy(nonce, context.mSsp->data, NetUnencryptedProtocolBytes);
		memcpy(nonce + NetUnencryptedProtocolBytes, context.mRemote.netSocket->mNonceOffset.Data(),
			   context.mRemote.netSocket->mNonceOffset.ElementCount);

		[[maybe_unused]] bool isEncrypted = ion::NetSecure::Encrypt((unsigned char*)(&context.mSsp->data[NetUnencryptedProtocolBytes]),
																	(unsigned char*)(&context.mSsp->data[NetUnencryptedProtocolBytes]),
																	len - NetUnencryptedProtocolBytes, nonce, context.mRemote.mSharedKey);
		ION_ASSERT(isEncrypted, "Encryption failed ");
		len += ion::NetSecure::AuthenticationTagLength;
		context.mSsp->length = len;
	}
	else
#endif
	{
		ION_ASSERT(len <= ion::NetMaxUdpPayloadSize(), "Too large packet");
		context.mSsp->length = len;
	}
	ION_NET_CHANNEL_LOG("Channel out: send;size=" << len << " bytes"
												  << ";channel=" << uint8_t(context.mSsp->data[0])
												  << ";conv=" << *reinterpret_cast<uint32_t*>(&context.mSsp->data[0])
												  << ";sn=" << *reinterpret_cast<uint32_t*>(&context.mSsp->data[4]));
	if (context.mRemote.mMetrics)
	{
		context.mRemote.mMetrics->OnSent(context.mCurrentTime, ion::PacketType::Raw,
										 ion::NetMtuSize(context.mSsp->length, context.mRemote.mAddress.GetIPVersion()));
	}
	context.mSsp->SetAddress(context.mRemote.mAddress);

#if ION_NET_SIMULATOR
	ION_CHECK_FATAL(context.mRemote.netSocket->mSendThreadEnabled, "Send thread is mandatory when using network simulator");
#endif
	if (context.mRemote.netSocket->mSendThreadEnabled)
	{
		if (NetSocketSendParameters* newBuffer = context.mRemote.netSocket->AllocateSend())
		{
			NetSocketSendParameters* bsp = context.mSsp;
			context.mSsp = newBuffer;
			ion::SocketLayer::SendTo(*context.mRemote.netSocket, bsp);
			return len;
		}
		// Use blocking send if no memory for new buffer
	}
	ion::SocketLayer::SendBlocking(*context.mRemote.netSocket, *context.mSsp);
	return len;
}

static void ikcp_encode_seg(ByteWriterUnsafe& writer, const NetUpstreamSegmentHeader& ION_RESTRICT seg)
{
	writer.Write(seg.conv);
	writer.Write(seg.sn);
	// timestamp
	// Note: We measure RTT of connection via RTT Tracker. Segment timestamps are used to measure RTT of channel, but also
	// for different purpose, congestion control.
	writer.Write(seg.ts);
	writer.Write((uint8_t)seg.frg);
	writer.Write((uint8_t)seg.cmd);
	writer.Write((uint16_t)seg.wnd);
	writer.Write(seg.una);
}

void NetChannel::Flush(NetChannelWriteContext& context)
{
	uint32_t resent, cwnd;
	uint32_t rtomin;
	NetUpstreamSegmentHeader seg;

	seg.conv = mState.conv;
	seg.cmd = IKCP_CMD_ACK;

	// Calculate unused window
	seg.wnd = (mRcvQueue.Size() < mState.rcv_wnd) ? ion::SafeRangeCast<uint32_t>(mState.rcv_wnd - mRcvQueue.Size()) : 0;

	seg.una = mState.rcv_nxt;
	seg.frg = 0;
	seg.len = 0;

	seg.sn = 0;
	seg.ts = 0;

	auto FlushBufferIfNeeded = [&](uint32_t need) -> bool
	{
		uint32_t size = SafeRangeCast<uint32_t>(context.mWriter.NumBytesUsed());
		if (size + need > mState.mtu)
		{
			SendKCPPacket(context, size);
			context.mWriter = ByteWriterUnsafe((byte*)context.mSsp->data);
			return true;
		}
		else if (!context.mWriter.IsValid())
		{
			context.mSsp = context.mRemote.netSocket->AllocateSend();
			if (context.mSsp)
			{
				context.mWriter = ByteWriterUnsafe((byte*)context.mSsp->data);
				return true;
			}
		}
		return context.mWriter.IsValid();
	};

	// flush acknowledges
	int count = mState.ackcount;
	mState.ackcount = 0;
	for (int i = 0; i < count; i++)
	{
		if (FlushBufferIfNeeded(NetConnectedProtocolMinOverHead))
		{
			seg.sn = acklist[i * 2 + 0];
			seg.ts = acklist[i * 2 + 1];
			ikcp_encode_seg(context.mWriter, seg);
			ION_NET_CHANNEL_LOG("Channel out: ack;conv=" << seg.conv << ";sn=" << seg.sn << ";ts=" << seg.ts);
		}
	}

	// probe window size (if remote window size equals zero)
	if (mState.rmt_wnd == 0)
	{
		if (mState.probe_wait == 0)
		{
			mState.probe_wait = IKCP_PROBE_INIT;
			mState.ts_probe = context.mCurrentTime + mState.probe_wait;
		}
		else
		{
			if (DeltaTime(context.mCurrentTime, mState.ts_probe) >= 0)
			{
				if (mState.probe_wait < IKCP_PROBE_INIT)
				{
					mState.probe_wait = IKCP_PROBE_INIT;
				}
				mState.probe_wait += mState.probe_wait / 2;
				if (mState.probe_wait > IKCP_PROBE_LIMIT)
				{
					mState.probe_wait = IKCP_PROBE_LIMIT;
				}
				mState.ts_probe = context.mCurrentTime + mState.probe_wait;
				mState.probe |= IKCP_ASK_SEND;
			}
		}
	}
	else
	{
		mState.ts_probe = 0;
		mState.probe_wait = 0;
	}

	// flush window probing commands
	if (mState.probe & IKCP_ASK_SEND)
	{
		if (FlushBufferIfNeeded(NetConnectedProtocolMinOverHead))
		{
			seg.cmd = IKCP_CMD_WASK;
			ikcp_encode_seg(context.mWriter, seg);
			ION_NET_CHANNEL_LOG("Channel out: ask send;Conv=" << seg.conv);
		}
	}

	// flush window probing commands
	if (mState.probe & IKCP_ASK_TELL)
	{
		if (FlushBufferIfNeeded(NetConnectedProtocolMinOverHead))
		{
			seg.cmd = IKCP_CMD_WINS;
			ikcp_encode_seg(context.mWriter, seg);
			ION_NET_CHANNEL_LOG("Channel out: ask tell;Conv=" << seg.conv);
		}
	}

	mState.probe = 0;

	// calculate window size
	cwnd = Min(mState.snd_wnd, mState.rmt_wnd);
	if (mState.nocwnd == 0)
	{
		cwnd = Min(mState.cwnd, cwnd);
	}

	auto WriteDataSegment = [&context](NetCommand* cmd, size_t pos, size_t len)
	{	
		context.mWriter.Write((uint16_t)len);
		ION_ASSERT(len > 0, "Invalid data segment");
		context.mWriter.WriteArray((byte*)(&cmd->mData) + pos, len);
	};

	// move data from snd_queue to snd_buf
	while (DeltaTime(mState.snd_nxt, mState.snd_una + cwnd) < 0)
	{
		if (mSndQueue.IsEmpty())
		{
			break;
		}

		NetUpstreamSegment* newseg = mSndQueue.Front();
		mSndQueue.PopFront();
		mSndBuf.PushBack(newseg);
		newseg->mHeader.conv = mState.conv;
		newseg->mHeader.cmd = NetChannelPriorityConfigs[int(mState.currentPriority)].workInterval == 0 ? IKCP_CMD_IMMEDIATE : IKCP_CMD_PUSH;
		newseg->mHeader.wnd = seg.wnd;
		newseg->mHeader.ts = context.mCurrentTime;
		newseg->mHeader.sn = mState.snd_nxt++;
		newseg->mHeader.una = mState.rcv_nxt;
		newseg->mHeader.resendts = context.mCurrentTime;
		newseg->mHeader.rto = mState.rx_rto;
		newseg->mHeader.fastack = 0;
		newseg->mHeader.xmit = 0;
	}

	// calculate resent
	resent = (mState.fastresend > 0) ? (uint32_t)mState.fastresend : 0xffffffff;
	rtomin = (mState.nodelay == 0) ? (mState.rx_rto >> 3) : 0;

	// flush data segments
	ION_ASSERT(!mSndBuf.IsEmpty() || mSndQueue.IsEmpty(),
			   "Data not moved to send buffer;snd_nxt=" << mState.snd_nxt << ";snd_una=" << mState.snd_una);

	while (!mUnrealiableSndQueue.IsEmpty())
	{
		NetCommand* cmd = mUnrealiableSndQueue.Front();
		if (FlushBufferIfNeeded(NetConnectedProtocolOverHead + SafeRangeCast<uint32_t>(cmd->mNumberOfBytesToSend)))
		{
			context.mWriter.Write(mState.conv);
			// #TODO: Free 9 bytes for unreliable data
			context.mWriter.Write(uint32_t(0));// sn
			context.mWriter.Write(uint32_t(0));// ts
			context.mWriter.Write(uint8_t(0));	// frg
			context.mWriter.Write((uint8_t)IKCP_CMD_UNRELIABLE_NO_ACK);
			context.mWriter.Write((uint16_t)seg.wnd);	 
			context.mWriter.Write((uint32_t)mState.rcv_nxt);	 
			WriteDataSegment(cmd, 0, cmd->mNumberOfBytesToSend);
		}
		mUnrealiableSndQueue.PopFront();
		ClearCommand(cmd, context.mControl);
	}

	int change = 0;
	int lost = 0;

	size_t resentData = 0;
	for (NetUpstreamSegment* segment : mSndBuf)
	{
		int needsend = 0;
		if (segment->mHeader.xmit == 0)
		{
			needsend = 1;
			segment->mHeader.xmit++;
			segment->mHeader.rto = mState.rx_rto;
			segment->mHeader.resendts = context.mCurrentTime + segment->mHeader.rto + rtomin;
		}
		else if (DeltaTime(context.mCurrentTime, segment->mHeader.resendts) >= 
						 long(Max(mState.interval, context.mControl.mResendExtraDelay)))
		{
			needsend = 1;
			segment->mHeader.xmit++;
			mState.xmit++;
			if (mState.nodelay == 0)
			{
				segment->mHeader.rto += Max(segment->mHeader.rto, (uint32_t)mState.rx_rto);
			}
			else
			{
				int32_t step = (mState.nodelay < 2) ? ((int32_t)(segment->mHeader.rto)) : mState.rx_rto;
				segment->mHeader.rto += step / 2;
			}
			ION_NET_CHANNEL_LOG("Segment lost after " << DeltaTime(context.mCurrentTime, segment->mHeader.resendts) + segment->mHeader.rto
													  << "ms;rto=" << segment->mHeader.rto << ";rx_rto=" << mState.rx_rto);
			segment->mHeader.resendts = context.mCurrentTime + segment->mHeader.rto;
			if (segment->mHeader.cmd == IKCP_CMD_PUSH)
			{
				segment->mHeader.cmd = IKCP_CMD_IMMEDIATE;
			}
			lost = 1;
			resentData += segment->mHeader.len;
		}
		else if (segment->mHeader.fastack >= resent)
		{
			if ((int)segment->mHeader.xmit <= mState.fastlimit || mState.fastlimit <= 0)
			{
				needsend = 1;
				segment->mHeader.xmit++;
				segment->mHeader.fastack = 0;
				segment->mHeader.resendts = context.mCurrentTime + segment->mHeader.rto;
				change++;
				resentData += segment->mHeader.len;
			}
		}

		if (needsend)
		{
			segment->mHeader.ts = context.mCurrentTime;
			segment->mHeader.wnd = seg.wnd;
			segment->mHeader.una = mState.rcv_nxt;

			FlushBufferIfNeeded(NetConnectedProtocolOverHead + segment->mHeader.len);

			ION_NET_CHANNEL_LOG("Channel out: data;conv=" << segment->mHeader.conv << ";size=" << segment->mHeader.len);


			ikcp_encode_seg(context.mWriter, segment->mHeader);
			if (segment->mCommand)
			{
				WriteDataSegment(segment->mCommand, segment->mPos, segment->mHeader.len);
				if (segment->mCommand->mReliability != NetPacketReliability::Reliable)
				{
					ClearCommand(segment->mCommand, context.mControl);
				}
			}
			else
			{
				uint16_t len = 0;
				context.mWriter.Write((uint16_t)len);
			}

			// #TODO: What to do with dead links.
			/* if (segment->xmit >= mState.dead_link)
			{

			}*/
		}
	}

	// flush remaining segments
	uint32_t size = SafeRangeCast<uint32_t>(context.mWriter.NumBytesUsed());
	if (size > 0)
	{
		SendKCPPacket(context, size);
	}

	if (context.mRemote.mMetrics)
	{
		if (resentData > 0)
		{
			context.mRemote.mMetrics->OnResent(context.mCurrentTime, ion::PacketType::Raw,
											   ion::NetMtuSize(resentData, context.mRemote.mAddress.GetIPVersion()));
		}
	}



	// update ssthresh
	if (change)
	{
		long inflight = DeltaTime(mState.snd_nxt, mState.snd_una);
		ION_ASSERT(inflight >= 0, "Invalid difference");
		mState.ssthresh = ion::SafeRangeCast<uint32_t>(inflight / 2);
		if (mState.ssthresh < IKCP_THRESH_MIN)
		{
			mState.ssthresh = IKCP_THRESH_MIN;
		}
		mState.cwnd = mState.ssthresh + resent;
		mState.incr = mState.cwnd * mState.mss;
	}

	if (lost)
	{
		mState.ssthresh = cwnd / 2;
		if (mState.ssthresh < IKCP_THRESH_MIN)
		{
			mState.ssthresh = IKCP_THRESH_MIN;
		}
		mState.cwnd = 1;
		mState.incr = mState.mss;
	}

	if (mState.cwnd < 1)
	{
		mState.cwnd = 1;
		mState.incr = mState.mss;
	}
}

void NetChannel::Update(NetChannelWriteContext& context)
{
	ion::TimeDeltaMS timeLeft = ion::DeltaTime(mState.ts_flush, context.mCurrentTime);
	if (timeLeft <= 0)
	{
		mState.ts_flush += mState.interval;
		if (ion::DeltaTime(mState.ts_flush, context.mCurrentTime) <= 0)
		{
			mState.ts_flush = context.mCurrentTime + mState.interval;
		}
		Flush(context);
	}
}

void NetChannel::ReconfigureChannelPriority(NetPacketPriority packetPriority)
{
	ION_NET_CHANNEL_LOG("Channel in: new packet priority:" << packetPriority);
	mState.currentPriority = packetPriority;
	int nodelay = ion::NetChannelPriorityConfigs[int(packetPriority)].nodelay;
	int interval = ion::NetChannelPriorityConfigs[int(packetPriority)].workInterval;
	int resend = ion::NetChannelPriorityConfigs[int(packetPriority)].resendAckSpans;
	int nc = ion::NetChannelPriorityConfigs[int(packetPriority)].nc;

	ION_ASSERT(nodelay >= 0, "Invalid nodelay");
	{
		mState.nodelay = nodelay;
		if (nodelay)
		{
			mState.rx_minrto = IKCP_RTO_NDL;
		}
		else
		{
			mState.rx_minrto = IKCP_RTO_MIN;
		}
	}
	ION_ASSERT(interval >= 0, "Invalid interval");
	ION_ASSERT(interval <= 5000, "Invalid interval");
	{
		if (interval < ion::NetUpdateInterval)
		{
			interval = ion::NetUpdateInterval;
		}
		mState.interval = interval;
	}
	ION_ASSERT(resend >= 0, "Invalid resend");
	{
		mState.fastresend = resend;
	}
	ION_ASSERT(nc >= 0, "Invalid nc");
	{
		mState.nocwnd = nc;
	}
}

void NetChannel::SndWndSize(uint32_t sndwnd)
{
	ION_ASSERT(sndwnd >= MinSndWindowSize, "Invalid send window");
	mState.cwnd = sndwnd > mState.cwnd ? sndwnd : mState.cwnd;
	mState.snd_wnd = sndwnd;
}

void NetChannel::RcvWndSize(uint32_t rcvwnd)
{
	ION_ASSERT(rcvwnd > MaxNumberOfFragments, "Invalid receive window: must be greater than max fragment size");
	mState.rcv_wnd = ion::Min(MaxRcvWindowSize, rcvwnd);
}


NetChannel::NetChannel(NetChannel&& other)
  :
	mSndQueue(std::move(other.mSndQueue)),
	mSndBuf(std::move(other.mSndBuf)),
	mRcvQueue(std::move(other.mRcvQueue)),
	mRcvBuf(std::move(other.mRcvBuf)),
	mUnrealiableSndQueue(std::move(other.mUnrealiableSndQueue)),
	acklist(other.acklist),
	mState(other.mState)
{
	other.acklist = nullptr;
	other.mState.ackblock = 0;
}
}  // namespace ion
