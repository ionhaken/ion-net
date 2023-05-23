#pragma once

#include <ion/net/NetInternalConfig.h>
#include <ion/net/NetLogging.h>
#include <ion/net/NetPayload.h>
#include <ion/net/NetTypes.h>

namespace ion
{

struct NetDownstreamSegmentHeader
{
	uint32_t conv;
	uint32_t frg;
	uint32_t wnd;
	uint32_t ts;
	uint32_t sn;
	uint32_t una;
	uint32_t len;
	uint32_t mOffset;
};

struct NetDownstreamSegment
{
	uint32_t conv;
	uint32_t frg;
	uint32_t wnd;
	uint32_t ts;
	uint32_t sn;
	uint32_t una;
	uint32_t len;
	uint32_t mOffset;
	byte data[1];
};

struct NetDownstreamSocketHeader
{
	// GUID
	uint64_t mGuid;

	NetSocket* mSource;
	byte* mDataPtr;	 // Offset to payload

	NetRemoteId mRemoteId;

	NetInternalPacketType mInternalPacketType;
	uint8_t mPadding2[sizeof(NetRemoteId) - 1];

	NetSocketAddress mAddress;

	uint32_t mBytesRead;
};
static_assert(offsetof(NetPacket, mAddress) == offsetof(NetDownstreamSocketHeader, mAddress));
static_assert(offsetof(NetPacket, mRemoteId) == offsetof(NetDownstreamSocketHeader, mRemoteId));

template <size_t PayloadSize = 1>
struct NetDownstreamPacket
{
	NetDownstreamPacket() {}
	union Header
	{
		Header() {}
		NetDownstreamSocketHeader mSocket;
		NetDownstreamSegmentHeader mSegment;
	} mHeader;
	byte mPayload[PayloadSize];

	NetSocket*& Socket() { return mHeader.mSocket.mSource; }
	uint32_t SocketBytesRead() const { return mHeader.mSocket.mBytesRead; }
	uint32_t& SocketBytesRead() { return mHeader.mSocket.mBytesRead; }
	uint32_t Length() const { return mHeader.mSegment.len; }
	uint32_t& Length() { return mHeader.mSegment.len; }

	const NetSocketAddress& Address() const { return mHeader.mSocket.mAddress; }
	NetSocketAddress& Address() { return mHeader.mSocket.mAddress; }
};

static constexpr const size_t NetDownstreamPacketPayloadOffset = offsetof(NetDownstreamPacket<1>, mPayload);

static constexpr const size_t NetPacketPayloadOffset = NetDownstreamPacketPayloadOffset;

static constexpr const size_t NetPacketMinSize = offsetof(NetPacket, mLength) + sizeof(uint32_t);

static_assert(NetPacketPayloadOffset >= NetPacketMinSize);

using NetSocketReceiveData = NetDownstreamPacket<NetMaxUdpPayloadSize()>;

struct NetCommand;
struct NetUpstreamSegmentHeader
{
	uint32_t conv;	// unencrypted conversation id
	uint32_t sn;	// unencrypted segment number
	uint32_t ts;	// unencrypted timestamp
	uint32_t frg;
	uint32_t cmd;
	uint32_t wnd;
	uint32_t una;
	uint32_t len;
	uint32_t resendts;
	uint32_t rto;
	uint32_t fastack;
	uint32_t xmit;
};

struct NetUpstreamSegment
{
	NetCommand* mCommand;
	uint64_t mPos;
	NetUpstreamSegmentHeader mHeader;
};

template <size_t PayloadSize = 1>
struct NetUpstreamPacket
{
	NetSocketAddress mAddress;
	union Optional
	{
		Optional() : mask(0) {}
		struct SocketOptions
		{
			int16_t ttl;
			bool doNotFragment;
			bool storeSocketSendResult;
		} options;
		int32_t mask;  // Apply socket options only when mask is not zero.
	} optional;
	int32_t length;
	char data[PayloadSize];

	//
	// Fluent API
	//

	inline NetUpstreamPacket& SetAddress(const NetSocketAddress& address)
	{
		mAddress = address;
		return *this;
	}

	inline NetUpstreamPacket& TTL(int ttl)
	{
		optional.options.ttl = ion::SafeRangeCast<int16_t>(ttl);
		return *this;
	}

	inline NetUpstreamPacket& DoNotFragment(bool isEnabled = true)
	{
		optional.options.doNotFragment = isEnabled;
		return *this;
	}

	inline NetUpstreamPacket& StoreSocketSendResult(bool isEnabled = true)
	{
		optional.options.storeSocketSendResult = isEnabled;
		return *this;
	}
};

using NetSocketSendParameters = NetUpstreamPacket<ion::NetMaxUdpPayloadSize()>;

static constexpr const size_t NetSocketSendParametersHeaderSize = offsetof(NetSocketSendParameters, data);

// [conversation id (4)][sequence number(4)][segment number(4)]
constexpr int NetUnencryptedProtocolBytes = 8;

// Header for unconnected messages. Replaces conversation id to distinguish between unconnected and connected messages.
constexpr uint32_t NetUnconnectedHeader =
  (uint32_t('I') << 0) | (uint32_t('O') << 8) | (uint32_t('N') << 16) | (uint32_t(NetProtocolVersion) << 24);

// Protocol version insensitive checking if a message is unconnected.
inline bool NetIsUnconnectedId(uint32_t protocolHeader) { return (protocolHeader >> 8) == (NetUnconnectedHeader & 0xFFFFFF); }

inline byte* NetPacketHeader(NetPacket* packet) { return reinterpret_cast<byte*>(packet) + NetDownstreamPacketPayloadOffset; }

}  // namespace ion
