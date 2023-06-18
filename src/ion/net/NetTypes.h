#pragma once

#include <ion/net/NetGUID.h>
#include <ion/net/NetSocketAddress.h>

namespace ion
{
class NetSocket;

enum class NetPacketFlags : uint8_t
{
	Clear = 0,
	DownstreamSegment = (1 << 0),  // Variable payload offset
	Unreliable = (1 << 1)
};

struct NetPacket
{
	[[nodiscard]] inline uint32_t Length() const { return mLength; }

	[[nodiscard]] inline byte* Data() { return mDataPtr; }

	inline bool IsUnreliablePacket() const
	{
		return (unsigned(mFlags) & unsigned(NetPacketFlags::Unreliable)) == unsigned(NetPacketFlags::Unreliable);
	}

	inline bool IsDirectSocketData() const
	{
		return (unsigned(mFlags) & unsigned(NetPacketFlags::DownstreamSegment)) == unsigned(NetPacketFlags::DownstreamSegment);
	}

	ion::NetGUID mGUID;
	NetSocket* mSource;

	// Offset to payload - can be something else than the NetPacketHeader() if packet is directly converted from network segment during
	// reassembly (internal type is 'DownstreamSegment') and offset is used to skip the protocol header.
	byte* mDataPtr;

	NetRemoteId mRemoteId;

	NetPacketFlags mFlags;

	uint8_t mPadding1[sizeof(NetRemoteId) - 1];

	uint32_t mLength;

	NetSocketAddress mAddress;
};

// struct AddressOrGUID;
struct ION_EXPORT NetAddressOrRemoteRef
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(NetAddressOrRemoteRef);

	const NetSocketAddress& mAddress;
	const NetRemoteId mRemoteId;

	constexpr NetRemoteId RemoteId() const { return mRemoteId; }
	constexpr bool IsUndefined(void) const { return !mRemoteId.IsValid() && mAddress == NetUnassignedSocketAddress; }
	constexpr NetAddressOrRemoteRef(const NetRemoteId id) : mAddress(NetUnassignedSocketAddress), mRemoteId(id) {}
	constexpr NetAddressOrRemoteRef(const NetRemoteId id, const NetSocketAddress& address) : mAddress(address), mRemoteId(id) {}
	constexpr NetAddressOrRemoteRef(const NetSocketAddress& address) : mAddress(address) {}
	inline NetAddressOrRemoteRef(const NetPacket* packet) : mAddress(packet->mAddress), mRemoteId(packet->mRemoteId) {}

	inline bool operator==(const NetAddressOrRemoteRef& other) const
	{
		return (mAddress != NetUnassignedSocketAddress && mAddress == other.mAddress) ||
			   (mRemoteId.IsValid() && mRemoteId == other.mRemoteId);
	}

	static inline uint32_t ToInteger(const NetAddressOrRemoteRef& aog)
	{
		return aog.mRemoteId.IsValid() ? aog.mRemoteId.UInt32() : aog.mAddress.ToHash();
	}

	inline void ToString(char* dest, size_t bufferLen, bool writePort) const
	{
		if (mRemoteId.IsValid())
		{
			StringWriter writer(dest, bufferLen);
			serialization::Serialize(mRemoteId.UInt32(), writer);
		}
		else
		{
			mAddress.ToString(dest, bufferLen, writePort);
		}
	}
};

template <>
inline size_t Hasher<ion::NetRemoteId>::operator()(const ion::NetRemoteId& key) const
{
	return Hasher<uint32_t>()(key.UInt32());
}

enum class NetMode : uint8_t
{
	Disconnected,
	DisconnectAsap,	 // We requested disconnection
	DisconnectAsapSilently,
	DisconnectAsapMutual,  // Both requested disconnection
	DisconnectOnNoAck,	   // Remote requested disconnection
	RequestedConnection,
	HandlingConnectionRequest,
	UnverifiedSender,
	Connected
};


}  // namespace ion
