#pragma once

#include <ion/net/NetMemory.h>
#include <ion/net/NetReliableChannels.h>
#include <ion/net/NetSecureTypes.h>
#include <ion/net/NetSimulator.h>
#include <ion/net/NetStats.h>
#include <ion/net/NetTimeSync.h>

#include <ion/arena/UniqueArenaPtr.h>

#include <ion/memory/TLSFResource.h>

namespace ion
{

constexpr bool NetModeIsOpen(NetMode mode) { return unsigned(mode) > unsigned(NetMode::DisconnectOnNoAck); }

using NetRemoteSystemResource = ion::TLSFResource<PolymorphicResource, ion::tag::Network>;

enum class NetDataTransferSecurity : uint8_t
{
	EncryptionAndReplayProtection,  // #TODO: Impl replay protection & checksum
	ReplayProtectionAndChecksum,
	Checksum,
	Disabled
};

struct NetRemoteSystem
{
	template <typename T>
	using RemoteSystemAllocator = ion::ArenaAllocator<T, NetRemoteSystemResource>;

	ion::ArenaPtr<NetRemoteSystemResource, ion::NetInterfaceResource> mResource;

	template <typename T>
	T* Allocate(size_t s)
	{
		RemoteSystemAllocator<T> allocator(mResource.Get());
		return allocator.AllocateRaw(s, alignof(T));
	}

	template <typename T>
	void Deallocate(T* ptr, size_t s = 0)
	{
		RemoteSystemAllocator<T> allocator(mResource.Get());
		allocator.DeallocateRaw(ptr, s, alignof(T));
	}

	// Data transport
	NetSocket* netSocket = nullptr;  // Reference counted socket to send back on
	ion::NetReliableChannels reliableChannels;

	// Qos
	ion::Mutex mMetrixInitMutex;
	ion::NetInterfacePtr<ion::DataMetrics> mMetrics;
	ion::NetRttTracker pingTracker;

#if ION_NET_FEATURE_SECURITY
	ion::NetSecure::SharedKey mSharedKey;
	ion::Array<unsigned char, ion::NetSecure::NonceLength - NetUnencryptedProtocolBytes> mNonceOffset;
#endif
	uint32_t mConversationId = 0;
	std::atomic<NetRemoteId> mId;
	uint16_t MTUSize = 0;

	// Connection handling
	ion::TimeMS connectionTime;	 /// connection time, if active.
	ion::TimeMS timeLastDatagramArrived;
	ion::TimeMS timeoutTime;
	ion::TimeMS lastReliableSend;  // When was the last reliable send requested. Reliable sends must occur at least once every
								   // timeoutTime/2 units to notice disconnects. Note this is indeed time of request, not the last time
								   // reliable layer triggered send or resend.
	NetMode mMode;

	// Other
	ion::NetTimeSync timeSync;
	NetDataTransferSecurity mDataTransferSecurity = NetDataTransferSecurity::Disabled;
	bool mIsRemoteInitiated = false;
	bool mAllowFastReroute = false;	// Sender can change system address without need to renegotiate connection.


	// Id
	NetGUID guid;
	NetSocketAddress mAddress;  /// Their external IP on the internet
};
}  // namespace ion
