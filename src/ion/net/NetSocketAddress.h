#pragma once

#include <ion/net/NetConfig.h>

#include <ion/byte/ByteSerialization.h>
#include <ion/util/Hasher.h>

#if ION_PLATFORM_MICROSOFT
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <sys/socket.h>
	#if ION_PLATFORM_ANDROID
		#include <arpa/inet.h>
	#endif
	#include <netdb.h>
#endif

namespace ion
{

union ION_EXPORT NetSocketAddress
{
	static constexpr unsigned short InvalidFamily = AF_UNSPEC;
#if ION_NET_FEATURE_IPV6 == 1
	struct sockaddr_storage sa_stor;  // protocol-family and protocol-version independent
	sockaddr_in6 addr6;
#endif
	sockaddr_in addr4;
	NetSocketAddress() { addr4.sin_family = InvalidFamily; }
	NetSocketAddress(const char* str);
	NetSocketAddress(const char* str, unsigned short port, int ipVersion = 0);
	NetSocketAddress(const NetSocketAddress& other) { *this = other; }
	NetSocketAddress& operator=(const NetSocketAddress& other);
	bool operator==(const NetSocketAddress& right) const;
	bool operator>(const NetSocketAddress& right) const;
	bool operator<(const NetSocketAddress& right) const;
	bool operator!=(const NetSocketAddress& right) const { return !(*this == right); }
	bool EqualsExcludingPort(const NetSocketAddress& right) const;
	constexpr unsigned char GetIPVersion() const
	{
		if (addr4.sin_family != InvalidFamily)
		{
			return (addr4.sin_family == AF_INET) ? 4 : 6;
		}
		else 
		{
			return 0;
		}
	}

	constexpr unsigned int GetIPPROTO() const
	{
		ION_ASSERT_FMT_IMMEDIATE(addr4.sin_family != InvalidFamily, "Invalid address");
		return (addr4.sin_family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6;
	}

	inline unsigned short GetPort(void) const { return ntohs(addr4.sin_port); }
	constexpr unsigned short GetPortNetworkOrder(void) const { return addr4.sin_port; }

	void ToString(char* dest, size_t bufferLen, bool writePort = true, char portDelineator = '|') const;
	uint64_t ToHash64() const;
	uint32_t ToHash() const;
	uint32_t ToHashExcludingPort() const;
	constexpr bool IsAssigned() const { return addr4.sin_family != InvalidFamily; }
	constexpr bool IsValid() const { return addr4.sin_family == AF_INET || addr4.sin_family == AF_INET6; }

	void CopyPort(const NetSocketAddress& right) { addr4.sin_port = right.addr4.sin_port; }
	void SetPortHostOrder(unsigned short s) { addr4.sin_port = htons(s); }
	void SetPortNetworkOrder(unsigned short s) { addr4.sin_port = s; }
	bool SetBinaryAddress(const char* str, char portDelineator = ':');
	void FixForIPVersion(int ipVersion);
	void SetToLoopback();
	void SetToLoopback(unsigned char ipVersion);
	bool IsLoopback() const;
};

extern const NetSocketAddress NetUnassignedSocketAddress;

#if 0  // #TODO: Explore using storage only for writing data
	#if ION_NET_FEATURE_IPV6 == 1
static_assert(sizeof(NetSocketAddress) == 32);
	#endif
union NetSocketAddressStorage
{
	static constexpr const unsigned short InvalidFamily = AF_UNSPEC;
	struct sockaddr_storage sa_stor;
	NetSocketAddress mAddr;
};
	#if ION_NET_FEATURE_IPV6 == 1
static_assert(sizeof(NetSocketAddressStorage) == 128);
	#endif
#endif

template <>
inline size_t Hasher<ion::NetSocketAddress>::operator()(const ion::NetSocketAddress& key) const
{
	if constexpr (sizeof(size_t) == 8)
	{
		return key.ToHash64();
	}
	else
	{
		return key.ToHash();
	}
}

}  // namespace ion

namespace ion::serialization
{
template <>
ion::UInt Serialize(const NetSocketAddress& data, char* buffer, size_t bufferLen, const void*);

template <>
void Serialize(const NetSocketAddress& src, ion::ByteWriter& writer);

template <>
bool Deserialize(NetSocketAddress& dst, ion::ByteReader& reader, void*);

}  // namespace ion::serialization
