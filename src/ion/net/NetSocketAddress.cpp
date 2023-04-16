#include <ion/net/NetSocketAddress.h>

#include <ion/byte/ByteSerialization.h>
#include <ion/util/Hasher.h>

#if ION_PLATFORM_MICROSOFT
	#include <tchar.h>
#else
	#include <arpa/inet.h>
#endif

namespace ion
{
constexpr const char* IPV6_LOOPBACK = "::1";
constexpr const char* IPV4_LOOPBACK = "127.0.0.1";
namespace
{
int CompareAssignedExcludingPort(const NetSocketAddress& left, const NetSocketAddress& right)
{
#if ION_NET_FEATURE_IPV6 == 1
	if (left.addr4.sin_family == AF_INET6)
	{
		return memcmp(left.addr6.sin6_addr.s6_addr, right.addr6.sin6_addr.s6_addr, sizeof(left.addr6.sin6_addr.s6_addr));
	}
#endif
	ION_ASSERT(left.addr4.sin_family == AF_INET, "Invalid address family");
	return int(left.addr4.sin_addr.s_addr) - int(right.addr4.sin_addr.s_addr);
}

int Compare(const NetSocketAddress& left, const NetSocketAddress& right)
{
	if (left.addr4.sin_family == ion::NetSocketAddress::InvalidFamily || right.addr4.sin_family == ion::NetSocketAddress::InvalidFamily)
	{
		return int(left.addr4.sin_family) - int(right.addr4.sin_family);
	}
	if (left.addr4.sin_port != right.addr4.sin_port)
	{
		return int(left.addr4.sin_port) - int(right.addr4.sin_port);
	}
	return CompareAssignedExcludingPort(left, right);
}

int CompareExcludingPort(const NetSocketAddress& left, const NetSocketAddress& right)
{
	if (left.addr4.sin_family == ion::NetSocketAddress::InvalidFamily || right.addr4.sin_family == ion::NetSocketAddress::InvalidFamily)
	{
		return int(left.addr4.sin_family) - int(right.addr4.sin_family);
	}
	return CompareAssignedExcludingPort(left, right);
}

bool NonNumericHostString(const char* host)
{
	// Return false if IP address. Return true if domain
	unsigned int i = 0;
	while (host[i])
	{
		if ((host[i] >= 'g' && host[i] <= 'z') || (host[i] >= 'A' && host[i] <= 'Z'))
			return true;
		++i;
	}
	return false;
}

void DomainNameToIP(const char* domainName, char ip[INET6_ADDRSTRLEN])
{
#if ION_NET_FEATURE_IPV6 == 1
	struct addrinfo hints, *res, *p;
	int status;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;  // AF_INET or AF_INET6 to force version
	hints.ai_socktype = SOCK_DGRAM;

	if ((status = getaddrinfo(domainName, NULL, &hints, &res)) != 0)
	{
		memset(ip, 0, INET6_ADDRSTRLEN);
		return;
	}

	p = res;
	void* addr;

	// get the pointer to the address itself,
	// different fields in IPv4 and IPv6:
	if (p->ai_family == AF_INET)
	{
		struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
		addr = &(ipv4->sin_addr);
		inet_ntop(p->ai_family, addr, ip, INET6_ADDRSTRLEN);
	}
	else
	{
		struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
		addr = &(ipv6->sin6_addr);
		inet_ntop(p->ai_family, addr, ip, INET6_ADDRSTRLEN);
	}
	freeaddrinfo(res);
#else
	static struct in_addr addr;
	memset(&addr, 0, sizeof(in_addr));

	// Use inet_addr instead? What is the difference?
	struct hostent* phe = gethostbyname(domainName);

	if (phe == 0 || phe->h_addr_list[0] == 0)
	{
		// cerr << "Yow! Bad host lookup." << endl;
		memset(ip, 0, 65 * sizeof(char));
		return;
	}

	if (phe->h_addr_list[0] == 0)
	{
		memset(ip, 0, 65 * sizeof(char));
		return;
	}

	memcpy(&addr, phe->h_addr_list[0], sizeof(struct in_addr));
	strcpy(ip, inet_ntoa(addr));
#endif	// #if ION_NET_FEATURE_IPV6==1
}

bool SetBinaryAddress(NetSocketAddress& address, const char* str, char portDelineator)
{
	if (NonNumericHostString(str))
	{
#if defined(_WIN32)
		if (_strnicmp(str, "localhost", 9) == 0)
#else
		if (strncasecmp(str, "localhost", 9) == 0)
#endif
		{
			inet_pton(AF_INET, "127.0.0.1", &address.addr4.sin_addr.s_addr);

			if (str[9])
			{
				unsigned short port;
				ion::serialization::Deserialize(port, str + 9, nullptr);
				address.SetPortHostOrder(port);
			}
			return true;
		}

		// const char *ip = ( char* ) SocketLayer::GlobalNameToIP( str );
		char ip[65];
		ip[0] = 0;
		DomainNameToIP(str, ip);
		if (ip[0])
		{
			inet_pton(AF_INET, ip, &address.addr4.sin_addr.s_addr);
		}
		else
		{
			address = NetUnassignedSocketAddress;
			return false;
		}
	}
	else
	{
		int index, portIndex;
		char IPPart[22];
		char portPart[10];
		for (index = 0; str[index] && str[index] != portDelineator && index < 22; index++)
		{
			if (str[index] != '.' && (str[index] < '0' || str[index] > '9'))
				break;
			IPPart[index] = str[index];
		}
		IPPart[index] = 0;
		portPart[0] = 0;
		if (str[index] && str[index + 1])
		{
			index++;
			for (portIndex = 0; portIndex < 10 && str[index] && index < 22 + 10; index++, portIndex++)
			{
				if (str[index] < '0' || str[index] > '9')
					break;

				portPart[portIndex] = str[index];
			}
			portPart[portIndex] = 0;
		}

		if (IPPart[0])
		{
			inet_pton(AF_INET, IPPart, &address.addr4.sin_addr.s_addr);
		}

		if (portPart[0])
		{
			unsigned short port;
			ion::serialization::Deserialize(port, portPart, nullptr);
			address.addr4.sin_port = htons(port);
		}
	}
	return true;
}

bool FromString(NetSocketAddress& address, const char* str, char portDelineator = '|', int ipVersion = 0)
{
#if ION_NET_FEATURE_IPV6 != 1
	(void)ipVersion;
	return SetBinaryAddress(str, portDelineator);
#else
	if (str == 0)
	{
		memset(&address, 0, sizeof(address));
		ION_ASSERT(address.addr4.sin_family == ion::NetSocketAddress::InvalidFamily, "Unexpected family");
		return true;
	}
	#if ION_NET_FEATURE_IPV6 == 1
	char ipPart[INET6_ADDRSTRLEN];
	#else
	char ipPart[INET_ADDRSTRLEN];
	#endif
	memset(ipPart, 0, sizeof(ipPart));
	char portPart[32];
	int i = 0, j;

	if (ipVersion == 4 && strcmp(str, IPV6_LOOPBACK) == 0)
	{
		ion::StringCopy(ipPart, INET_ADDRSTRLEN, IPV4_LOOPBACK);
	}
	#if ION_NET_FEATURE_IPV6 == 1
	else if (ipVersion == 6 && strcmp(str, IPV4_LOOPBACK) == 0)
	{
		address.addr4.sin_family = AF_INET6;
		ion::StringCopy(ipPart, INET6_ADDRSTRLEN, IPV6_LOOPBACK);
	}
	#endif
	else if (NonNumericHostString(str) == false)
	{
		for (; i < sizeof(ipPart) && str[i] != 0 && str[i] != portDelineator; i++)
		{
			if ((str[i] < '0' || str[i] > '9') && (str[i] < 'a' || str[i] > 'f') && (str[i] < 'A' || str[i] > 'F') && str[i] != '.' &&
				str[i] != ':' && str[i] != '%' && str[i] != '-' && str[i] != '/')
				break;

			ipPart[i] = str[i];
		}
		ipPart[i] = 0;
	}
	else
	{
		ion::StringCopy(ipPart, sizeof(ipPart), str);
	}

	j = 0;
	if (str[i] == portDelineator && portDelineator != 0)
	{
		i++;
		for (; j < sizeof(portPart) && str[i] != 0; i++, j++)
		{
			portPart[j] = str[i];
		}
	}
	portPart[j] = 0;

	// This could be a domain, or a printable address such as "192.0.2.1" or "2001:db8:63b3:1::3490"
	// I want to convert it to its binary representation
	addrinfo hints, *servinfo = 0;
	memset(&hints, 0, sizeof hints);
	hints.ai_socktype = SOCK_DGRAM;
	if (ipVersion == 6)
	{
		hints.ai_family = AF_INET6;
	}
	else if (ipVersion == 4)
	{
		hints.ai_family = AF_INET;
	}
	else
	{
		hints.ai_family = AF_UNSPEC;
	}
	int code = getaddrinfo(ipPart, nullptr, &hints, &servinfo);
	if (servinfo == 0)
	{
		if (ipVersion == 6)
		{
			ipVersion = 4;
			hints.ai_family = AF_UNSPEC;
			code = getaddrinfo(ipPart, nullptr, &hints, &servinfo);
			if (servinfo == 0)
			{
				ION_ABNORMAL("getaddrinfo() returned " << code);
				return false;
			}
		}
		else
		{
			// IPv4 fallback
			ION_ABNORMAL("getaddrinfo() returned " << code);
			return SetBinaryAddress(address, str, portDelineator);
		}
	}
	ION_NET_ASSERT(servinfo);

	unsigned short oldPort = address.addr4.sin_port;
	#if ION_NET_FEATURE_IPV6 == 1
	if (servinfo->ai_family == AF_INET)
	{
		address.addr4.sin_family = AF_INET;
		memcpy(&address.addr4, (struct sockaddr_in*)servinfo->ai_addr, sizeof(struct sockaddr_in));
	}
	else
	{
		address.addr4.sin_family = AF_INET6;
		memcpy(&address.addr6, (struct sockaddr_in6*)servinfo->ai_addr, sizeof(struct sockaddr_in6));
	}
	#else
	address.addr4.sin_family = AF_INET4;
	memcpy(&address.addr4, (struct sockaddr_in*)servinfo->ai_addr, sizeof(struct sockaddr_in));
	#endif

	freeaddrinfo(servinfo);

	// PORT
	if (portPart[0])
	{
		unsigned short port;
		ion::serialization::Deserialize(port, portPart, nullptr);
		address.addr4.sin_port = htons(port);
	}
	else
	{
		address.addr4.sin_port = oldPort;
	}
#endif	// #if ION_NET_FEATURE_IPV6!=1

	return true;
}

bool FromStringExplicitPort(NetSocketAddress& address, const char* str, unsigned short port, int ipVersion = 0)
{
	bool b = FromString(address, str, (char)0, ipVersion);
	if (b == false)
	{
		address = NetUnassignedSocketAddress;
		return false;
	}
	address.addr4.sin_port = htons(port);
	return true;
}

}  // namespace
inline uint64_t HashAddress(const NetSocketAddress& sa, uint32_t seed)
{
	if (sa.addr4.sin_family == AF_INET)
	{
		return ion::HashMemory64((const char*)&sa.addr4.sin_addr.s_addr, sizeof(sa.addr4.sin_addr.s_addr), seed);
	}
#if ION_NET_FEATURE_IPV6
	else if (sa.addr4.sin_family == AF_INET6)
	{
		return ion::HashMemory64((const char*)&sa.addr6.sin6_addr.s6_addr, sizeof(sa.addr6.sin6_addr.s6_addr), seed);
	}
#endif
	else
	{
		return 0;
	}
}

NetSocketAddress::NetSocketAddress(const char* str)
{
	addr4.sin_family = AF_INET;
	SetPortHostOrder(0);
	FromString(*this, str);
}
NetSocketAddress::NetSocketAddress(const char* str, unsigned short port, int ipVersion)
{
	addr4.sin_family = AF_INET;
	FromStringExplicitPort(*this, str, port, ipVersion);
	FixForIPVersion(ipVersion);
}

uint64_t NetSocketAddress::ToHash64() const { return HashAddress(*this, ion::Hash32(addr4.sin_port)); }

uint32_t NetSocketAddress::ToHashExcludingPort() const
{
	uint64_t hash = HashAddress(*this, 0);
	return uint32_t(hash) ^ uint32_t(hash >> 32);
}

uint32_t NetSocketAddress::ToHash() const
{
	uint64_t hash = this->ToHash64();
	return uint32_t(hash) ^ uint32_t(hash >> 32);
}

void NetSocketAddress::FixForIPVersion(int ipVersion)
{
	char str[128];
	ToString(str, 128, false);

	if (strcmp(str, IPV6_LOOPBACK) == 0)
	{
		if (ipVersion == 4)
		{
			FromString(*this, IPV4_LOOPBACK, 0, 4);
		}
	}
	else if (strcmp(str, IPV4_LOOPBACK) == 0)
	{
#if ION_NET_FEATURE_IPV6 == 1
		if (ipVersion == 6)
		{
			FromString(*this, IPV6_LOOPBACK, 0, 6);
		}
#endif
	}
}

static NetSocketAddress CreateUnassignedAddress()
{
	NetSocketAddress address;
	memset(&address, 0x0, sizeof(NetSocketAddress));
	ION_ASSERT(address.addr4.sin_family == NetSocketAddress::InvalidFamily, "Unexpected family");
	return address;
}

const NetSocketAddress NetUnassignedSocketAddress = CreateUnassignedAddress();

void NetSocketAddress::ToString(char* dest, size_t bufferLen, bool writePort, char portDelineator) const
{
	if (!IsAssigned())
	{
		ion::StringCopy(dest, bufferLen, "NetUnassignedSocketAddress");
		return;
	}

	int ret;
#if ION_NET_FEATURE_IPV6 == 1
	if (addr4.sin_family == AF_INET)
#endif	// #if ION_NET_FEATURE_IPV6!=1
	{
		ret = getnameinfo((struct sockaddr*)&addr4, sizeof(struct sockaddr_in), dest, 22, NULL, 0, NI_NUMERICHOST);
	}

#if ION_NET_FEATURE_IPV6 == 1
	else
	{
		ret = getnameinfo((struct sockaddr*)&addr6, sizeof(struct sockaddr_in6), dest, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
	}
#endif
	if (ret != 0)
	{
		dest[0] = 0;
	}

	if (writePort)
	{
		unsigned char ch[2];
		ch[0] = portDelineator;
		ch[1] = 0;
		StringConcatenate(dest, bufferLen, (const char*)ch);
		ion::serialization::Serialize(ntohs(addr4.sin_port), dest + ion::StringLen(dest), 8, nullptr);
	}
}
NetSocketAddress& NetSocketAddress::operator=(const NetSocketAddress& other)
{
	ION_ASSERT(other.addr4.sin_family == AF_INET6 || other.addr4.sin_family == AF_INET || other.addr4.sin_family == 0,
			   "Invalid address family");
	if (other.addr4.sin_family != InvalidFamily)
	{
		memcpy(&addr4, &other.addr6, other.addr4.sin_family == AF_INET6 ? sizeof(addr6) : sizeof(addr4));
	}
	else
	{
		addr4.sin_family = InvalidFamily;
	}
	return *this;
}

bool NetSocketAddress::operator==(const NetSocketAddress& right) const { return Compare(*this, right) == 0; }

bool NetSocketAddress::operator>(const NetSocketAddress& right) const { return Compare(*this, right) > 0; }

bool NetSocketAddress::operator<(const NetSocketAddress& right) const { return Compare(*this, right) < 0; }

bool NetSocketAddress::EqualsExcludingPort(const NetSocketAddress& right) const { return CompareExcludingPort(*this, right) == 0; }

bool NetSocketAddress::SetBinaryAddress(const char* str, char portDelineator) { return ion::SetBinaryAddress(*this, str, portDelineator); }

void NetSocketAddress::SetToLoopback() { SetToLoopback(GetIPVersion()); }
void NetSocketAddress::SetToLoopback(unsigned char ipVersion)
{
	if (ipVersion == 4)
	{
		FromString(*this, IPV4_LOOPBACK, 0, ipVersion);
	}
#if ION_NET_FEATURE_IPV6 == 1
	else if (ipVersion == 6)
	{
		FromString(*this, IPV6_LOOPBACK, 0, ipVersion);
	}
#endif
}

bool NetSocketAddress::IsLoopback() const
{
	if (GetIPVersion() == 4)
	{
		if (htonl(addr4.sin_addr.s_addr) == 2130706433)
		{
			return true;
		}
		if (addr4.sin_addr.s_addr == 0)
		{
			return true;
		}
	}
#if ION_NET_FEATURE_IPV6 == 1
	else if (GetIPVersion() == 6)
	{
		const static char localhost[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
		if (memcmp(&addr6.sin6_addr, localhost, 16) == 0)
		{
			return true;
		}
	}
#endif
	return false;
}

}  // namespace ion

namespace ion::serialization
{
template <>
ion::UInt Serialize(const NetSocketAddress& data, char* buffer, size_t bufferLen, const void*)
{
	ION_ASSERT(bufferLen > INET6_ADDRSTRLEN + 5 + 1, "Out of buffer");
	data.ToString(buffer, bufferLen);
	return ion::UInt(ion::StringLen(buffer));
}
template <>
void Serialize(const NetSocketAddress& src, ion::ByteWriter& writer)
{
	writer.Write(src.GetIPVersion());
#if ION_NET_FEATURE_IPV6
	if (src.GetIPVersion() == 6)
	{
		writer.Write(src.addr6);
	}
	else
#endif
	  if (src.GetIPVersion() == 4)
	{
		writer.Write(src.addr4.sin_addr.s_addr);
		writer.Write(src.GetPortNetworkOrder());
	}
}

template <>
bool Deserialize(NetSocketAddress& dst, ion::ByteReader& reader, void*)
{
	bool isValid = true;
	unsigned char ipVersion;
	isValid &= reader.Read(ipVersion);
#if ION_NET_FEATURE_IPV6
	if (ipVersion == 6)
	{
		dst.addr4.sin_family = AF_INET6;
		isValid &= reader.Read(dst.addr6);
	}
	else if (ipVersion == 4)
#endif
	{
		dst.addr4.sin_family = AF_INET;
		isValid &= reader.Read(dst.addr4.sin_addr.s_addr);
		isValid &= reader.Read(dst.addr4.sin_port);
	}
	else
	{
		dst = NetUnassignedSocketAddress;
	}
	return isValid;
}

}  // namespace ion::serialization
