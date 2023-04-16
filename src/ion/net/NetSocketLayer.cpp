#include <ion/net/NetCommand.h>
#include <ion/net/NetControlLayer.h>
#include <ion/net/NetPayload.h>
#include <ion/net/NetReceptionLayer.h>
#include <ion/net/NetSocketLayer.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/container/ForEach.h>

#include <ion/string/String.h>
#include <ion/string/StringUtil.h>

namespace ion
{
namespace SocketLayer
{
namespace
{
struct AddressInfo
{
	AddressInfo(int type)
	{
		char ac[256];
		int err = gethostname(ac, sizeof(ac));
		ION_ASSERT(err != -1, "No hostname: " << ion::debug::GetLastErrorString());

		ion::NetBindParameters bindParameters;
		memset(&bindParameters, 0x0, sizeof(ion::NetBindParameters));
		bindParameters.hostAddress = ac;
		bindParameters.type = type;
		Load(bindParameters);
	}

	AddressInfo(const ion::NetBindParameters& bindParameters) { Load(bindParameters); }

	~AddressInfo() { freeaddrinfo(mServinfo); }

	// Calls callback with all found system addresses for given socket parameters
	ion::ForEachOp ForEach(ion::InplaceFunction<ion::ForEachOp(struct addrinfo* aip)> callback)
	{
		auto isRequiestedAI = [&](struct addrinfo* aip)
		{
			return (mBindParameters.addressFamily == 0 || aip->ai_family == mBindParameters.addressFamily) &&
				   (mBindParameters.type == 0 || aip->ai_socktype == mBindParameters.type) &&
				   (mBindParameters.protocol == 0 || aip->ai_protocol == mBindParameters.protocol);
		};

		// Get best first.
		for (struct addrinfo* aip = mServinfo; aip != nullptr; aip = aip->ai_next)
		{
			if (isRequiestedAI(aip))
			{
				if (callback(aip) == ion::ForEachOp::Break)
				{
					return ion::ForEachOp::Break;
				}
			}
		}

		for (struct addrinfo* aip = mServinfo; aip != nullptr; aip = aip->ai_next)
		{
			if (!isRequiestedAI(aip))
			{
				if (callback(aip) == ion::ForEachOp::Break)
				{
					return ion::ForEachOp::Break;
				}
			}
		}

		return ion::ForEachOp::Next;
	}

	// As ForEach, but additionally will call with fallback addresses.
	ion::ForEachOp ForEachWithFallback(ion::InplaceFunction<ion::ForEachOp(struct addrinfo* aip)> callback)
	{
		if (ForEach(callback) == ion::ForEachOp::Break)
		{
			return ion::ForEachOp::Break;
		}

		struct addrinfo aip;
		aip.ai_protocol = mBindParameters.protocol;
		aip.ai_socktype = mBindParameters.type;

		// Fallback to IPv6
		if (mBindParameters.addressFamily != AF_INET)
		{
			aip.ai_family = AF_INET6;
			sockaddr_in6 addr6;
			memset(&addr6, 0, sizeof(struct sockaddr_in6));
			addr6.sin6_addr = IN6ADDR_ANY_INIT;
			addr6.sin6_port = htons(mBindParameters.port);
			aip.ai_addr = reinterpret_cast<struct sockaddr*>(&addr6);
			aip.ai_addrlen = sizeof(addr6);
			if (mBindParameters.hostAddress && mBindParameters.hostAddress[0])
			{
				inet_pton(AF_INET6, mBindParameters.hostAddress, &addr6.sin6_addr);
			}
			if (callback(&aip) == ion::ForEachOp::Break)
			{
				return ion::ForEachOp::Break;
			}
		}

		// Fallback to IPv4
		{
			aip.ai_family = AF_INET;
			sockaddr_in addr4;
			memset(&addr4, 0, sizeof(struct sockaddr_in));
			addr4.sin_addr.s_addr = INADDR_ANY;
			addr4.sin_port = htons(mBindParameters.port);
			aip.ai_addr = reinterpret_cast<struct sockaddr*>(&addr4);
			aip.ai_addrlen = sizeof(addr4);
			if (mBindParameters.hostAddress && mBindParameters.hostAddress[0])
			{
				inet_pton(AF_INET, mBindParameters.hostAddress, &addr4.sin_addr);
			}
			if (callback(&aip) == ion::ForEachOp::Break)
			{
				return ion::ForEachOp::Break;
			}
		}
		return ion::ForEachOp::Next;
	}

private:
	ion::NetBindParameters mBindParameters;
	struct addrinfo* mServinfo = nullptr;

	void Load(const ion::NetBindParameters& bindParameters)
	{
		mBindParameters = bindParameters;
		struct addrinfo hints;
		memset(&hints, 0, sizeof(addrinfo));
		hints.ai_socktype = bindParameters.type;
		hints.ai_flags = AI_PASSIVE |	  // Socket address will be used in bind() call
						 AI_NUMERICSERV;  // Service is numeric port
		hints.ai_family = bindParameters.addressFamily;
		hints.ai_protocol = bindParameters.protocol;

		// Unspecified address strings must be converted to null. Also empty ("") might not give suitable results on some systems.
		const char* node = bindParameters.hostAddress;
		if (node && (ion::StringCaseCompare(node, "NetUnassignedSocketAddress") == 0 || node[0] == 0))
		{
			node = 0;
		}

		char portStr[32];
		ion::serialization::Serialize(bindParameters.port, portStr, 32, nullptr);

		const int code = getaddrinfo(node, portStr, &hints, &mServinfo);
		if (code != 0)
		{
#ifndef ION_PLATFORM_MICROSOFT
			if (code != EAI_SYSTEM)
			{
				ION_ABNORMAL("getaddrinfo() returned: " << code);
			}
			else
#endif
			{
				ION_ABNORMAL("getaddrinfo() error:" << ion::debug::GetLastErrorString());
			}
		}
		else if (mServinfo == nullptr)
		{
			ION_ABNORMAL("getaddrinfo() returned no data");
		}
	}
};

template <typename T>
inline int SetSocketOption(ion::NetNativeSocket& nativeSocket, int level, int optname, T& optVal)
{
	int result = setsockopt(nativeSocket, level, optname, reinterpret_cast<const char*>(&optVal), sizeof(T));
	if (result != 0)
	{
		ION_ABNORMAL("setsockopt() failed. " << ion::debug::GetLastErrorString() << ";level=" << level << ";option=" << optname);
	}
	return result;
}

void GetSystemAddress(ion::NetNativeSocket& nativeSocket, ion::NetSocketAddress& systemAddressOut)
{
	socklen_t slen;
	sockaddr_storage ss;
	memset(&ss, 0, sizeof(sockaddr_storage));
	slen = sizeof(ss);

	if (getsockname(nativeSocket, (struct sockaddr*)&ss, &slen) != 0)
	{
		ION_ABNORMAL("getsockname failed:" << ion::debug::GetLastErrorString());
		systemAddressOut = NetSocketAddress(nullptr);
		return;
	}

	if (ss.ss_family == AF_INET)
	{
		{
			sockaddr_in& sa = (sockaddr_in&)(ss);
			memcpy(&systemAddressOut.addr4, &sa, sizeof(sockaddr_in));

			systemAddressOut.SetPortNetworkOrder(sa.sin_port);
			systemAddressOut.addr4.sin_addr.s_addr = sa.sin_addr.s_addr;
		}
		if (systemAddressOut.addr4.sin_addr.s_addr == INADDR_ANY)
		{
			inet_pton(AF_INET, "127.0.0.1", &systemAddressOut.addr4.sin_addr);
		}

		uint32_t zero = 0;
		if (memcmp(&systemAddressOut.addr4.sin_addr.s_addr, &zero, sizeof(zero)) == 0)
		{
			systemAddressOut.SetToLoopback(4);
		}
	}
#if ION_NET_FEATURE_IPV6 == 1
	else
	{
		memcpy(&systemAddressOut.addr6, (sockaddr_in6*)&ss, sizeof(sockaddr_in6));

		char zero[16];
		memset(zero, 0, sizeof(zero));
		if (memcmp(&systemAddressOut.addr4.sin_addr.s_addr, &zero, sizeof(zero)) == 0)
		{
			systemAddressOut.SetToLoopback(6);
		}
	}
#endif
}

}  // namespace

#if ION_PLATFORM_MICROSOFT
int CloseSocket(NetSocket& socket) { return closesocket(socket.mNativeSocket); };
#elif ION_PLATFORM_APPLE
int CloseSocket(NetSocket& socket) { return CFSocketInvalidate(socket.mNativeSocket); };
#else
int CloseSocket(NetSocket& socket) { return close(socket.mNativeSocket); };
#endif

ion::NetBindResult BindSocket(NetSocket& socketLayer, ion::NetBindParameters& bindParameters)
{
	ion::NetBindResult result = ion::NetBindResult::FailedToBind;
	AddressInfo addressInfo(bindParameters);
	addressInfo.ForEachWithFallback(
	  [&](struct addrinfo* aip)
	  {
		  socketLayer.mNativeSocket = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);
		  if (!socketLayer.mNativeSocket)
		  {
			  ION_ABNORMAL("Invalid socket: " << ion::debug::GetLastErrorString());
			  return ion::ForEachOp::Next;
		  }
#if ION_NET_FEATURE_IPV6 == 1
		  if (aip->ai_family == AF_INET6)
		  {
			  // Set as Dual-Stack Socket. Must be done before socket is bound
			  int opt = 0;
			  SetSocketOption(socketLayer.mNativeSocket, IPPROTO_IPV6, IPV6_V6ONLY, opt);
		  }
#endif
		  SetSocketOption(socketLayer.mNativeSocket, SOL_SOCKET, SO_RCVBUF, ion::NetDefaultReceiveBufferSizeBytes);
		  {
			  struct timeval tv;
			  tv.tv_sec = 0;
			  tv.tv_usec = ion::NetDefaultReceiveTimeoutMicros;
			  SetSocketOption(socketLayer.mNativeSocket, SOL_SOCKET, SO_RCVTIMEO, tv);
		  }
		  {
			  struct timeval tv;
			  tv.tv_sec = 0;
			  tv.tv_usec = ion::NetDefaultSendTimeoutMicros;
			  SetSocketOption(socketLayer.mNativeSocket, SOL_SOCKET, SO_SNDTIMEO, tv);
		  }

		  /*if (aip->ai_socktype == SOCK_STREAM)
		  {
			  struct linger opt = {
				.l_onoff = 1,
				.l_linger = 0,
			  };
			  SetSocketOption(nativeSocket, SOL_SOCKET, SO_LINGER, opt);
		  }*/
		  SetSocketOption(socketLayer.mNativeSocket, SOL_SOCKET, SO_SNDBUF, ion::NetDefaultSendBufferSizeBytes);
		  if (aip->ai_socktype == SOCK_DGRAM)
		  {
			  SetSocketOption(socketLayer.mNativeSocket, SOL_SOCKET, SO_BROADCAST, bindParameters.setBroadcast);
		  }
		  if (aip->ai_socktype == SOCK_RAW)
		  {
			  SetSocketOption(socketLayer.mNativeSocket, IPPROTO_IP, IP_HDRINCL, bindParameters.setIPHdrIncl);
		  }
		  ION_ASSERT((aip->ai_family == AF_INET && aip->ai_addrlen == sizeof(sockaddr_in)) ||
					   (aip->ai_family == AF_INET6 && aip->ai_addrlen == sizeof(sockaddr_in6)),
					 "Invalid system address");

		  int ret = bind(socketLayer.mNativeSocket, aip->ai_addr, ion::SafeRangeCast<int>(aip->ai_addrlen));
		  if (ret < 0)
		  {
			  ION_ABNORMAL("Bind failed: port " << bindParameters.port << " (" << ret << ") " << ion::debug::GetLastErrorString());
		  }
		  else
		  {
			  memcpy(&socketLayer.mBoundAddress, aip->ai_addr, aip->ai_addrlen);

			  GetSystemAddress(socketLayer.mNativeSocket, socketLayer.mBoundAddress);

			  // UDP: Also test sending
			  int sr(1);
			  if (bindParameters.type == SOCK_DGRAM)
			  {
				  ION_ALIGN(alignof(ion::NetSocketSendParameters)) uint32_t zero[NetSocketSendParametersHeaderSize + sizeof(uint32_t)] = {};
				  ion::NetSocketSendParameters& sendParameters = reinterpret_cast<ion::NetSocketSendParameters&>(zero);
				  sendParameters.length = sizeof(uint32_t);
				  sendParameters.SetAddress(socketLayer.mBoundAddress);
				  sr = ion::SocketLayer::SendBlocking(socketLayer, sendParameters);
			  }
			  if (sr)
			  {
				  memcpy(&socketLayer.mBindParameters, &bindParameters, sizeof(ion::NetBindParameters));
				  result = NetBindResult::Success;
				  return ion::ForEachOp::Break;
			  }
			  result = NetBindResult::FailedToSendTest;
		  }
		  if (socketLayer.mNativeSocket != NetInvalidSocket)
		  {
			  CloseSocket(socketLayer);
		  }
		  return ion::ForEachOp::Next;
	  });
	return result;
}

void GetInternalAddresses(ion::Array<NetSocketAddress, NetMaximumNumberOfInternalIds>& addresses)
{
	AddressInfo addressInfo(SOCK_DGRAM);
	int idx = 0;
	addressInfo.ForEach(
	  [&](struct addrinfo* aip)
	  {
		  if (aip->ai_family == AF_INET)
		  {
			  struct sockaddr_in* ipv4 = (struct sockaddr_in*)aip->ai_addr;
			  memcpy(&addresses[idx].addr4, ipv4, sizeof(sockaddr_in));
		  }
#if ION_NET_FEATURE_IPV6 == 1
		  else if (aip->ai_family == AF_INET6)
		  {
			  struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)aip->ai_addr;
			  memcpy(&addresses[idx].addr6, ipv6, sizeof(sockaddr_in6));
		  }
#endif
		  else
		  {
			  return ion::ForEachOp::Next;
		  }
		  idx++;
		  if (idx >= NetMaximumNumberOfInternalIds)
		  {
			  return ion::ForEachOp::Break;
		  }
		  return ion::ForEachOp::Next;
	  });

	while (idx < NetMaximumNumberOfInternalIds)
	{
		addresses[idx] = ion::NetUnassignedSocketAddress;
		idx++;
	}
}

int ListenSocket(NetSocket& socketLayer, unsigned int maxConnections) { return listen(socketLayer.mNativeSocket, maxConnections); }

int ConnectSocket(NetSocket& socketLayer, ion::NetSocketAddress& systemAddress)
{
	int connectResult = connect(socketLayer.mNativeSocket, (struct sockaddr*)&systemAddress, sizeof(struct sockaddr));
	if (connectResult == 0)
	{
		return 1;
		/*unsigned sockfdIndex;
		blockingSocketListMutex.Lock();
		sockfdIndex = blockingSocketList.GetIndexOf(sockfd);
		if (sockfdIndex != (unsigned)-1)
			blockingSocketList.RemoveAtIndexFast(sockfdIndex);
		blockingSocketListMutex.Unlock();*/
	}
	ION_LOG_INFO("Connect failed:" << ion::debug::GetLastErrorString() << " target=" << systemAddress);
	CloseSocket(socketLayer);
	return 0;
}

void RecvFromBlocking(const NetSocket& socketLayer, ion::NetSocketReceiveData& recvFromStruct)
{
	sockaddr_storage their_addr;
	sockaddr* sockAddrPtr;
	socklen_t sockLen;
	socklen_t* socketlenPtr = (socklen_t*)&sockLen;
	memset(&their_addr, 0, sizeof(their_addr));
	{
		sockLen = sizeof(their_addr);
		sockAddrPtr = (sockaddr*)&their_addr;
	}

	constexpr int dataOutSize = ion::NetMaxUdpPayloadSize();
	constexpr int flag = 0;
	int bytesRead =
	  recvfrom(socketLayer.mNativeSocket, reinterpret_cast<char*>(recvFromStruct.mPayload), dataOutSize, flag, sockAddrPtr, socketlenPtr);

	if (bytesRead > 0)
	{
		ION_NET_SOCKET_LOG("Socket in: receiving: size=" << bytesRead);
		recvFromStruct.SocketBytesRead() = uint32_t(bytesRead);
		if (their_addr.ss_family == AF_INET)
		{
			memcpy(&recvFromStruct.Address().addr4, (sockaddr_in*)&their_addr, sizeof(sockaddr_in));
		}
#if ION_NET_FEATURE_IPV6 == 1
		else
		{
			memcpy(&recvFromStruct.Address().addr6, (sockaddr_in6*)&their_addr, sizeof(sockaddr_in6));
		}
#endif
	}
	else
	{
		recvFromStruct.SocketBytesRead() = 0;
#if ION_PLATFORM_MICROSOFT && ION_BUILD_DEBUG
		if (bytesRead == -1)
		{
			DWORD dwIOError = GetLastError();
			if (dwIOError != 10035)
			{
				ION_DBG_TAG(Network, "Recvfrom failed:" << dwIOError);
			}
		}
#endif
	}
}

void SetNonBlocking(NetSocket& socket, unsigned long nonblocking)
{
#if ION_PLATFORM_MICROSOFT
	int res = ioctlsocket(socket.mNativeSocket, FIONBIO, &nonblocking);
	ION_ASSERT(res == 0, "Bad socket");

#else
	if (nonblocking)
	{
		fcntl(socket.mNativeSocket, F_SETFL, O_NONBLOCK);
	}
#endif
}

#if ION_NET_FEATURE_STREAMSOCKET
void StreamSendThread(__TCPSOCKET__ socket)
{
	streamSocket = socket;
	endThreads = false;
	HandleSendData(std::bind(&RNS2_Berkley::StreamSendData, this, std::placeholders::_1));
}
static constexpr size_t TCP_IP_MAX_PACKET_SIZE = size_t(1024) * 1024 * 1024 * 1024;

void ConnectingThread(NetSocket& socket, SystemAddress& systemAddress)
{
	endThreads = false;
	mReceiveThread.SetEntryPoint(
	  [&]()
	  {
		  auto result = ion::NetConnectionLayer::HandleOpenConnectionRequest(&rakPeer, systemAddress, socketLayer.boundAddress,
																			 &socketLayer, ion::NetGUID(1), false, TCP_IP_MAX_PACKET_SIZE);
		  if (result.rssFromSA && result.outcome == ion::NetConnectionLayer::ConnectionResult::Verdict::Ok)
		  {
			  ION_LOG_INFO("Done connecting");
			  result.rssFromSA->weInitiatedTheConnection = true;
			  result.rssFromSA->mMode = NetMode::Connected;
			  socketLayer.StreamSendThread(socketLayer.mNativeSocket);
			  ion::NetSocketReceiveData* recvFromStruct = AllocateRecv();
			  while (endThreads == false)
			  {
				  recvFromStruct->socket = this;
				  recvFromStruct->systemAddress = systemAddress;
				  recvFromStruct->bytesRead = recv(socketLayer.mNativeSocket, recvFromStruct->data, StreamingBufferSize, 0);
				  recvFromStruct->timeRead = ion::SteadyClock::GetTimeMS();
				  if (recvFromStruct->bytesRead > 0)
				  {
					  ION_NET_ASSERT(recvFromStruct->systemAddress.GetPort());
					  recvFromStruct = rakPeer.OnRNS2Recv(recvFromStruct);
				  }
				  else
				  {
					  //  ION_DBG("VAL=" << ion::debug::GetLastErrorString());
					  ion::Thread::SleepMs(0);
				  }
			  }
			  mFreePayload.Release(reinterpret_cast<RakNetSocket2::Payload*>(recvFromStruct));
		  }
	  });
	mReceiveThread.Start(32 * 1024, ion::NetworkReceivePriority);
}

void ListeningThread(NetSocket& socket)
{
	endThreads = false;

	mReceiveThread.SetEntryPoint(
	  [this, &rakPeer, &socketLayer]()
	  {
		  fd_set readFD, exceptionFD, writeFD;
		  while (endThreads == false)
		  {
			  FD_ZERO(&readFD);
			  FD_ZERO(&exceptionFD);
			  FD_ZERO(&writeFD);
			  __TCPSOCKET__ largestDescriptor = 0;
			  largestDescriptor = 0;
			  if (mNativeSocket != 0)
			  {
				  FD_SET(mNativeSocket, &readFD);
				  FD_SET(mNativeSocket, &exceptionFD);
				  largestDescriptor = mNativeSocket;  // @see largestDescriptor def
			  }
			  __TCPSOCKET__ socketCopy = mNativeSocket;
			  if (socketCopy != 0)
			  {
				  FD_SET(socketCopy, &readFD);
				  FD_SET(socketCopy, &exceptionFD);
				  /*if (sts->remoteClients[i].outgoingData.GetBytesWritten() > 0)
					  FD_SET(socketCopy, &writeFD);*/
				  if (socketCopy > largestDescriptor)  // @see largestDescriptorDef
					  largestDescriptor = socketCopy;

				  timeval tv;
				  tv.tv_sec = 0;
				  tv.tv_usec = 30000;
				  // ION_LOG_INFO("Select");
				  int selectResult = (int)select((int)(largestDescriptor) + 1, &readFD, &writeFD, &exceptionFD, &tv);
				  if (selectResult > 0)
				  {
					  struct sockaddr_storage sockAddr;
					  socklen_t sockAddrSize = sizeof(sockAddr);
					  ION_LOG_INFO("Accepting");
					  __TCPSOCKET__ acceptedSocket = accept(mNativeSocket, (sockaddr*)&sockAddr, (socklen_t*)&sockAddrSize);
					  ION_LOG_INFO("Accepted");
					  SystemAddress systemAddress;
					  memcpy(&systemAddress.address, (sockaddr_in*)&sockAddr,
							 sockAddr.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));

					  auto result = ion::NetConnectionLayer::HandleOpenConnectionRequest(&rakPeer, systemAddress, this->boundAddress, this,
																						 ion::NetGUID(1), false, TCP_IP_MAX_PACKET_SIZE);
					  if (result.rssFromSA && result.outcome == ion::NetConnectionLayer::ConnectionResult::Verdict::Ok)
					  {
						  result.rssFromSA->mMode = NetMode::Connected;
						  ion::NetSocketReceiveData* recvFromStruct = AllocateRecv();
						  StreamSendThread(acceptedSocket);
						  while (endThreads == false)
						  {
							  recvFromStruct->socket = this;
							  recvFromStruct->systemAddress = systemAddress;
							  recvFromStruct->bytesRead = recv(acceptedSocket, recvFromStruct->data, StreamingBufferSize, 0);
							  recvFromStruct->timeRead = ion::SteadyClock::GetTimeMS();
							  if (recvFromStruct->bytesRead > 0)
							  {
								  ION_NET_ASSERT(recvFromStruct->systemAddress.GetPort());
								  recvFromStruct = rakPeer.OnRNS2Recv(recvFromStruct);
							  }
							  else
							  {
								  ion::Thread::SleepMs(0);
							  }
						  }
						  mFreePayload.Release(reinterpret_cast<RakNetSocket2::Payload*>(recvFromStruct));
					  }
				  }
			  }
		  }
		  // mFreePayload.Release(reinterpret_cast<RakNetSocket2::Payload*>(recvFromStruct));
	  });
	mReceiveThread.Start(32 * 1024, ion::NetworkReceivePriority);
}
#endif

bool StartThreads(NetSocket& socket, NetReception& reception, NetControl& control, const NetStartupParameters& parameters)
{
	socket.mReceiveThread.SetEntryPoint(
	  [&socket, &control, &reception]()
	  {
		  ion::NetSocketReceiveData* recvFromStruct = ion::NetControlLayer::AllocateReceiveBuffer(control);
		  while (socket.mIsReceiveThreadActive)
		  {
			  recvFromStruct->Socket() = &socket;
			  ion::SocketLayer::RecvFromBlocking(socket, *recvFromStruct);
			  ION_PROFILER_SCOPE(Network, "Socket Receive");
			  if (recvFromStruct->SocketBytesRead() > 0)
			  {
				  recvFromStruct->mHeader.mSocket.mInternalPacketType = NetInternalPacketType::DownstreamSegment;
				  ION_ASSERT(recvFromStruct->Address().IsAssigned() && recvFromStruct->Address().GetPort(), "Invalid source");
				  recvFromStruct = ion::NetReceptionLayer::Receive(reception, control, recvFromStruct);
			  }
			  else
			  {
				  ion::Thread::Sleep(1);
			  }
		  }
		  ion::NetControlLayer::DeallocateReceiveBuffer(control, recvFromStruct);
	  });
	socket.mIsReceiveThreadActive = true;
	if (!socket.mReceiveThread.Start(32 * 1024, parameters.mReceiveThreadPriority))
	{
		socket.mIsReceiveThreadActive = false;
		return false;
	}
#if !ION_NET_SIMULATOR
	if (parameters.mEnableSendThread)
#endif
	{
		if (!socket.StartSendThread(parameters.mSendThreadPriority))
		{
			StopThreads(socket);
			return false;
		}
	}
	return true;
}

void StopThreads(NetSocket& socket)
{
	if (socket.mSendThreadEnabled)
	{
		socket.StopSendThread();
	}
	if (socket.mIsReceiveThreadActive)
	{
		socket.mIsReceiveThreadActive = false;
		ION_ALIGN(alignof(ion::NetSocketSendParameters)) uint32_t zero[ion::NetSocketSendParametersHeaderSize + sizeof(uint32_t)] = {};

		ion::NetSocketSendParameters* bsp = reinterpret_cast<ion::NetSocketSendParameters*>(&zero);
		bsp->optional.mask = 0;
		bsp->length = sizeof(uint32_t);
		bsp->SetAddress(socket.mBoundAddress);
		int res = SendBlocking(socket, *bsp);
		ION_ASSERT(res > 0, "Unblocking send failed");
		ION_ASSERT(!socket.mIsReceiveThreadActive, "Socket thread still active");
		socket.mReceiveThread.Join();
	}
}
void SendTo(NetSocket& socketLayer, ion::NetCommand& command, const ion::NetSocketAddress& address)
{
	ION_ASSERT(command.mNumberOfBytesToSend <= ion::NetMaxUdpPayloadSize(), "Invalid payload");
	ion::NetSocketSendParameters* bsp = socketLayer.AllocateSend();
	bsp->length = SafeRangeCast<int32_t>(command.mNumberOfBytesToSend);
	memcpy(bsp->data, (char*)&command.mData, bsp->length);
	bsp->SetAddress(address);
	SendTo(socketLayer, bsp);  // Deallocate struct here
}

}  // namespace SocketLayer
}  // namespace ion
