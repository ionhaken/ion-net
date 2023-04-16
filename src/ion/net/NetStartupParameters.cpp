#include <ion/net/NetSocketAddress.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/string/StringUtil.h>

namespace ion
{

NetSocketDescriptor::NetSocketDescriptor()
{
	port = 0;
	hostAddress[0] = 0;
	protocol = 0;
	socketFamily = AF_INET;
	socketType = SOCK_DGRAM;
}

NetSocketDescriptor::NetSocketDescriptor(unsigned short _port, const char* _hostAddress)
{
	port = _port;
	if (_hostAddress)
		StringCopy(hostAddress, 32, _hostAddress);
	else
		hostAddress[0] = 0;
	protocol = 0;
	socketFamily = AF_INET;
	socketType = SOCK_DGRAM;
}

NetStartupParameters::NetStartupParameters()
  : mUpdateMode(ion::core::gSharedScheduler ? NetPeerUpdateMode::Job : NetPeerUpdateMode::Worker),
	mJobScheduler(ion::core::gSharedScheduler)
{
}

NetStartupParameters::NetStartupParameters(unsigned int maxConnections, const ion::NetSocketDescriptor* socketDescriptors,
										   unsigned socketDescriptorCount)
  : mUpdateMode(ion::core::gSharedScheduler ? NetPeerUpdateMode::Job : NetPeerUpdateMode::Worker),
	mJobScheduler(ion::core::gSharedScheduler)
{
	*this = Create(maxConnections, socketDescriptors, socketDescriptorCount);
}

NetStartupParameters NetStartupParameters::Create(unsigned int maxConnections, const ion::NetSocketDescriptor* socketDescriptors,
												  unsigned socketDescriptorCount, unsigned int maxIncomingConnections)
{
	ION_ASSERT(maxIncomingConnections <= maxConnections, "Incoming connections cannot peer more than max connections");
	NetStartupParameters params;
	params.mMaxConnections = maxConnections;
	params.mMaxIncomingConnections = maxIncomingConnections;
	params.mNetSocketDescriptors = socketDescriptors;
	params.mNetSocketDescriptorCount = socketDescriptorCount;

	bool hasPortSetForAllDescriptors = true;
	for (unsigned i = 0; i < socketDescriptorCount; ++i)
	{
		if (socketDescriptors[i].port == 0)
		{
			hasPortSetForAllDescriptors = false;
			break;
		}
	}
	params.mIsMainAuthority = hasPortSetForAllDescriptors && maxIncomingConnections > 0;

	params.mEnableSendThread = maxConnections >= 4;
	return params;
}

NetStartupParameters NetStartupParameters::Create(unsigned int maxConnections, const ion::NetSocketDescriptor* socketDescriptors,
												  unsigned socketDescriptorCount)
{
	return NetStartupParameters::Create(maxConnections, socketDescriptors, socketDescriptorCount, maxConnections);
}

NetStartupParameters NetStartupParameters::CreatePeer(unsigned int maxConnections, const ion::NetSocketDescriptor* socketDescriptors,
													  unsigned socketDescriptorCount)
{
	auto pars = NetStartupParameters::Create(maxConnections, socketDescriptors, socketDescriptorCount, maxConnections);
	pars.mIsMainAuthority = false;
	return pars;
}

NetStartupParameters NetStartupParameters::CreateClient(const ion::NetSocketDescriptor* socketDescriptors, unsigned socketDescriptorCount)
{
	return NetStartupParameters::Create(1, socketDescriptors, socketDescriptorCount, 0);
}

}  // namespace ion
