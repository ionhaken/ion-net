#pragma once

#include <ion/net/NetMemory.h>

#include <ion/concurrency/Thread.h>

namespace ion
{
class RakNetSocket2;

struct NetSocketDescriptor;
class JobScheduler;

/// Describes the local socket to use for NetBasePeer::Startup
struct ION_EXPORT NetSocketDescriptor
{
	NetSocketDescriptor();
	NetSocketDescriptor(unsigned short _port, const char* _hostAddress);

	unsigned short port;
	char hostAddress[32];
	short socketFamily;
	short socketType;
	short protocol;
};

struct NetStartupParameters
{
	NetStartupParameters();

	// Create NetStartupParameters from parameters as follows:
	// - Start as main authority server if all descriptors have port set and incoming connections are allowed.
	// - Enable send thread only if there are equal or more than 4 max connections.
	static NetStartupParameters Create(unsigned int maxConnections, const ion::NetSocketDescriptor* socketDescriptors,
									   unsigned socketDescriptorCount, unsigned int maxIncomingConnections);

	// As Create() but maxConnections equals maxIncomingConnections.
	static NetStartupParameters Create(unsigned int maxConnections, const ion::NetSocketDescriptor* socketDescriptors,
									   unsigned socketDescriptorCount);


	// Create NetStartupParameters from parameters for network peer as in Create(), but never allows main authority
	static NetStartupParameters CreatePeer(unsigned int maxConnections, const ion::NetSocketDescriptor* socketDescriptors, unsigned socketDescriptorCount);

	// Create NetStartupParameters from parameters for network client.
	static NetStartupParameters CreateClient(const ion::NetSocketDescriptor* socketDescriptors, unsigned socketDescriptorCount);

	// As Create()
	NetStartupParameters(unsigned int maxConnections, const ion::NetSocketDescriptor* socketDescriptors, unsigned socketDescriptorCount);

	ion::JobScheduler* mJobScheduler;
	unsigned int mMaxConnections = 0;
	unsigned int mMaxIncomingConnections = 0;
	const ion::NetSocketDescriptor* mNetSocketDescriptors = nullptr;
	unsigned mNetSocketDescriptorCount = 0;

	// Thread priorities
	ion::Thread::Priority mReceiveThreadPriority = ion::Thread::Priority::Highest;
	ion::Thread::Priority mSendThreadPriority = ion::Thread::Priority::Highest;
	ion::Thread::Priority mUpdateThreadPriority = ion::Thread::Priority::Highest;

	NetPeerUpdateMode mUpdateMode;

	// When enabled, peer is always authority in all connections. Behaviour is undefined if there are more than one main authority in a
	// mesh. Default value is disabled.
	bool mIsMainAuthority = false;

	// When enabled, data is sent to socket by a separate "Send Thread". This will prevent data processing to be blocked to socket, but
	// might add small (few microseconds) extra latency. The more connections you have, the more likely you should enable send thread, so
	// it's recommended to enable it only when your "max connections" is more than one.
	bool mEnableSendThread = true;
};

}  // namespace ion
