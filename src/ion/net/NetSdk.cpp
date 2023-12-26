#include <ion/net/NetSecure.h>

#include <ion/debug/AccessGuard.h>

#include <ion/memory/MemoryScope.h>

#include <ion/string/String.h>
#include <libsodium/include/sodium.h>
#include <libsodium/include/sodium/crypto_pwhash_argon2id.h>

#if ION_PLATFORM_LINUX
	#include <fcntl.h>
	#include <unistd.h>
	#include <sys/ioctl.h>
	#include <linux/random.h>
#endif

#if (ION_ASSERTS_ENABLED == 1)
	#include <atomic>
#endif

#if ION_PLATFORM_MICROSOFT
	#include <winsock2.h>
	#include <ws2tcpip.h>
#endif

namespace ion
{
NetManager::NetManager(NetResource&) {}
NetManager::~NetManager() {}

int NetManager::mLoggingLevel = 2;

namespace net
{
STATIC_INSTANCE(NetManager, NetResource);
}
bool NetIsInitialized() { return net::gIsInitialized != 0; }

bool NetInit()
{
	ION_MEMORY_SCOPE(ion::tag::Network);
	ION_ACCESS_GUARD_WRITE_BLOCK(net::gGuard);

	if (0 != net::gRefCount++)
	{
		return true;
	}
	TracingInit();

	int netStartup = 0;
#if ION_PLATFORM_MICROSOFT
	WSADATA winsockInfo;
	netStartup = WSAStartup(MAKEWORD(2, 2), &winsockInfo);
	if (netStartup != 0)
	{
		ION_NET_LOG_ABNORMAL("WSA startup failed: " << ion::debug::GetLastErrorString());
	}
#endif

	if (netStartup == 0)
	{
		//
		// See https://libsodium.gitbook.io/doc/usage
		//
#if ION_PLATFORM_LINUX && defined(RNDGETENTCNT)
		int fd;
		int c;
		if ((fd = open("/dev/random", O_RDONLY)) != -1)
		{
			if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160)
			{
				fputs(
				  "This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
				  "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n"
				  "On virtualized Linux environments, also consider using virtio-rng.\n"
				  "The service will not start until enough entropy has been collected.\n",
				  stderr);
			}
			(void)close(fd);
		}
#endif
		int sodiumInit = sodium_init();
		ION_ASSERT(sodiumInit >= 0, "Sodium init failed");
		
		net::gInstance.Init(4 * 1024 * 1024);
		net::gIsInitialized = true;
		return true;
	}

	TracingDeinit();	
	net::gRefCount--;
	return false;
}

void NetDeinit()
{
	ION_ACCESS_GUARD_WRITE_BLOCK(net::gGuard);
	if (1 != net::gRefCount--)
	{
		return;
	}
	net::gIsInitialized = false;
	ION_MEMORY_SCOPE(ion::tag::Network);

	net::gInstance.Deinit();
	randombytes_close();

#ifdef _WIN32
	int ret = WSACleanup();
	if (ret != 0)
	{
		ION_NET_LOG_ABNORMAL("WSA cleanup failed: " << ion::debug::GetLastErrorString());
	}
#endif
	TracingDeinit();
}

}  // namespace ion
