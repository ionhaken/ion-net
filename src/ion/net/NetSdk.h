#pragma once

#include <ion/net/NetConfig.h>

#include <ion/memory/DomainAllocator.h>
#include <ion/memory/DomainPtr.h>
#include <ion/memory/TSMultiPoolResource.h>

#include <ion/core/StaticInstance.h>
namespace ion
{

using NetResource = TSMultiPoolResource<VirtualMemoryBuffer, ion::tag::Network>;
// TSMultiPoolResource<1024 * 1024, ion::tag::Core>;
class NetManager
{
public:
	NetManager(NetResource&);
	~NetManager();

private:
};

bool NetInit();
void NetDeinit();
bool NetIsInitialized();

namespace net
{
STATIC_INSTANCE_PUBLIC(NetManager, NetResource);
}

class NetResourceProxy
{
public:
#if ION_CONFIG_MEMORY_RESOURCES == 1
	template <typename T>
	[[nodiscard]] static inline T* AllocateRaw(size_t n, size_t alignment = alignof(T))
	{
		return reinterpret_cast<T*>(ion::net::gInstance.Source().Allocate(n, alignment));
	}

	template <typename T>
	static void inline DeallocateRaw(T* p, size_t n)
	{
		ion::net::gInstance.Source().Deallocate(p, n);
	}

	template <typename T, size_t Alignment = alignof(T)>
	[[nodiscard]] static inline T* allocate(size_t n)
	{
		return AssumeAligned<T, Alignment>(AllocateRaw<T>(n * sizeof(T), Alignment));
	}

	template <typename T, size_t Alignment = alignof(T)>
	static void inline deallocate(T* p, size_t n)
	{
		DeallocateRaw<T>(p, sizeof(T) * n);
	}
#endif
};

template <typename T>
using NetAllocator = DomainAllocator<T, NetResourceProxy>;

template <typename T>
using NetPtr = Ptr<T, NetAllocator<T>>;

template <typename T, typename... Args>
inline NetPtr<T> MakeNetPtr(Args&&... args)
{
	return MakeDomainPtr<T, NetAllocator<T>>(std::forward<Args>(args)...);
}

template <typename T>
inline void DeleteNetPtr(ion::NetPtr<T>& ptr)
{
	DeleteDomainPtr<T, NetAllocator<T>>(ptr);
}

}  // namespace ion
