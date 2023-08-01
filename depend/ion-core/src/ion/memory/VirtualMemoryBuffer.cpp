#include <ion/memory/VirtualMemoryBuffer.h>
#include <ion/memory/GlobalAllocator.h>
#include <ion/debug/MemoryTracker.h>

#include <ion/util/Math.h>

#if ION_PLATFORM_MICROSOFT
	#ifndef WIN32_LEAN_AND_MEAN
		#define WIN32_LEAN_AND_MEAN
	#endif
	#include <Windows.h>
#else
	#include <sys/mman.h>
	#ifdef __FreeBSD__
		#include <sys/sysctl.h>
		#define MAP_HUGETLB MAP_ALIGNED_SUPER
	#endif
	#ifndef MAP_UNINITIALIZED
		#define MAP_UNINITIALIZED 0
	#endif
#endif

namespace ion
{

namespace
{

void* OsAllocate(void* address, size_t size, bool commit)
{
	void* ptr;
	bool useHugePages = false;
#if ION_PLATFORM_MICROSOFT
	ptr = VirtualAlloc(address, size, (useHugePages ? MEM_LARGE_PAGES : 0) | (commit ? MEM_COMMIT : MEM_RESERVE), PAGE_READWRITE);

#else
	if (commit)
	{
		if (mprotect(address, size, PROT_READ | PROT_WRITE) != 0)
		{
			ION_ASSERT_FMT_IMMEDIATE(false, "mprotect failed");
			return 0;
		}
		ptr = address;
	}
	else
	{
	#if ION_PLATFORM_APPLE
		ptr = mmap(address, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNINITIALIZED,
				   (useHugePages ? VM_FLAGS_SUPERPAGE_SIZE_2MB : -1), 0);
	#elif defined(MAP_HUGETLB)
		ptr =
		  mmap(0, size, 0, (useHugePages ? MAP_HUGETLB : 0) | MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNINITIALIZED, -1, 0);
	#else
		ptr = mmap(address, size, 0, MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNINITIALIZED, -1, 0);
	#endif
		if ((ptr == MAP_FAILED) || !ptr)
		{
			ION_ASSERT_FMT_IMMEDIATE(false, "Failed to map virtual memory block");
			return 0;
		}
	}
#endif
	return ptr;
}
void OsFree(void* ptr)
{
#if ION_PLATFORM_MICROSOFT
	if (!VirtualFree(ptr, 0, MEM_RELEASE))
	{
		ION_ASSERT_FMT_IMMEDIATE(false, "failed unmap virtual memory");
	}
#else

	if (munmap(ptr, 1) != 0)
	{
		ION_ASSERT_FMT_IMMEDIATE(false, "failed unmap virtual memory");
	}
#endif
}
}  // namespace

VirtualMemoryBuffer::VirtualMemoryBuffer(size_t reservedBytes) : mReservedBytes(reservedBytes)
{
	memory_tracker::TrackStatic(uint32_t(mReservedBytes), ion::tag::External);
	mRootAddress = OsAllocate(0, mReservedBytes, false);
}

VirtualMemoryBuffer::~VirtualMemoryBuffer()
{
	if (mRootAddress)
	{
		OsFree(mRootAddress);
		memory_tracker::UntrackStatic(uint32_t(mReservedBytes), ion::tag::External);
	}
}

void* VirtualMemoryBuffer::Allocate(size_t len, size_t alignment)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
	if (mRootAddress)
	{
		void* ptr = ion::AlignAddress((char*)mRootAddress + mBytesUsed, alignment);
		mBytesUsed = size_t((char*)ptr - (char*)mRootAddress) + len + alignment;
		if (mBytesUsed <= mReservedBytes)
		{
			OsAllocate(mRootAddress, mBytesUsed, true);
			return ptr;
		}
	}

	//ION_LOG_FMT_IMMEDIATE("Out of virtual space %zu/%zu", mBytesUsed, mReservedBytes);
	GlobalAllocator<uint8_t> allocator;
	return allocator.AllocateRaw(len, 64);
}

void VirtualMemoryBuffer::Deallocate(void* ptr, size_t s)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
	if ((char*)ptr < (char*)mRootAddress || (char*)ptr > (char*)mRootAddress + mReservedBytes)
	{
		GlobalAllocator<uint8_t> allocator;
		allocator.DeallocateRaw(ptr, s, 64);
	}
}

void* VirtualMemoryBuffer::Reallocate(void*, size_t)
{
	ION_ASSERT(false, "TODO");
	return nullptr;
}

}  // namespace ion
