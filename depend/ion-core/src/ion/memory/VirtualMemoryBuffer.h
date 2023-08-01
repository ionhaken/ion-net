#pragma once
#include <ion/Base.h>
#include <ion/debug/AccessGuard.h>


namespace ion
{
class VirtualMemoryBuffer
{
public:
	VirtualMemoryBuffer(size_t reservedBytes);

	~VirtualMemoryBuffer();

	void* Allocate(size_t len, size_t alignment);
	void* Reallocate(void* ptr, size_t);
	void Deallocate(void* ptr, size_t);

private:
	size_t mReservedBytes;
	void* mRootAddress;
	size_t mBytesUsed = 0;
	ION_ACCESS_GUARD(mGuard);
};

}  // namespace ion
