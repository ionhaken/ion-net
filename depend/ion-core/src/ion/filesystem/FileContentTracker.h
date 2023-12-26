#pragma once

#include <atomic>
#include <ion/Base.h>

namespace ion
{

struct FileContentTracker
{
	ION_CLASS_NON_COPYABLE(FileContentTracker)

	FileContentTracker() {}
	FileContentTracker(FileContentTracker&& other) noexcept : mNumActiveRequests(UInt(other.mNumActiveRequests)) {}
	FileContentTracker& operator=(FileContentTracker&& other) noexcept
	{
		mNumActiveRequests = std::move(UInt(other.mNumActiveRequests));
		return *this;
	}

	std::atomic<UInt> mNumActiveRequests = 0;
};

}  // namespace ion
