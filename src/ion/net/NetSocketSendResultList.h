#pragma once

#include <ion/net/NetSdk.h>
#include <ion/net/NetSocketAddress.h>

#include <ion/container/Algorithm.h>
#include <ion/container/Vector.h>

#include <ion/concurrency/Mutex.h>

namespace ion
{
class NetSocketSendResultList
{
public:
	void Prepare(const NetSocketAddress& socketAddress)
	{
		ion::AutoLock<ion::Mutex> lock(mMutex);
		ION_ASSERT(mResults.End() == ion::FindIf(mResults, [&](auto& result) { return result.address == socketAddress; }),
				   "Duplicate address");
		mResults.Add(SendResult{socketAddress, 0});
	}

	void Set(const ion::NetSocketAddress& socketAddress, int code)
	{
		ion::AutoLock<ion::Mutex> lock(mMutex);
		auto iter = ion::FindIf(mResults, [&](auto& result) { return result.address == socketAddress; });
		;
		if (iter != mResults.End())
		{
			iter->code = code;
		}
	}

	int Get(const NetSocketAddress& socketAddress)
	{
		int code = 0;
		ion::AutoLock<ion::Mutex> lock(mMutex);
		auto iter = ion::FindIf(mResults, [&](auto& result) { return result.address == socketAddress; });
		if (iter != mResults.End())
		{
			if (iter->code != 0)
			{
				code = iter->code;
				mResults.Erase(iter);
			}
		}
		return code;
	}

	void Clear(const NetSocketAddress& socketAddress)
	{
		ion::AutoLock<ion::Mutex> lock(mMutex);
		auto iter = ion::FindIf(mResults, [&](auto& result) { return result.address == socketAddress; });
		;
		if (iter != mResults.End())
		{
			mResults.Erase(iter);
		}
	}

private:
	struct SendResult
	{
		ion::NetSocketAddress address;
		int code;
	};
	ion::Mutex mMutex;
	ion::Vector<SendResult, NetAllocator<SendResult>> mResults;
};

}  // namespace ion
