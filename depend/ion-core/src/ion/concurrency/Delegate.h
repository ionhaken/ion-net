/*
 * Copyright 2023 Markus Haikonen, Ionhaken
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once
#include <ion/container/Algorithm.h>
#include <ion/container/Array.h>
#include <ion/container/Vector.h>

#include <ion/debug/AccessGuard.h>

#include <ion/concurrency/MPSCQueue.h>
#include <ion/concurrency/Runner.h>
#include <ion/concurrency/SCThreadSynchronizer.h>
#include <ion/concurrency/SPSCQueue.h>

#include <ion/Base.h>
#include <ion/core/Core.h>
#include <limits>

namespace ion
{
template <typename T, typename TItem>
class ION_ALIGN_CACHE_LINE CountedBuffer
{
public:
	CountedBuffer() : mWriteCounter(0) {}

	CountedBuffer& operator=(const CountedBuffer& other)
	{
		mImpl = other.mImpl;
		mWriteCounter = other.mWriteCounter.load();
		return *this;
	}

	CountedBuffer(const CountedBuffer& other)
	{
		mImpl = other.mImpl;
		mWriteCounter = other.mWriteCounter.load();
	}

	ION_FORCE_INLINE bool Dequeue(TItem& item) { return mImpl.Dequeue(item); }

	inline bool Enqueue(TItem&& item) { return mImpl.Enqueue(std::move(item)); }

	inline bool Enqueue(TItem& item) { return mImpl.Enqueue(item); }

	// Returns true only if wrote first item of buffer
	ION_FORCE_INLINE bool MarkWrite() { return ++mWriteCounter == 1; }

	void MarkReads(size_t& totalReads)
	{
		size_t writes = mWriteCounter;
		writes = ion::Min(totalReads, writes);
		mWriteCounter -= writes;
		totalReads -= writes;
	}

private:
	T mImpl;
	std::atomic<size_t> mWriteCounter;
};

template <typename T, size_t TSize = 256>
class MultiWriterBuffer
{
public:
	static constexpr size_t MaxItemsPerWriter = TSize;

	MultiWriterBuffer(size_t /*workerCount*/)
	{
#if 0
			mWriterBuffer.Resize(workerCount + 1 /* Main thread*/);
#endif
	}

	// keepOrder: If true, keeps items received from the same thread in order, but
	//            will spin lock forever if there is no buffer space.
	// Note: This basically requires that consumer is in separate thread
	ION_FORCE_INLINE bool Enqueue(T&& item) /*, bool keepOrder = true)*/
	{
#if 0
			auto index = ion::Thread::GetId();
			if (index < mWriterBuffer.Size())
			{
				while (keepOrder)
				{
					if (mWriterBuffer[index].Enqueue(std::move(item)))
					{
						return mWriterBuffer[index].MarkWrite();
					}
					std::this_thread::yield();
				}
			}
#endif
		mAuxBuffer.Enqueue(std::move(item));
		return mAuxBuffer.MarkWrite();
	}

	ION_FORCE_INLINE bool Dequeue(T& item)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mReadGuard);
#if 0
			auto numBuffers = mWriterBuffer.Size();
			for (size_t i = 0; i < numBuffers; i++)
			{
				if (mWriterBuffer[mReadIndex].Dequeue(item))
				{
					return true;
				}
				mReadIndex = (mReadIndex + 1) % numBuffers;
			}
#endif
		if (mAuxBuffer.Dequeue(item))
		{
			return true;
		}
		return false;
	}

	void MarkReads(size_t& totalReads)
	{
#if 0
			for (size_t i = 0; i < mWriterBuffer.Size(); i++)
			{
				mWriterBuffer[i].MarkReads(totalReads);
			}
#endif
		mAuxBuffer.MarkReads(totalReads);
	}

private:
	ION_ACCESS_GUARD(mReadGuard);
	CountedBuffer<MPSCQueue<T>, T> mAuxBuffer;
};

}  // namespace ion

namespace ion
{
template <typename T, size_t TBufferWidth = 256>
class Delegate
{
public:
	Delegate(size_t workerCount) : mBuffer(workerCount) {}

	using ItemList = ion::Array<T, TBufferWidth>;

	template <typename TFunc>
	ION_FORCE_INLINE bool Execute(ion::Thread::Priority priority, TFunc&& function)
	{
		mThreads.Add(ion::Runner(
		  [this, function]()
		  {
			  ItemList allItems;
			  size_t readCounter = 0;
			  size_t processedCount = 0;
			  for (;;)
			  {
				  bool continueReading;
				  do
				  {
					  Dequeue(allItems, processedCount);
					  for (size_t i = 0; i < processedCount; i++)
					  {
						  function(allItems[i]);
					  }
					  readCounter += processedCount;
					  continueReading = processedCount != 0;
					  processedCount = 0;
				  } while (continueReading);
				  mBuffer.MarkReads(readCounter);
				  if (readCounter == 0 && !mSynchronizer.TryWait())
				  {
					  break;
				  }
			  }
		  }));
		return mThreads.Back().Start(32 * 1024, priority);
	}

	ION_FORCE_INLINE void Dequeue(ItemList& items, size_t& processedCount)
	{
		while (processedCount < TBufferWidth && mBuffer.Dequeue(items[processedCount]))
		{
			processedCount++;
		}
	}

	ION_FORCE_INLINE bool Enqueue(T&& item)
	{
		// auto ret =
		mBuffer.Enqueue(std::move(item));
		mSynchronizer.Signal();
		return true;  // ret;
	}

	bool Cancel() 
	{
		if (mSynchronizer.IsActive())
		{
			mSynchronizer.Stop();
			return true;
		}
		return false;
	}

	void Shutdown()
	{
		if (mSynchronizer.IsActive())
		{
			mSynchronizer.Stop();
			WaitForThreads();
		}
	}

	void WaitForThreads()
	{
		for (size_t i = 0; i < mThreads.Size(); i++)
		{
			mThreads[i].Join();
		}
	}

	~Delegate()
	{
#if (ION_ASSERTS_ENABLED == 1)
		ION_ASSERT(!mSynchronizer.IsActive() || mThreads.Size() == 0, "Synchronizer still active");
		ItemList allItems;
		size_t processedCount = 0;
		Dequeue(allItems, processedCount);
		ION_ASSERT(processedCount == 0, "Buffered data left");
#endif
	}

private:


	ion::Vector<ion::Runner, ion::CoreAllocator<ion::Runner>> mThreads;
	ion::MultiWriterBuffer<T, TBufferWidth> mBuffer;
	ion::SCThreadSynchronizer mSynchronizer;
};
}  // namespace ion
