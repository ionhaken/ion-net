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
#include <ion/debug/MemoryTracker.h>
#if ION_MEMORY_TRACKER == 1
	#include <ion/container/Algorithm.h>
	#include <ion/container/Array.h>
	#include <ion/container/UnorderedMap.h>
	#include <ion/string/String.h>
	#include <ion/container/ForEach.h>
	#include <ion/concurrency/Mutex.h>
	#include <ion/memory/DebugAllocator.h>
	#include <ion/memory/Memory.h>

	#include <atomic>
	#if ION_BUILD_DEBUG
		#include <cstring>	// memset
	#endif
	#include <ion/core/Engine.h>

namespace ion
{
namespace memory_tracker
{
static bool gEnableTracking = false;
static size_t FatalMemoryLeakLimitBytes = 0;
bool WaitUserOnLeak = false;

struct MemoryTracker
{
	static constexpr const char* LayerNames[] = {"TLSF", "Global", "Os"};
	struct TrackedLayer
	{
		ion::Array<std::atomic<int64_t>, tag::Count> memoryBlockCount;
		ion::Array<std::atomic<int64_t>, tag::Count> memoryCount;
		ion::Array<std::atomic<int64_t>, tag::Count> memoryPeak;
		ion::Array<std::atomic<uint64_t>, tag::Count> memoryCountDelta;
		ion::Array<std::atomic<uint64_t>, tag::Count> allocCountDelta;
	};
	ion::Array<TrackedLayer, 3> mTrackedLayers;

	#if ION_PLATFORM_MICROSOFT && 0	 // defined(_DEBUG)
	struct ExternalMallocEntry
	{
		char const* mFile;
		size_t mSize;
		unsigned int mLine;
		int mType;
		MemTag mTag;
	};

	ion::UnorderedMap<long, ExternalMallocEntry, Hasher<long>, ArenaAllocator<std::pair<long const, ExternalMallocEntry>>>
	  mExternalMallocLeaks;

	ion::Mutex mLeakMutex;
	#endif

	MemoryTracker() { Init(); }
	~MemoryTracker()
	{
	#if ION_MEMORY_TRACKER
		ION_LOG_IMMEDIATE("---Final memory stats---");
	#endif
		PrintStats(Layer::Invalid, true);
	}

	void Init()
	{
	#if ION_PLATFORM_MICROSOFT && 0	 // defined(_DEBUG)
		_CrtSetAllocHook(CrtMallocHook);
	#endif

		ion::ForEach(mTrackedLayers,
					 [&](auto& layer)
					 {
						 std::fill(layer.memoryBlockCount.Begin(), layer.memoryBlockCount.End(), 0);
						 std::fill(layer.memoryCount.Begin(), layer.memoryCount.End(), 0);
						 std::fill(layer.memoryPeak.Begin(), layer.memoryPeak.End(), 0);
						 std::fill(layer.memoryCountDelta.Begin(), layer.memoryCountDelta.End(), 0);
						 std::fill(layer.allocCountDelta.Begin(), layer.allocCountDelta.End(), 0);
					 });
	}

	void GetStats(MemoryStats* memStats)
	{
		memStats[ion::tag::Count].totalAllocs = 0;
		TrackedLayer& layer = mTrackedLayers[int(Layer::Global)];
		for (size_t i = 0; i < layer.memoryCount.Size(); ++i)
		{
			auto numAllocs = static_cast<uint64_t>(layer.allocCountDelta[i]);
			auto allocSize = static_cast<uint64_t>(layer.memoryCountDelta[i]);
			if (numAllocs > 0)
			{
				layer.allocCountDelta[i] -= numAllocs;
				layer.memoryCountDelta[i] -= allocSize;

				memStats[i].totalAllocs = allocSize;
				memStats[ion::tag::Count].totalAllocs += allocSize;
			}
		}
	}

	void PrintStats(Layer layer = Layer::Invalid, bool breakOnLeaks = false)
	{
		if (!gEnableTracking)
		{
			return;
		}
		bool detectedLeak = false;

	#if ION_PLATFORM_MICROSOFT && 0	 // defined(_DEBUG)
		constexpr size_t MallocLeakLimit = 16 * 1024;
		size_t leakSum = 0;
		ion::ForEach(mExternalMallocLeaks,
					 [&](auto& pair)
					 {
						 auto& elem = pair.second;
						 leakSum += elem.mSize;
					 });
		if (leakSum > MallocLeakLimit)
		{
			ion::ForEach(mExternalMallocLeaks,
						 [&](auto& pair)
						 {
							 auto& elem = pair.second;
							 ION_LOG_FMT_IMMEDIATE("Malloc leak: file:%s line:%u size:%zu type:%i tag:%s", elem.mFile, elem.mLine,
												   elem.mSize, elem.mType, ion::tag::Name(elem.mTag));
						 });
			detectedLeak = true;
		}
		ION_ASSERT_FMT_IMMEDIATE(leakSum <= MallocLeakLimit, "External systems have fatal memory leak");
	#endif

		for (int run = 0; run < 2; run++)
		{
			if (run == 1)
			{
				ION_LOG_IMMEDIATE("--- Memory stats ---");
			}
			for (size_t j = 0; j < mTrackedLayers.Size(); ++j)
			{
				if (layer != Layer::Invalid && size_t(layer) != j)
				{
					continue;
				}

				auto& trackedLayer = mTrackedLayers[j];

				for (size_t i = 0; i < trackedLayer.memoryCount.Size(); ++i)
				{
					auto numAllocs = static_cast<uint64_t>(trackedLayer.allocCountDelta[i]);
					auto allocSize = static_cast<uint64_t>(trackedLayer.memoryCountDelta[i]);
					if (numAllocs > 0)
					{
						trackedLayer.allocCountDelta[i] -= numAllocs;
						trackedLayer.memoryCountDelta[i] -= allocSize;
					}
					bool isLeaking = trackedLayer.memoryCount[i] > int64_t(FatalMemoryLeakLimitBytes) && i != ion::tag::IgnoreLeaks &&
									 i != ion::tag::Profiling;
					if (isLeaking && breakOnLeaks)
					{
						detectedLeak = true;
					}
					if (numAllocs > 0 || (breakOnLeaks && isLeaking))
					{
						if (run == 1)
						{
							// Note: IgnoreLeaks count can be negative as pre dynamic init gets reset after dynamic init is
							// complete
							ION_LOG_FMT_IMMEDIATE("Memory[%s/%s] %zu bytes allocated (%zi blocks; peak %f Mbytes)", LayerNames[j],
												  ion::tag::Name(ion::MemTag(i)), static_cast<size_t>(trackedLayer.memoryCount[i]) /*/ 1024*/,
												  size_t(trackedLayer.memoryBlockCount[i]),
												  float(trackedLayer.memoryPeak[i]) / (1024.0 * 1024.0));
							if (isLeaking)
							{
								ION_LOG_IMMEDIATE("^^^^^^^^^^^^^^^^^^^");
							}
							if (!WaitUserOnLeak)
							{
								ION_ASSERT_FMT_IMMEDIATE(!breakOnLeaks || !isLeaking, "Fatal memory leak");
							}
						}
					}
				}
			}
			if (!detectedLeak)
			{
				break;
			}
		}
		if (WaitUserOnLeak)
		{
			if (detectedLeak)
			{
				ION_LOG_IMMEDIATE("Waiting for user");
				volatile int i = 1;
				while (i == 1) {}
			}
		}
	}
};

static MemoryTracker* gTracker = nullptr;

namespace
{

void Track(Layer layerIndex, uint32_t size, ion::MemTag tag)
{
	if (gTracker == nullptr)
	{
		gTracker = (MemoryTracker*)malloc(sizeof(MemoryTracker));
		new (gTracker) MemoryTracker();
		gTracker->Init();
	}

	auto& layer = gTracker->mTrackedLayers[int(layerIndex)];
	layer.memoryBlockCount[tag]++;
	layer.memoryCount[tag] += size;
	if (layer.memoryCount[tag] > layer.memoryPeak[tag])
	{
		layer.memoryPeak[tag] = (int64_t)layer.memoryCount[tag];
	}
	layer.memoryCountDelta[tag] += size;
	layer.allocCountDelta[tag]++;
	
	/*if (layerIndex == Layer::Global && tag == ion::tag::Test && size == 16)
	{
		ION_LOG_FMT_IMMEDIATE("+%zu", size);
	}*/
}

void Untrack(Layer layerIndex, uint32_t size, ion::MemTag tag)
{
	auto& layer = gTracker->mTrackedLayers[int(layerIndex)];
	layer.memoryBlockCount[tag]--;
	layer.memoryCount[tag] -= size;
	/*if (layerIndex == Layer::Global && tag == ion::tag::Test && size == 16)
	{
		ION_LOG_FMT_IMMEDIATE("-%zu", size);
	}*/
}

void* OnAllocation(detail::MemHeader* header, uint32_t size)
{
	uint8_t* payload = reinterpret_cast<uint8_t*>(header) + sizeof(detail::MemHeader);

	#if ION_BUILD_DEBUG
	std::memset(payload, 0xCD, size);  // 0XCD = Clean Memory
	#endif

	// Note: Footer might not be aligned correctly, we need to handle it via memcpy.
	detail::MemFooter footer;
	memcpy(payload + size, &footer, sizeof(detail::MemFooter));

	return payload;
}

void OnDeallocation() {}
}  // namespace

void TrackStatic(uint32_t size, ion::MemTag tag) { Track(Layer::Native, size, tag); }
void UntrackStatic(uint32_t size, ion::MemTag tag) { Untrack(Layer::Native, size, tag); }

ion::MemTag SanitizeTag(ion::MemTag tag)
{
	if (Engine::IsDynamicInitExit())
	{
		tag = ion::tag::IgnoreLeaks;
	}
	else if (tag == ion::tag::Unset)
	{
		// ION_DBG_FMT("Tracking unset memory");
	}
	return tag;
}

void* OnAllocation(void* ptr, size_t size, ion::MemTag tag, Layer layer)
{
	if (ptr == nullptr)
	{
		if (layer == Layer::Native)
		{
			NotifyOutOfMemory();
		}
		return nullptr;
	}
	tag = SanitizeTag(tag);

	detail::MemHeader* header = ion::AssumeAligned<detail::MemHeader>(reinterpret_cast<detail::MemHeader*>(ptr));
	*header = detail::MemHeader(ion::SafeRangeCast<uint32_t>(size), tag);
	Track(layer, ion::SafeRangeCast<uint32_t>(size), tag);
	return OnAllocation(header, ion::SafeRangeCast<uint32_t>(size));
}

void* OnAlignedAllocation(void* ptr, size_t size, size_t alignment, ion::MemTag tag, Layer layer)
{
	if (ptr == nullptr)
	{
		if (layer == Layer::Native)
		{
			NotifyOutOfMemory();
		}
		return nullptr;
	}

	tag = SanitizeTag(tag);

	alignment = ion::Max(sizeof(detail::MemHeader), alignment);
	detail::MemHeader* header = ion::AssumeAligned<detail::MemHeader>(
	  reinterpret_cast<detail::MemHeader*>(reinterpret_cast<uint8_t*>(ptr) + alignment - sizeof(detail::MemHeader)));
	*header = detail::MemHeader(ion::SafeRangeCast<uint32_t>(size), alignment, tag);
	Track(layer, ion::SafeRangeCast<uint32_t>(size), tag);
	return OnAllocation(header, ion::SafeRangeCast<uint32_t>(size));
}

void* OnDeallocation(void* payload, Layer layer)
{
	uint32_t alignment;
	return OnAlignedDeallocation(payload, alignment, layer);
}

void* OnAlignedDeallocation(void* payload, uint32_t& outAlignment, Layer layer)
{
	if (payload)
	{
		uint32_t size;
		MemTag tag;
		{
			detail::MemHeader* header =
			  AssumeAligned(reinterpret_cast<detail::MemHeader*>(reinterpret_cast<uint8_t*>(payload) - sizeof(detail::MemHeader)));
			size = header->size;
			tag = header->tag;
			outAlignment = header->alignment;
			header->Clear();
		}
	#if ION_BUILD_DEBUG
		memset(payload, 0xDD, size);  // 0XDD = Dead Memory
	#endif

		// Note: Footer might not be aligned correctly, we need to handle it via memcpy.
		detail::MemFooter footer;
		void* footerPtr = reinterpret_cast<uint8_t*>(payload) + size;
		memcpy(&footer, footerPtr, sizeof(detail::MemFooter));
		footer.Clear();
		memcpy(footerPtr, &footer, sizeof(detail::MemFooter));

		OnDeallocation();

		Untrack(layer, size, tag);

		return reinterpret_cast<uint8_t*>(payload) - outAlignment;
	}
	return nullptr;
}

void Stats(MemoryStats* stats)
{
	if (stats == nullptr)
	{
		gTracker->PrintStats();
	}
	else
	{
		gTracker->GetStats(stats);
	}
}

void PrintStats(bool breakOnLeaks, Layer layer) { gTracker->PrintStats(layer, breakOnLeaks); }

void EnableWaitUserOnLeak() { WaitUserOnLeak = true; }

void SetFatalMemoryLeakLimit(size_t s) { FatalMemoryLeakLimitBytes = s; }

void EnableTracking() { gEnableTracking = true; }

	#if ION_PLATFORM_MICROSOFT && 0	 // defined(_DEBUG)
struct _CrtMemBlockHeader
{
	_CrtMemBlockHeader* _block_header_next;
	_CrtMemBlockHeader* _block_header_prev;
	char const* _file_name;
	int _line_number;

	int _block_use;
	size_t _data_size;

	long _request_number;
	unsigned char _gap[4];

	// Followed by:
	// unsigned char    _data[_data_size];
	// unsigned char    _another_gap[no_mans_land_size];
};
int CrtMallocHook([[maybe_unused]] int allocType, [[maybe_unused]] void* userData, [[maybe_unused]] size_t size,
				  [[maybe_unused]] int blockType, [[maybe_unused]] long requestNumber, [[maybe_unused]] const unsigned char* filename,
				  [[maybe_unused]] int lineNumber)
{
	if (ion::Engine::IsDynamicInitExit())
	{
		return 1;
	}
	if (size > 0)
	{
		if (ion::detail::GetMemoryTag() == ion::tag::IgnoreLeaks || ion::Engine::IsDynamicInitExit() ||
			ion::Thread::GetId() == ~static_cast<UInt>(0))
		{
			return 1;
		}
	}

	static bool isInHook = false;

	if (isInHook)
	{
		return 1;
	}
	isInHook = true;

	MemoryTracker::ExternalMallocEntry e;
	e.mFile = (char const*)filename;
	e.mLine = lineNumber;
	e.mType = allocType;
	e.mSize = size;
	e.mTag = ion::detail::GetMemoryTag();

	auto ClearLeak = [&userData]()
	{
		_CrtMemBlockHeader* const header = static_cast<_CrtMemBlockHeader*>(const_cast<void*>(userData)) - 1;
		auto iter = gTracker.mExternalMallocLeaks.Find(header->_request_number);
		if (iter != gTracker.mExternalMallocLeaks.End())
		{
			// Untrack(ion::SafeRangeCast<uint32_t>(header->_data_size), iter->second.mTag);
			gTracker.mExternalMallocLeaks.Erase(iter);
		}
	};

	AutoLock<Mutex> lock(gTracker.mLeakMutex);
	switch (allocType)
	{
	case _HOOK_ALLOC:
	{
		// Track(ion::SafeRangeCast<uint32_t>(size), e.mTag);
		gTracker.mExternalMallocLeaks.Insert(requestNumber, e);
		break;
	}
	case _HOOK_REALLOC:
	{
		ClearLeak();
		// Track(ion::SafeRangeCast<uint32_t>(size), e.mTag);
		gTracker.mExternalMallocLeaks.Insert(requestNumber, e);
		break;
	}
	case _HOOK_FREE:
	{
		ClearLeak();
		break;
	}
	default:
		ION_UNREACHABLE("Invalid alloc type");
	}
	isInHook = false;
	return 1;
}
	#endif

}  // namespace memory_tracker
}  // namespace ion

#else
namespace ion::memory_tracker
{
void Stats(MemoryStats*) {}
void PrintStats(bool, Layer) {}
void SetFatalMemoryLeakLimit(size_t) {}
void EnableWaitUserOnLeak() {}
void EnableTracking() {}
}  // namespace ion::memory_tracker
#endif
