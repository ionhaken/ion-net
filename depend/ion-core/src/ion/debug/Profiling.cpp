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
#include <ion/debug/Profiling.h>
#if ION_PROFILER_BUFFER_SIZE_PER_THREAD > 0
	#include <ion/core/Core.h>

	#include <ion/json/JSONSerialization.h>
	#include <ion/core/StaticInstance.h>
	#include <ion/memory/UniquePtr.h>
	#include <ion/container/ForEach.h>
	#include <ion/container/Sort.h>
	#include <ion/string/String.h>
	#include <ion/memory/MemoryScope.h>
	#include <ion/jobs/ThreadPool.h>
	#include <ion/byte/ByteBuffer.h>
	#include <ion/tweakables/Tweakables.h>
	#include <ion/container/Vector.h>

	#include <ion/util/Bits.h>

namespace ion
{
namespace profiling
{
struct TemporaryStringBuffer
{
	ion::Vector<ion::UniquePtr<ion::String>> mData;
};

constexpr size_t MaxProfilingIds = 2048;

struct ProfilingSummary
{
	double min = 0;
	double max = 0;
	double total = 0;
	size_t numSamples = 0;
};

	#if ION_PLATFORM_MICROSOFT
constexpr ion::UInt MaxBuffers = 256 * ion::MaxThreads;
	#else
constexpr ion::UInt MaxBuffers = 4 * ion::MaxThreads;
	#endif
static_assert(MaxBuffers >= 2 * MaxThreads, "Not enough profiling buffers for thread pool");
using Resource = int;

TWEAKABLE_BOOL("profiler.scheduler", ProfilerEnableScheduler, true);
TWEAKABLE_BOOL("profiler.job", ProfilerEnableJob, false);
TWEAKABLE_BOOL("profiler.render", ProfilerEnableRender, false);
TWEAKABLE_BOOL("profiler.physics", ProfilerEnablePhysics, false);
TWEAKABLE_BOOL("profiler.nodescript", ProfilerEnableNodeScript, false);
TWEAKABLE_BOOL("profiler.memory", ProfilerEnableMemory, false);

TWEAKABLE_BOOL("profiler.all", ProfilerEnableAll, false);

// Profiling is not ready when memory allocation is registered, add it here explicitly.
constexpr const char* PreInitEventStrings[] = {"Invalid", "Memory alloc", "Memory free", "Memory aligned free", "Memory aligned alloc"};
constexpr uint16_t PreInitTags[] = {ion::profiling::tag::Core, ion::profiling::tag::Memory, ion::profiling::tag::Memory,
									ion::profiling::tag::Memory, ion::profiling::tag::Memory};

uint32_t RegisterPreInit(const char* name)
{
	for (unsigned int i = 0; i < sizeof(PreInitEventStrings) / sizeof(const char*); ++i)
	{
		if (ion::StringCompare(name, PreInitEventStrings[i]) == 0)
		{
			return i;
		}
	}
	ION_ASSERT_FMT_IMMEDIATE(false, "Invalid pre init string: %s", name);
	return 0;
}

struct ProfilingData
{
	ProfilingData(Resource&) : gSchedulerCount(0)
	{
		std::fill(mEnabledTags.Begin(), mEnabledTags.End(), false);
		std::fill(mStoredEnabledTags.Begin(), mStoredEnabledTags.End(), true);
		std::fill(mBufferOrder.Begin(), mBufferOrder.End(), uint8_t(255));

		mEvents.Reserve(MaxProfilingIds);

		for (unsigned int i = 0; i < sizeof(PreInitEventStrings) / sizeof(const char*); ++i)
		{
			mEvents.Add(ProfilingEvent{PreInitEventStrings[i], "", i, PreInitTags[i]});
		}
		Unpause();
	}
	~ProfilingData()
	{
		ION_ASSERT_FMT_IMMEDIATE(gSchedulerCount == 0, "Cannot stop profiling when scheduler may have tracing tasks");
		gSerializerProfilerFile = nullptr;
		ion::tracing::Flush();
	}

	void OnBeginScheduling()
	{
		gSchedulerCount++;

		auto SetTagState = [&](uint16_t tag, bool isSet) -> bool
		{
			if (TWEAKABLE_VALUE(ProfilerEnableAll))
			{
				isSet = true;
			}
			if (mStoredEnabledTags[tag] != isSet)
			{
				mStoredEnabledTags[tag] = isSet;
				return true;
			}
			return false;
		};

		bool changed = false;
		changed |= SetTagState(ion::profiling::tag::Scheduler, TWEAKABLE_VALUE(ProfilerEnableScheduler));
		changed |= SetTagState(ion::profiling::tag::Job, TWEAKABLE_VALUE(ProfilerEnableJob));
		changed |= SetTagState(ion::profiling::tag::Render, TWEAKABLE_VALUE(ProfilerEnableRender));
		changed |= SetTagState(ion::profiling::tag::Physics, TWEAKABLE_VALUE(ProfilerEnablePhysics));
		changed |= SetTagState(ion::profiling::tag::NodeScript, TWEAKABLE_VALUE(ProfilerEnableNodeScript));
		changed |= SetTagState(ion::profiling::tag::Memory, TWEAKABLE_VALUE(ProfilerEnableMemory));
		if (changed)
		{
			mEnabledTags = mStoredEnabledTags;
		}
	}

	void OnEndScheduling() { gSchedulerCount--; }

	const char* GetName(uint32_t id) const
	{
		return mEvents[id].name.CStr();
	}

	const uint16_t GetTag(uint32_t id) const { return mEvents[id].tag; }

	bool IsEnabled(uint32_t tag) const { return mEnabledTags[tag]; }

	void Pause() { std::fill(mEnabledTags.Begin(), mEnabledTags.End(), false); }

	void Unpause() { mEnabledTags = mStoredEnabledTags; }

	uint32_t Register(uint16_t tag, const char* name, const char* file, uint32_t line)
	{
		ION_MEMORY_SCOPE(ion::tag::Profiling);
		uint32_t id;
		ion::AutoLock<Mutex> lock(mMutex);
		id = ion::SafeRangeCast<uint32_t>(mEvents.Size());
		// If we need to resize mEvents, we will violate GetName() thread safety.
		ION_ASSERT_FMT_IMMEDIATE(id < MaxProfilingIds, "Out of events capacity");
		mEvents.Add({name, file, line, tag});
		return id;
	}

	ion::Array<ion::ProfilingBuffer, MaxBuffers> data;
	std::atomic<UInt> gSchedulerCount;
	ion::Mutex mMutex;

	// Use debug allocator: otherwise profiler tags try to use Ion memory allocation too early.
	template <typename T>
	using Allocator = DebugAllocator<T>;

	struct ProfilingEvent
	{
		const ion::BasicString<Allocator<char>> name;
		const ion::BasicString<Allocator<char>> file;
		uint32_t line;
		uint16_t tag;
	};

	ion::Vector<ProfilingEvent, Allocator<ProfilingEvent>> mEvents;
	ion::Array<ProfilingSummary, MaxProfilingIds> mSummary;
	ion::Array<bool, 256> mEnabledTags;		   // Active profiling tags, disabled when paused
	ion::Array<bool, 256> mStoredEnabledTags;  // Selected profiling tags
	ion::UniquePtr<ByteBuffer<>> gSerializerProfilerFile;
	ion::Array<uint8_t, MaxBuffers> mBufferOrder;
};

STATIC_INSTANCE(ProfilingData, Resource);

namespace detail
{
void UpdateSummary(uint32_t id, const SystemTimePoint& end, const SystemTimePoint& start)
{
	double deltaS = SystemTimeDelta(end, start).Seconds();
	if (Instance().mSummary[id].numSamples == 0)
	{
		Instance().mSummary[id].min = deltaS;
		Instance().mSummary[id].max = deltaS;
	}
	else
	{
		Instance().mSummary[id].min = ion::Min(Instance().mSummary[id].min, deltaS);
		Instance().mSummary[id].max = ion::Max(Instance().mSummary[id].max, deltaS);
	}
	Instance().mSummary[id].numSamples++;
	Instance().mSummary[id].total += deltaS;
}
}  // namespace detail

void OnBeginScheduling() { Instance().OnBeginScheduling(); }

void OnEndScheduling() { Instance().OnEndScheduling(); }

ion::ProfilingBuffer* Buffer(size_t index, uint8_t priority)
{
	// #TODO: Replace big buffers with paged buffer.
	if (index >= Instance().data.Size()) 
	{
		ION_CHECK_FAILED("Out of profiling buffers");
		abort();
	}
	ION_MEMORY_SCOPE(ion::tag::Profiling);
	Instance().data[index].Resize(ion::Thread::GetQueueIndex() != ion::Thread::NoQueueIndex &&
									  priority == uint8_t(ion::Thread::Priority::Normal)
									? ION_PROFILER_BUFFER_SIZE_PER_THREAD
									: (ION_PROFILER_BUFFER_SIZE_PER_THREAD / 16));
	Instance().mBufferOrder[index] = priority == uint8_t(ion::Thread::Priority::Highest) ? 0 : priority;
	return &Instance().data[index];
}

void Record(uint64_t CaptureLengthMs, bool saveFile)
{
	ION_MEMORY_SCOPE(ion::tag::Profiling);
	Instance().Pause();
	ION_LOG_INFO("Saving profiling data.");
	TemporaryStringBuffer stringBuffer;
	ion::SystemTimePoint now(ion::SystemTimePoint::Current());
	JSONDocument output;
	{
		JSONArrayWriter samplesJSON(output, "traceEvents");

		struct ThreadInfo
		{
			UInt index;
			UInt priority;
			bool operator<(const ThreadInfo& other) const
			{
				if (priority != other.priority)
				{
					return priority > other.priority;
				}
				if (other.index == 0)
				{
					return false;
				}
				if (index == 0)
				{
					return true;
				}
				return index < other.index;
			}
		};

		ion::Vector<ThreadInfo> sortData;
		for (UInt i = 0; i < MaxBuffers; i++)
		{
			if (Instance().mBufferOrder[i] != 255)
			{
				sortData.Add({i, Instance().mBufferOrder[i]});
			}
		}

		ion::Sort(sortData.Begin(), sortData.End());

		ion::UInt index = 0;
		ion::ForEach(sortData,
					 [&](ThreadInfo& info) -> void
					 {
						 Instance().data[info.index].Save(stringBuffer, samplesJSON, now, CaptureLengthMs, index);
						 index++;
					 });

		output.Set("displayTimeUnit", "ms");
	}

	if (saveFile)
	{
		static size_t indexCounter = 0;
		ion::StackStringFormatter<256> filename;
		auto exeName = ion::core::gInstance.Data().ExecutableName();
		if (!exeName.IsEmpty())
		{
			ion::String outname = exeName;
			ion::Vector<ion::String> splits;
			outname.Tokenize(splits, "\\", true);
			outname = splits.Back();
			splits.Clear();
			outname.Tokenize(splits, "/", true);
			outname = splits.Back();
			filename.Format("%s_%zu_profiling.json", outname.CStr(), indexCounter);
		}
		else
		{
			filename.Format("app_%zu_profiling.json", indexCounter);
		}
		ION_LOG_INFO_FMT("Writing profiling data to %s.", filename.CStr());
		indexCounter++;
		output.Save(filename);
	}
	else
	{
		Instance().gSerializerProfilerFile = ion::MakeUnique<ByteBuffer<>>();
		output.Save(*Instance().gSerializerProfilerFile);
	}
	ION_LOG_INFO("Profiling done");
	Instance().Unpause();
}

uint32_t Register(uint16_t tag, const char* name, const char* file, uint32_t line)
{
	uint32_t id = (gIsInitialized != 0 ? Instance().Register(tag, name, file, line) : RegisterPreInit(name));
	ION_ASSERT_FMT_IMMEDIATE(id, "Cannot register scope for %s", name);
	return id;
}

bool IsEnabled(uint32_t tag)
{
	// #TODO: Move profiling from thread TLS to here...
	return ion::Thread::IsProfilingEnabled() && Instance().IsEnabled(tag);
}

ion::UniquePtr<ion::ByteBuffer<>> SerializedRecord()
{
	ion::UniquePtr<ion::ByteBuffer<>> out;
	std::swap(out, Instance().gSerializerProfilerFile);
	return out;
}

}  // namespace profiling

void ProfilingInit()
{
	ION_ACCESS_GUARD_WRITE_BLOCK(profiling::gGuard);
	if (1 == profiling::gIsInitialized)
	{
		return;
	}
	profiling::gInstance.Init();
	profiling::gIsInitialized = 1;
}
void ProfilingDeinit()
{
	ION_ACCESS_GUARD_WRITE_BLOCK(profiling::gGuard);
	if (1 != profiling::gIsInitialized)
	{
		return;
	}
	profiling::gInstance.Deinit();
	profiling::gIsInitialized = 0;
}

}  // namespace ion

ion::ProfilingBuffer::ProfilingBuffer()
{
	mSamples.Resize(1);
	mDetailInfo.Resize(1);
}

void ion::ProfilingBuffer::Resize(size_t maxSamples)
{
	mSamples.Resize(maxSamples);
	#if !ION_PLATFORM_ANDROID
	mDetailInfo.Resize(SafeRangeCast<uint16_t>(uint64_t(1) << (63 - ion::CountLeadingZeroes<uint64_t>(maxSamples) - 2)));
	#endif
}

size_t ion::ProfilingBuffer::Add(const Sample& sample)
{
	size_t nextSamplePos = ion::Mod2(mSamplePos++, mSamples.Size());
	mSamples[nextSamplePos] = sample;
	return nextSamplePos;
}

void ion::ProfilingBuffer::Save(profiling::TemporaryStringBuffer& stringBuffer, ion::JSONArrayWriter& tracesArray, ion::SystemTimePoint now,
								uint64_t lenMs, UInt tid)
{
	// Find capture start and end
	if (mSamples.Size() <= 4)
	{
		return;
	}

	size_t systemTimeFrequency = now.TimeFrequency();
	uint64_t nanoSecondScale = 1000u * 1000u * 1000u;
	ION_ASSERT(systemTimeFrequency < uint64_t(-1) / (lenMs * 10),
			   "uint64_t is too small type for capturing " << lenMs << "ms using system frequency : " << systemTimeFrequency);
	auto nowMs = now.MillisecondsSinceStart();

	uint64_t startMs = nowMs > lenMs ? nowMs - lenMs : 0;
	auto startNs = ion::timing::detail::ScaleTime<uint64_t>(startMs, 1000, nanoSecondScale);

	size_t endPos = mSamplePos % mSamples.Size();
	size_t pos = (endPos - 2) % mSamples.Size();

	if (mSamples[pos].type == Event::None)
	{
		return;
	}
	for (size_t i = 0; i < mSamples.Size() - 3; i++)
	{
		auto nextPos = (pos - 1);
		if (nextPos == SIZE_MAX)
		{
			nextPos = mSamples.Size() - 1;
		}
		const Sample& sample = mSamples[nextPos];
		if (sample.type == Event::None)
		{
			break;
		}
		auto timestampMs = sample.mTimePoint.MillisecondsSinceStart();
		int64_t deltaMs = static_cast<int64_t>(timestampMs - startMs);
		if (deltaMs < 0)
		{
			break;
		}
		pos = nextPos;
	}

	constexpr size_t NumTags = sizeof(ion::profiling::tag::TagStrings) / sizeof(const char*);
	constexpr ion::Array<ArrayView<const char, uint32_t>, NumTags> tagView{ion::MakeArray<ArrayView<const char, uint32_t>, NumTags>(
	  [&](auto i)
	  {
		  return ion::ArrayView<const char, uint32_t>(ion::profiling::tag::TagStrings[i],
													  uint32_t(ion::ConstexprStringLength(ion::profiling::tag::TagStrings[i])));
	  })};

	// Write samples
	const int pid = 0;
	double prevTime = 0.0;

	while (pos != endPos)
	{
		const Sample& sample = mSamples[pos];
		uint64_t timestampMs = sample.mTimePoint.MillisecondsSinceStart();
		int64_t deltaMs = static_cast<int64_t>(timestampMs - startMs);
		if (deltaMs <= static_cast<int64_t>(lenMs) && deltaMs >= 0)
		{
			JSONStructWriter sampleJSON(tracesArray);
			const ion::String& str = ion::profiling::Instance().GetName(sample.id);
			if (!(uint8_t(sample.type) & (1 << 7)))
			{
				sampleJSON.AddMember("name", str);
			}
			else
			{
				ion::StackString<256> detailedStr;
				if (mDetailInfo[sample.mDetailId].mSampleIndex != pos)
				{
					detailedStr.Format("%s (?)", str.CStr());
				}
				else
				{
					detailedStr.Format("%s (%s)", str.CStr(), &mDetailInfo[sample.mDetailId].mText);
				}
				stringBuffer.mData.Add(ion::MakeUnique<ion::String>(detailedStr));
				sampleJSON.AddMember("name", *stringBuffer.mData.Back().get());
			}
			auto& tag = tagView[ion::Min(uint16_t(tagView.Size() - 1), ion::profiling::Instance().GetTag(sample.id))];

			sampleJSON.AddMember("cat", tag);
			sampleJSON.AddMember("pid", pid);
			sampleJSON.AddMember("tid", tid);

			// Calculate nanosecond fraction separately to prevent nanosecond time overflow error.
			uint64_t timestampNs = sample.mTimePoint.NanosecondsSinceStart();
			int64_t deltaNs = static_cast<int64_t>(timestampNs - startNs);
			int64_t deltaNsFraction = std::abs(deltaNs) % (1000 * 1000);
			if (deltaNs < 0)
			{
				deltaNsFraction = 1000 * 1000 - deltaNsFraction;
			}

			double deltaUs = static_cast<double>(deltaMs) * 1000.0 + static_cast<double>(deltaNsFraction) / 1000.0;
			if (deltaUs < prevTime)
			{
				continue;
			}
			ION_ASSERT(deltaUs >= prevTime,
					   "Invalid time data; timestamp="
						 << sample.mTimePoint.SecondsSinceStart() << ";timeStampMs=" << sample.mTimePoint.MillisecondsSinceStart()
						 << ";startMs=" << startMs << ";invalid timestamp;deltaUs=" << deltaUs << ";prevDeltaUs=" << prevTime
						 << ";deltaMs=" << deltaMs << ";deltaNs=" << deltaNs << ";deltaNsFraction=" << deltaNsFraction);
			prevTime = deltaUs;

			sampleJSON.AddMember("ts", deltaUs);
			switch (Event(uint8_t(sample.type) & 0x7F))
			{
			case Event::Begin:
				sampleJSON.AddMember("ph", "B");
				break;
			case Event::End:
				sampleJSON.AddMember("ph", "E");
				break;
			case Event::InstantGlobal:
				sampleJSON.AddMember("ph", "i");
				sampleJSON.AddMember("s", "g");
				break;
			case Event::InstantProcess:
				sampleJSON.AddMember("ph", "i");
				sampleJSON.AddMember("s", "p");
				break;
			case Event::InstantThread:
				sampleJSON.AddMember("ph", "i");
				break;
			default:
				ION_ASSERT(false, "Invalid profiling type");
				break;
			}
		}
		pos = (pos + 1) % mSamples.Size();
	}

	// Print totals - Sort using total time.
	struct ProfilingTime
	{
		double mTotalTime;
		size_t mIndex;
		bool operator<(const ProfilingTime& other) const { return mTotalTime > other.mTotalTime; }
	};
	ion::Vector<ProfilingTime> totals;
	totals.Reserve(ion::profiling::Instance().mSummary.Size());
	ion::ForEachIndex(ion::profiling::Instance().mSummary,
					  [&](size_t index, ion::profiling::ProfilingSummary& elem) {
						  totals.Add({elem.total, index});
					  });
	ion::Sort(totals.Begin(), totals.End());
	ion::ForEach(totals,
				 [&](ProfilingTime& ref)
				 {
					 ion::profiling::ProfilingSummary elem = ion::profiling::Instance().mSummary[ref.mIndex];
					 if (elem.numSamples > 0)
					 {
						 ION_LOG_INFO("Profiler: total: "
									  << elem.total * (1000.0) << "ms\t\t\t avg: " << (elem.total / elem.numSamples) * (1000.0 * 1000.0)
									  << "us\t\t\t min: " << elem.min * (1000.0 * 1000.0)
									  << "us\t\t\t max: " << elem.max * (1000.0 * 1000.0) << "us\t\t\t samples:" << elem.numSamples
									  << "\t\t\t" << ion::profiling::Instance().GetName(ion::SafeRangeCast<unsigned int>(ref.mIndex)));
						 ion::profiling::Instance().mSummary[ref.mIndex] = ion::profiling::ProfilingSummary();
					 }
				 });
}

#endif
