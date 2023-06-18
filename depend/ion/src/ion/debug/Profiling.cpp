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

namespace ion
{
namespace profiling
{
struct TemporaryStringBuffer
{
	ion::Vector<ion::UniquePtr<ion::String>> mData;
};

const constexpr size_t MaxProfilingIds = 1024;

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
struct ProfilingData
{
	ProfilingData(Resource&) : gSchedulerCount(0)
	{
		std::fill(mStoredEnabledTags.Begin(), mStoredEnabledTags.End(), true);
		std::fill(mBufferOrder.Begin(), mBufferOrder.End(), uint8_t(255));
		mStoredEnabledTags[ion::profiling::tag::Job] = false;
		mStoredEnabledTags[ion::profiling::tag::Physics] = false;
		mStoredEnabledTags[ion::profiling::tag::Render] = false;
		mStoredEnabledTags[ion::profiling::tag::NodeScript] = false;
		mStoredEnabledTags[ion::profiling::tag::Memory] = false;
		mEvents.Reserve(MaxProfilingIds);

		// Profiling is not ready when memory allocation is registered, add it here explicitly.
		// Also id=0 is consider invalid tag
		mEvents.Add(ProfilingEvent{"Invalid profiling block", "", 0, ion::profiling::tag::Core});
		mEvents.Add(ProfilingEvent{"Memory alloc", "", 0, ion::profiling::tag::Memory});
		Unpause();
	}
	~ProfilingData()
	{
		ION_ASSERT_FMT_IMMEDIATE(gSchedulerCount == 0, "Cannot stop profiling when scheduler may have tracing tasks");
		gSerializerProfilerFile = nullptr;
		ion::tracing::Flush();
	}

	void OnBeginScheduling() { gSchedulerCount++; }

	void OnEndScheduling() { gSchedulerCount--; }

	const char* GetName(uint32_t id) const
	{
		// #TODO: This is not thread safe. Register() could resize the vector
		return mEvents[id].name.CStr();
	}

	const uint16_t GetTag(uint32_t id) const { return mEvents[id].tag; }

	bool IsEnabled(uint32_t tag) const { return mEnabledTags[tag]; }

	void Pause() { std::fill(mEnabledTags.Begin(), mEnabledTags.End(), false); }

	void Unpause() { mEnabledTags = mStoredEnabledTags; }

	uint32_t Register(uint16_t tag, const char* name, const char* file, uint32_t line)
	{
		ion::MemoryScope scope(ion::tag::Profiling);
		uint32_t id;
		ion::AutoLock<Mutex> lock(mMutex);
		id = ion::SafeRangeCast<uint32_t>(mEvents.Size());
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
	ion::MemoryScope scope(ion::tag::Profiling);
	Instance().data[index].Resize(ion::Thread::GetQueueIndex() != ion::Thread::NoQueueIndex &&
									  priority == uint8_t(ion::Thread::Priority::Normal)
									? ION_PROFILER_BUFFER_SIZE_PER_THREAD
									: (ION_PROFILER_BUFFER_SIZE_PER_THREAD / 16));
	Instance().mBufferOrder[index] = priority;
	return &Instance().data[index];
}

void Record(uint64_t CaptureLengthMs, bool saveFile)
{
	ion::MemoryScope scope(ion::tag::Profiling);
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
		ion::StackString<256> filename;
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
		output.Save(filename.CStr());
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
	uint32_t id = (gIsInitialized != 0 ? Instance().Register(tag, name, file, line) : (tag == ion::profiling::tag::Memory ? 1 : 0));
	ION_ASSERT(id, "Cannot register scope");
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

	const ion::Array<ArrayView<const char, uint32_t>, 9> tagView{ion::MakeArray<ArrayView<const char, uint32_t>, 9>(
	  [&](size_t i)
	  {
		  static const ion::Array<const char* const, 9> Tags = {"Generic", "Core",	 "Scheduler", "Job", "Tracing",
																"Network", "Render", "Physics",	  "Game"};
		  return ion::ArrayView<const char, uint32_t>(Tags[i], uint32_t(strlen(Tags[i])));
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
			if (sample.mDetailedInfo[0] == 0)
			{
				sampleJSON.AddMember("name", str);
			}
			else
			{
				ion::StackString<256> detailedStr;
				detailedStr.Format("%s (%s)", str.CStr(), &sample.mDetailedInfo[0]);
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
			switch (sample.type)
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
		bool operator<(const ProfilingTime& other) const { return mTotalTime < other.mTotalTime; }
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
						 ION_LOG_INFO("Profiler: avg: "
									  << (elem.total / elem.numSamples) * (1000.0 * 1000.0)
									  << "us\t\t\t min: " << elem.min * (1000.0 * 1000.0)
									  << "us\t\t\t max: " << elem.max * (1000.0 * 1000.0) << "us\t\t\t samples:" << elem.numSamples
									  << "\t\t\t" << ion::profiling::Instance().GetName(ion::SafeRangeCast<unsigned int>(ref.mIndex)));
						 ion::profiling::Instance().mSummary[ref.mIndex] = ion::profiling::ProfilingSummary();
					 }
				 });
}

#endif
