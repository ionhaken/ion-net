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
#include <ion/Base.h>

#if ION_PROFILER_BUFFER_SIZE_PER_THREAD > 0
	#include <ion/concurrency/Thread.h>
	#include <ion/container/Vector.h>
	#include <ion/time/CoreTime.h>
	#include <ion/time/Clock.h>
	#include <ion/memory/UniquePtr.h>
	#include <ion/byte/ByteBuffer.h>
	#include <ion/memory/DebugAllocator.h>
	#include <atomic>

namespace ion
{
class JSONArrayWriter;

namespace profiling
{
struct TemporaryStringBuffer;
}

class ProfilingBuffer
{
public:
	enum class Event : uint16_t
	{
		None,
		Begin,
		End,
		Complete,
		InstantGlobal,
		InstantThread,
		InstantProcess,
		Counter,
		AsyncStart,
		AsyncFinish,
		Event
	};

	class Sample
	{
		using Category = uint16_t;
		static const size_t MetaLength = sizeof(ion::SystemTimeUnit) + sizeof(Category) + sizeof(Event);
		static_assert(MetaLength < ION_CONFIG_CACHE_LINE_SIZE / 4, "Too long meta");

	public:
		Sample() : mTimePoint(SystemTimePoint::Current()) {}

		Sample(const SystemTimePoint& t, uint32_t tag, Event eventType, uint32_t eventId)
		  : mTimePoint(t), id(eventId), cat(ion::SafeRangeCast<Category>(tag)), type(eventType)
		{
			mDetailedInfo[0] = 0;
		}

		template <typename Detail>
		Sample(const SystemTimePoint& t, uint32_t tag, Event eventType, uint32_t eventId, const Detail& detail)
		  : mTimePoint(t), id(eventId), cat(ion::SafeRangeCast<Category>(tag)), type(eventType)
		{
			StringWriter writer(mDetailedInfo, 12);
			serialization::Serialize(detail, writer);
		}

		SystemTimePoint mTimePoint;
		uint32_t id;
		Category cat;
		Event type = Event::None;
		char mDetailedInfo[12];
	};
	static_assert(sizeof(Sample) == ION_CONFIG_CACHE_LINE_SIZE / 2, "Sample not cache efficient");

	ProfilingBuffer() {}

	void Resize(size_t maxSamples) { mSamples.Resize(maxSamples); }

	void Save(profiling::TemporaryStringBuffer& stringBuffer, ion::JSONArrayWriter& tracesArray, ion::SystemTimePoint now, uint64_t lenNs,
			  UInt tid);

	void InstantGlobal(uint32_t id) { Add(Sample(SystemTimePoint::Current(), 0 /* tag*/, Event::InstantGlobal, id)); }

	void InstantProcess(uint32_t id) { Add(Sample(SystemTimePoint::Current(), 0 /* tag*/, Event::InstantProcess, id)); }

	void Instant(uint32_t id) { Add(Sample(SystemTimePoint::Current(), 0, Event::InstantThread, id)); }

	void Begin(const SystemTimePoint& t, uint32_t tag, uint32_t id) { Add(Sample(t, tag, Event::Begin, id)); }

	template <typename Detail>
	void Begin(const SystemTimePoint& t, uint32_t tag, uint32_t id, const Detail& detail)
	{
		Add(Sample(t, tag, Event::Begin, id, detail));
	}

	void End(const SystemTimePoint& t, uint32_t id) { Add(Sample(t, 0 /* tag*/, Event::End, id)); }

private:
	void Add(const Sample& sample)
	{
		size_t nextSamplePos = mSamplePos++;
		mSamples[nextSamplePos % mSamples.Size()] = sample;
	}

	ion::Vector<Sample, ion::DebugAllocator<Sample>> mSamples;
	std::atomic<size_t> mSamplePos = 0;
};

void ProfilingInit();

void ProfilingDeinit();

namespace profiling
{
void Record(uint64_t CaptureLengthMs, bool saveFile = true);

ion::UniquePtr<ByteBuffer<>> SerializedRecord();

ProfilingBuffer* Buffer(size_t index, uint8_t priority);

void OnBeginScheduling();

void OnEndScheduling();

bool IsEnabled(uint32_t tag);

uint32_t Register(uint16_t tag, const char* name, const char* file, uint32_t line);

namespace detail
{
void UpdateSummary(uint32_t id, const SystemTimePoint& end, const SystemTimePoint& start);
}

class Block
{
public:
	Block(uint32_t tag, uint32_t id) : mStart(SystemTimeUnit(0)), mId(id), mIsEnabled(ion::profiling::IsEnabled(tag))
	{
		if (mIsEnabled)
		{
			mStart = SystemTimePoint::Current();
			ion::Thread::Profiling().Begin(mStart, tag, mId);
		}
	}

	template <typename Detail>
	Block(uint32_t tag, uint32_t id, const Detail& detail) : mStart(SystemTimeUnit(0)), mId(id), mIsEnabled(ion::profiling::IsEnabled(tag))
	{
		if (mIsEnabled)
		{
			mStart = SystemTimePoint::Current();
			ion::Thread::Profiling().Begin(mStart, tag, mId, detail);
		}
	}

	~Block()
	{
		if (mIsEnabled)
		{
			auto end = SystemTimePoint::Current();
			ion::Thread::Profiling().End(end, mId);
			detail::UpdateSummary(mId, end, mStart);
		}
	}
	SystemTimePoint mStart;
	const uint32_t mId;
	const bool mIsEnabled;
};
};	// namespace profiling
}  // namespace ion

namespace ion
{
namespace profiling
{
namespace tag
{
constexpr const uint16_t Core = 1;
constexpr const uint16_t Scheduler = 2;
constexpr const uint16_t Job = 3;
constexpr const uint16_t Tracing = 4;
constexpr const uint16_t Network = 5;
constexpr const uint16_t Render = 6;
constexpr const uint16_t Physics = 7;
constexpr const uint16_t Audio = 8;
constexpr const uint16_t NodeScript = 9;
constexpr const uint16_t Memory = 10;
constexpr const uint16_t Online = 11;
constexpr const uint16_t Game = 255;
}  // namespace tag
}  // namespace profiling
}  // namespace ion

	#define ION_PROFILER_REGISTER_EVENT_ID(__tag, __name) \
		static const uint32_t ION_CONCATENATE(profile_event_id_, __LINE__) = ion::profiling::Register(__tag, __name, __FILE__, __LINE__)

	#define ION_PROFILER_SCOPE(__tag, __name)                                                    \
		ION_PROFILER_REGISTER_EVENT_ID(ion::profiling::tag::__tag, __name);                      \
		ion::profiling::Block ION_ANONYMOUS_VARIABLE(profilingBlock)(ion::profiling::tag::__tag, \
																	 ION_CONCATENATE(profile_event_id_, __LINE__))

	#define ION_PROFILER_SCOPE_DETAIL(__tag, __name, __detail)                                   \
		ION_PROFILER_REGISTER_EVENT_ID(ion::profiling::tag::__tag, __name);                      \
		ion::profiling::Block ION_ANONYMOUS_VARIABLE(profilingBlock)(ion::profiling::tag::__tag, \
																	 ION_CONCATENATE(profile_event_id_, __LINE__), __detail)

	#define ION_PROFILER_RECORD(__len) ion::profiling::Record(__len)

	#define ION_PROFILER_RECORD_BUFFER(__len) ion::profiling::Record(__len, false)

	#define ION_PROFILER_EVENT(__name)             \
		ION_PROFILER_REGISTER_EVENT_ID(0, __name); \
		ion::Thread::Profiling().Instant(ION_CONCATENATE(profile_event_id_, __LINE__))

	#define ION_PROFILER_PROCESS_EVENT(__name)     \
		ION_PROFILER_REGISTER_EVENT_ID(0, __name); \
		ion::Thread::Profiling().InstantProcess(ION_CONCATENATE(profile_event_id_, __LINE__))

	#define ION_PROFILER_GLOBAL_EVENT(__name)      \
		ION_PROFILER_REGISTER_EVENT_ID(0, __name); \
		ion::Thread::Profiling().InstantGlobal(ION_CONCATENATE(profile_event_id_, __LINE__))
#else
	#define ION_PROFILER_SCOPE(__tag, __name)
	#define ION_PROFILER_SCOPE_DETAIL(__tag, __name, __detail)
	#define ION_PROFILER_RECORD(__len)
	#define ION_PROFILER_RECORD_BUFFER(__len)
	#define ION_PROFILER_EVENT(__name)
	#define ION_PROFILER_PROCESS_EVENT(__name)
	#define ION_PROFILER_GLOBAL_EVENT(__name)
#endif
