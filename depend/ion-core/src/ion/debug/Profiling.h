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
	using Category = uint8_t;

	enum class Event : uint8_t
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
		Event,
		HasDetail = 1 << 7
	};

	class Sample
	{
	public:
		Sample() : mTimePoint(SystemTimePoint::Current()) {}

		Sample(const SystemTimePoint& t, uint32_t tag, Event eventType, uint32_t eventId)
		  : mTimePoint(t), id(ion::SafeRangeCast<uint16_t>(eventId)), mDetailId(0), cat(ion::SafeRangeCast<Category>(tag)), type(eventType)
		{
		}

		Sample(const SystemTimePoint& t, uint32_t tag, Event eventType, uint32_t eventId, uint16_t detailId)
		  : mTimePoint(t), id(ion::SafeRangeCast<uint16_t>(eventId)), mDetailId(detailId), cat(ion::SafeRangeCast<Category>(tag)), type(Event(uint8_t(eventType) | uint8_t(Event::HasDetail)))
		{
		}

		SystemTimePoint mTimePoint;
		uint32_t id;
		uint16_t mDetailId;
		Category cat;
		Event type = Event::None;

		static_assert(sizeof(mTimePoint) + sizeof(id) + sizeof(cat) + sizeof(type) + sizeof(mDetailId) ==
						ION_CONFIG_CACHE_LINE_SIZE / 4,
					  "Sample not cache efficient");
	};

	ProfilingBuffer();

	void Resize(size_t maxSamples);

	void Save(profiling::TemporaryStringBuffer& stringBuffer, ion::JSONArrayWriter& tracesArray, ion::SystemTimePoint now, uint64_t lenNs,
			  UInt tid);

	void InstantGlobal(uint32_t id) { Add(Sample(SystemTimePoint::Current(), 0 /* tag*/, Event::InstantGlobal, id)); }

	void InstantProcess(uint32_t id) { Add(Sample(SystemTimePoint::Current(), 0 /* tag*/, Event::InstantProcess, id)); }

	void Instant(uint32_t id) { Add(Sample(SystemTimePoint::Current(), 0, Event::InstantThread, id)); }

	void Begin(const SystemTimePoint& t, uint32_t tag, uint32_t id) { Add(Sample(t, tag, Event::Begin, id)); }

	template <typename Detail>
	void Begin(const SystemTimePoint& t, uint32_t tag, uint32_t id, const Detail& detail)
	{
		uint16_t nextDetailPos = ion::Mod2(mDetailPos++, mDetailInfo.Size());
		size_t samplePos = Add(Sample(t, tag, Event::Begin, id, nextDetailPos));
		
		mDetailInfo[nextDetailPos].mSampleIndex = uint32_t(samplePos);
		StringWriter writer(mDetailInfo[nextDetailPos].mText.Data(), sizeof(mDetailInfo[nextDetailPos].mText));
		serialization::Serialize(detail, writer);
	}

	void End(const SystemTimePoint& t, uint32_t id) { Add(Sample(t, 0 /* tag*/, Event::End, id)); }


private:
	size_t Add(const Sample& sample);

	ion::Vector<Sample, ion::DebugAllocator<Sample>> mSamples;
	std::atomic<size_t> mSamplePos = 0;
	std::atomic<uint16_t> mDetailPos = 0;
	struct DetailInfo
	{
		uint32_t mSampleIndex; // map detail to sample
		ion::Array<char, 12> mText;
	};

	ion::Vector<DetailInfo, ion::DebugAllocator<DetailInfo>> mDetailInfo;
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

namespace tag
{
constexpr const ProfilingBuffer::Category Core = 1;
constexpr const ProfilingBuffer::Category Scheduler = 2;
constexpr const ProfilingBuffer::Category Job = 3;
constexpr const ProfilingBuffer::Category Tracing = 4;
constexpr const ProfilingBuffer::Category Network = 5;
constexpr const ProfilingBuffer::Category Render = 6;
constexpr const ProfilingBuffer::Category Physics = 7;
constexpr const ProfilingBuffer::Category Audio = 8;
constexpr const ProfilingBuffer::Category NodeScript = 9;
constexpr const ProfilingBuffer::Category Memory = 10;
constexpr const ProfilingBuffer::Category Online = 11;
constexpr const ProfilingBuffer::Category Game = 255;

constexpr const ion::Array<const char* const, 13> TagStrings = {"Generic", "Core",	"Scheduler",  "Job",	"Tracing", "Network", "Render",
																"Physics", "Audio", "NodeScript", "Memory", "Online",  "Game"};

}  // namespace tag
}  // namespace profiling
}  // namespace ion

	#define ION_PROFILER_REGISTER_EVENT_ID(__tag, __name) \
		static const uint32_t ION_CONCATENATE(profile_event_id_, __LINE__) = ion::profiling::Register(__tag, __name, __FILE__, __LINE__)

	#define ION_PROFILER_SCOPE(__tag, __name)                                                    \
		ION_PROFILER_REGISTER_EVENT_ID(ion::profiling::tag::__tag, __name);                      \
		ion::profiling::Block ION_ANONYMOUS_VARIABLE(profilingBlock)(ion::profiling::tag::__tag, \
																	 ION_CONCATENATE(profile_event_id_, __LINE__))

	#define ION_PROFILER_SCOPE_DETAIL(__tag, __name, __detail)              \
		ION_PROFILER_REGISTER_EVENT_ID(ion::profiling::tag::__tag, __name); \
		ion::profiling::Block ION_ANONYMOUS_VARIABLE(profilingBlock)(       \
		  ion::profiling::tag::__tag, ION_CONCATENATE(profile_event_id_, __LINE__), __detail)

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
