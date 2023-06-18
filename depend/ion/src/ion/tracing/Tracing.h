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

#include <ion/Types.h>

namespace ion
{
class String;
class StringView;
template <typename TData, typename TSize>
struct MultiData;
class JobScheduler;
class FileOut;

void TracingInit();
bool TracingIsInitialized();
void TracingDeinit();

namespace tracing
{

void SetOutputFile(ion::FileOut* file);

static constexpr size_t EventBufferSize = 32 * 1024;

enum class EventType : uint8_t
{
	EventDebug,
	EventInfo,
	EventWarning,
	EventError,
	EventGTest	// Force debugger output
};

template <size_t TSize>
struct BytePage;

struct LogMessageHeader
{
	BytePage<EventBufferSize>* mPage;
#if !ION_PLATFORM_ANDROID
	uint64_t mTimeStamp;
#endif
	uint16_t mMsgLength;
	ion::tracing::EventType mType;
	bool mIsShortBlock;
};

const constexpr size_t MaxStaticMsgLength = 1024;

struct LogMessage
{
	LogMessageHeader mHeader;
	char mData[MaxStaticMsgLength];
};

void Flush();

void FlushUntilEmpty();

void PrintFormatted(EventType type, const char* format, ...);
void Print(EventType type, const char* text);

}  // namespace tracing
}  // namespace ion

#define ion_forward(...) static_cast<decltype(__VA_ARGS__)&&>(__VA_ARGS__)

namespace ion::tracing
{
template <typename ValueType, typename Logger>
inline void Handler(Logger& logger, const ValueType& value);

class LogEvent
{
public:
#if ION_DEBUG_LOG_FILE == 1
	LogEvent(EventType type, const char* file, int line);
	template <typename... Args>
	LogEvent(EventType type, const char* file, int line, const char* format, Args&&... args)
	{
		Format(type, file, line, format, ion_forward(args)...);
	}
#else
	LogEvent(EventType type);
	template <typename... Args>
	LogEvent(EventType type, const char* format, Args&&... args)
	{
		Format(type, format, ion_forward(args)...);
	}
#endif
	~LogEvent();

	friend LogEvent& operator<<(LogEvent& out, const ion::String& text);

	friend LogEvent& operator<<(LogEvent& out, const ion::StringView& text);

	friend LogEvent& operator<<(LogEvent& out, const ion::MultiData<char, uint32_t>& multi);

	friend LogEvent& operator<<(LogEvent& out, const char text[]);

	friend LogEvent& operator<<(LogEvent& out, char text[]);

	template <typename T>
	inline friend LogEvent& operator<<(LogEvent& out, const T& value)
	{
		Handler(out, value);
		return out;
	}

	// private:
#if ION_DEBUG_LOG_FILE == 1
	void Format(ion::tracing::EventType type, const char* file, int line, const char* format, ...);
#else
	void Format(ion::tracing::EventType type, const char* format, ...);
#endif

#if ION_DEBUG_LOG_FILE == 1
	void Init(ion::tracing::EventType type, const char* file, unsigned int line);
#else
	void Init(ion::tracing::EventType type);
#endif

	void Write(const StringView& text);
	void Write(const char* someChars, size_t aCount);
	void Write(char key, const char* someChars, size_t aCount);
	inline void Write(const char* someChars);
	inline size_t Available() const { return MaxStaticMsgLength - sizeof(LogMessageHeader) - mNumWritten; }

	char* ION_RESTRICT mWriteBuffer;
	int mNumWritten;
};
}  // namespace ion::tracing
