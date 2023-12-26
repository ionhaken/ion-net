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

enum class EventType : uint8_t
{
	EventDebug,
	EventInfo,
	EventWarning,
	EventError
};

template <size_t TSize>
struct BytePage;

constexpr size_t LogMessageSize = 1024;
constexpr size_t EventBufferSize = 32 * LogMessageSize;

struct LogMessageHeader
{
#if !ION_PLATFORM_ANDROID
	uint64_t mTimeStamp;
#endif
	BytePage<EventBufferSize>* mPage;
	uint16_t mMsgLength;
	ion::tracing::EventType mType;
	bool mIsShortBlock;
};

constexpr size_t LogMessageHeaderSize = offsetof(LogMessageHeader, mIsShortBlock) + sizeof(bool);
constexpr size_t LogContentSize = LogMessageSize - LogMessageHeaderSize;

struct LogMessage
{
	LogMessageHeader mHeader;
	// Log content starts at header filler bytes
	char mTrailingPayload[LogMessageSize - sizeof(LogMessageHeader)];
};

void Flush();

void FlushUntilEmpty();

void PrintFormatted(EventType type, const char* format, ...);
void Print(EventType type, const char* text);

}  // namespace tracing
}  // namespace ion

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

#if ION_PLATFORM_MICROSOFT
	static constexpr size_t MsgFootersize = 3;
#else
	static constexpr size_t MsgFootersize = 2;
#endif

	inline size_t Available() const { return LogContentSize - MsgFootersize - mNumWritten; }

	char* mWriteBuffer;
	int mNumWritten;
};
}  // namespace ion::tracing
