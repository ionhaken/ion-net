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
#include <ion/time/CoreTime.h>

#include <ion/container/Algorithm.h>
#include <ion/container/ForEach.h>

#include <ion/debug/Profiling.h>

#include <ion/memory/GlobalMemoryPool.h>
#include <ion/memory/Memory.h>

#include <ion/concurrency/MPMCQueue.h>

#include <ion/jobs/JobScheduler.h>

#include <ion/temporary/TemporaryAllocator.h>

#include <ion/core/Core.h>
#include <ion/core/Engine.h>
#include <ion/core/StaticInstance.h>
#include <ion/filesystem/File.h>
#include <ion/filesystem/Folder.h>
#include <ion/string/String.h>
#include <ion/string/StringView.h>
#include <ion/util/Math.h>
#include <ion/util/MultiData.h>

#if !ION_PLATFORM_ANDROID
	#include <iostream>
#endif

#if ION_PLATFORM_MICROSOFT
	#if ION_DEBUGGER_OUTPUT == 1
		#define WIN32_LEAN_AND_MEAN
		#include <windows.h>  // For OutputDebugStringA
	#endif
#endif

#if ION_PLATFORM_ANDROID
	#include <android/log.h>
#endif
namespace ion
{
namespace tracing
{
using Resource = int;  // Dummy resource, because we are only using temporary allocator
std::atomic<size_t> gTotalMessages = 0;

struct TracingManager
{
#if !ION_PLATFORM_ANDROID
	struct OutStream
	{
		OutStream(FILE* out = stdout) : mOut(out) {}

		ION_FORCE_INLINE void Write(const char* str, size_t len) { fwrite(str, sizeof(char), len, mOut); }
		ION_FORCE_INLINE void Flush() { fflush(mOut); }

		FILE* mOut;
	};
#endif

	TracingManager(Resource&) {}

	~TracingManager() { ion::tracing::FlushUntilEmpty(); }

	MPMCQueue<LogMessageHeader*, ion::CoreAllocator<LogMessageHeader*>> mQueue;
	ion::Mutex mFlushMutex;
#if !ION_PLATFORM_ANDROID
	OutStream mOutputStream;
#endif
};

STATIC_INSTANCE(TracingManager, Resource);

#if ION_PLATFORM_ANDROID
constexpr const char* TAG = "ion";
#endif

namespace
{

constexpr size_t NullBlockSize = 1;
#if ION_PLATFORM_MICROSOFT
constexpr char MsgFooter[LogEvent::MsgFootersize] = {'\r', '\n', 0};
const constexpr char* EventId[] = {"[Debug]\r\n", "", "[Warning]\r\n", "[Error]\r\n"};
#else
constexpr char MsgFooter[LogEvent::MsgFootersize] = {'\n', 0};
const constexpr char* EventId[] = {"[Debug]\n", "", "[Warning]\n", "[Error]\n"};
#endif

#if ION_DEBUGGER_OUTPUT == 1 && ION_BUILD_DEBUG
constexpr bool ImmediateDebuggerOutput = true;
#else
constexpr bool ImmediateDebuggerOutput = false;
#endif

inline bool IsImmediateOutput()
{
	if constexpr (ImmediateDebuggerOutput)
	{
		if (ion::debug::IsDebugging())
		{
			return true;
		}
	}
	return false;
}

void ConsoleOutput(const char* text, size_t count)
{
#if ION_PLATFORM_ANDROID
	__android_log_write(ANDROID_LOG_INFO, TAG, text);
#else
	Instance().mOutputStream.Write(text, count);
#endif
}

void DebugOutput(const char* text)
{
#if ION_DEBUGGER_OUTPUT == 1
	OutputDebugStringA(text);
#elif ION_PLATFORM_ANDROID
	__android_log_write(ANDROID_LOG_DEBUG, TAG, text);
#else
	puts(text);
#endif
}

#if ION_DEBUGGER_OUTPUT == 1
void Output(const char* text, size_t length, bool useDebuggerOutput)
{
	if (useDebuggerOutput)
	{
		DebugOutput(text);
	}
	else
	{
		ConsoleOutput(text, length);
	}
}
#endif

void Print(const StringView& text)
{
#if ION_DEBUGGER_OUTPUT == 1
	Output(text.CStr(), text.Length(), false);
	Output(text.CStr(), text.Length(), true);
#else
	ConsoleOutput(text.CStr(), text.Length());
#endif
}

#if ION_DEBUGGER_OUTPUT == 1
void Print(const char* text, const LogMessageHeader& msgHeader, bool useDebuggerOutput)
#else
void Print(const char* text, const LogMessageHeader& msgHeader)
#endif
{
#if ION_PLATFORM_ANDROID
	auto logType = ANDROID_LOG_DEBUG;
	switch (msgHeader.mType)
	{
	case EventType::EventDebug:
		logType = ANDROID_LOG_DEBUG;
		break;
	case EventType::EventInfo:
		logType = ANDROID_LOG_INFO;
		break;
	case EventType::EventWarning:
		logType = ANDROID_LOG_WARN;
		break;
	case EventType::EventError:
		logType = ANDROID_LOG_ERROR;
		break;
	}
	__android_log_write(logType, TAG, text);
#else

	ION_ASSERT_FMT_IMMEDIATE(int(msgHeader.mType) <= 3, "Invalid type %i", int(msgHeader.mType));

	// #TODO: Remove snprintf and just copy strings to buffer for a speed-up.
	char buffer[128];
	int bufferLength;
	#if ION_DEBUGGER_OUTPUT == 1
	if (useDebuggerOutput)
	{
		bufferLength = snprintf(buffer, 128, "%s", EventId[static_cast<int>(msgHeader.mType)]);
	}
	else
	#endif
	{
		timing::TimeInfo tm(msgHeader.mTimeStamp);
		bufferLength =
		  snprintf(buffer, 128, "%s[%02u/%02u %02u:%02u:%02u.%03u]", EventId[static_cast<int>(msgHeader.mType)], tm.mReadable.mMon + 1,
				   tm.mReadable.mDay, tm.mReadable.mHour, tm.mReadable.mMin, tm.mReadable.mSec, tm.mReadable.mMilliSeconds);
	}

	#if ION_DEBUGGER_OUTPUT == 1
	Output(buffer, bufferLength, useDebuggerOutput);
	Output(text, msgHeader.mMsgLength - NullBlockSize, useDebuggerOutput);
	#else
	ConsoleOutput(buffer, bufferLength);
	ConsoleOutput(text, msgHeader.mMsgLength - NullBlockSize);
	#endif
#endif
}

#if ION_DEBUGGER_OUTPUT == 1
void PrintTraces(const char* logMessage, bool useDebuggerOutput = false)
#else
void PrintTraces(const char* logMessage)
#endif
{
	const LogMessageHeader* msgHeader = ion::AssumeAligned(reinterpret_cast<const LogMessageHeader*>(logMessage));
#if ION_DEBUGGER_OUTPUT == 1
	Print(logMessage + LogMessageHeaderSize, *msgHeader, useDebuggerOutput);
#else
	Print(logMessage + LogMessageHeaderSize, *msgHeader);
#endif
}

void FlushInputLocked(LogMessageHeader* header)
{
	PrintTraces(reinterpret_cast<const char*>(header));
#if ION_DEBUGGER_OUTPUT == 1
	if constexpr (!ImmediateDebuggerOutput)
	{
		PrintTraces(reinterpret_cast<const char*>(header), true);
	}
#endif
	ion::TemporaryAllocator<LogMessage> allocator;
	size_t blockSize = header->mIsShortBlock ? (LogMessageHeaderSize + header->mMsgLength) : sizeof(LogMessage);
	allocator.DeallocateRaw(header, blockSize);
}
}  // namespace

void SetOutputFile([[maybe_unused]] ion::FileOut* outfile)
{
#if !ION_PLATFORM_ANDROID
	if (outfile)
	{
		if (outfile->IsGood())
		{
			Instance().mOutputStream = TracingManager::OutStream(outfile->mImpl);
		}
		else
		{
			ION_WRN("Cannot write tracing to log file");
		}
	}
	else
	{
		FlushUntilEmpty();
		if (TracingIsInitialized())
		{
			Instance().mOutputStream = TracingManager::OutStream();
		}
	}
#endif
}

void FlushUntilEmpty()
{
	if (TracingIsInitialized())
	{
		for (;;)
		{
			size_t totalReceived = 0;
			{
				ion::AutoLock<ion::Mutex> flushLock(gInstance.Data().mFlushMutex);
				gInstance.Data().mQueue.DequeueAll(
				  [&](LogMessageHeader* header)
				  {
					  FlushInputLocked(header);
					  totalReceived++;
				  });
			}
			gTotalMessages -= totalReceived;
			if (gTotalMessages == 0)
			{
				break;
			}
			ion::Thread::Sleep(100);
		}
	}
}

void Flush()
{
	if (TracingIsInitialized())
	{
		ION_MEMORY_SCOPE(ion::tag::Debug);
		size_t totalReceived = 0;
		ion::AutoLock<ion::Mutex> flushLock(gInstance.Data().mFlushMutex);
		gInstance.Data().mQueue.DequeueAll(
		  [&](LogMessageHeader* header)
		  {
			  FlushInputLocked(header);
			  totalReceived++;
		  });
		gTotalMessages -= totalReceived;
#if !ION_PLATFORM_ANDROID
		Instance().mOutputStream.Flush();
#endif
	}
}

void PrintImmediate(EventType type, const StringView& text)
{
	if (type == EventType::EventDebug)
	{
#if ION_DEBUGGER_OUTPUT == 0
		return;
#endif
	}
	else if (TracingIsInitialized())
	{
		ConsoleOutput(text.CStr(), text.Length());
#if ION_DEBUGGER_OUTPUT == 0
		return;
#endif
	}
	DebugOutput(text.CStr());  // Use debug output if logger not initialized
}

void Print(EventType type, const char* text) { PrintImmediate(type, StringView(text, StringLen(text))); }

void PrintFormatted(EventType type, const char* format, ...)
{
	ion::StackStringFormatter<LogContentSize> processed;
	va_list arglist;
	va_start(arglist, format);
	int written = processed.Format(format, arglist);
	va_end(arglist);
	PrintImmediate(type, StringView(processed.CStr(), written));
}

#if ION_DEBUG_LOG_FILE == 1
ion::tracing::LogEvent::LogEvent(ion::tracing::EventType type, const char* file, int line)
#else
ion::tracing::LogEvent::LogEvent(ion::tracing::EventType type)
#endif
{
	ION_PROFILER_SCOPE(Tracing, "Log");
#if ION_DEBUG_LOG_FILE == 1
	Init(type, file, line);
#else
	Init(type);
#endif
}

#if ION_DEBUG_LOG_FILE == 1
void LogEvent::Format(ion::tracing::EventType type, const char* file, int line, const char* format, ...)
#else
void LogEvent::Format(ion::tracing::EventType type, const char* format, ...)
#endif
{
#if ION_DEBUG_LOG_FILE == 1
	Init(type, file, line);
#else
	Init(type);
#endif
	va_list arglist;
	va_start(arglist, format);
	int written = vsnprintf(&mWriteBuffer[mNumWritten], Available(), format, arglist);
	va_end(arglist);
	if (written != -1)
	{
		mNumWritten += written;
	}
}

#if ION_DEBUG_LOG_FILE == 1
void LogEvent::Init(ion::tracing::EventType type, const char* file, unsigned int line)
#else
void LogEvent::Init(ion::tracing::EventType type)
#endif
{
	ion::TemporaryAllocator<LogMessage> allocator;

	LogMessage* msg = allocator.AllocateTwoPhasePre();
	LogMessageHeader* header = &msg->mHeader;

	mWriteBuffer = reinterpret_cast<char*>(header) + LogMessageHeaderSize;
#if !ION_PLATFORM_ANDROID
	header->mTimeStamp = timing::LocalTime().mStamp;
#endif

	header->mType = type;
#if ION_DEBUG_LOG_FILE == 1
	mNumWritten = snprintf(mWriteBuffer, LogContentSize - LogEvent::MsgFootersize, "%s(%u):", file, line);
	if (mNumWritten == -1)
	{
		mNumWritten = 0;
	}
#else
	mNumWritten = 0;
#endif
}

void LogEvent::Write(const StringView& string) { Write(string.CStr(), string.Length()); }

void LogEvent::Write(const char* someChars, size_t aCount)
{
	aCount = ion::Min(aCount, Available());
	std::memcpy(&mWriteBuffer[mNumWritten], someChars, aCount);
	mNumWritten += static_cast<Int>(aCount);
}

void LogEvent::Write([[maybe_unused]] char key, const char* someChars, size_t aCount)
{
	aCount = ion::Min(aCount, Available());
	std::memcpy(&mWriteBuffer[mNumWritten], someChars, aCount);
	mNumWritten += static_cast<Int>(aCount);
}

LogEvent::~LogEvent()
{
	LogMessageHeader* header = ion::AssumeAligned(reinterpret_cast<LogMessageHeader*>(mWriteBuffer - LogMessageHeaderSize));
	auto eventType = header->mType;

	{
		char* txtBuffer = reinterpret_cast<char*>(header) + LogMessageHeaderSize + mNumWritten;
		mNumWritten += LogEvent::MsgFootersize;
		ION_ASSERT(mNumWritten < LogContentSize, "Out of message buffer");

		memcpy(txtBuffer, MsgFooter, LogEvent::MsgFootersize);
	}

	header->mMsgLength = ion::SafeRangeCast<uint16_t>(mNumWritten);

	// #TODO: gInstanceReady should be flag that tells what to do when tracing is not enabled and there is output
	if (!TracingIsInitialized() || IsImmediateOutput())
	{
		PrintTraces(reinterpret_cast<char*>(header)
#if ION_DEBUGGER_OUTPUT == 1
					  ,
					true
#endif
		);
		if (!TracingIsInitialized())
		{
			return;
		}
	}

	gTotalMessages++;
	ion::TemporaryAllocator<LogMessage> allocator;
	size_t blockSize = LogMessageHeaderSize + header->mMsgLength;
	header->mIsShortBlock = allocator.AllocateTwoPhasePost(reinterpret_cast<LogMessage*>(header), blockSize);

	gInstance.Data().mQueue.Enqueue(header);
	if (ion::core::gSharedScheduler == nullptr || eventType == EventType::EventError)
	{
		ION_PROFILER_SCOPE(Tracing, "Tracing");
		Flush();
	}
	else
	{
		class LogJob : public RepeatableIOJob
		{
		public:
			LogJob() : RepeatableIOJob(ion::tag::Core) {}
			void RunIOJob()
			{
				ION_PROFILER_SCOPE(Tracing, "Tracing");
				Flush();
			}
		};
		static LogJob logJob;
		logJob.Execute(ion::core::gSharedScheduler->GetPool());
	}
}

LogEvent& operator<<(ion::tracing::LogEvent& out, const ion::String& text)
{
	out.Write(text.CStr(), text.Length());
	return out;
}

LogEvent& operator<<(ion::tracing::LogEvent& out, const ion::StringView& text)
{
	out.Write(text.CStr(), text.Length());
	return out;
}

LogEvent& operator<<(LogEvent& out, const ion::MultiData<char, uint32_t>& multi)
{
	out.Write(multi.data, static_cast<size_t>(multi.size));
	return out;
}

LogEvent& operator<<(LogEvent& out, const char text[])
{
	out.Write(text, ion::StringLen(text));
	return out;
}

LogEvent& operator<<(LogEvent& out, char text[])
{
	out.Write(text, ion::StringLen(text));
	return out;
}

}  // namespace tracing

void TracingInit()
{
	ION_MEMORY_SCOPE(ion::tag::Debug);
	ION_ACCESS_GUARD_WRITE_BLOCK(tracing::gGuard);
	tracing::Init(
	  []()
	  {
#if ION_CONFIG_GLOBAL_MEMORY_POOL
		  GlobalMemoryInit();
#endif
		  CoreInit();
		  Thread::InitMain();
	  },
	  64 * 1024);
}

void TracingDeinit()
{
	ION_MEMORY_SCOPE(ion::tag::Debug);
	ION_ACCESS_GUARD_WRITE_BLOCK(tracing::gGuard);
	if (1 != tracing::gRefCount--)
	{
		return;
	}
	tracing::gIsInitialized = false;
	tracing::gInstance.Deinit();
	Thread::DeinitMain();
	CoreDeinit();
#if ION_CONFIG_GLOBAL_MEMORY_POOL
	GlobalMemoryDeinit();
#else
	ion::memory_tracker::PrintStats(true, ion::memory_tracker::Layer::Invalid);
#endif

}
bool TracingIsInitialized() { return tracing::gIsInitialized; }
}  // namespace ion
