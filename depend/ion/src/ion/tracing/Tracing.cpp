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
		#include <windows.h>  // For OutputDebugStringA
		#undef AddJob
	#endif
#endif

#if ION_PLATFORM_ANDROID
	#include <android/log.h>
#endif
namespace ion
{
namespace tracing
{
#if ION_PLATFORM_ANDROID
constexpr const char* TAG = "ion";
#endif

#if ION_DEBUGGER_OUTPUT == 1 && ION_BUILD_DEBUG
const bool ImmediateDebuggerOutput = true;
#else
const bool ImmediateDebuggerOutput = false;
#endif

using Resource = int;

std::atomic<size_t> gTotalMessages = 0;

struct TracingManager
{
#if !ION_PLATFORM_ANDROID
	struct OutStream
	{
		OutStream(FILE* out = stdout) : mOut(out) {}

		void Write(const char* str, size_t len) { fwrite(str, sizeof(char), len, mOut); }
		void Flush() { fflush(mOut); }

		FILE* mOut;
	};
#endif

	TracingManager(Resource&) /*: mObjectPool(16)*/ {}

	~TracingManager() { ion::tracing::FlushUntilEmpty(); }

	MPMCQueue<LogMessageHeader*, ion::CoreAllocator<LogMessageHeader*>> mQueue;
	ion::Mutex mFlushMutex;
#if !ION_PLATFORM_ANDROID
	OutStream mOutputStream;
#endif
};

STATIC_INSTANCE(TracingManager, Resource);

void SetOutputFile(ion::FileOut* outfile)
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

static void ConsoleOutput(const char* text, size_t count)
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
static void Output(const char* text, size_t length, bool useDebuggerOutput)
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
	Output(text.CStr(), text.Length(), true);
	Output(text.CStr(), text.Length(), false);
#else
	ConsoleOutput(text.CStr(), text.Length());
#endif
}

#if ION_DEBUGGER_OUTPUT == 1
static void Print(const char* text, const LogMessageHeader& msgHeader, bool useDebuggerOutput)
#else
static void Print(const char* text, const LogMessageHeader& msgHeader)
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
	case EventType::EventGTest:
		logType = ANDROID_LOG_INFO;
		break;
	}
	__android_log_write(logType, TAG, text);
#else
	if (msgHeader.mType == EventType::EventGTest)
	{
	#if ION_DEBUGGER_OUTPUT == 1
		if (!useDebuggerOutput)
		{
			Output(text, msgHeader.mMsgLength - 1 /* ignore null*/, true);
		}
	#endif
		return;
	}

	const char* EventId[] = {"[Debug]\n", "", "[Warning]\n", "[Error]\n"};
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
	Output(text, msgHeader.mMsgLength - 1 /*ignore null*/, useDebuggerOutput);
	#else
	ConsoleOutput(buffer, bufferLength);
	ConsoleOutput(text, msgHeader.mMsgLength - 1 /*ignore null*/);
	#endif
#endif
}

#if ION_DEBUGGER_OUTPUT == 1
static void PrintTraces(char* loggingPos, bool useDebuggerOutput = false)
#else
static void PrintTraces(char* loggingPos)
#endif
{
	const LogMessageHeader* msgHeader = ion::AssumeAligned(reinterpret_cast<LogMessageHeader*>(&loggingPos[0]));
	// while (msgHeader->mMsgLength > 0)
	{
		char* msgEnd = &loggingPos[sizeof(LogMessageHeader)] + msgHeader->mMsgLength - 1;

		// Need to have null string for debugger output
		// char swappedBytes[1] = {msgEnd[0]};
		msgEnd[0] = 0;

#if ION_DEBUGGER_OUTPUT == 1
		Print(&loggingPos[sizeof(LogMessageHeader)], *msgHeader, useDebuggerOutput);
#else
		Print(&loggingPos[sizeof(LogMessageHeader)], *msgHeader);
#endif

		/*msgEnd[0] = swappedBytes[0];
		int alignmentBytes = AlignmentBytes(msgHeader->mMsgLength);
		loggingPos = msgEnd + alignmentBytes;
		msgHeader = ion::AssumeAligned(reinterpret_cast<LogMessageHeader*>(loggingPos));*/
	}
}

static void FlushInputLocked(LogMessageHeader* header)
{
#if ION_DEBUGGER_OUTPUT == 1
	if constexpr (!ImmediateDebuggerOutput)
	{
		PrintTraces(reinterpret_cast<char*>(header), true);
	}
#endif
	PrintTraces(reinterpret_cast<char*>(header));

	ion::TemporaryAllocator<LogMessage> allocator;
	allocator.DeallocateRaw(reinterpret_cast<LogMessage*>(header),
							header->mIsShortBlock ? sizeof(LogMessage) - (MaxStaticMsgLength - header->mMsgLength) : sizeof(LogMessage));
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
		ion::MemoryScope debugScope(ion::tag::Debug);
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

void Print(EventType type, const char* text) { PrintImmediate(type, StringView(text, strlen(text))); }

void PrintFormatted(EventType type, const char* format, ...)
{
	ion::StackStringFormatter<MaxStaticMsgLength> processed;
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
	int written = vsnprintf(&mWriteBuffer[sizeof(LogMessageHeader) + mNumWritten], Available(), format, arglist);
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

	mWriteBuffer = reinterpret_cast<char*>(header);
#if !ION_PLATFORM_ANDROID
	header->mTimeStamp = timing::LocalTime().mStamp;
#endif

	header->mType = type;
#if ION_DEBUG_LOG_FILE == 1
	mNumWritten = snprintf(&mWriteBuffer[sizeof(LogMessageHeader)], MaxStaticMsgLength - sizeof(LogMessageHeader), "%s(%u):", file, line);
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
	std::memcpy(&mWriteBuffer[sizeof(LogMessageHeader) + mNumWritten], someChars, aCount);
	mNumWritten += static_cast<Int>(aCount);
}

void LogEvent::Write([[maybe_unused]] char key, const char* someChars, size_t aCount)
{
	aCount = ion::Min(aCount, Available());
	std::memcpy(&mWriteBuffer[sizeof(LogMessageHeader) + mNumWritten], someChars, aCount);
	mNumWritten += static_cast<Int>(aCount);
}

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

LogEvent::~LogEvent()
{
	LogMessageHeader* header = ion::AssumeAligned(reinterpret_cast<LogMessageHeader*>(mWriteBuffer));
	auto eventType = header->mType;

	mWriteBuffer[sizeof(LogMessageHeader) + mNumWritten] = '\n';
	mNumWritten += 2;  // Reserve for \n & \0

	header->mMsgLength = ion::SafeRangeCast<uint16_t>(mNumWritten);

	// #TODO: gInstanceReady should be flag that tells what to do when tracing is not enabled and there is output
	if (!TracingIsInitialized() || IsImmediateOutput())
	{
		/*LogMessageHeader* nextHeader =
		  ion::AssumeAligned(reinterpret_cast<LogMessageHeader*>(&mWriteBuffer[sizeof(LogMessageHeader) + mNumWritten]));
		nextHeader->mMsgLength = 0;*/
		PrintTraces(reinterpret_cast<char*>(header) /* mWriteBuffer*/
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
	header->mIsShortBlock =
	  allocator.AllocateTwoPhasePost(reinterpret_cast<LogMessage*>(header), sizeof(LogMessage) - (MaxStaticMsgLength - header->mMsgLength));

	// Instance().buffer.LockFront();

	// size_t msgCopySize = sizeof(LogMessageHeader) + mNumWritten;
	// ION_ASSERT_FMT_IMMEDIATE(msgCopySize < EventBufferSize, "Out of event buffer bounds");
	// std::memcpy(Instance().buffer.Front().pos, mWriteBuffer, msgCopySize);
	// Instance().buffer.Front().pos += msgCopySize;

	// ION_ASSERT_FMT_IMMEDIATE(Instance().buffer.Front().Size() < BufferLength, "Out of tracing buffer bounds");

	gInstance.Data().mQueue.Enqueue(header);
	if (ion::core::gSharedScheduler == nullptr || eventType == EventType::EventError /*||
		(gInstance.Data().buffer.Front().Size() >= BufferLength - ion::tracing::EventBufferSize)*/)
	{
		ION_PROFILER_SCOPE(Tracing, "Tracing");
		// FlushInputLocked(header);
		Flush();
	}
	else
	{
		class LogJob : public RepeatableIOJob
		{
		public:
			LogJob() : RepeatableIOJob(ion::tag::Core) {}
			virtual void RunIOJob()
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
	ION_ACCESS_GUARD_WRITE_BLOCK(tracing::gGuard);
	if (0 != tracing::gIsInitialized++)
	{
		return;
	}
#if ION_CONFIG_GLOBAL_MEMORY_POOL
	GlobalMemoryInit();
#endif
	CoreInit();
	Thread::InitMain();
	ION_MEMORY_SCOPE(ion::tag::Debug);
	tracing::gInstance.Init(64 * 1024);
}

void TracingDeinit()
{
	ION_ACCESS_GUARD_WRITE_BLOCK(tracing::gGuard);
	if (1 != tracing::gIsInitialized--)
	{
		return;
	}
	tracing::gInstance.Deinit();
	Thread::DeinitMain();
	CoreDeinit();
#if ION_CONFIG_GLOBAL_MEMORY_POOL
	GlobalMemoryDeinit();
#else
	ion::memory_tracker::PrintStats(true, ion::memory_tracker::Layer::Invalid);
#endif
}

bool TracingIsInitialized() { return tracing::gIsInitialized != 0; }
}  // namespace ion
