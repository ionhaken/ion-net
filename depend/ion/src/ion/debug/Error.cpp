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
#include <ion/Base.h>
#include <ion/core/Engine.h>
#include <ion/core/Core.h>
#include <ion/debug/Profiling.h>
#include <ion/tracing/Logger.h>
#include <ion/string/String.h>

#if ION_PLATFORM_MICROSOFT
	#if !defined(WIN32_LEAN_AND_MEAN)
		#define WIN32_LEAN_AND_MEAN
	#endif
	#include <Windows.h>
#endif

namespace ion::debug
{
#if (ION_ABORT_ON_FAILURE == 1)
ErrorMode errorMode = ErrorMode::Break;
bool allowAbnormalCondition = false;
bool IsBreakingOnAbnormalError() { return !::ion::debug::allowAbnormalCondition && IsDebugging(); }
// Have debug break in internal function to prevent MSVC compiler invalid code generation when full optimizations enabled
// Can be reproduced with test FixedPointTest, ATan2
void HiddenDebugBreak() { ION_DEBUG_BREAK; }
bool IsErrorDebugBreak()
{
	switch (::ion::debug::errorMode)
	{
	#if (ION_EXCEPTIONS_ENABLED == 1)
	case ::ion::debug::ErrorMode::Throw:
		THROW_EXCEPTION(std::exception());
		break;
	#endif
	case ::ion::debug::ErrorMode::Break:
		allowAbnormalCondition = true;
		return true;
	case ::ion::debug::ErrorMode::Abort:
		abort();
	case ::ion::debug::ErrorMode::Ignore:
		break;
	}
	return false;
}
#endif
void FatalErrorHandler()
{
#if ION_PROFILER_BUFFER_SIZE_PER_THREAD > 0
	if (!IsDebugging())
	{
		ION_PROFILER_RECORD(500);
	}
#endif
	ion::core::gSharedScheduler = nullptr;
	ion::tracing::Flush();
	if (ion::tracing::gGlobalLogger)
	{
		ion::tracing::gGlobalLogger->Reset();
	}
}

#if ION_PLATFORM_MICROSOFT
ion::String GetLastErrorString()
{
	DWORD errorMessageID = ::GetLastError();
	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
								 errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);
	if (size >= 2)	// Remove line break
	{
		message.pop_back();
		message.pop_back();
	}
	LocalFree(messageBuffer);

	ion::StackStringFormatter<256> s;
	s.Format("(0x%x) '%s'", errorMessageID, message.c_str());
	return s.CStr();
}
#else
ion::String GetLastErrorString() { return ion::String(strerror(errno)); }
#endif

}  // namespace ion::debug


#if ION_PLATFORM_MICROSOFT
bool ion::debug::IsDebugging() { return IsDebuggerPresent(); }
#else

// GDB Detection
// https://stackoverflow.com/questions/3596781/how-to-detect-if-the-current-process-is-being-run-by-gdb

	#include <unistd.h>
	#include <stdint.h>
	#include <sys/ptrace.h>
	#include <sys/wait.h>

	#if !defined(PTRACE_ATTACH) && defined(PT_ATTACH)
		#define PTRACE_ATTACH PT_ATTACH
	#endif
	#if !defined(PTRACE_DETACH) && defined(PT_DETACH)
		#define PTRACE_DETACH PT_DETACH
	#endif

	#if ION_PLATFORM_LINUX
		#define _PTRACE(_x, _y) ptrace(_x, _y, NULL, NULL)
	#else
		#define _PTRACE(_x, _y) ptrace(_x, _y, NULL, 0)
	#endif

/** Determine if we're running under a debugger by attempting to attach using pattach
 *
 * @return 0 if we're not, 1 if we are, -1 if we can't tell.
 */
bool ion::debug::IsDebugging()
{
	static bool gDoNotCheckDebugger = false;
	if (gDoNotCheckDebugger)
	{
		return false;
	}
	int pid;

	int from_child[2] = {-1, -1};

	if (pipe(from_child) < 0)
	{
		gDoNotCheckDebugger = true;
		ION_LOG_INFO("Debugger check failed: Error opening internal pipe: " << errno);	//<< syserror(errno));
		return false;
	}

	pid = fork();
	if (pid == -1)
	{
		gDoNotCheckDebugger = true;
		ION_LOG_INFO("Debugger check failed: Error forking: " << errno);  // syserror(errno));
		return false;
	}

	/* Child */
	if (pid == 0)
	{
		uint8_t ret = 0;
		int ppid = getppid();

		/* Close parent's side */
		close(from_child[0]);

		if (_PTRACE(PTRACE_ATTACH, ppid) == 0)
		{
			waitpid(ppid, NULL, 0);					  //  Wait for the parent to stop
			write(from_child[1], &ret, sizeof(ret));  // Tell the parent what happened */
			_PTRACE(PTRACE_DETACH, ppid);
			exit(0);
		}

		ret = 1;
		/* Tell the parent what happened */
		write(from_child[1], &ret, sizeof(ret));

		exit(0);
		/* Parent */
	}
	else
	{
		uint8_t ret = -1;

		/*
		 *  The child writes a 1 if pattach failed else 0.
		 *
		 *  This read may be interrupted by pattach,
		 *  which is why we need the loop.
		 */
		while ((read(from_child[0], &ret, sizeof(ret)) < 0) && (errno == EINTR))
			;

		/* Ret not updated */
		if (ret < 0)
		{
			gDoNotCheckDebugger = true;
			ION_LOG_INFO("Debugger check failed: Error getting status from child: " << errno);	// syserror(errno));
		}

		/* Close the pipes here, to avoid races with pattach (if we did it above) */
		close(from_child[1]);
		close(from_child[0]);

		/* Collect the status of the child */
		waitpid(pid, NULL, 0);

		if (ret == 1)
		{
			return true;
		}
		else
		{
			gDoNotCheckDebugger = true;  // Just don't try this again.
			return false;
		}
	}
}
#endif

