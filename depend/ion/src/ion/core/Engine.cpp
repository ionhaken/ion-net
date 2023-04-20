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
#include <ion/core/Core.h>
#include <ion/core/Engine.h>
#include <ion/debug/Profiling.h>
#include <ion/concurrency/Thread.h>
#include <ion/memory/Memory.inl>
#include <ion/tweakables/Tweakables.h>
#include <ion/temporary/TemporaryAllocator.h>

#include <atomic>
#include <signal.h>
#if ION_PLATFORM_MICROSOFT
	#include <Windows.h>
	#include <ion/debug/Minidump.h>
#endif

#if ION_PLATFORM_ANDROID
	#include <errno.h>
#endif

namespace ion
{
bool gIsActive = false;
bool gIsDynamicInitExitDone = false;
bool gIsDynamicInitDone = false;
std::atomic<bool> gExitRequested = false;
}  // namespace ion

extern "C" void ClearAbortHandler()
{
#if ION_PLATFORM_MICROSOFT
	signal(SIGABRT, SIG_DFL);
	// signal(SIGINT, SIG_DFL);
	signal(SIGBREAK, SIG_DFL);
#else
	struct sigaction sa;
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_RESTART;
	sigfillset(&sa.sa_mask);  // Block every signal during the handler
	if (sigaction(SIGHUP, &sa, NULL) == -1)
	{
		ION_LOG_IMMEDIATE("Cannot uninstall SIGHUP handler.");
	}
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		ION_LOG_IMMEDIATE("Cannot uninstall SIGINT handler.");
	}
#endif
}

extern "C" void AbortHandler(int aSignalNumber)	 // #TODO: Move to core:error?
{
	ion::gExitRequested = true;
	ClearAbortHandler();
	ION_LOG_FMT_IMMEDIATE("Abort code: %i", aSignalNumber);
	ion::debug::FatalErrorHandler();
}

extern "C" void BreakHandler(int aSignalNumber)	 // #TODO: Move to core:error?
{
	ion::gExitRequested = true;
	signal(aSignalNumber, BreakHandler);
}

#if ION_PLATFORM_MICROSOFT
BOOL WINAPI consoleHandler(DWORD signal)
{
	if (signal == CTRL_C_EVENT)
	{
		BreakHandler(SIGBREAK);
	}
	return TRUE;
}
#endif

namespace ion
{
Engine::Engine()
{
	memory_tracker::EnableTracking();
	#if 0 // wait on memory leak
	ION_LOG_FMT_IMMEDIATE("Waiting 10s for user...");
	memory_tracker::EnableWaitUserOnLeak();
	ion::Thread::SleepMs(10000);
	ION_LOG_FMT_IMMEDIATE("Wait ended.");
	#endif

	gIsDynamicInitDone = true;
	gIsDynamicInitExitDone = true;
	ion::Engine::Start();
	{
		ion::MemoryScope scope(ion::tag::Core);
		ion::core::gInstance.Data().InitGlobalSettings();
	}
}

Engine::~Engine()
{
	{
		ion::MemoryScope scope(ion::tag::Core);
		ion::core::gInstance.Data().DeinitGlobalSettings();
	}
	ion::Engine::Stop();
	gIsDynamicInitExitDone = false;
}

bool Engine::IsDynamicInitExit() { return !gIsDynamicInitExitDone; }

bool Engine::IsDynamicInitDone() { return gIsDynamicInitDone; }

bool Engine::IsExitRequested() { return gExitRequested; }

void Engine::RequestExit() { ion::gExitRequested = true; }

}  // namespace ion

void ion::Engine::Start()
{
	if (gIsActive)
	{
		return;
	}
	gIsActive = true;
	StartInternal();
}

void ion::Engine::Restart()
{
	if (gIsActive)
	{
		ion::Thread::OnEngineRestart();
		return;
	}
	StartInternal();
}
void ion::Engine::StartInternal()
{
#if ION_PLATFORM_MICROSOFT
	{
		if (!SetConsoleCtrlHandler(consoleHandler, TRUE))
		{
			ION_ABNORMAL("Could not set console control handler");
		}

		SetUnhandledExceptionFilter(minidump::HandleException);	 // #TODO: Move to ion::error?
		PULONG pulong = NULL;
		ULONG ulong = ion::Thread::MinimumStackSize;
		pulong = &ulong;
		SetThreadStackGuarantee(pulong);
	}

	signal(SIGABRT, &AbortHandler);
	// signal(SIGINT, &AbortHandler);
	signal(SIGBREAK, &BreakHandler);
#else
	struct sigaction sa;
	sa.sa_handler = &BreakHandler;
	sa.sa_flags = SA_RESTART;
	sigfillset(&sa.sa_mask);  // Block every signal during the handler
	if (sigaction(SIGHUP, &sa, NULL) == -1)
	{
		ION_LOG_INFO("Cannot install SIGHUP handler.");
	}
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		ION_LOG_INFO("Cannot install SIGINT handler.");
	}
#endif

	ion::TracingInit();
	ion::TweakablesInit();
}

void ion::Engine::Stop()
{
	ion::TweakablesDeinit();
	ion::TracingDeinit();

	gIsActive = false;
	ClearAbortHandler();
}

bool ion::Engine::IsActive() { return gIsActive; }
