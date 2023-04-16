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
#include <ion/memory/MemoryScope.h>

#include <ion/Base.h>
#include <ion/tracing/Log.h>
#define CATCH_BREAK_INTO_DEBUGGER() ION_CHECK_FAILED("Test failed")
#define CATCH_CONFIG_DISABLE_EXCEPTIONS
#define CATCH_CONFIG_FAST_COMPILE
#ifdef __SANITIZE_ADDRESS__
	#define CATCH_CONFIG_NO_WINDOWS_SEH
#endif

#ifdef TEST_MAIN
	#define CATCH_CONFIG_RUNNER
#endif
#include <catch2/catch.hpp>	 // Catch v2.

#ifdef TEST_MAIN
	#include <ion/core/Engine.h>
	#include <ion/tweakables/Tweakables.h>
	#include <ion/core/OptionParser.h>
	#include <ion/debug/MemoryTracker.h>
	#include <limits>

TWEAKABLE_BOOL("test.infinite", InfiniteTest, false);

int main(int argc, char* argv[])
{
	ion::Engine e;

	#if !ION_BUILD_DEBUG
	// Catch2 shows in memory leaks
	ion::memory_tracker::SetFatalMemoryLeakLimit(1024);
	#endif

	ion::option_parser::ParseArgs(argc, argv);
	int numFailed = 0;
	ION_MEMORY_SCOPE(ion::tag::IgnoreLeaks);  // Don't care about Catch2 leaks
	Catch::Session session;					  // There must be exactly one instance

	// writing to session.configData() here sets defaults
	// this is the preferred way to set them

	int returnCode = session.applyCommandLine(argc, argv);
	if (returnCode != 0)  // Indicates a command line error
		return returnCode;

	session.configData().shouldDebugBreak = true;
	session.configData().showSuccessfulTests = false;
	session.configData().noThrow = true;
	session.configData().abortAfter = (std::numeric_limits<int>::max)();

	for (;;)
	{
		ION_MEMORY_SCOPE(ion::tag::Test);
		numFailed = session.run();

		if (numFailed != 0)
		{
			break;
		}
		// numFailed is clamped to 255 as some unices only use the lower 8 bits.
		// This clamping has already been applied, so just return it here
		// You can also do any post run clean-up here
		if TWEAKABLE_IS_EQUAL (InfiniteTest, false)
		{
			break;
		}
	}
	return numFailed;
}
#endif
