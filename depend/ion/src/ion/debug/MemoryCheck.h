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

#if ION_PLATFORM_MICROSOFT
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>
#endif

namespace ion
{
class MemoryCheck
{
#if ION_PLATFORM_MICROSOFT
	#if ION_BUILD_DEBUG
	_CrtMemState state1;
	_CrtMemState state2;
	#endif
#endif
public:
	MemoryCheck()
	{
#if ION_PLATFORM_MICROSOFT
	#if ION_BUILD_DEBUG
		_CrtMemCheckpoint(&state1);
	#endif
#endif
	}
	~MemoryCheck()
	{
#if ION_PLATFORM_MICROSOFT
	#if ION_BUILD_DEBUG
		_CrtMemCheckpoint(&state2);
		_CrtMemState state3;
		if (_CrtMemDifference(&state3, &state1, &state2))
		{
			_CrtMemDumpStatistics(&state3);
		}
	#endif
#endif
	}
};
}  // namespace ion
