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
#include <ion/tracing/Log.h>
#include <ion/hw/TimeCaps.h>
#include <ion/hw/CPU.inl>
#include <ion/util/Math.h>
#if ION_PLATFORM_MICROSOFT
	#include <timeapi.h>
#endif

namespace ion
{
TimeCaps::TimeCaps(TimeMS millis)
{
#if ION_PLATFORM_MICROSOFT

	UINT TARGET_RESOLUTION = static_cast<UINT>(millis);	 // target in milliseconds
	TIMECAPS tc;
	wTimerRes;
	[[maybe_unused]] auto res = timeGetDevCaps(&tc, sizeof(TIMECAPS));
	ION_ASSERT(res == TIMERR_NOERROR, "cannot get time caps");
	{
		wTimerRes = Min(Max(tc.wPeriodMin, TARGET_RESOLUTION), tc.wPeriodMax);
		timeBeginPeriod(wTimerRes);
	}
#endif
}

TimeCaps::~TimeCaps()
{
#if ION_PLATFORM_MICROSOFT
	timeEndPeriod(wTimerRes);
#endif
}
}  // namespace ion
