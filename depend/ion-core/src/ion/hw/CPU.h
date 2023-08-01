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

namespace ion
{
#ifdef ION_ARCH_X86
inline bool CPUHasSSE2Enabled() { return true; }
bool CPUHasAVXEnabled();
	#define ION_CPU_SSE2_ASSUMED 1
#else
	#define ION_CPU_SSE2_ASSUMED 0
#endif

#ifdef ION_ARCH_ARM_64
	#define ION_CPU_NEON_ASSUMED 1
inline bool CPUHasNeonEnabled() { return true; }
#else
	#define ION_CPU_NEON_ASSUMED 0
	#ifdef ION_ARCH_ARM_32
bool CPUHasNeonEnabled();
	#endif
#endif

}  // namespace ion
