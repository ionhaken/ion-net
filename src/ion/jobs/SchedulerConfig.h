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
// Queue and thread limits.
// - Limit threads to prevent running out of TLS
// - Higher thread counts are not tested with real system
#if ION_PLATFORM_ANDROID
static constexpr UInt MaxQueues = 16;
static constexpr UInt MaxThreads = 16;
#else
static constexpr UInt MaxQueues = 128;
static constexpr UInt MaxThreads = MaxQueues * 2;
#endif
}  // namespace ion
