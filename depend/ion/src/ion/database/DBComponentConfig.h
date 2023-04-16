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
#include <ion/tracing/Log.h>

#ifndef ION_COMPONENT_VERSION_NUMBER
	#if ION_BUILD_DEBUG
		#define ION_COMPONENT_VERSION_NUMBER 1
	#else
		#define ION_COMPONENT_VERSION_NUMBER 0
	#endif
#endif

#ifndef ION_COMPONENT_READ_WRITE_CHECKS
	#define ION_COMPONENT_READ_WRITE_CHECKS ION_CONFIG_ERROR_CHECKING
#endif

#ifndef ION_COMPONENT_SUPPORT_CACHE_TRACKING
	#define ION_COMPONENT_SUPPORT_CACHE_TRACKING 0
#endif
