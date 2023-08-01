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

#if ION_EXTERNAL_SIMD == 1
	#pragma warning(push)
	#pragma warning(disable : 4244)
	#include <xsimd/xsimd.hpp>
	#pragma warning(pop)

//	#if (XSIMD_WITH_SSE2) || (XSIMD_WITH_NEON)
	#if (XSIMD_X86_INSTR_SET != XSIMD_VERSION_NUMBER_NOT_AVAILABLE) || (XSIMD_ARM_INSTR_SET != XSIMD_VERSION_NUMBER_NOT_AVAILABLE)
		#define ION_SIMD 1
	#else
		#define ION_SIMD 0
		#include <ion/util/Math.h>
	#endif
#else
	#define ION_SIMD 0
	#include <ion/util/Math.h>
#endif

namespace ion
{

template <typename T, typename U>
[[nodiscard]] inline U GetAsScalar(const T& t)
{
	return t;
}

template <typename U>
[[nodiscard]] inline U GetAsScalar(const float& t)
{
	return U(t);
}

}  // namespace ion

#if ION_EXTERNAL_SIMD == 1
	#define ION_BATCH_SIZE 4
#else
	#define ION_BATCH_SIZE 1
#endif
