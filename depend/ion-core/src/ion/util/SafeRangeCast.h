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
#include <ion/debug/Error.h>
#include <type_traits>

namespace ion
{

template <typename TOut, typename TIn>
inline constexpr TOut SafeRangeCast(const TIn& input)
{
	if constexpr (std::is_signed<TIn>::value && std::is_signed<TOut>::value)
	{
		ION_ASSERT_FMT_IMMEDIATE(static_cast<TOut>(input) == input, "Signed value cast failed");
		return static_cast<TOut>(input);
	}
	else if constexpr (std::is_signed<TIn>::value)
	{
		ION_PRAGMA_WRN_PUSH;
		ION_PRAGMA_WRN_IGNORE_SIGNED_UNSIGNED_MISMATCH;
		ION_ASSERT_FMT_IMMEDIATE(static_cast<TOut>(input) == input, "Cast from signed to unsigned failed");
		ION_PRAGMA_WRN_POP;
		return static_cast<TOut>(input);
	}
	else if constexpr (std::is_signed<TOut>::value)
	{
		ION_PRAGMA_WRN_PUSH;
		ION_PRAGMA_WRN_IGNORE_SIGNED_UNSIGNED_MISMATCH;
		ION_ASSERT_FMT_IMMEDIATE(static_cast<TOut>(input) == input, "Cast from unsigned to signed failed");
		ION_PRAGMA_WRN_POP;
		return static_cast<TOut>(input);
	}
	else
	{
		ION_ASSERT_FMT_IMMEDIATE(static_cast<TOut>(input) == input, "Unsigned value cast failed");
		return static_cast<TOut>(input);
	}
}

}  // namespace ion
