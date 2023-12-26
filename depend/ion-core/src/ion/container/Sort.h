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
#include <timsort/include/gfx/timsort.hpp>

namespace ion
{
template <typename Iterator>
inline void Sort(Iterator first, Iterator last)
{
	// Cannot use std::sort, because we need similar behaviour in all platforms,
	// but clang and MSVC do std::sort differently.
	gfx::timsort(first, last);
}
template <typename Iterator, typename Callback>
inline void Sort(Iterator first, Iterator last, Callback&& callback)
{
	gfx::timsort(first, last, std::forward<Callback&&>(callback));
}

}  // namespace ion
