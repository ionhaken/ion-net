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
#include <SG14/inplace_function.h>
#include <iterator>

namespace ion
{

template <typename Function, size_t Capacity = 64, size_t Alignment = 16>
using InplaceFunction = stdext::inplace_function<Function, Capacity, Alignment>;

template <typename Iterator>
using InplaceIteratorFunction = InplaceFunction<void(typename std::iterator_traits<Iterator>::reference)>;

}  // namespace ion
