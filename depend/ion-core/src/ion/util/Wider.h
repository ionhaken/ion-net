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
template <typename T>
struct Wider
{
};

template <>
struct Wider<int8_t>
{
	using type = int16_t;
};
template <>
struct Wider<uint8_t>
{
	using type = uint16_t;
};

template <>
struct Wider<int16_t>
{
	using type = int32_t;
};
template <>
struct Wider<uint16_t>
{
	using type = uint32_t;
};

template <>
struct Wider<int32_t>
{
	using type = int64_t;
};
template <>
struct Wider<uint32_t>
{
	using type = uint64_t;
};

template <>
struct Wider<float>
{
	using type = double;
};
template <>
struct Wider<double>
{
	using type = long double;
};

}  // namespace ion
