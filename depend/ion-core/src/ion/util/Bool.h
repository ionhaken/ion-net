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

#include <ion/container/Array.h>

namespace ion
{

template <size_t N = 1>
class Bool
{
	using T = bool;

public:
	Bool() {}

	template <typename Other>
	Bool(const Other& other) : mValue(other)
	{
	}

	template <size_t... Is>
	Bool(std::initializer_list<T> il, std::index_sequence<Is...>) : mValue{{(il.begin()[Is])...}}
	{
	}

	//[[nodiscard]] constexpr T& Raw() { return mValue; }
	//[[nodiscard]] constexpr const T& Raw() const { return mValue; }

	[[nodiscard]] const bool& operator[](size_t index) const { return mValue[index]; }
	[[nodiscard]] bool& operator[](size_t index) { return mValue[index]; }

private:
	ion::Array<bool, N> mValue;
};

}  // namespace ion
