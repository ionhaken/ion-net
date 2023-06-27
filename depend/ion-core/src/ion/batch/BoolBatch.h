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
#include <ion/hw/SIMD.h>
#include <ion/util/Bool.h>

namespace ion
{
template <typename Type = float>
class RawBoolBatch
{
#if ION_SIMD
	using T = xsimd::batch_bool<Type, ION_BATCH_SIZE>;
#else
	using T = ion::Bool<ION_BATCH_SIZE>;
#endif
public:
	constexpr RawBoolBatch() {}

	template <typename Other>
	constexpr RawBoolBatch(const Other& other) : mValue(other)
	{
	}

	template <size_t... Is>
	constexpr RawBoolBatch(std::initializer_list<Type> il, std::index_sequence<Is...>) : mValue{{(il.begin()[Is])...}}
	{
	}
	[[nodiscard]] constexpr T& Raw() { return mValue; }
	[[nodiscard]] constexpr const T& Raw() const { return mValue; }

	[[nodiscard]] inline bool operator[](size_t index) const { return /*mValue.get(index)*/ mValue[index]; }

private:
	ION_ALIGN(alignof(T)) T mValue;
};

}  // namespace ion
