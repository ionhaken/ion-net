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
#include <ion/container/ArrayView.h>
#include <ion/string/String.h>

namespace ion
{
template <typename T>
struct Hex
{
	constexpr Hex(const T& in) : data(in) {}
	constexpr Hex(const Hex<T>& other) : data(other.data) {}
	T data;
};

template <typename T>
struct HexArrayView : public ArrayView<T, uint32_t>
{
	HexArrayView(T* const data, const uint32_t length) : ArrayView<T, uint32_t>(data, length) {}
};

}  // namespace ion

namespace ion::serialization
{
template <>
void Deserialize(ion::Hex<uint8_t>& dst, StringReader& reader);

template <>
void Deserialize(ion::Hex<uint32_t>& dst, StringReader& reader);

template <>
void Deserialize(ion::HexArrayView<uint8_t>& dst, StringReader& reader);

template <>
ion::UInt Serialize(const ion::Hex<uint8_t>& src, StringWriter& writer);

template <>
ion::UInt Serialize(const ion::Hex<uint32_t>& src, StringWriter& writer);

template <>
ion::UInt Serialize(const ion::Hex<uint64_t>& src, StringWriter& writer);

template <>
ion::UInt Serialize(const ion::HexArrayView<const uint8_t>& src, StringWriter& writer);

}  // namespace ion::serialization
