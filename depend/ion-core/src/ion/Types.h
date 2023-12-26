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

//
// Basic types and type traits used by ion library.
//

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ion/Base.h>
#if ION_PLATFORM_MICROSOFT
	#include <cstdarg>
#endif

using byte = unsigned char;

namespace ion
{
using u8 = uint8_t;
using i8 = int8_t;
using i16 = int16_t;
using u16 = uint16_t;
using i32 = int32_t;
using u32 = uint32_t;
using f32 = float;
using f64 = double;
using UInt = unsigned int;
using Int = int;

template <class value_type, value_type __value>
struct IntegralConstant
{
	static constexpr value_type value = __value;

	using ValueType = value_type;
	using Type = IntegralConstant;

	constexpr operator ValueType() const noexcept { return value; }

	[[nodiscard]] constexpr ValueType operator()() const noexcept { return value; }
};

template <bool _Val>
using bool_constant = IntegralConstant<bool, _Val>;

using true_type = bool_constant<true>;
using false_type = bool_constant<false>;

template <typename>
struct IsArray : false_type
{
};

template <typename>
struct IsFixedArray : false_type
{
};

template <class type>
struct IsConst : IntegralConstant<bool, false>
{
};
template <class type>
struct IsConst<const type> : IntegralConstant<bool, true>
{
};

}  // namespace ion

// Forward declarations for common types
namespace ion
{
template <typename TData, typename TSize = uint32_t>
struct ArrayView;

template <size_t, typename Allocator>
class ByteBuffer;
class ByteWriter;
class ByteReader;
class Folder;

template <typename T>
class GlobalAllocator;

class JobGroup;
class JobScheduler;

class JSONDocument;
class JSONStructReader;
class JSONStructWriter;

class Mailbox;
class MailRegistry;

template <typename T>
class Ptr;

template <typename T, typename Allocator>
class SPSCQueue;

class String;

template <typename T, size_t N>
struct Vec;

template <typename T>
using Vec2 = Vec<T, 2>;

using Vec2f = Vec<float, 2>;

template <typename TValue, typename TSize = uint32_t>
struct MultiData;

template <typename TValue, typename TAllocator, typename CountType, size_t SmallBufferSize, size_t TinyBufferSize>
class Vector;

template <typename TKey, typename TValue, typename THasher, typename Allocator>
class UnorderedMap;

}  // namespace ion
