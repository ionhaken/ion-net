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
#include <stddef.h>
#include <ion/Base.h>

namespace ion
{
namespace detail
{
size_t EncodedLength(size_t length_in);
size_t DecodedLength(const char* code_in, size_t length_in);
size_t Base64Encode(const unsigned char* data_in, size_t length_in, char* bufferOut);
size_t Base64Decode(const char* code_in, size_t length_in, unsigned char* bufferOut);
}  // namespace detail

inline size_t Base64Encode(const unsigned char* data_in, size_t length_in, char* bufferOut, size_t bufferSize)
{
	size_t encodedLength = detail::EncodedLength(length_in);
	return encodedLength <= bufferSize ? detail::Base64Encode(data_in, length_in, bufferOut) : 0;
}

inline size_t Base64Decode(const char* code_in, size_t length_in, unsigned char* bufferOut, size_t bufferSize)
{
	size_t decodeLength = detail::DecodedLength(code_in, length_in);
	return decodeLength <= bufferSize ? detail::Base64Decode(code_in, length_in, bufferOut) : 0;
}

template <typename Buffer>
inline size_t Base64Encode(const unsigned char* data_in, size_t length_in, Buffer& buffer)
{
	size_t encodedLength = detail::EncodedLength(length_in);
	buffer.Resize(encodedLength);
	size_t len = detail::Base64Encode(data_in, length_in, buffer.Data());
	buffer.Resize(len);
	return len;
}

template <typename Buffer>
inline size_t Base64Decode(const char* code_in, size_t length_in, Buffer& buffer)
{
	size_t decodedLength = detail::DecodedLength(code_in, length_in);
	buffer.Resize(decodedLength);
	size_t len = detail::Base64Decode(code_in, length_in, buffer.Data());
	buffer.Resize(len);
	return len;
}

}  // namespace ion
