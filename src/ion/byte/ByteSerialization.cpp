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
#include <ion/byte/ByteSerialization.h>
#include <ion/string/String.h>

namespace ion::serialization
{

template <>
void Serialize(const String& src, ion::ByteWriter& writer)
{
	uint32_t length = ion::SafeRangeCast<uint32_t>(src.Length());
	writer.Write(length);
	writer.WriteArray(reinterpret_cast<const uint8_t*>(src.Data()), length);
}

template <>
bool Deserialize(String& dst, ion::ByteReader& reader, void*)
{
	uint32_t length = detail::DeserializeLength<uint32_t, char>(reader);
	ion::SmallVector<char, 64> buffer;
	buffer.Resize(length);
	if (!reader.ReadArray(reinterpret_cast<ion::u8*>(buffer.Data()), length))
	{
		return false;
	}
	dst = ion::String(buffer.Data(), length);
	return true;
}

}  // namespace ion::serialization
