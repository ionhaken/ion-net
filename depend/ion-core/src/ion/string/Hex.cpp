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
#include <ion/string/Hex.h>
#include <ion/container/Array.h>
#include <ion/util/Math.h>
#include <ion/util/SafeRangeCast.h>

#include <inttypes.h>

namespace ion::serialization
{
namespace
{
ion::Array<uint8_t, 256> gHex2Dec = {ion::MakeArray<uint8_t, 256>(
  [](auto number)
  {
	  if (number <= '9')
	  {
		  return uint8_t(number - '0');
	  }
	  if (number == 'A')
	  {
		  return uint8_t(10);
	  }
	  if (number == 'B')
	  {
		  return uint8_t(11);
	  }
	  if (number == 'C')
	  {
		  return uint8_t(12);
	  }
	  if (number == 'D')
	  {
		  return uint8_t(13);
	  }
	  if (number == 'E')
	  {
		  return uint8_t(14);
	  }
	  if (number == 'F')
	  {
		  return uint8_t(15);
	  };
	  return uint8_t(0);
  })};

constexpr uint8_t HexToDec(char number) { return gHex2Dec[number]; }
}  // namespace

template <>
void Deserialize(ion::Hex<uint8_t>& dst, StringReader& reader)
{
	dst.data = (16 * HexToDec(reader.Data()[0])) + (HexToDec(reader.Data()[1]));
}

template <>
void Deserialize(ion::Hex<uint32_t>& dst, StringReader& reader)
{
	dst.data = 0;
	for (size_t i = 0; i < 8; i++)
	{
		dst.data += ion::SafeRangeCast<uint32_t>(size_t(std::pow(16, 7 - i)) * size_t(HexToDec(reader.Data()[i])));
	}
}

template <>
void Deserialize(ion::HexArrayView<uint8_t>& dst, StringReader& reader)
{
	const char* src = reader.Data();
	auto iter = dst.Begin();
	while (iter != dst.End())
	{
		char buffer[2];
		if (*reader.Data() == 0)
		{
			break;
		}
		buffer[0] = *src;
		src++;
		if (*src == 0)
		{
			break;
		}
		buffer[1] = *src;
		src++;
		ion::Hex<uint8_t> v(0);

		StringReader bufferReader(buffer, 2);
		ion::serialization::Deserialize(v, bufferReader);
		*iter = v.data;
		iter++;
	}
}

template <>
ion::UInt Serialize(const ion::Hex<uint8_t>& src, StringWriter& writer)
{
	[[maybe_unused]] int len = snprintf(writer.Data(), writer.Available(), "%02X", src.data);
	ION_ASSERT(len <= int(writer.Available()), "Out of buffer");
	writer.Skip(2);
	return 2;
}

template <>
ion::UInt Serialize(const ion::Hex<uint32_t>& src, StringWriter& writer)
{
	[[maybe_unused]] int len = snprintf(writer.Data(), writer.Available(), "%08X", src.data);
	ION_ASSERT(len <= int(writer.Available()), "Out of buffer");
	writer.Skip(8);
	return 8;
}

template <>
ion::UInt Serialize(const ion::Hex<uint64_t>& src, StringWriter& writer)
{
	[[maybe_unused]] int len = snprintf(writer.Data(), writer.Available(), "%016" PRIx64, src.data);
	ION_ASSERT(len <= int(writer.Available()), "Out of buffer");
	writer.Skip(16);
	return 16;
}

template <>
ion::UInt Serialize(const ion::HexArrayView<const uint8_t>& src, StringWriter& writer)
{
	ion::UInt bufferPos = 0;
	for (auto iter = src.Begin(); iter != src.End(); ++iter)
	{
		ion::Hex<uint8_t> val(*iter);
		StringWriter other(&writer.Data()[bufferPos], writer.Available() - bufferPos);
		bufferPos += ion::serialization::Serialize(val, other);
	}
	writer.Skip(bufferPos);
	return bufferPos;
}

}  // namespace ion::serialization
