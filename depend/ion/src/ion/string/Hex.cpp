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
void Deserialize(ion::Hex<uint8_t>& dst, const char* src, void*)
{
	dst.data = (16 * HexToDec(src[0])) + (HexToDec(src[1]));
}

template <>
void Deserialize(ion::Hex<uint32_t>& dst, const char* src, void*)
{
	dst.data = 0;
	for (size_t i = 0; i < 8; i++)
	{
		dst.data += ion::SafeRangeCast<uint32_t>(size_t(std::pow(16, 7 - i)) * size_t(HexToDec(src[i])));
	}
}

template <>
void Deserialize(ion::HexArrayView<uint8_t>& dst, const char* src, void*)
{
	auto iter = dst.Begin();
	while (iter != dst.End())
	{
		char buffer[2];
		if (*src == 0)
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
		ion::serialization::Deserialize(v, buffer, nullptr);
		*iter = v.data;
		iter++;
	}
}

template <>
ion::UInt Serialize(const ion::Hex<uint8_t>& src, char* buffer, [[maybe_unused]] size_t bufferLen, const void*)
{
	[[maybe_unused]] int len = snprintf(buffer, bufferLen, "%02X", src.data);
	ION_ASSERT(len <= int(bufferLen), "Out of buffer");
	return 2;
}

template <>
ion::UInt Serialize(const ion::Hex<uint32_t>& src, char* buffer, [[maybe_unused]] size_t bufferLen, const void*)
{
	[[maybe_unused]] int len = snprintf(buffer, bufferLen, "%08X", src.data);
	ION_ASSERT(len <= int(bufferLen), "Out of buffer");
	return 8;
}

template <>
ion::UInt Serialize(const ion::Hex<uint64_t>& src, char* buffer, [[maybe_unused]] size_t bufferLen, const void*)
{
	[[maybe_unused]] int len = snprintf(buffer, bufferLen, "%016" PRIx64, src.data);
	ION_ASSERT(len <= int(bufferLen), "Out of buffer");
	return 16;
}

template <>
ion::UInt Serialize(const ion::HexArrayView<const uint8_t>& src, char* buffer, [[maybe_unused]] size_t bufferLen, const void*)
{
	ion::UInt bufferPos = 0;
	for (auto iter = src.Begin(); iter != src.End(); ++iter)
	{
		ion::Hex<uint8_t> val(*iter);
		bufferPos += ion::serialization::Serialize(val, &buffer[bufferPos], bufferLen - bufferPos, nullptr);
	}
	ION_ASSERT(bufferPos <= bufferLen, "Out of buffer");
	return bufferPos;
}

}  // namespace ion::serialization
