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
class CRC32Context
{
public:
	CRC32Context()
	{
		for (uint32_t i = 0; i < table.Size(); ++i)
		{
			table[i] = CRC32ForByte(i);
		}
	}

	ion::Array<uint32_t, 0x100> table;

private:
	uint32_t CRC32ForByte(uint32_t r)
	{
		for (int j = 0; j < 8; ++j)
		{
			r = (r & 1 ? 0 : (uint32_t)0xEDB88320L) ^ r >> 1;
		}
		return r ^ (uint32_t)0xFF000000L;
	}
};

class CRC32
{
public:
	CRC32(CRC32Context& context) : m_context(context) {}

	template <typename T>
	inline void Add(const T& val)
	{
		Add(reinterpret_cast<const uint8_t*>(&val), sizeof(T));
	}

	inline void Add(const uint8_t* data, size_t length)
	{
		const uint8_t* end = data + length;
		do
		{
			m_crc = m_context.table[static_cast<const uint8_t>(m_crc) ^ *data] ^ m_crc >> 8;
			data++;
		} while (data != end);
	}

	inline uint32_t UInt32() const { return m_crc; }

	void Reset() { m_crc = 0; }

private:
	CRC32Context& m_context;
	uint32_t m_crc = 0;
};
}  // namespace ion
