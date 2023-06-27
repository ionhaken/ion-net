/*
 * Copyright 2015-2022 Markus Haikonen, Ionhaken
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
#include <ion/filesystem/File.h>
#include <ion/byte/ByteBuffer.h>
#include <ion/byte/ByteReader.h>
#include <ion/filesystem/Folder.h>

class CodegenFile
{
	ion::String mFilename;
	ion::ByteBuffer<> mBuffer;

public:
	CodegenFile(const char* str) : mFilename(str) { mBuffer.Reserve(16 * 1024); }

	void Write(char str)
	{
		ion::ByteWriter writer(mBuffer);
		writer.Write(str);
	}

	void Write(const char* str)
	{
		auto len = ion::SafeRangeCast<ion::ByteSizeType>(strlen(str));
		ion::ByteWriter writer(mBuffer);
		for (size_t i = 0; i < len; ++i)
		{
			writer.Write(str[i]);
		}
	}

	virtual ~CodegenFile()
	{
		bool hasChanged = false;
		{
			ion::FileIn in(mFilename.CStr());
			std::vector<uint8_t> oldBuffer;
			if (in.GetAsVector(oldBuffer))
			{
				ion::ByteReader reader(mBuffer);
				size_t i = 0;
				while (i < oldBuffer.size())
				{
					if (reader.Available() == 0)
					{
						ION_DBG("Old file has more data");
						hasChanged = true;
						break;
					}
					auto next = reader.ReadAssumeAvailable<uint8_t>();
					if (next != oldBuffer[i])
					{
						ION_DBG("File has changed at " << i);
						hasChanged = true;
						break;
					}
					++i;
				}
				if (!hasChanged && reader.Available() > 0)
				{
					ION_DBG("New file has more data");
					hasChanged = true;
				}
			}
			else
			{
				ION_DBG("First time to generate this file");
				hasChanged = true;
			}
		}

		if (hasChanged)
		{
			ION_LOG_INFO("Updating file: " << mFilename);
			ion::ByteReader reader(mBuffer);
			ion::file_util::ReplaceTargetFile(mFilename.CStr(), reader);
		}
		else
		{
			ION_DBG("File not changed: " << mFilename);
		}
	}
};
