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
#include <ion/byte/ByteReader.h>
#include <ion/filesystem/File.h>
#include <ion/filesystem/Folder.h>

#include <stdio.h>
#include <string.h>

void ion::file_util::ReplaceTargetFile(const char* target, ion::ByteReader& inStream)
{
	if (inStream.Available() > 0)
	{
		ion::StackStringFormatter<256> tmpFile;
		tmpFile.Format("%s.tmp", target);
		{
			bool isOk = false;
			{
				ion::FileOut file(tmpFile.CStr(), ion::FileOut::Mode::TruncateBinary);
				if (!file.IsGood())
				{
					ION_ABNORMAL("Cannot open temporary file " << tmpFile.CStr());
					return;
				}
				isOk = file.Write(&inStream.ReadAssumeAvailable<uint8_t>(), inStream.Available());
			}
			if (isOk)
			{
				ion::Folder::Replace(tmpFile.CStr(), target);
			}
			else
			{
				ION_ABNORMAL("Cannot write " << target);
			}
		}
	}
}

ion::FileIn::FileIn(const ion::Folder& folder, const char* target)
{
#if ION_PLATFORM_ANDROID
	folder.GetContents(target, mImpl);
#else
	auto fullFileName = folder.FullPathTo(target);
	mImpl = std::ifstream(fullFileName.CStr(), std::ios::in | std::ios::binary);
#endif
}

ion::FileIn::FileIn([[maybe_unused]] const char* fullFileName)
{
#if ION_PLATFORM_ANDROID
	ION_ASSERT(false, "Folder required");
#else
	mImpl = std::ifstream(fullFileName, std::ios::in | std::ios::binary);
#endif
}

bool ion::FileIn::Get(std::string& tmp)
{
#if ION_PLATFORM_ANDROID
	ion::ByteReader reader(mImpl);
	while (reader.Available())
	{
		char c = reader.ReadAssumeAvailable<uint8_t>();
		// if (c != '\n' && c != '\r')
		{
			if (c == 0)
			{
				break;
			}
			tmp = tmp + c;
		}
	}
	return !tmp.empty();
#else
	if (mImpl)
	{
		tmp = (std::string((std::istreambuf_iterator<char>(mImpl)), std::istreambuf_iterator<char>()));
		return !tmp.empty();
	}
	return false;
#endif
}

bool ion::FileIn::GetAsVector(std::vector<uint8_t>& tmp)
{
#if ION_PLATFORM_ANDROID
	ion::ByteReader reader(mImpl);
	while (reader.Available())
	{
		uint8_t c = reader.ReadAssumeAvailable<uint8_t>();
		tmp.emplace_back(c);
	}
	return !tmp.empty();
#else
	if (mImpl)
	{
		tmp = std::vector<uint8_t>(std::istreambuf_iterator<char>(mImpl), {});
		return !tmp.empty();
	}
	return false;
#endif
}

ion::FileIn::~FileIn()
{
#if ION_PLATFORM_MICROSOFT
	mImpl.close();
#endif
}

bool ion::FileOut::Write(const char* format)
{
	ION_ASSERT(mImpl, "File is not open for writing");
	size_t len = strlen(format);
	return fwrite(format, sizeof(uint8_t), len, mImpl) == len;
}
