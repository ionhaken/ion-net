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
#include <ion/string/String.h>
#include <ion/string/StringFormatter.h>
#include <stdio.h>
#include <string.h>

#if ION_PLATFORM_MICROSOFT
	#define WIN32_LEAN_AND_MEAN
	#include <Windows.h>
	#include <direct.h>
#elif ION_PLATFORM_ANDROID
	#include <android/asset_manager.h>
	#include <sys/stat.h>
#else
	#include <sys/stat.h>
#endif
#if ION_PLATFORM_ANDROID
static AAssetManager* gAssetmanager = nullptr;
#endif

#if ION_PLATFORM_LINUX
	#include <unistd.h>
	#include <stdio.h>
	#include <limits.h>
#endif

#include <filesystem>

namespace ion::file_util
{
namespace
{
void Replace([[maybe_unused]] const char* sourceCstr, [[maybe_unused]] const char* destCstr)
{
#if ION_PLATFORM_MICROSOFT
	auto source = ion::String(sourceCstr).WStr();
	auto dest = ion::String(destCstr).WStr();
	auto fSuccess = MoveFileExW(source.get(), dest.get(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);
	if (fSuccess == 0)
	{
		ION_ABNORMAL("Move " << sourceCstr << " to " << destCstr << " failed: " << ion::debug::GetLastErrorString());
	}
#elif ION_PLATFORM_ANDROID
	ION_ASSERT(false, "not implemented for this platform");
#else
	int ret = rename(sourceCstr, destCstr);
	if (ret != 0)
	{
		ION_ABNORMAL("Move " << sourceCstr << " to " << destCstr << " failed: " << strerror(ret));
	}
#endif

}

}  // namespace

void AllFiles(StringView path, ion::Vector<ion::String>& files)
{
	size_t pathLength = path.Length() + 1;

	for (std::filesystem::recursive_directory_iterator i(path.CStr()), end; i != end; ++i)
	{
		if (!is_directory(i->path()))
		{
			files.Add(&i->path().string().c_str()[pathLength]);
		}
	}
}

namespace
{
enum class Availability
{
	None,
	File,
	Directory
};

Availability IsAvailable(ion::StringView str)
{
#if ION_PLATFORM_MICROSOFT
	ion::String path(str);
	auto widestring = path.WideString();
	LPCTSTR szPath = widestring.c_str();
	DWORD dwAttrib = GetFileAttributes(szPath);

	if (dwAttrib != INVALID_FILE_ATTRIBUTES)
	{
		if (dwAttrib & FILE_ATTRIBUTE_DIRECTORY)
		{
			return Availability::Directory;
		}
		return Availability::File;
	}
	return Availability::None;
#else
	struct stat stats;
	if (stat(str.CStr(), &stats) != 0)
	{
		if (S_ISDIR(stats.st_mode))	 // Check for file existence
		{
			return Availability::Directory;
		}
		return Availability::File;
	}
	return Availability::None;
#endif
}
}

bool IsFileAvailable(StringView str) { return IsAvailable(str) == Availability::File; }

bool IsPathAvailable(ion::StringView str) { return IsAvailable(str) == Availability::Directory; }


ion::String WorkingDir()
{
#if ION_PLATFORM_MICROSOFT
	constexpr size_t PathMaxLength = ion::Max(MAX_PATH, 4096);
	char buffer[PathMaxLength];
	if (_getcwd(buffer, PathMaxLength) != nullptr)
	{
		return ion::String(buffer);
	}
#elif ION_PLATFORM_LINUX
	constexpr size_t PathMaxLength = ion::Max(PATH_MAX, 4096);
	char buffer[PathMaxLength];
	if (getcwd(buffer, PathMaxLength) != nullptr)
	{
		return ion::String(buffer);
	}
#endif
#if ION_PLATFORM_ANDROID
	return ion::String();
#else
	ION_ABNORMAL("Cannot get working directoy");
	return ion::String(".");
#endif
}

#if ION_PLATFORM_ANDROID
void SetAssetManager(AAssetManager* a) { gAssetmanager = a; }
#endif

void ReplaceTargetFile(StringView target, ion::ByteReader& inStream)
{
	if (inStream.Available() > 0)
	{
		ion::StackStringFormatter<256> tmpFile;
		tmpFile.Format("%s.tmp", target.CStr());
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
				Replace(tmpFile.CStr(), target.CStr());
			}
			else
			{
				ION_ABNORMAL("Cannot write " << target);
			}
		}
	}
}
void DeleteTargetFile(StringView fileStr)
{
#if ION_PLATFORM_MICROSOFT
	auto source = ion::String(fileStr).WStr();
	auto fSuccess = DeleteFile(source.get());
	if (fSuccess == 0)
	{
		ION_LOG_INFO("Delete " << fileStr << " failed: " << ion::debug::GetLastErrorString());
	}
#else
	ION_ASSERT(false, "not implemented for this platform");
#endif
}

}  // namespace ion::file_util

ion::FileIn::FileIn([[maybe_unused]] const char* fullFileName)
  :
#if ION_PLATFORM_ANDROID
	mImpl(AAssetManager_open(gAssetmanager, fullFileName, AASSET_MODE_BUFFER))
#else
	mImpl(std::ifstream(fullFileName, std::ios::in | std::ios::binary))
#endif

{
}

bool ion::FileIn::Get(Vector<uint8_t>& tmp, size_t pos, size_t size)
{
	if (!mImpl)
	{
		return false;
	}
#if ION_PLATFORM_ANDROID
	if (size == 0)
	{
		size = AAsset_getLength(mImpl);
	}
	off_t newPos = AAsset_seek(mImpl, pos, SEEK_SET /* Beginning of file */);
	if (newPos == -1)
	{
		ION_ABNORMAL("Seek failed to position " << pos);
		return false;
	}
#else
	if (size == 0)
	{
		mImpl.seekg(0, mImpl.end);
		size = mImpl.tellg();
	}
	mImpl.seekg(pos, mImpl.beg);
#endif
	const uint32_t MaxSize = 32 * 1024 * 1024;
	if (size > MaxSize)
	{
		ION_ABNORMAL("Unexpected resource size: " << size);
		return false;
	}

	tmp.Reserve(size_t(size) + 1u);	 // For potential null char for text streams
	tmp.ResizeFastKeepCapacity(size_t(size));

#if ION_PLATFORM_ANDROID
	auto readsize = AAsset_read(mImpl, tmp.Data(), size);
#else
	mImpl.read((char*)tmp.Data(), size_t(size));
	auto readsize = mImpl.gcount();
#endif
	if (size_t(readsize) != size)
	{
		ION_DBG("File read got " << readsize << " bytes, expected " << size << " bytes");
		tmp.ResizeFast(readsize);
		if (readsize < 0)  // not error code
		{
			ION_ABNORMAL("Read failed;readsize=" << readsize);
		}
	}
	return !tmp.empty();

}

ion::FileIn::~FileIn()
{
	ION_MEMORY_SCOPE(ion::tag::External);
#if ION_PLATFORM_ANDROID
	if (mImpl)
	{
		AAsset_close(mImpl);
	}
#else
	mImpl.close();
#endif
}

bool ion::FileOut::Write(const char* format)
{
	ION_ASSERT(mImpl, "File is not open for writing");
	size_t len = strlen(format);
	return fwrite(format, sizeof(uint8_t), len, mImpl) == len;
}
