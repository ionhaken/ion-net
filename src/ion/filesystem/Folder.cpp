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
#include <ion/byte/ByteBuffer.h>
#include <ion/core/Core.h>
#include <ion/filesystem/Folder.h>
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

#include <ion/byte/ByteWriter.h>
#include <ion/string/String.h>

#if ION_PLATFORM_ANDROID
static AAssetManager* gAssetmanager = nullptr;
#endif

#if ION_PLATFORM_LINUX
	#include <unistd.h>
	#include <stdio.h>
	#include <limits.h>
#endif

namespace
{
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
}  // namespace

#if ION_PLATFORM_ANDROID
void ion::Folder::SetAssetManager(AAssetManager* a) { gAssetmanager = a; }
#endif

bool ion::Folder::IsAvailable() const
{
#if ION_PLATFORM_MICROSOFT
	auto widestring = mPath.WideString();
	LPCTSTR szPath = widestring.c_str();
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
#else
	struct stat stats;
	stat(mPath.CStr(), &stats);
	if (S_ISDIR(stats.st_mode))	 // Check for file existence
	{
		return true;
	}
	return false;
#endif
}

ion::Folder::Folder(const ion::String& path) : mPath(path) {}

ion::Folder ion::Folder::FindFromTree(ion::String path, UInt maxDepth)
{
	ion::Folder folder(path);
	if (!folder.IsAvailable())
	{
		auto dir = WorkingDir();
		do
		{
			auto fullPath = dir + "/" + path;
			ion::Folder other = ion::Folder(fullPath);
			if (other.IsAvailable())
			{
				return other;
			}
			dir = dir + "/..";
		} while (--maxDepth > 0);
	}
	else
	{
		folder = ion::Folder(WorkingDir() + "/" + path);
	}
	return folder;
}

ion::String ion::Folder::FullPathTo(const ion::String& target) const
{
#if ION_PLATFORM_ANDROID
	return target;
#else
	auto dir = mPath;
	dir = dir + "/" + target;
	return dir;
#endif
}

void ion::Folder::Replace([[maybe_unused]] const char* sourceCstr, [[maybe_unused]] const char* destCstr)
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

void ion::Folder::Delete(const char* fileStr)
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

#if ION_PLATFORM_ANDROID
void ion::Folder::GetContents(const ion::String& filename, ion::ByteBuffer<>& buffer) const
{
	ion::String fullPath = FullPathTo(filename);

	// ION_ASSERT(fullPath[0] != '/', "Not supported reading system files");

	ION_ASSERT(gAssetmanager, "No asset manager");

	AAsset* asset = AAssetManager_open(gAssetmanager, fullPath.CStr(), AASSET_MODE_BUFFER);
	if (nullptr == asset)
	{
		ION_ABNORMAL("Asset not found:" << fullPath.CStr());
		return;
	}
	ION_DBG("ion::Folder::GetContents: " << fullPath.CStr());

	auto size = AAsset_getLength(asset);
	const uint32_t MaxSize = 1024 * 1024;
	if (size <= MaxSize)
	{
		buffer.Reserve(SafeRangeCast<uint32_t>(size));
		int readsize;
		{
			ByteWriter writer(buffer);
			readsize = AAsset_read(asset, &writer.WriteArrayKeepCapacity<char>(size), size);
			ION_DBG("ReadSize=" << readsize << " total size=" << size);
		}
		if (readsize < size)
		{
			if (readsize >= 0)	// not error code
			{
				buffer.Reserve(readsize);
			}
			ION_ABNORMAL("Read failed;readsize=" << readsize);
		}
	}
	else
	{
		ION_ABNORMAL("Unexpected resource size: " << size);
	}
	AAsset_close(asset);
}
#endif
