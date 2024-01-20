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
#include <ion/container/Vector.h>

#include <cstdarg>
#include <fstream>
#include <ion/Base.h>
#include <ion/tracing/Log.h>
#include <ion/util/InplaceFunction.h>
#include <sstream>

#if ION_PLATFORM_ANDROID
	#include <ion/byte/ByteBuffer.h>
#endif
#if !ION_PLATFORM_MICROSOFT
	#include <stdio.h>
#endif

#if ION_PLATFORM_ANDROID
struct AAssetManager;
struct AAsset;
#endif

namespace ion
{
class ByteReader;

using FileJobCallback = ion::InplaceFunction<void(ion::Vector<byte>&, size_t fileSize, size_t unpackedSize), 32, 8>;

namespace file_util
{

#if ION_PLATFORM_ANDROID
void SetAssetManager(AAssetManager* a);
#endif

void AllFiles(StringView path, ion::Vector<ion::String>& files);
void ReplaceTargetFile(StringView target, ByteReader& inStream);
void DeleteTargetFile(StringView fileStr);
ion::String WorkingDir();
bool IsPathAvailable(StringView str);
bool IsFileAvailable(StringView str);

}  // namespace file_util
class FileIn
{
public:
	FileIn(const char* target);

	bool Get(Vector<uint8_t>& tmp, size_t pos = 0, size_t len = 0);

	~FileIn();

private:
#if ION_PLATFORM_ANDROID
	AAsset* mImpl = nullptr;
#else
	std::ifstream mImpl;
#endif
};

class FileOut
{
public:
	enum class Mode : uint8_t
	{
		AppendText,
		AppendBinary,
		TruncateText,
		TruncateBinary
	};

	FileOut(const char* target, Mode mode = Mode::AppendText) : mImpl(nullptr)
	{
		switch (mode)
		{
		case Mode::AppendText:
			Open(target, "a");	// std::ios::out | std::ios::app);
			break;
		case Mode::AppendBinary:
			Open(target, "ab");
			// mImpl.open(target, std::ios::out | std::ios::app | std::ios::binary);
			break;
		case Mode::TruncateText:
			Open(target, "w");
			// mImpl.open(target, std::ios::out | std::ios::trunc);
			break;
		case Mode::TruncateBinary:
			Open(target, "wb");
			// mImpl.open(target, std::ios::out | std::ios::trunc | std::ios::binary);
			break;
		}
	}

	bool IsGood() const
	{
		return mImpl != nullptr;
		/*!mImpl.fail();*/
	}

	bool Write(const char* format);

	bool Write(const uint8_t* data, size_t len)
	{
		ION_ASSERT(mImpl, "File is not open for writing");
		// auto& stream = mImpl.write(reinterpret_cast<const char*>(data), len);
		return fwrite(data, sizeof(uint8_t), len, mImpl) == len;
		// return stream.good();
	}

	void WriteFormat(const char* format, ...)
	{
		const size_t maxLen = 1024;
		char buffer[maxLen];
		va_list arglist;
		va_start(arglist, format);
		vsnprintf(buffer, maxLen, format, arglist);
		va_end(arglist);
		Write(buffer);
		// mImpl << buffer;
	}

	~FileOut()
	{
		if (mImpl)
		{
			fclose(mImpl);
		}
	}

	// std::ofstream mImpl;
	FILE* mImpl;

private:
	void Open(const char* filename, const char* mode)
	{
		ION_ASSERT(mImpl == nullptr, "File already open");
#if ION_PLATFORM_MICROSOFT
		fopen_s(&mImpl, filename, mode);
#else
		mImpl = fopen(filename, mode);
#endif
	}
};
}  // namespace ion
