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
#include <ion/Base.h>
#include <cstdarg>
#include <fstream>
#include <sstream>
#include <ion/tracing/Log.h>

// #TODO: Replace with ion::Vector
#include <vector>

#if ION_PLATFORM_ANDROID
	#include <ion/byte/ByteBuffer.h>
#endif
#if !ION_PLATFORM_MICROSOFT
	#include <stdio.h>
#endif

namespace ion
{
class ByteReader;
namespace file_util
{
void ReplaceTargetFile(const char* target, ByteReader& inStream);
}
class Folder;
class FileIn
{
public:
	FileIn(const ion::Folder& folder, const char* target);

	FileIn(const char* target);

	bool Get(std::string&);

	bool GetAsVector(std::vector<uint8_t>& tmp);

	~FileIn();

private:
#if ION_PLATFORM_ANDROID
	ion::ByteBuffer<> mImpl;
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
		// mImpl.close();
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
