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

#include <ion/filesystem/File.h>
#include <ion/memory/UniquePtr.h>

namespace ion
{
namespace tracing
{
class Logger;
extern Logger* gGlobalLogger;

class Logger
{
public:
	Logger(const char* filename)
	{
		ion::TracingInit();
		ION_ASSERT(gGlobalLogger == nullptr, "Duplicate logger");
		mOutputFile = ion::MakeUnique<ion::FileOut>(filename, ion::FileOut::Mode::TruncateText);
		if (!mOutputFile->IsGood())
		{
			mOutputFile = nullptr;
		}
		ion::tracing::SetOutputFile(mOutputFile.get());
		gGlobalLogger = this;
	}

	void Reset()
	{
		if (mOutputFile)
		{
			ion::tracing::SetOutputFile(nullptr);
			mOutputFile = nullptr;
		}
	}

	~Logger()
	{
		Reset();
		ION_ASSERT(gGlobalLogger == this, "Global logger corrupted");
		gGlobalLogger = nullptr;
		ion::TracingDeinit();
	}

private:
	ion::UniquePtr<ion::FileOut> mOutputFile;
};
}  // namespace tracing
}  // namespace ion
