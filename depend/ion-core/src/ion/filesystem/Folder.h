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
#include <ion/memory/UniquePtr.h>

#include <ion/concurrency/Mutex.h>

#include <ion/core/Core.h>
#include <ion/filesystem/File.h>
#include <ion/string/String.h>

class FileContentJob;
class FileContentTracker;

namespace ion
{
struct PackIndex;
class DataProcessorRegistry;
class Folder
{
public:
	ION_CLASS_NON_COPYABLE(Folder);

	Folder(ion::StringView path);
	~Folder();

	Folder(Folder&& other) noexcept;

	Folder& operator=(Folder&& other) noexcept;

	bool IsAvailable() const;

	bool IsAvailable(ion::StringView filename) const;

	void SetPacked(ion::PackIndex&& index);

	class FileContentAccess
	{
	public:
		friend class Folder;
		~FileContentAccess();

	private:
		FileContentAccess(Folder& folder, FileContentTracker& content);
		Folder& mFolder;
		FileContentTracker& mContent;
	};

	FileContentAccess GetFileContent(ion::JobScheduler& js, ion::StringView view, FileJobCallback&& callback);

	ion::String FullPathTo(StringView target) const;

	void AllFiles(ion::Vector<ion::String>& files) const;

	static Folder FindFromTree(ion::String folder, UInt maxDepth = 5);

private:
	void OnContentAccessStarted(FileContentTracker& tracker);
	void OnContentAccessEnded(FileContentTracker& tracker);

#if (ION_ASSERTS_ENABLED == 1)
	bool HasOpenContent() const;
#endif

	ion::String mPath;
	ion::UniquePtr<ion::PackIndex> mPacked;

	struct FileReader
	{
		ION_CLASS_NON_COPYABLE(FileReader);

		FileReader();
		~FileReader();
		FileReader(FileReader&& other) noexcept;
		FileReader& operator=(FileReader&& other) noexcept;
		ion::UniquePtr<FileContentJob> mFileJob;
		ion::Vector<ion::UniquePtr<FileContentTracker>, CoreAllocator<ion::UniquePtr<FileContentTracker>>> mContents;
	};
	ion::Vector<FileReader> mFileReaders;
	ion::Mutex mMutex;
};

}  // namespace ion
