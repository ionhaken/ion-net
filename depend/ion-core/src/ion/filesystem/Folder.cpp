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
#include <ion/container/ForEach.h>

#include <ion/concurrency/ThreadSynchronizer.h>

#include <ion/byte/ByteBuffer.h>
#include <ion/byte/ByteWriter.h>
#include <ion/core/Core.h>
#include <ion/filesystem/File.h>
#include <ion/filesystem/FileContentJob.h>
#include <ion/filesystem/FileContentTracker.h>
#include <ion/filesystem/Folder.h>
#include <ion/string/String.h>
#include <ion/filesystem/PackIndex.h>


namespace ion::filesystem
{
// Remote \\ from windows file paths
ion::String SanitizePath(ion::StringView path)
{
#if ION_PLATFORM_MICROSOFT
	ion::SmallVector<char, 256> buffer;
	buffer.Reserve(path.Length() + 1);

	for (size_t i = 0; i < path.Length(); ++i)
	{
		if (path.CStr()[i] == '\\')
		{
			buffer.Add('/');
		}
		else
		{
			buffer.Add(path.CStr()[i]);
		}
	}
	buffer.Add(0);
	ion::String output(buffer.Data(), buffer.Size() - 1);
	return output;
#else
	return path;
#endif
}
}

ion::Folder::Folder(ion::StringView path) : mPath(ion::filesystem::SanitizePath(path)) {}

bool ion::Folder::IsAvailable() const { return mPacked ? true : ion::file_util::IsPathAvailable(mPath); }

void ion::Folder::AllFiles(ion::Vector<ion::String>& files) const { ion::file_util::AllFiles(mPath, files); }

ion::Folder ion::Folder::FindFromTree(ion::String path, UInt maxDepth)
{
	ion::Folder folder(path);
	if (!file_util::IsPathAvailable(path))
	{
		auto dir = file_util::WorkingDir();
		do
		{
			auto fullPath = dir + "/" + path;
			ion::Folder other(fullPath);
			if (file_util::IsPathAvailable(fullPath))
			{
				return other;
			}
			dir = dir + "..";
		} while (--maxDepth > 0);
	}
	else
	{
		folder = std::move(ion::Folder(file_util::WorkingDir() + path));
	}
	return folder;
}

bool ion::Folder::IsAvailable(ion::StringView filename) const
{
	if (mPacked)
	{
		auto idToFileInfoIter = mPacked->mIdToFileInfo.Find(filename);
		if (idToFileInfoIter != mPacked->mIdToFileInfo.End())
		{
			return true;
		}
	}
	return file_util::IsFileAvailable(FullPathTo(filename));
}

ion::String ion::Folder::FullPathTo(ion::StringView target) const
{
	ion::String tmp = target;
	if (mPacked)
	{
		auto idToFileInfoIter = mPacked->mIdToFileInfo.Find(target);
		if (idToFileInfoIter != mPacked->mIdToFileInfo.End())
		{
			tmp = mPacked->mPackFiles[idToFileInfoIter->second.mPackFileIndex];
		}
	}
#if ION_PLATFORM_ANDROID
	return tmp;
#else
	auto dir = mPath;
	if (dir.Length() > 0 && dir[dir.Length() - 1] != '/')
	{
		dir = dir + "/";
	}
	dir = dir + tmp;
	return dir;
#endif
}

void ion::Folder::SetPacked(ion::PackIndex&& index)
{
	mPacked = ion::MakeUnique<ion::PackIndex>(std::move(index));
	mFileReaders.Resize(mPacked->mPackFiles.Size() + 1);
}
void ion::Folder::OnContentAccessStarted(FileContentTracker& tracker)
{
	// Assume locked.
	tracker.mNumActiveRequests++;
}

void ion::Folder::OnContentAccessEnded(FileContentTracker& tracker)
{
	AutoLock<Mutex> lock(mMutex);
	--tracker.mNumActiveRequests;
	if (tracker.mNumActiveRequests != 0)
	{
		return;
	}
	for (size_t i = 0; i < mFileReaders.Size(); ++i)
	{
		for (auto iter = mFileReaders[i].mContents.Begin(); iter != mFileReaders[i].mContents.End(); ++iter)
		{
			if (iter->get() == &tracker)
			{
				UnorderedErase(mFileReaders[i].mContents, iter);

				if (mFileReaders[i].mContents.IsEmpty())
				{
					mFileReaders[i].mFileJob->Wait();
					if (!mPacked || i >= mPacked->mPackFiles.Size())
					{
						UnorderedErase(mFileReaders, mFileReaders.Begin() + i);
					}
					else
					{
						mFileReaders[i].mFileJob = nullptr;
					}
				}
				return;
			}
		}
	}
	ION_ASSERT(false, "Content not found");
}


ion::Folder::FileContentAccess ion::Folder::GetFileContent(ion::JobScheduler& js, ion::StringView target, FileJobCallback&& callback)
{
	AutoLock<Mutex> lock(mMutex);
	FileContentTracker* content = nullptr;
	if (mPacked)
	{
		auto idToFileInfoIter = mPacked->mIdToFileInfo.Find(target);
		if (idToFileInfoIter != mPacked->mIdToFileInfo.End())
		{
			content = mFileReaders[idToFileInfoIter->second.mPackFileIndex].mContents.Add(MakeUnique<FileContentTracker>())->get();
			if (!mFileReaders[idToFileInfoIter->second.mPackFileIndex].mFileJob)
			{
				mFileReaders[idToFileInfoIter->second.mPackFileIndex].mFileJob =
				  MakeUnique<FileContentJob>(FullPathTo(mPacked->mPackFiles[idToFileInfoIter->second.mPackFileIndex]));
			}
			mFileReaders[idToFileInfoIter->second.mPackFileIndex].mFileJob->Request(
			  js, std::forward<FileJobCallback&&>(callback), target, content, idToFileInfoIter->second.mPackFilePosition,
			  idToFileInfoIter->second.mPackedSize,
			  idToFileInfoIter->second.mUnpackedSize);
			return ion::Folder::FileContentAccess(*this, *content);
		}
		ION_ABNORMAL("Cannot find " << target << " from pack");
	}

	auto fullPath = FullPathTo(target);
	Folder::FileReader* fileReader = nullptr;
	for (size_t i = 0; i < mFileReaders.Size(); ++i)
	{
		if (mFileReaders[i].mFileJob && mFileReaders[i].mFileJob->Filename() == fullPath)
		{
			fileReader = &mFileReaders[i];
			break;
		}
	}

	if (fileReader == nullptr)
	{
		fileReader = mFileReaders.Add(FileReader());
		fileReader->mFileJob = MakeUnique<FileContentJob>(fullPath);
	}
	content = fileReader->mContents.Add(MakeUnique<FileContentTracker>())->get();
	fileReader->mFileJob->Request(js, std::forward<FileJobCallback&&>(callback), target, content);

	return ion::Folder::FileContentAccess(*this, *content);
}

ion::Folder::FileReader::FileReader(ion::Folder::FileReader&& other) noexcept
  : mFileJob(std::move(other.mFileJob)), mContents(std::move(other.mContents))
{
}

ion::Folder::FileReader::FileReader() {}

ion::Folder::FileReader::~FileReader() {}

#if (ION_ASSERTS_ENABLED == 1)
bool ion::Folder::HasOpenContent() const
{
	for (size_t i = 0; i < mFileReaders.Size(); ++i)
	{
		if (mFileReaders[i].mFileJob)
		{
			return true;
		}
	}
	return false;
}
#endif

ion::Folder::~Folder() { ION_ASSERT(!HasOpenContent(), "Folder has open content"); }

ion::Folder::Folder(Folder&& other) noexcept
  : mPath(std::move(other.mPath)),
	mPacked(std::move(other.mPacked)),
	mFileReaders(std::move(other.mFileReaders)),
	mMutex(std::move(other.mMutex))
{
}

ion::Folder& ion::Folder::operator=(Folder&& other) noexcept
{
	mPath = std::move(other.mPath);
	mPacked = std::move(other.mPacked);
	mFileReaders = std::move(other.mFileReaders);
	mMutex = std::move(other.mMutex);
	return *this;
}

ion::Folder::FileReader& ion::Folder::FileReader::operator=(ion::Folder::FileReader&& other) noexcept
{
	mFileJob = std::move(other.mFileJob);
	mContents = std::move(other.mContents);
	return *this;
}

ion::Folder::FileContentAccess::FileContentAccess(Folder& folder, FileContentTracker& content) : mFolder(folder), mContent(content)
{
	folder.OnContentAccessStarted(content);
}
ion::Folder::FileContentAccess::~FileContentAccess() { mFolder.OnContentAccessEnded(mContent); }


