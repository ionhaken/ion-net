#pragma once

#include <ion/Types.h>
#include <ion/filesystem/FileContentTracker.h>
#include <ion/filesystem/Folder.h>
#include <ion/string/StringView.h>

#include <atomic>

namespace ion
{
class ThreadSynchronizer;
class DataProcessorRegistry;

struct FileJobWorkspace
{
	void* mUserData = nullptr;
	ion::InplaceFunction<void(void*)> mDeinitCallback;
};

struct FileLoadingContext
{
	FileLoadingContext(StringView target, Folder& folder, JobScheduler& js, const DataProcessorRegistry* dataProcessorRegistry)
	  : mTarget(target), mFolder(folder), mJs(js), mProcessorRegistry(dataProcessorRegistry)
	{
	}
	StringView mTarget;
	Folder& mFolder;
	JobScheduler& mJs;
	const DataProcessorRegistry* mProcessorRegistry;
};

class Job;
class FileLoader;
using ResourceLoaderCallback = ion::InplaceFunction<void(FileLoader& loader), 32, 8>;

template<typename T>
class AutoLock;

class FileLoader
{
public:
	ION_CLASS_NON_COPYABLE(FileLoader)
	FileLoader(Folder& folder, const DataProcessorRegistry* processorregistry, StringView target, ion::JobScheduler& js);
	FileLoader(Folder& folder, const DataProcessorRegistry* processorregistry, StringView target, ion::JobScheduler& js,
			   ion::ThreadSynchronizer* synchronizer, ResourceLoaderCallback&& callback);
	FileLoader(FileLoader&& other) noexcept;
	~FileLoader();

	void AsyncWork(ion::JobScheduler& js, ion::Vector<byte>& tmp, size_t fileSize, size_t unpackedSize);

	void Wait();

	void OnDone();

	void Get(ion::Vector<byte>&);

	StringView Filename() const { return mFilename; }

	ion::JobScheduler& Scheduler() { return mJs; }

	bool IsDone() const { return mState == State::Done; }

private:
	void WaitUnlocked(AutoLock<ThreadSynchronizer>& lock);
	
	enum State
	{
		Loading,
		Done,
	};

	const ion::String mFilename;
	ion::Vector<byte> mData;
	ion::UniquePtr<ion::ThreadSynchronizer> mLoaderSynchronizer;
	ion::ThreadSynchronizer* mSynchronizer;
	const ion::DataProcessorRegistry* mDataProcessorRegistry;
	ResourceLoaderCallback mCallback;
	FileJobWorkspace mResourceJobWorkspace;
	std::atomic<State> mState = State::Loading;
	ion::JobScheduler& mJs;

	// This must be kept last, because it will trigger async operation.
	ion::Folder::FileContentAccess mTracker;

};


class ResourceLoader
{
public:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(ResourceLoader)

	ResourceLoader();
	~ResourceLoader();
	bool IsLoading() const;
	void Load(ion::Folder& folder, const ion::DataProcessorRegistry* processorregistry, StringView target, ion::JobScheduler& js,
			  ResourceLoaderCallback&& callback);
	void Remove(FileLoader&);
	void Wait(ion::Folder& folder, StringView target);

private:
	ion::UniquePtr<ion::ThreadSynchronizer> mLoaderSynchronizer;
	ion::Vector<ion::UniquePtr<FileLoader>> mLoaders;

};


}  // namespace ion
