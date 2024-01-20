#include <ion/container/ForEach.h>

#include <ion/concurrency/ThreadSynchronizer.h>

#include <ion/jobs/Job.h>
#include <ion/jobs/JobScheduler.h>

#include <ion/filesystem/DataProcessorRegistry.h>
#include <ion/filesystem/ResourceLoader.h>

namespace ion
{

FileLoader::FileLoader(FileLoader&& other) noexcept
  : mLoaderSynchronizer(std::move(other.mLoaderSynchronizer)),
	mSynchronizer(other.mSynchronizer),
	mDataProcessorRegistry(other.mDataProcessorRegistry),
	mData(std::move(other.mData)),
	mJs(other.mJs),
	mTracker(std::move(other.mTracker))
{
	other.mSynchronizer = nullptr;
	other.mDataProcessorRegistry = nullptr;
}

FileLoader::FileLoader(Folder& folder, const DataProcessorRegistry* processorregistry, StringView target, ion::JobScheduler& js,
					   ion::ThreadSynchronizer* synchronizer, ResourceLoaderCallback&& callback)
  : mFilename(target),
	mSynchronizer(synchronizer),
	mDataProcessorRegistry(processorregistry),
	mCallback(std::forward<ResourceLoaderCallback&&>(callback)),
	mJs(js),
	mTracker(folder.GetFileContent(js, target,
								   [this, &js](ion::Vector<byte>& tmp, size_t fileSize, size_t unpackedSize)
								   { AsyncWork(js, tmp, fileSize, unpackedSize); }))
{
	ION_ASSERT(!mFilename.IsEmpty(), "Invalid filename");
}

FileLoader::FileLoader(ion::Folder& folder, const ion::DataProcessorRegistry* processorregistry, StringView target, ion::JobScheduler& js)
  : mFilename(target),
	mLoaderSynchronizer(ion::MakeUnique<ThreadSynchronizer>()),
	mSynchronizer(mLoaderSynchronizer.get()),
	mDataProcessorRegistry(processorregistry),
	mCallback([](FileLoader& loader) { loader.OnDone(); }),
	mJs(js),
	mTracker(folder.GetFileContent(js, target,
								   [this, &js](ion::Vector<byte>& tmp, size_t fileSize, size_t unpackedSize)
								   { AsyncWork(js, tmp, fileSize, unpackedSize); }))

{
	ION_ASSERT(!mFilename.IsEmpty(), "Invalid filename");
}

FileLoader::~FileLoader() { ION_ASSERT(mData.IsEmpty(), "Data was not consumed"); }

void FileLoader::Get(ion::Vector<byte>& data) { data = std::move(mData); }

void FileLoader::OnDone()
{
	if (mResourceJobWorkspace.mUserData)
	{
		mResourceJobWorkspace.mDeinitCallback(mResourceJobWorkspace.mUserData);
	}
	AutoLock<ThreadSynchronizer> lock(*mSynchronizer);
	ION_ASSERT(mState == State::Loading, "Invalid state");
	mState = State::Done;
	lock.NotifyAll();
}

void FileLoader::AsyncWork(ion::JobScheduler& js, ion::Vector<byte>& tmp, size_t fileSize, size_t unpackedSize)
{
	mData = std::move(tmp);
	js.PushTask(
	  [unpackedSize, fileSize, this]()
	  {
		  if (!mData.IsEmpty() && fileSize != unpackedSize)
		  {
			  ion::Vector<byte> decompressedTmp;
			  ION_ASSERT(mDataProcessorRegistry, "File requires decompressor");
			  const ion::ArrayView<byte, uint32_t> src(mData.Data(), mData.Size());
			  decompressedTmp.ResizeFast(unpackedSize + 1024 /* extra space for processing #TODO: Get actual value from ZSTD */);
			  ion::ArrayView<byte, uint32_t> dst(decompressedTmp.Data(), decompressedTmp.Size());
			  size_t resultSize = mDataProcessorRegistry->Process("decompressor", dst, src, nullptr, mResourceJobWorkspace);
			  decompressedTmp.ResizeFast(resultSize);
			  mData = std::move(decompressedTmp);
		  }
		  mCallback(*this);
	  });
}

void FileLoader::Wait()
{
	AutoLock<ThreadSynchronizer> lock(*mSynchronizer);
	WaitUnlocked(lock);
}

void FileLoader::WaitUnlocked(AutoLock<ThreadSynchronizer>& lock)
{
	for (;;)
	{
		if (mState == State::Done)
		{
			break;
		}
		if (ion::Thread::GetCurrentJob()->GetType() == BaseJob::Type::IOJob)
		{
			lock.UnlockAndWait();
		}
		else
		{
			lock.UnlockAndWaitEnsureWork(mJs.GetPool());
		}
	}
}

ResourceLoader::ResourceLoader() : mLoaderSynchronizer(ion::MakeUnique<ThreadSynchronizer>()) {}

bool ResourceLoader::IsLoading() const
{
	ion::AutoLock<ion::ThreadSynchronizer> lock(*mLoaderSynchronizer);
	return mLoaders.Size() > 0;
}

void ResourceLoader::Load(ion::Folder& folder, const ion::DataProcessorRegistry* processorregistry, StringView target,
						  ion::JobScheduler& js, ResourceLoaderCallback&& callback)

{
	ion::AutoLock<ion::ThreadSynchronizer> lock(*mLoaderSynchronizer);
	auto iter = ion::FindIf(mLoaders, [&target](const ion::UniquePtr<FileLoader>& other) { return other.get()->Filename() == target; });
	if (iter == mLoaders.End())
	{
		mLoaders.Add(ion::MakeUnique<FileLoader>(folder, processorregistry, target, js, mLoaderSynchronizer.get(),
												 std::forward<ResourceLoaderCallback&&>(callback)));
	}
}

void ResourceLoader::Remove(FileLoader& fileLoader)
{
	ion::AutoLock<ion::ThreadSynchronizer> lock(*mLoaderSynchronizer);	
	auto iter = ion::FindIf(mLoaders, [&fileLoader](const ion::UniquePtr<FileLoader>& other) { return other.get() == &fileLoader; });
	if (iter != mLoaders.End())
	{
		iter->reset();
		ion::UnorderedErase(mLoaders, iter);
	}
}

void ResourceLoader::Wait(ion::Folder& /* folder*/, StringView target)
{
	ion::AutoLock<ion::ThreadSynchronizer> lock(*mLoaderSynchronizer);
	for (;;)
	{
		auto iter = ion::FindIf(mLoaders, [&target](const ion::UniquePtr<FileLoader>& other) { return other.get()->Filename() == target; });
		if (iter != mLoaders.End())
		{
			if (iter->get()->IsDone())
			{
				return;
			}
			// Iter is not valid after unlock & wait.
			if (ion::Thread::GetCurrentJob()->GetType() == BaseJob::Type::IOJob)
			{
				lock.UnlockAndWait();
			}
			else
			{
				lock.UnlockAndWaitEnsureWork(ion::core::gSharedScheduler->GetPool());
			}
		}
		else
		{
			return;
		}
	}
}

ResourceLoader::~ResourceLoader()
{
	for (;;)
	{
		ion::AutoLock<ion::ThreadSynchronizer> lock(*mLoaderSynchronizer);
		if (mLoaders.IsEmpty())
		{
			return;
		}
		ION_DBG("Waiting for file loaders");
		mLoaders.Front()->Wait();
	}
}

}  // namespace ion
