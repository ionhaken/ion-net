#include <ion/container/ForEach.h>
#include <ion/container/Sort.h>

#include <ion/jobs/JobScheduler.h>

#include <ion/filesystem/DataProcessorRegistry.h>
#include <ion/filesystem/FileContentJob.h>
#include <ion/filesystem/FileContentTracker.h>

namespace ion
{

FileContentJob::FileContentJob(StringView filename) : ion::RepeatableIOJob(ion::tag::Core), mFilename(filename)
{
	ION_ASSERT(!mFilename.IsEmpty(), "Invalid filename");
}

void FileContentJob::Request(ion::JobScheduler& js, FileJobCallback&& callback, StringView fileName,
							 FileContentTracker* tracker, size_t filePos, size_t fileSize, size_t fileUnpackedSize)
{
	ion::AutoLock<ion::Mutex> lock(mMutex);
	bool startNewJob = (mWorkList.IsEmpty());
	mWorkList.Add(WorkItem{tracker, std::forward<FileJobCallback&&>(callback), fileName, fileSize, filePos, fileUnpackedSize});
	if (startNewJob)
	{
		Execute(js.GetPool());
	}
}

bool FileContentJob::CheckHasWork()
{
	{
		ion::AutoLock<ion::Mutex> lock(mMutex);
		if (mWorkList.IsEmpty())
		{
			ION_ASSERT(mActiveWorkList.IsEmpty(), "Work was not completed");
			return false;
		}

		std::swap(mWorkList, mActiveWorkList);
	}

	ion::Sort(mActiveWorkList.Begin(), mActiveWorkList.End());
	return true;
}

void FileContentJob::RunIOJob()
{
	if (CheckHasWork())
	{
		ION_MEMORY_SCOPE(ion::tag::IgnoreLeaks);
		ion::FileIn file(mFilename.CStr());
		do
		{
			ion::ForEach(mActiveWorkList,
						 [&](WorkItem& item)
						 {
							 ION_PROFILER_SCOPE(Core, "Read File");
							 ion::Vector<byte> tmp;
							 file.Get(tmp, item.mPackFilePosition, item.mPackFileSize);
							 ION_DBG("Reading file " << mFilename << " (" << item.mFilename << ") at " << item.mPackFilePosition << " for "
													 << tmp.Size() << " bytes (work index: " << size_t(&item - mActiveWorkList.Begin())
													 << "/" << mActiveWorkList.Size() << ")");
							 item.mCallback(tmp, item.mPackFileSize, item.mPackFileUnpackedSize);
						 });
			mActiveWorkList.Clear();
		} while (CheckHasWork());
	}
}

}  // namespace ion
