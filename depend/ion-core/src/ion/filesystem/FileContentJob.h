#pragma once

#include <ion/jobs/Job.h>

#include <ion/filesystem/File.h>
#include <ion/string/String.h>

namespace ion
{
struct FileContentTracker;
class JobScheduler;
struct PackFileInfo;
class DataProcessorRegistry;

class FileContentJob final : public ion::RepeatableIOJob
{
public:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(FileContentJob);

	FileContentJob(StringView filename);

	void RunIOJob() final override;

	void Request(ion::JobScheduler& js, FileJobCallback&& callback, StringView fileName, FileContentTracker* tracker,
				 size_t filePos = 0, size_t fileSize = 0,
				 size_t fileUnpackedSize = 0);

	bool CheckHasWork();

	const ion::String& Filename() const { return mFilename; }

private:
	ion::Mutex mMutex;
	ion::String mFilename;

	struct WorkItem
	{
		FileContentTracker* mContentTracker;
		FileJobCallback mCallback;
		ion::String mFilename;
		size_t mPackFileSize;
		size_t mPackFilePosition;
		size_t mPackFileUnpackedSize;
		bool operator<(const WorkItem& other) const { return mPackFilePosition < other.mPackFilePosition; }
	};

	Vector<WorkItem, CoreAllocator<WorkItem>> mWorkList;
	Vector<WorkItem, CoreAllocator<WorkItem>> mActiveWorkList;	
};

}  // namespace ion
