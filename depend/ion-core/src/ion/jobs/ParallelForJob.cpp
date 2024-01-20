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
#include <ion/jobs/ParallelForJob.h>

ION_CODE_SECTION(".jobs")
void ion::parallel_for::MultiPartition::Set(UInt partitionSize, size_t /*numTaskLists*/)
{
	size_t partitions = ion::Min(size_t(mPartitions.Capacity()), (TotalItems() / partitionSize));
	if (partitions > 1)
	{
		mPartitions.Resize(partitions);
		size_t itemsPerPartition = TotalItems() / partitions;
		size_t index = 0;
		for (size_t i = 1; i < partitions; ++i)
		{
			index += itemsPerPartition;
			mPartitions[i - 1].SetEnd(index);
			mPartitions[i].ResetIndex();
			mPartitions[i].SetStart(index);
		}
	}
	else
	{
		mPartitions.Resize(1);
	}
	mPartitions.Front().ResetIndex();
	mPartitions.Front().SetStart(0);
	mPartitions.Back().SetEnd(TotalItems());
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
size_t ion::ParallelForJob::CalcNumTaskLists(UInt batchSize, size_t items) const
{
	ION_ASSERT(batchSize > 0, "Invalid partition size");
	size_t numTaskLists = items;
	if (batchSize != 1)
	{
		auto mod = items % batchSize;
		if (mod != 0)
		{
			numTaskLists += (batchSize - mod);
		}
		numTaskLists /= batchSize;
	}
	return numTaskLists;
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ParallelForJob::AddTaskLists(UInt firstQueueIndex, size_t numTaskLists)
{
	// -1 because local thread is also using doing task list
	ION_ASSERT(numTaskLists > 1, "Not enough lists for running parallel");
	numTaskLists = ion::Min(numTaskLists - 1, static_cast<size_t>(GetThreadPool().GetWorkerCount()));
	AutoLock<ThreadSynchronizer> lock(GetSynchronizer());
	AddTaskListsLocked(firstQueueIndex, numTaskLists);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ParallelForJob::AddTaskListsLocked(UInt firstQueueIndex, size_t numTaskLists)
{
	NumTasksInProgress() += ion::SafeRangeCast<UInt>(numTaskLists);
	NumTasksAvailable() += ion::SafeRangeCast<UInt>(numTaskLists);
	GetThreadPool().AddTasks(ion::Thread::QueueIndex(firstQueueIndex), ion::SafeRangeCast<UInt>(numTaskLists), this);
}
ION_SECTION_END

ION_CODE_SECTION(".jobs")
void ion::ListJobBase::AddTaskLists(UInt firstQueueIndex)
{
	ION_ASSERT(mMinBatchSize > 0, "Invalid batch size");
	size_t numBatches = mNumItems;
	if (mMinBatchSize != 1)
	{
		auto mod = mNumItems % mMinBatchSize;
		if (mod != 0)
		{
			numBatches += (mMinBatchSize - mod);
		}
		numBatches /= mMinBatchSize;
	}
	ION_ASSERT(numBatches > 1, "Not enough batches for running parallel");
	{
		// -1 because local thread is also virtually one task list
		size_t numTaskLists = ion::Min(numBatches - 1, static_cast<size_t>(ParallelForJob::GetThreadPool().GetWorkerCount()));

		// If there is lot to do have additional task lists.
		if (numBatches > numTaskLists * 2)
		{
			numTaskLists = numTaskLists * 2;
		}

		AutoLock<ThreadSynchronizer> lock(ParallelForJob::GetSynchronizer());
		ParallelForJob::AddTaskListsLocked(firstQueueIndex, numTaskLists);
	}
}
ION_SECTION_END
