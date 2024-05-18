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
	ION_ASSERT(numTaskLists > 0 && numTaskLists <= GetThreadPool().GetWorkerCount(), "Not enough lists for running parallel");
	AutoLock<ThreadSynchronizer> lock(GetSynchronizer());
	NumTasksInProgress() += ion::SafeRangeCast<UInt>(numTaskLists);
	NumTasksAvailable() += ion::SafeRangeCast<UInt>(numTaskLists);
	GetThreadPool().AddTasks(ion::Thread::QueueIndex(firstQueueIndex), ion::SafeRangeCast<UInt>(numTaskLists), this);
}
ION_SECTION_END

#if ION_LIST_JOB_USE_LATE_TASKS
ION_CODE_SECTION(".jobs")
void ion::ParallelForJob::AddLateTaskLists(size_t numTaskLists)
{
	ION_ASSERT(numTaskLists > 0 && numTaskLists <= GetThreadPool().GetWorkerCount(), "Not enough lists for running parallel");
	auto queueIndex = GetThreadPool().UseNextQueueIndexExceptThis();
	AutoLock<ThreadSynchronizer> lock(GetSynchronizer());
	NumTasksInProgress() += ion::SafeRangeCast<UInt>(numTaskLists);
	NumTasksAvailable() += ion::SafeRangeCast<UInt>(numTaskLists);
	GetThreadPool().AddTasks(ion::Thread::QueueIndex(queueIndex), ion::SafeRangeCast<UInt>(numTaskLists), this);
}
ION_SECTION_END
#endif

ION_CODE_SECTION(".jobs")
void ion::ListJobBase::AddTaskLists(UInt firstQueueIndex, size_t numTaskLists)
{
	numTaskLists = ion::Min(numTaskLists, size_t(GetThreadPool().GetWorkerCount() + ION_MAIN_THREAD_IS_A_WORKER));
#if ION_LIST_JOB_USE_LATE_TASKS
	size_t maxTaskListCount = UInt(GetThreadPool().GetWaitingWorkerCount() + 2) * 2;
	if (numTaskLists > maxTaskListCount)
	{
		mNumLateTasks = numTaskLists - maxTaskListCount;
		numTaskLists = maxTaskListCount;
	}
#endif
	if (numTaskLists > 1)
	{
		ParallelForJob::AddTaskLists(firstQueueIndex, numTaskLists - 1);
	}
}
ION_SECTION_END

#if 1
ION_CODE_SECTION(".jobs")
size_t ion::ListJobBase::CountNumIntermediateBatches() const
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
	return numBatches;
}
ION_SECTION_END
#endif
