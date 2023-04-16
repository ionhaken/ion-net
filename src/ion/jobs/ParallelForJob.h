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
#include <ion/jobs/Job.h>
#include <ion/jobs/ThreadPool.h>
#include <ion/container/StaticVector.h>

namespace ion
{
namespace parallel_for
{
void PreFetch(const void* addr);

class SinglePartition
{
public:
	SinglePartition(size_t items) : mIndex(0), mEnd(items) {}
	SinglePartition() {}

	size_t Size() const { return 1; }

	size_t Last() const { return mEnd; }
	size_t First() const { return 0; }
	size_t Current() const { return mIndex; }
	size_t Next() { return mIndex.fetch_add(1, std::memory_order_relaxed); }
	void SetEnd(size_t v) { mEnd = v; }
	size_t TotalItems() const { return Last(); }
	void ResetIndex() { mIndex = 0; }

private:
	std::atomic<size_t> mIndex;
	size_t mEnd;
};

class ION_ALIGN_CACHE_LINE Partition : public SinglePartition
{
public:
	ION_ALIGN_CLASS(Partition);

	Partition(size_t items) : SinglePartition(items), mStart(0) {}
	Partition(const Partition& other) : SinglePartition(other.Last()), mStart(other.mStart) {}
	Partition() {}

	size_t First() const { return mStart; }
	void SetStart(size_t v) { mStart = v; }

private:
	size_t mStart;
};

class MultiPartition
{
public:
	MultiPartition(size_t items) : mTotalItems(items) {}

	MultiPartition() {}

	size_t Size() const { return mPartitions.Size(); }
	Partition& Get(size_t index) { return mPartitions[index]; }

	size_t TotalItems() const { return mTotalItems; }

	void Set(UInt partitionSize, size_t /*numTaskLists*/);

private:
	size_t mTotalItems;
	ion::StaticVector<Partition, ion::MaxQueues> mPartitions;
};

class TaskList
{
public:
	TaskList(size_t items, UInt /*batchSize*/) : mPartition(items) {}

	template <typename Iterator, class Callback>
	void Run(const Iterator& first, Callback function)
	{
		size_t startIndex;
		while (FindTasks(startIndex))
		{
			Iterator iter = first + startIndex;
			ION_PROFILER_SCOPE_DETAIL(Job, "Task", size_t(iter - first));

			function(*iter);
		}
	}

	size_t TotalItems() const { return mPartition.Last(); }

private:
	bool FindTasks(size_t& startIndex)
	{
		startIndex = mPartition.Next();
		return startIndex < mPartition.Last();
	}

	ION_ALIGN_CACHE_LINE SinglePartition mPartition;
};

template <typename Partitions = SinglePartition>
class TaskListBatched
{
public:
	TaskListBatched(size_t items, UInt batchSize) : mPartitions(items), mBatchSize(batchSize) {}

	template <typename Iterator, typename Callback>
	void Run(const Iterator& first, Callback&& function)
	{
		ION_ASSERT(mBatchSize > 1, "Invalid batch size");
		size_t startIndex;
		size_t endIndex;
		while (FindTasks(mPartitions, startIndex, endIndex))
		{
			ProcessBatch(first, startIndex, endIndex, function);
		}
	}

	size_t TotalItems() const { return mPartitions.TotalItems(); }

protected:
	template <typename Iterator, typename Callback>
	void ProcessBatch(const Iterator& first, size_t startIndex, size_t endIndex, Callback&& callback)
	{
		auto iter = first + startIndex;
		auto end = first + endIndex;
		do
		{
			ION_PROFILER_SCOPE_DETAIL(Job, "Task", size_t(iter - first));
			callback(*iter);
			++iter;
		} while (iter != end);
	}

	template <typename Partition>
	bool FindTasks(Partition& partition, size_t& startIndex, size_t& endIndex)
	{
		auto nextBatchIndex = partition.Next();
		startIndex = (nextBatchIndex * mBatchSize) + partition.First();
		endIndex = startIndex + mBatchSize;
		if (endIndex >= partition.Last())
		{
			if (startIndex >= partition.Last())
			{
				return false;
			}
			endIndex = partition.Last();
		}
		return true;
	}

	UInt BatchSize() const { return mBatchSize; }

	size_t NumPartitions() const { return mPartitions.Size(); }

	Partitions& GetPartitions() { return mPartitions; }

private:
	ION_ALIGN_CACHE_LINE Partitions mPartitions;
	UInt mBatchSize;
};

class TaskListPartitioned : public TaskListBatched<MultiPartition>
{
public:
	TaskListPartitioned(size_t items, UInt batchSize) : TaskListBatched<MultiPartition>(items, batchSize), mRunningIndex(0) {}

	size_t CreatePartitions(UInt partitionSize, size_t numTaskLists)
	{
		GetPartitions().Set(partitionSize, numTaskLists);
		return GetPartitions().Size();
	}

	template <typename Iterator, typename Callback>
	void Run(const Iterator& first, Callback&& function)
	{
		ProcessPartitions(
		  [&](Partition& partition)
		  {
			  size_t startIndex;
			  size_t endIndex;
			  while (FindTasks(partition, startIndex, endIndex))
			  {
				  ProcessBatch(first, startIndex, endIndex, function);
			  }
		  });
	}

private:
	template <typename Callback>
	void ProcessPartitions(Callback&& callback)
	{
		ION_PROFILER_SCOPE(Job, "List iteration");
		size_t numPartitions = NumPartitions();
		size_t firstPartition = ChooseFirstPartition();
		for (size_t j = 0; j < numPartitions; ++j)
		{
			Partition& partition = GetPartitions().Get((firstPartition + j) % numPartitions);
			callback(partition);
		}
	}

	inline size_t ChooseFirstPartition()
	{
		size_t next = mRunningIndex.fetch_add(1, std::memory_order_relaxed);
		return next;
	}

	ION_ALIGN_CACHE_LINE std::atomic<size_t> mRunningIndex;
};
}  // namespace parallel_for

class ParallelForJob : public WaitableJob
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(ParallelForJob);

public:
	ION_ALIGN_CLASS(ParallelForJob);

	ParallelForJob(ThreadPool& tp) : WaitableJob(tp, ion::Thread::GetCurrentJob(), 0) {}

protected:
	size_t CalcNumTaskLists(UInt batchSize, size_t items) const;

	void AddTaskLists(UInt firstQueueIndex, size_t numTaskLists);

	void AddTaskListsLocked(UInt firstQueueIndex, size_t numTaskLists);
};

class ListJobBase : public ParallelForJob
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(ListJobBase);

public:
	ListJobBase(ThreadPool& tp, size_t numItems, UInt minBatchSize)
	  : ParallelForJob(tp), mIndex(0), mMinBatchSize(minBatchSize), mNumItems(numItems)
	{
	}

	void AddTaskLists(UInt firstQueueIndex);

protected:
	inline bool FindTasks(size_t& startIndex, size_t& endIndex)
	{
		auto nextBatchIndex = mIndex.fetch_add(1, std::memory_order_relaxed);
		startIndex = nextBatchIndex * mMinBatchSize;
		endIndex = startIndex + mMinBatchSize;
		if (endIndex >= mNumItems)
		{
			if (startIndex >= mNumItems)
			{
				return false;
			}
			endIndex = mNumItems;
		}
		return true;
	}

protected:
	size_t Index() const { return static_cast<size_t>(mIndex); }
	size_t NumItems() const { return mNumItems; }

private:
	std::atomic<size_t> mIndex;
	const size_t mMinBatchSize;
	const size_t mNumItems;

private:
};

#if 0

	template<typename Algorithm>
	class ListJob : public ParallelForJob
	{
		ION_CLASS_NON_COPYABLE_NOR_MOVABLE(ListJobBase);
	public:
		template<typename Iterator>
		ListJobBase(ThreadPool& tp, const Iterator& first, const Iterator& last, size_t batchSize)
			:
			ParallelForJob(tp),
			mBatchSize(batchSize)
		{
		}

		void AddTaskLists(UInt firstQueueIndex);

	protected:

		virtual void RunTask() override
		{
			ION_ASSERT(false, "Sub class must implement RunTask()");
		}

		bool HasTasks(size_t tsIndex) const;

		size_t NumTaskSequences() const { return mTaskSequences.Size(); }

		size_t ChooseFirstTaskSequence();

		template<typename Callback>
		inline void ProcessSequences(Callback&& callback)
		{
			ION_PROFILER_SCOPE(Job, "List iteration");
			size_t numTaskSeqs = NumTaskSequences();
			size_t firstTaskSequence = ChooseFirstTaskSequence();
			for (size_t j = 0; j < numTaskSeqs; ++j)
			{
				size_t taskSequence = (firstTaskSequence + j) % numTaskSeqs;
				if (ListJobBase::HasTasks(taskSequence))
				{
					callback(taskSequence);
				}
			}
		}


	private:

		UInt mBatchSize;
		std::atomic<size_t> mFirstSequenceIndex;
	};

	template<typename Iterator, class Function>
	class ListJob : public ListJobBase
	{
		ION_CLASS_NON_COPYABLE_NOR_MOVABLE(ListJob);
	public:

		ListJob(ThreadPool& tp, const Iterator& first, const Iterator& last, const Function&& function,
			size_t minBatchSize)
			:
			ListJobBase(tp, first, last, minBatchSize),
			mFunction([function, first, this]()
				{
					ListJobBase::ProcessSequences([&](size_t taskSequence)
						{
							size_t startIndex;
							size_t endIndex;
							while (ListJobBase::FindTasks(taskSequence, startIndex, endIndex))
							{
								ListJobBase::ProcessBatch(first, startIndex, endIndex,
									[&](auto& iter)
									{
										function(iter);
									});
							}
						});
				})
		{
		}

		void Wait(UInt firstQueueIndex)
		{
			ListJobBase::AddTaskLists(firstQueueIndex);
			ion::Thread::SetCurrentJob(this);
			mFunction();
			ion::Thread::SetCurrentJob(this->mSourceJob);
			WaitableJob::Wait();
		}

	protected:

		virtual void RunTask() final override
		{
			ION_PROFILER_SCOPE(Scheduler, "Task List");
			this->OnTaskStarted();
			mFunction();
			this->OnTaskDone();
		}

	private:
		task::Function<void()> mFunction;
	};
#endif
}  // namespace ion

#if 0  // #TODO: Parallel for to support intermediate list correctly
namespace ion
{

	template<typename Iterator, class Function, class Intermediate>
	class IntermediateListJob : public ListJobBase
	{
		ION_CLASS_NON_COPYABLE_NOR_MOVABLE(IntermediateListJob);
	public:

		IntermediateListJob(ThreadPool& tp, const Iterator& first, const Iterator& last, const Function&& function,
			size_t minBatchSize, Intermediate& intermediate)
			:
			ListJobBase(tp, first, last, minBatchSize),
			mFunction([function, first, &intermediate, this](bool isWaiting)
				{
					ION_PROFILER_SCOPE(Job, "List iteration (intermediate)");
					if (isWaiting)
					{
						ProcessSequences([&](size_t taskSequence)
							{
								size_t startIndex;
								size_t endIndex;
								while (ListJobBase::FindTasks(taskSequence, startIndex, endIndex))
								{
									ListJobBase::ProcessBatch(first, startIndex, endIndex, [&](auto& iter)
										{
											function(iter, intermediate.GetMain());
										});
								}
							});
					}
					else
					{
						typename Intermediate::Type* freeIntermediate;

						ListJobBase::ProcessSequences([&](size_t taskSequence)
							{
								size_t startIndex;
								size_t endIndex;
								if (ListJobBase::FindTasks(taskSequence, startIndex, endIndex))
								{
									freeIntermediate = &intermediate.GetFree();
									do
									{
										ListJobBase::ProcessBatch(first, startIndex, endIndex, [&](auto& iter)
											{
												function(iter, *freeIntermediate);
											});
									} while (ListJobBase::FindTasks(taskSequence, startIndex, endIndex));
								}
							});
					}
				})
		{
		}

				void Wait(UInt firstQueueIndex)
				{
					ListJobBase::AddTaskLists(firstQueueIndex);
					ion::Thread::SetCurrentJob(this);
					mFunction(true);
					ion::Thread::SetCurrentJob(this->mSourceJob);
					WaitableJob::Wait();
				}

	protected:

		virtual void RunTask() final override
		{
			ION_PROFILER_SCOPE(Scheduler, "Task List(intermediate)");
			this->OnTaskStarted();
			mFunction(false);
			this->OnTaskDone();
		}

	private:
		static constexpr size_t Alignment = 16;
		task::Function<void(bool)> mFunction;
	};
}

#endif
