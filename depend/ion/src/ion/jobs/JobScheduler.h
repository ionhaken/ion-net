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
#include <ion/jobs/IntermediateListJob.h>
#include <ion/jobs/Job.h>
#include <ion/jobs/JobDispatcher.h>
#include <ion/jobs/SplittingJob.h>
#include <ion/container/Vector.h>

#include <iterator>

namespace ion
{
#if 0
			// Item size is usually not enough information for setting batch size, but it's useful for some cases.
template <typename Function>
inline UInt ItemsPerCacheLine()
{
	using firstParam = typename detail::functraits<decltype(&Function::operator())>::type;
	return ion::Max(1u, static_cast<UInt>(ION_CONFIG_SAFE_CACHE_LINE_SIZE / sizeof(firstParam)));
}
#endif

class JobDispatcher;
class TimedJob;
class JobScheduler
{
public:
	JobScheduler(uint16_t hwConcurrency = 0);
	ION_ALIGN_CLASS(JobScheduler);
	class TimeCritical
	{
		JobScheduler& mJs;

	public:
		TimeCritical(JobScheduler& js) : mJs(js) { mJs.BeginTimeCritical(); }
		~TimeCritical() { mJs.EndTimeCritical(); }
	};

	~JobScheduler();

	void WorkOnMainThread() { mDispatcher.ThreadPool().WorkOnMainThread(); }
	void WorkOnMainThreadNoBlock() { mDispatcher.ThreadPool().WorkOnMainThreadNoBlock(); }

	inline ThreadPool& GetPool() { return mDispatcher.ThreadPool(); }

	template <class Function>
	inline void PushTask(Function&& function)
	{
		PushTask(false, std::forward<decltype(function)>(function));
	}

	template <class Function>
	inline void PushLongTask(Function&& function)
	{
		PushTask(true, std::forward<decltype(function)>(function));
	}

	void PushJob(TimedJob& job);

	void PushMainThreadJob(BaseJob& job);

	// Long jobs do not ever run on main thread. This is useful when you need to run jobs
	// that persist over multiple frames.
	void PushLongJob(BaseJob& job);

	inline void PushJob(BaseJob& job)
	{
		Task task(&job);
		mDispatcher.ThreadPool().PushTask(std::move(task));
	}

	template <typename DataType>
	static constexpr UInt DefaultBatchSize(size_t count, size_t partitions)
	{
		return partitions > 1 ? static_cast<UInt>(ion::Max(static_cast<size_t>(1), count / ion::MaxThreads)) : 1;
	}

	static constexpr UInt DefaultPartitionSize(size_t count)
	{
		return static_cast<UInt>(ion::Max(static_cast<size_t>(1), count / (ion::MaxThreads * 4)));
	}

	struct IndexIterator
	{
		UInt mValue;
#if ION_PLATFORM_ANDROID
		using iterator_category = std::forward_iterator_tag;
#else
		using iterator_category = std::contiguous_iterator_tag;
#endif
		using value_type = UInt;
		using difference_type = UInt;
		using pointer = UInt*;
		using reference = UInt&;

		explicit IndexIterator(size_t value) : mValue(ion::SafeRangeCast<UInt>(value)) {}
		UInt operator*() const { return mValue; }
		UInt& operator*() { return mValue; }
		UInt operator-(const IndexIterator& other) const { return mValue - other.mValue; }
		UInt operator-(const size_t count) const { return mValue - UInt(count); }
		IndexIterator operator+(const size_t count) const
		{
			IndexIterator result(mValue + UInt(count));
			return result;
		}
		bool operator<(const size_t count) const { return mValue < UInt(count); }
		bool operator==(const IndexIterator& other) const { return mValue == other.mValue; }
		bool operator==(const size_t count) const { return mValue == UInt(count); }
		bool operator!=(const IndexIterator& other) const { return !(*this == other); }
		bool operator!=(const size_t count) const { return !(*this == UInt(count)); }

		IndexIterator& operator++()
		{
			mValue++;
			return *this;
		}

		IndexIterator operator++(int)
		{
			IndexIterator result(mValue);
			++mValue;
			return result;
		}
	};

	template <class Function>
	inline void ParallelForIndex(const size_t start, const size_t end, const UInt partitionSize, const UInt batchSize,
								 Function&& function) noexcept
	{
		const IndexIterator startIter(start);
		const IndexIterator endIter(end);

		ParallelFor(partitionSize, startIter, endIter, std::forward<decltype(function)>(function), batchSize);
	}

	template <typename Iterator, class Function, class Intermediate = EmptyIntermediate>
	inline void ParallelFor(const Iterator& first, const Iterator& last, const UInt partitionSize, const UInt batchSize,
							Function&& function) noexcept
	{
		ParallelFor(partitionSize, first, last, std::forward<decltype(function)>(function), batchSize);
	}

	template <typename Iterator, class Function, class Intermediate = EmptyIntermediate>
	inline void ParallelFor(const Iterator& first, const Iterator& last, UInt partitionSize, Function&& function) noexcept
	{
		const UInt batchSize = ion::JobScheduler::DefaultBatchSize<decltype(*first)>(last - first, partitionSize);
		ParallelFor(partitionSize, first, last, std::forward<decltype(function)>(function), batchSize);
	}

	template <typename Iterator, class Function, class Intermediate = EmptyIntermediate>
	inline void ParallelFor(const Iterator& first, const Iterator& last, Function&& function) noexcept
	{
		const UInt partitions = ion::JobScheduler::DefaultPartitionSize(last - first);
		const UInt batchSize = ion::JobScheduler::DefaultBatchSize<decltype(*first)>(last - first, partitions);
		ParallelFor(partitions, first, last, std::forward<decltype(function)>(function), batchSize);
	}

	template <typename Iterator, class Function, class Intermediate = EmptyIntermediate>
	inline void ParallelFor(const Iterator& first, const Iterator& last, UInt partitionSize, Intermediate& intermediate,
							Function&& function) noexcept
	{
		const UInt batchSize = ion::JobScheduler::DefaultBatchSize<decltype(*first)>(last - first, partitionSize);
		ParallelFor(partitionSize, first, last, std::forward<decltype(function)>(function), batchSize, &intermediate);
	}

	template <typename Iterator, class Function, class Intermediate = EmptyIntermediate>
	inline void ParallelFor(const Iterator& first, const Iterator& last, Intermediate& intermediate, Function&& function) noexcept
	{
		const UInt partitions = ion::JobScheduler::DefaultPartitionSize(last - first);
		const UInt batchSize = ion::JobScheduler::DefaultBatchSize<decltype(*first)>(last - first, partitions);
		ParallelFor(partitions, first, last, std::forward<decltype(function)>(function), batchSize, &intermediate);
	}

	// Partitions:
	// Partition is number of tasks per job.
	// More partitions add overhead, but have better load balancing. Use smaller values when iterations have varying
	// speed.
	//
	// If 'partitions' is 0, all tasks will be moved to a job with given batch size, and no tasks
	// will be run locally (except if there's only single item). This should be used when you know that are workers are idle.
	//
	// BatchSize: minimum number of tasks processed once. Default value is 1 and should be increased only
	// when tasks are really small and other threads should not steal any tasks. If batch size is larger than partition size, partition size
	// will be ignored and tasks are put into a single job.
	//
	// Note: Currently parallel fors with intermediates will not be partitioned.
	//
	template <typename Iterator, class Function, class Intermediate = EmptyIntermediate>
	inline void ParallelFor(UInt partitionSize, const Iterator& first, const Iterator& last, Function&& function, const UInt batchSize,
							Intermediate* intermediate = nullptr) noexcept
	{
		ION_ASSERT(batchSize >= 1, "Invalid batch size: " << batchSize);
		ION_ASSERT(partitionSize > 0 || batchSize == 1, "Tasks are not batched when partition size is 0");

		auto iter = first;
#if ION_MAIN_THREAD_IS_A_WORKER
		if (mDispatcher.ThreadPool().GetWorkerCount() > 0)
#endif
		{
			auto numItems = static_cast<UInt>(last - first);
			partitionSize = mMeasurement.PartitionSize(partitionSize);
			auto numSerialItems = ion::Max(partitionSize, batchSize);
			if (numItems > numSerialItems)
			{
				TaskQueueStatus status;
				if (numItems < size_t(partitionSize) * 1024u)
				{
					// Run locally until there's a thread available.
					status.FindFreeQueue(mDispatcher.ThreadPool());
				}
				else
				{
					// If there are many generated partitions, parallel jobs will be generated
					// even if there are no available threads.
					status.FindAnyQueue(mDispatcher.ThreadPool());
				}

				auto parallelLast = last - numSerialItems;
				for (; iter != parallelLast; ++iter)
				{
					if (status.IsFree())
					{
						ParallelForInternal(iter, last, function, status.GetFirstQueue(), partitionSize, batchSize, intermediate);
						return;
					}
					status.FindFreeQueue(mDispatcher.ThreadPool());
					JobCall(std::forward<decltype(function)>(function), *iter, intermediate);
				}
			}
		}

		// Rest of iterations
		for (; iter != last; ++iter)
		{
			JobCall(std::forward<decltype(function)>(function), *iter, intermediate);
		}
	}

	struct TaskQueueStatus
	{
	public:
		inline void FindAnyQueue(ThreadPool& tp) { mFirstQueueIndex = tp.UseNextQueueIndexExceptThis(); }
		inline void FindFreeQueue(ThreadPool& tp) { mFirstQueueIndex = tp.UseJoblessQueueIndexExceptThis(); }

		inline bool IsFree() const { return mFirstQueueIndex != ion::Thread::NoQueueIndex; }
		inline ion::Thread::QueueIndex GetFirstQueue() const { return mFirstQueueIndex; }

	private:
		ion::Thread::QueueIndex mFirstQueueIndex;
	};

	template <class FunctionA, class FunctionB>
	inline void ParallelInvoke(FunctionA&& functionA, FunctionB&& functionB)
	{
		ParallelInvoke(std::forward<decltype(functionA)>(functionA), std::forward<decltype(functionB)>(functionB),
					   mDispatcher.ThreadPool().UseNextQueueIndexExceptThis());
	}

	template <class FunctionA, class FunctionB>
	inline void ParallelInvoke(FunctionA&& functionA, FunctionB&& functionB, TaskQueueStatus& status)
	{
		ParallelInvoke(std::forward<decltype(functionA)>(functionA), std::forward<decltype(functionB)>(functionB), status.GetFirstQueue());
	}

	template <class FunctionA, class FunctionB>
	inline void ParallelInvoke(FunctionA&& functionA, FunctionB&& functionB, ion::Thread::QueueIndex index)
	{
		ion::Job jobB(GetPool(), std::forward<decltype(functionB)>(functionB), ion::Thread::GetCurrentJob());
		jobB.Execute(index);
		functionA();
		jobB.Wait();
	}

	// Adds job to be executed after time critical block
	inline void PushDelayedJob(BaseJob* job)
	{
		Task task(job);
		if (mDelayedTasks.IsActive())
		{
			if (mDispatcher.ThreadPool().GetWorkerCount() > 0)
			{
				mDispatcher.ThreadPool().PushTask(std::move(task));
			}
			else
			{
				task.Run();
			}
		}
		else
		{
			mDelayedTasks.Add(std::move(task));
		}
	}

	void UpdateOptimizer(double t);

private:
	template <class Function>
	inline void PushTask(bool isLong, Function&& function)
	{
		if (mDispatcher.ThreadPool().GetWorkerCount() > 0 || isLong)
		{
			auto* job = new SelfDestructingJob<Function>(std::forward<decltype(function)>(function));
			Task task(job);
			if (isLong)
			{
				mDispatcher.ThreadPool().PushLongTask(std::move(task));
			}
			else
			{
				mDispatcher.ThreadPool().PushTask(std::move(task));
			}
		}
		else
		{
			function();
		}
	}

	template <typename Function>
	class SelfDestructingJob : public BaseJob
	{
	public:
		SelfDestructingJob(Function&& function) : BaseJob(), mFunction(function) {}

		virtual void RunTask()
		{
			Thread::SetCurrentJob(nullptr);
			mFunction();
			delete this;
		}

	private:
		Function mFunction;
	};

	class DelayedTasks
	{
	public:
		DelayedTasks() : mCounter(0) {}

		void Begin() { mCounter++; }

		void Add(Task&& task)
		{
			AutoLock<Mutex> lock(mSync);
			mTasks.Add(std::move(task));
		}

		bool IsActive() const { return mCounter == 0; }

		void End(ThreadPool& pool)
		{
			ION_ASSERT(mCounter > 0, "Invalid end of time critical block");
			if (--mCounter == 0)
			{
				AutoLock<Mutex> lock(mSync);
				if (pool.GetWorkerCount() > 0)
				{
					std::for_each(mTasks.Begin(), mTasks.End(), [&](Task& task) { pool.PushTask(std::move(task)); });
				}
				else
				{
					std::for_each(mTasks.Begin(), mTasks.End(), [&](Task& task) { task.Run(); });
				}
				mTasks.Clear();
			}
		}

	private:
		Vector<Task, ion::CoreAllocator<Task>> mTasks;
		Mutex mSync;
		std::atomic<size_t> mCounter;
	} mDelayedTasks;

	void BeginTimeCritical() { mDelayedTasks.Begin(); }
	void EndTimeCritical() { mDelayedTasks.End(mDispatcher.ThreadPool()); }

	template <typename Iterator, class Function, class Intermediate>
	void ParallelForInternal(const Iterator& first, const Iterator& last, Function&& function, ion::Thread::QueueIndex firstQueueIndex,
							 const UInt, const UInt batchSize, Intermediate* intermediate = nullptr)
	{
		ION_ASSERT(intermediate != nullptr, "Intermediate missing");
		IntermediateListJob<Iterator, Function, Intermediate> job(mDispatcher.ThreadPool(), first, last, function, batchSize,
																  *intermediate);
		job.Wait(firstQueueIndex);
	}

	template <typename Iterator, class Function>
	void ParallelForInternal(const Iterator& first, const Iterator& last, Function&& function, ion::Thread::QueueIndex firstQueueIndex,
							 const UInt partitionSize, UInt batchSize, EmptyIntermediate*)
	{
		if (partitionSize <= 1)
		{
			ListJob<parallel_for::TaskList> job(mDispatcher.ThreadPool(), first, last, std::forward<decltype(function)>(function),
												batchSize);
			job.Wait(firstQueueIndex, batchSize);
		}
		else if (batchSize > partitionSize)
		{
			ListJob<parallel_for::TaskListBatched<>> job(mDispatcher.ThreadPool(), first, last, std::forward<decltype(function)>(function),
														 batchSize);
			job.Wait(firstQueueIndex, batchSize);
		}
		else
		{
			ListJob<parallel_for::TaskListPartitioned> job(mDispatcher.ThreadPool(), first, last,
														   std::forward<decltype(function)>(function), batchSize);
			job.Wait(firstQueueIndex, partitionSize, batchSize);
		}
	}

	JobDispatcher mDispatcher;
	struct SelfMeasurement
	{
		SelfMeasurement() : mLastTime(0), mBestCoefficientA(1.0f), mCoefficientA(1.0f), mVolatility(1.0f) {}
		~SelfMeasurement()
		{
			// ION_LOG_INFO("Self measurement coefficient=" << mCoefficientA);
		}
		double mLastTime;
		float mBestCoefficientA;
		float mCoefficientA;
		float mVolatility;
		int mGoodResultCounter = 0;
		inline const UInt PartitionSize([[maybe_unused]] size_t workLoad)
		{
#if ION_BUILD_DEBUG
			return 0;  // Force multithreading to detect race conditions in debug builds.
#else
			// #TODO: Fix self-measurement
			// return static_cast<UInt>(static_cast<float>(workLoad) * (mCoefficientA) + 0.5f);
			return static_cast<UInt>(static_cast<float>(workLoad) + 0.5f);
#endif
		}
	};
	SelfMeasurement mMeasurement;
};


template <class FunctionA, class FunctionB>
inline void ParallelInvoke(FunctionA&& functionA, FunctionB&& functionB)
{
	if (ion::core::gSharedScheduler)
	{
		ion::core::gSharedScheduler->ParallelInvoke(std::forward<decltype(functionA)>(functionA),
													std::forward<decltype(functionB)>(functionB));
	}
	else
	{
		functionA();
		functionB();
	}
}

template <class Function>
inline void ParallelForIndex(const size_t start, const size_t end, const ion::UInt partitionSize, const ion::UInt batchSize,
							 Function&& function) noexcept
{
	ion::JobScheduler::IndexIterator startIter(start);
	const ion::JobScheduler::IndexIterator endIter(end);
	if (ion::core::gSharedScheduler)
	{
		ion::core::gSharedScheduler->ParallelFor(partitionSize, startIter, endIter, std::forward<decltype(function)>(function), batchSize);
	}
	else
	{
		while (startIter != endIter)
		{
			function(startIter.mValue);
			++startIter;
		}
	}
}


}  // namespace ion
