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

#if 0
namespace ion
{
	// Binary splitting list job
	template<typename Iterator, class Function>
	class SplittingJob : public ParallelForJob<Iterator, Function>
	{
		ION_CLASS_NON_COPYABLE_NOR_MOVABLE(SplittingJob);
	public:
		SplittingJob(ThreadPool& tp, const Iterator& first, const Iterator& last, const Function&& function,
			const size_t itemsPerJob, UInt firstQueueIndex)
			:
			ParallelForJob<Iterator, Function>(tp, first, function)
		{
			const size_t numItems = last - first;
			// Run leftover (mod) items in main thread.
			size_t currentThreadItems = (itemsPerJob == numItems) ? itemsPerJob : (numItems % itemsPerJob);

			const size_t otherWork = numItems - currentThreadItems;

			mMaxSplits = ion::Min(numItems, this->GetThreadPool().GetQueueCount()*itemsPerJob);
			// ION_LOG_INFO_FMT("Number of items %d-%d/%d per task: %d", currentThreadItems, otherWork, numItems, itemsPerJob);
			if (otherWork)
			{
				const size_t numItemsPerWorker = (numItems / this->GetThreadPool().GetWorkerCount()) + 1;
				AddTasks(otherWork, itemsPerJob, numItemsPerWorker, firstQueueIndex);
			}
			if (currentThreadItems > 0)
			{
				ion::Thread::SetCurrentJob(this);
				RunTaskInternal(/*otherWork, otherWork + currentThreadItems*/);
				ion::Thread::SetCurrentJob(this->mSourceJob);
			}
		}

		bool PushTask(const UInt index, const size_t /*start*/, const size_t /*end*/)
		{
			AutoLock<ThreadSynchronizer> lock(this->GetSynchronizer());
			if (mMaxSplits)
			{
				this->AddTaskLockFree(index);
				this->GetSynchronizer().NotifyOne();
				mMaxSplits--;
				return true;
			}
			else
			{
				ION_LOG_INFO("Hit Max Splits");
				return false;
			}
		}

	private:
		void AddTasks(size_t numItems, size_t numItemsPerJob, size_t numItemsPerWorker, UInt firstQueueIndex)
		{
			AutoLock<ThreadSynchronizer> lock(this->GetSynchronizer());
			const UInt index = firstQueueIndex != ion::Thread::NoQueueIndex ? firstQueueIndex :
				ion::Thread::GetQueueIndex() + static_cast<UInt>(this->mSourceJob == nullptr);
			for (size_t i = 0; i < numItems; i += numItemsPerJob)
			{
				this->AddTaskLockFree((index + (i / numItemsPerWorker)) % this->GetThreadPool().GetQueueCount()/*,
																											i, i + numItemsPerJob*/);
			}
		}

		void DoWork() override final;

		void RunTaskInternal();

		size_t mMaxSplits;
	};

	template<typename Iterator, class Function>
	void SplittingJob<Iterator, Function>::DoWork()
	{
		ION_PROFILER_SCOPE(Scheduler, "Splitted Tasks");
		this->OnTaskStarted();
		RunTaskInternal();
		this->OnTaskDone();
	}

	template<typename Iterator, class Function>
	inline void SplittingJob<Iterator, Function>::RunTaskInternal()
	{
		size_t start = 0; // FIXME
		size_t end = 0; // FIXME
		size_t last = end;
		size_t i = start;
		size_t cutOff = 1;
		if (start + cutOff < last)
		{
			for (; i < last - cutOff; i++)
			{
				const UInt joblessIndex = this->GetThreadPool().UseJoblessQueueIndexExceptThis();
				if (joblessIndex != UINT16_MAX)
				{
					const size_t numLeft = last - i;
					ION_ASSERT(numLeft >= 2, "Not enough left to split");
					const size_t split = numLeft / 2;
					if (PushTask(joblessIndex, last - split, last))
					{
						last -= split;
					}
				}
				JobCall(this->mFunction, this->mIterator[i]);
			}
		}
		for (; i < last; i++)
		{
			JobCall(this->mFunction, this->mIterator[i]);
		}
	}

}
#endif
