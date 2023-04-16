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

#include <ion/jobs/JobScheduler.h>
#include <ion/container/Sort.h>

namespace ion
{
using namespace std::placeholders;

template <typename Iterator>
void Sort(Iterator begin, Iterator end, JobScheduler& js, size_t cutoff = 512)
{
	size_t numItems = static_cast<size_t>(end - begin);
	if (numItems >= cutoff)
	{
		JobScheduler::TaskQueueStatus stats;
		stats.FindFreeQueue(js.GetPool());
		if (stats.IsFree())
		{
			typedef typename std::iterator_traits<Iterator>::value_type value_type;
			Iterator mid = std::partition(begin + 1, end, std::bind(std::less<value_type>(), _1, *begin));
			std::swap(*begin, mid[-1]);

			// Bigger half first
			size_t halfItems = static_cast<size_t>(mid - begin);
			if (halfItems > numItems / 2)
			{
				js.ParallelInvoke([&]() { Sort<Iterator>(begin, mid - 1, js, cutoff); }, [&]() { Sort<Iterator>(mid, end, js, cutoff); },
								  stats);
				return;
			}
			else if (halfItems > 1)
			{
				js.ParallelInvoke([&]() { Sort<Iterator>(mid, end, js, cutoff); }, [&]() { Sort<Iterator>(begin, mid - 1, js, cutoff); },
								  stats);
				return;
			}
		}
	}
	ion::Sort<Iterator>(begin, end);
}
}  // namespace ion
