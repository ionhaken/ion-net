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
#include <ion/container/Sort.h>
#include <ion/container/Vector.h>
#include <cmath>

namespace ion
{
template <typename Iterator, typename Callback>
double CalcMean(
  Iterator begin, Iterator end, Callback&& callback = [](const auto& v) { return v; })
{
	size_t numSamples = static_cast<size_t>(end - begin);
	double sum = 0.0;
	for (auto iter = begin; iter != end; ++iter)
	{
		sum += static_cast<double>(callback(*iter));
	}
	return sum / numSamples;
}

template <typename Iterator, typename Callback>
double CalcStandardDeviation(Iterator begin, Iterator end, Callback&& callback)
{
	const double mean = CalcMean(begin, end, callback);

	double standardDeviation = 0.0;
	for (auto iter = begin; iter != end; ++iter)
	{
		standardDeviation += std::pow(static_cast<double>(callback(*iter)) - mean, 2);
	}
	size_t numSamples = static_cast<size_t>(end - begin);
	standardDeviation = std::sqrt(standardDeviation / numSamples);
	return standardDeviation;
}

template <typename Iterator>
double CalcStandardDeviation(Iterator begin, Iterator end)
{
	return CalcStandardDeviation(begin, end, [](const auto& v) { return v; });
}

// TODO: C++20: Use std::nth_element to calculate this faster
template <typename Iterator, typename Callback>
double CalcMedian(Iterator begin, Iterator end, Callback&& callback)
{
	ion::SmallVector<double, 2048> values;
	values.Reserve(end - begin);
	for (auto iter = begin; iter != end; ++iter)
	{
		values.Add(static_cast<double>(callback(*iter)));
	}
	ion::Sort(values.Begin(), values.End());
	return values.IsEmpty() ? 0 : values[values.Size() / 2];
}

template <typename Iterator>
double CalcMedian(Iterator begin, Iterator end)
{
	return CalcMedian(begin, end, [](const auto& v) { return v; });
}
}  // namespace ion
