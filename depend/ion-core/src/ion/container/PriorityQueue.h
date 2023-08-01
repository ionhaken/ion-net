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
#include <ion/tracing/Log.h>
#include <vector>
#include <queue>

namespace ion
{
template <typename TValue>
class PriorityQueue
{
public:
	PriorityQueue(size_t reserve = 0)
	: mImpl(std::less<TValue>(), reserve > 0 ? std::move(createContainer(reserve)) : std::move(std::vector<TValue>()))
	{
	}

	inline void Push(const TValue& key) { mImpl.push(key); }

	inline void Pop() { mImpl.pop(); }

	[[nodiscard]] inline const auto& Top() const 
	{
		ION_ASSERT(!mImpl.empty(), "No elements left");
		return mImpl.top(); 
	}

	// #TODO: Need to have access to data part without touching priority part hence const casting. But we should have new priority queue
	// type with own key and priority types...
	[[nodiscard]] inline TValue& Top() 
	{ 
		ION_ASSERT(!mImpl.empty(), "No elements left");
		return const_cast<TValue&>(mImpl.top()); 
	}

	[[nodiscard]] inline bool IsEmpty() const { return mImpl.empty(); }

	[[nodiscard]] inline size_t Size() const { return mImpl.size(); }

private:
	std::priority_queue<TValue, std::vector<TValue>> mImpl;
	inline std::vector<TValue> createContainer(size_t reserve)
	{
		std::vector<TValue> container;
		container.reserve(reserve);
		return container;
	}
};
}  // namespace ion
