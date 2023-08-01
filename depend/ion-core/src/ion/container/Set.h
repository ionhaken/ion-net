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
#include <ion/Base.h>
#include <ion/util/Hasher.h>
#include <ion/memory/GlobalAllocator.h>
#include <hopscotch_map/hopscotch_set.h>

//#include <set>

namespace ion
{
template <class TKey, class TAllocator = ion::GlobalAllocator<TKey>, class THasher = Hasher<TKey>>
class Set
{
public:
	// using SetImplementation = std::set<TKey, std::less<TKey>, TAllocator>;
	// #TODO: std set is faster with proper allocator?
	using SetImplementation = tsl::hopscotch_set<TKey, THasher, std::equal_to<TKey>, TAllocator>;
	using ElementType = TKey;

	explicit Set() : mImpl() {}

	template <typename Resource>
	constexpr Set(Resource* const resource) : mImpl(resource)
	{
	}

	constexpr Set(const Set& other) noexcept : mImpl(other.mImpl) {}

	constexpr Set(Set&& other) noexcept : mImpl(other.mImpl) {}

	Set& operator=(const Set& other)
	{
		mImpl = other.mImpl;
		return *this;
	}

	template <class... Args>
	std::pair<typename SetImplementation::iterator, bool> Add(Args&&... args)
	{
		return mImpl.emplace(std::forward<Args>(args)...);
	}

	bool IsEmpty() const { return mImpl.empty(); }

	void Clear() { mImpl.clear(); }

	typename SetImplementation::iterator Find(const TKey& key) { return mImpl.find(key); }

	typename SetImplementation::const_iterator Find(const TKey& key) const { return mImpl.find(key); }

	typename SetImplementation::iterator Begin() { return mImpl.begin(); }
	typename SetImplementation::iterator End() { return mImpl.end(); }
	typename SetImplementation::const_iterator Begin() const noexcept { return mImpl.begin(); }
	typename SetImplementation::const_iterator End() const noexcept { return mImpl.end(); }

	typename SetImplementation::iterator Erase(typename SetImplementation::iterator iter) { return mImpl.erase(iter); }

	typename SetImplementation::const_iterator Remove(const TKey& key)
	{
		auto iter = mImpl.find(key);
		ION_ASSERT(iter != mImpl.end(), "Element not found");
		return mImpl.erase(iter);
	}

	template <typename Iterator>
	void Insert(Iterator begin, Iterator end)
	{
		mImpl.insert(begin, end);
	}

	size_t Size() const { return mImpl.size(); }

	const TKey& Front() { return *mImpl.begin(); }
	const TKey& Back() { return *mImpl.end(); }

	void Reserve(size_t s) { mImpl.reserve(s); }

private:
	SetImplementation mImpl;
};
}  // namespace ion
