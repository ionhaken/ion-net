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

#if ION_EXTERNAL_UNORDERED_MAP == 0
	#include <unordered_map>
#elif ION_EXTERNAL_UNORDERED_MAP == 1
	#define TSL_HH_NO_EXCEPTIONS
	#include <hopscotch_map/hopscotch_map.h>
#endif

namespace ion
{
template <typename A, typename B>
using Pair = std::pair<A, B>;

/**
 * Unordered Map. All keys must be unique.
 * THasher = Hashing function. Check CoreAlgorithm.h for algorithm suggestions.
 */
template <typename TKey, typename TValue, typename THasher = Hasher<TKey>, typename Allocator = GlobalAllocator<Pair<TKey const, TValue>>>
class UnorderedMap
{
#if ION_EXTERNAL_UNORDERED_MAP == 0
	using UnorderedMapContainer = std::unordered_map<TKey, TValue, THasher, std::equal_to<TKey>, Allocator>;
#else
	using UnorderedMapContainer = tsl::hopscotch_map<TKey, TValue, THasher, std::equal_to<TKey>, Allocator>;
#endif
public:
	using KeyType = TKey;
	using ValueType = TValue;
	using ElementType = Pair<const TKey, TValue>;

	UnorderedMap(size_t expectedSize = 32) : mImpl(expectedSize) {}

	template <typename Resource>
	UnorderedMap(Resource* resource, size_t expectedSize) : mImpl(expectedSize, Allocator(resource))
	{
	}

	template <typename Resource>
	UnorderedMap(Resource* resource) : mImpl(Allocator(resource))
	{
	}

	constexpr UnorderedMap(const UnorderedMap& other) : mImpl(other.mImpl) {}

	constexpr UnorderedMap& operator=(const UnorderedMap& other)
	{
		mImpl = other.mImpl;
		return *this;
	}

	UnorderedMap(UnorderedMap&& other) noexcept : mImpl(std::move(other.mImpl)) {}

	UnorderedMap& operator=(UnorderedMap&& other) noexcept
	{
		mImpl = std::move(other.mImpl);
		return *this;
	}


	void Reserve(size_t s) { mImpl.reserve(s); }

	template <typename Resource>
	Resource* MemoryResource()
	{
		return mImpl.get_allocator().GetSource();
	}

	using Element = Pair<TKey, TValue>;

	float LoadFactor() const { return mImpl.load_factor(); }

	void Clear() { mImpl.clear(); }

	using Iterator = typename UnorderedMapContainer::iterator;
	using ConstIterator = typename UnorderedMapContainer::const_iterator;

	auto Insert(const TKey& key, const TValue& value)
	{
		auto pair = mImpl.insert(std::move(std::make_pair(key, value)));
		ION_ASSERT(pair.second, "Value already set");

		return pair.first;
	}

	auto Insert(const TKey& key, TValue&& value)
	{
		auto pair = mImpl.insert(std::move(std::make_pair(key, std::move(value))));

		ION_ASSERT(pair.second, "Value already set");
		return pair.first;
	}

	auto Insert(const Element& d)
	{
		auto pair = mImpl.insert(d);
		ION_ASSERT(pair.second, "Value already set");
		return pair.first;
	}

	auto Insert(Element&& d)
	{
		auto pair = mImpl.insert(std::move(d));
		ION_ASSERT(pair.second, "Value already set");
		return pair.first;
	}

	std::pair<Iterator, bool> TryInsert(const Element& d) { return mImpl.insert(d); }

	const TValue& operator[](const TKey& key) const
	{
		auto iter = mImpl.find(key);
		ION_ASSERT(iter != mImpl.end(), "Key not found");
		return iter->second;
	}

	TValue& operator[](const TKey& key)
	{
		Iterator iter = mImpl.find(key);
		ION_ASSERT(iter != mImpl.end(), "Key not found");
		return iter->second;
	}

	const TValue* Lookup(const TKey& key) const
	{
		auto iter = mImpl.find(key);
		return (iter != mImpl.end()) ? &iter->second : nullptr;
	}

	TValue& At(const TKey& key) { return mImpl.at(key); }
	TValue& at(const TKey& key) { return mImpl.at(key); }
	const TValue& at(const TKey& key) const { return mImpl.at(key); }

	TValue* Lookup(const TKey& key)
	{
		auto iter = mImpl.find(key);
		return iter != mImpl.end() ? &iter->second : nullptr;
	}

	Iterator Remove(const TKey& key)
	{
		auto iter = mImpl.find(key);
		ION_ASSERT(iter != mImpl.end(), "Key not found");
		return mImpl.erase(iter);
	}

	bool IsEmpty() const { return mImpl.empty(); }

	Iterator Find(const TKey& key) { return mImpl.find(key); }

	ConstIterator Find(const TKey& key) const { return mImpl.find(key); }

	Iterator Erase(const Iterator& iter) { return mImpl.erase(iter); }

	ConstIterator Erase(const ConstIterator& iter) { return mImpl.erase(iter); }

	Iterator Begin() { return mImpl.begin(); }

	Iterator End() { return mImpl.end(); }

	ConstIterator Begin() const { return mImpl.begin(); }

	ConstIterator End() const { return mImpl.end(); }

	size_t Size() const { return mImpl.size(); }

private:
	UnorderedMapContainer mImpl;
};
}  // namespace ion
