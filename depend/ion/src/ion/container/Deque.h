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
#include <ion/container/Algorithm.h>
#include <ion/memory/GlobalAllocator.h>

#include <deque>

namespace ion
{
template <typename T, typename TAllocator = GlobalAllocator<T>>
class Deque
{
	using DequeImpl = std::deque<T, TAllocator>;
public:
	using Iterator = typename DequeImpl::iterator;
	using ReverseIterator = typename DequeImpl::reverse_iterator;
	using ConstIterator = typename DequeImpl::const_iterator;
	using ConstReverseIterator = typename DequeImpl::const_reverse_iterator;

	constexpr Deque() {}

	template <typename Resource>
	constexpr Deque(Resource* r) : mImpl(r)
	{
	}

	constexpr Deque(const Deque& other) noexcept : mImpl(other.mImpl) {}

	constexpr Deque(Deque&& other) noexcept : mImpl(std::move(other.mImpl)) {}

	constexpr Deque& operator=(const Deque& other) noexcept
	{
		mImpl = other.mImpl;
		return *this;
	}

	constexpr Deque& operator=(Deque&& other) noexcept
	{
		mImpl = std::move(other.mImpl);
		return *this;
	}

	[[nodiscard]] constexpr T& operator[](std::size_t index) { return mImpl[index]; }

	[[nodiscard]] constexpr const T& operator[](std::size_t index) const { return mImpl[index]; }

	inline void PushFront(const T& val) { return mImpl.push_front(val); }

	inline void PushBack(const T& val) { return mImpl.push_back(val); }

	inline void PushFront(T&& val) { mImpl.emplace_front(std::move(val)); }

	inline void PushBack(T&& val) { mImpl.emplace_back(std::move(val)); }

	[[nodiscard]] constexpr T& Front() { return mImpl.front(); }

	[[nodiscard]] constexpr const T& Front() const { return mImpl.front(); }

	[[nodiscard]] constexpr T& Back() { return mImpl.back(); }

	[[nodiscard]] constexpr const T& Back() const { return mImpl.back(); }

	ION_FORCE_INLINE void PopFront() { mImpl.pop_front(); }

	ION_FORCE_INLINE void PopBack() { mImpl.pop_back(); }

	ION_FORCE_INLINE bool IsEmpty() const { return mImpl.empty(); }

	ION_FORCE_INLINE size_t Size() const { return mImpl.size(); }

	ION_FORCE_INLINE void Clear() { mImpl.clear(); }

	ION_FORCE_INLINE void Insert(size_t index, const T& val) { mImpl.insert(mImpl.begin() + index, val); }

	ION_FORCE_INLINE void Insert(Iterator iterator, const T& val) { mImpl.insert(iterator, val); }
	ION_FORCE_INLINE void Insert(ReverseIterator iterator, const T& val) { mImpl.insert(iterator, val); }
	ION_FORCE_INLINE void Insert(ConstReverseIterator iterator, const T& val) { mImpl.insert(iterator, val); }

	ION_FORCE_INLINE Iterator Erase(ConstIterator iter) { return mImpl.erase(iter); }
	ION_FORCE_INLINE Iterator Erase(Iterator iter) { return mImpl.erase(iter); }
	ION_FORCE_INLINE ReverseIterator Erase(ReverseIterator iter) { return mImpl.erase(iter); }
	ION_FORCE_INLINE ReverseIterator Erase(ConstReverseIterator iter) { return mImpl.erase(iter); }
	ION_FORCE_INLINE Iterator Erase(ConstIterator start, ConstIterator end) { return mImpl.erase(start, end); }
	ION_FORCE_INLINE Iterator Erase(size_t pos) { return mImpl.erase(mImpl.begin() + pos); }
	ION_FORCE_INLINE Iterator Erase(size_t start, size_t end) { return mImpl.erase(mImpl.begin() + start, mImpl.begin() + end); }

	ION_FORCE_INLINE void SortSimpleType() { std::sort(mImpl.begin(), mImpl.end()); }

	ION_FORCE_INLINE void InsertSorted(const T& value) { ion::InsertSorted(mImpl, value); }

	inline void Resize(size_t size) { mImpl.resize(size); }

	ION_FORCE_INLINE void ShrinkToFit() { mImpl.shrink_to_fit(); }

	[[nodiscard]] constexpr Iterator Begin() { return mImpl.begin(); }
	[[nodiscard]] constexpr Iterator End() { return mImpl.end(); }
	[[nodiscard]] constexpr ConstIterator Begin() const { return mImpl.begin(); }
	[[nodiscard]] constexpr ConstIterator End() const { return mImpl.end(); }

	[[nodiscard]] constexpr Iterator begin() { return mImpl.begin(); }
	[[nodiscard]] constexpr Iterator end() { return mImpl.end(); }
	[[nodiscard]] constexpr ConstIterator begin() const { return mImpl.begin(); }
	[[nodiscard]] constexpr ConstIterator end() const { return mImpl.end(); }

	[[nodiscard]] constexpr ReverseIterator RBegin() { return mImpl.rbegin(); }
	[[nodiscard]] constexpr ReverseIterator REnd() { return mImpl.rend(); }
	[[nodiscard]] constexpr ConstReverseIterator RBegin() const { return mImpl.rbegin(); }
	[[nodiscard]] constexpr ConstReverseIterator REnd() const { return mImpl.rend(); }

private:
	DequeImpl mImpl;
};
}  // namespace ion
