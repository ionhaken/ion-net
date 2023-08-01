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
#include <ion/util/Hasher.h>

namespace ion
{
/**
 * Convenience type for constant data of TData that is at given memory location
 * with given number of elements. Number of elements is type of TSize.
 */
template <typename TData, typename TSize>
struct ArrayView
{
	constexpr ArrayView() : mData(nullptr), mSize(0) {}
	constexpr ArrayView(TData* const aData, const TSize aSize) : mData(aData), mSize(aSize) {}

	template <typename T>
	constexpr ArrayView(T& container) : mData(container.Data()), mSize(container.Size())
	{
	}

	ArrayView& operator=(const ArrayView& other)
	{
		mData = other.mData;
		mSize = other.mSize;
		return *this;
	}

	using Iterator = TData*;
	using ConstIterator = const TData* const;
	TData* const Data() { return mData; }
	const TData* const Data() const { return mData; }
	TSize Size() const { return mSize; }
	[[nodiscard]] constexpr Iterator Begin() { return Data(); }
	[[nodiscard]] constexpr Iterator End() { return Data() + mSize; }
	[[nodiscard]] constexpr ConstIterator Begin() const { return Data(); }
	[[nodiscard]] constexpr ConstIterator End() const { return Data() + mSize; }

	struct Hasher
	{
		size_t operator()(const ArrayView& key) const { return ion::HashKey<TData>(key.mData, sizeof(TData) * key.mSize); }
	};

private:
	TData* const mData;
	TSize mSize;
};

template <typename TData, typename TSize>
bool ION_INLINE operator==(const ArrayView<TData, TSize>& a, const ArrayView<TData, TSize>& b)
{
	return (a.size == b.size) ? memcmp(a.data, b.data, a.size) == 0 : false;
}
}  // namespace ion
