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

namespace ion
{
// #TODO: Replace with array view
template <typename TData, typename TSize>
struct MultiData
{
	MultiData() : data(nullptr), size(0) {}
	MultiData(const TData* aData, const TSize aSize) : data(aData), size(aSize) {}

	template <typename T>
	MultiData(const T& container) : data(container.Data()), size(container.Size())
	{
	}

	const TData* data;
	const TSize size;

	MultiData& operator=(const MultiData& other)
	{
		const_cast<TData&>(*data) = const_cast<TData&>(*other.data);
		const_cast<TSize&>(size) = other.size;
		return *this;
	}

	using Iterator = TData*;
	using ConstIterator = const TData* const;
	const TData* Data() { return data; }
	const TData* const Data() const { return data; }
	TSize Size() const { return size; }
	[[nodiscard]] constexpr Iterator Begin() { return Data(); }
	[[nodiscard]] constexpr Iterator End() { return Data() + size; }
	[[nodiscard]] constexpr ConstIterator Begin() const { return Data(); }
	[[nodiscard]] constexpr ConstIterator End() const { return Data() + size; }

	struct Hasher
	{
		size_t operator()(const MultiData& key) const { return ion::HashKey<TData>(key.data, sizeof(TData) * key.size); }
	};
};

template <typename TData, typename TSize>
bool ION_INLINE operator==(const MultiData<TData, TSize>& a, const MultiData<TData, TSize>& b)
{
	return (a.size == b.size) ? memcmp(a.data, b.data, a.size) == 0 : false;
}

}  // namespace ion
