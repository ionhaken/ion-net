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
#include <ion/tracing/Log.h>
#include <algorithm>

namespace ion
{
template <class InputIt, class OutputIt>
inline OutputIt Copy(InputIt first, InputIt last, OutputIt d_first)
{
	return std::copy(first, last, d_first);
}

template <class InputIt, class OutputIt>
inline OutputIt CopyBackward(InputIt first, InputIt last, OutputIt d_last)
{
	return std::copy_backward(first, last, d_last);
}

template <class InputIt, class OutputIt>
inline void Move(InputIt first, InputIt last, OutputIt d_first)
{
	std::move(first, last, d_first);
}

template <class InputIt, class OutputIt>
inline void MoveBackward(InputIt first, InputIt last, OutputIt d_first)
{
	std::move_backward(first, last, d_first);
}

template <typename Value>
inline void MoveBackByOffset(Value* buffer, size_t offset, size_t count)
{
	if constexpr (std::is_trivially_copyable<Value>::value)
	{
		ion::Copy(buffer + offset, buffer + offset + count, buffer);
	}
	else
	{
		ion::Move(buffer + offset, buffer + offset + count, buffer);
	}
}

template <typename Value>
inline void MoveForwardByOffset(Value* buffer, size_t offset, size_t count)
{
	auto* last = buffer - offset;
	auto* first = last - count;
	ION_ASSERT(buffer < first || buffer > last, "Invalid copy_backward");
	if constexpr (std::is_trivially_copyable<Value>::value)
	{
		ion::CopyBackward(first, last, buffer);
	}
	else
	{
		ion::MoveBackward(first, last, buffer);
	}
}

// Assuming container with sorted elements, inserts to correct position
template <typename TImpl, typename TValue>
inline void InsertSorted(TImpl& impl, const TValue& value, bool allowDuplicates = true)
{
	if (impl.IsEmpty() || impl.Back() < value)
	{
		impl.Add(value);
	}
	else
	{
		auto bounds = std::lower_bound(impl.Begin(), impl.End(), value);
		if (allowDuplicates || !(*bounds == value))
		{
			ION_ASSERT(allowDuplicates || std::find(impl.Begin(), impl.End(), value) == impl.End(), "Duplicated");
			impl.Insert(bounds, value);
		}
	}
}

// Assuming container with sorted elements, inserts to correct position
// #TODO: Check should insert all fast and use quick sort.
template <typename TImpl, typename TSource>
inline void InsertSortedAll(TImpl& impl, const TSource& source)
{
	if (!source.IsEmpty())
	{
		auto iter = source.Begin();
		InsertSorted(impl, *iter);
		++iter;
		for (; iter != source.End(); ++iter)
		{
			if (impl.Back() < *iter)
			{
				impl.Add(*iter);
			}
			else
			{
				auto bounds = std::lower_bound(impl.Begin(), impl.End(), *iter);
				impl.Insert(bounds, *iter);
			}
		}
	}
}

template <typename Container, typename Value>
[[nodiscard]] constexpr auto Find(Container& data, const Value& value)
{
	return std::find(data.Begin(), data.End(), value);
}

template <typename Container, typename Func>
[[nodiscard]] constexpr auto FindIf(Container& container, Func&& func)
{
	return std::find_if(container.Begin(), container.End(), std::forward<decltype(func)>(func));
}

template <typename Iterator, class Compare>
[[nodiscard]] inline constexpr Iterator MaxElement(Iterator begin, Iterator end, Compare compare)
{
	return std::max_element(begin, end, compare);
}

template <class _Container>
class BackInsertIterator
{  // wrap pushes to back of container as output iterator
public:
	// using iterator_category = std::output_iterator_tag;
	using value_type = void;
	using pointer = void;
	using reference = void;

	using container_type = _Container;

#ifdef __cpp_lib_concepts
	using difference_type = std::ptrdiff_t;

	constexpr BackInsertIterator() noexcept = default;
#else	// ^^^ __cpp_lib_concepts / !__cpp_lib_concepts vvv
	using difference_type = void;
#endif	// __cpp_lib_concepts

	explicit BackInsertIterator(_Container& _Cont) noexcept /* strengthened */ : container(&_Cont) {}

	BackInsertIterator& operator=(const typename _Container::Type& _Val)
	{
		container->Add(_Val);
		return *this;
	}

	BackInsertIterator& operator=(typename _Container::Type&& _Val)
	{
		container->Add(std::move(_Val));
		return *this;
	}

	[[nodiscard]] BackInsertIterator& operator*() noexcept /* strengthened */ { return *this; }

	BackInsertIterator& operator++() noexcept /* strengthened */ { return *this; }

	BackInsertIterator operator++(int) noexcept /* strengthened */ { return *this; }

protected:
	_Container* container = nullptr;
};

template <class _Container>
[[nodiscard]] BackInsertIterator<_Container> BackInserter(_Container& _Cont) noexcept /* strengthened */
{
	return BackInsertIterator<_Container>(_Cont);
}

}  // namespace ion
