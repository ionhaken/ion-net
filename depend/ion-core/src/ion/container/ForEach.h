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

#include <ion/debug/Error.h>
#include <type_traits>
#include <utility> // move

namespace ion
{
template <typename T>
constexpr T&& Forward(std::remove_reference_t<T>& param)
{
	return static_cast<T&&>(param);
}

// Erases target, but can change order of items for performance.
template <typename Container, typename Iterator>
ION_FORCE_INLINE Iterator UnorderedErase(Container& container, Iterator iter)
{
	ION_ASSERT_FMT_IMMEDIATE(iter != container.End(), "Invalid iterator");
	if (iter != (container.End()-1))
	{
		*iter = std::move(container.Back());
	}
	container.Pop();
	return iter;
}

// Erases index, but can change order of items for performance.
template <typename Container>
ION_FORCE_INLINE void UnorderedEraseAt(Container& container, size_t index)
{
	if (index != container.Size() - 1)
	{
		container[index] = std::move(container.Back());
	}
	container.Pop();
}

template <typename Container, typename Iterator>
ION_FORCE_INLINE Iterator Erase(Container& container, Iterator iter)
{
	ION_ASSERT_FMT_IMMEDIATE(iter != container.End(), "Invalid iterator");
	return container.Erase(iter);
}

enum class ForEachOp : unsigned int
{
	Next = 0,
	Erase,
	Break
};

namespace
{
struct EraseVisitor
{
	template <typename Container, typename Iterator>
	static inline Iterator Visit(Container& container, Iterator& iterator)
	{
		return ion::Erase(container, iterator);
	}
};

struct UnorderedEraseVisitor
{
	template <typename Container, typename Iterator>
	static inline Iterator Visit(Container& container, Iterator& iterator)
	{
		return ion::UnorderedErase(container, iterator);
	}
};

template <typename EraseVisitor, typename TData, typename TFunc>
ION_FORCE_INLINE void ForEachEraseInternal(TData& data, TFunc&& func)
{
	auto iter = data.Begin();
	auto last = data.End();
	for (; iter != last;)
	{
		auto op = func(*iter);
		if (op != ForEachOp::Next)
		{
			ION_ASSERT_FMT_IMMEDIATE(op == ForEachOp::Erase, "Invalid operation");
			iter = EraseVisitor::Visit(data, iter);
			last = data.End();
		}
		else
		{
			++iter;
		}
	}
}
}  // namespace

template <typename TData, typename TFunc>
ION_FORCE_INLINE void ForEachPartial(TData* iter, TData* last, TFunc&& func)
{
	for (; iter != last; ++iter)
	{
		func(*iter);
	}
}

template <typename TData, typename TFunc>
ION_FORCE_INLINE void ForEach(TData& data, TFunc&& func)
{
	auto iter = data.Begin();
	const auto last = data.End();
	for (; iter != last; ++iter)
	{
		func(*iter);
		ION_ASSERT_FMT_IMMEDIATE(last == data.End(), "Container changed during loop");
	}
}

template <typename TData, typename TFunc>
ION_FORCE_INLINE ion::ForEachOp ForEachBreakable(TData& data, TFunc&& func)
{
	auto iter = data.Begin();
	const auto last = data.End();
	for (; iter != last; ++iter)
	{
		auto op = func(*iter);
		ION_ASSERT_FMT_IMMEDIATE(last == data.End(), "Container changed during loop");
		if (op != ion::ForEachOp::Next)
		{
			ION_ASSERT_FMT_IMMEDIATE(op == ion::ForEachOp::Break, "Invalid operation");
			return ion::ForEachOp::Break;
		}
	}
	return ion::ForEachOp::Next;
}

template <typename TData, typename TFunc>
ION_FORCE_INLINE void ForEachErase(TData& data, TFunc&& func)
{
	ion::ForEachEraseInternal<EraseVisitor>(data, Forward<TFunc>(func));
}

template <typename TData, typename TFunc>
ION_FORCE_INLINE void ForEachEraseUnordered(TData& data, TFunc&& func)
{
	ion::ForEachEraseInternal<UnorderedEraseVisitor>(data, Forward<TFunc>(func));
}

template <typename TData, typename TFunc>
ION_FORCE_INLINE void ForEachReverse(TData& data, TFunc&& func)
{
	auto iter = data.RBegin();
	const auto last = data.REnd();
	for (; iter != last; ++iter)
	{
		func(*iter);
		ION_ASSERT_FMT_IMMEDIATE(last == data.REnd(), "Container changed during loop");
	}
}

template <typename TData, typename TFunc>
ION_FORCE_INLINE void ForEachPartialIndex(TData* iter, TData* last, TFunc&& func)
{
	size_t index = 0;
	for (; iter != last; ++iter)
	{
		func(index, *iter);
		++index;
	}
}

template <typename TData, typename TFunc>
ION_FORCE_INLINE void ForEachIndex(TData& data, TFunc&& func)
{
	auto iter = data.Begin();
	const auto last = data.End();
	size_t index = 0;
	for (; iter != last; ++iter)
	{
		func(index, *iter);
		ION_ASSERT_FMT_IMMEDIATE(last == data.End(), "Container changed during loop");
		++index;
	}
}

}  // namespace ion
