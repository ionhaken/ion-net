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
#include <ion/arena/ArenaVector.h>
#include <ion/arena/ArenaUtil.h>

namespace ion::graph
{
class Resource;

[[nodiscard]] constexpr uint16_t NodeTypeIdx(uint16_t typeId) { return typeId & 0xFF; }

[[nodiscard]] constexpr uint16_t NodeGroupIdx(uint16_t typeId) { return (typeId >> 8); }

template <typename GraphResource>
struct BaseNodeRegistry
{
	static constexpr size_t NodeGroupCount = 64;

	template <typename ClearResource, typename T, uint32_t SmallItemCount, typename CountType, uint32_t TinyItemCount>
	static void Clear(ClearResource& resource, ArenaVector<T, SmallItemCount, CountType, TinyItemCount>& av)
	{
		ArenaAllocator<T, ClearResource> allocator(&resource);
		av.Clear();
		av.ShrinkToFit(allocator);
	}

	template <typename T>
	static inline void NodeConstruct(ArenaVector<uint8_t>& nodeData, const ArenaVector<uint8_t>& otherNodeData, size_t oldSize)
	{
		auto numElems = nodeData.Size() / sizeof(T);
		T* arr = reinterpret_cast<T*>(nodeData.Data());
		const T* otherArr = reinterpret_cast<const T*>(otherNodeData.Data());

		for (size_t i = oldSize / sizeof(T); i < numElems; ++i)
		{
			new (static_cast<void*>(ion::AssumeAligned<>(&arr[i]))) T(otherArr[i]);
		}
	}

	template <typename T>
	static inline void NodeDestruct(ArenaVector<uint8_t>& nodeData, size_t newSize)
	{
		auto numElems = nodeData.Size() / sizeof(T);
		T* arr = reinterpret_cast<T*>(nodeData.Data());
		for (size_t i = newSize / sizeof(T); i < numElems; ++i)
		{
			arr[i].~T();
		}
	}

	template <typename ClearResource, typename T>
	static inline void NodeClear(ClearResource& resource, ArenaVector<uint8_t>& nodeData)
	{
		if constexpr (!std::is_trivially_destructible<T>::value)
		{
			NodeDestruct<T>(nodeData, 0);
		}
		Clear(resource, nodeData);
	}

	template <typename CopyResource, typename T>
	static inline void NodeCopy(CopyResource& resource, ArenaVector<uint8_t>& nodeData, const ArenaVector<uint8_t>& otherNodeData)
	{
		ION_ASSERT(nodeData.Size() == 0, "Assuming destination is empty");
		ArenaAllocator<T, CopyResource> allocator(&resource);
		if constexpr (std::is_trivially_copyable<T>::value)
		{
			nodeData.ResizeFast(allocator, otherNodeData.Size(), otherNodeData.Size());
			memcpy(nodeData.Data(), otherNodeData.Data(), otherNodeData.Size());
		}
		else
		{
			nodeData.ResizeFast(allocator, otherNodeData.Size(), otherNodeData.Size());
			NodeConstruct<T>(nodeData, otherNodeData, 0);
		}
	}

	using NodeRunFunc = void (*)(ArenaVector<uint8_t>& nodeData, void* userData, ion::JobScheduler& js);
	using NodeDebugFunc = void (*)(ArenaVector<uint8_t>& nodeData, void* userData);
	using NodeCopyFunc = void (*)(GraphResource& resource, ArenaVector<uint8_t>& nodeData, const ArenaVector<uint8_t>& otherNodeData);
	using NodeClearFunc = void (*)(GraphResource& resource, ArenaVector<uint8_t>& nodeData);

	template <typename T>
	void RegisterNodeType()
	{
		if constexpr (T::Type != 0)	 // IO Reservation Node
		{
			auto groupIdx = ion::graph::NodeGroupIdx(T::Type);
			auto typeIdx = ion::graph::NodeTypeIdx(T::Type);
			mEntryPoints[groupIdx][typeIdx] = &T::EntryPoint;
			mDebugEntryPoints[groupIdx][typeIdx] = &T::DebugEntryPoint;
			mCopyFunctions[groupIdx][typeIdx] = &NodeCopy<GraphResource, T>;
			mClearFunctions[groupIdx][typeIdx] = &NodeClear<GraphResource, T>;
		}
	}

	template <typename Callback>
	inline void ForEachFunctionType(Callback&& callback)
	{
		callback(mEntryPoints);
		callback(mCopyFunctions);
		callback(mClearFunctions);
		callback(mDebugEntryPoints);
	}

	template <typename ArenaResource>
	inline void Reserve(ArenaResource& resource, size_t group, size_t s)
	{
		ForEachFunctionType([&](auto& list) { ion::arena::Resize(resource, list[group], s); });
	}

	template <typename ArenaResource>
	void Clear(ArenaResource& resource)
	{
		for (size_t group = 0; group < NodeGroupCount; ++group)
		{
			ForEachFunctionType([&](auto& list) { ion::arena::Clear(resource, list[group]); });
		}
	}

	ion::Array<ArenaVector<NodeRunFunc>, NodeGroupCount> mEntryPoints;
	ion::Array<ArenaVector<NodeCopyFunc>, NodeGroupCount> mCopyFunctions;
	ion::Array<ArenaVector<NodeClearFunc>, NodeGroupCount> mClearFunctions;
	ion::Array<ArenaVector<NodeDebugFunc>, NodeGroupCount> mDebugEntryPoints;
};
}  // namespace ion::graph
