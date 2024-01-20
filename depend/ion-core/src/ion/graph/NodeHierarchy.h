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
#include <ion/graph/NodeHierarchyTypes.h>
#include <ion/container/Vector.h>
#include <ion/container/Array.h>
#include <ion/container/Algorithm.h>
#include <ion/container/ForEach.h>
#include <ion/jobs/JobScheduler.h>
#include <ion/graph/BaseNodeRegistry.h>
#include <ion/memory/TSMultiPoolResource.h>
#include <ion/arena/ArenaAllocator.h>

#include <ion/container/UnorderedMap.h>

// Force multithreading to detect issues early
#ifndef ION_GRAPH_FORCE_MULTITHREADING
	#define ION_GRAPH_FORCE_MULTITHREADING ION_BUILD_DEBUG
#endif

namespace ion::graph
{
// Purpose of Node Hierarchy is to manage and process efficiently nodes organized in directed
// acyclic graphs.
//
// A directed acyclic graph is a directed graph that contains no cycles.
// https://en.wikipedia.org/wiki/Directed_acyclic_graph
//
// In this node hierarchy implementation, nodes are sorted into phases and partitions.
// Nodes are stored starting from phase-0 to phase-n according to node dependencies.
// First nodes of graph, or input nodes, are always in phase-0, and last nodes of graph,
// output nodes, are always in partition-1.
//
// Nodes in each phase can be processed in parallel. Additionally, since partition-1 contains
// output nodes only, and thus, has no dependency to next phase, nodes in partition-0 of next
// phase can be processed before partition-1 of current phase has finished.
//
// Example, 4 graphs:
//  A D   F    J
//  | |  / \
		//  B E  G  H
//  |    \ /
//  C     I
//
//  Graphs are stored as follows:
//
//           Partition-0| Partition-1
// Phase-0 | ADF		| J
// Phase-1 | BGH        | E
// Phase-2 |			| CI
//
// Nodes shall be processed as follows:
//
// 1. Start processing nodes ADFJ in phase-0
// 2. After ADF of phase-0 are done, start processing nodes BGHE in phase-1
// 3. After BGH of phase-1 are done, process nodes CI of phase-2.
//
template <size_t MaxPhases = 8, typename GraphId = uint32_t>
class NodeHierarchy
{
public:
	using Resource = ion::TSMultiPoolResourceDefault<64 * 1024, ion::tag::NodeGraph>;
	using RegistryResource = TSMultiPoolResourceDefault<16 * 1024, ion::tag::NodeGraph>;
	using NodeRegistry = BaseNodeRegistry<Resource>;

private:
	Resource mResource;
	const NodeRegistry* mTypeInfo;

	template <typename T, uint32_t SmallItemCount, typename CountType, uint32_t TinyItemCount>
	static void Copy(Resource& resource, ArenaVector<T, SmallItemCount, CountType, TinyItemCount>& to,
					 const ArenaVector<T, SmallItemCount, CountType, TinyItemCount>& from)
	{
		ArenaAllocator<T, Resource> allocator(&resource);
		to.Set(allocator, from);
	}

	// #TODO: Replace with ArenaUtil
	template <typename T, uint32_t N>
	static void Resize(Resource& resource, ArenaVector<T, N>& av, size_t s)
	{
		Resize(resource, av, s, s);
	}

	template <typename T, uint32_t N>
	static void Resize(Resource& resource, ArenaVector<T, N>& av, size_t s, size_t minAlloc)
	{
		ArenaAllocator<T, Resource> allocator(&resource);
		av.Resize(allocator, s, minAlloc);
		if (s == 0)
		{
			av.ShrinkToFit(allocator);
		}
	}

	template <typename T, uint32_t SmallItemCount, typename CountType, uint32_t TinyItemCount>
	static void ResizeFast(Resource& resource, ArenaVector<T, SmallItemCount, CountType, TinyItemCount>& av, size_t s)
	{
		ResizeFast(resource, av, s, s * 2);
	}

	template <typename T, uint32_t SmallItemCount, typename CountType, uint32_t TinyItemCount>
	static void ResizeFast(Resource& resource, ArenaVector<T, SmallItemCount, CountType, TinyItemCount>& av, size_t s, size_t minAlloc)
	{
		ArenaAllocator<T, Resource> allocator(&resource);
		av.ResizeFast(allocator, s, minAlloc);
		if (s == 0)
		{
			av.ShrinkToFit(allocator);
		}
	}

	template <typename T>
	static inline void PushBack(Resource& resource, ArenaVector<T>& av, T&& t)
	{
		ArenaAllocator<T, Resource> allocator(&resource);
		av.Emplace(allocator, std::move(t));
	}

	template <typename T>
	static inline void PopBack(Resource& resource, ArenaVector<T>& av)
	{
		av.PopBack();
		if (av.Size() == 0)
		{
			ArenaAllocator<T, Resource> allocator(&resource);
			av.ShrinkToFit(allocator);
		}
	}

public:
	NodeHierarchy(const NodeRegistry* registry)
	  : /* #TODO  mPhases(mResource) */
		mTypeInfo(registry)
	{
		std::fill(mNumNodesPerPhase.Begin(), mNumNodesPerPhase.End(), 0);
	}

	NodeHierarchy(const NodeHierarchy& other) : mTypeInfo(other.mTypeInfo) { *this = other; }

	NodeHierarchy(NodeHierarchy&& other) = delete;
	NodeHierarchy& operator=(NodeHierarchy&& other) = delete;

	NodeHierarchy& operator=(const NodeHierarchy& other)
	{
		ION_ASSERT(this != &other, "Assign to self");
		mTypeInfo = other.mTypeInfo;

		size_t j = 0;
		while (other.IsPhaseValid(j))
		{
			mNumNodesPerPhase[j] = other.mNumNodesPerPhase[j];
			for (size_t i = 0; i < 2; ++i)
			{
				mPhases[i][j].Copy(mResource, other.mPhases[i][j], *mTypeInfo);
			}
			j++;
		}

		while (IsPhaseValid(j))
		{
			mNumNodesPerPhase[j] = 0;
			for (size_t i = 0; i < 2; ++i)
			{
				mPhases[i][j].Clear(mResource, *mTypeInfo);
			}
			j++;
		}

		if (mGraphInfo.Size() != other.mGraphInfo.Size())
		{
			while (mGraphInfo.Size() > other.mGraphInfo.Size())
			{
				mGraphInfo.Back().Clear(mResource);
				PopBack(mResource, mGraphInfo);
			}
			ResizeFast(mResource, mGraphInfo, other.mGraphInfo.Size(), other.mGraphInfo.Size());
		}
		for (size_t i = 0; i < other.mGraphInfo.Size(); ++i)
		{
			mGraphInfo[i].Copy(mResource, other.mGraphInfo[i]);
		}
		return *this;
	}

	~NodeHierarchy()
	{
		ion::ForEach(mPhases,
					 [&](auto& partitions) { ion::ForEach(partitions, [&](auto& phase) { phase.Clear(mResource, *mTypeInfo); }); });
		for (size_t i = 0; i < mGraphInfo.Size(); ++i)
		{
			mGraphInfo[i].Clear(mResource);
		}
		NodeRegistry::Clear(mResource, mGraphInfo);
		// mTypeInfo.Clear(mResource);
	}

	template <typename T, ion::UInt partitionSize, ion::UInt batchSize, typename GraphContextType>
	static ION_INLINE_RELEASE void NodeEntryPoint(ArenaVector<uint8_t>& nodeData, GraphContextType& userData, ion::JobScheduler& js)
	{
		T* iter = ion::AssumeAligned<T>(reinterpret_cast<T*>(nodeData.Data()));

#if ION_GRAPH_FORCE_MULTITHREADING
		if constexpr (true)
#else
		if constexpr (batchSize < 16 * 1024 || partitionSize == 1)  // Use parallel only for heavy types. Currently this is just guess work.
#endif
		{
			js.ParallelFor(&iter[0], &iter[nodeData.Size() / sizeof(T)],
#if ION_GRAPH_FORCE_MULTITHREADING
						   0u, 1u,
#else
						   partitionSize, batchSize,
#endif
						   [&](T& t) { t.Update(userData); });
		}
		else
		{
			T* end = &iter[nodeData.Size() / sizeof(T)];
			do
			{
				iter->Update(userData);
				iter++;
			} while (iter != end);
		}
	}

	template <typename T, typename GraphContextType>
	static inline void NodeDebugEntryPoint(ArenaVector<uint8_t>& nodeData, GraphContextType& userData)
	{
		T* arr = ion::AssumeAligned<T>(reinterpret_cast<T*>(nodeData.Data()));
		T* iter = &arr[0];
		T* end = &arr[nodeData.Size() / sizeof(T)];
		while (iter != end)
		{
			iter->Debug(userData);
			iter++;
		};
	}

	void Run(void* userData, ion::JobScheduler& js)
	{
		ION_PROFILER_SCOPE(NodeScript, "Node Script");
		ProcessPhase(userData, 0, js);
	}

	struct GraphUpdater
	{
		NodeHierarchy& mGraph;
		GraphId mGraphId;
		ion::UInt mCount = 0;
		ion::UInt mOffset = 0;
		~GraphUpdater()
		{
			// ION_ASSERT(mPhase == mCount, "Invalid node count");
		}
	};

	struct NodeAdder : public GraphUpdater
	{
		template <typename T, typename... Args>
		inline T* Create(ion::UInt phase, Args&&... args)
		{
			ION_PROFILER_SCOPE(NodeScript, "Add node");
			T* t = GraphUpdater::mGraph.template Add<T>(GraphUpdater::mGraphId, phase + GraphUpdater::mOffset,
														phase + 1u == GraphUpdater::mCount, std::forward<Args>(args)...);
			return t;
		}

		template <typename T>
		inline T* Get(ion::UInt phase)
		{
			return GraphUpdater::mGraph.template Get<T>(GraphUpdater::mGraphId, phase + GraphUpdater::mOffset,
														phase + 1u == GraphUpdater::mCount);
		}

		~NodeAdder() {}
	};

	struct NodeEraser : public GraphUpdater
	{
		template <typename T>
		inline NodeEraser& Remove(ion::UInt phase)
		{
			ION_PROFILER_SCOPE(NodeScript, "Remove node");
			ION_ASSERT(phase < GraphUpdater::mCount, "Invalid phase");
			GraphUpdater::mGraph.template Remove<T>(GraphUpdater::mGraphId, phase, GraphUpdater::mOffset,
													phase + 1u == GraphUpdater::mCount);
			return *this;
		}

		void Clear() { NodeRegistry::Clear(GraphUpdater::mGraph.mResource, GraphUpdater::mGraph.mGraphInfo[GraphUpdater::mGraphId].nodes); }
	};
	NodeAdder Reserve(GraphId graphId, UInt phaseCount) { return Reserve(graphId, phaseCount, phaseCount, 0); }

	NodeAdder Reserve(GraphId graphId, [[maybe_unused]] UInt phaseCount, UInt reservedPhaseCount, UInt firstPhase)
	{
		ION_ASSERT(phaseCount > 0, "Invalid node count");
		if (mGraphInfo.Size() <= graphId)
		{
			Resize(mResource, mGraphInfo, graphId + 1, graphId * 2 + 1);
		}
		ION_ASSERT(mGraphInfo[graphId].nodes.Size() == 0, "Invalid node state");
		{
			ResizeFast(mResource, mGraphInfo[graphId].nodes, reservedPhaseCount);
		}
		return NodeAdder{{*this, graphId, ion::SafeRangeCast<ion::UInt>(reservedPhaseCount), firstPhase}};
	}

	ION_FORCE_INLINE NodeEraser Clear(GraphId graphId, UInt phaseCount) { return Clear(graphId, phaseCount, phaseCount, 0); }

	ION_FORCE_INLINE NodeEraser Clear(GraphId graphId, [[maybe_unused]] UInt phaseCount, UInt reservedPhaseCount, UInt firstPhase)
	{
		ION_ASSERT(phaseCount > 0, "Invalid node count");
		ION_ASSERT(mGraphInfo[graphId].nodes.Size() == reservedPhaseCount, "Invalid node count");
		return NodeEraser{{*this, graphId, ion::SafeRangeCast<ion::UInt>(reservedPhaseCount), firstPhase}};
	}

	template <typename T>
	T* Get(GraphId graphId, ion::UInt phaseId, bool isFinalNode)
	{
		Phase& phase = mPhases[isFinalNode ? 1 : 0][phaseId];
		auto blockIndex = phase.BlockIndex(mResource, T::Type);
		typename Phase::NodeBlock& block = phase.nodeBlocks[blockIndex];
		return reinterpret_cast<T*>(&block.data[sizeof(T) * mGraphInfo[graphId].nodes[phaseId].index]);
	}

	template <typename T, typename... Args>
	T* Add(GraphId graphId, ion::UInt phaseId, bool isFinalNode, Args&&... args)
	{
		Phase& phase = mPhases[isFinalNode ? 1 : 0][phaseId];
		auto blockIndex = phase.BlockIndex(mResource, T::Type);
		typename Phase::NodeBlock& block = phase.nodeBlocks[blockIndex];
		ArenaVector<uint8_t>& data = block.data;
		auto pos = data.Size();
		ION_ASSERT((pos % sizeof(T)) == 0, "Invalid pos");
		uint32_t index = ion::SafeRangeCast<uint32_t>(pos / sizeof(T));

		{
			ArenaAllocator<T, Resource> allocator(&mResource);
			data.ResizeFast(allocator, sizeof(T) + pos, (sizeof(T) + pos) * 2);
		}
		T* node = ion::AssumeAligned<T>(new (data.Data() + pos) T(ion_forward(args)...));

		mNumNodesPerPhase[phaseId]++;

		if (block.graphIds.Size() <= index)
		{
			ResizeFast(mResource, block.graphIds, index + 1, index * 2 + 1);
		}
		block.graphIds[index] = graphId;
		mGraphInfo[graphId].nodes[phaseId].index = index;
		return node;
	}

	template <typename T>
	void Remove(GraphId graphId, ion::UInt phaseIdx, ion::UInt phaseOffset, bool isFinalNode)
	{
		ion::UInt phase = phaseIdx + phaseOffset;
		uint8_t partition = isFinalNode ? 1u : 0u;
		auto blockIndex = mPhases[partition][phase].BlockIndex(mResource, T::Type);
		auto& block = mPhases[partition][phase].nodeBlocks[blockIndex];
		ION_ASSERT((block.data.Size() % sizeof(T)) == 0, "Invalid data for type T(size=" << sizeof(T) << ")");
		T* const t = ion::AssumeAligned<T>(reinterpret_cast<T*>(block.data.Data()));
		auto index = mGraphInfo[graphId].nodes[phase].index;
		ION_ASSERT(block.graphIds[index] == graphId, "Found graph " << block.graphIds[index] << " at index " << index);
		t[index].~T();
		auto lastIndex = block.data.Size() / sizeof(T) - 1;
		if (index != lastIndex)
		{
			new (static_cast<void*>(&t[index])) T(std::move(t[lastIndex]));
			t[lastIndex].~T();
			auto otherGraphId = block.graphIds[lastIndex];
			block.graphIds[index] = otherGraphId;

			{
				if (mGraphInfo[otherGraphId].nodes.Size() != 0)
				{
					auto& node = mGraphInfo[otherGraphId].nodes[phase];
					ION_ASSERT(node.index == lastIndex, "Invalid node");
					node.index = index;
				}
			}
		}
		{
			ArenaAllocator<T, Resource> allocator(&mResource);
			block.data.ResizeFast(allocator, lastIndex * sizeof(T), lastIndex * sizeof(T));
		}
		ResizeFast(mResource, block.graphIds, lastIndex);
		if (block.data.Size() == 0)
		{
			{
				ArenaAllocator<T, Resource> allocator(&mResource);
				block.data.ShrinkToFit(allocator);
			}
			mPhases[partition][phase].RemoveBlock(mResource, blockIndex, T::Type);
		}
		ION_ASSERT(mNumNodesPerPhase[phase] > 0, "Invalid node count");
		mNumNodesPerPhase[phase]--;
	}

	void SetDebugging(bool isEnabled) { mIsDebugging = isEnabled; }

private:
	void ProcessPartition(void* userData, uint8_t partition, uint8_t phase, ion::JobScheduler& js, float phaseWorkLoad)
	{
		ION_PROFILER_SCOPE(NodeScript, "Node Partition");
		auto numNodeBlocks = mPhases[partition][phase].nodeBlocks.Size();
		auto partitionWorkLoad = phaseWorkLoad / (numNodeBlocks + 1);
		js.ParallelFor(mPhases[partition][phase].nodeBlocks.Begin(), mPhases[partition][phase].nodeBlocks.End(),
					   partitionWorkLoad > 1.0f ? 0u : numNodeBlocks, 1u,
					   [&](auto& block)
					   { mTypeInfo->mEntryPoints[NodeGroupIdx(block.typeId)][NodeTypeIdx(block.typeId)](block.data, userData, js); });
		if (mIsDebugging)
		{
			ion::ForEach(mPhases[partition][phase].nodeBlocks, [&](auto& block)
						 { mTypeInfo->mDebugEntryPoints[NodeGroupIdx(block.typeId)][NodeTypeIdx(block.typeId)](block.data, userData); });
		}
	}

	inline bool IsPhaseValid(size_t phase) const { return phase < MaxPhases && mNumNodesPerPhase[phase] != 0; }

	void ProcessPhase(void* userData, const uint8_t phase, ion::JobScheduler& js)
	{
		ION_PROFILER_SCOPE(NodeScript, "Node Phase");
		float phaseWorkLoad = static_cast<float>(mNumNodesPerPhase[phase]) / 512;
		auto ProcessFirstPartition = ([&]()
				{
					ProcessPartition(userData, 0, phase, js, phaseWorkLoad);
					if (IsPhaseValid(phase+1))
					{
						ProcessPhase(userData, phase + 1, js);
					}
				});

		if (!mPhases[1][phase].nodeBlocks.IsEmpty() && phaseWorkLoad > 1.0f)
		{
			js.ParallelInvoke([&]() { ProcessFirstPartition(); }, [&]() { ProcessPartition(userData, 1, phase, js, phaseWorkLoad); });
		}
		else
		{
			ProcessFirstPartition();
			ProcessPartition(userData, 1, phase, js, phaseWorkLoad);
		}
		/*ProcessPartition(userData, 0, phase, js, phaseWorkLoad);
		ProcessPartition(userData, 1, phase, js, phaseWorkLoad);
		if (phase < MaxPhases - 1)
		{
			ProcessPhase(userData, phase + 1, js);
		}*/
	}

	struct Phase
	{
		// Sequence of nodes of single type
		struct NodeBlock
		{
			NodeBlock() {}
			NodeBlock(NodeType type) : typeId(type) {}
			NodeBlock(const NodeBlock& other) = delete;
			NodeBlock(NodeBlock&& other) : graphIds(std::move(other.graphIds)), data(std::move(other.data)), typeId(other.typeId) {}

			NodeBlock& operator=(const NodeBlock& other) = delete;
			NodeBlock& operator=(NodeBlock&& other) = delete;

			template <typename Resource>
			NodeBlock& Set(Resource& resource, NodeBlock&& other)
			{
				typeId = other.typeId;
				{
					ArenaAllocator<GraphId, Resource> allocator(&resource);
					graphIds.Set(allocator, std::move(other.graphIds));
				}
				{
					ArenaAllocator<uint8_t, Resource> allocator(&resource);
					data.Set(allocator, std::move(other.data));
				}
				return *this;
			}

			ArenaVector<GraphId> graphIds;
			ArenaVector<uint8_t> data;
			NodeType typeId;

			template <typename Resource>
			void Clear(Resource& resource)
			{
				ION_ASSERT(data.Size() == 0, "Data left");
				NodeRegistry::Clear(resource, graphIds);
			}
		};

		Phase() {}
		// #TODO: Phase(Resource& resource) : mTypeToBlockMap(&resource) {}

		Phase(const Phase&) = delete;

		void Trim(Resource& resource, const NodeRegistry& typeInfo, size_t maxSize = 0)
		{
			while (nodeBlocks.Size() > maxSize)
			{
				if (nodeBlocks.Back().data.Size() != 0)
				{
					uint16_t typeId = nodeBlocks.Back().typeId;
					typeInfo.mClearFunctions[NodeGroupIdx(typeId)][NodeTypeIdx(typeId)](resource, nodeBlocks.Back().data);
				}
				nodeBlocks.Back().Clear(resource);
				NodeHierarchy::PopBack(resource, nodeBlocks);
			}
			NodeHierarchy::ResizeFast(resource, nodeBlocks, maxSize);
		}

		void Clear(Resource& resource, const NodeRegistry& typeInfo)
		{
			Trim(resource, typeInfo);
			mTypeToBlockMap.Clear();
		}

		void Copy(Resource& resource, const Phase& other, const NodeRegistry& typeInfo)
		{
			Trim(resource, typeInfo, other.nodeBlocks.Size());

			for (size_t i = 0; i < nodeBlocks.Size(); ++i)
			{
				if (nodeBlocks[i].data.Size() != 0)
				{
					typeInfo.mClearFunctions[NodeGroupIdx(nodeBlocks[i].typeId)][NodeTypeIdx(nodeBlocks[i].typeId)](resource,
																													nodeBlocks[i].data);
				}

				auto type = other.nodeBlocks[i].typeId;
				nodeBlocks[i].typeId = type;
				NodeHierarchy::ResizeFast(resource, nodeBlocks[i].graphIds, other.nodeBlocks[i].graphIds.Size());
				memcpy(nodeBlocks[i].graphIds.Data(), other.nodeBlocks[i].graphIds.Data(),
					   other.nodeBlocks[i].graphIds.Size() * sizeof(GraphId));

				typeInfo.mCopyFunctions[NodeGroupIdx(type)][NodeTypeIdx(type)](resource, nodeBlocks[i].data, other.nodeBlocks[i].data);
			}
			mTypeToBlockMap = other.mTypeToBlockMap;
		}

		template <typename Resource>
		void RemoveBlock(Resource& resource, size_t blockIndex, NodeType typeId)
		{
			auto typeToBlockIter = mTypeToBlockMap.Find(typeId);
			ION_ASSERT(typeToBlockIter != mTypeToBlockMap.End(), "Invalid type id");
			mTypeToBlockMap.Erase(typeToBlockIter);

			if (blockIndex != nodeBlocks.Size() - 1)
			{
				nodeBlocks[blockIndex].Set(resource, std::move(nodeBlocks.Back()));
				mTypeToBlockMap[nodeBlocks[blockIndex].typeId] = ion::SafeRangeCast<NodeType>(blockIndex);
			}
			PopBack(resource, nodeBlocks);
		}

		template <typename Resource>
		size_t BlockIndex(Resource& resource, NodeType typeId)
		{
			auto typeToBlockIter = mTypeToBlockMap.Find(typeId);
			if (typeToBlockIter != mTypeToBlockMap.End())
			{
				return typeToBlockIter->second;
			}
			auto index = nodeBlocks.Size();
			PushBack(resource, nodeBlocks, NodeBlock(typeId));
			mTypeToBlockMap.Insert(typeId, ion::SafeRangeCast<NodeType>(index));
			return index;
		}

		ArenaVector<NodeBlock> nodeBlocks;
		// #TODO: UnorderedMap<NodeType, uint16_t, Hasher<NodeType>, ArenaAllocator<std::pair<const NodeType, uint16_t>, Resource>>
		// mTypeToBlockMap;
		UnorderedMap<NodeType, uint16_t> mTypeToBlockMap;
	};

	struct NodeIndex
	{
		uint32_t index;
	};

	// Indices of graph's nodes
	struct GraphInfo
	{
		TinyArenaVector<NodeIndex> nodes;

		void Clear(Resource& resource) { NodeRegistry::Clear(resource, nodes); }

		void Copy(Resource& resource, const GraphInfo& other) { NodeHierarchy::Copy(resource, nodes, other.nodes); }
	};

	Array<Array<Phase, MaxPhases>, 2> mPhases;
	Array<uint32_t, MaxPhases> mNumNodesPerPhase;
	ArenaVector<GraphInfo> mGraphInfo;
	bool mIsDebugging = false;
};
}  // namespace ion::graph

#define ION_NODE_ENTRYPOINT_IMPL_SCHEDULER_PARAMS(__name, __graph, __partitionSize, __batchSize)                                          \
	void __name::EntryPoint(ion::ArenaVector<uint8_t>& nodeData, void* userData, ion::JobScheduler& js)                                   \
	{                                                                                                                                     \
		ION_PROFILER_SCOPE_DETAIL(NodeScript, ION_STRINGIFY(__name), nodeData.Size() / sizeof(__name));                                   \
		ion::graph::NodeHierarchy<>::NodeEntryPoint<__name, __partitionSize, __batchSize>(nodeData,                                       \
																						  *static_cast<GraphContextType*>(userData), js); \
	}                                                                                                                                     \
	void __name::DebugEntryPoint(ion::ArenaVector<uint8_t>& nodeData, void* userData)                                                     \
	{                                                                                                                                     \
		ION_PROFILER_SCOPE_DETAIL(NodeScript, ION_STRINGIFY(__name), nodeData.Size() / sizeof(__name));                                   \
		ion::graph::NodeHierarchy<>::NodeDebugEntryPoint<__name>(nodeData, *static_cast<GraphContextType*>(userData));                    \
	}

#define ION_NODE_ENTRYPOINT(__name, __graph, __contextType)                                                                 \
	static constexpr auto Type =                                                                                            \
	  static_cast<ion::graph::NodeType>(__graph::NodeType::__name) | (static_cast<ion::graph::NodeType>(__graph::Id) << 8); \
	static void EntryPoint(ion::ArenaVector<uint8_t>& nodeData, void* userData, ion::JobScheduler& js);                     \
	static void DebugEntryPoint(ion::ArenaVector<uint8_t>& nodeData, void* userData);                                       \
	using GraphContextType = __contextType;
