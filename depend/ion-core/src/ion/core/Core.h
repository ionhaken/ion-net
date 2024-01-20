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
#include <ion/memory/DomainAllocator.h>
#include <ion/memory/DomainPtr.h>
#include <ion/memory/TSMultiPoolResource.h>
#include <ion/memory/UniquePtr.h>

#include <ion/core/StaticInstance.h>

namespace ion
{

void CoreInit();
void CoreDeinit();

class JobDispatcher;
struct GlobalSettings;

using CoreResource = TSMultiPoolResource<VirtualMemoryBuffer, ion::tag::Core>;
class Core
{
	friend class Engine;
	friend class JobDispatcher;

public:
	const ion::String ExecutableName() const;

	Core(CoreResource&);

private:
	void InitGlobalSettings();
	void DeinitGlobalSettings();
	ion::UniqueOpaquePtr<GlobalSettings> mGlobalSettings;
};

namespace core
{
extern ion::JobScheduler* gSharedScheduler;
extern ion::JobDispatcher* gSharedDispatcher;

STATIC_INSTANCE_PUBLIC(Core, CoreResource);
}  // namespace core

class CoreResourceProxy
{
public:
#if ION_CONFIG_MEMORY_RESOURCES == 1
	template <typename T>
	[[nodiscard]] static inline T* AllocateRaw(size_t n, size_t alignment = alignof(T))
	{
		return reinterpret_cast<T*>(ion::core::gInstance.Source().Allocate(n, alignment));
	}

	template <typename T>
	static void inline DeallocateRaw(T* p, size_t n)
	{
		ion::core::gInstance.Source().Deallocate(p, n);
	}

	template <typename T, size_t Alignment = alignof(T)>
	[[nodiscard]] static inline T* allocate(size_t n)
	{
		return AssumeAligned<T, Alignment>(AllocateRaw<T>(n * sizeof(T), Alignment));
	}

	template <typename T, size_t Alignment = alignof(T)>
	static void inline deallocate(T* p, size_t n)
	{
		DeallocateRaw<T>(p, sizeof(T) * n);
	}
#endif
};

template <typename T>
using CoreAllocator = DomainAllocator<T, CoreResourceProxy>;

template <typename T>
using CorePtr = Ptr<T>;

template <typename T, typename... Args>
inline ion::CorePtr<T> MakeCorePtr(Args&&... args)
{
	return MakeDomainPtr<T, CoreAllocator<T>>(ion_forward(args)...);
}

template <typename T>
inline void DeleteCorePtr(ion::CorePtr<T>& ptr)
{
	DeleteDomainPtr<T, CoreAllocator<T>>(ptr);
}
}  // namespace ion
