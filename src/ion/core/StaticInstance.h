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
#include <ion/container/StaticRawBuffer.h>

namespace ion
{
template <typename InstanceData, typename MemoryResource>
class StaticInstance
{
public:
	StaticInstance()
#if ION_BUILD_DEBUG
	  : gData(nullptr), gResource(nullptr)
#endif
	{
		// Don't init data here as this constructor will be called by dynamic initializer
		// and we don't know if we need data before that.
	}

	template <typename... Args>
	void Init(Args&&... args)
	{
		gResource.Insert(0, std::forward<Args>(args)...);
		gData.Insert(0, gResource[0]);

		// Don't care if we are leaking, because we don't know when test cases don't need us anymore.
		gResource.DebugAllowMemoryLeaks();
		gData.DebugAllowMemoryLeaks();
	}

	void Deinit()
	{
		gData.Erase(0);
		gResource.Erase(0);
	}

	[[nodiscard]] constexpr MemoryResource& Source() { return gResource[0]; }
	[[nodiscard]] constexpr InstanceData& Data() { return gData[0]; }

private:
	ion::StaticBuffer<InstanceData, 1> gData;
	ion::StaticBuffer<MemoryResource, 1> gResource;
};
}  // namespace ion

#define STATIC_INSTANCE(__dataType, __resourceType)                                 \
	ION_ACCESS_GUARD_STATIC(gGuard);                                                \
	namespace                                                                       \
	{                                                                               \
	std::atomic<int> gIsInitialized = 0;                                            \
	}                                                                               \
	::ion::StaticInstance<__dataType, __resourceType> gInstance;                    \
	__dataType& Instance()                                                          \
	{                                                                               \
		ION_ASSERT_FMT_IMMEDIATE(gIsInitialized != 0, "Static instance not ready"); \
		return gInstance.Data();                                                    \
	}                                                                               \
	__resourceType& Source()                                                        \
	{                                                                               \
		ION_ASSERT_FMT_IMMEDIATE(gIsInitialized != 0, "Static instance not ready"); \
		return gInstance.Source();                                                  \
	}

#define STATIC_INSTANCE_PUBLIC(__dataType, __resourceType) extern ::ion::StaticInstance<__dataType, __resourceType> gInstance;
