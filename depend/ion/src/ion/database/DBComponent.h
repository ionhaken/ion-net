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
#include <ion/database/DBComponentConfig.h>
#include <ion/debug/AccessGuard.h>
#include <ion/memory/UniquePtr.h>

namespace ion
{
#if (ION_COMPONENT_READ_WRITE_CHECKS == 1)
class ComponentDetails
{
	friend struct DefaultComponent;
	friend struct ManualComponent;

	template <typename T>
	friend class ComponentView;

	template <typename T>
	friend class ComponentFacade;

	bool IsManualGuards() const { return !mIsGuardEnabled; }

private:
	ComponentDetails() {}

	void SetManualGuards() { mIsGuardEnabled = false; }

	inline void Validate() const { ION_ASSERT(mComponentValidation == 0xABCD, "Component is corrupted"); }

	ION_ACCESS_GUARD(mGuard);
	int mComponentValidation = 0xABCD;
	bool mIsGuardEnabled = true;
};

template <typename T>
ComponentDetails GetComponentDetails();

#endif

struct DefaultComponent
{
#if (ION_COMPONENT_READ_WRITE_CHECKS == 1)
	static ComponentDetails Get() { return ComponentDetails(); }
#endif
};

struct ManualComponent
{
#if (ION_COMPONENT_READ_WRITE_CHECKS == 1)
	static ComponentDetails Get()
	{
		ComponentDetails s;
		s.SetManualGuards();
		return s;
	}
#endif
};

template <typename T>
ion::UniqueOpaquePtr<T> CreateOpaqueData();

template <typename T, typename... Args>
ion::UniqueOpaquePtr<T> CreateOpaqueDataPars(Args&...);

template <typename T>
void CloneOpaqueData(ion::UniqueOpaquePtr<T>& dst, const ion::UniqueOpaquePtr<T>& src);

}  // namespace ion

#if (ION_COMPONENT_READ_WRITE_CHECKS == 1)
	#define ION_ADMIN_COMPONENT_DETAILS(__name)             \
		template <>                                         \
		ion::ComponentDetails GetComponentDetails<__name>() \
		{                                                   \
			return __name::ComponentType::Get();            \
		}
#else
	#define ION_ADMIN_COMPONENT_DETAILS(__name)
#endif

#define ION_ADMIN_COMPONENT_IMPL(__name)            \
	template <>                                     \
	ion::UniqueOpaquePtr<__name> CreateOpaqueData() \
	{                                               \
		return ion::MakeUniqueOpaque<__name>();     \
	}                                               \
	ION_ADMIN_COMPONENT_DETAILS(__name);
