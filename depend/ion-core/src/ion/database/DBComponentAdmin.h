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

#include <ion/database/DBComponent.h>

namespace ion
{
template <typename T>
class ComponentFacade
{
public:
	ComponentFacade(T&& t) : mComponent(std::forward<T>(t))
	{
#if (ION_COMPONENT_READ_WRITE_CHECKS == 1)
		mDetails = GetComponentDetails<typename std::pointer_traits<T>::element_type>();
#endif
	}

	[[nodiscard]] inline T& operator->() { return mComponent; }
	[[nodiscard]] inline T& operator*() { return mComponent; }
	[[nodiscard]] constexpr const T& operator*() const { return mComponent; }
	[[nodiscard]] constexpr const T& operator->() const { return mComponent; }
#if (ION_COMPONENT_READ_WRITE_CHECKS == 1)
	ion::ComponentDetails mDetails;
#endif
	T mComponent;
};

template <typename T>
class ComponentView;

// Admin provides access to domain specific components.
// You can store references to admin, but you are not allowed to store references to any of its components.
class Admin
{
protected:
#if (ION_COMPONENT_READ_WRITE_CHECKS == 1)
	template <typename T>
	[[nodiscard]] inline ComponentView<T> GetComponent(T& t, ComponentDetails& componentDetails);

	template <typename T>
	[[nodiscard]] inline ComponentView<const T> GetConstComponent(const T& t, const ComponentDetails& componentDetails) const;
#else
	template <typename T>
	[[nodiscard]] inline ComponentView<T> GetComponent(T& t);

	template <typename T>
	[[nodiscard]] inline ComponentView<const T> GetConstComponent(const T& t) const;
#endif
};

template <typename T>
class ComponentView
{
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(ComponentView<T>);
	friend class Admin;

public:
	[[nodiscard]] inline T* const operator->() { return &mComponent; }
	[[nodiscard]] inline T& operator*() { return mComponent; }
	[[nodiscard]] inline T* const Get() { return &mComponent; }

	[[nodiscard]] constexpr const T& operator*() const { return mComponent; }
	[[nodiscard]] constexpr const T* const operator->() const { return &mComponent; }
	[[nodiscard]] constexpr const T* const Get() const { return &mComponent; }

	~ComponentView()
	{
#if (ION_COMPONENT_READ_WRITE_CHECKS == 1)
		if constexpr (std::is_const<T>::value)
		{
			if (mDetails.mIsGuardEnabled)
			{
				ION_ACCESS_GUARD_STOP_READING(mDetails.mGuard);
			}
		}
		else
		{
			if (mDetails.mIsGuardEnabled)
			{
				ION_ACCESS_GUARD_STOP_WRITING(mDetails.mGuard);
			}
		}
#endif
	}

private:
#if (ION_COMPONENT_READ_WRITE_CHECKS == 1)
	const ion::ComponentDetails& mDetails;
	ComponentView(T& component, const ion::ComponentDetails& details) : mDetails(details), mComponent(component)
	{
		if constexpr (std::is_const<T>::value)
		{
			mDetails.Validate();
			if (mDetails.mIsGuardEnabled)
			{
				ION_ACCESS_GUARD_START_READING(mDetails.mGuard);
			}
		}
		else
		{
			mDetails.Validate();
			if (mDetails.mIsGuardEnabled)
			{
				ION_ACCESS_GUARD_START_WRITING(mDetails.mGuard);
			}
		}
	}
#else
	ComponentView(T& component) : mComponent(component) {}
#endif
	T& mComponent;
};

#if (ION_COMPONENT_READ_WRITE_CHECKS == 1)
template <typename T>
[[nodiscard]] inline ComponentView<T> Admin::GetComponent(T& t, ion::ComponentDetails& details)
{
	return ComponentView<T>(t, details);
}
template <typename T>
[[nodiscard]] inline ComponentView<const T> Admin::GetConstComponent(const T& t, const ion::ComponentDetails& details) const
{
	return ComponentView<const T>(t, details);
}
#else
template <typename T>
[[nodiscard]] inline ComponentView<T> Admin::GetComponent(T& t)
{
	return ComponentView<T>(t);
}

template <typename T>
[[nodiscard]] inline ComponentView<const T> Admin::GetConstComponent(const T& t) const
{
	return ComponentView<const T>(t);
}
#endif
}  // namespace ion

#define ION_ADMIN_COMPONENT_INTERFACE()                        \
	template <typename T>                                      \
	[[nodiscard]] ion::ComponentView<T> Get()                  \
	{                                                          \
		return ion::ComponentView<T>();                        \
	}                                                          \
	template <typename T>                                      \
	[[nodiscard]] ion::ComponentView<T const> GetConst() const \
	{                                                          \
		return ion::ComponentView<T const>();                  \
	}

#if (ION_COMPONENT_READ_WRITE_CHECKS == 1)
	#define ION_ADMIN_COMPONENT(__name)                                                                                          \
		ion::ComponentFacade<ion::UniqueOpaquePtr<__name>> ION_CONCATENATE(m, __name);                                           \
                                                                                                                                 \
	public:                                                                                                                      \
		template <>                                                                                                              \
		inline ion::ComponentView<__name> Get()                                                                                  \
		{                                                                                                                        \
			return ion::Admin::GetComponent<>(*ION_CONCATENATE(m, __name).mComponent, ION_CONCATENATE(m, __name).mDetails);      \
		}                                                                                                                        \
		template <>                                                                                                              \
		inline ion::ComponentView<__name const> GetConst() const                                                                 \
		{                                                                                                                        \
			return ion::Admin::GetConstComponent<>(*ION_CONCATENATE(m, __name).mComponent, ION_CONCATENATE(m, __name).mDetails); \
		}                                                                                                                        \
                                                                                                                                 \
	private:
#else
	#define ION_ADMIN_COMPONENT(__name)                                                     \
		ion::ComponentFacade<ion::UniqueOpaquePtr<__name>> ION_CONCATENATE(m, __name);      \
                                                                                            \
	public:                                                                                 \
		template <>                                                                         \
		inline ion::ComponentView<__name> Get()                                             \
		{                                                                                   \
			return ion::Admin::GetComponent<>(*ION_CONCATENATE(m, __name).mComponent);      \
		}                                                                                   \
		template <>                                                                         \
		inline ion::ComponentView<__name const> GetConst() const                            \
		{                                                                                   \
			return ion::Admin::GetConstComponent<>(*ION_CONCATENATE(m, __name).mComponent); \
		}                                                                                   \
                                                                                            \
	private:
#endif
