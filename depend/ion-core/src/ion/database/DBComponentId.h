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
#include <ion/util/IdType.h>

namespace ion
{
template <typename T, T TInvalid = (std::numeric_limits<T>::max)()>
class ComponentId : public IdType<T, TInvalid>
{
	using Super = IdType<T, TInvalid>;
public:
#if ION_COMPONENT_VERSION_NUMBER
	constexpr bool operator==(const ComponentId& other) const
	{
		if (Super::operator==(other))
		{
			ION_ASSERT_FMT_IMMEDIATE(mVersion == other.mVersion || !Super::IsValid() || !other.Super::IsValid(),
									 "Version mismatch");
			return true;
		}
		return false;
	}

	constexpr bool operator!=(const ComponentId& other) const
	{
		if (Super::operator!=(other))
		{
			return true;
		}
		ION_ASSERT_FMT_IMMEDIATE(mVersion == other.mVersion || !Super::IsValid() || !other.Super::IsValid(), "Version mismatch");
		return false;
	}
#endif

	constexpr T GetIndex() const { return Super::GetRaw(); }

#if ION_COMPONENT_VERSION_NUMBER
	constexpr T GetVersion() const { return mVersion; }
#endif

protected:
	constexpr ComponentId()
	  : Super()
#if ION_COMPONENT_VERSION_NUMBER
		,
		mVersion(0)
#endif
	{
	}

#if ION_COMPONENT_VERSION_NUMBER
	constexpr ComponentId(const T anIndex, const T aVersion) : Super(anIndex), mVersion(aVersion) {}
#else
	constexpr ComponentId(const T anIndex) : Super(anIndex) {}
#endif

private:
#if ION_COMPONENT_VERSION_NUMBER
	T mVersion;
#endif
};

namespace tracing
{
template <typename T>
inline void Handler(LogEvent& e, ComponentId<T>& value)
{
	char buffer[32];
	ion::serialization::Serialize(value.GetIndex(), buffer, 32, nullptr);
	e.Write(buffer);
}
}  // namespace tracing
}  // namespace ion
