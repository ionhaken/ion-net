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

#include <ion/tracing/Log.h>

#if ION_BUILD_DEBUG
	#define ION_RTTI_ENABLED
#endif

#define ION_DYNAMIC_CAST_TAGS 1

namespace ion
{
template <typename T>
struct remove_pointer
{
	typedef T type;
};

template <typename T>
struct remove_pointer<T*>
{
	typedef typename remove_pointer<T>::type type;
};

template <typename T, typename U>
[[nodiscard]] inline T DynamicCast(U ptr)
{
	if constexpr (std::is_same_v<T, U>)
	{
		return ptr;
	}
	else
	{
#if ION_DYNAMIC_CAST_TAGS
		if (ptr && ptr->GetTags() & remove_pointer<T>::type::Tag)
		{
	#ifdef ION_RTTI_ENABLED
			ION_ASSERT(dynamic_cast<T>(ptr) == reinterpret_cast<T>(ptr),
					   "Dynamic cast:" << uintptr_t(dynamic_cast<T>(ptr)) << " reinterpret:" << uintptr_t(reinterpret_cast<T>(ptr)));
	#endif
			return reinterpret_cast<T>(ptr);
		}
		else
		{
	#ifdef ION_RTTI_ENABLED
			ION_ASSERT(dynamic_cast<T>(ptr) == nullptr, "Expected dynamic cast to fail");
	#endif
			return nullptr;
		}
#else
		return dynamic_cast<T>(ptr);
#endif
	}
}
}  // namespace ion
