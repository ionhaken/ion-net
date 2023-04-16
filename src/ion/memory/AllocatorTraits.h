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
#include <memory>

namespace ion
{
template <typename Allocator>
class AllocatorTraits
{
public:
	template <class T, class... Args>
	static constexpr T* Construct(Allocator& a, Args&&... args)
	{
		return ::new (const_cast<void*>(static_cast<const volatile void*>(a.allocate(1)))) T(std::forward<Args>(args)...);
	}

	template <class T>
	static constexpr void Destroy(Allocator& a, T* p)
	{
		if constexpr (std::is_array_v<T>)
		{
			for (auto& elem : *p)
			{
				(Destroy)(a, std::addressof(elem));
			}
		}
		else
		{
			p->~T();
			a.deallocate(p, 1);
		}
	}
};

template <typename T, class... Args>
constexpr typename T::value_type* Construct(T& allocator, Args&&... args)
{
	return AllocatorTraits<T>::template Construct<typename T::value_type>(allocator, std::forward<Args>(args)...);
}

template <typename T>
constexpr void Destroy(T& allocator, typename T::value_type* ptr)
{
	AllocatorTraits<T>::template Destroy<typename T::value_type>(allocator, ptr);
}

}  // namespace ion
