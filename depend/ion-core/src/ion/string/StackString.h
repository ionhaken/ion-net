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
#include <ion/memory/Memory.h>
#include <ion/string/String.h>
#include <ion/arena/ArenaAllocator.h>
#include <ion/memory/MonotonicBufferResource.h>
#include <ion/container/StackContainer.h>

namespace ion
{
template <size_t stack_capacity>
class StackString : public StackContainer<BasicString<StackAllocator<char, stack_capacity>>, stack_capacity>
{
public:
	StackString() : StackContainer<BasicString<StackAllocator<char, stack_capacity>>, stack_capacity>()
	{
		// std::string implementation may allocate more than requested capacity, hence we need to reduce allocation length to not to
		// overflow stack capacity. This can be fixed only with custom string implementation.
		ION_ASSERT(this->Native().Capacity() <= stack_capacity, "Too small stack string capacity;expected=" << this->Native().Capacity());
		this->Native().Reserve(stack_capacity / sizeof(char) / 2);
	}

	StackString(const char* buffer) : StackContainer<BasicString<StackAllocator<char, stack_capacity>>, stack_capacity>()
	{
		this->Native().Reserve(stack_capacity / sizeof(char) / 2);
		this->Native() = buffer;
	}

	const char* CStr() const { return this->Native().CStr(); }

	template <typename... Args>
	int Format(Args&&... args)
	{
		return this->Native().Format(std::forward<Args>(args)...);
	}

	size_t Length() const { return this->Native().Length(); }

private:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(StackString);
};

template <size_t stack_capacity>
class StackWString
  : public StackContainer<std::basic_string<wchar_t, std::char_traits<wchar_t>, StackAllocator<wchar_t, stack_capacity>>, stack_capacity>
{
public:
	StackWString()
	  : StackContainer<std::basic_string<wchar_t, std::char_traits<wchar_t>, StackAllocator<wchar_t, stack_capacity>>, stack_capacity>()
	{
		this->Native().reserve(stack_capacity / sizeof(wchar_t) / 2);
	}

private:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(StackWString);
};

}  // namespace ion
