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
#include <ion/Base.h>
#include <ion/container/Array.h>
#include <cstring>	// memset

namespace ion
{
// ObjectWrapper is compiling time optimization as contained class is not needed to know when memory reservation is made.
template <size_t ObjectSize, size_t ObjectAlignment>
class ION_ALIGN(ObjectAlignment) ObjectWrapper
{
public:
	static const size_t Size = ObjectSize;
	static const size_t Alignment = ObjectAlignment;

	template <typename T>
	inline T* Ptr()
	{
		return reinterpret_cast<T*>(mData.Data());
	}

	template <typename T>
	inline const T* Ptr() const
	{
		return reinterpret_cast<const T*>(mData.Data());
	}

	template <typename T>
	inline T& Ref()
	{
		return reinterpret_cast<T&>(*mData.Data());
	}

	template <typename T>
	inline const T& Ref() const
	{
		return reinterpret_cast<T&>(*mData.Data());
	}

	template <typename T, size_t WrapperSize = ObjectSize, size_t WrapperAlignment = ObjectAlignment, size_t TypeSize = sizeof(T),
			  size_t TypeAlignment = alignof(T)>
	struct Proxy
	{
		static_assert(WrapperSize == TypeSize, "Invalid object wrapper size");
		static_assert(WrapperAlignment == TypeAlignment, "Invalid object wrapper alignment");

		template <typename... Args>
		static inline void Construct(ObjectWrapper<ObjectSize, ObjectAlignment>& wrapper, Args&&... args)
		{
			new (static_cast<void*>(wrapper.template Ptr<T>())) T(std::forward<Args>(args)...);
		}

		static inline void Destroy(ObjectWrapper<ObjectSize, ObjectAlignment>& wrapper) { (wrapper.template Ptr<T>())->~T(); }

		static inline void Init(ObjectWrapper<ObjectSize, ObjectAlignment>& wrapper) { std::memset(wrapper.Ptr<uint8_t>(), 0x0, Size); }
	};

private:
	ion::Array<uint8_t, Size> mData;
};

// Object wrapper type to be used when class is being inlined and compile time optimization is not used
template <typename T>
class ObjectWrapperInline
{
public:
	template <typename U>
	inline T* Ptr()
	{
		return &mData;
	}

	template <typename U>
	inline const T* Ptr() const
	{
		return &mData;
	}

	template <typename U>
	inline T& Ref()
	{
		return mData;
	}

	template <typename U>
	inline const T& Ref() const
	{
		return mData;
	}

	template <typename U>
	struct Proxy
	{
		template <typename V, typename... Args>
		static inline void Construct(V&&, Args&&...)
		{
		}

		template <typename V>
		static inline void Destroy(V&)
		{
		}

		template <typename V>
		static inline void Init(V&)
		{
		}
	};

private:
	T mData;
};
}  // namespace ion
