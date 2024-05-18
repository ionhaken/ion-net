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
#include <ion/container/Algorithm.h>
#include <ion/util/Math.h>

#ifndef ION_BUILD_DEBUG_DYNAMIC_BUFFER
	#define ION_BUILD_DEBUG_DYNAMIC_BUFFER 0
#endif

namespace ion
{
template <typename Value>
class RawBuffer
{
public:
	ION_FORCE_INLINE RawBuffer& operator=(const RawBuffer& other)
	{
#if ION_BUILD_DEBUG_DYNAMIC_BUFFER
		mDebugCount = other.mDebugCount;
#endif
		mData = other.mData;
		return *this;
	}

	ION_FORCE_INLINE RawBuffer& operator=(RawBuffer&& other)
	{
#if ION_BUILD_DEBUG_DYNAMIC_BUFFER
		mDebugCount = other.mDebugCount;
#endif
		mData = other.mData;
		other.mData = nullptr;
		return *this;
	}

	ION_FORCE_INLINE RawBuffer& operator=(Value* other)
	{
#if ION_BUILD_DEBUG_DYNAMIC_BUFFER
		mDebugCount = 0;
#endif
		mData = other;
		return *this;
	}

	[[nodiscard]] constexpr Value& operator[](std::size_t index)
	{
		OnAccess(index);
		return Get()[index];
	}

	[[nodiscard]] constexpr const Value& operator[](std::size_t index) const
	{
		OnAccess(index);
		return Get()[index];
	}

	ION_FORCE_INLINE void Erase(std::size_t index)
	{
		OnErase();
		Get()[index].~Value();
	}

	ION_FORCE_INLINE Value* Insert(std::size_t index)
	{
		OnInsert(index);
		auto iter = &Get()[index];
		new (static_cast<void*>(iter)) Value();
		return iter;
	}

	ION_FORCE_INLINE Value* Insert(std::size_t index, const Value& value)
	{
		OnInsert(index);
		return new (static_cast<void*>(&Get()[index])) Value(value);
	}

	ION_FORCE_INLINE Value* Insert(std::size_t index, Value&& value)
	{
		OnInsert(index);
		return new (static_cast<void*>(&Get()[index])) Value(std::move(value));
	}

	template <typename... Args>
	ION_FORCE_INLINE Value* Insert(std::size_t index, const Value& value, Args&&... args)
	{
		OnInsert(index);
		return new (static_cast<void*>(&Get()[index])) Value(value, std::forward<Args>(args)...);
	}

	template <typename... Args>
	ION_FORCE_INLINE Value* Insert(std::size_t index, Args&&... args)
	{
		OnInsert(index);
		return new (static_cast<void*>(&Get()[index])) Value(std::forward<Args>(args)...);
	}

	[[nodiscard]] constexpr Value* Get() { return mData; }
	[[nodiscard]] constexpr Value* const Get() const { return mData; }

	// Init container with given data
	inline void CreateFrom(const Value* ION_RESTRICT source, size_t size)
	{
		if constexpr (std::is_trivially_copyable<Value>::value)
		{
			ion::Copy(source, &source[size], mData);
#if ION_BUILD_DEBUG_DYNAMIC_BUFFER
			if constexpr (!IsTrivial())
			{
				mDebugCount = size;
			}
#endif
		}
		else
		{
			for (size_t i = 0; i < size; ++i)
			{
				Insert(i, source[i]);
			}
		}
	}

	// Replace container sequence with given sequence assuming give size is larger than original size
	void Replace(Value* ION_RESTRICT newContainer, size_t size)
	{
		MoveTo(newContainer, size);
		Set(newContainer, size);
	}

	// Set data sequence as new container.
	ION_FORCE_INLINE void Set(Value* source, [[maybe_unused]] size_t size)
	{
#if ION_BUILD_DEBUG_DYNAMIC_BUFFER
		mDebugCount = size;
#endif
		mData = source;
	}

	// Move part of contents to given byte sequence
	inline void MoveTo(Value* ION_RESTRICT destination, size_t size)
	{
		if constexpr (std::is_trivially_copyable<Value>::value)
		{
			ion::Copy(mData, &mData[size], destination);
#if ION_BUILD_DEBUG_DYNAMIC_BUFFER
			if constexpr (!IsTrivial())
			{
				ION_CHECK(mDebugCount >= size, "Invalid erase");
				mDebugCount -= size;
			}
#endif
		}
		else
		{
			for (size_t i = 0; i < size; ++i)
			{
				new (static_cast<void*>(&destination[i])) Value(std::move(mData[i]));
				Erase(i);
			}
		}
	}

	// Copy contents of given sequence to container.
	void CopyFrom(const Value* ION_RESTRICT source, size_t newSize, size_t oldSize)
	{
		auto replaces = ion::Min(oldSize, newSize);
		ion::Copy(source, &source[replaces], mData);

		if constexpr (std::is_trivially_copyable<Value>::value)
		{
			ion::Copy(&source[replaces], &source[newSize], &mData[replaces]);
		}
		else
		{
			for (size_t i = replaces; i < newSize; ++i)
			{
				Insert(i, source[i]);
			}
		}

		if constexpr (!std::is_trivially_destructible<Value>::value)
		{
			for (size_t i = replaces; i < oldSize; ++i)
			{
				Erase(i);
			}
		}
	}

	void Clear(size_t size)
	{
		for (size_t i = 0; i < size; ++i)
		{
			Erase(i);
		}
	}

	void Reset(size_t size, Value* ptr = nullptr)
	{
		Clear(size);
		Set(ptr, 0);
	}

	static constexpr bool IsTrivial() { return std::is_trivial<Value>::value; }

private:
	Value* mData;

#if ION_BUILD_DEBUG_DYNAMIC_BUFFER
	inline void OnErase()
	{
		if constexpr (!IsTrivial())
		{
			ION_CHECK(mDebugCount > 0, "Invalid erase");
			mDebugCount--;
		}
	}

	inline void OnInsert([[maybe_unused]] size_t index)
	{
		if constexpr (!IsTrivial())
		{
			ION_CHECK(index == mDebugCount, "Invalid insert");
			mDebugCount++;
		}
	}

	inline void OnAccess([[maybe_unused]] size_t index) const
	{
		if constexpr (!IsTrivial())
		{
			ION_CHECK(index < mDebugCount, "Invalid access");
		}
	}
	size_t mDebugCount;
#else
	inline void OnErase() {}
	inline void OnAccess(size_t) const {}
	inline void OnInsert(size_t) {}
#endif
};
}  // namespace ion
