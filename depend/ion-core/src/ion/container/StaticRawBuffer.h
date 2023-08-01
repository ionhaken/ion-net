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
	#include <array>  // #TODO: For debugging, get rid of
#endif
#include <ion/container/Algorithm.h>

namespace ion
{
template <typename TValue, UInt TSize>
class ION_ALIGN(alignof(TValue)) AlignedStorage
{
public:
	using Container = TValue[TSize];  // ion::Array<TValue, TSize>;

	[[nodiscard]] constexpr TValue& operator[](std::size_t index) { return Array()[index]; }

	[[nodiscard]] constexpr const TValue& operator[](std::size_t index) const { return Array()[index]; }

	[[nodiscard]] constexpr Container& Array() { return reinterpret_cast<Container&>(mData[0]); }

	[[nodiscard]] constexpr const Container& Array() const { return reinterpret_cast<const Container&>(mData[0]); }

	[[nodiscard]] constexpr TValue* Data() { return &Array()[0]; }

	[[nodiscard]] constexpr const TValue* const Data() const { return &Array()[0]; }

	TValue* Insert(std::size_t index)
	{
		auto iter = &Array()[index];
		new (static_cast<void*>(iter)) TValue();
		return iter;
	}

	TValue* Insert(std::size_t index, const TValue& value)
	{
		auto iter = &Array()[index];
		new (static_cast<void*>(iter)) TValue(value);
		return iter;
	}

	TValue* Insert(std::size_t index, TValue&& value)
	{
		auto iter = &Array()[index];
		new (static_cast<void*>(iter)) TValue(std::move(value));
		return iter;
	}

	template <typename... Args>
	TValue* Insert(std::size_t index, const TValue& value, Args&&... args)
	{
		auto iter = &Array()[index];
		new (static_cast<void*>(iter)) TValue(value, std::forward<Args>(args)...);
		return iter;
	}

	template <typename... Args>
	TValue* Insert(std::size_t index, Args&&... args)
	{
		auto iter = &Array()[index];
		new (static_cast<void*>(iter)) TValue(std::forward<Args>(args)...);
		return iter;
	}

	inline void Erase(std::size_t index) { Array()[index].~TValue(); }

private:
	ION_ALIGN(alignof(TValue)) char mData[sizeof(Container)];
};

// Static Buffer is an array, where user is responsible for construction and destruction of elements.
template <typename TValue, UInt TSize>
class StaticBuffer
{
public:
	ION_CLASS_NON_COPYABLE_NOR_MOVABLE(StaticBuffer);

#if ION_BUILD_DEBUG
	StaticBuffer() : /* No mData initialization */ mMagicNumber1(0), mMagicNumber2(0) { EnsureDebugInfo(); }

	struct Debug
	{
	};
	StaticBuffer(const Debug*) { EnsureDebugInfo(); }

	~StaticBuffer()
	{
		ION_ASSERT(mAllowMemoryLeaks || std::find(mIsInit.begin(), mIsInit.end(), true) == mIsInit.end(), "Initialized values left");
		// These will be optimized out, so it's not possible to reuse StaticBuffer for StaticInstances
		// mMagicNumber1 = 0;
		// mMagicNumber2 = 0;
	}
#else
	StaticBuffer() /* No mData initialization */ {}
#endif

	// Set to ignore memory leak check in destructor if you don't know when buffer can be destroyed.
	// E.g. data is still needed in dynamic exit.
	void DebugAllowMemoryLeaks()
	{
#if ION_BUILD_DEBUG
		mAllowMemoryLeaks = true;
#endif
	}

	[[nodiscard]] constexpr TValue& operator[](std::size_t index)
	{
		ION_ASSERT_FMT_IMMEDIATE(index < TSize, "Index out of range");
#if ION_BUILD_DEBUG
		ION_ASSERT_FMT_IMMEDIATE(mIsInit[index], "Index %zu not set", index);
#endif
		return mData[index];
	}

	[[nodiscard]] constexpr const TValue& operator[](std::size_t index) const
	{
		ION_ASSERT_FMT_IMMEDIATE(index < TSize, "Index out of range");
#if ION_BUILD_DEBUG
		ION_ASSERT_FMT_IMMEDIATE(mIsInit[index], "Index %zu not set", index);
#endif
		return mData[index];
	}

	TValue* Insert(std::size_t index)
	{
		OnInsert(index);
		auto iter = &mData[index];
		new (static_cast<void*>(iter)) TValue();
		return iter;
	}

	TValue* Insert(std::size_t index, const TValue& value)
	{
		OnInsert(index);
		auto iter = &mData[index];
		new (static_cast<void*>(iter)) TValue(value);
		return iter;
	}

	TValue* Insert(std::size_t index, TValue&& value)
	{
		OnInsert(index);
		auto iter = &mData[index];
		new (static_cast<void*>(iter)) TValue(std::move(value));
		return iter;
	}

	template <typename... Args>
	TValue* Insert(std::size_t index, const TValue& value, Args&&... args)
	{
		OnInsert(index);
		auto iter = &mData[index];
		new (static_cast<void*>(iter)) TValue(value, std::forward<Args>(args)...);
		return iter;
	}

	template <typename... Args>
	TValue* Insert(std::size_t index, Args&&... args)
	{
		OnInsert(index);
		auto iter = &mData[index];
		new (static_cast<void*>(iter)) TValue(std::forward<Args>(args)...);
		return iter;
	}

	inline void Erase(std::size_t index)
	{
		OnErase(index);
		mData[index].~TValue();
	}

	inline void EraseFillIn(size_t start, size_t end, size_t size)
	{
		auto eraseCount = end - start;
		MoveBackByOffset<TValue>(&mData[start], eraseCount, size - end);
#if ION_BUILD_DEBUG
		while (eraseCount > 0)
		{
			OnErase(size - eraseCount);
			eraseCount--;
		}
#endif
	}

	void Clear()
	{
		if (std::is_trivially_destructible<TValue>::value)
		{
#if ION_BUILD_DEBUG
			std::fill(mIsInit.begin(), mIsInit.end(), false);
#endif
		}
		else
		{
			ION_ASSERT(false, "Clear() is not possible for non trivial types: number of elements is not known");
		}
	}

	inline TValue* Begin() { return &mData.Array()[0]; }
	inline TValue* End() { return &mData.Array()[TSize - 1]; }
	inline const TValue* Begin() const { return &mData.Array()[0]; }
	inline const TValue* End() const { return &mData.Array()[TSize - 1]; }

	[[nodiscard]] constexpr TValue* Data() { return mData.Data(); }
	[[nodiscard]] constexpr const TValue* Data() const { return mData.Data(); }

private:
#if ION_BUILD_DEBUG
	inline void EnsureDebugInfo()
	{
		if (mMagicNumber1 != MagicNumber1 || mMagicNumber2 != MagicNumber2)
		{
			std::fill(mIsInit.begin(), mIsInit.end(), false);
			mMagicNumber1 = MagicNumber1;
			mMagicNumber2 = MagicNumber2;
			mAllowMemoryLeaks = false;
		}
	}

	inline void OnInsert(size_t index)
	{
		EnsureDebugInfo();
		ION_ASSERT(!mIsInit[index], "Index " << index << " already set");
		mIsInit[index] = true;
	}

	inline void OnErase(size_t index)
	{
		ION_ASSERT(mIsInit[index], "Index " << index << " not set");
		mIsInit[index] = false;
	}
#else
	inline void OnInsert(size_t) {}
	inline void OnErase(size_t) {}
#endif

	AlignedStorage<TValue, TSize> mData;
#if ION_BUILD_DEBUG
	std::array<bool, TSize> mIsInit;

	// Note: StaticBuffer can be used before Constructor is called. Therefore we use magic number
	// to detect are we initialized yet. It's possible number is already initialized to
	// this value, but we don't care since this is just used for debug builds.
	static const uint64_t MagicNumber1 = 987654321;
	static const uint64_t MagicNumber2 = 123456789;
	uint64_t mMagicNumber1;
	uint64_t mMagicNumber2;
	bool mAllowMemoryLeaks;
#endif
};
}  // namespace ion
