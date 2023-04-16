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
#include <ion/arena/ArenaVector.h>

#include <ion/memory/GlobalAllocator.h>

#include <ion/Types.h>

// Dynamic array implementation with optional static buffer support.
//
// Typically dynamic arrays are implemented as pointers to start and end of data and a capacity counter. ion::Vector<> uses size counter
// instead of pointer to end of data, and implements size and capacity counters as 32-bit values, which allows 8 bytes smaller memory
// footprint on 64-bit systems than the typical implementation. Depending on your use case and compiler optimizations, this can
// have positive or negative performance implications.
//
// Additionally, ion::Vector<> has optional static buffer via SmallBufferSize and TinyBufferSize template parameters. Setting
// SmallBufferSize adds the static buffer after the data pointer. Setting TinyBufferSize replaces data pointer with static buffer when
// applicable. Tiny buffer is smaller in size, but small buffer has better random access performance. Please see also SmallVector<> and
// TinyVector<>.
//
namespace ion
{
template <typename TValue, typename TAllocator = GlobalAllocator<TValue>, typename CountType = uint32_t, size_t SmallBufferSize = 0,
		  size_t TinyBufferSize = 0>
class Vector
{
	static_assert(std::is_same_v<TAllocator::value_type, TValue>, "Allocator value type must match container value type");

	using Native = ion::ArenaVector<TValue, SmallBufferSize, CountType, TinyBufferSize>;

public:
	using Type = TValue;
	using size_type = CountType;

	constexpr Vector() : mProxy() {}

	template <typename Resource>
	constexpr Vector(Resource* resource) : mProxy(resource)
	{
	}

	explicit constexpr Vector(size_type n) : mProxy() { mProxy.mImpl.Reserve(mProxy, n); }

	constexpr Vector(const Vector& other) noexcept : mProxy(other.mProxy) {}

	constexpr Vector(Vector&& other) noexcept : mProxy(std::move(other.mProxy)) {}

	constexpr Vector(Vector const&& other) noexcept : mProxy(std::move(other.mProxy)) {}

	constexpr Vector& operator=(const Vector& other) noexcept
	{
		mProxy = other.mProxy;
		return *this;
	}

	constexpr Vector& operator=(Vector&& other) noexcept
	{
		mProxy = std::move(other.mProxy);
		return *this;
	}

	~Vector()
	{
		Clear();
		ShrinkToFit();
	}

	inline void ShrinkToFit() { mProxy.mImpl.ShrinkToFit(mProxy); }

	[[nodiscard]] constexpr const TValue* Data() const { return mProxy.mImpl.Data(); }
	[[nodiscard]] constexpr TValue* Data() { return mProxy.mImpl.Data(); }

	[[nodiscard]] constexpr TValue& operator[](std::size_t index) { return mProxy.mImpl[index]; }
	[[nodiscard]] constexpr const TValue& operator[](std::size_t index) const { return mProxy.mImpl[index]; }

	[[nodiscard]] constexpr TValue& Back() { return mProxy.mImpl.Back(); }
	[[nodiscard]] constexpr const TValue& Back() const { return mProxy.mImpl.Back(); }
	[[nodiscard]] constexpr TValue& Front() { return mProxy.mImpl[0]; }
	[[nodiscard]] constexpr const TValue& Front() const { return mProxy.mImpl[0]; }

	inline void Clear() { mProxy.mImpl.Clear(); }

	using Iterator = typename Native::Iterator;
	using ReverseIterator = typename Native::ReverseIterator;
	using ConstIterator = typename Native::ConstIterator;
	using ConstReverseIterator = typename Native::ConstReverseIterator;

	[[nodiscard]] constexpr Iterator Begin() { return mProxy.mImpl.Begin(); }

	[[nodiscard]] constexpr Iterator End() { return mProxy.mImpl.End(); }

	[[nodiscard]] constexpr Iterator begin() { return mProxy.mImpl.Begin(); }

	[[nodiscard]] constexpr Iterator end() { return mProxy.mImpl.End(); }

	[[nodiscard]] constexpr ReverseIterator RBegin() { return mProxy.mImpl.RBegin(); }

	[[nodiscard]] constexpr ReverseIterator REnd() { return mProxy.mImpl.REnd(); }

	[[nodiscard]] constexpr ConstReverseIterator RBegin() const { return mProxy.mImpl.RBegin(); }

	[[nodiscard]] constexpr ConstReverseIterator REnd() const { return mProxy.mImpl.REnd(); }

	[[nodiscard]] constexpr ConstIterator Begin() const { return mProxy.mImpl.Begin(); }

	[[nodiscard]] constexpr ConstIterator End() const { return mProxy.mImpl.End(); }

	[[nodiscard]] constexpr ConstIterator begin() const { return mProxy.mImpl.Begin(); }

	[[nodiscard]] constexpr ConstIterator end() const { return mProxy.mImpl.End(); }

	inline void PushBack(const TValue& data) { Add(data); }

	inline void PushFront(const TValue& data) { Insert(Begin(), data); }

	inline void PopFront() { Erase(Begin()); }

	inline void PopBack() { Pop(); }

	inline Iterator Add(const TValue& data) { return mProxy.mImpl.Add(mProxy, data); }

	// Adds element ands asserts that container capacity does not change.
	ION_FORCE_INLINE Iterator AddKeepCapacity(const TValue& data) { return mProxy.mImpl.AddKeepCapacity(data); }

	template <typename Callback>
	inline void AddMultiple(size_t count, Callback&& callback)
	{
		mProxy.mImpl.AddMultiple(mProxy, count, callback);
	}

	inline Iterator Add(TValue&& data) { return mProxy.mImpl.Add(mProxy, std::move(data)); }

	template <class... Args>
	inline Iterator Emplace(Args&&... args)
	{
		return mProxy.mImpl.Emplace(mProxy, std::forward<Args>(args)...);
	}

	template <class... Args>
	inline Iterator EmplaceKeepCapacity(Args&&... args)
	{
		return mProxy.mImpl.EmplaceKeepCapacity(std::forward<Args>(args)...);
	}

	ION_FORCE_INLINE Iterator AddKeepCapacity(TValue&& data) { return mProxy.mImpl.EmplaceKeepCapacity(std::move(data)); }

	inline Iterator Insert(size_t pos, const TValue& data) { return mProxy.mImpl.Insert(mProxy, ion::SafeRangeCast<size_type>(pos), data); }

	inline Iterator Insert(Iterator pos, const TValue& data) { return mProxy.mImpl.Insert(mProxy, pos, data); }

	inline Iterator Erase(const Iterator& iter) { return mProxy.mImpl.Erase(iter); }

	inline Iterator Erase(const Iterator& start, const Iterator& end) { return mProxy.mImpl.Erase(start, end); }

	inline Iterator Erase(size_t index) { return mProxy.mImpl.Erase(index); }

	inline void Reserve(size_t s) { mProxy.mImpl.Reserve(mProxy, ion::SafeRangeCast<size_type>(s)); }

	// Resizes to s, if out of capacity, increases capacity exactly to "s".
	// Use Resize(s, newCapacity) when you have to control capacity.
	inline void Resize(size_t s) { mProxy.mImpl.Resize(mProxy, ion::SafeRangeCast<size_type>(s)); }

	// Resizes container to given size. If out of capacity, increases capacity to given new capacity.
	inline void Resize(size_t s, size_t newCapacity)
	{
		ION_ASSERT(newCapacity >= s, "Invalid new capacity");
		mProxy.mImpl.Resize(mProxy, ion::SafeRangeCast<size_type>(s), ion::SafeRangeCast<size_type>(newCapacity));
	}

	// Resize container to given size. Only trivial types supported.
	inline void ResizeFast(size_t s) { mProxy.mImpl.ResizeFast(mProxy, ion::SafeRangeCast<size_type>(s)); }

	// Resize container to given size and capacity. Only trivial types supported.
	inline void ResizeFast(size_t s, size_t newCapacity)
	{
		mProxy.mImpl.ResizeFast(mProxy, ion::SafeRangeCast<size_type>(s), ion::SafeRangeCast<size_type>(newCapacity));
	}

	// Resize container to given size. Assert if out of capacity. Only trivial types supported.
	inline void ResizeFastKeepCapacity(size_t s) { mProxy.mImpl.ResizeFastKeepCapacity(ion::SafeRangeCast<size_type>(s)); }

	inline size_type Size() const { return mProxy.mImpl.Size(); }

	inline size_type MaxSize() const { return static_cast<CountType>(-1); }

	inline size_type Capacity() const { return mProxy.mImpl.Capacity(); }

	inline bool IsEmpty() const { return mProxy.mImpl.IsEmpty(); }

	inline void Pop() { mProxy.mImpl.PopBack(); }

	// STL interface
	inline size_t size() const { return mProxy.mImpl.Size(); }
	inline bool empty() const { return mProxy.mImpl.IsEmpty(); }
	template <class... Args>
	inline Iterator emplace_back(Args&&... args)
	{
		return mProxy.mImpl.Emplace(mProxy, std::forward<Args>(args)...);
	}
	inline void pop_back() { Pop(); }
	inline size_t capacity() const { return mProxy.mImpl.Capacity(); }

	template<typename AssignIterator>
	void assign(AssignIterator start, AssignIterator end) 
	{
		Clear();
		Reserve(end - start);
		while (start != end) 
		{
			AddKeepCapacity(std::move(*start));
			++start;
		}
	}

private:
	// Empty Base Optimization
	template <class Base, class Implementation>
	struct BaseOptProxy : Base
	{
		Implementation mImpl;
		BaseOptProxy() : Base(), mImpl() {}
		BaseOptProxy(Implementation const& impl) : Base(), mImpl(impl) {}

		constexpr BaseOptProxy(const BaseOptProxy& other) noexcept : Base(other), mImpl(*this, other.mImpl) {}

		constexpr BaseOptProxy(BaseOptProxy&& other) noexcept : Base(other), mImpl(std::move(other.mImpl)) {}

		constexpr BaseOptProxy(BaseOptProxy const&& other) noexcept : Base(other), mImpl(std::move(other.mImpl)) {}

		BaseOptProxy& operator=(const BaseOptProxy& other) noexcept
		{
			if constexpr (std::allocator_traits<TAllocator>::propagate_on_container_copy_assignment::value)
			{
				Base::operator=(other);
			}
			mImpl.Set(*this, other.mImpl);
			return *this;
		}

		BaseOptProxy& operator=(BaseOptProxy&& other) noexcept
		{
			if constexpr (std::allocator_traits<TAllocator>::propagate_on_container_move_assignment::value)
			{
				Base::operator=(std::move(other));
			}
			mImpl.Move(*this, std::move(other.mImpl));
			return *this;
		}

		template <typename Resource>
		BaseOptProxy(Resource* resource) : Base(resource), mImpl()
		{
		}
	};

	BaseOptProxy<TAllocator, Native> mProxy;
};

// Small buffer optimized Vector.
template <typename Value, size_t BufferSize, typename TAllocator = GlobalAllocator<Value>, typename CountType = uint32_t>
using SmallVector = Vector<Value, TAllocator, CountType, BufferSize>;

// TinyVector: Max 255 items, smaller footprint than SmallVector, but worse random access time.
template <typename Value, typename TAllocator = GlobalAllocator<Value>,
		  size_t BufferSize = (2 * sizeof(ion::RawBuffer<Value>) - (sizeof(uint8_t) * 2)) / sizeof(Value)>
using TinyVector = Vector<Value, TAllocator, uint8_t, 0, BufferSize>;

// TinyVector16: As TinyVector, but max 65535 items.
template <typename Value, typename TAllocator = GlobalAllocator<Value>,
		  size_t BufferSize = (2 * sizeof(ion::RawBuffer<Value>) - (sizeof(uint16_t) * 2)) / sizeof(Value)>
using TinyVector16 = Vector<Value, TAllocator, uint16_t, 0, BufferSize>;

template <typename Container>
inline typename Container::Type& SafeIndexAt(Container& container, size_t index)
{
	if (container.Size() <= index)
	{
		container.Resize(index + 1, (index + 1) * 2);
	}
	return container[index];
}

template <typename Type, typename Allocator, typename CountType, size_t SmallBufferSize, size_t TinyBufferSize>
struct IsArray<ion::Vector<Type, Allocator, CountType, SmallBufferSize, TinyBufferSize>> : std::true_type
{
};

}  // namespace ion
