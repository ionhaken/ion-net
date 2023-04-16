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
#include <ion/Types.h>
#include <ion/container/RawBuffer.h>
#include <ion/container/StaticRawBuffer.h>
#include <ion/container/Algorithm.h>
#include <ion/util/SafeRangeCast.h>

#include <cstring>	// memset

namespace ion
{
// ArenaVector is a sequence container, but memory resource for allocation and deallocation
// must be provided explicitly. User is responsible for clearing arena vector before
// destructor is called.
//
// While it could be possible to register deleter the intention is to keep memory foot print
// as small as possible.
//
template <typename Value, uint32_t SmallItemCount = 0, typename CountType = uint32_t, uint32_t TinyItemCount = 0>
class ArenaVector
{
	static constexpr uint32_t StaticItemCount = TinyItemCount == 0 ? SmallItemCount : TinyItemCount;

public:
	static_assert((SmallItemCount == 0 && TinyItemCount == 0) || (SmallItemCount == 0) || (TinyItemCount == 0),
				  "Simultaneous tiny and small buffer not supported");

	template <typename Iterator>
	struct ReverseArrayIterator
	{
		ReverseArrayIterator(Iterator v) : current(v) {}
		ReverseArrayIterator(const ReverseArrayIterator& other) : current(other.current) {}
		ReverseArrayIterator& operator=(const ReverseArrayIterator& other)
		{
			current = other.current;
			return *this;
		}

		Iterator current;
		constexpr ReverseArrayIterator operator++()
		{
			ReverseArrayIterator tmp = *this;
			--current;
			return tmp;
		}
		[[nodiscard]] constexpr auto& operator*() const
		{
			Iterator tmp = current;
			return *--tmp;
		}

		bool operator==(const ReverseArrayIterator& other) const { return other.current == current; }

		bool operator!=(const ReverseArrayIterator& other) const { return other.current != current; }
	};

	using Type = Value;
	using Iterator = Value*;
	using ConstIterator = const Value*;
	using ReverseIterator = ReverseArrayIterator<Iterator>;
	using ConstReverseIterator = ReverseArrayIterator<ConstIterator>;

	ArenaVector() : mStorage(0, StaticItemCount)
	{
		static_assert(TinyItemCount == 0 ||
						(sizeof(ArenaVector<Value, TinyItemCount, CountType, 0>) > sizeof(ArenaVector<Value, 0, CountType, TinyItemCount>)),
					  "Type cannot take advantage of tiny memory optimization - use small buffer instead");

		if constexpr (SmallItemCount == 0)
		{
			Items() = nullptr;
		}
		else
		{
			Items() = &mStorage.SmallItems()[0];
		}
	}

	// ArenaVector needs to be copied manually due to lack of pointer to memory resource
	ArenaVector(ArenaVector& other) = delete;
	ArenaVector& operator=(const ArenaVector& other) = delete;
	ArenaVector& operator=(ArenaVector&& other) = delete;

	ArenaVector(ArenaVector&& other) noexcept : mStorage(0, StaticItemCount)
	{
		if constexpr (SmallItemCount == 0)
		{
			mStorage.mData.mBuffer.mItems = nullptr;
		}
		else
		{
			mStorage.mData.mBuffer.mItems = &mStorage.SmallItems()[0];
		}
		Move(std::move(other));
	}

	ArenaVector(ArenaVector const&& other) noexcept : mStorage(0, StaticItemCount)
	{
		if constexpr (SmallItemCount == 0)
		{
			mStorage.mData.mBuffer.mItems = nullptr;
		}
		else
		{
			mStorage.mData.mBuffer.mItems = &mStorage.SmallItems()[0];
		}
		Move(std::move(other));
	}

	template <typename Allocator>
	void Move(Allocator& allocator, ArenaVector&& other)
	{
		Clear();
		ShrinkToFit(allocator);
		Move(std::move(other));
	}

	template <typename Allocator>
	ArenaVector(Allocator& allocator, const ArenaVector& other)
	{
		if constexpr (TinyItemCount == 0)
		{
			InternalCapacity() = other.InternalCapacity();
			InternalSize() = other.InternalSize();
			if (InternalCapacity() > SmallItemCount)
			{
				Value* items = Allocate(allocator, InternalCapacity());
				Items() = items;
				Items().CreateFrom(other.Items().Get(), InternalSize());
			}
			else if constexpr (SmallItemCount != 0)
			{
				Items() = mStorage.SmallItems().Data();
				Items().CreateFrom(other.Items().Get(), InternalSize());
			}
			else
			{
				Items() = nullptr;
			}
		}
		else if (other.Capacity() > TinyItemCount)
		{
			InternalCapacity() = other.InternalCapacity();
			InternalSize() = other.InternalSize();
			Value* items = Allocate(allocator, InternalCapacity());
			Items() = items;
			Items().CreateFrom(other.Items().Get(), InternalSize());
		}
		else
		{
			InternalCapacity() = TinyItemCount;
			InternalSize() = other.InternalSize();
			for (size_t i = 0; i < other.Size(); ++i)
			{
				mStorage.TinyItems().Insert(i, other.mStorage.TinyItems()[i]);
			}
		}
	}

	template <typename Allocator>
	constexpr void Set(Allocator& allocator, const ArenaVector& other)
	{
		if (other.Size() > Capacity())
		{
			if constexpr (TinyItemCount == 0)
			{
				Clear();
				Reset(allocator);
				Value* items = Allocate(allocator, other.Size());
				Items() = items;
				Items().CreateFrom(other.Items().Get(), other.Size());
				InternalCapacity() = other.Size();
			}
			else
			{
				if (InternalCapacity() > TinyItemCount)
				{
					Clear();
					Reset(allocator);
				}
				Value* items = Allocate(allocator, other.Size());
				Items() = items;
				Items().CreateFrom(other.Items().Get(), other.Size());
				InternalCapacity() = other.Size();
			}
		}
		else
		{
			if constexpr (TinyItemCount == 0)
			{
				Items().CopyFrom(other.Items().Get(), other.Size(), Size());
			}
			else
			{
				Clear();

				const Value* source = other.Data();
				if ION_LIKELY (InternalCapacity() == TinyItemCount)
				{
					for (size_t i = 0; i < other.Size(); ++i)
					{
						mStorage.TinyItems().Insert(i, source[i]);
					}
				}
				else
				{
					for (size_t i = 0; i < other.Size(); ++i)
					{
						Items().Insert(i, source[i]);
					}
				}
			}
		}
		InternalSize() = other.Size();
	}

	template <typename Allocator>
	constexpr void Set(Allocator& allocator, ArenaVector&& other)
	{
		Clear();
		Reset(allocator);
		Move(std::move(other));
	}

	[[nodiscard]] constexpr Value& operator[](std::size_t index)
	{
		ION_ASSERT_FMT_IMMEDIATE(index < InternalSize(), "Bad index: %zu", index);
		return Data()[index];
	}

	[[nodiscard]] constexpr const Value& operator[](std::size_t index) const
	{
		ION_ASSERT_FMT_IMMEDIATE(index < InternalSize(), "Bad index: %zu", index);
		return Data()[index];
	}

	[[nodiscard]] static constexpr CountType GrowthSize(CountType size)
	{
		// #TODO: Take memory allocator into account. (E.g. grow to block size)
		return size <= 128 ? (size + 16 + (size >> 1)) : (size * 2);
	}

	template <typename Allocator>
	inline Iterator Add(Allocator& allocator, Value&& value)
	{
		if (InternalSize() == InternalCapacity())
		{
			EnsureCapacity(allocator, GrowthSize(InternalSize()));
		}
		return AddKeepCapacity(std::move(value));
	}

	template <typename Allocator>
	inline Iterator Add(Allocator& allocator, const Value& value)
	{
		if (InternalSize() == InternalCapacity())
		{
			EnsureCapacity(allocator, GrowthSize(InternalSize()));
		}
		return AddKeepCapacity(value);
	}

	template <typename Allocator, class... Args>
	inline Iterator Emplace(Allocator& allocator, Args&&... args)
	{
		if (InternalSize() == InternalCapacity())
		{
			EnsureCapacity(allocator, GrowthSize(InternalSize()));
		}
		return EmplaceKeepCapacity(std::forward<Args>(args)...);
	}

	ION_FORCE_INLINE Iterator AddKeepCapacity(const Value& value)
	{
		ION_ASSERT(InternalSize() < InternalCapacity(), "Out of reserved capacity");
		Iterator iter;
		if constexpr (TinyItemCount == 0)
		{
			iter = Items().Insert(InternalSize()++, value);
		}
		else if (InternalCapacity() != TinyItemCount)
		{
			iter = Items().Insert(InternalSize()++, value);
		}
		else
		{
			iter = mStorage.TinyItems().Insert(InternalSize()++, value);
		}
		return iter;
	}

	ION_FORCE_INLINE Iterator AddKeepCapacity(Value&& value)
	{
		ION_ASSERT(InternalSize() < InternalCapacity(), "Out of reserved capacity");
		Iterator iter;
		if constexpr (TinyItemCount == 0)
		{
			iter = Items().Insert(InternalSize()++, std::move(value));
		}
		else if (InternalCapacity() != TinyItemCount)
		{
			iter = Items().Insert(InternalSize()++, std::move(value));
		}
		else
		{
			iter = mStorage.TinyItems().Insert(InternalSize()++, std::move(value));
		}
		return iter;
	}

	template <class... Args>
	inline Iterator EmplaceKeepCapacity(Args&&... args)
	{
		ION_ASSERT(InternalSize() < InternalCapacity(), "Out of reserved capacity");
		Iterator iter;
		if constexpr (TinyItemCount == 0)
		{
			iter = Items().Insert(InternalSize()++, std::forward<Args>(args)...);
		}
		else if (InternalCapacity() != TinyItemCount)
		{
			iter = Items().Insert(InternalSize()++, std::forward<Args>(args)...);
		}
		else
		{
			iter = mStorage.TinyItems().Insert(InternalSize()++, std::forward<Args>(args)...);
		}
		return iter;
	}

	// Adds multiple elements. Container size is updated after all elements have been added.
	template <typename Allocator, typename Callback>
	void AddMultiple(Allocator& allocator, size_t count, Callback&& callback)
	{
		CountType newSize = InternalSize() + ion::SafeRangeCast<CountType>(count);
		if constexpr (TinyItemCount == 0)
		{
			Reserve(allocator, newSize);
			for (size_t i = 0; i < count; ++i)
			{
				Items().Insert(InternalSize() + i, callback(InternalSize() + i));
			}
		}
		else if (Reserve(allocator, newSize) || InternalCapacity() != TinyItemCount)
		{
			for (size_t i = 0; i < count; ++i)
			{
				Items().Insert(InternalSize() + i, callback(InternalSize() + i));
			}
		}
		else
		{
			for (size_t i = 0; i < count; ++i)
			{
				mStorage.TinyItems().Insert(InternalSize() + i, callback(InternalSize() + i));
			}
		}
		// Don't update InternalSize() inside the loop, so that we are able to iterate using cpu registers
		InternalSize() = newSize;
	}

	void PopBack() { Pop(); }

	template <typename Allocator>
	inline bool Reserve(Allocator& allocator, size_t size)
	{
		if (size > InternalCapacity())
		{
			EnsureCapacity(allocator, ion::SafeRangeCast<CountType>(size));
			return true;
		}
		return false;
	}

	// Resize without memsetting memory to zero.
	template <typename Allocator>
	void ResizeFast(Allocator& allocator, size_t size)
	{
		ResizeFast(allocator, size, size);
	}

	// Resize without memsetting memory to zero.
	template <typename Allocator>
	void ResizeFast(Allocator& allocator, size_t size, size_t newCapacityAllocation)
	{
		if constexpr (std::is_trivially_constructible<typename Allocator::value_type>::value)
		{
			if (size > InternalCapacity())
			{
				ION_ASSERT(size <= newCapacityAllocation, "Invalid minimum capacity");
				EnsureCapacity(allocator, ion::SafeRangeCast<CountType>(newCapacityAllocation));
			}
			ResizeFastKeepCapacity(size);
		}
		else
		{
			Resize(allocator, size, newCapacityAllocation);
		}
	}

	// Resize without memsetting memory to zero or changing capacity.
	void ResizeFastKeepCapacity(size_t size)
	{
		ION_ASSERT(size <= InternalCapacity(), "Cannot keep capacity");
		if constexpr (std::is_trivially_constructible<Value>::value)
		{
			InternalSize() = ion::SafeRangeCast<CountType>(size);
		}
		else
		{
			Value::CannotResizeFastNonTrivialType();
		}
	}

	template <typename Allocator>
	void Resize(Allocator& allocator, size_t size)
	{
		Resize(allocator, size, size);
	}

	template <typename Allocator>
	void Resize(Allocator& allocator, size_t size, size_t newCapacityAllocation)
	{
		if (size < InternalSize())
		{
			PopTo(ion::SafeRangeCast<CountType>(size));
		}
		else
		{
			if (size > InternalCapacity())
			{
				ION_ASSERT(size <= newCapacityAllocation, "Invalid minimum capacity");
				EnsureCapacity(allocator, ion::SafeRangeCast<CountType>(newCapacityAllocation));
			}
			if constexpr (std::is_trivially_constructible<typename Allocator::value_type>::value)
			{
				std::memset(&Data()[InternalSize()], 0x0, (size - InternalSize()) * sizeof(typename Allocator::value_type));
			}
			else if constexpr (TinyItemCount != 0)
			{
				if constexpr (std::is_trivially_constructible<typename Allocator::value_type>::value)
				{
					std::memset(&Data()[InternalSize()], 0x0, (size - InternalSize()) * sizeof(typename Allocator::value_type));
				}
			}
			PushTo(ion::SafeRangeCast<CountType>(size));
		}
	}

	~ArenaVector()
	{
		ION_ASSERT(InternalSize() == 0 && InternalCapacity() == StaticItemCount,
				   "Please call Clear() & ShrinkToFit() before destructing ArenaVector;Capacity=" << InternalCapacity()
																								  << ";Size=" << InternalSize());
	}

	[[nodiscard]] constexpr CountType Size() const
	{
		ION_ASSERT_FMT_IMMEDIATE(
		  (InternalSize() <= StaticItemCount && InternalCapacity() == StaticItemCount) || (InternalCapacity() > StaticItemCount),
		  "ArenaVector is invalid - data was moved?");
		return InternalSize();
	}

	[[nodiscard]] constexpr CountType Capacity() const { return InternalCapacity(); }

	[[nodiscard]] constexpr Value* Data()
	{
		if constexpr (TinyItemCount == 0)
		{
			ION_ASSERT_FMT_IMMEDIATE(InternalCapacity() != 0 || mStorage.mData.mBuffer.mItems.Get() == nullptr, "Invalid data");
			return mStorage.mData.mBuffer.mItems.Get();
		}
		else if ION_LIKELY (InternalCapacity() == TinyItemCount)
		{
			return mStorage.TinyItems().Data();
		}
		else
		{
			ION_ASSERT_FMT_IMMEDIATE(Items().Get(), "Invalid data");
			return Items().Get();
		}
	}

	[[nodiscard]] constexpr const Value* const Data() const
	{
		if constexpr (TinyItemCount == 0)
		{
			ION_ASSERT_FMT_IMMEDIATE(InternalCapacity() != 0 || Items().Get() == nullptr, "Invalid data");
			return Items().Get();
		}
		else if ION_LIKELY (InternalCapacity() == TinyItemCount)
		{
			return mStorage.TinyItems().Data();
		}
		else
		{
			ION_ASSERT_FMT_IMMEDIATE(Items().Get(), "No data available");
			return Items().Get();
		}
	}

	[[nodiscard]] constexpr const Value& Back() const
	{
		ION_ASSERT_FMT_IMMEDIATE(InternalSize() > 0, "Out of data");
		return Data()[InternalSize() - 1];
	}

	[[nodiscard]] constexpr Value& Back()
	{
		ION_ASSERT_FMT_IMMEDIATE(InternalSize() > 0, "Out of data");
		return Data()[InternalSize() - 1];
	}

	void Clear() { PopTo(0); }

	template <typename Allocator>
	void ShrinkToFit(Allocator& allocator)
	{
		if (InternalSize() <= StaticItemCount)
		{
			if constexpr (SmallItemCount != 0)
			{
				if (InternalCapacity() != SmallItemCount)
				{
					for (size_t i = 0; i < InternalSize(); ++i)
					{
						mStorage.SmallItems().Insert(i, std::move(Items()[i]));
					}
					Deallocate(allocator);
					InternalCapacity() = SmallItemCount;
				}
				Items() = &mStorage.SmallItems()[0];
			}
			else if constexpr (TinyItemCount != 0)
			{
				if (InternalCapacity() != TinyItemCount)
				{
					for (size_t i = 0; i < InternalSize(); ++i)
					{
						mStorage.TinyItems().Insert(i, std::move(Items()[i]));
					}
					Deallocate(allocator);
					Items() = nullptr;
					InternalCapacity() = TinyItemCount;
				}
			}
			else
			{
				Reset(allocator);
			}
		}
		else if (InternalSize() != InternalCapacity())
		{
			EnsureCapacity(allocator, InternalSize());
		}
	}

	[[nodiscard]] constexpr Iterator Begin() { return Data(); }
	[[nodiscard]] constexpr Iterator End() { return Data() + InternalSize(); }
	[[nodiscard]] constexpr ConstIterator Begin() const { return Data(); }
	[[nodiscard]] constexpr ConstIterator End() const { return Data() + InternalSize(); }

	[[nodiscard]] constexpr ReverseIterator REnd() { return ReverseIterator(Data()); }
	[[nodiscard]] constexpr ReverseIterator RBegin() { return ReverseIterator(Data() + InternalSize()); }
	[[nodiscard]] constexpr ConstReverseIterator REnd() const { return ConstReverseIterator(Data()); }
	[[nodiscard]] constexpr ConstReverseIterator RBegin() const { return ConstReverseIterator(Data() + InternalSize()); }

	template <typename Allocator>
	Iterator Insert(Allocator& allocator, size_t index, const Value& value)
	{
		Iterator iter = MakeSpaceForInsert(allocator, ion::SafeRangeCast<CountType>(index));
		*iter = value;
		return iter;
	}

	template <typename Allocator>
	Iterator Insert(Allocator& allocator, const Iterator& iter, const Value& value)
	{
		auto index = ion::SafeRangeCast<CountType>(size_t(iter - Begin()));
		return Insert(allocator, index, value);
	}

	Iterator Erase(size_t index) { return EraseInternal(ion::SafeRangeCast<CountType>(index), ion::SafeRangeCast<CountType>(index + 1)); }

	Iterator Erase(const Iterator& iter)
	{
		auto index = ion::SafeRangeCast<CountType>(size_t(iter - Begin()));
		return EraseInternal(index, index + 1);
	}

	Iterator Erase(const Iterator& start, const Iterator& end)
	{
		auto startIndex = ion::SafeRangeCast<CountType>(size_t(start - Begin()));
		auto endIndex = ion::SafeRangeCast<CountType>(size_t(end - Begin()));
		return EraseInternal(startIndex, endIndex);
	}

	bool IsEmpty() const { return InternalSize() == 0; }

private:
	template<typename Allocator>
	Value* Allocate(Allocator& allocator, CountType newCapacity)
	{
		Value* items;
		if constexpr (std::is_same<Value, typename Allocator::value_type>::value)
		{
			items = allocator.allocate(newCapacity);
		}
		else
		{
			static_assert(StaticItemCount == 0, "Cannot use custom types with static item buffer");
			items = reinterpret_cast<Value*>(allocator.allocate(newCapacity / sizeof(typename Allocator::value_type)));
		}
		return items;
	}

	template <typename Allocator>
	void Deallocate(Allocator& allocator)
	{
		if constexpr (std::is_same<Value, typename Allocator::value_type>::value)
		{
			allocator.deallocate(reinterpret_cast<typename Allocator::value_type*>(Items().Get()), InternalCapacity());
		}
		else
		{
			static_assert(StaticItemCount == 0, "Cannot use custom types with static item buffer");
			allocator.deallocate(reinterpret_cast<typename Allocator::value_type*>(Items().Get()),
								 InternalCapacity() / sizeof(typename Allocator::value_type));
		}
	}

	void Move(ArenaVector&& other)
	{
		ION_ASSERT(InternalSize() == 0, "Cannot move here when buffer has items");
		ION_ASSERT(InternalCapacity() == StaticItemCount, "Cannot move here when old buffer has allocation");
		if constexpr (TinyItemCount == 0)
		{
			if constexpr (SmallItemCount == 0)
			{
				Items().Set(other.Items().Get(), other.Size());
				InternalCapacity() = other.InternalCapacity();
				other.Items() = nullptr;
				other.InternalCapacity() = 0;
			}
			else
			{
				ION_ASSERT(other.Capacity() >= SmallItemCount, "Other vector has invalid capacity: " << other.Capacity());
				if (other.Capacity() == SmallItemCount)
				{
					MoveStatic(mStorage.SmallItems().Data(), other.mStorage.SmallItems(), other.Size());
					Items().Set(mStorage.SmallItems().Data(), other.Size());
				}
				else
				{
					Items().Set(other.Items().Get(), other.Size());
					InternalCapacity() = other.InternalCapacity();
				}
				other.Items().Set(other.mStorage.SmallItems().Data(), 0);
				other.InternalCapacity() = SmallItemCount;
			}
			ION_ASSERT(Capacity() >= SmallItemCount, "Invalid other vector");
		}
		else if (other.InternalCapacity() > TinyItemCount)
		{
			Items() = other.Items();
			InternalCapacity() = other.InternalCapacity();
			other.Items() = nullptr;
			other.InternalCapacity() = TinyItemCount;
		}
		else
		{
			for (size_t i = 0; i < other.InternalSize(); ++i)
			{
				mStorage.TinyItems().Insert(i, std::move(other.mStorage.TinyItems()[i]));
				other.mStorage.TinyItems().Erase(i);
			}
		}
		InternalSize() = other.InternalSize();
		other.InternalSize() = 0;
	}

	template <typename Allocator>
	Iterator MakeSpaceForInsert(Allocator& allocator, CountType index)
	{
		auto lastIndex = Size();
		auto count = lastIndex - index;

		if (InternalSize() == InternalCapacity())
		{
			// #TODO: here everything is copied, and move forward will copy again. Should be only single copy.
			EnsureCapacity(allocator, GrowthSize(InternalSize()));
		}
		AddKeepCapacity(Value());
		Iterator iter = Data();
		ION_ASSERT(InternalSize() >= index, "Invalid index");
		MoveForwardByOffset<Value>(iter + lastIndex + 1, 1, count);
		return iter + index;
	}

	inline Iterator EraseInternal(CountType start, CountType end)
	{
		CountType eraseCount = end - start;
		ION_ASSERT(eraseCount <= InternalSize(), "Erase out of bounds");
		ION_ASSERT(eraseCount > 0, "Invalid erase");
		CountType newCount = InternalSize() - eraseCount;
		Value* dataStart = &Data()[start];
		MoveBackByOffset<Value>(dataStart, eraseCount, InternalSize() - end);
		PopTo(newCount);
		return dataStart;
	}

	template <typename Buffer>
	inline void MoveStatic(Value* dst, Buffer&& src, size_t count)
	{
		if (std::is_trivially_copyable<Value>::value)
		{
			std::memcpy(dst, &src[0], count * sizeof(Value));
		}
		else
		{
			for (size_t i = 0; i < count; ++i)
			{
				new (static_cast<void*>(&dst[i])) Value(std::move(src[i]));
				src[i].~Value();
			}
		}
	}

	template <typename Buffer>
	inline void CopyStatic(Value* dst, Buffer& src, size_t count)
	{
		if (std::is_trivially_copyable<Value>::value)
		{
			memcpy(dst, &src[0], count * sizeof(Value));
		}
		else
		{
			for (size_t i = 0; i < count; ++i)
			{
				new (static_cast<void*>(&dst[i])) Value(src[i]);
			}
		}
	}

	template <typename Allocator>
	void EnsureCapacity(Allocator& allocator, CountType newCapacity)
	{
		ION_ASSERT(newCapacity != InternalCapacity(), "Invalid size");
		ION_ASSERT(
		  InternalCapacity() == StaticItemCount || reinterpret_cast<uintptr_t>(Data()) % alignof(typename Allocator::value_type) == 0,
		  "Alignment changed before clearing old buffer");

		Value* items = Allocate(allocator, newCapacity);

		if (InternalCapacity() != StaticItemCount)
		{
			Items().MoveTo(items, InternalSize());
			Deallocate(allocator);
		}
		else if constexpr (SmallItemCount != 0)
		{
			MoveStatic(items, mStorage.SmallItems(), InternalSize());
		}
		else if constexpr (TinyItemCount != 0)
		{
			MoveStatic(items, mStorage.TinyItems(), InternalSize());
		}
		ION_ASSERT(newCapacity > TinyItemCount, "Invalid capacity");
		InternalCapacity() = newCapacity;
		Items().Set(items, InternalSize());
	}

	template <typename Allocator>
	void Reset(Allocator& allocator)
	{
		ION_ASSERT(InternalSize() == 0, "ArenaVector was not properly emptied");
		if constexpr (TinyItemCount == 0)
		{
			if (InternalCapacity() != SmallItemCount)
			{
				Deallocate(allocator);
				InternalCapacity() = SmallItemCount;
			}
			if constexpr (SmallItemCount == 0)
			{
				Items() = nullptr;
			}
			else
			{
				Items() = &mStorage.SmallItems()[0];
			}
			ION_ASSERT(InternalCapacity() == SmallItemCount, "Invalid capacity");
		}
		else if (InternalCapacity() != TinyItemCount)
		{
			Deallocate(allocator);
			Items() = nullptr;
			InternalCapacity() = TinyItemCount;
		}
	}

	inline void Pop()
	{
		InternalSize()--;
		if constexpr (TinyItemCount == 0)
		{
			Items().Erase(InternalSize());
		}
		else if (InternalCapacity() != TinyItemCount)
		{
			Items().Erase(InternalSize());
		}
		else
		{
			mStorage.TinyItems().Erase(InternalSize());
		}
	}

	inline void Push()
	{
		if constexpr (TinyItemCount == 0)
		{
			Items().Insert(InternalSize()++);
		}
		else if (InternalCapacity() != TinyItemCount)
		{
			Items().Insert(InternalSize()++);
		}
		else
		{
			mStorage.TinyItems().Insert(InternalSize()++);
		}
	}

	void PushTo(CountType size)
	{
		if constexpr (!std::is_trivially_constructible<Value>::value)
		{
			auto currentSize = InternalSize();
			if constexpr (TinyItemCount == 0)
			{
				while (currentSize < size)
				{
					Items().Insert(currentSize);
					currentSize++;
				}
			}
			else if (InternalCapacity() != TinyItemCount)
			{
				while (currentSize < size)
				{
					Items().Insert(currentSize);
					currentSize++;
				}
			}
			else
			{
				while (currentSize < size)
				{
					mStorage.TinyItems().Insert(currentSize);
					currentSize++;
				}
			}
		}
		InternalSize() = size;
	}

	void PopTo(CountType size)
	{
		if constexpr (!RawBuffer<Value>::IsTrivial())
		{
			auto currentSize = InternalSize();
			if constexpr (TinyItemCount == 0)
			{
				while (currentSize > size)
				{
					currentSize--;
					Items().Erase(currentSize);
				}
			}
			else if ION_LIKELY (InternalCapacity() == TinyItemCount)
			{
				while (currentSize > size)
				{
					currentSize--;
					mStorage.TinyItems().Erase(currentSize);
				}
			}
			else
			{
				while (currentSize > size)
				{
					currentSize--;
					Items().Erase(currentSize);
				}
			}
		}
		InternalSize() = size;
	}

	template <size_t Padding>
	struct BufferInfo
	{
		BufferInfo(CountType size, CountType capacity) : mSize(size), mCapacity(capacity) {}
		uint8_t mPadding[Padding];
		CountType mSize;
		CountType mCapacity;
	};

	template <>
	struct BufferInfo<0>
	{
		BufferInfo(CountType size, CountType capacity) : mSize(size), mCapacity(capacity) {}
		CountType mSize;
		CountType mCapacity;
	};

	template <typename ItemType, int PayloadSize = 0>
	struct Buffer
	{
		Buffer(CountType size, CountType capacity) : mInfo(size, capacity) {}
		using Impl = ion::RawBuffer<ItemType>;
		Impl mItems;
		static constexpr int Padding = (PayloadSize != 0) ? ion::Max(0, PayloadSize - int(sizeof(Impl)) - int(sizeof(CountType) * 2)) : 0;
		BufferInfo<Padding> mInfo;
	};

	template <typename ItemType, CountType TTinyItemCount, int PayloadSize = 0>
	struct TinyBuffer
	{
		TinyBuffer(CountType size, CountType capacity) : mInfo(size, capacity) {}
		using Impl = ion::AlignedStorage<ItemType, TTinyItemCount>;
		Impl mTinyItems;
		static constexpr int Padding = (PayloadSize != 0) ? ion::Max(0, PayloadSize - int(sizeof(Impl)) - int(sizeof(CountType) * 2)) : 0;
		BufferInfo<Padding> mInfo;
	};

	template <typename ItemType, CountType TSmallItemCount>
	struct SmallBuffer
	{
		SmallBuffer(CountType size, CountType capacity) : mInfo(size, capacity) {}
		ion::RawBuffer<ItemType> mItems;
		ion::AlignedStorage<ItemType, TSmallItemCount> mSmallItems;
		BufferInfo<0> mInfo;
	};

	template <CountType TSmallItemCount, CountType TTinyItemCount, typename TValue>
	struct Storage
	{
		Storage(CountType size = 0, CountType capacity = TSmallItemCount) : mData(size, capacity) {}
		struct Data
		{
			Data(CountType size, CountType capacity) : mBuffer(size, capacity) {}
			SmallBuffer<TValue, SmallItemCount> mBuffer;
		} mData;
		static_assert(TTinyItemCount == 0, "Invalid buffer");

		constexpr ion::AlignedStorage<Value, TSmallItemCount>& SmallItems() { return mData.mBuffer.mSmallItems; }
		constexpr const ion::AlignedStorage<Value, TSmallItemCount>& SmallItems() const { return mData.mBuffer.mSmallItems; }
	};

	template <CountType TTinyItemCount, typename TValue>
	struct Storage<0, TTinyItemCount, TValue>
	{
		Storage(CountType size = 0, CountType capacity = TTinyItemCount) : mData(size, capacity)
		{
			ION_ASSERT_FMT_IMMEDIATE(mData.mTinyBuffer.mInfo.mCapacity == mData.mBuffer.mInfo.mCapacity, "Invalid capacity address");
		}

		static constexpr size_t TinyStoragePayloadSize =
		  ion::Max(sizeof(RawBuffer<TValue>), sizeof(ion::AlignedStorage<TValue, TTinyItemCount>)) + (sizeof(CountType) * 2);
		static constexpr size_t TinyStoragePayloadAligment =
		  ion::Max(alignof(RawBuffer<TValue>), alignof(ion::AlignedStorage<TValue, TTinyItemCount>));

		static constexpr size_t TinyStorageSize =
		  (TinyStoragePayloadSize % TinyStoragePayloadAligment) != 0
			? ((TinyStoragePayloadAligment - (TinyStoragePayloadSize % TinyStoragePayloadAligment)) + TinyStoragePayloadSize)
			: TinyStoragePayloadSize;

		alignas(TinyStoragePayloadAligment) union Data
		{
			Data(CountType size, CountType capacity) : mBuffer(size, capacity) {}
			Buffer<TValue, TinyStorageSize> mBuffer;
			TinyBuffer<TValue, TTinyItemCount, TinyStorageSize> mTinyBuffer;
		} mData;

		static_assert(sizeof(Data) == 2 * sizeof(ion::RawBuffer<TValue>), "Invalid tiny vector");

		constexpr ion::AlignedStorage<Value, TTinyItemCount>& TinyItems() { return mData.mTinyBuffer.mTinyItems; }
		constexpr const ion::AlignedStorage<Value, TTinyItemCount>& TinyItems() const { return mData.mTinyBuffer.mTinyItems; }
	};

	template <typename TValue>
	struct Storage<0, 0, TValue>
	{
		Storage(CountType size = 0, CountType capacity = 0) : mData(size, capacity) {}
		struct Data
		{
			Data(CountType size, CountType capacity) : mBuffer(size, capacity) {}
			Buffer<TValue> mBuffer;
		} mData;
	};

	Storage<SmallItemCount, TinyItemCount, Value> mStorage;

	constexpr CountType& InternalSize() { return mStorage.mData.mBuffer.mInfo.mSize; }
	constexpr CountType& InternalCapacity() { return mStorage.mData.mBuffer.mInfo.mCapacity; }
	constexpr const CountType& InternalSize() const { return mStorage.mData.mBuffer.mInfo.mSize; }
	constexpr const CountType& InternalCapacity() const { return mStorage.mData.mBuffer.mInfo.mCapacity; }

	constexpr ion::RawBuffer<Value>& Items() { return mStorage.mData.mBuffer.mItems; }
	constexpr const ion::RawBuffer<Value>& Items() const { return mStorage.mData.mBuffer.mItems; }
};

// Use size of storage pointer + padding bytes of size/capacity as tiny buffer
template <typename Value, size_t BufferSize = (2 * sizeof(ion::RawBuffer<Value>) - (sizeof(uint8_t) * 2)) / sizeof(Value)>
using TinyArenaVector = ArenaVector<Value, 0, uint8_t, BufferSize>;

}  // namespace ion
