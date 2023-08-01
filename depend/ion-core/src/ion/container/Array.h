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
#include <ion/debug/Error.h>
#ifndef ION_EXTERNAL_ARRAY
	#define ION_EXTERNAL_ARRAY 1
#endif
#if ION_EXTERNAL_ARRAY == 1
	#include <array>
#else
	#include <initializer_list>
	#include <type_traits>
#endif

namespace ion
{
template <typename TValue, uint32_t TSize>
class Array
{
#if ION_EXTERNAL_ARRAY == 1
	using Native = std::array<TValue, TSize>;
#else
	using Native = TValue[TSize];
#endif

	Native mData;

	template <size_t... Is>
	constexpr Array(std::initializer_list<TValue> il, std::index_sequence<Is...>) : mData{{( il.begin()[Is] )...}}
	{
	}

	template <size_t... Is, typename Callback>
	constexpr Array(Callback&& callback, std::index_sequence<Is...>) : mData{{(callback(Is))...}}
	{
	}


public:
	static constexpr size_t ElementCount = TSize;

	using Type = TValue;

	template <typename Callback>
	explicit constexpr Array(Callback&& callback) : Array(callback, std::make_index_sequence<TSize>{})
	{
	}

	constexpr Array(std::initializer_list<TValue> il) : Array(il, std::make_index_sequence<TSize>{}) {}

	constexpr Array() {}

	template <typename... Args>
	constexpr Array(const TValue& value, Args&&... args) : mData{value, std::forward<Args>(args)...}
	{
	}

	constexpr Array(Array<TValue, TSize>&& array) : mData(std::move(array.mData)) {}

	constexpr Array(const Array<TValue, TSize>& array) : mData(array.mData) {}



	Array<TValue, TSize>& operator=(Array<TValue, TSize>&& other)
	{
		mData = std::move(other.mData);
		return *this;
	}

	Array<TValue, TSize>& operator=(const Array<TValue, TSize>& other)
	{
		mData = other.mData;
		return *this;
	}

	~Array() = default;

	[[nodiscard]] constexpr TValue& operator[](std::size_t index)
	{
		ION_ASSERT_FMT_IMMEDIATE(index < TSize, "Index out of range;%zu/%zu", index, TSize);
		return mData[index];
	}

	[[nodiscard]] constexpr const TValue& operator[](std::size_t index) const
	{
		ION_ASSERT_FMT_IMMEDIATE(index < TSize, "Index out of range");
		return mData[index];
	}

#if ION_EXTERNAL_ARRAY == 0
	class Iterator
	{
	public:
		Iterator(TValue& data) : mPos(&data) {}

		ptrdiff_t operator-(const Iterator& rhs) const { return mPos - rhs.mPos; }

		Iterator operator-(const size_t rhs) const
		{
			Iterator iter(*this);
			iter.mPos -= rhs;
			return iter;
		}
		Iterator operator+(const size_t rhs) const
		{
			Iterator iter(*this);
			iter.mPos += rhs;
			return iter;
		}
		// size_t operator-(const Iterator& rhs) const { return mPos - rhs.mPos; }

		TValue& operator*() { return *mPos; }
		TValue& operator*() const { return *mPos; }

		TValue* operator->() { return mPos; }
		const TValue* operator->() const { return mPos; }

		TValue& operator[](size_t pos) { return mPos[pos]; }
		TValue& operator[](size_t pos) const { return mPos[pos]; }

		bool operator==(const Iterator& rhs) const { return mPos == rhs.mPos; }

		bool operator!=(const Iterator& rhs) const { return mPos != rhs.mPos; }
		Iterator& operator++()
		{
			mPos++;
			return *this;
		}

		Iterator operator++(int)
		{
			Iterator iter(*mPos);
			mPos++;
			return iter;
		}

	private:
		TValue* mPos;
	};

	typedef Iterator ConstIterator;
#else
	typedef typename std::array<TValue, TSize>::iterator Iterator;
	typedef typename std::array<TValue, TSize>::reverse_iterator ReverseIterator;
	typedef typename std::array<TValue, TSize>::const_iterator ConstIterator;
#endif

	ION_FORCE_INLINE Iterator Begin()
	{
#if ION_EXTERNAL_ARRAY == 0
		return Iterator(mData[0]);
#else
		return mData.begin();
#endif
	}

#if 0
		ReverseIterator RBegin()
		{
			return mData.rbegin();
		}
#endif

	ION_FORCE_INLINE const Iterator End()
	{
#if ION_EXTERNAL_ARRAY == 0
		return Iterator(mData[TSize]);
#else
		return mData.end();
#endif
	}

	ION_FORCE_INLINE ConstIterator Begin() const
	{
#if ION_EXTERNAL_ARRAY == 0
		return ConstIterator(mData[0]);
#else
		return mData.begin();
#endif
	}

	ION_FORCE_INLINE ConstIterator End() const
	{
#if ION_EXTERNAL_ARRAY == 0
		return ConstIterator(mData[TSize]);
#else
		return mData.end();
#endif
	}

	constexpr size_t Size() const { return TSize; }

#if ION_EXTERNAL_ARRAY == 0
	[[nodiscard]] constexpr const TValue* Data() const { return &mData[0]; }
	[[nodiscard]] constexpr TValue* Data() { return &mData[0]; }
#else
	[[nodiscard]] constexpr const TValue* Data() const { return mData.data(); }
	[[nodiscard]] constexpr TValue* Data() { return mData.data(); }
#endif
};

namespace detail
{
template <typename T, typename F, std::size_t... Is>
[[nodiscard]] constexpr auto MakeArray(F&& f, std::index_sequence<Is...>) -> ion::Array<T, sizeof...(Is)>
{
	return {{f(std::integral_constant<std::size_t, Is>{})...}};
}
}  // namespace detail

template <typename T, std::size_t N, typename F>
[[nodiscard]] constexpr ion::Array<T, N> MakeArray(F&& f)
{
	return detail::MakeArray<T>(f, std::make_index_sequence<N>{});
}

template <typename Type, size_t Size>
struct IsFixedArray<ion::Array<Type, Size>> : std::true_type
{
};

}  // namespace ion

template <class T, std::size_t N>
constexpr bool operator==(const ion::Array<T, N>& lhs, const ion::Array<T, N>& rhs)
{
	return memcmp(lhs.Data(), rhs.Data(), sizeof(T) * N) == 0;
}
