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
#include <limits>

namespace ion
{

template <typename T, T TMax = (std::numeric_limits<T>::max)()>
class IdType
{
public:
	static constexpr T Max = TMax;
	static constexpr T Invalid = Max;

	using Type = T;

	constexpr IdType(const T id) : mId(id) { ION_ASSERT_FMT_IMMEDIATE(mId <= Max, "Value is out of id range"); }

	constexpr explicit operator bool() const { return mId != Invalid; }
	constexpr bool IsValid() const { return mId != Invalid; }
	constexpr bool operator==(const IdType& other) const { return mId == other.mId; }
	constexpr bool operator!=(const IdType& other) const { return mId != other.mId; }
	constexpr bool operator<(const IdType& other) const { return mId < other.mId; }
	constexpr bool operator<=(const IdType& other) const { return mId <= other.mId; }
	constexpr bool operator>(const IdType& other) const { return mId > other.mId; }
	constexpr bool operator>=(const IdType& other) const { return mId >= other.mId; }

	constexpr IdType operator++()
	{
		++mId;
		ION_ASSERT_FMT_IMMEDIATE(mId <= Max, "Increased to out of id range");
		return *this;
	}

	constexpr IdType operator--()
	{
		--mId;
		ION_ASSERT_FMT_IMMEDIATE(mId <= Max, "Decreased to out of id range");
		return *this;
	}

protected:
	constexpr IdType() : mId(Invalid) {}
	constexpr T GetRaw() const { return mId; }
	constexpr void SetRaw(const T value)
	{
		mId = value;
		ION_ASSERT_FMT_IMMEDIATE(mId <= Max, "Raw value is out of id range");
	}

private:
	T mId;
};
}  // namespace ion
