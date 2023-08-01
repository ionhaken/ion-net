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

namespace ion
{
template <typename Type, typename ContainerType>
class BitFlags
{
public:
	template <typename... Args>
	inline BitFlags(Args... args)
	{
		for (auto&& x : {args...})
		{
			mState = mState | ContainerType(1 << int(x));
		}
	}

	BitFlags() : mState(0) {}

	constexpr BitFlags(ContainerType value) : mState(value) {}

	template <Type TFlag>
	void Toggle()
	{
		mState = ContainerType(int(mState) ^ (1 << int(TFlag)));
	}

	template <Type TFlag>
	void Set()
	{
		mState = ContainerType(int(mState) | (1 << int(TFlag)));
	}

	template <Type TFlag>
	void Clear()
	{
		mState = ContainerType(int(mState) & ~(1 << int(TFlag)));
	}

	template <Type TFlag>
	constexpr bool IsSet() const
	{
		return (int(mState) & int(1 << int(TFlag))) != 0;
	}
	constexpr bool operator==(const BitFlags<Type, ContainerType>& other) const { return mState == other.mState; }
	constexpr bool operator!=(const BitFlags<Type, ContainerType>& other) const { return mState != other.mState; }

private:
	ContainerType mState = 0;
};
}  // namespace ion
