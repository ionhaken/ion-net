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
#include <ion/util/Tuple.h>

namespace ion
{
template <typename Ids, class... Types>
class ReflectionData
{
public:
	static constexpr bool IsDynamic = false;

	template <typename T>
	inline void Visit(T& visitor, const char** Names)
	{
		ion::ForEachTuple(mData, [&](auto index, auto& field) { visitor(field, Names[index]); });
	}

	template <typename Callback>
	inline void ForEach(Callback&& callback)
	{
		ion::ForEachTuple(mData, [&](auto index, auto& field) { callback(index, field); });
	}

	template <int N, typename... Ts>
	struct get;

	template <int N, typename T, typename... Ts>
	struct get<N, std::tuple<T, Ts...>>
	{
		using type = typename get<N - 1, std::tuple<Ts...>>::type;
	};

	template <typename T, typename... Ts>
	struct get<0, std::tuple<T, Ts...>>
	{
		using type = T;
	};

	using Tuple = ion::Tuple<Types...>;

	template <std::size_t N>
	using type = typename std::tuple_element<N, Tuple>::type;

	static constexpr size_t Count = std::tuple_size<Tuple>::value;

	template <size_t Id>
	inline const auto& Get() const
	{
		return std::get<Id>(mData);
	}

	template <size_t Id>
	inline auto& Get()
	{
		return std::get<Id>(mData);
	}

private:
	Tuple mData;
};
}  // namespace ion
