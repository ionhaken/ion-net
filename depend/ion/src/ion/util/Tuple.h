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
#include <tuple>
#include <utility>

namespace ion
{
template <class... Types>
using Tuple = std::tuple<Types...>;

template <std::size_t I = 0, typename FuncT, typename... Tp>
inline typename std::enable_if<I == sizeof...(Tp), void>::type ForEachTuple(std::tuple<Tp...>&,
																			FuncT)	// Unused arguments are given no names.
{
}

template <std::size_t I = 0, typename FuncT, typename... Tp>
  inline typename std::enable_if < I<sizeof...(Tp), void>::type ForEachTuple(std::tuple<Tp...>& t, FuncT f)
{
	f(I, std::get<I>(t));
	ForEachTuple<I + 1, FuncT, Tp...>(t, f);
}

// Const

template <std::size_t I = 0, typename FuncT, typename... Tp>
inline typename std::enable_if<I == sizeof...(Tp), void>::type ForEachTuple(const std::tuple<Tp...>&,
																			FuncT)	// Unused arguments are given no names.
{
}

template <std::size_t I = 0, typename FuncT, typename... Tp>
  inline typename std::enable_if < I<sizeof...(Tp), void>::type ForEachTuple(const std::tuple<Tp...>& t, FuncT f)
{
	f(I, std::get<I>(t));
	ForEachTuple<I + 1, FuncT, Tp...>(t, f);
}

}  // namespace ion
