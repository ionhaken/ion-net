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

namespace ion
{
template <typename T>
class ComponentStoreView
{
protected:
	T& mStore;
	const typename T::Index mIndex;

	constexpr ComponentStoreView(T& aStore, const typename T::Index anIndex) : mStore(aStore), mIndex(anIndex)
	{
		ION_ASSERT_FMT_IMMEDIATE(anIndex != ~static_cast<typename T::Index>(0), "Invalid component");
		mStore.OnCreated(mIndex);
	}

	~ComponentStoreView() { mStore.OnDeleted(mIndex); }
};
}  // namespace ion
