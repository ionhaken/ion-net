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
#include <utility>

namespace ion
{
// Pointer container that will assert it has been deallocated when destructor is called.
template <typename T, typename Allocator>
class Ptr
{
public:
	ION_CLASS_NON_COPYABLE(Ptr);

	Ptr() { mData = nullptr; }

	Ptr(T* data) : mData(data) {}

	~Ptr() { ION_ASSERT(mData == nullptr, "Pointer is leaking memory"); }

	operator bool() const { return mData != nullptr; }

	bool operator==(T* other) const { return other == mData; }

	void operator=(Ptr const&&) = delete;
	void operator=(Ptr&& other)
	{
		ION_ASSERT(mData == nullptr, "Pointer is leaking memory");
		mData = other.mData;
		other.mData = nullptr;
	}
	Ptr(Ptr const&& other) : mData(std::move(other.mData)) { other.mData = nullptr; }

	Ptr(Ptr&& other) : mData(std::move(other.mData)) { other.mData = nullptr; }

	T& operator[](size_t index)
	{
		ION_ASSERT(mData, "Invalid array");
		return mData[index];
	}

	const T& operator[](size_t index) const
	{
		ION_ASSERT(mData, "Invalid array");
		return mData[index];
	}

	[[nodiscard]] inline T* operator->() { return mData; }
	[[nodiscard]] inline T* operator*() { return mData; }
	[[nodiscard]] constexpr const T* operator*() const { return mData; }
	[[nodiscard]] constexpr const T* operator->() const { return mData; }

	T* Release()
	{
		auto* tmp = mData;
		mData = nullptr;
		return tmp;
	}

	T* Get() { return mData; }

	const T* Get() const { return mData; }

private:
	T* mData;
};

}  // namespace ion
