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
#include <ion/concurrency/Synchronized.h>
#include <ion/container/Vector.h>
#include <ion/container/ForEach.h>
#include <ion/util/BitFlags.h>

#include <atomic>

namespace ion
{
class Mail
{
public:
	constexpr Mail(int32_t value) : mValue(value) {}
	bool IsValid() { return mValue; }

	template <typename Type>
	BitFlags<Type, int32_t> Get(size_t index)
	{
		return BitFlags<Type, int32_t>(mValue >> index);
	}

private:
	int32_t mValue;
};

class Mailbox
{
public:
	inline Mail Check()
	{
		return Mail(mHasMail.exchange(0));
	}

	template <typename Type>
	inline void Notify(const Type& index)
	{
		mHasMail |= int32_t(1) << size_t(index);
	}

private:
	std::atomic<int32_t> mHasMail;
};

class MailRegistry
{
public:
	inline void Register(Mailbox* box)
	{
		ION_ASSERT(box != nullptr, "Invalid mailbox");
		mSubscribers.Access([&](auto& list) { list.Add(box); });
	}

	inline void Unregister(Mailbox* box)
	{
		mSubscribers.Access(
		  [&](auto& list)
		  {
			  auto iter = ion::Find(list, box);
			  ION_ASSERT(iter != list.End(), "Invalid mailbox");
			  list.Erase(iter);
		  });
	}

	template <typename Type>
	inline void Notify(const Type& value)
	{
		mSubscribers.Access([&](auto& list) { ion::ForEach(list, [&](Mailbox* box) { box->Notify(value); }); });
	}

	size_t NumSubscribers()
	{
		size_t count = 0;
		mSubscribers.Access([&](auto& list) { count = list.Size(); });
		return count;
	}

private:
	using List = ion::Vector<Mailbox*>;
	ion::Synchronized<List> mSubscribers;
};

}  // namespace ion
