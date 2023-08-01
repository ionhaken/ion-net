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
class ComponentIndex
{
	struct Index
	{
		Index(T aValue) : value(aValue), count(1) {}

		T GetValue() const { return T(value.GetIndex() + count); }

		T value;
		uint16_t count;
	};

public:
	void Add(T& value)
	{
		if (!mImpl.IsEmpty() && mImpl.Back().GetValue().GetIndex() == value.GetIndex())
		{
			mImpl.Back().count++;
		}
		else
		{
			mImpl.Add(std::move(Index(value)));
		}
	}

	void Clear() { mImpl.Clear(); }

	typedef typename ComponentIndex<T>::Index Container;

	ion::Vector<Container> mImpl;

	class ConstIterator
	{
	public:
		typedef ConstIterator self_type;
		typedef Container value_type;
		typedef Container& reference;
		typedef Container* pointer;
		typedef int difference_type;
		typedef std::forward_iterator_tag iterator_category;
		ConstIterator(pointer ptr, Container value) : tmp(value) { tmp.count = 0; }
		self_type operator++()
		{
			self_type i = *this;
			tmp.value = T(tmp.value.GetIndex() + 1);
			/*if (ptr_->GetValue() == tmp.GetValue())
			{
				ptr_++;
			}*/
			return i;
		}
		/*self_type operator++(int junk)
		{
			tmp.count++;
			if (ptr_->GetValue() == tmp.count)
			{
				ptr_++;
				tmp.value = ptr_->value;
				tmp.count = 0;
			}
			return *this;
		}*/
		const T& operator*() { return tmp.value; }
		const T* operator->() { return &tmp.value; }
		bool operator==(const self_type& rhs) { return tmp.value.GetIndex() == rhs.tmp.value.GetIndex(); }
		bool operator!=(const self_type& rhs) { return tmp.value.GetIndex() != rhs.tmp.value.GetIndex(); }

	private:
		Container tmp;
	};

	ConstIterator Begin() { return ConstIterator(&mImpl[0], mImpl[0].value); }

	ConstIterator End() { return ConstIterator(&mImpl[0] + mImpl.Size(), T(mImpl[mImpl.Size() - 1].GetValue().GetIndex())); }
};
}  // namespace ion
