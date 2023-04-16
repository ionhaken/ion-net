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
#include <ion/byte/ByteWriter.h>

namespace ion
{

bool BufferWriterUnsafe::Extend(ByteSizeType newAvailableCount)
{
	size_t pos = size_t(mParent.mPos - mSource->Begin());
	size_t startPos = size_t(mParent.mStart - mSource->Begin());
	mSource->Extend(ion::SafeRangeCast<ByteSizeType>(newAvailableCount + pos));
	mParent.mPos = mSource->Begin() + pos;
	mParent.mStart = mSource->Begin() + startPos;	
	if (Available() >= newAvailableCount)
	{
		return true;
	}
	ION_ABNORMAL("Out of memory; Available=" << Available() << ";Capacity=" << mSource->Capacity());
	return false;
}

bool ByteWriter::Extend(ByteSizeType newAvailableCount)
{
	size_t pos = size_t(mParent.mPos - mSource.Begin());
	size_t startPos = size_t(mParent.mStart - mSource.Begin());
	mSource.Extend(ion::SafeRangeCast<ByteSizeType>(newAvailableCount + pos));
	mParent.mPos = mSource.Begin() + pos;
	mParent.mStart = mSource.Begin() + startPos;
	mEnd = mSource.Begin() + mSource.Capacity();
	if (Available() >= newAvailableCount)
	{
		return true;
	}
	ION_ABNORMAL("Out of memory; Available=" << Available() << ";Capacity=" << mSource.Capacity());
	return false;
}
bool ByteWriter::Copy(ByteReader& src)
{
	auto len = src.Available();
	if (len > 0)
	{
		if (Available() < len)
		{
			if (!Extend(len))
			{
				return false;
			}
		}

		src.ReadAssumeAvailable(mParent.mPos, len);
		mParent.mPos += len;
	}
	return true;
}
}  // namespace ion
