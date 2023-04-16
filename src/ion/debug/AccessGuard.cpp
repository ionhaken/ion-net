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
#include <ion/debug/AccessGuard.h>

#if (ION_ASSERTS_ENABLED == 1)
	#include <atomic>
	#include <ion/concurrency/Thread.h>

namespace ion
{
// Read/Write guard for debugging.
AccessGuard::AccessGuard() : mReadCount(0) {}

AccessGuard::AccessGuard(const AccessGuard& other)
  : mReadCount(0)
	#ifdef ION_ACCESS_GUARD_ALLOW_RECURSIVE
	,
	mOwnerThreadId(0)
	#endif
{
	ION_CHECK(other.mReadCount == 0, "Cannot copy when readers/writers present");
}

AccessGuard& AccessGuard::operator=(const AccessGuard& other)
{
	ION_CHECK(other.mReadCount == 0, "Cannot assign when readers/writers present");
	mReadCount = 0;
	return *this;
}

void AccessGuard::StartWriting() const
{
	#ifdef ION_ACCESS_GUARD_ALLOW_RECURSIVE
	auto threadId = mOwnerThreadId.exchange(ion::Thread::GetId());
	#endif
	auto value = mReadCount--;

	#ifdef ION_ACCESS_GUARD_ALLOW_RECURSIVE
	ION_CHECK_FMT_IMMEDIATE(value == 0 || (value < 0 && mOwnerThreadId == threadId), "Cannot write when already locked by %i readers",
							value);
	#else
	ION_CHECK_FMT_IMMEDIATE(value == 0, "Cannot write when already locked by %i readers", value);
	#endif
}

void AccessGuard::StopWriting() const
{
	auto value = ++mReadCount;
	#ifdef ION_ACCESS_GUARD_ALLOW_RECURSIVE
	ION_CHECK(value == 0 || (value < 0 && mOwnerThreadId == ion::Thread::GetId()), "Not marked for writing (value=" << value << ")");
	#else
	ION_CHECK(value == 0, "Not marked for writing (value=" << value << ")");
	#endif
}

void AccessGuard::StartReading() const
{
	#ifdef ION_ACCESS_GUARD_ALLOW_RECURSIVE
	auto threadId = mOwnerThreadId.exchange(ion::Thread::GetId());
	#endif
	auto value = mReadCount++;
	ION_CHECK(value >= 0 /*|| (mOwnerThreadId == threadId)*/,
			  (value < 1024 ? "Accessing readable when writables already present" : "More readers than supported")
				<< " (value=" << value << ")");
}

void AccessGuard::StopReading() const
{
	auto value = --mReadCount;
	#ifdef ION_ACCESS_GUARD_ALLOW_RECURSIVE
	ION_CHECK(value >= 0 || (mOwnerThreadId == ion::Thread::GetId()),
			  (value < 1024 ? "Not marked for reading" : "More readers than supported") << " (value=" << value << ")");
	#else
	ION_CHECK(value >= 0, (value < 1024 ? "Not marked for reading" : "More readers than supported") << " (value=" << value << ")");
	#endif
}
}  // namespace ion
#endif
