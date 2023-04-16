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

#include <ion/Types.h>

#if (ION_ASSERTS_ENABLED == 1)
	#include <atomic>

namespace ion
{
// Read/Write guard for debugging.
struct AccessGuard // #TODO: Rename RaceGuard -> move under concurrency
{
	AccessGuard();

	AccessGuard(const AccessGuard& other);

	AccessGuard& operator=(const AccessGuard& other);

	void StartWriting() const;
	void StopWriting() const;

	void StartReading() const;

	void StopReading() const;

	bool IsFree() const { return mReadCount == 0; }

	struct WriteBlock
	{
		WriteBlock(ion::AccessGuard& guard) : mGuard(guard) { mGuard.StartWriting(); }
		~WriteBlock() { mGuard.StopWriting(); }

	private:
		ion::AccessGuard& mGuard;
	};

	struct ReadBlock
	{
		ReadBlock(ion::AccessGuard& guard) : mGuard(guard) { mGuard.StartReading(); }
		~ReadBlock() { mGuard.StopReading(); }

	private:
		ion::AccessGuard& mGuard;
	};

private:
	// Number of readers or -1 when writing
	mutable std::atomic<Int> mReadCount;
	// Use owner thread if you want to allow recursive access. It is disabled to promote better coding style.
	#ifdef ION_ACCESS_GUARD_ALLOW_RECURSIVE
	mutable std::atomic<UInt> mOwnerThreadId;
	#endif
};
}  // namespace ion
	#define ION_ACCESS_GUARD(__name)			   mutable ion::AccessGuard __name
	#define ION_ACCESS_GUARD_STATIC(__name)		   ion::AccessGuard __name
	#define ION_ACCESS_GUARD_START_WRITING(__name) __name.StartWriting()
	#define ION_ACCESS_GUARD_STOP_WRITING(__name)  __name.StopWriting()
	#define ION_ACCESS_GUARD_START_READING(__name) __name.StartReading()
	#define ION_ACCESS_GUARD_STOP_READING(__name)  __name.StopReading()
	#define ION_ACCESS_GUARD_WRITE_BLOCK(__name)   ion::AccessGuard::WriteBlock ION_ANONYMOUS_VARIABLE(accessGuardBlock)((__name))
	#define ION_ACCESS_GUARD_READ_BLOCK(__name)	   ion::AccessGuard::ReadBlock ION_ANONYMOUS_VARIABLE(accessGuardBlock)((__name))
#else
	#define ION_ACCESS_GUARD(__name)
	#define ION_ACCESS_GUARD_STATIC(__name)
	#define ION_ACCESS_GUARD_START_WRITING(__name)
	#define ION_ACCESS_GUARD_STOP_WRITING(__name)
	#define ION_ACCESS_GUARD_START_READING(__name)
	#define ION_ACCESS_GUARD_STOP_READING(__name)
	#define ION_ACCESS_GUARD_WRITE_BLOCK(__name)
	#define ION_ACCESS_GUARD_READ_BLOCK(__name)
#endif
