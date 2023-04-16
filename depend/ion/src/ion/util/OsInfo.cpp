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

#include <ion/hw/CPU.inl>
#include <ion/tracing/Log.h>
#include <ion/util/OsInfo.h>
#if !ION_PLATFORM_MICROSOFT
	#include <sys/sysinfo.h>
	#include <unistd.h>
#else
	#include "psapi.h"
#endif
#if ION_PLATFORM_ANDROID
	#include <fstream>
#endif

namespace ion
{
struct OsSystemInfo
{
	size_t mMemoryPageSize = 0;
	unsigned mHWConcurrency = 0;
	bool mReady = false;
};
namespace
{

const OsSystemInfo& GetSystemInfo()
{
	static OsSystemInfo systemInfo;

	if (!systemInfo.mReady)
	{
		unsigned hwConcurrency = 0;
		size_t memoryPageSize = 0;

#if ION_PLATFORM_MICROSOFT
		SYSTEM_INFO info = {{0}};
		GetSystemInfo(&info);
		hwConcurrency = info.dwNumberOfProcessors;
		memoryPageSize = info.dwPageSize;
#else
	#if ION_PLATFORM_ANDROID
		std::ifstream cpuinfo("/proc/cpuinfo");

		hwConcurrency =
		  std::count(std::istream_iterator<std::string>(cpuinfo), std::istream_iterator<std::string>(), std::string("processor"));
	#elif defined(PTW32_VERSION) || defined(__hpux)
		hwConcurrency = pthread_num_processors_np();
	#elif ION_PLATFORM_APPLE || defined(__FreeBSD__)
		int count;
		size_t size = sizeof(count);
		hwConcurrency = sysctlbyname("hw.ncpu", &count, &size, NULL, 0) ? 0 : count;
	#elif defined(_GNU_SOURCE)
		hwConcurrency = get_nprocs();
	#else
		#error not implemented
	#endif
		memoryPageSize = sysconf(_SC_PAGESIZE);
#endif
		ION_CHECK(hwConcurrency != 0, "Cannot read number of processors");
		ION_CHECK(memoryPageSize != 0, "Cannot read memory page size");
		systemInfo.mHWConcurrency = hwConcurrency != 0 ? hwConcurrency : 1;
		systemInfo.mMemoryPageSize = memoryPageSize != 0 ? memoryPageSize : 4096;
		systemInfo.mReady = true;
	}
	return systemInfo;
}
}  // namespace

unsigned OsHardwareConcurrency() { return GetSystemInfo().mHWConcurrency; }

size_t OsMemoryPageSize() { return GetSystemInfo().mMemoryPageSize; }

#if ION_CONFIG_DEV_TOOLS && ION_PLATFORM_MICROSOFT && 0	 // Requires PSAPI dll
void OsMemoryInfo()
{
	PROCESS_MEMORY_COUNTERS pmc{};
	DWORD cb = sizeof(pmc);
	auto success = GetProcessMemoryInfo(GetCurrentProcess(), &pmc, cb);
	ION_ASSERT(success != 0, "Cannot read memory info");

	// ION_LOG_INFO("PageFaultCount:" << pmc.PageFaultCount);
	ION_LOG_INFO("PeakWorkingSetSize: " << pmc.PeakWorkingSetSize);
	ION_LOG_INFO("WorkingSetSize:" << pmc.WorkingSetSize);
	/* ION_LOG_INFO("QuotaPeakPagedPoolUsage: " << pmc.QuotaPeakPagedPoolUsage);
	ION_LOG_INFO("QuotaPagedPoolUsage: " << pmc.QuotaPagedPoolUsage);
	ION_LOG_INFO("QuotaPeakNonPagedPoolUsage: " << pmc.QuotaPeakNonPagedPoolUsage);
	ION_LOG_INFO("QuotaNonPagedPoolUsage: " << pmc.QuotaNonPagedPoolUsage);
	ION_LOG_INFO("PagefileUsage: " << pmc.PagefileUsage);
	ION_LOG_INFO("PeakPagefileUsage: " << pmc.PeakPagefileUsage);
	*/
}
#endif

ion::UInt OsProcessorNumber()
{
#if ION_PLATFORM_MICROSOFT
	return GetCurrentProcessorNumber();
#else
	ION_ASSERT(false, "Not implemented");
	return 0;
#endif
}

}  // namespace ion
