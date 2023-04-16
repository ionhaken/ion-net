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
#include <ion/Base.h>

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <Windows.h>
#include <DbgHelp.h>

namespace ion
{
namespace minidump
{
inline LONG WINAPI CrashDump(EXCEPTION_POINTERS* exPointer)
{
	MINIDUMP_EXCEPTION_INFORMATION miniInfo;

	SYSTEMTIME sysTime;
	GetSystemTime(&sysTime);

	wchar_t* tStamp = new wchar_t[64];
	swprintf_s(tStamp, sizeof(wchar_t) * 64, L"MiniDump_%02d-%02d-%02d_%02d-%02d.dmp", sysTime.wYear, sysTime.wMonth, sysTime.wDay,
			   sysTime.wHour, sysTime.wMinute);

	miniInfo.ThreadId = GetCurrentThreadId();
	miniInfo.ExceptionPointers = exPointer;
	miniInfo.ClientPointers = false;

	MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
					  CreateFileW(LPCWSTR(tStamp), GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL),
					  MiniDumpWithDataSegs, &miniInfo, NULL, NULL);
	return EXCEPTION_CONTINUE_SEARCH;
}

inline LONG WINAPI HandleException(EXCEPTION_POINTERS* exPointer)
{
	CrashDump(exPointer);
	ion::debug::FatalErrorHandler();
	return EXCEPTION_CONTINUE_SEARCH;
}
}  // namespace minidump
}  // namespace ion
