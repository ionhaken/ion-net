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
#include <cstring>	// strcpy

namespace ion
{
inline int StringCopy(char* ION_RESTRICT dest, [[maybe_unused]] size_t destByteSize, const char* ION_RESTRICT src)
{
#if ION_PLATFORM_MICROSOFT
	return int(strcpy_s(dest, destByteSize, src) == 0 ? destByteSize : 0);
#else
	char* end = strcpy(dest, src);
	return int(end - dest);
#endif
}

inline int StringCaseCompare(const char* ION_RESTRICT a, const char* ION_RESTRICT b)
{
#if ION_PLATFORM_MICROSOFT
	return _stricmp(a, b);
#else

	return strcasecmp(a, b);
#endif
}

inline size_t StringLen(const char* str)
{
	ION_ASSERT_FMT_IMMEDIATE(str != 0, "Invalid string");
	return strlen(str);
}

size_t ION_CONSTEVAL ConstexprStringLength(const char* str) { return *str ? 1 + ConstexprStringLength(str + 1) : 0; }

inline int StringConcatenate(char* ION_RESTRICT dest, [[maybe_unused]] size_t destByteSize, const char* ION_RESTRICT src)
{
#if ION_PLATFORM_MICROSOFT
	return strcat_s(dest, destByteSize, src); // return zero on success
#else
	strcat(dest, src); // returns pointer to destination string
	return 0;
#endif
}

}  // namespace ion
