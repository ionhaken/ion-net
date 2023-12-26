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
#include <ion/core/Core.h>
#include <ion/byte/ByteWriter.h>
#include <ion/string/String.h>
#include <ion/string/StringView.h>

#if ION_PLATFORM_MICROSOFT
	#include <Windows.h>
	#include <locale>
	#include <codecvt>

ion::String::String(const wchar_t* aString) : mImpl()
{
	// setup converter
	auto len = wcslen(aString);
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, aString, (int)len, NULL, 0, NULL, NULL);
	std::string strTo(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, aString, (int)len, &strTo[0], size_needed, NULL, NULL);
	mImpl.Native() = strTo;
}

std::unique_ptr<wchar_t[]> ion::String::WStr() const
{
	size_t newsize = mImpl.Native().size() + 1;
	std::unique_ptr<wchar_t[]> wcstring = std::make_unique<wchar_t[]>(newsize);
	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, wcstring.get(), newsize, mImpl.Native().c_str(), _TRUNCATE);
	return wcstring;
}

// https://stackoverflow.com/questions/22689859/converting-string-to-lpctstr
std::wstring ion::String::WideString() const
{
	int len;
	int slength = (int)mImpl.Native().length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, mImpl.Native().c_str(), slength, 0, 0);

	std::unique_ptr<wchar_t[]> buf = std::make_unique<wchar_t[]>(len);
	// wchar_t* buf = new wchar_t[len];

	MultiByteToWideChar(CP_ACP, 0, mImpl.Native().c_str(), slength, buf.get(), len);
	std::wstring r(buf.get());
	// delete[] buf;
	return r;
}


#endif
