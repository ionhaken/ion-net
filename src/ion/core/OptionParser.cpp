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
#include <ion/core/OptionParser.h>
#if ION_PLATFORM_MICROSOFT
	#define WIN32_LEAN_AND_MEAN
	#include <windows.h>
	#include <tchar.h>
	#include <shellapi.h>
#endif

#include <ion/tweakables/Tweakables.h>
#include <ion/json/JSONSerialization.h>
#include <ion/memory/MemoryScope.h>

namespace ion
{
namespace option_parser
{
struct ParseContext
{
	ParseContext() : id("--name") {}
	ion::String id;
	ion::String value;
};

namespace detail
{
void HandleArgument(ParseContext& c, const ion::String& arg)
{
	if (arg.SubStr(0, 2) == "--")
	{
		c.id = arg;
	}
	else if (c.id.Length() > 2)
	{
		c.value = arg;
		if (c.value.Length() > 0)
		{
			c.id = c.id.SubStr(2, c.id.Length() - 2).CStr();
			ion::tweakables::SetTweakable(c.id.CStr(), c.value.CStr(), true);
			c.id = "";
			c.value = "";
		}
	}
}

#if ION_TWEAKABLES
void HandleArgumentPre(ParseContext& c, const ion::String& arg)
{
	if (arg.SubStr(0, 2) == "--")
	{
		c.id = arg;
	}
	else if (c.id.Length() > 2)
	{
		c.value = arg;
		if (c.value.Length() > 0)
		{
			c.id = c.id.SubStr(2, c.id.Length() - 2).CStr();
			if (c.id == "userindex")
			{
				ion::tweakables::SetTweakable(c.id.CStr(), c.value.CStr(), true);
			}
			c.id = "";
			c.value = "";
		}
	}
}
#endif

}  // namespace detail

void ParseArgs(int argc, const char* const argv[])
{
	ION_MEMORY_SCOPE(ion::tag::Core);
	ParseContext c;
	for (int i = 0; i < argc; ++i)
	{
		ion::String arg(argv[i]);
		detail::HandleArgument(c, arg);
	}
}

#if ION_PLATFORM_MICROSOFT

template<typename Callback>
void ParseArguments(Callback&& callback)
{
}

void Parse()
{
	int nArgs;
	LPWSTR* szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (szArglist != nullptr)
	{
		ParseContext c;
		for (int i = 0; i < nArgs; ++i)
		{
			ion::String arg(szArglist[i]);
			detail::HandleArgument(c, arg);
		}
		LocalFree(szArglist);
	}
}

#if ION_TWEAKABLES
void ParseConfigIndex()
{
	int nArgs;
	LPWSTR* szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (szArglist != nullptr)
	{
		ParseContext c;
		for (int i = 0; i < nArgs; ++i)
		{
			ion::String arg(szArglist[i]);
			detail::HandleArgumentPre(c, arg);
		}
		LocalFree(szArglist);
	}
}
#endif

#endif
}  // namespace option_parser
}  // namespace ion
