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

#include <ion/Base.h>
#include <fenv.h>

#if !ION_PLATFORM_ANDROID
_Pragma("float_control(precise, on)");
_Pragma("float_control(except, off)");
#endif

#if !ION_PLATFORM_LINUX
_Pragma("fenv_access (on)");
_Pragma("fp_contract (off)");
#endif

namespace ion
{
namespace FPControl
{
// ARM Note:
// _controlfp requires you to select a floating - point model that supports exceptions.
// For example, --fpmode = ieee_full or --fpmode = ieee_fixed.

void SetMode()
{
#if ION_PLATFORM_MICROSOFT
	// Floating-point mode
	unsigned int controlWord = 0;
#endif

	/* Precision control is not supported on ARM or x64 platforms.
	https://svn.boost.org/trac10/ticket/4964
	Microsoft says on MSDN (when you google for _control87):
	"On the x64 architecture, changing the floating point precision is not supported.
	If the precision control mask is used on that platform, an assertion and the invalid
	parameter handler is invoked, as described in Parameter Validation." */
#if !defined ION_ARCH_ARM && !defined(ION_ARCH_X86_64)
	{
		auto err = _controlfp_s(&controlWord, _PC_24, MCW_PC);
		ION_CHECK(err == 0, "Cannot set floating point mode;err=" << err);
	}
#endif
	// Rounding control (RC)
	{
#if ION_PLATFORM_MICROSOFT
		auto err = _controlfp_s(&controlWord, _RC_NEAR, MCW_RC);
#else
		auto err = fesetround(FE_TONEAREST);
#endif
		ION_CHECK(err == 0, "Cannot set rounding mode;err=" << err);
	}
}

unsigned int GetControlWord()
{
	unsigned int controlWord = 0;
#if ION_PLATFORM_MICROSOFT
	auto err = _controlfp_s(&controlWord, 0, 0);
	if (err != 0)
	{
		ION_ABNORMAL("Cannot read floating point control word;err=" << err);
	}
#else
	controlWord = fegetround();
#endif
	return controlWord;
}

void Validate()
{
#if !defined ION_ARCH_ARM && !defined(ION_ARCH_X86_64)
	ION_CHECK((GetControlWord() & _MCW_PC) == _PC_24, "Floating point mode has been changed");
#endif
#if ION_PLATFORM_MICROSOFT
	ION_CHECK((GetControlWord() & _MCW_RC) == _RC_NEAR, "Floating point mode has been changed");
#else
	ION_CHECK(GetControlWord() == FE_TONEAREST, "Floating point mode has been changed");
#endif
}

};	// namespace FPControl
}  // namespace ion
