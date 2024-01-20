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
#include <ion/jobs/JobScheduler.h>

#include <ion/core/Core.h>
#include <ion/tweakables/Tweakables.h>
#if ION_PLATFORM_MICROSOFT
	#pragma comment(lib, "winmm.lib")
#endif

namespace ion
{
struct GlobalSettings
{
	GlobalSettings() : mExecutableName("name", "") { mExecutableName.DisableSerialization(); }
	ion::ConfigString mExecutableName;
};

Core::Core(CoreResource&) : mGlobalSettings(ion::MakeUniqueOpaqueNull<GlobalSettings>()) {}

const ion::String Core::ExecutableName() const { return mGlobalSettings->mExecutableName; }

void Core::InitGlobalSettings() { mGlobalSettings = ion::MakeUniqueOpaqueDomain<ion::CoreAllocator<GlobalSettings>>(); }

void Core::DeinitGlobalSettings() { mGlobalSettings = nullptr; }

namespace core
{
ion::JobScheduler* gSharedScheduler = nullptr;
ion::JobDispatcher* gSharedDispatcher = nullptr;

STATIC_INSTANCE(Core, CoreResource);



}  // namespace core

void CoreInit()
{
	ION_ACCESS_GUARD_WRITE_BLOCK(core::gGuard);
	constexpr size_t CoreMemoryDefaultSize = 1024 * 1024;

	core::Init([]() {}, CoreMemoryDefaultSize);
	ION_MEMORY_SCOPE(ion::tag::Core);
}
void CoreDeinit()
{
	ION_ACCESS_GUARD_WRITE_BLOCK(core::gGuard);
	if (1 != core::gRefCount--)
	{
		return;
	}
	core::gIsInitialized = false;
#if ION_CLEAN_EXIT
	core::gInstance.Deinit();
#endif
}

}  // namespace ion

// Temporarily moved from Base64.cpp as a workaround for clang

#include <ion/util/Base64.h>
#include <ion/util/SafeRangeCast.h>

// https://github.com/SizzlingCalamari/cbase64
#define CBASE64_IMPLEMENTATION
#include <base64/cbase64.h>

namespace ion
{
namespace detail
{
size_t EncodedLength(size_t length_in) { return cbase64_calc_encoded_length(ion::SafeRangeCast<unsigned int>(length_in)); }

size_t DecodedLength(const char* code_in, size_t length_in)
{
	return cbase64_calc_decoded_length(code_in, ion::SafeRangeCast<unsigned int>(length_in));
}

size_t Base64Encode(const unsigned char* data_in, size_t length_in, char* codeOut)
{
	char* codeOutEnd = codeOut;

	cbase64_encodestate encodeState;
	cbase64_init_encodestate(&encodeState);
	codeOutEnd += cbase64_encode_block(data_in, ion::SafeRangeCast<unsigned int>(length_in), codeOutEnd, &encodeState);
	codeOutEnd += cbase64_encode_blockend(codeOutEnd, &encodeState);

	return (codeOutEnd - codeOut);
}
size_t Base64Decode(const char* code_in, size_t length_in, unsigned char* dataOut)
{
	cbase64_decodestate decodeState;
	cbase64_init_decodestate(&decodeState);
	return cbase64_decode_block(code_in, ion::SafeRangeCast<unsigned int>(length_in), dataOut, &decodeState);
}
}  // namespace detail

}  // namespace ion
