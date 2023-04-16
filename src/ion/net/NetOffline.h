#pragma once

#include <ion/container/Array.h>

namespace ion
{
struct Offline
{
	Offline() : mResponseLength(0) {}
	ion::Array<char, 400> mResponse;
	uint16_t mResponseLength;
};

}  // namespace ion
