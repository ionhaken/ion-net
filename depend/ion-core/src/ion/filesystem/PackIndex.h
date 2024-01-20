#pragma once
#include <ion/container/UnorderedMap.h>
#include <ion/container/Vector.h>

namespace ion
{

struct PackFileInfo
{
	size_t mPackedSize;
	size_t mUnpackedSize;
	size_t mPackFilePosition;
	ion::UInt mPackFileIndex;
};

struct PackIndex
{
	ion::UnorderedMap<ion::String, PackFileInfo> mIdToFileInfo;
	ion::Vector<ion::String> mPackFiles;
};
}  // namespace ion
