#include <ion/net/NetGUID.h>

#include <ion/string/Hex.h>
#include <ion/string/StringSerialization.h>

namespace ion
{
static constexpr size_t StringSize = 64;

uint32_t NetGUID::ToString(char* dest) const
{
	ION_ASSERT(dest, "Invalid destination buffer");
	if (mRaw == UnassignedGuid)
	{
		constexpr char tmp[] = "NetGuidUnassigned";
		constexpr size_t len = ion::ConstexprStringLength(tmp);
		std::memcpy(dest, tmp, len + 1);
		return len;
	}
	else
	{
		return ion::serialization::Serialize(Hex<uint64_t>(mRaw), dest, StringSize, nullptr);
	}
}

bool NetGUID::FromString(const char* source)
{
	if (source == nullptr)
	{
		return false;
	}
	ion::serialization::Deserialize(mRaw, source, nullptr);
	return true;
}
}  // namespace ion
