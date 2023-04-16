#pragma once

#include <ion/Base.h>
#include <ion/byte/ByteWriter.h>
#include <ion/tracing/Log.h>
#include <stdint.h>

namespace ion
{
using NetRemoteIndex = uint16_t;
using NetRemoteGeneration = uint16_t;

class NetRemoteId
{
	static constexpr uint32_t UnassignedId = static_cast<uint32_t>(0);

public:
	constexpr NetRemoteId() : mRaw(UnassignedId) {}
	// constexpr NetRemoteId(const NetRemoteId& other) : mRaw(other.mRaw) {}
	// constexpr NetRemoteId(NetRemoteId&& other) : mRaw(other.mRaw) {}
	constexpr explicit NetRemoteId(NetRemoteGeneration generation, NetRemoteIndex index)
	  : mRaw(uint32_t(generation) << 16 | uint32_t(index))
	{
	}
	constexpr bool operator==(const NetRemoteId& other) const { return mRaw == other.mRaw; }
	constexpr bool operator!=(const NetRemoteId& other) const { return mRaw != other.mRaw; }
	constexpr bool operator>(const NetRemoteId& other) const { return mRaw > other.mRaw; }
	constexpr bool operator<(const NetRemoteId& other) const { return mRaw < other.mRaw; }

	constexpr uint16_t DataIndex() const { return uint16_t((mRaw & 0xFFFF) - 1); }
	constexpr NetRemoteGeneration Generation() const { return NetRemoteGeneration(mRaw >> 16); }
	constexpr NetRemoteIndex RemoteIndex() const { return NetRemoteIndex((mRaw & 0xFFFF)); }
	constexpr bool IsValid() const { return (mRaw & 0xFFFF) != 0; };
	explicit constexpr operator bool() const { return (mRaw & 0xFFFF) != 0; };
	uint32_t UInt32() const { return mRaw; }

private:
	uint32_t mRaw;
};

// Global unique identifier.
class NetGUID
{
	static constexpr uint64_t UnassignedGuid = static_cast<uint64_t>(0);

public:
	static constexpr NetRemoteIndex InvalidNetRemoteIndex = static_cast<NetRemoteIndex>(0);

	constexpr NetGUID() : mRaw(UnassignedGuid) {}
	constexpr NetGUID(const NetGUID& other) : mRaw(other.mRaw) {}
	constexpr explicit NetGUID(uint64_t raw) : mRaw(raw) {}
	constexpr NetGUID& operator=(const NetGUID& other)
	{
		mRaw = other.mRaw;
		return *this;
	}
	constexpr bool operator==(const NetGUID& other) const { return mRaw == other.mRaw; }
	constexpr bool operator!=(const NetGUID& other) const { return mRaw != other.mRaw; }
	constexpr bool operator>(const NetGUID& other) const { return mRaw > other.mRaw; }
	constexpr bool operator<(const NetGUID& other) const { return mRaw < other.mRaw; }

	uint32_t ToString(char* dest) const;
	bool FromString(const char* source);

	static constexpr uint32_t ToUint32(const NetGUID& guid) { return uint32_t(guid.mRaw >> 32) ^ uint32_t(guid.mRaw); }
	static constexpr int size() { return (int)sizeof(uint64_t); }

	constexpr uint64_t& Raw() { return mRaw; }
	constexpr const uint64_t& Raw() const { return mRaw; }

private:
	uint64_t mRaw;
};

constexpr NetGUID NetGuidUnassigned;
constexpr NetGUID NetGuidAuthority(uint64_t(1));

namespace serialization
{

template <>
inline ion::UInt Serialize(const NetGUID& guid, char* buffer, size_t bufferLen, const void*)
{
	if (bufferLen > 64)
	{
		return guid.ToString(buffer);
	}
	return 0;
}

template <>
inline ion::UInt Serialize(const NetRemoteId& remoteId, char* buffer, size_t bufferLen, const void*)
{
	return serialization::Serialize(remoteId.RemoteIndex(), buffer, bufferLen, nullptr);
}

template <typename Type>
bool Deserialize(Type& dst, ion::ByteReader& reader, void*);

template <typename Type, typename WriterType>
void Serialize(const Type& dst, WriterType& writer);

template <>
inline void Serialize(const NetGUID& dst, ion::ByteWriter& writer)
{
	return writer.Write(dst.Raw());
}

template <>
inline bool Deserialize(NetGUID& dst, ion::ByteReader& reader, void*)
{
	return reader.Read(dst.Raw());
}

}  // namespace serialization

}  // namespace ion
