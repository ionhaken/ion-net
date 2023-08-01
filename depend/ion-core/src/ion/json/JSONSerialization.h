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
#include <ion/json/JSONDocument.h>
#if ION_EXTERNAL_JSON
	#include <ion/util/Vec.h>
	#include <ion/container/Vector.h>
	#include <ion/string/String.h>
	#include <ion/string/StringView.h>
	#include <ion/tracing/Log.h>

namespace ion
{
class JSONStructWriter;

class JSONArrayWriter : public JSONElement
{
public:
	friend class JSONStructWriter;

	JSONArrayWriter(JSONStructWriter& aParent, const char* name);
	JSONArrayWriter(JSONDocument& aParent, const char* name);
	~JSONArrayWriter();

	template <typename T>
	void AddMember(const char* name, const T& value)
	{
		data.AddMember(rapidjson::GenericValue<rapidjson::UTF8<>>(name, strlen(name)), value, document.mAllocator);
	}

	template <typename T>
	void AddMember(const T& value)
	{
		data.PushBack(value, document.mAllocator);
	}

	template <>
	void AddMember(const ion::String& str)
	{
		rapidjson::GenericValue<rapidjson::UTF8<>> jsonStr(str.CStr(), static_cast<rapidjson::SizeType>(str.Length()));
		data.PushBack(jsonStr, document.mAllocator);
	}

	void* mContext = nullptr;

private:
	const char* mName;
	rapidjson::Value data;
	JSONElement* parent;
};

class JSONStructReader;
class JSONArrayReader : public JSONElement
{
public:
	friend class JSONStructReader;

	explicit JSONArrayReader(const JSONStructReader& aParent, const char* name);
	explicit JSONArrayReader(const JSONDocument& aParent, const char* name);
	~JSONArrayReader();

	rapidjson::SizeType Size() const { return IsValid() ? (data.IsArray() ? data.Size() : 0) : 0; }

	bool IsValid() const { return parent != nullptr; }

	template <typename Callback>
	void ForEach(Callback&& callback) const;

	void* mContext = nullptr;

private:
	const rapidjson::Value& data;
	const JSONElement* parent;
};

class JSONStructReader : public JSONElement
{
public:
	friend class JSONArrayReader;

	// #TODO: Move to private, use foreach to use only
	explicit JSONStructReader(const JSONArrayReader& aParent, size_t index);

	explicit JSONStructReader(const JSONDocument& aParent, const char* name);

	template <typename Callback>
	void ForEachArray(const char* name, Callback&& callback) const
	{
		if (data.HasMember(name))
		{
			const auto& jsonList = data[name];
			if (jsonList.IsArray())
			{
				for (rapidjson::SizeType i = 0; i < jsonList.Size(); i++)
				{
					callback(jsonList[static_cast<int>(i)]);
				}
			}
		}
	}

	ion::Vector<double> GetVector(const char* name) const
	{
		ion::Vector<double> list;
		ForEachArray(name,
					 [&](const auto& in)
					 {
						 if (in.IsNumber())
						 {
							 list.Add(in.GetDouble());
						 }
					 });
		return list;
		/*if (data.HasMember(name))
		{
			const auto& jsonList = data[name];
			if (jsonList.IsArray())
			{
				for (size_t i = 0; i < jsonList.Size(); i++)
				{
					const auto& in = jsonList[static_cast<int>(i)];
					if (in.IsNumber())
					{
						list.Add(in.GetDouble());
					}
				}
				return list;
			}
		}
		return list;*/
	}

	template <typename Container>
	void GetVector(Container& container, const char* name) const
	{
		ForEachArray(name,
					 [&](const auto& in)
					 {
						 if (in.IsUint())
						 {
							 container.Add(ion::SafeRangeCast<uint8_t>(in.GetUint()));
						 }
					 });

		/*if (data.HasMember(name))
		{
			const auto& jsonList = data[name];
			if (jsonList.IsArray())
			{
				for (size_t i = 0; i < jsonList.Size(); i++)
				{
					const auto& in = jsonList[static_cast<int>(i)];
					if (in.IsUint())
					{
						container.Add(ion::SafeRangeCast<uint8_t>(in.GetUint()));
					}
				}
			}
		}*/
	}

	ion::Vector<ion::String> GetStringVector(const char* name) const
	{
		ion::Vector<ion::String> list;
		ForEachArray(name,
					 [&](const auto& in)
					 {
						 if (in.IsString())
						 {
							 list.Add(in.GetString());
						 }
					 });
		return list;
		/*if (data.HasMember(name))
		{
			const auto& jsonList = data[name];
			if (jsonList.IsArray())
			{
				for (size_t i = 0; i < jsonList.Size(); i++)
				{
					const auto& in = jsonList[static_cast<int>(i)];
					if (in.IsString())
					{
						list.Add(in.GetString());
					}
				}
				return list;
			}
		}
		return list;*/
	}

	const ion::StringView GetString(const char* name) const
	{
		if (data.HasMember(name))
		{
			auto& str = data[name];
			if (str.IsString())
			{
				return ion::StringView(str.GetString(), str.GetStringLength());
			}
		}
		return ion::StringView();
	}

	template <typename U>
	U GetInt(const char* name) const
	{
		if (data.HasMember(name))
		{
			auto& out = data[name];
			if (out.IsInt64())
			{
				return static_cast<U>(out.GetInt64());
			}
		}
		return static_cast<U>(~0);
	}

	template <typename U>
	U GetUInt(const char* name) const
	{
		if (data.HasMember(name))
		{
			auto& out = data[name];
			if (out.IsUint64())
			{
				return static_cast<U>(out.GetUint64());
			}
		}
		return static_cast<U>(~0);
	}

	template <typename U>
	void GetInt(const char* name, U& value, U defaultValue = ~static_cast<U>(0)) const
	{
		if (data.HasMember(name))
		{
			auto& out = data[name];
			if (out.IsNumber())
			{
				value = static_cast<U>(out.GetInt64());
				return;
			}
		}
		value = defaultValue;
	}

	template <typename U>
	void GetUInt(const char* name, U& value, U defaultValue = ~static_cast<U>(0)) const
	{
		if (data.HasMember(name))
		{
			auto& out = data[name];
			if (out.IsNumber())
			{
				value = static_cast<U>(out.GetUint64());
				return;
			}
		}
		value = defaultValue;
	}

	void GetInt(const char* name, int64_t& value, int64_t defaultValue = ~static_cast<int64_t>(0)) const
	{
		if (data.HasMember(name))
		{
			auto& out = data[name];
			if (out.IsNumber())
			{
				value = static_cast<int64_t>(out.GetInt64());
				return;
			}
		}
		value = defaultValue;
	}

	const float GetFloat(const char* name, float defaultValue = 0.0f) const
	{
		if (data.IsObject() && data.HasMember(name))
		{
			auto& out = data[name];
			if (out.IsNumber())
			{
				return static_cast<float>(out.GetFloat());
			}
		}
		return defaultValue;
	}

	const double GetDouble(const char* name, double defaultValue = 0.0) const
	{
		if (data.IsObject() && data.HasMember(name))
		{
			auto& out = data[name];
			if (out.IsNumber())
			{
				return static_cast<double>(out.GetDouble());
			}
		}
		return defaultValue;
	}

	bool GetBool(const char* name, bool defaultValue = false) const
	{
		if (data.HasMember(name))
		{
			auto& out = data[name];
			if (out.IsBool())
			{
				return static_cast<bool>(out.GetBool());
			}
		}
		return defaultValue;
	}

	JSONStructReader Child(const char* name) const;

	JSONArrayReader Array(const char* name) const;

	bool IsObject() const { return data.IsObject(); }

	bool IsValid() const { return parent != nullptr; }

	void* mContext = nullptr;

protected:
	JSONStructReader(const JSONStructReader& aParent, const char* name);
	JSONStructReader(const JSONDocument& aDocument);
	const rapidjson::Value& data;
	const JSONElement* parent;
};

class JSONStructWriter : public JSONElement
{
public:
	JSONStructWriter(JSONStructWriter& aParent, const char* name = nullptr);
	JSONStructWriter(JSONArrayWriter& aParent, const char* name = nullptr);
	JSONStructWriter(JSONDocument& aParent, const char* name = nullptr);
	~JSONStructWriter();

	template <typename T>
	void AddMember(const char* name, const T& value)
	{
		rapidjson::GenericValue<rapidjson::UTF8<>> jsonName(name, static_cast<rapidjson::SizeType>(strlen(name)));
		data.AddMember(jsonName, value, document.mAllocator);
	}

	template <>
	void AddMember(const char* name, const ion::ArrayView<const char, uint32_t>& value)
	{
		rapidjson::GenericValue<rapidjson::UTF8<>> jsonName(name, static_cast<rapidjson::SizeType>(strlen(name)));

		rapidjson::GenericValue<rapidjson::UTF8<>> jsonValue(value.Data(), value.Size());
		data.AddMember(jsonName, jsonValue, document.mAllocator);
	}

	/*template<>
	void AddMember(const char* name, const ion::Vector<ion::String>& value)
	{
		rapidjson::GenericValue<rapidjson::UTF8<>> jsonName(name,
			static_cast<rapidjson::SizeType>(strlen(name)));

		rapidjson::Value list(rapidjson::kArrayType);
		ion::ForEach(value, [&](const ion::String& str)
			{
				rapidjson::GenericValue<rapidjson::UTF8<>> jsonStr(
					str.CStr(),
					static_cast<rapidjson::SizeType>(str.Length()));
				list.PushBack(jsonStr, document.mAllocator);
			});
		data.AddMember(jsonName, list, document.mAllocator);
	}
	*/

	// Note: Do not pass local strings to RapidJSON!
	void AddMember(const char* const name, const char* const string) { AddString(name, string, strlen(string)); }

	void AddMember(const char* const name, const ion::StringView& string) { AddString(name, string.CStr(), string.Length()); }

	template <>
	void AddMember(const char* name, const ion::String& string)
	{
		AddString(name, string.CStr(), string.Length());
	}

	const char* mName;
	rapidjson::Value data;
	JSONElement* parent;
	enum Parent
	{
		Array,
		Struct,
		Document
	};

	Parent mParentType;
	void* mContext = nullptr;

private:
	void AddString(const char* const name, const char* const buffer, size_t len)
	{
		rapidjson::GenericValue<rapidjson::UTF8<>> jsonName(name, static_cast<rapidjson::SizeType>(strlen(name)));

		rapidjson::Value jsonString;
		jsonString.SetString(buffer, ion::SafeRangeCast<rapidjson::SizeType>(len), document.mAllocator);
		data.AddMember(jsonName, jsonString, document.mAllocator);
	}
};

template <typename Callback>
void JSONArrayReader::ForEach(Callback&& callback) const
{
	ION_ASSERT(IsValid(), "Invalid data");
	for (rapidjson::SizeType i = 0, n = Size(); i < n; i++)
	{
		ion::JSONStructReader sub(*this, i);
		callback(sub);
	}
}

struct Rect
{
	ion::Vec2<uint16_t> mMin;
	ion::Vec2<uint16_t> mMax;
};

namespace serialization
{
template <typename T>
inline bool Serialize(const T& in, const char* name, ion::JSONStructWriter& out)
{
	if constexpr (std::is_enum<T>::value)
	{
		using EnumType = typename std::underlying_type<T>::type;
		static_assert(!std::is_enum<EnumType>::value, "Invalid enum");
		EnumType enumValue = static_cast<EnumType>(in);
		return Serialize(enumValue, name, out);
	}
	else
	{
		static_assert(std::is_integral<T>::value, "Integral required");
		out.AddMember(name, in);
		return true;
	}
}

template <typename T>
inline bool Deserialize(T& out, const char* name, ion::JSONStructReader& in)
{
	if constexpr (std::is_enum<T>::value)
	{
		using EnumType = typename std::underlying_type<T>::type;
		static_assert(!std::is_convertible<T, EnumType>::value, "Scoped enums allowed only");
		static_assert(!std::is_enum<EnumType>::value, "Invalid enum");
		EnumType enumValue;
		auto result = Deserialize(enumValue, name, in);
		out = static_cast<T>(enumValue);
		return result;
	}
	else
	{
		static_assert(std::is_integral<T>::value, "Integral required");
		if constexpr (std::is_unsigned<T>::value)
		{
			out = in.GetUInt<T>(name);
		}
		else
		{
			out = in.GetInt<T>(name);
		}
		return true;
	}
}

template <>
inline bool Serialize(const double& in, const char* name, ion::JSONStructWriter& out)
{
	out.AddMember(name, in);
	return true;
}

template <>
inline bool Deserialize(double& out, const char* name, ion::JSONStructReader& in)
{
	out = in.GetDouble(name);
	return true;
}

template <>
inline bool Serialize(const float& in, const char* name, ion::JSONStructWriter& out)
{
	out.AddMember(name, in);
	return true;
}

template <>
inline bool Deserialize(float& out, const char* name, ion::JSONStructReader& in)
{
	out = in.GetFloat(name);
	return true;
}

template <>
inline bool Serialize(const ion::String& in, const char* name, ion::JSONStructWriter& out)
{
	out.AddMember(name, in);
	return true;
}

template <>
inline bool Deserialize(ion::String& out, const char* name, ion::JSONStructReader& in)
{
	out = in.GetString(name);
	return true;
}

template <>
inline bool Serialize(const ion::Vec2f& in, const char* name, ion::JSONStructWriter& out)
{
	ion::JSONStructWriter pivot(out, name);
	pivot.AddMember("x", in.x());
	pivot.AddMember("y", in.y());
	return true;
}

template <>
inline bool Deserialize(ion::Vec2f& out, const char* name, ion::JSONStructReader& in)
{
	ion::JSONStructReader group(in.Child(name));
	out = {group.GetFloat("x"), group.GetFloat("y")};
	return true;
}

inline void ReadRect(Rect& out, ion::JSONStructReader& in)
{
	out.mMin = {in.GetInt<uint16_t>("x"), in.GetInt<uint16_t>("y")};
	ion::Vec2<uint16_t> size = {in.GetInt<uint16_t>("w"), in.GetInt<uint16_t>("h")};
	out.mMax = out.mMin + size;
}

inline void ReadSize(ion::Vec2<uint16_t>& out, ion::JSONStructReader& in) { out = {in.GetInt<uint16_t>("w"), in.GetInt<uint16_t>("h")}; }

inline void ReadSize(ion::Vec2f& out, ion::JSONStructReader& in) { out = {in.GetFloat("w"), in.GetFloat("h")}; }

template <typename IdType, typename StoreType>
inline void SerializeFinal(const IdType, const StoreType&, ion::JSONStructWriter&)
{
}

template <typename IdType, typename StoreType>
inline void DeserializeFinal(const IdType, StoreType&, ion::JSONStructReader&)
{
}
}  // namespace serialization
}  // namespace ion

#endif
