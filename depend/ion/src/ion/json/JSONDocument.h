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
#include <ion/hw/CPU.h>
#include <ion/tracing/Log.h>

#if ION_EXTERNAL_JSON
	#include <ion/memory/Memory.h>

	#define RAPIDJSON_ASSERT(__expr)		  ION_ASSERT(__expr, "RapidJSON");
	#define RAPIDJSON_NOEXCEPT_ASSERT(__expr) ION_ASSERT(__expr, "RapidJSON");
	//#define RAPIDJSON_LIKELY(__cond) ION_LIKELY(__cond )
	//#define RAPIDJSON_UNLIKELY(__cond) ION_UNLIKELY(__cond )
	#if ION_CPU_SSE2_ASSUMED == 1
		#define RAPIDJSON_SIMD
		#define RAPIDJSON_SSE2
	#elif ION_CPU_NEON_ASSUMED == 1
		#define RAPIDJSON_SIMD
		#define RAPIDJSON_NEON
	#endif
	//#define RAPIDJSON_MALLOC(size) ion::Malloc(size)
	//#define RAPIDJSON_REALLOC(ptr, new_size) ion::Realloc(ptr, new_size)
	//#define RAPIDJSON_FREE(p) ion::Free(p)

ION_PRAGMA_WRN_PUSH
ION_PRAGMA_WRN_IGNORE_UNREACHABLE_CODE
	#include <rapidjson/document.h>
	#include <rapidjson/reader.h>
ION_PRAGMA_WRN_POP

namespace ion
{
class Folder;
class JSONDocument;
class ByteBufferBase;

class JSONElement
{
public:
	JSONElement(JSONDocument& aDocument);
	JSONDocument& document;
};

class JSONDocument : public JSONElement
{
public:
	friend class JSONArrayWriter;
	friend class JSONStructWriter;
	friend class JSONStructReader;
	friend class JSONArrayReader;
	friend class JSONSerializer;

	JSONDocument();

	void Save(const ion::Folder& folder, const char* target);

	void Save(const char* target);

	void Save(ByteBufferBase& target);

	void Load(const ion::Folder& folder, const char* target);

	void Load(const char* target);

	void Parse(const char* target, const ion::String& data);

	void Set(const char* name, const char* string)
	{
		rapidjson::GenericValue<rapidjson::UTF8<>> jsonName(name, static_cast<rapidjson::SizeType>(strlen(name)));
		rapidjson::GenericValue<rapidjson::UTF8<>> jsonString(string, static_cast<rapidjson::SizeType>(strlen(string)));
		mDocument.AddMember(jsonName, jsonString, mAllocator);
	}

	bool HasLoaded() const { return mHasLoaded; }

	template <typename Callback>
	void ForEachMember(Callback&& callback) const
	{
		for (auto iter = mDocument.MemberBegin(); iter != mDocument.MemberEnd(); ++iter)
		{
			callback(iter->name, iter->value);
		}
	}

protected:
	template <typename T>
	const rapidjson::GenericValue<rapidjson::UTF8<>>* GetList(const T& obj, const char* name) const
	{
		if (obj.HasMember(name))
		{
			const auto& list = obj[name];
			if (list.IsArray())
			{
				return &list;
			}
		}
		return nullptr;
	}

	char mBuffer[1024];
	rapidjson::MemoryPoolAllocator<> mAllocator;
	rapidjson::Document mDocument;
	bool mHasLoaded = false;
};
}  // namespace ion
#endif
