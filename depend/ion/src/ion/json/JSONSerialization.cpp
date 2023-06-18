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
#include <ion/json/JSONSerialization.h>
#if ION_EXTERNAL_JSON
static rapidjson::Value EmptyValue;

ion::JSONArrayWriter::JSONArrayWriter(JSONStructWriter& aParent, const char* name)
  : JSONElement(aParent.document), mName(name), data(rapidjson::kArrayType), parent(&aParent)
{
	data.SetArray();
	mContext = aParent.mContext;
}

ion::JSONArrayWriter::JSONArrayWriter(JSONDocument& aDocument, const char* name)
  : JSONElement(aDocument),
	mName(name),

	data(rapidjson::kArrayType),
	parent(nullptr)
{
	data.SetArray();
	mContext = aDocument.mContext;
}

ion::JSONArrayReader::JSONArrayReader(const JSONStructReader& source, const char* name)
  : JSONElement(source.document), data(source.data.HasMember(name) ? source.data[name] : source.data), parent(&source)
{
	mContext = source.mContext;
}

ion::JSONArrayReader::JSONArrayReader(const JSONDocument& document, const char* name)
  : JSONElement(document), data(document.mDocument.HasMember(name) ? document.mDocument[name] : EmptyValue), parent(&document)
{
	mContext = document.mContext;
}
ion::JSONArrayReader ::~JSONArrayReader() {}

ion::JSONArrayWriter::~JSONArrayWriter()
{
	if (parent != nullptr)
	{
		if (mName == nullptr)
		{
			reinterpret_cast<JSONArrayWriter*>(parent)->data.PushBack(data, document.mAllocator);
		}
		else
		{
			reinterpret_cast<JSONStructWriter*>(parent)->data.AddMember(
			  rapidjson::GenericValue<rapidjson::UTF8<>>(mName, static_cast<rapidjson::SizeType>(strlen(mName))), data,
			  document.mAllocator);
		}
	}
	else
	{
		document.mDocument.AddMember(rapidjson::GenericValue<rapidjson::UTF8<>>(mName, static_cast<rapidjson::SizeType>(strlen(mName))),
									 data, document.mAllocator);
	}
}

ion::JSONStructWriter::JSONStructWriter(JSONStructWriter& aParent, const char* name)
  : JSONElement(aParent.document), mName(name), parent(&aParent), mParentType(Parent::Struct)
{
	data.SetObject();
	mContext = aParent.mContext;
}

ion::JSONStructWriter::JSONStructWriter(JSONArrayWriter& aParent, const char* name)
  : JSONElement(aParent.document), mName(name), parent(&aParent), mParentType(Parent::Array)
{
	data.SetObject();
	mContext = aParent.mContext;
}

ion::JSONStructWriter::JSONStructWriter(JSONDocument& aParent, const char* name)
  : JSONElement(aParent), mName(name), parent(&aParent), mParentType(Parent::Document)
{
	data.SetObject();
	mContext = aParent.mContext;
}

ion::JSONStructWriter::~JSONStructWriter()
{
	switch (mParentType)
	{
	case Array:
		reinterpret_cast<JSONArrayWriter*>(parent)->data.PushBack(data, document.mAllocator);
		break;
	case Struct:
		reinterpret_cast<JSONStructWriter*>(parent)->data.AddMember(
		  rapidjson::GenericValue<rapidjson::UTF8<>>(mName, static_cast<rapidjson::SizeType>(strlen(mName))), data, document.mAllocator);
		break;
	case Document:
		document.mDocument.AddMember(rapidjson::GenericValue<rapidjson::UTF8<>>(mName, static_cast<rapidjson::SizeType>(strlen(mName))),
									 data, document.mAllocator);
		break;
	}
}

ion::JSONStructReader::JSONStructReader(const JSONStructReader& aParent, const char* name)
  : JSONElement(aParent.document), data(aParent.data.HasMember(name) ? aParent.data[name] : aParent.data), parent(&aParent)
{
	ION_ASSERT(aParent.data.HasMember(name), "Invalid data");
	mContext = aParent.mContext;
}

ion::JSONStructReader::JSONStructReader(const JSONArrayReader& aParent, size_t index)
  : JSONElement(aParent.document),
	data(index < aParent.Size() ? aParent.data[static_cast<rapidjson::SizeType>(index)] : aParent.data),
	parent(&aParent)
{
	ION_ASSERT(index < aParent.Size(), "Out of bounds");
	mContext = aParent.mContext;
}

ion::JSONStructReader::JSONStructReader(const JSONDocument& aDocument, const char* name)
  : JSONElement(aDocument), data(aDocument.mDocument.HasMember(name) ? aDocument.mDocument[name] : EmptyValue), parent(&aDocument)
{
	mContext = aDocument.mContext;
}

ion::JSONStructReader ion::JSONStructReader::Child(const char* name) const
{
	if (data.HasMember(name))
	{
		return ion::JSONStructReader(*this, name);
	}
	return ion::JSONStructReader(document);
}

ion::JSONArrayReader ion::JSONStructReader::Array(const char* name) const
{
	if (data.HasMember(name))
	{
		return ion::JSONArrayReader(*this, name);
	}
	return ion::JSONArrayReader(document, name);
}

ion::JSONStructReader::JSONStructReader(const JSONDocument& aDocument) : JSONElement(aDocument), data(EmptyValue), parent(nullptr) {}

#endif
