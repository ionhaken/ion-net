/*
 * Copyright 2015-2022 Markus Haikonen, Ionhaken
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
#include <codegen/stdafx.h>
#include <codegen/SerializationWriter.h>
#include <codegen/CodegenContext.h>

namespace ion::codegen
{
namespace priv
{
template <typename Callback>
void IterateFields(CodegenContext& c, Callback&& callback)
{
	auto order = c.mSettings.GetParamOrder();
	for (size_t i = 0; i < c.mSettings.mData.Size(); i++)
	{
		const ion::codegen::Data& data = c.mSettings.mData[order[i]];

		// 1) Change first letter of ID to lowercase.
		// 2) If whole string is uppercase, change everything to lowercae
		ion::String name = data.GetName();
		size_t upperCaseCount = 0;
		for (size_t j = 0; j < name.Length(); ++j)
		{
			if (std::tolower(name.CStr()[j]) != name.CStr()[j])
			{
				upperCaseCount++;
			}
		}
		if (upperCaseCount == name.Length())
		{
			for (size_t j = 0; j < name.Length(); ++j)
			{
				name.Replace(j, char(std::tolower(name.CStr()[j])));
			}
		}
		else
		{
			name.Replace(0, char(std::tolower(name.CStr()[0])));
		}

		callback(name, data);
	}
}
}  // namespace priv

const bool IsMovingInternally = true;

SerializationWriter::SerializationWriter(CodegenFile& aFile) : SourceCodeWriter(aFile) {}

void SerializationWriter::Generate(CodegenContext& c)
{
	AutoGenHeader();
	WriteLn("#pragma once");

	WriteNamespaceBegin(c.mNamespaceName);
	WriteNamespaceBegin("serialization");

	if (!c.mWriterName.IsEmpty())
	{
		for (uint16_t index = 0; index < c.mSettings.mComponents.Size(); index++)
		{
			WriteLn("bool Serialize(const ion::Vector<%sId>& ids, const %s& store, %s& data)",
					c.mSettings.mComponents[index].mName.CStr(), c.mSettings.mSystemName.CStr(), c.mWriterName.CStr());
			WriteLn("{");
			AddIndent();
			WriteLn("bool isOk = true;");
			WriteLn("ion::ForEach(ids, [&](const auto& id)");
			WriteLn("{");
			AddIndent();
			WriteLn("%s arrElem(data);", c.mRowWriterName.CStr());
			WriteLn("arrElem.mContext = data.mContext;");
			WriteLn("Const%sComponent c(id, store);", c.mSettings.mComponents[index].mName.CStr());
			priv::IterateFields(c,
								[&](const ion::String& name, const ion::codegen::Data& data)
								{
									if (!data.IsTransient())
									{
										WriteLn("isOk &= serialization::Serialize<%s>(c.Get%s(), \"%s\", arrElem);",
												data.GetType(0).CStr(),
												// data.HasNonConstGetter() ? "" : "Get",
												data.GetName().CStr(), name.CStr());
									}
								});
			WriteLn("serialization::SerializeFinal(id, store, arrElem);");
			RemoveIndent();
			WriteLn("});");
			WriteLn("return isOk;");
			RemoveIndent();
			WriteLn("}");
		}

		WriteLn("");
	}

	if (!c.mReaderName.IsEmpty())
	{
		for (uint16_t index = 0; index < c.mSettings.mComponents.Size(); index++)
		{
			WriteLn("bool Deserialize(ion::Vector<%sId>& ids, %s& store, const %s& data)",
					c.mSettings.mComponents[index].mName.CStr(), c.mSettings.mSystemName.CStr(), c.mReaderName.CStr());
			WriteLn("{");
			AddIndent();
			WriteLn("if (!data.IsValid())");
			WriteLn("{");
			AddIndent();
			WriteLn("return false;");
			RemoveIndent();
			WriteLn("}");
			WriteLn("bool isOk = true;");
			WriteLn("ids.AddMultiple(data.Size(), [&](size_t index)");
			// WriteLn("data.ForEach([&](const ion::ReadableStruct& arrElem)");
			WriteLn("{");
			AddIndent();
			WriteLn("%s arrElem(data, index);", c.mRowReaderName.CStr());
			WriteLn("arrElem.mContext = data.mContext;");

			priv::IterateFields(c,
								[&](const ion::String& name, const ion::codegen::Data& data)
								{
									WriteLn("%s a%s%s;", data.GetType(0).CStr(), data.GetName().CStr(), data.IsTransient() ? "{}" : "");
									if (!data.IsTransient())
									{
										WriteLn("isOk &= serialization::Deserialize<%s>(a%s, \"%s\", arrElem);",
												data.GetType(0).CStr(), data.GetName().CStr(), name.CStr());
									}
								});
			auto buffer = c.mSettings.GetCreateParams(CreateMethodSignature::Public, CreateMethodType::Construct, true);
			WriteLn("auto id = store.Create(%s);", buffer.CStr());
			WriteLn("serialization::DeserializeFinal(id, store, arrElem);");
			WriteLn("return id;");
			RemoveIndent();
			WriteLn("});");

			WriteLn("return isOk;");
			RemoveIndent();
			WriteLn("}");
			WriteLn("");
		}
	}

	WriteNamespaceEnd();
	WriteNamespaceEnd();
}
}  // namespace ion::codegen
