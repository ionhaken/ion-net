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
#include <codegen/ModelWriter.h>
#include "StoreSettings.h"

ion::codegen::ModelWriter::ModelWriter(CodegenFile& aFile) : SourceCodeWriter(aFile) {}

void ion::codegen::ModelWriter::GenerateHeader()
{
	AutoGenHeader();
	WriteLn("#pragma once");
	WriteLn("#include <ion/database/DBComponentStore.h>");
	WriteLn("#include <ion/util/Hasher.h>");
}

void ion::codegen::ModelWriter::GenerateFooter() {}

void ion::codegen::ModelWriter::Generate(CodegenContext& context)
{
	StoreSettings& settings = context.mSettings;
	WriteNamespaceBegin(context.mNamespaceName);
	for (uint16_t index = 0; index < settings.mComponents.Size(); index++)
	{
		GenerateComponentId(index, context);
	}
	WriteNamespaceEnd();

	WriteLn("namespace ion");
	WriteLn("{");
	AddIndent();
	for (uint16_t index = 0; index < settings.mComponents.Size(); index++)
	{
		GenerateHasher(index, context);
	}
	RemoveIndent();
	WriteLn("}");
}

void ion::codegen::ModelWriter::GenerateComponentId(u16 entityIndex, CodegenContext& context)
{
	auto& settings = context.mSettings;
	WriteLn("class %sId : public ion::ComponentId<%s>", settings.mComponents[entityIndex].mName.CStr(), settings.GetIndexType());
	WriteLn("{");
	WriteLn("public:");
	AddIndent();

	WriteLn("friend class %s;", settings.mSystemName.CStr());
	WriteLn("friend class ion::ComponentStore<%s>;", settings.GetIndexType());

	// Default invalid id constructor
	WriteLn("constexpr %sId() : ion::ComponentId<%s>() {}", settings.mComponents[entityIndex].mName.CStr(), settings.GetIndexType());

	// Copy constructor
	/*WriteLn("%sId(const %sId& copy)",
		settings.mComponents[entityIndex].mName.CStr(),
		settings.mComponents[entityIndex].mName.CStr());
	WriteLn("#if ION_COMPONENT_VERSION_NUMBER");
	WriteLn(": ion::ComponentId<%s>(copy.GetIndex(), copy.GetVersion()) {}", settings.GetIndexType());
	WriteLn("#else");
	WriteLn(": ion::ComponentId<%s>(copy.GetIndex()) {}", settings.GetIndexType());
	WriteLn("#endif");*/

	RemoveIndent();
	WriteLn("private:");
	AddIndent();

	// Default constructor
	WriteLn("#if ION_COMPONENT_VERSION_NUMBER");
	WriteLn("constexpr %sId(const %s index, const %s version) : ion::ComponentId<%s>(index, version) {}",
			settings.mComponents[entityIndex].mName.CStr(), settings.GetIndexType(), settings.GetIndexType(), settings.GetIndexType());
	WriteLn("#else");
	WriteLn("constexpr %sId(const %s index) : ion::ComponentId<%s>(index) {}", settings.mComponents[entityIndex].mName.CStr(),
			settings.GetIndexType(), settings.GetIndexType());
	WriteLn("#endif");

	RemoveIndent();

	WriteLn("};");
	WriteLn("");
}

void ion::codegen::ModelWriter::GenerateHasher(u16 entityIndex, CodegenContext& context)
{
	StoreSettings& settings = context.mSettings;
	WriteLn("template<>");
	WriteLn("inline size_t Hasher<%s::%sId>::operator() (const %s::%sId& key) const", context.mNamespaceName.CStr(),
			settings.mComponents[entityIndex].mName.CStr(), context.mNamespaceName.CStr(), settings.mComponents[entityIndex].mName.CStr());
	WriteLn("{");
	AddIndent();
	WriteLn("return Hasher<%s>()(key.GetIndex());", settings.GetIndexType());
	RemoveIndent();
	WriteLn("}");
}
