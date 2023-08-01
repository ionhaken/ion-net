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
#include <codegen/ComponentWriter.h>
#include <codegen/CodegenContext.h>

static const bool IsTrackingCache = true;

ion::codegen::ComponentWriter::ComponentWriter(SourceCodeWriter& other) : SourceCodeWriter(other) {}

void ion::codegen::ComponentWriter::Generate(CodegenContext& context)
{
	for (uint16_t index = 0; index < context.mSettings.mComponents.Size(); index++)
	{
		auto& settings = context.mSettings;
		GenerateHeader(index, context);
		GenerateEntity(index, settings, true);
		WriteLn("");
		GenerateEntity(index, settings, false);
		GenerateFooter();
	}
}

void ion::codegen::ComponentWriter::GenerateHeader(uint16_t /*entityIndex*/, CodegenContext& /*context*/) {}

void ion::codegen::ComponentWriter::GenerateEntity(uint16_t entityIndex, StoreSettings& settings, bool isReadOnly)
{
	ion::String componentName = isReadOnly ? settings.mComponents[entityIndex].GetConstName() : settings.mComponents[entityIndex].GetName();

	WriteLn("class %s : public ion::ComponentStoreView<%s%s>", componentName.CStr(), isReadOnly ? "const " : "",
			settings.mSystemName.CStr());
	WriteLn("{");
	AddIndent();
	WriteLn("ION_CLASS_NON_COPYABLE_NOR_MOVABLE(%s);", componentName.CStr());

	WriteLn("");
	RemoveIndent();
	WriteLn("public:");
	AddIndent();

	if (settings.IsRemapped())
	{
		WriteLn("constexpr %s(const size_t index, %s%s& aStore) : ion::ComponentStoreView<%s%s>(aStore, static_cast<%s>(index)) {}",
				componentName.CStr(), isReadOnly ? "const " : "", settings.mSystemName.CStr(), isReadOnly ? "const " : "",
				settings.mSystemName.CStr(), settings.GetIndexType());
	}

	WriteLn("#if !ION_COMPONENT_VERSION_NUMBER");
	WriteLn("constexpr");
	WriteLn("#endif");

	WriteLn("%s(const %sId& anId, %s%s& aStore) : ion::ComponentStoreView<%s%s>(aStore, %s)", componentName.CStr(),
			settings.mComponents[entityIndex].mName.CStr(), isReadOnly ? "const " : "", settings.mSystemName.CStr(),
			isReadOnly ? "const " : "", settings.mSystemName.CStr(), settings.IsRemapped() ? "aStore.Remap(anId)" : "anId.GetIndex()");

	WriteLn("{");
	AddIndent();
	WriteLn("#if ION_COMPONENT_VERSION_NUMBER");
	WriteLn("ION_CHECK(anId.GetVersion() == aStore.GetVersion(anId.GetIndex()),");
	AddIndent();
	WriteLn("\"Invalid version \" << anId.GetVersion() << \";expected:\" << aStore.GetVersion(anId.GetIndex()));");
	RemoveIndent();
	WriteLn("#endif");
	RemoveIndent();
	WriteLn("}");
	WriteLn("");

	size_t callIndex = 0;
	for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
	{
		if (iter->mMaxSize > 1)
		{
			WriteLn("[[nodiscard]] inline %s Get%s() const { %sreturn %s; }", iter->GetTypeParam(settings.mIndexMax, true).CStr(),
					iter->GetName().CStr(), settings.HasCacheTracking() ? iter->GetTrackingCall(callIndex).CStr() : "",
					iter->GetPathToData().CStr());
			callIndex += 2;
		}
		else
		{
			for (size_t i = 0; i < 2; i++)
			{
				bool isGetterSetter = !isReadOnly && iter->HasNonConstGetter() && iter->GetReverseMapping() == ReverseMapping::None;
				if (i == 0 || isGetterSetter)
				{
					WriteLn("[[nodiscard]] constexpr %s %s%s() %s{ %sreturn %s; }",
							iter->GetTypeParam(settings.mIndexMax, i == 0, true).CStr(), isGetterSetter ? "" : "Get",
							iter->GetName().CStr(), i == 0 ? "const " : "",
							settings.HasCacheTracking() ? iter->GetTrackingCall(callIndex, isGetterSetter).CStr() : "",
							iter->GetPathToData().CStr());
				}
			}
			if (!isReadOnly)
			{
				if (iter->HasSetter() && iter->GetReverseMapping() == ReverseMapping::None)
				{
					WriteLn("inline void Set%s(%s in) { %s%s = in; }", iter->GetName().CStr(),
							iter->GetTypeParam(settings.mIndexMax).CStr(),
							settings.HasCacheTracking() ? iter->GetTrackingCall(callIndex, true).CStr() : "", iter->GetPathToData().CStr());
				}
			}
			callIndex++;
		}
	}

	RemoveIndent();
	WriteLn("};");

	if (settings.IsRemapped())
	{
		WriteLn("inline %s %s::Get%s(size_t idx) %s{ return %s(idx, *this); }", componentName.CStr(), settings.mSystemName.CStr(),
				isReadOnly ? "Const" : "", isReadOnly ? "const " : "", componentName.CStr());
	}
	WriteLn("inline %s %s::Get%s(const %sId& id) %s{ return %s(id, *this); }", componentName.CStr(), settings.mSystemName.CStr(),
			isReadOnly ? "Const" : "", settings.mComponents[entityIndex].mName.CStr(), isReadOnly ? "const " : "", componentName.CStr());

	WriteLn("");
}

void ion::codegen::ComponentWriter::GenerateFooter() {}
