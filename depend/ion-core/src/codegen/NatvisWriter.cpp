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
#include <codegen/NatvisWriter.h>
#include <codegen/CodegenContext.h>

namespace ion::codegen
{
NatvisWriter::NatvisWriter(CodegenFile& file) : SourceCodeWriter(file) {}
void NatvisWriter::Generate(CodegenContext& context)
{
	for (uint16_t index = 0; index < context.mSettings.mComponents.Size(); index++)
	{
		GenerateType(index, context, false);
		GenerateType(index, context, true);
	}
}

void NatvisWriter::GenerateHeader()
{
	WriteLn("<?xml version = \"1.0\" encoding = \"utf-8\" ?>");
	WriteLn("<AutoVisualizer xmlns = \"http://schemas.microsoft.com/vstudio/debugger/natvis/2010\">");
	AddIndent();
}

void NatvisWriter::GenerateFooter()
{
	RemoveIndent();
	WriteLn("</AutoVisualizer>");
}

void NatvisWriter::GenerateType(uint16_t entityIndex, CodegenContext& context, bool isReadOnly)
{
	ion::String componentName =
	  isReadOnly ? context.mSettings.mComponents[entityIndex].GetConstName() : context.mSettings.mComponents[entityIndex].GetName();

	WriteLn("<Type Name = \"%s::%s\">", context.mNamespaceName.CStr(), componentName.CStr());
	AddIndent();
	WriteLn("<DisplayString>{{ index={mIndex} }}</DisplayString>");
	WriteLn("<Expand>");
	AddIndent();

	auto& settings = context.mSettings;

	for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
	{
		/*if (iter->mMaxSize > 1)
		{
		}*/
		WriteLn("<Item Name=\"[%s]\">%s</Item>", iter->GetName().CStr(), iter->GetPathToData(nullptr, true).CStr());
	}

	RemoveIndent();
	WriteLn("</Expand>");
	RemoveIndent();
	WriteLn("</Type>");
}

}  // namespace ion::codegen
