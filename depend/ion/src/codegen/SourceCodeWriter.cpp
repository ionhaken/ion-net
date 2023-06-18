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
#include <codegen/SourceCodeWriter.h>
#include <codegen/CodegenContext.h>

ion::codegen::SourceCodeWriter::SourceCodeWriter(CodegenFile& aFile) : mFile(aFile) {}

void ion::codegen::SourceCodeWriter::WriteLn(const char* format, ...)
{
	const size_t maxLen = 1024;
	char buffer[maxLen];
	size_t pos = 0;
	auto indent = ion::Min(MaxIndent, mIndent);
	for (size_t i = 0; i < indent;)
	{
		if (indent - i >= TabSize)
		{
			buffer[pos] = '\t';
			i += TabSize;
		}
		else
		{
			buffer[pos] = ' ';
			i++;
		}
		pos++;
	}

	va_list arglist;
	va_start(arglist, format);
	vsprintf_s(&buffer[pos], maxLen - pos, format, arglist);
	va_end(arglist);
	mFile.Write(buffer);
	mFile.Write('\n');
}

const char* ion::codegen::SourceCodeWriter::SignatureStr(FunctionSignature sig)
{
	switch (sig)
	{
	case FunctionSignature::Inline:
		return "inline ";
	case FunctionSignature::ConstExpr:
		return "constexpr ";
	default:
		return "";
	}
}

void ion::codegen::SourceCodeWriter::WriteFunctionSignature(CodegenContext& context, FunctionSignature sig, const char* returnValue,
															const char* method, const char* pars)
{
	ion::StackString<1024> back;
	back->Format("%s%s%s(%s)%s", context.mIsHeader ? "" : context.mSettings.mSystemName.CStr(), context.mIsHeader ? "" : "::", method, pars,
				 sig == FunctionSignature::Declaration ? ";" : "");

	if (strcmp(returnValue, "") != 0)
	{
		ion::StackString<1024> front;
		front->Format("%s%s", context.mIsHeader ? SignatureStr(sig) : "", returnValue);
		WriteLn("%s %s", front.CStr(), back.CStr());
	}
	else
	{
		WriteLn("%s", back.CStr());
	}
}

void ion::codegen::SourceCodeWriter::WriteNamespaceBegin(const ion::String& name)
{
	if (!name.IsEmpty())
	{
		mNameSpaceDepth++;
		WriteLn("namespace %s", name.CStr());
		WriteLn("{");
		AddIndent();
	}
}

void ion::codegen::SourceCodeWriter::WriteNamespaceEnd()
{
	if (mNameSpaceDepth)
	{
		mNameSpaceDepth--;
		RemoveIndent();
		WriteLn("}");
	}
}

void ion::codegen::SourceCodeWriter::AutoGenHeader()
{
	WriteLn("/*");
	WriteLn(" * Auto-generated using Ionhaken Core Libray Codegen.");
	WriteLn(" */");
}
