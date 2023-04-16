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
#pragma once

#include <codegen/CodegenFile.h>

namespace ion::codegen
{

enum class CreateMethodSignature : size_t
{
	Public,
	Private,
	Call
};

enum class CreateMethodType : size_t
{
	Construct,
	Assign,
	Move
};

struct CodegenContext;

enum class FunctionSignature : uint8_t
{
	Declaration,
	Definition,
	ConstExpr,
	Inline
};

class SourceCodeWriter
{
public:
	static const uint8_t TabSize = 4;
	static const uint8_t IndentSize = 4;
	static const uint8_t MaxIndent = 80;

	SourceCodeWriter(CodegenFile& aFile);
	void WriteNamespaceBegin(const ion::String& name);
	void WriteNamespaceEnd();

	~SourceCodeWriter() {}

protected:
	void AutoGenHeader();
	void WriteLn(const char* format, ...);
	void AddIndent()
	{
		mIndent += IndentSize;
		ION_ASSERT(mIndent <= MaxIndent, "Invalid indent");
	}

	void RemoveIndent()
	{
		ION_ASSERT(mIndent >= IndentSize, "Invalid indent");
		mIndent -= IndentSize;
	}

	void WriteFunctionSignature(CodegenContext& context, FunctionSignature sig, const char* returnValue, const char* method,
								const char* pars);

private:
	const char* SignatureStr(FunctionSignature sig);

	CodegenFile& mFile;
	uint16_t mNameSpaceDepth = 0;
	uint8_t mIndent = 0;
};

}  // namespace ion::codegen
