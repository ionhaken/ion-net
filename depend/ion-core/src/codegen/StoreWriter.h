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

#include <codegen/SourceCodeWriter.h>

namespace ion::codegen
{
struct StoreSettings;
struct Data;
struct CodegenContext;
class StoreWriter : public SourceCodeWriter
{
public:
	StoreWriter(CodegenFile& aFile);

	void Generate(CodegenContext& c);

private:
	void GenerateCreateMethods(StoreSettings& settings, const ion::Vector<uint16_t>& groups, CreateMethodSignature signature,
							   CreateMethodType type = CreateMethodType::Construct);
	void GenerateHeader(CodegenContext& context);
	void GeneratePublicMethods(StoreSettings& settings, const ion::Vector<uint16_t>& groups);
	void GenerateReverseMap(const Data& data, const char* indexName, bool isRemapped);
	void GeneratePrivateMethods(CodegenContext& c, const ion::Vector<uint16_t>& groups);
	void GenerateData(StoreSettings& settings, const ion::Vector<uint16_t>& groups);
	void GenerateFooter(CodegenContext& c);
	void GenerateResize(CodegenContext& c, const ion::Vector<uint16_t>& groups);
	void GenerateGetId(StoreSettings& settings);
	void GenerateConstructor(const CodegenContext& c);

	void WriteTemporaryAllocator(const StoreSettings& settings);

	enum class BufferHandling : uint8_t
	{
		BufferSize,
		Resize,
		CopyToOldBuffer,
		CopyToNewBuffer
	};
	void WriteBufferHandling(StoreSettings& settings, const ion::Vector<uint16_t>& groups, BufferHandling mode);

	void WriteBufferItemCount(StoreSettings& settings, const ion::Vector<uint16_t>& groups, bool isCopy);
	void WriteCreateMethod(StoreSettings& settings, CreateMethodSignature signature, CreateMethodType type, const char* idName);
	void WriteReverseMap(StoreSettings& settings);
	void WriteInitVars(StoreSettings& settings, const ion::Vector<uint16_t>& groups, CreateMethodType type);
	void WriteDynamicInitVars(StoreSettings& settings, bool hasReferencedReverseMaps);

	bool HasInitVars(StoreSettings& settings) const;
	ion::String ParentClass(const StoreSettings& settings) const;
	void WriteInitializer(const ion::String& parentClass, const StoreSettings& settings, bool isCopy);
};
}  // namespace ion::codegen
