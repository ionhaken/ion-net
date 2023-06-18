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
#include <codegen/StoreWriter.h>
#include <codegen/ModelWriter.h>
#include <codegen/NatvisWriter.h>
#include <codegen/SerializationWriter.h>
#include <codegen/Reader.h>

#include <ion/filesystem/Folder.h>
#include <ion/core/Engine.h>

int main(int argc, char* argv[])
{
	int ret = -1;
	ion::Engine e;
	if (argc > 2)
	{
		ion::codegen::Reader reader;
		ION_LOG_INFO("Reading " << argv[1]);
		reader.Load(argv[1]);
		if (reader.HasLoaded())
		{
			ion::String target = argv[2];
			ION_LOG_INFO("Writing " << reader.GetNumComponents() << " components to " << target);

			ion::StackString<1024> modelHeaderFileName;
			
			modelHeaderFileName->Format("%s/ComponentModel.generated.h", target.CStr());

			CodegenFile modelFile(modelHeaderFileName.CStr());
			ion::codegen::ModelWriter modelTemplate(modelFile);

			modelTemplate.GenerateHeader();

			ion::StackString<1024> natvisFileName;
			natvisFileName->Format("%s/ComponentModel.generated.natvis", target.CStr());

			CodegenFile natvisFile(natvisFileName.CStr());
			ion::codegen::NatvisWriter natvisWriter(natvisFile);
			natvisWriter.GenerateHeader();

			for (uint16_t i = 0; i < reader.GetNumComponents(); i++)
			{
				ion::codegen::CodegenContext context;
				context.mTargetPath = argv[2];
				context.mNamespaceName = reader.Namespace(i);
				context.mPrecompiledHeader = reader.PrecompiledHeader();
				context.mStoreHeaderIncludes = reader.StoreHeaderIncludes("header_includes", i);
				context.mStoreSrcHeaderIncludes = reader.StoreHeaderIncludes("header_includes_src", i);
				context.mReaderName = reader.ReaderName();
				context.mWriterName = reader.WriterName();
				context.mRowReaderName = reader.RowReaderName();
				context.mRowWriterName = reader.RowWriterName();
				reader.GetSystem(i, context.mSettings);
				context.BuildGroups();
				context.mStoreHeaderName->Format("%s/%s.generated.h", argv[2], context.mSettings.mSystemName.CStr());

				if (!context.mInlining.IsEverythingInlined())
				{
					ion::StackString<1024> storeSourceFileName;
					storeSourceFileName->Format("%s/%s.generated.cpp", argv[2], context.mSettings.mSystemName.CStr());

					CodegenFile sourceFile(storeSourceFileName.CStr());
					ion::codegen::StoreWriter storeSourceWriter(sourceFile);
					storeSourceWriter.Generate(context);
					storeSourceWriter.WriteNamespaceEnd();
				}

				context.mIsHeader = true;
				if (!context.mReaderName.IsEmpty() || !context.mWriterName.IsEmpty())
				{
					ion::StackString<1024> serializationHeaderName;
					serializationHeaderName->Format("%s/%s.serialization.generated.h", argv[2], context.mSettings.mSystemName.CStr());
					CodegenFile serializationHeader(serializationHeaderName.CStr());
					{
						ion::codegen::SerializationWriter serializationWriter(serializationHeader);
						serializationWriter.Generate(context);
					}
				}
				CodegenFile headerFile(context.mStoreHeaderName.CStr());
				ion::codegen::StoreWriter storeWriter(headerFile);
				storeWriter.Generate(context);

				modelTemplate.Generate(context);

				natvisWriter.Generate(context);

				{
					ion::codegen::ComponentWriter out(storeWriter);
					out.Generate(context);
					out.WriteNamespaceEnd();
				}
			}
			natvisWriter.GenerateFooter();
			modelTemplate.GenerateFooter();
			ret = 0;
		}
	}
	return ret;
}
