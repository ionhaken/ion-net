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
#include <codegen/StoreWriter.h>
#include <codegen/ComponentWriter.h>
#include <codegen/CodegenContext.h>
#include <ion/container/ForEach.h>

namespace ion::codegen
{
const bool IsMovingInternally = true;
}

ion::codegen::StoreWriter::StoreWriter(CodegenFile& aFile) : SourceCodeWriter(aFile) {}

void ion::codegen::StoreWriter::Generate(CodegenContext& c)
{
	GenerateHeader(c);

	auto& settings = c.mSettings;
	if (settings.mIndexMax != settings.mIndexMin)
	{
		ion::StackString<256> destructorCall;
		destructorCall->Format("~%s", settings.mSystemName.CStr());
		if (c.mIsHeader == c.mInlining.mDestructor)
		{
			WriteFunctionSignature(c, FunctionSignature::Definition, "", destructorCall.CStr(), "");
			WriteLn("{");
			AddIndent();
			WriteLn("Clear();");

			WriteTemporaryAllocator(settings);
			WriteLn("allocator.deallocate(mBuffer.Get(), BufferSize(mCapacity));");
			RemoveIndent();
			WriteLn("}");
		}
		else
		{
			WriteFunctionSignature(c, FunctionSignature::Declaration, "", destructorCall.CStr(), "");
		}
	}

	if (c.mIsHeader)
	{
		GeneratePublicMethods(c.mSettings, c.mGroups);
	}

	GeneratePrivateMethods(c, c.mGroups);

	if (c.mIsHeader)
	{
		GenerateData(c.mSettings, c.mGroups);
	}
	GenerateFooter(c);
}

void ion::codegen::StoreWriter::WriteReverseMap(StoreSettings& settings)
{
	if (settings.HasReverseMaps())
	{
		WriteLn("CreateReverseMapping(index%s);", settings.IsRemapped() ? ", reindex" : "");
	}
}

bool ion::codegen::StoreWriter::HasInitVars(StoreSettings& settings) const
{
	for (auto dataIter = settings.mData.Begin(); dataIter != settings.mData.End(); ++dataIter)
	{
		if (dataIter->mMaxSize <= 1)
		{
			return true;
		}
	}
	return false;
}

void ion::codegen::StoreWriter::WriteInitVars(StoreSettings& settings, const ion::Vector<uint16_t>& /*groups*/, CreateMethodType type)
{
	if (settings.mIndexMax == settings.mIndexMin || type == CreateMethodType::Assign || type == CreateMethodType::Move)
	{
		for (auto dataIter = settings.mData.Begin(); dataIter != settings.mData.End(); ++dataIter)
		{
			if (type == CreateMethodType::Move)
			{
				WriteLn("%s = %s(%s);", dataIter->GetDataStructure("index").CStr(), dataIter->IsUnique() ? "std::move" : "",
						dataIter->GetDataStructure("source").CStr());
			}
			else
			{
				if (dataIter->mMaxSize <= 1)
				{
					WriteLn("%s = %s(a%s);", dataIter->GetDataStructure("index").CStr(), dataIter->IsUnique() ? "std::move" : "",
							dataIter->GetName().CStr());
				}
				else
				{
					WriteLn("%s = 0;", dataIter->GetDataStructure("index").CStr());
				}
			}
		}
		return;
	}

	struct Group
	{
		ion::SmallVector<ion::String, 32> fields;
		ion::SmallVector<bool, 32> mIsUnique;
		uint16_t groupName;
	};

	ion::Vector<Group> groupStrings;

	for (auto dataIter = settings.mData.Begin(); dataIter != settings.mData.End(); ++dataIter)
	{
		if (dataIter->mDataGroup == NO_GROUP)
		{
			if (dataIter->mMaxSize <= 1)
			{
				WriteLn("%s.Insert(index, %s(a%s));", dataIter->GetDataContainer().CStr(), dataIter->IsUnique() ? "std::move" : "",
						dataIter->GetName().CStr());
			}
		}
		else
		{
			if (groupStrings.Size() <= dataIter->mDataGroup)
			{
				groupStrings.Resize(dataIter->mDataGroup + 1);
			}

			auto& group = groupStrings[dataIter->mDataGroup];

			if (group.fields.Size() == 0)
			{
				group.groupName = dataIter->mDataGroup;
			}
			ion::StackString<256> name;
			if (dataIter->mMaxSize <= 1)
			{
				name->Format("a%s", dataIter->GetName().CStr());
			}
			else
			{
				name->Format("0");
			}
			group.fields.Add(name);
			group.mIsUnique.Add(dataIter->IsUnique());
		}
	}

	ion::ForEach(groupStrings,
				 [&](Group& group)
				 {
					 if (group.fields.Size() > 0)
					 {
						 size_t numUnique = 0;
						 ion::ForEach(group.mIsUnique,
									  [&](auto val)
									  {
										  if (val)
										  {
											  numUnique++;
										  }
									  });
						 if (numUnique != group.fields.Size() && numUnique != 0)
						 {
							 ION_WRN("Group G" << group.groupName << " is only partially movable.");
						 }

						 ion::StackString<256> groupInsert;
						 groupInsert->Format("%s(%s)", group.mIsUnique[0] ? "std::move" : "", group.fields[0].CStr());

						 for (size_t i = 1; i < group.fields.Size(); ++i)
						 {
							 groupInsert->Format("%s, %s(%s)", groupInsert.CStr(), group.mIsUnique[i] ? "std::move" : "",
												 group.fields[i].CStr());
						 }
#if 0
				if (group.fields.Size() == 1 && group.mIsUnique[0])
				{
					WriteLn("mG%d.Insert(index, std::move(G%d{%s}));", group.groupName, group.groupName, groupInsert.CStr());
					// WriteLn("mG%d.Insert(index, %s);", group.groupName, groupInsert.CStr());
				}
				else
#endif
						 {
							 WriteLn("mG%d.Insert(index, (G%d{%s}));", group.groupName, group.groupName, groupInsert.CStr());
						 }
					 }
				 });
}

void ion::codegen::StoreWriter::WriteDynamicInitVars(StoreSettings& settings, bool hasReferencedReverseMaps)
{
	for (auto dataIter = settings.mData.Begin(); dataIter != settings.mData.End(); ++dataIter)
	{
		if (dataIter->mMaxSize > 1)
		{
			WriteLn("{");
			AddIndent();
			WriteLn("auto res = mDynamicData.m%s.Add(a%s, a%sSize);", dataIter->GetName().CStr(), dataIter->GetName().CStr(),
					dataIter->GetName().CStr());
			if (hasReferencedReverseMaps)
			{
				WriteLn("isReverseMapDirty |= res.isDirty;");
			}
			WriteLn("%s = res.pos;", dataIter->GetDataStructure("index").CStr());
			RemoveIndent();
			WriteLn("}");
		}
	}
	if (hasReferencedReverseMaps)
	{
		WriteLn("if (isReverseMapDirty)");
		WriteLn("{");
		AddIndent();
		for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
		{
			if (iter->GetReverseMapping() == ion::codegen::ReverseMapping::Reference)
			{
				WriteLn("%s.Clear();", iter->GetPathToReverseMapping().CStr());
			}
		}
		WriteLn("auto list = mIndexPool.CreateUsedIdList();");
		WriteLn("for (auto iter = list.Begin(); iter != list.End(); ++iter)");
		WriteLn("{");
		AddIndent();
		for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
		{
			if (iter->GetReverseMapping() == ion::codegen::ReverseMapping::Reference)
			{
				WriteLn("if (*iter != index)");
				WriteLn("{");
				AddIndent();
				GenerateReverseMap(*iter, "*iter", settings.IsRemapped());
				RemoveIndent();
				WriteLn("}");
			}
		}
		RemoveIndent();
		WriteLn("}");
		RemoveIndent();
		WriteLn("}");
	}
}

void ion::codegen::StoreWriter::WriteCreateMethod(StoreSettings& settings, CreateMethodSignature signature, CreateMethodType type,
												  const char* idName)
{
	auto buffer = settings.GetCreateParams(signature, type, false);

	WriteLn("%s%s %s%s(%s)%s", signature != CreateMethodSignature::Private ? idName : "",
			signature != CreateMethodSignature::Private ? "Id" : "void", type != CreateMethodType::Construct ? "Assign" : "Create",
			signature == CreateMethodSignature::Private ? "Internal" : "", buffer.CStr(),
			signature == CreateMethodSignature::Call ? ";" : "");
}

void ion::codegen::StoreWriter::WriteBufferItemCount(StoreSettings& settings, const ion::Vector<uint16_t>& /*groups*/, bool isCopy)
{
	if (settings.IsMoveOperationNeeded() && IsMovingInternally)
	{
		if (isCopy)
		{
			WriteLn("%s itemCount = mIndexPool.Size();", settings.GetIndexType());
			WriteLn("%s otherItemCount = other.mIndexPool.Size();", settings.GetIndexType());
		}
		else
		{
			WriteLn("%s itemCount = mIndexPool.Size() - 1;", settings.GetIndexType());
		}
	}
	else
	{
		if (isCopy)
		{
			WriteLn("%s itemCount = mIndexPool.Max();", settings.GetIndexType());
			if (settings.IsCopyAllowed())
			{
				WriteLn("%s otherItemCount = other.mIndexPool.Max();", settings.GetIndexType());
			}
		}
		else
		{
			WriteLn("%s itemCount = mIndexPool.Max() - 1;", settings.GetIndexType());
		}
	}

	if (settings.IsRemapped())
	{
		if (isCopy)
		{
			WriteLn("%s remapCount = mIndexPool.Max();", settings.GetIndexType());
			WriteLn("%s otherRemapCount = other.mIndexPool.Max();", settings.GetIndexType());
		}
		else
		{
			WriteLn("%s remapCount = mIndexPool.Max() - 1;", settings.GetIndexType());
		}
	}
}

void ion::codegen::StoreWriter::GenerateResize(CodegenContext& c, const ion::Vector<uint16_t>& groups)
{
	StoreSettings& settings = c.mSettings;
	const bool hasReferencedReverseMaps = settings.HasReferencedReverseMaps();
	const bool isWritingBody = c.mIsHeader == c.mInlining.mUtils;
	{
		const char* returnValue = hasReferencedReverseMaps ? "bool" : "void";

		ion::StackString<256> methodPars;
		methodPars->Format("%s capacity", settings.GetIndexType());

		if (isWritingBody)
		{
			WriteFunctionSignature(c, FunctionSignature::Definition, returnValue, "ResizeBuffer", methodPars.CStr());

			WriteLn("{");
			AddIndent();
			WriteTemporaryAllocator(settings);
			WriteLn("auto* oldBuffer = mBuffer.Get();");
			WriteLn("auto oldCapacity = mCapacity;");

			WriteBufferItemCount(settings, groups, false);

			WriteLn("mBuffer = allocator.allocate(BufferSize(capacity));");
			WriteBufferHandling(settings, groups, BufferHandling::Resize);

			WriteLn("mCapacity = capacity;");
			WriteLn("allocator.deallocate(oldBuffer, BufferSize(oldCapacity));");
			if (hasReferencedReverseMaps)
			{
				WriteLn("return true;");
			}

			RemoveIndent();
			WriteLn("}");
		}
		else
		{
			WriteFunctionSignature(c, FunctionSignature::Declaration, returnValue, "ResizeBuffer", methodPars.CStr());
		}
	}

	{
		ion::StackString<256> methodPars;
		methodPars->Format("%s capacity, [[maybe_unused]] const %s& other", settings.GetIndexType(), settings.mSystemName.CStr());
		if (isWritingBody)
		{
			WriteFunctionSignature(c, FunctionSignature::Definition, "void", "ResizeAndCopyBuffer", methodPars.CStr());
			WriteLn("{");
			AddIndent();
			WriteLn("auto* oldBuffer = mBuffer.Get();");
			WriteLn("auto oldCapacity = mCapacity;");

			WriteBufferItemCount(settings, groups, true);

			WriteTemporaryAllocator(settings);
			WriteLn("mBuffer = allocator.allocate(BufferSize(capacity));");
			WriteBufferHandling(settings, groups, BufferHandling::CopyToNewBuffer);
			WriteLn("mCapacity = capacity;");
			WriteLn("if (oldBuffer)");
			WriteLn("{");
			AddIndent();
			WriteLn("allocator.deallocate(oldBuffer, BufferSize(oldCapacity));");
			RemoveIndent();
			WriteLn("}");
			RemoveIndent();
			WriteLn("}");
		}
		else
		{
			WriteFunctionSignature(c, FunctionSignature::Declaration, "void", "ResizeAndCopyBuffer", methodPars.CStr());
		}
	}
}

void ion::codegen::StoreWriter::GenerateCreateMethods(StoreSettings& settings, const ion::Vector<uint16_t>& groups,
													  CreateMethodSignature signature, CreateMethodType type)
{
	for (auto iter = settings.mComponents.Begin(); iter != settings.mComponents.End(); ++iter)
	{
		WriteCreateMethod(settings, signature, type, iter->mName.CStr());

		if (signature != CreateMethodSignature::Call)
		{
			WriteLn("{");
			AddIndent();
			const bool hasReferencedReverseMaps = settings.HasReferencedReverseMaps();
			if (signature != CreateMethodSignature::Private)
			{
				WriteLn("LockProtection();");
				if (!(settings.IsMoveOperationNeeded() && IsMovingInternally))
				{
					if (settings.mIndexMax != settings.mIndexMin)
					{
						WriteLn("auto lastIndex = mIndexPool.Max();");
					}
				}

				if (settings.IsMoveOperationNeeded())
				{
					WriteLn("auto index = mIndexPool.Size();");
				}
				else
				{
					WriteLn("auto index = mIndexPool.Reserve();");
				}

				WriteLn("ION_ASSERT(index < %lu, \"Invalid index:\" << index);", settings.mIndexMax);
				WriteLn("ResizeProtection(index);");

				if (hasReferencedReverseMaps)
				{
					WriteLn("bool isReverseMapDirty = false;");
				}
			}

			if (signature == CreateMethodSignature::Private)
			{
				WriteInitVars(settings, groups, type);
			}
			else
			{
				if (settings.IsRemapped())
				{
					WriteLn("auto reindex = mIndexPool.Reserve();");
				}

				if (!(settings.IsMoveOperationNeeded() && IsMovingInternally))
				{
					if (settings.mIndexMax != settings.mIndexMin)
					{
						if (settings.IsRemapped())
						{
							WriteLn("if (reindex != lastIndex)");
						}
						else
						{
							WriteLn("if (index != lastIndex)");
						}
					}
					WriteLn("{");
					AddIndent();
					{
						auto buffer = settings.GetCreateParams(CreateMethodSignature::Private, CreateMethodType::Construct, true);
						WriteLn("AssignInternal(%s);", buffer.CStr());
					}
					RemoveIndent();
					WriteLn("}");
				}
				if (settings.mIndexMax != settings.mIndexMin)
				{
					if (!(settings.IsMoveOperationNeeded() && IsMovingInternally))
					{
						WriteLn("else");
					}
					WriteLn("{");
					AddIndent();
					{
						if (settings.mIndexMax != settings.mIndexMin)
						{
							WriteLn("if (mCapacity == index)");
							WriteLn("{");
							AddIndent();
							WriteLn("%sResizeBuffer(ion::SafeRangeCast<%s>(ion::Min(size_t(index)*2, size_t(%zu))));",
									(hasReferencedReverseMaps ? "isReverseMapDirty = " : ""), settings.GetIndexType(), settings.mIndexMax);
							RemoveIndent();
							WriteLn("}");
						}

						auto buffer = settings.GetCreateParams(CreateMethodSignature::Private, CreateMethodType::Construct, true);
						WriteLn("CreateInternal(%s);", buffer.CStr());
					}
					RemoveIndent();
					WriteLn("}");
				}

				if (settings.IsRemapped())
				{
					WriteLn("mRemap[reindex] = index;");
					WriteLn("mReverseRemap[index] = reindex;");
				}

				WriteDynamicInitVars(settings, hasReferencedReverseMaps);

				WriteReverseMap(settings);
			}

			if (signature == CreateMethodSignature::Public)
			{
				WriteLn("#if ION_COMPONENT_VERSION_NUMBER");
				WriteLn("auto version = GetVersion(%s);", settings.IsRemapped() ? "reindex" : "index");
				WriteLn("#endif");
			}

			if (signature != CreateMethodSignature::Private)
			{
				WriteLn("UnlockProtection();");
			}
			if (signature == CreateMethodSignature::Public)
			{
				WriteLn("#if ION_COMPONENT_VERSION_NUMBER");
				WriteLn("return %sId(%s, version);", iter->mName.CStr(), settings.IsRemapped() ? "reindex" : "index");
				WriteLn("#else");
				WriteLn("return %sId(%s);", iter->mName.CStr(), settings.IsRemapped() ? "reindex" : "index");
				WriteLn("#endif");
			}
			RemoveIndent();
			WriteLn("}");
		}
		WriteLn("");
	}
}

void ion::codegen::StoreWriter::GenerateGetId(StoreSettings& settings)
{
	if (settings.IsRemapped())
	{
		for (auto iter = settings.mComponents.Begin(); iter != settings.mComponents.End(); ++iter)
		{
			WriteLn("%sId GetId(size_t index) const", iter->mName.CStr());

			WriteLn("{");
			AddIndent();
			WriteLn("auto reindex = mReverseRemap[index];");
			WriteLn("#if ION_COMPONENT_VERSION_NUMBER");
			WriteLn("return %sId(reindex, GetVersion(reindex));", iter->mName.CStr());
			WriteLn("#else");
			WriteLn("return %sId(reindex);", iter->mName.CStr());
			WriteLn("#endif");
			RemoveIndent();
			WriteLn("}");
		}
	}
}

void ion::codegen::StoreWriter::WriteTemporaryAllocator(const StoreSettings& settings)
{
	if (settings.mResource.Length() > 0)
	{
		WriteLn("ion::AlignedAllocator<alignof(void*), ion::ArenaAllocator<uint8_t, %s>> allocator(&mResource);", settings.mResource.CStr());
	}
	else
	{
		WriteLn("ion::GlobalAllocator<uint8_t> allocator;");
	}
}

void ion::codegen::StoreWriter::GenerateConstructor(const CodegenContext& c)
{
	auto& settings = c.mSettings;

	WriteLn("{");

	if (settings.mIndexMax != settings.mIndexMin)
	{
		AddIndent();

		WriteLn("mBuffer = nullptr;");
		WriteLn("mCapacity = %d;", ion::Max(size_t(1), settings.mIndexAverage));
		WriteLn("ResizeAndCopyBuffer(mCapacity, *this);");
		WriteLn("SetName(\"%s\");", settings.mSystemName.CStr());
		RemoveIndent();
	}
	WriteLn("}");
}

void ion::codegen::StoreWriter::GeneratePublicMethods(StoreSettings& settings, const ion::Vector<uint16_t>& groups)
{
	// #TODO: Get Rid of component vector. all stores will use single component type
	ION_ASSERT(settings.mComponents.Size() == 1, "Only single component stores supported");
	ion::StackString<256> componentIdName;
	componentIdName->Format("%sId", settings.mComponents.Begin()->mName.CStr());

	for (auto iter = settings.mComponents.Begin(); iter != settings.mComponents.End(); ++iter)
	{
		if (settings.IsRemapped())
		{
			WriteLn("inline %s Get(size_t idx);", iter->GetName().CStr());
			WriteLn("");
			WriteLn("inline %s GetConst(size_t idx) const;", iter->GetConstName().CStr());
			WriteLn("");
		}
		WriteLn("inline %s Get(const %s& id);", iter->GetName().CStr(), componentIdName.CStr());
		WriteLn("");
		WriteLn("inline %s GetConst(const %s& id) const;", iter->GetConstName().CStr(), componentIdName.CStr());
		WriteLn("");
	}

	GenerateCreateMethods(settings, groups, CreateMethodSignature::Public);

	auto WriteReturnComponentId = [this, &componentIdName]
	{
		WriteLn("#if ION_COMPONENT_VERSION_NUMBER");
		WriteLn("return %s(index, GetVersion(index));", componentIdName.CStr());
		WriteLn("#else");
		WriteLn("return (index);");
		WriteLn("#endif");
	};

	if (!settings.IsRemapped())
	{
		WriteLn("%s RawIndexToId(%s index) const", componentIdName.CStr(), settings.GetIndexType());
		WriteLn("{");
		AddIndent();
		WriteReturnComponentId();
		RemoveIndent();
		WriteLn("}");
		WriteLn("");
	}

	for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
	{
		if (iter->GetReverseMapping() != ion::codegen::ReverseMapping::None)
		{
			WriteLn("// Gets component with given value. Behaviour is undefined if component is not found");
			const ion::String paramType = iter->GetTypeParam(settings.mIndexMax, true, true);
			WriteLn("%s Get%s(%s a%s) const", componentIdName.CStr(), iter->GetName().CStr(), paramType.CStr(), iter->GetName().CStr());
			WriteLn("{");
			AddIndent();
			WriteLn("const auto index = %s[a%s];", iter->GetPathToReverseMapping().CStr(), iter->GetName().CStr());
			WriteReturnComponentId();
			RemoveIndent();
			WriteLn("}");
			WriteLn("");
			WriteLn("// Finds component with given value. Returns invalid component if component is not found");
			WriteLn("%s Find%s(%s a%s) const", componentIdName.CStr(), iter->GetName().CStr(), paramType.CStr(), iter->GetName().CStr());
			WriteLn("{");
			AddIndent();
			WriteLn("auto index = %s.Lookup(a%s);", iter->GetPathToReverseMapping().CStr(), iter->GetName().CStr());
			WriteLn("#if ION_COMPONENT_VERSION_NUMBER");
			WriteLn("return index != nullptr ? %s(*index, GetVersion(*index)) : %s();", componentIdName.CStr(), componentIdName.CStr());
			WriteLn("#else");
			WriteLn("return index != nullptr ? %s(*index) : %s();", componentIdName.CStr(), componentIdName.CStr());
			WriteLn("#endif");
			RemoveIndent();
			WriteLn("}");
			WriteLn("");
		}
	}
	WriteLn("void Delete(const %s& anId)", componentIdName.CStr());
	WriteLn("{");
	AddIndent();
	WriteLn("ION_ASSERT(anId.GetIndex() < %lu, \"Invalid index:\" << anId.GetIndex());", settings.mIndexMax);
	WriteLn("LockProtection();");
	if (settings.IsRemapped())
	{
		WriteLn("auto index = Remap(anId);");
	}
	else
	{
		WriteLn("auto index = anId.GetIndex();");
	}
	WriteLn("#if ION_COMPONENT_VERSION_NUMBER");
	WriteLn("ION_CHECK(anId.GetVersion() == GetVersion(anId.GetIndex()),");
	AddIndent();
	WriteLn("\"Invalid version \" << anId.GetVersion() << \";expected:\" << GetVersion(anId.GetIndex()));");
	RemoveIndent();
	WriteLn("#endif");
	if (settings.HasDynamicData())
	{
		for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
		{
			if (iter->mMaxSize > 1)
			{
				WriteLn("mDynamicData.m%s.Remove(%s);", iter->GetName().CStr(), iter->GetDataStructure("index").CStr());
			}
		}
	}

	WriteLn("DeleteIndex(index%s);", settings.IsRemapped() ? ", anId.GetIndex()" : "");
	if (settings.IsMoveOperationNeeded())
	{
		WriteLn("auto lastIndex = mIndexPool.Size();");
		WriteLn("if (lastIndex != index)");
		WriteLn("{");
		AddIndent();
		WriteLn("Move(index, lastIndex, mReverseRemap[lastIndex]);");
		if (settings.IsRemapped())
		{
			WriteLn("mRemap[mReverseRemap[lastIndex]] = index;");
			WriteLn("mReverseRemap[index] = mReverseRemap[lastIndex];");
		}
		RemoveIndent();
		WriteLn("}");

		if (IsMovingInternally)
		{
			for (auto dataIter = settings.mData.Begin(); dataIter != settings.mData.End(); ++dataIter)
			{
				if (dataIter->mDataGroup == NO_GROUP)
				{
					WriteLn("%s.Erase(lastIndex);", dataIter->GetDataContainer().CStr());
				}
			}
			for (auto dataIter = groups.Begin(); dataIter != groups.End(); ++dataIter)
			{
				WriteLn("mG%d.Erase(lastIndex);", *dataIter);
			}
		}
	}

	WriteLn("UnlockProtection();");
	RemoveIndent();
	WriteLn("}");

	if (settings.IsDataLayoutStrict())
	{
		WriteLn("void Compact()");
		WriteLn("{");
		AddIndent();
		WriteLn("while(mIndexPool.HasFreeItems())");
		WriteLn("{");
		AddIndent();
		WriteLn("%s source = mIndexPool.ClearFreeList();", settings.GetIndexType());
		WriteLn("if (mIndexPool.HasFreeItems())");
		WriteLn("{");
		AddIndent();
		WriteLn("Move(mIndexPool.Reserve(), source);");
		RemoveIndent();
		WriteLn("}");
		RemoveIndent();
		WriteLn("}");
		RemoveIndent();
		WriteLn("}");
	}

	GenerateGetId(settings);

	WriteLn("[[nodiscard]] inline size_t Size() const");
	WriteLn("{");
	AddIndent();
	WriteLn("return mIndexPool.Size();");
	RemoveIndent();
	WriteLn("}");

	WriteLn("[[nodiscard]] static constexpr size_t MaxSize()");
	WriteLn("{");
	AddIndent();
	WriteLn("return %lu;", settings.mIndexMax);
	RemoveIndent();
	WriteLn("}");

	if (settings.IsCopyAllowed())
	{
		for (size_t copyType = 0; copyType < 2; copyType++)
		{
			if (copyType == 0)
			{
				ion::String parentClass = ParentClass(settings);
				WriteLn("%s(const %s& other)", settings.mSystemName.CStr(), settings.mSystemName.CStr());
				WriteInitializer(parentClass, settings, true);
			}
			else
			{
				WriteLn("const %s& operator=(const %s& other)", settings.mSystemName.CStr(), settings.mSystemName.CStr());
			}
			WriteLn("{");
			AddIndent();
			WriteLn("LockProtection();");
			WriteLn("other.LockProtection();");
			WriteLn("CloneProtection(other);");

			if (settings.mIndexMax != settings.mIndexMin)
			{
				if (copyType == 0)
				{
					WriteLn("mBuffer = nullptr;");
					WriteLn("ResizeAndCopyBuffer(other.mCapacity, other);");
				}
				else
				{
					WriteLn("if (mCapacity != other.mCapacity)");
					WriteLn("{");
					AddIndent();
					WriteLn("ResizeAndCopyBuffer(other.mCapacity, other);");
					RemoveIndent();
					WriteLn("}");
					WriteLn("else");
					WriteLn("{");
					AddIndent();
					WriteLn("CopyBuffer(other);");
					RemoveIndent();
					WriteLn("}");
				}
			}
			else
			{
				WriteLn("CopyBuffer(other);");
			}
			WriteLn("mIndexPool = other.mIndexPool;");
			WriteLn("UnlockProtection();");
			WriteLn("other.UnlockProtection();");
			if (copyType == 1)
			{
				WriteLn("return *this;");
			}
			RemoveIndent();
			WriteLn("}");
		}
	}

	if (settings.IsRemapped())
	{
		for (uint16_t index = 0; index < settings.mComponents.Size(); index++)
		{
			WriteLn("%s Remap(const %sId& id) const", settings.GetIndexType(), settings.mComponents[index].mName.CStr());
			WriteLn("{");
			AddIndent();
			WriteLn("return mRemap[id.GetIndex()];");
			RemoveIndent();
			WriteLn("}");
		}
	}
}

void ion::codegen::StoreWriter::GenerateData(StoreSettings& settings, const ion::Vector<uint16_t>& groups)
{
	if (settings.mIndexMax != settings.mIndexMin)
	{
		if (settings.mResource.Length() > 0)
		{
			WriteLn("%s& mResource;", settings.mResource.CStr());
		}
		WriteLn("ion::RawBuffer<uint8_t> mBuffer;");
		WriteLn("%s mCapacity = 0;", settings.GetIndexType());
	}

	if (settings.HasReverseMaps())
	{
		for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
		{
			if (iter->GetReverseMapping() != ion::codegen::ReverseMapping::None)
			{
				ion::StackString<256> hasher;
				if (iter->mMaxSize > 1)
				{
					hasher->Format(", %s::Hasher", iter->GetTypeParam(settings.mIndexMax, false).CStr());
				}
				else
				{
					hasher->Format(", ion::Hasher<%s>", iter->GetTypeParam(settings.mIndexMax, false, false).CStr());
				}

				ion::StackString<256> keyValue;
				keyValue->Format("%s, %s", iter->GetTypeParam(settings.mIndexMax, false, false).CStr(), settings.GetIndexType());

				ion::StackString<256> allocator;
				if (settings.mResource.Length() > 0)
				{
					allocator->Format(", ion::ArenaAllocator<ion::Pair<const %s>, %s>", keyValue.CStr(), settings.mResource.CStr());
				}

				WriteLn("ion::UnorderedMap<%s%s%s> %s;", keyValue.CStr(), hasher.CStr(), allocator.CStr(),
						iter->GetPathToReverseMapping().CStr());
			}
		}
	}
	if (settings.IsRemapped())
	{
		WriteLn("%s mRemap;", settings.GetDataContainer(settings.GetIndexType()).CStr());
		WriteLn("%s mReverseRemap;", settings.GetDataContainer(settings.GetIndexType()).CStr());
	}
	if (settings.HasGrouplessData())
	{
		WriteLn("struct");
		WriteLn("{");
		AddIndent();
		for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
		{
			if (iter->mDataGroup == ion::codegen::NO_GROUP)
			{
				WriteLn("%s m%s;", settings.GetDataContainer(iter->GetTypeId(settings.mIndexMax)).CStr(), iter->GetName().CStr());
			}
		}
		RemoveIndent();
		WriteLn("} mData;");
	}

	if (settings.HasDynamicData())
	{
		WriteLn("struct Dynamic");
		WriteLn("{");
		AddIndent();
		WriteLn("Dynamic() {}");
		WriteLn("Dynamic(size_t size) : ");
		bool found = false;
		for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
		{
			if (iter->mMaxSize > 1)
			{
				WriteLn("%sm%s(static_cast<%s>(size))", found ? ", " : "", iter->GetName().CStr(),
						GetSizeType(iter->mMaxSize * settings.mIndexMax));
				found = true;
			}
		}
		WriteLn("{}");
		for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
		{
			if (iter->mMaxSize > 1)
			{
				WriteLn("%s m%s;", iter->GetType(settings.mIndexMax).CStr(), iter->GetName().CStr());
			}
		}
		RemoveIndent();
		WriteLn("} mDynamicData;");
	}

	for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
	{
		if (iter->mDataGroup == ion::codegen::NO_GROUP) {}
	}

	for (auto iter = groups.Begin(); iter != groups.End(); ++iter)
	{
		WriteLn("struct G%d", *iter);
		WriteLn("{");
		AddIndent();
		for (auto siter = settings.mData.Begin(); siter != settings.mData.End(); ++siter)
		{
			if (siter->mDataGroup == *iter)
			{
				WriteLn("%s m%s;", siter->GetTypeId(settings.mIndexMax).CStr(), siter->GetName().CStr());
			}
		}
		RemoveIndent();
		WriteLn("};");
		ion::StackString<256> groupName;
		groupName->Format("G%d", *iter);
		WriteLn("%s mG%d;", settings.GetDataContainer(groupName).CStr(), *iter);
	}
}

void ion::codegen::StoreWriter::WriteBufferHandling(StoreSettings& settings, const ion::Vector<uint16_t>& groups, BufferHandling mode)
{
	ion::StackString<1024> bytesReserved = "0";

	auto WriteOperation = [&](const char* name, const char* type, const char* pointer, bool isRemap = false)
	{
		WriteLn("{");
		AddIndent();
		if (mode == BufferHandling::CopyToOldBuffer)
		{
			if (settings.mIndexMax == settings.mIndexMin)
			{
				WriteLn("%s = other.%s;", name, name);
			}
			else
			{
				WriteLn("%s.CopyFrom(other.%s.Get(), %sCount, %sCount);", name, name, isRemap ? "otherRemap" : "otherItem",
						isRemap ? "remap" : "item");
			}
		}
		else
		{
			WriteLn("pos = pos + %s;", bytesReserved.CStr());
			WriteLn("uintptr_t offset = reinterpret_cast<uintptr_t>(pos) %% alignof(%s);", type);
			bytesReserved->Format("0");
			if (mode == BufferHandling::Resize)
			{
				WriteLn("%s.Replace(ion::AssumeAligned(reinterpret_cast<%s>(pos + (alignof(%s) - offset))), %sCount);", name, pointer, type,
						isRemap ? "remap" : "item");
			}
			else if (mode == BufferHandling::CopyToNewBuffer)
			{
				WriteLn("%s.Reset(%sCount, ion::AssumeAligned(reinterpret_cast<%s>(pos + (alignof(%s) - offset))));", name,
						isRemap ? "remap" : "item", pointer, type);
				if (settings.IsCopyAllowed())
				{
					WriteLn("%s.CreateFrom(other.%s.Get(), %sCount);", name, name, isRemap ? "otherRemap" : "otherItem");
				}
			}
		}
		RemoveIndent();
		WriteLn("}");
	};

	if (mode != BufferHandling::BufferSize && mode != BufferHandling::CopyToOldBuffer)
	{
		WriteLn("uint8_t* pos = mBuffer.Get();");
	}

	if (mode == BufferHandling::CopyToNewBuffer || mode == BufferHandling::CopyToOldBuffer)
	{
		if (settings.HasReverseMaps())
		{
			for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
			{
				if (iter->GetReverseMapping() != ion::codegen::ReverseMapping::None)
				{
					WriteLn("%s = other.%s;", iter->GetPathToReverseMapping().CStr(), iter->GetPathToReverseMapping().CStr());
				}
			}
		}

		if (settings.HasDynamicData())
		{
			WriteLn("mDynamicData = other.mDynamicData;");
		}
	}

	for (auto iter = groups.Begin(); iter != groups.End(); ++iter)
	{
		ion::StackString<64> name;
		name->Format("mG%d", *iter);
		ion::StackString<64> type;
		type->Format("G%d", *iter);
		if (mode != BufferHandling::BufferSize)
		{
			ion::StackString<64> pointer;
			pointer->Format("G%d*", *iter);
			WriteOperation(name.CStr(), type.CStr(), pointer.CStr());
		}
		bytesReserved->Format("%s + sizeof(%s)*capacity", bytesReserved.CStr(), type.CStr());
		bytesReserved->Format("%s + alignof(%s)", bytesReserved.CStr(), type.CStr());
	}
	for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
	{
		if (iter->mDataGroup == ion::codegen::NO_GROUP)
		{
			ion::StackString<64> type;
			type->Format("%s", iter->GetTypeId(settings.mIndexMax).CStr());

			if (mode != BufferHandling::BufferSize)
			{
				ion::StackString<64> name;
				name->Format("mData.m%s", iter->GetName().CStr());
				ion::StackString<64> pointer;
				pointer->Format("%s*", type.CStr());
				WriteOperation(name.CStr(), type.CStr(), pointer.CStr());
			}
			bytesReserved->Format("%s + sizeof(%s)*capacity + alignof(%s)", bytesReserved.CStr(), type.CStr(), type.CStr());
		}
	}

	auto indexType = settings.GetIndexType();
	ion::StackString<64> indexTypePtr;
	indexTypePtr->Format("%s *", indexType);

	if (settings.IsRemapped())
	{
		if (mode != BufferHandling::BufferSize)
		{
			WriteOperation("mRemap", indexType, indexTypePtr.CStr(), true);
		}
		bytesReserved->Format("%s + sizeof(%s)*capacity + alignof(%s)", bytesReserved.CStr(), indexType, indexType);

		if (mode != BufferHandling::BufferSize)
		{
			WriteOperation("mReverseRemap", indexType, indexTypePtr.CStr());
		}
		bytesReserved->Format("%s + sizeof(%s)*capacity + alignof(%s)", bytesReserved.CStr(), indexType, indexType);
	}

	if (mode == BufferHandling::BufferSize)
	{
		WriteLn("return %s;", bytesReserved.CStr());
	}
}

/*void ion::codegen::StoreWriter::GenerateDataCopy(
	StoreSettings& settings, const ion::Vector<uint16_t>& groups)
{
	// TODO: Optimize copy, use only used indices
	if (settings.HasReverseMaps())
	{
		for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
		{
			if (iter->GetReverseMapping() != ion::codegen::ReverseMapping::None)
			{
				WriteLn("%s = other.%s;",
					iter->GetPathToReverseMapping().CStr(), iter->GetPathToReverseMapping().CStr());
			}
		}
	}


	if (settings.IsRemapped())
	{
		GenerateListCopy("mRemap");
		GenerateListCopy("mReverseRemap");
	}
	for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
	{
		if (iter->mDataGroup == ion::codegen::NO_GROUP)
		{
			ion::StackString<256> fieldName;
			fieldName->Format("mData.m%s", iter->GetName().CStr());
			GenerateListCopy(fieldName.CStr());
		}
	}
	for (auto iter = groups.Begin(); iter != groups.End(); ++iter)
	{
		ion::StackString<256> fieldName;
		fieldName->Format("mG%d", *iter);
		GenerateListCopy(fieldName.CStr());
	}
}*/

ion::String ion::codegen::StoreWriter::ParentClass(const StoreSettings& settings) const
{
	ion::StackString<256> parentClass;
	{
		ion::StackString<256> allocatorType;
		if (settings.mResource.Length() > 0)
		{
			allocatorType->Format(", ion::ArenaAllocator<%s, %s>", settings.GetIndexType(), settings.mResource.CStr());
		}
		parentClass->Format("ion::ComponentStore<%s%s>", settings.GetIndexType(), allocatorType.CStr());
	}
	return parentClass;
}

void ion::codegen::StoreWriter::WriteInitializer(const ion::String& parentClass, const StoreSettings& settings, bool isCopy)
{
	auto AddDelimeters = [&](bool& isFirst)
	{
		if (isFirst)
		{
			WriteLn(":");
			isFirst = false;
		}
		else
		{
			WriteLn(",");
		}
	};

	bool isFirst = true;
	if (settings.mResource.Length() > 0)
	{
		AddDelimeters(isFirst);
		WriteLn("%s(%s)", parentClass.CStr(), isCopy ? "&other.mResource" : "resource");
		AddDelimeters(isFirst);
		WriteLn("mResource(%s)", isCopy ? "other.mResource" : "*resource");
	}

	ion::StackString<256> resourceParameter;
	if (settings.mResource.Length() > 0)
	{
		resourceParameter->Format("resource, ");
	}
	for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
	{
		if (iter->GetReverseMapping() != ion::codegen::ReverseMapping::None)
		{
			if (isCopy)
			{
				if (settings.mResource.Length() > 0)
				{
					AddDelimeters(isFirst);
					WriteLn("%s(&other.mResource, %llu)", iter->GetPathToReverseMapping().CStr(), settings.mIndexAverage);
				}
			}
			else
			{
				AddDelimeters(isFirst);
				WriteLn("%s(%s%llu)", iter->GetPathToReverseMapping().CStr(), resourceParameter.CStr(), settings.mIndexAverage);
			}
		}
	}
	if (settings.HasDynamicData())
	{
		AddDelimeters(isFirst);
		if (isCopy)
		{
			WriteLn("mDynamicData(other.mDynamicData)");
		}
		else
		{
			WriteLn("mDynamicData(%llu)", settings.mIndexAverage);
		}
	}
}

void ion::codegen::StoreWriter::GenerateHeader(CodegenContext& context)
{
	StoreSettings& settings = context.mSettings;
	AutoGenHeader();
	if (!context.mIsHeader)
	{
		if (!context.mPrecompiledHeader.IsEmpty())
		{
			WriteLn("#include \"%s\"", context.mPrecompiledHeader.CStr());
		}

		ion::ForEach(context.mStoreSrcHeaderIncludes,
					 [&](const ion::String& str)
					 {
						 if (str.FindFirstOf('/') == std::string::npos)
						 {
							 WriteLn("#include \"%s\"", str.CStr());
						 }
						 else
						 {
							 WriteLn("#include <%s>", str.CStr());
						 }
					 });

		WriteLn("#include <%s>", context.mStoreHeaderName.CStr());
	}
	else
	{
		WriteLn("#pragma once");
		WriteLn("#include <%s/ComponentModel.generated.h>", context.mTargetPath.CStr());
		WriteLn("#include <ion/database/DBComponentStoreView.h>");
		WriteLn("#include <ion/database/DBComponentStore.h>");
		WriteLn("#include <ion/database/DBComponentDataVector.h>");
		WriteLn("#include <ion/database/DBComponent.h>");
		WriteLn("#include <ion/arena/ArenaVector.h>");
		WriteLn("#include <ion/arena/ArenaAllocator.h>");
		WriteLn("#include <ion/memory/AlignedAllocator.h>");
		if (settings.HasBatchData())
		{
			WriteLn("#include <ion/batch/VecBatch.h>");
		}

		if (settings.HasDynamicData())
		{
			WriteLn("#include <ion/util/MultiData.h>");
		}

		ion::ForEach(context.mStoreHeaderIncludes, [&](const auto& str) { WriteLn("#include <%s>", str.CStr()); });
	}

	SourceCodeWriter::WriteNamespaceBegin(context.mNamespaceName);

	ion::String parentClass = ParentClass(settings);
	if (context.mIsHeader)
	{
		for (uint16_t index = 0; index < settings.mComponents.Size(); index++)
		{
			WriteLn("class %s;", settings.mComponents[index].GetName().CStr());
			WriteLn("class %s;", settings.mComponents[index].GetConstName().CStr());
		}
		WriteLn("class %s : public %s", settings.mSystemName.CStr(), parentClass.CStr());
		WriteLn("{");
		AddIndent();
		if (!settings.IsCopyAllowed())
		{
			WriteLn("ION_CLASS_NON_COPYABLE_NOR_MOVABLE(%s)", settings.mSystemName.CStr());
		}
		RemoveIndent();
		WriteLn("public:");
		AddIndent();
		WriteLn("using ComponentType = ion::ManualComponent;");
		for (uint16_t index = 0; index < settings.mComponents.Size(); index++)
		{
			WriteLn("friend class %sId;", settings.mComponents[index].mName.CStr());
			WriteLn("friend class %s;", settings.mComponents[index].GetName().CStr());
			WriteLn("friend class %s;", settings.mComponents[index].GetConstName().CStr());
		}
	}

	const bool isWritingConstructorBody = (context.mIsHeader == context.mInlining.mConstructor);
	{
		ion::StackString<256> resourceParameter;
		if (settings.mResource.Length() > 0)
		{
			resourceParameter->Format("%s* resource", settings.mResource.CStr());
		}
		WriteFunctionSignature(context, isWritingConstructorBody ? FunctionSignature::Definition : FunctionSignature::Declaration, "",
							   settings.mSystemName.CStr(), resourceParameter.CStr());
	}

	if (isWritingConstructorBody)
	{
		WriteInitializer(parentClass, settings, false);
		GenerateConstructor(context);
	}
	WriteLn("");
}

void ion::codegen::StoreWriter::GenerateReverseMap(const Data& data, const char* indexName, bool isRemapped)
{
	WriteLn("ION_ASSERT(%s.Lookup(%s) == nullptr, \"Data is not unique\");", data.GetPathToReverseMapping().CStr(),
			data.GetPathToData(indexName).CStr());
	if (isRemapped)
	{
		WriteLn("%s.Insert(%s, reindex);", data.GetPathToReverseMapping().CStr(), data.GetPathToData(indexName).CStr(), indexName);
	}
	else
	{
		WriteLn("%s.Insert(%s, %s);", data.GetPathToReverseMapping().CStr(), data.GetPathToData(indexName).CStr(), indexName);
	}
}

void ion::codegen::StoreWriter::GeneratePrivateMethods(CodegenContext& c, const ion::Vector<uint16_t>& groups)
{
	StoreSettings& settings = c.mSettings;
	if (c.mIsHeader)
	{
		RemoveIndent();
		WriteLn("private:");
		AddIndent();
	}

	if (c.mIsHeader)
	{
		if (settings.mIndexMax != settings.mIndexMin)
		{
			GenerateCreateMethods(settings, groups, CreateMethodSignature::Private, CreateMethodType::Construct);
		}

		if (!(settings.IsMoveOperationNeeded() && IsMovingInternally))
		{
			GenerateCreateMethods(settings, groups, CreateMethodSignature::Private, CreateMethodType::Assign);
		}
	}

	if (c.mIsHeader)
	{
		if (settings.IsMoveOperationNeeded())
		{
			if (settings.IsRemapped())
			{
				WriteLn("void Move(const %s index, const %s source, const %s %s)", settings.GetIndexType(), settings.GetIndexType(),
						settings.GetIndexType(), settings.HasReverseMaps() ? "reindex" : "/*reindex*/");
			}
			else
			{
				WriteLn("void Move(const %s index, const %s source)", settings.GetIndexType(), settings.GetIndexType());
			}
			WriteLn("{");
			AddIndent();
			if (settings.HasReverseMaps())
			{
				WriteLn("RemoveReverseMapping(source);");
			}

			if (settings.IsMoveOperationNeeded())
			{
				WriteInitVars(settings, groups, CreateMethodType::Move);
			}
			else
			{
				auto buffer = settings.GetCreateParams(CreateMethodSignature::Private, CreateMethodType::Assign, true);
				WriteLn("AssignInternal(%s);", buffer.CStr());
			}

			for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
			{
				if (iter->mMaxSize > 1)
				{
					WriteLn("%s = %s;", iter->GetDataStructure("index").CStr(), iter->GetDataStructure("source").CStr());
				}
			}
			WriteReverseMap(settings);
			RemoveIndent();
			WriteLn("}");
		}

		if (settings.IsRemapped())
		{
			WriteLn("void DeleteIndex(const %s %s, const %s reindex)", settings.GetIndexType(),
					settings.HasReverseMaps() ? "index" : "/*index*/", settings.GetIndexType());
		}
		else
		{
			WriteLn("void DeleteIndex(const %s index)", settings.GetIndexType());
		}
		WriteLn("{");
		AddIndent();
		WriteLn("#if ION_COMPONENT_VERSION_NUMBER");
		WriteLn("IncreaseVersion(%s);", settings.IsRemapped() ? "reindex" : "index");
		WriteLn("#endif");
		if (settings.HasReverseMaps())
		{
			WriteLn("RemoveReverseMapping(index);");
		}
		WriteLn("mIndexPool.Free(%s);", settings.IsRemapped() ? "reindex" : "index");
		RemoveIndent();
		WriteLn("}");
	}

	if (settings.mIndexMax != settings.mIndexMin)
	{
		GenerateResize(c, groups);
	}

	if (c.mIsHeader)
	{
		if (settings.HasReverseMaps())
		{
			if (settings.IsRemapped())
			{
				WriteLn("void CreateReverseMapping(const %s index, const %s reindex)", settings.GetIndexType(), settings.GetIndexType());
			}
			else
			{
				WriteLn("void CreateReverseMapping(const %s index)", settings.GetIndexType());
			}
			WriteLn("{");
			AddIndent();
			for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
			{
				if (iter->GetReverseMapping() != ion::codegen::ReverseMapping::None)
				{
					GenerateReverseMap(*iter, "index", settings.IsRemapped());
				}
			}
			RemoveIndent();
			WriteLn("}");
			WriteLn("void RemoveReverseMapping(const %s index)", settings.GetIndexType());
			WriteLn("{");
			AddIndent();
			for (auto iter = settings.mData.Begin(); iter != settings.mData.End(); ++iter)
			{
				if (iter->GetReverseMapping() != ion::codegen::ReverseMapping::None)
				{
					WriteLn("%s.Remove(%s);", iter->GetPathToReverseMapping().CStr(), iter->GetPathToData("index").CStr());
				}
			}
			RemoveIndent();
			WriteLn("}");
		}
	}

	const bool isWritingBody = c.mIsHeader == c.mInlining.mUtils;
	if (settings.IsCopyAllowed())
	{
		ion::StackString<256> copyBufferPars;
		copyBufferPars->Format("const %s& other", settings.mSystemName.CStr());

		WriteFunctionSignature(c, isWritingBody ? FunctionSignature::Definition : FunctionSignature::Declaration, "void", "CopyBuffer",
							   copyBufferPars.CStr());
		// WriteLn("void CopyBuffer(const %s& other)", settings.mSystemName.CStr());
		if (isWritingBody)
		{
			WriteLn("{");
			AddIndent();

			if (settings.mIndexMin != settings.mIndexMax)
			{
				WriteBufferItemCount(settings, groups, true);
			}
			WriteBufferHandling(settings, groups, BufferHandling::CopyToOldBuffer);

			RemoveIndent();
			WriteLn("}");
		}
	}

	{
		WriteFunctionSignature(c, isWritingBody ? FunctionSignature::Definition : FunctionSignature::Declaration, "void", "Clear", "");
		// WriteLn("void Clear()");
		if (isWritingBody)
		{
			WriteLn("{");
			AddIndent();
			if (settings.mIndexMax != settings.mIndexMin)
			{
				if (settings.IsMoveOperationNeeded() && IsMovingInternally)
				{
					WriteLn("%s itemCount = mIndexPool.Size();", settings.GetIndexType());
				}
				else
				{
					WriteLn("%s itemCount = mIndexPool.Max();", settings.GetIndexType());
				}

				for (auto dataIter = settings.mData.Begin(); dataIter != settings.mData.End(); ++dataIter)
				{
					if (dataIter->mDataGroup == NO_GROUP)
					{
						WriteLn("%s.Clear(itemCount);", dataIter->GetDataContainer().CStr());
					}
				}
				for (auto iter = groups.Begin(); iter != groups.End(); ++iter)
				{
					WriteLn("mG%d.Clear(itemCount);", *iter);
				}

				if (settings.IsRemapped())
				{
					WriteLn("mRemap.Clear(mIndexPool.Max());");
					WriteLn("mReverseRemap.Clear(itemCount);");
				}
			}
			RemoveIndent();
			WriteLn("}");
		}
	}

	if (c.mIsHeader)
	{
		WriteLn("constexpr size_t BufferSize(size_t capacity) const");
		WriteLn("{");
		AddIndent();
		WriteBufferHandling(settings, groups, BufferHandling::BufferSize);
		RemoveIndent();
		WriteLn("}");
	}
}

void ion::codegen::StoreWriter::GenerateFooter(CodegenContext& c)
{
	if (c.mIsHeader)
	{
		RemoveIndent();
		WriteLn("};");
		WriteLn("");
	}
#if 0
	for (uint16_t index = 0; index < settings.mEntities.Size(); index++)
	{
		WriteLn("#include \"%s.generated.h\"", settings.mEntities[index].mName.CStr());
	}
#endif
}
