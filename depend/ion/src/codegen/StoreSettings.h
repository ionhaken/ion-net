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

#include <algorithm>

namespace ion::codegen
{
static const uint16_t NO_GROUP = UINT16_MAX;
enum class ReverseMapping : uint8_t
{
	None,	   // No reverse mapping
	Copy,	   // Mapping returns by copy
	Reference  // Mapping returns by reference. Note: Arrays are always returned by reference
};

enum class GetSetType : uint8_t
{
	Regular,	 // Getter and setter methods generated
	Constant,	 // No Setter methods generated
	Modifiable,	 // Setter method is replaced by non-constant getter method.
	Unique		 // Disallow copies
};

static size_t GetSizeBytes(size_t size)
{
	if (size < UINT8_MAX)
	{
		return 1;
	}
	else if (size < UINT16_MAX)
	{
		return 2;
	}
	else if (size < UINT32_MAX)
	{
		return 4;
	}
	else
	{
		return 8;
	}
}

static const char* GetSizeType(size_t size)
{
	switch (GetSizeBytes(size))
	{
	case 1:
		return "uint8_t";
	case 2:
		return "uint16_t";
	case 4:
		return "uint32_t";
	default:
		ION_UNREACHABLE("Invalid byte size");
	case 8:
		return "uint64_t";
	}
}

struct Data
{
	Data(const char* name, const char* type, size_t maxSize, ReverseMapping reverseMapping, GetSetType aGetSet = GetSetType::Regular,
		 uint16_t dataGroup = NO_GROUP, ion::UInt batchSize = 0, bool isTransient = false)
	  : mName(name),
		mBatchSize(batchSize),
		mType(type),
		mDataGroup(dataGroup),
		mMaxSize(maxSize),
		mReverseMapping(reverseMapping),
		mGetSetType(aGetSet),
		mIsTransient(isTransient)
	{
		if (reverseMapping != ReverseMapping::None && mMaxSize > 1)
		{
			reverseMapping = ReverseMapping::Reference;
		}
	}

	ion::String mType;
	ion::UInt mBatchSize;
	size_t mMaxSize;
	uint16_t mDataGroup;

	bool HasSetter() const { return mGetSetType == GetSetType::Regular; }

	bool HasNonConstGetter() const { return mGetSetType == GetSetType::Modifiable || mGetSetType == GetSetType::Unique; }

	bool IsUnique() const { return mGetSetType == GetSetType::Unique; }

	const ion::String GetTypeParam(size_t maxNumberOfComponents = 0, bool isConst = true, bool useRef = true) const
	{
		ion::StackString<256> buffer;
		if (mMaxSize == 1)
		{
			if (isPointer())
			{
				buffer->Format("%s%s", mType.CStr(), isConst ? " const" : "");
			}
			else
			{
				buffer->Format("%s%s%s", isConst ? "const " : "", mType.CStr(), useRef ? "&" : "");
			}
		}
		else
		{
			ion::String typeId = GetTypeId(maxNumberOfComponents);
			buffer->Format("%sion::MultiData<%s, %s>", isConst ? "const " : "", mType.CStr(), typeId.CStr());
		}
		return buffer;
	}

	bool isPointer() const { return mType.SubStr(mType.Length() - 1, 1) == "*"; }

	const ion::String GetAsCallParam() const
	{
		ion::StackString<256> buffer;
		if (mGetSetType == GetSetType::Unique)
		{
			buffer->Format("%s&&", mType.CStr());
		}
		else if (isPointer())
		{
			buffer->Format("%s%s", mType.CStr(), mMaxSize > 1 ? "*" : "");
		}
		else
		{
			buffer->Format("const %s%s", mType.CStr(), mMaxSize > 1 ? "*" : "&");
		}
		return buffer;
	}

	size_t GetVectorMaxSize(size_t maxNumberOfComponents) const
	{
		size_t sizeBytes = GetSizeBytes(mMaxSize);
		return maxNumberOfComponents * (mMaxSize + sizeBytes);
	}

	const ion::String GetType(size_t maxNumberOfComponents) const
	{
		if (mMaxSize == 1)
		{
			return GetTypeId(maxNumberOfComponents);
		}
		else
		{
			ion::StackString<256> buffer;
			buffer->Format("ion::ComponentDataVector<%s, %s, %s>", mType.CStr(), GetSizeType(GetVectorMaxSize(maxNumberOfComponents)),
						   GetSizeType(mMaxSize));
			return buffer;
		}
	}

	const ion::String GetTypeId(size_t maxNumberOfComponents) const
	{
		if (mMaxSize == 1)
		{
			if (mBatchSize == 0)
			{
				return mType;
			}
			ion::StackString<256> buffer;
			buffer->Format("ion::Batch<%s, %u>", mType.CStr(), mBatchSize);
			return buffer;
		}
		else
		{
			return ion::String(GetSizeType(GetVectorMaxSize(maxNumberOfComponents)));
		}
	}

	ion::String GetDataContainer(bool isNatvis = false) const
	{
		ion::StackString<256> string;
		if (mDataGroup == ion::codegen::NO_GROUP)
		{
			string->Format("m%s.m%s", mMaxSize > 1 ? "DynamicData" : "Data", mName.CStr());
		}
		else
		{
			string->Format("mG%d%s", mDataGroup, isNatvis ? ".mData" : "");
		}
		return string;
	}

	ion::String GetDataStructure(const char* indexName, bool isNatvis = false) const
	{
		ion::StackString<256> string;
		if (mDataGroup == ion::codegen::NO_GROUP)
		{
			string->Format("%s[%s]", GetDataContainer(isNatvis).CStr(), indexName);
		}
		else
		{
			string->Format("%s[%s].m%s", GetDataContainer(isNatvis).CStr(), indexName, mName.CStr());
		}
		return string;
	}

	const ion::String GetPathToReverseMapping() const
	{
		ION_ASSERT(GetReverseMapping() != ReverseMapping::None, "Data does not have reverse mapping");
		ion::StackString<256> string;
		string->Format("m%sToIndex", mName.CStr());
		return string;
	}

	const ion::String GetName() const { return mName; }

	const ion::String GetTrackingCall(const size_t callIndex, bool isWriting = false, const char* index = nullptr) const
	{
		ion::StackString<256> string;
		if (mMaxSize > 1)
		{
			string->Format("mStore.TrackCache(%d, &%s); mStore.TrackCache(%d, %s.data%s); ", callIndex,
						   GetPathToNonDynamicData(index).CStr(), callIndex + 1, GetPathToData(index).CStr(), isWriting ? ", true" : "");
		}
		else
		{
			string->Format("mStore.TrackCache(%d, &%s%s); ", callIndex, GetPathToData(index).CStr(), isWriting ? ", true" : "");
		}
		return string;
	}

	const ion::String GetPathToNonDynamicData(const char* index = nullptr, bool isNatvis = false) const
	{
		ion::StackString<256> string;
		string->Format("%s%s", index ? "" : "mStore.", GetDataStructure(index ? index : "mIndex", isNatvis).CStr());
		return string;
	}

	const ion::String GetPathToData(const char* index = nullptr, bool isNatvis = false) const
	{
		if (mMaxSize > 1)
		{
			ion::StackString<256> string;
			string->Format("%smDynamicData.m%s.Get(%s)", index ? "" : "mStore.", mName.CStr(),
						   GetPathToNonDynamicData(index, isNatvis).CStr());
			return string;
		}
		else
		{
			return GetPathToNonDynamicData(index, isNatvis);
		}
	}

	const ReverseMapping GetReverseMapping() const { return mReverseMapping; }
	bool IsTransient() const { return mIsTransient; }

private:
	ion::String mName;
	ReverseMapping mReverseMapping;
	GetSetType mGetSetType;
	bool mIsTransient;
};

struct StoreSettings
{
	struct DataAccess
	{
		DataAccess(const char* data) : mDataName(data) {}
		ion::String mDataName;
	};

	struct Component
	{
		Component(const char* name) : mName(name) {}

		ion::String GetName()
		{
			ion::StackString<256> name;
			name->Format("%sComponent", mName.CStr());
			return name.CStr();
		}

		ion::String GetConstName()
		{
			ion::StackString<256> name;
			name->Format("Const%sComponent", mName.CStr());
			return name.CStr();
		}

		ion::String mName;
		ion::Vector<DataAccess> mDataAccess;
	};

	const char* GetIndexType() const { return GetSizeType(mIndexMax); }

	bool HasGrouplessData() const
	{
		for (auto iter = mData.Begin(); iter != mData.End(); ++iter)
		{
			if (iter->mDataGroup == NO_GROUP)
			{
				return true;
			}
		}
		return false;
	}

	bool HasBatchData() const
	{
		for (auto iter = mData.Begin(); iter != mData.End(); ++iter)
		{
			if (iter->mBatchSize > 1)
			{
				return true;
			}
		}
		return false;
	}

	bool HasDynamicData() const
	{
		for (auto iter = mData.Begin(); iter != mData.End(); ++iter)
		{
			if (iter->mMaxSize > 1)
			{
				return true;
			}
		}
		return false;
	}

	bool HasReverseMaps() const
	{
		auto iter = std::find_if(mData.Begin(), mData.End(),
								 [](const Data& data) -> bool { return data.GetReverseMapping() != ReverseMapping::None; });
		return iter != mData.End();
	}

	bool HasReferencedReverseMaps() const
	{
		auto iter = std::find_if(mData.Begin(), mData.End(),
								 [](const Data& data) -> bool { return data.GetReverseMapping() == ReverseMapping::Reference; });
		return iter != mData.End();
	}

	ion::String GetDataContainer(ion::String type)
	{
		ion::StackString<256> string;
		if (mIndexMin == mIndexMax)
		{
			string->Format("ion::Array<%s, %lu>", type.CStr(), mIndexMin);
		}
		else
		{
			string->Format("ion::RawBuffer<%s>", type.CStr());
		}
		return string;
	}

	enum class Layout : uint8_t
	{
		Lazy,	   // Non-contiguous data allowed
		Remapped,  // Ids are remapped to actual data
		Strict,	   // Data is always contiguous, but no Ids available
		Manual	   // User is responsible for moving data (Not implemented)
	};

	enum class Stats : uint8_t
	{
		None,
		All
	};

	bool HasCacheTracking() const { return mStats == Stats::All; }

	bool IsDataLayoutStrict() const { return mLayout == Layout::Strict; }

	bool IsRemapped() const { return mLayout == Layout::Remapped; }

	bool IsMoveOperationNeeded() const { return mLayout != Layout::Lazy; }

	ion::Vector<size_t> GetParamOrder()
	{
		ion::Vector<size_t> tmp;
		tmp.Resize(mData.Size());
		for (size_t i = 0; i < mData.Size(); i++)
		{
			size_t pos = 0;
			for (size_t j = 0; j < mData.Size(); j++)
			{
				if (i != j)
				{
					if (mData[j].GetName().Compare(mData[i].GetName()) < 0)
					{
						pos++;
					}
				}
			}
			tmp[pos] = i;
		}
		return tmp;
	}

	ion::String GetCreateParams(CreateMethodSignature signature, CreateMethodType type, bool isCall)
	{
		const int BufferSize = 1024;
		char buffer[BufferSize];
		int pos = 0;
		bool isFirst = true;

		if (signature == CreateMethodSignature::Private)
		{
			if (!isCall)
			{
				int numWritten = sprintf_s(&buffer[pos], BufferSize - pos, "const %s index", GetIndexType());
				// HasInitVars(settings) ? "index" : "/*index*/");
				pos += numWritten;
			}
			else
			{
				int numWritten = sprintf_s(&buffer[pos], BufferSize - pos, "index");
				pos += numWritten;
			}
			isFirst = false;
		}

		auto order = GetParamOrder();  // Use ASCII order for parameters
		for (size_t i = 0; i < mData.Size(); i++)
		{
			ion::codegen::Data& data = mData[order[i]];

			if (data.mMaxSize <= 1 || (signature != CreateMethodSignature::Private))
			{
				if (!isCall)
				{
					int numWritten = sprintf_s(&buffer[pos], BufferSize - pos, "%s%s%s ", isFirst ? "" : ", ", data.GetAsCallParam().CStr(),
											   /*type == CreateMethodType::Move ? "&" :*/ "");
					pos += numWritten;
					isFirst = false;
				}

				if (!isCall || type != CreateMethodType::Assign)
				{
					{
						int numWritten = sprintf_s(&buffer[pos], BufferSize - pos, "%s", !isCall || isFirst ? "" : ", ");
						pos += numWritten;
					}

					if (isCall && data.IsUnique())
					{
						int numWritten = sprintf_s(&buffer[pos], BufferSize - pos, "std::move(a%s)", data.GetName().CStr());
						pos += numWritten;
					}
					else
					{
						int numWritten = sprintf_s(&buffer[pos], BufferSize - pos, "a%s", data.GetName().CStr());
						pos += numWritten;
					}
				}
				else
				{
					/*if (type == CreateMethodType::Move)
					{
						int numWritten = sprintf_s(&buffer[pos], BufferSize - pos, "%sstd::move(%s)",
							!isCall || isFirst ? "" : ", ",
							data.GetDataStructure("source").CStr());
						pos += numWritten;
					}
					else*/
					{
						int numWritten = sprintf_s(&buffer[pos], BufferSize - pos, "%s%s", !isCall || isFirst ? "" : ", ",
												   data.GetDataStructure("source").CStr());
						pos += numWritten;
					}
				}
				isFirst = false;
			}

			if (data.mMaxSize > 1 && (signature != CreateMethodSignature::Private))
			{
				int numWritten = sprintf_s(&buffer[pos], 1024 - pos, ", %s a%sSize", GetSizeType(data.mMaxSize), data.GetName().CStr());
				pos += numWritten;
			}
		}
		return buffer;
	}

	bool IsCopyAllowed() const
	{
		for (size_t i = 0; i < mData.Size(); i++)
		{
			if (mData[i].IsUnique())
			{
				return false;
			}
		}
		return true;
	}

	size_t mIndexMin;
	size_t mIndexMax;
	size_t mIndexAverage;

	ion::String mSystemName;
	ion::String mResource;
	ion::Vector<Data> mData;
	ion::Vector<Component> mComponents;
	Stats mStats = Stats::None;
	Layout mLayout = Layout::Lazy;

private:
};
}  // namespace ion::codegen
