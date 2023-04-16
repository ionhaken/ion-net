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
#include <ion/JSON/JSONSerialization.h>
#include <codegen/StoreSettings.h>

namespace ion::codegen
{
class Reader : public ion::JSONDocument
{
	ion::String GetString(const char* name, const char* defaultName = "") const
	{
		ion::String tmp = defaultName;
		if (mDocument.HasMember(name) && mDocument[name].IsString())
		{
			tmp = mDocument[name].GetString();
		}
		return tmp;
	}

public:
	ion::Vector<ion::String> StoreHeaderIncludes(const char* id, uint16_t index)
	{
		ion::Vector<ion::String> headers;
		if (mDocument["model"].IsArray())
		{
			ion::JSONArrayReader model(*this, "model");
			if (model.IsValid())
			{
				ion::JSONStructReader system(model, index);
				headers = system.GetStringVector(id);
			}
		}
		return headers;
	}

	ion::String RowWriterName() const { return GetString("row_writer", "ion::JSONStructWriter"); }

	ion::String RowReaderName() const { return GetString("row_reader", "ion::JSONStructReader"); }

	ion::String WriterName() const { return GetString("writer", "ion::JSONArrayWriter"); }

	ion::String ReaderName() const { return GetString("reader", "ion::JSONArrayReader"); }

	ion::String Namespace() const { return GetString("namespace"); }

	ion::String PrecompiledHeader() const { return GetString("precompiled_header"); }

	ion::String Namespace(uint16_t index) const
	{
		const auto& system = mDocument["model"][index];
		if (system.HasMember("namespace") && system["namespace"].IsString())
		{
			ion::String tmp(system["namespace"].GetString());
			if (!tmp.IsEmpty())
			{
				return tmp;
			}
		}
		return Namespace();
	}

	uint16_t GetNumComponents()
	{
		if (mDocument["model"].IsArray())
		{
			return static_cast<uint16_t>(mDocument["model"].Size());
		}
		return 0;
	}

	void GetSystem(uint16_t index, ion::codegen::StoreSettings& settings)
	{
		const auto& system = mDocument["model"][index];
		ion::String systemName = system["name"].GetString();
		ION_LOG_INFO("Processing " << systemName.CStr());

		if (system.HasMember("resource"))
		{
			settings.mResource = system["resource"].GetString();
		}

		if (system.HasMember("layout"))
		{
			ion::String layout = system["layout"].GetString();
			if (layout == "strict")
			{
				settings.mLayout = ion::codegen::StoreSettings::Layout::Strict;
			}
			else if (layout == "remapped")
			{
				settings.mLayout = ion::codegen::StoreSettings::Layout::Remapped;
			}
			else if (layout == "lazy")
			{
				settings.mLayout = ion::codegen::StoreSettings::Layout::Lazy;
			}
			else
			{
				ION_WRN("Invalid 'layout' value: " << layout);
			}
		}

		settings.mIndexMax = system["indexMax"].GetInt();
		if (system.HasMember("indexMin"))
		{
			settings.mIndexMin = system["indexMin"].GetInt();
		}
		else
		{
			settings.mIndexMin = 0;
		}
		settings.mIndexAverage = 0;
		if (system.HasMember("indexEstimate"))
		{
			settings.mIndexAverage = system["indexEstimate"].GetInt();
		}

		if (system.HasMember("stats") && system["stats"].IsString())
		{
			ion::String stats(system["stats"].GetString());
			if (stats == "all")
			{
				settings.mStats = ion::codegen::StoreSettings::Stats::All;
			}
			else if (stats == "none")
			{
				settings.mStats = ion::codegen::StoreSettings::Stats::None;
			}
			else
			{
				ION_WRN("Invalid 'stats' value:" << stats);
			}
		}
		if (!system.HasMember("data"))
		{
			ION_WRN("Data field not found!");
			return;
		}

		ion::UInt batchSize = 0;
		if (system.HasMember("batchSize"))
		{
			batchSize = system["batchSize"].GetUint();
		}

		const auto& data = system["data"];
		for (size_t i = 0; i < data.Size(); i++)
		{
			const auto& dataMember = data[static_cast<int>(i)];
			const auto& name = dataMember["name"];
			const auto& type = dataMember["type"];

			uint16_t groupId = ion::codegen::NO_GROUP;

			if (dataMember.HasMember("group"))
			{
				const auto& group = dataMember["group"];
				if (group.IsNumber())
				{
					groupId = static_cast<uint16_t>(group.GetInt());
				}
			}

			size_t maxNumberOfElements = 1;
			if (dataMember.HasMember("maxSize"))
			{
				const auto& maxSize = dataMember["maxSize"];
				if (!maxSize.IsNull())
				{
					if (maxSize.IsNumber())
					{
						maxNumberOfElements = static_cast<size_t>(maxSize.GetInt());
					}
					else
					{
						ION_WRN("maxSize is not a number");
					}
				}
			}

			ion::codegen::ReverseMapping reverseMapping = ion::codegen::ReverseMapping::None;
			if (dataMember.HasMember("reverseMap"))
			{
				const auto& reverseMap = dataMember["reverseMap"];
				if (!reverseMap.IsNull() && reverseMap.IsString())
				{
					ion::String jsonString(reverseMap.GetString());
					if (jsonString == "copy")
					{
						reverseMapping = ion::codegen::ReverseMapping::Copy;
					}
					if (jsonString == "reference")
					{
						reverseMapping = ion::codegen::ReverseMapping::Reference;
					}
				}
			}

			ion::String fullTypeString(type.GetString());
			ion::Vector<ion::String> types;
			fullTypeString.Tokenize(types);
			GetSetType getSetType = GetSetType::Regular;
			bool isTransient = false;
			for (size_t j = 0; j < types.Size() - 1; ++j)
			{
				if (types[j] == "const")
				{
					getSetType = GetSetType::Constant;
				}
				else if (types[j] == "modifiable")
				{
					getSetType = GetSetType::Modifiable;
				}
				else if (types[j] == "unique")
				{
					getSetType = GetSetType::Unique;
				}
				else if (types[j] == "transient")
				{
					isTransient = true;
				}
				else
				{
					ION_WRN("Invalid type: " << fullTypeString.CStr());
				}
			}

			settings.mData.Add(ion::codegen::Data(name.GetString(), types[types.Size() - 1].CStr(), maxNumberOfElements, reverseMapping,
												  getSetType, groupId, batchSize, isTransient));
		}

		{
			ion::codegen::StoreSettings::Component e(systemName.CStr());
			settings.mComponents.Add(e);
		}

		{
			ion::StackString<1024> buffer;
			buffer->Format("%sStore", systemName.CStr());
			settings.mSystemName = buffer.CStr();
		}
	}
};
}  // namespace ion::codegen
