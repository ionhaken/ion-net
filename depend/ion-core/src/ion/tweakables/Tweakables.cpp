/*
 * Copyright 2023 Markus Haikonen, Ionhaken
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
#include <ion/tweakables/Tweakables.h>
#include <ion/core/StaticInstance.h>
#include <ion/container/UnorderedMap.h>
#include <ion/string/String.h>
#include <ion/memory/ThreadSafeResource.h>
#include <ion/memory/TLSFResource.h>
#include <ion/arena/ArenaAllocator.h>
#include <ion/container/ForEach.h>
#include <ion/core/Engine.h>
#include <ion/json/JSONDocument.h>
#include <ion/json/JSONSerialization.h>
#include <ion/byte/ByteBuffer.h>
#include <ion/debug/AccessGuard.h>

namespace ion
{
namespace tweakables
{
using Resource = ThreadSafeResource<TLSFResource<MonotonicBufferResource<64 * 1024, ion::tag::Debug>, ion::tag::Debug>>;

// This is used in dynamic init: Increase static allocation if needed
using String = ion::BasicString<ion::ArenaAllocator<char, Resource>>;
}  // namespace tweakables

template <>
inline size_t Hasher<tweakables::String>::operator()(const tweakables::String& key) const
{
	return ion::HashDJB2(key.CStr());
}

namespace tweakables
{
struct TweakableData
{
	using TweakableMap = ion::UnorderedMap<tweakables::String, ConfigValueBase*, Hasher<tweakables::String>,
										   ArenaAllocator<ion::Pair<const tweakables::String, ConfigValueBase*>, Resource>>;

	struct PendingValue
	{
		tweakables::String mValue;
		bool mIsCommandLineParameter;
	};

	using PendingMap = ion::UnorderedMap<tweakables::String, PendingValue, Hasher<tweakables::String>,
										 ArenaAllocator<ion::Pair<const tweakables::String, PendingValue>, Resource>>;

	TweakableData(Resource& resource) : mCommandToTweakable(&resource, 8), mPendingTweakables(&resource, 8) {}
	TweakableMap mCommandToTweakable;
	PendingMap mPendingTweakables;	// Pending values for unloaded tweakables
	ION_ACCESS_GUARD(mGuard);

	~TweakableData() {}
};

STATIC_INSTANCE(TweakableData, Resource);

void AddTweakable(const char* id, ConfigValueBase& owner, tweakables::Type type)
{
	ION_ASSERT(type == tweakables::Type::Tweakable || !ion::Engine::IsDynamicInitExit(), "Config values cannot be static");
#if ION_TWEAKABLES
	if (type == tweakables::Type::Tweakable)
	{
		ION_ASSERT(ion::Engine::IsDynamicInitExit(), "Tweakables must be static");
		// Tweakables are added in dynamic init, so we need to implicitly initialize data.
		TweakablesInit();
	}
#endif
	ION_ACCESS_GUARD_WRITE_BLOCK(Instance().mGuard);
	tweakables::String str(&Source(), id);
	ION_ASSERT(Instance().mCommandToTweakable.Find(str) == Instance().mCommandToTweakable.End(), "Duplicate config value:" << id);
	Instance().mCommandToTweakable.Insert(std::move(str), &owner);
	auto iter = Instance().mPendingTweakables.Find(str);
	if (iter != Instance().mPendingTweakables.End())
	{
		owner.Set(iter->second.mValue.CStr());
		if (iter->second.mIsCommandLineParameter)
		{
			owner.DisableSerialization();
		}
		if (type != tweakables::Type::Config)  // Config value might be used again if ConfigValue is reinstantiated
		{
			Instance().mPendingTweakables.Erase(iter);
		}
	}
}

void GetTweakable(const char* id, char* buffer, size_t bufferLen)
{
	ION_ACCESS_GUARD_READ_BLOCK(Instance().mGuard);
	tweakables::String str(&Source(), id);
	auto iter = Instance().mCommandToTweakable.Find(str);
	if (iter != Instance().mCommandToTweakable.End())
	{
		iter->second->Get(buffer, bufferLen);
	}
	else
	{
		ION_ABNORMAL("Unknown tweakable " << id);
		buffer[0] = 0;
	}
}

void SetTweakable(const char* id, const char* newValue, bool isCommandLine)
{
	ION_MEMORY_SCOPE(ion::tag::Debug);
	TweakablesInit();
	ION_ACCESS_GUARD_WRITE_BLOCK(Instance().mGuard);
	tweakables::String str(&Source(), id);
	auto iter = Instance().mCommandToTweakable.Find(str);
	if (iter != Instance().mCommandToTweakable.End())
	{
		iter->second->Set(newValue);
		if (isCommandLine)
		{
			iter->second->DisableSerialization();
		}
	}
	else
	{
		tweakables::String strValue(&Source(), newValue);
		auto piter = Instance().mPendingTweakables.Find(str);
		if (piter == Instance().mPendingTweakables.End())
		{
			Instance().mPendingTweakables.Insert(std::move(str), TweakableData::PendingValue{std::move(strValue), isCommandLine});
		}
		else
		{
			piter->second = TweakableData::PendingValue{std::move(strValue), true};
		}
	}
}

void RemoveTweakable(ConfigValueBase&)
{
	// #TODO: ignore if in dynamic atexit
	// #TODO: Need reverse mapping - use component store?
}

bool Load([[maybe_unused]] const ion::String& data)
{
	bool isLoaded = false;
#if ION_EXTERNAL_JSON
	if (data.IsEmpty())
	{
		return true;
	}
	ion::JSONDocument doc;
	doc.Parse("config", data);
	if (doc.HasLoaded())
	{
		doc.ForEachMember(
		  [&](auto& name, auto& value)
		  {
			  if (name.IsString() && value.IsString())
			  {
				  ION_LOG_INFO("Config " << name.GetString() << "=" << value.GetString());
				  ion::tweakables::SetTweakable(name.GetString(), value.GetString());
			  }
		  });

		isLoaded = true;
	}
#endif
	return isLoaded;
}

void Save([[maybe_unused]] ion::String& s)
{
#if ION_EXTERNAL_JSON
	ion::Vector<ion::String> valueTmp;
	ion::Vector<ion::String> nameTmp;
	valueTmp.Reserve(Instance().mCommandToTweakable.Size());
	nameTmp.Reserve(Instance().mCommandToTweakable.Size());

	std::string data;
	{
		ion::JSONDocument doc;
		{
			{
				ion::ForEach(Instance().mCommandToTweakable,
							 [&](const ion::Pair<tweakables::String, ConfigValueBase*>& pair)
							 {
								 if (pair.second->ShouldSave())
								 {
									 nameTmp.Add(pair.first.CStr());
									 char buffer[1024];
									 pair.second->Get(buffer, 1024);
									 valueTmp.Add(buffer);
									 ION_DBG("Saving config " << nameTmp.Back().CStr() << "=" << valueTmp.Back().CStr());
									 doc.Set(nameTmp.Back().CStr(), valueTmp.Back().CStr());
								 }
							 });
			}
		}
		ion::ByteBuffer<> buffer(16 * 1024);
		doc.Save(buffer);
		ion::ByteReader reader(buffer);
		while (reader.Available())
		{
			const char& c = reader.ReadAssumeAvailable<char>();
			data = data + c;
		}
	}
	s = data.c_str();
#endif
}
}  // namespace tweakables

template <>
void ConfigValue<bool>::Set(const char* str)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
	if (str != nullptr && *str != 0)
	{
		if (str[0] == 't' || str[0] == '1')
		{
			mValue = true;
			return;
		}
		else
		{
			mValue = false;
			return;
		}
	}
	mValue = !mValue;
}

template <>
void ConfigValue<ion::UInt>::Set(const char* value)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
	StringReader reader(value, StringLen(value));
	serialization::Deserialize(mValue, reader);
}

template <>
void ConfigValue<uint64_t>::Set(const char* value)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
	StringReader reader(value, StringLen(value));
	serialization::Deserialize(mValue, reader);
}

template <>
void ConfigValue<ion::Int>::Set(const char* value)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
	ion::Int tmp;
	StringReader reader(value, StringLen(value));
	serialization::Deserialize(tmp, reader);
	mValue = ion::MinMax(mMin, tmp, mMax);
}

template <>
void ConfigValue<float>::Set(const char* value)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
	float tmp;
	StringReader reader(value, StringLen(value));
	serialization::Deserialize(tmp, reader);
	mValue = ion::MinMax(mMin, tmp, mMax);
}

void ConfigString::Set(const char* value)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
	mValue = value;
}

void TweakablesInit()
{
	ION_MEMORY_SCOPE(ion::tag::Debug);
	ION_ACCESS_GUARD_WRITE_BLOCK(tweakables::gGuard);
	tweakables::Init([]() {});
}
void TweakablesDeinit()
{
	ION_MEMORY_SCOPE(ion::tag::Debug);
	ION_ACCESS_GUARD_WRITE_BLOCK(tweakables::gGuard);

	tweakables::gRefCount--; // Don't care about ref count, because tweakables are initialized dynamically
	tweakables::gIsInitialized = false;
#if ION_CLEAN_EXIT
	tweakables::gInstance.Deinit();
#endif
}
}  // namespace ion
