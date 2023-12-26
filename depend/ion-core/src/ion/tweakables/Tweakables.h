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
#pragma once
#include <ion/Base.h>
#include <ion/debug/AccessGuard.h>
#include <ion/string/StringUtil.h>
#include <ion/string/String.h>

#define TWEAKABLE_VALUE(__name) g##__name

namespace ion
{
class String;
class ConfigValueBase
{
public:
	ConfigValueBase() : mIsSerialized(true) {}
	virtual void Set(const char* str) = 0;
	virtual void Get(char* buffer, size_t bufferLen) const = 0;
	virtual bool ShouldSave() const = 0;
	virtual ~ConfigValueBase() {}

	void DisableSerialization() { mIsSerialized = false; }

protected:
	bool IsSerialized() const { return mIsSerialized; }
	bool mIsSerialized;
};

class Folder;

void TweakablesInit();
void TweakablesDeinit();

namespace tweakables
{
enum class Type : int
{
	Tweakable,
	Config
};

void AddTweakable(const char* id, ConfigValueBase& owner, tweakables::Type type);
void RemoveTweakable(ConfigValueBase& owner);
void SetTweakable(const char* id, const char* newValue, bool isCommandLine = false);
void GetTweakable(const char* id, char* buffer, size_t bufferLen);
bool Load(const ion::String& data);
void Save(ion::String& buffer);
}  // namespace tweakables

template <typename T>
class ConfigValue : public ConfigValueBase
{
public:
	ConfigValue(const char* id, const T& value, const T& min, const T& max)
	  : ConfigValueBase(), mDefaultValue(value), mValue(value), mMin(min), mMax(max)
	{
		ION_ASSERT(value >= min, "Invalid default value=" << value);
		ION_ASSERT(value <= max, "Invalid default value=" << value);
		tweakables::AddTweakable(id, *this, tweakables::Type::Config);
	}

	ConfigValue(tweakables::Type type, const char* id, const T& value, const T& min, const T& max)
	  : ConfigValueBase(), mDefaultValue(value), mValue(value), mMin(min), mMax(max)
	{
		ION_ASSERT(type == tweakables::Type::Tweakable, "Constructor for tweakables only");
		ION_ASSERT(value >= min, "Invalid default value=" << value);
		ION_ASSERT(value <= max, "Invalid default value=" << value);
		tweakables::AddTweakable(id, *this, type);
	}

	~ConfigValue() { tweakables::RemoveTweakable(*this); }

	T& operator=(const T& value)
	{
		ION_ACCESS_GUARD_WRITE_BLOCK(mGuard);
		mValue = ion::MinMax(mMin, value, mMax);
		return mValue;
	}

	operator T() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mValue;
	}

	virtual void Set(const char* str) final;

	void Get(char* buffer, size_t bufferLen) const override 
	{ 
		StringWriter writer(buffer, bufferLen);
		ion::serialization::Serialize(mValue, writer); 
	}
	bool ShouldSave() const final { return mValue != mDefaultValue && ConfigValueBase::IsSerialized(); }

protected:
	ION_ACCESS_GUARD(mGuard);

private:
	T mDefaultValue;
	T mValue;
	T mMin;
	T mMax;
};

class ConfigString : public ConfigValueBase
{
public:
	ConfigString(const char* id, const char* defaultValue = nullptr) : mDefaultValue(defaultValue ? defaultValue : ""), mValue()
	{
		if (defaultValue)
		{
			mValue = defaultValue;
		}
		tweakables::AddTweakable(id, *this, tweakables::Type::Config);
	}

	~ConfigString() { tweakables::RemoveTweakable(*this); }

	ConfigString& operator=(const char* str)
	{
		Set(str);
		return *this;
	}

	ConfigString& operator=(const ion::String& str)
	{
		Set(str.CStr());
		return *this;
	}

	// Note: due to having access guard checks, do not add direct access to data.
	operator ion::String() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return ion::String(mValue.CStr());
	}

	void Set(const char* str) final;

	void Get(char* buffer, size_t bufferLen) const override { ion::StringCopy(buffer, bufferLen, mValue.CStr()); }

	bool IsSet() const
	{
		ION_ACCESS_GUARD_READ_BLOCK(mGuard);
		return mValue.Length() > 0;
	}

	bool ShouldSave() const final { return mValue.Compare(mDefaultValue) != 0 && ConfigValueBase::IsSerialized(); }

protected:
	ION_ACCESS_GUARD(mGuard);

private:
	ion::String mDefaultValue;
	ion::String mValue;
};

namespace tracing
{
template <typename T>
inline void Handler(LogEvent& e, const ion::ConfigValue<T>& value)
{
	char buffer[64];
	T raw = value;
	StringWriter writer(buffer, 64);
	ion::serialization::Serialize(raw, writer);
	e.Write(buffer);
}

inline void Handler(LogEvent& e, const ion::ConfigString& value)
{
	ion::String str = value;
	e.Write(str.CStr());
}
}  // namespace tracing
}  // namespace ion
#if ION_TWEAKABLES

	#define TWEAKABLE_TYPE(__command, __name, __value, __type, __minValue, __maxValue) \
		/*static __type g##__name = __value;*/                                       \
		static ion::ConfigValue<__type> g##__name(ion::tweakables::Type::Tweakable, __command, __value, __minValue, __maxValue);

	#define TWEAKABLE_BOOL(__command, __name, __value) TWEAKABLE_TYPE(__command, __name, __value, bool, false, true)
	#define TWEAKABLE_UINT(__command, __name, __minValue, __value, __maxValue) \
		TWEAKABLE_TYPE(__command, __name, __value, ion::UInt, __minValue, __maxValue)
	#define TWEAKABLE_FLOAT(__command, __name, __minValue, __value, __maxValue) \
		TWEAKABLE_TYPE(__command, __name, __value, float, __minValue, __maxValue)
	#define TWEAKABLE_IS_EQUAL(__name, __value) (g##__name == __value)
	#define TWEAKABLE_IS_GT(__name, __value)	(g##__name > __value)
	#define TWEAKABLE_SET(__name, __value)		g##__name##Store = __value
#else
	#define TWEAKABLE_BOOL(__command, __name, __value)							static constexpr bool g##__name = __value;
	#define TWEAKABLE_UINT(__command, __name, __minValue, __value, __maxValue)	static constexpr ion::UInt g##__name = __value;
	#define TWEAKABLE_FLOAT(__command, __name, __minValue, __value, __maxValue) static constexpr float g##__name = __value;
	#define TWEAKABLE_IS_EQUAL(__name, __value)									constexpr(ION_CONCATENATE(g, __name) == __value)
	#define TWEAKABLE_IS_GT(__name, __value)									constexpr(g##__name > __value)
#endif
