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

#include <codegen/StoreSettings.h>

namespace ion::codegen
{
struct CodegenContext
{
	StoreSettings mSettings;
	ion::Vector<uint16_t> mGroups;
	ion::StackString<1024> mStoreHeaderName;
	ion::Vector<ion::String> mStoreHeaderIncludes;
	ion::Vector<ion::String> mStoreSrcHeaderIncludes;
	ion::String mNamespaceName;
	ion::String mPrecompiledHeader;
	ion::String mTargetPath;
	ion::String mWriterName;
	ion::String mReaderName;
	ion::String mRowWriterName;
	ion::String mRowReaderName;

	struct Inlining
	{
		bool mConstructor = false;
		bool mDestructor = false;
		bool mUtils = false;
		bool IsEverythingInlined() const { return mConstructor && mDestructor && mUtils; }
	} mInlining;
	bool mIsHeader = false;

	void BuildGroups()
	{
		mGroups.Clear();
		for (auto iter = mSettings.mData.Begin(); iter != mSettings.mData.End(); ++iter)
		{
			if (iter->mDataGroup != ion::codegen::NO_GROUP)
			{
				if (ion::Find(mGroups, iter->mDataGroup) == mGroups.End())
				{
					mGroups.Add(iter->mDataGroup);
				}
			}
		}
	}
};
}  // namespace ion::codegen
