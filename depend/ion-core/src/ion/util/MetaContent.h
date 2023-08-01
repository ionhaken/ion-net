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

#include <ion/string/String.h>
#include <ion/container/UnorderedMap.h>

namespace ion
{
using ContentUID = uint64_t;

struct ContentLayer
{
	ion::String mName;
	ion::String mFilename;
};

using ContentLayers = ion::UnorderedMap<ContentUID, ContentLayer>;

struct MetaContent
{
	ion::UnorderedMap<ion::String, ContentLayers> mContentTypeToLayers;
};
}  // namespace ion
