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
#include <ion/string/String.h>
#include <ion/string/StringUtil.h>
#include <ion/string/StringView.h>

namespace ion
{
const char gNullString = 0;

StringView::StringView() : mArray(&gNullString, 0) {}

StringView::StringView(const String& str) : StringView(str.Data(), str.Length()) {}

[[nodiscard]] bool StringView::operator==(const char* str) const
{
	return ion::StringCompare(str, mArray.Data(), Length()) == 0 && str[Length()] == 0;
}

}  // namespace ion
