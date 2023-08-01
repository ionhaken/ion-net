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
#include <ion/util/Fraction.h>
#include <ion/util/Wider.h>
#include <ion/util/SafeRangeCast.h>

#include <fxpoint/Fixed.h>

namespace ion
{
template <>
inline void tracing::Handler(LogEvent& e, const ion::Fixed32& value)  // , char* buffer, size_t size)
{
	char buffer[32];
	snprintf(buffer, 32, "%f", static_cast<float>(value));
	e.Write(buffer);
}

}  // namespace ion
