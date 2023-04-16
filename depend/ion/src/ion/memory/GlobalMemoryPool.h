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

namespace ion
{

void GlobalMemoryInit();

void GlobalMemoryDeinit();

void GlobalMemoryThreadInit(UInt index);

void GlobalMemoryThreadDeinit(UInt index);

void GlobalMemoryThreadDeinit(UInt index);

void* GlobalMemoryAllocate(UInt index, size_t size, size_t aligmnet);

void* GlobalMemoryReallocate(UInt index, void* ptr, size_t size);

void GlobalMemoryDeallocate(UInt index, void* ptr);

}
