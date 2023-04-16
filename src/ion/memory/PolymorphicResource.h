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

#include <ion/debug/Error.h>

namespace ion
{

class PolymorphicResourceInterface
{
public:
	PolymorphicResourceInterface() {}
	virtual ~PolymorphicResourceInterface() {}
	virtual void* PMRAllocate(size_t len, size_t align) = 0;
	virtual void* PMRReallocate(void* p, size_t align, size_t oldSize, size_t alignment) = 0;
	virtual void PMRDeallocate(void* p, size_t) = 0;
};

class PolymorphicResource
{
public:
	PolymorphicResource() { ION_ASSERT_FMT_IMMEDIATE(false, "Invalid resource"); }
	PolymorphicResource(size_t) { ION_ASSERT_FMT_IMMEDIATE(false, "Invalid resource"); }
	PolymorphicResource(PolymorphicResourceInterface* res);
	~PolymorphicResource();
	inline void* Allocate(size_t len, size_t align) { return mResource->PMRAllocate(len, align); }
	inline void Deallocate(void* p, size_t s) { mResource->PMRDeallocate(p, s); }

private:
	PolymorphicResourceInterface* mResource;
};
}  // namespace ion
