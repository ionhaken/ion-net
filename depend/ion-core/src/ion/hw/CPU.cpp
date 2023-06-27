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
#include <ion/Base.h>

#if defined(ION_ARCH_X86)
	#if ION_EXTERNAL_CPU_INFO == 1
		#include <cpufeatures/include/cpuinfo_x86.h>
namespace ion
{
const cpu_features::X86Info info = cpu_features::GetX86Info();
bool CPUHasAVXEnabled() { return info.features.avx; }
}  // namespace ion
	#else
namespace ion
{
bool CPUHasAVXEnabled() { return true; }
}  // namespace ion
	#endif

// Check ARM Neon

#elif defined(ION_ARCH_ARM_64)
	#include <cpufeatures/include/cpuinfo_aarch64.h>
// Arm Neon always supported on 64-bit)
#elif defined(ION_ARCH_ARM_32)
	#if ION_EXTERNAL_CPU_INFO == 1
		#include <cpufeatures/include/cpuinfo_arm.h>
namespace ion
{
const cpu_features::ArmFeatures features = cpu_features::GetArmInfo().features;
bool CPUHasNeonEnabled() { return features.neon; }

}  // namespace ion

	#else
namespace ion
{
bool CPUHasNeonEnabled() { return true; }

}  // namespace ion
	#endif

#endif
