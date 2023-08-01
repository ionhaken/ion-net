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
#include <ion/concurrency/Thread.h>
#include <ion/util/Fraction.h>

namespace ion
{
class Random
{
public:
	Random(uint64_t seed = 0);

	// Thread local u32
	static inline uint32_t UInt32Tl() { return static_cast<uint32_t>(Xoroshiro128Plus(ion::Thread::GetRandState())); }
	// Thread local u64
	static inline uint64_t UInt64Tl() { return static_cast<uint64_t>(Xoroshiro128Plus(ion::Thread::GetRandState())); }
	// Thread local float
	static inline float FastFloat() { return static_cast<float>(Dec64(ion::Thread::GetRandState())); }
	// Thread local double
	static inline double FastDouble() { return static_cast<double>(Dec64(ion::Thread::GetRandState())); }

	inline uint32_t UInt32() { return static_cast<uint32_t>(Xoroshiro128Plus(mState)); }
	inline uint64_t UInt64() { return Xoroshiro128Plus(mState); }

	inline float GetFastFloat() { return static_cast<float>(Dec64(mState)); }
	inline double GetFastDouble() { return static_cast<double>(Dec64(mState)); }

	static void Seed(uint64_t seed, uint64_t* state);

private:
	uint64_t mState[2];

	static inline Fraction<uint16_t> Dec16(uint64_t* state)
	{
		return Fraction<uint16_t>(static_cast<uint16_t>(Xoroshiro128Plus(state)), UINT16_MAX);
	}

	static inline Fraction<uint32_t> Dec32(uint64_t* state)
	{
		return Fraction<uint32_t>(static_cast<uint32_t>(Xoroshiro128Plus(state)), UINT32_MAX);
	}

	static inline Fraction<uint64_t> Dec64(uint64_t* state)
	{
		return Fraction<uint64_t>(static_cast<uint64_t>(Xoroshiro128Plus(state)), UINT64_MAX);
	}

	// xorshift*: https://en.wikipedia.org/wiki/Xorshift
	static inline uint64_t XorShift64Star(uint64_t* state)
	{
		ION_ASSERT(state[0] != 0, "Invalid seed");
		uint64_t x = state[0];
		x ^= x >> 12;  // a
		x ^= x << 25;  // b
		x ^= x >> 27;  // c
		state[0] = x;
		return x * 0x2545F4914F6CDD1D;
	}

	// xorshift+: https://en.wikipedia.org/wiki/Xorshift
	static inline uint64_t XorShift128Plus(uint64_t* state)
	{
		ION_ASSERT(state[0] != 0, "Invalid seed");
		ION_ASSERT(state[1] != 0, "Invalid seed");
		uint64_t x = state[0];
		uint64_t const y = state[1];
		state[0] = y;
		x ^= x << 23;							   // a
		state[1] = x ^ y ^ (x >> 17) ^ (y >> 26);  // b, c
		return state[1] + y;
	}

	// http://xoroshiro.di.unimi.it/xoroshiro128plus.c
	/*  Written in 2016-2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

	To the extent possible under law, the author has dedicated all copyright
	and related and neighboring rights to this software to the public domain
	worldwide. This software is distributed without any warranty.

	See <http://creativecommons.org/publicdomain/zero/1.0/>. */
	static inline uint64_t Rotl(const uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
	static inline uint64_t Xoroshiro128Plus(uint64_t* state)
	{
		ION_ASSERT(state[0] != 0, "Invalid seed");
		ION_ASSERT(state[1] != 0, "Invalid seed");
		const uint64_t s0 = state[0];
		uint64_t s1 = state[1];
		const uint64_t result = s0 + s1;

		s1 ^= s0;
		state[0] = Rotl(s0, 55) ^ s1 ^ (s1 << 14);	// a, b
		state[1] = Rotl(s1, 36);					// c
		return result;
	}
};
}  // namespace ion
