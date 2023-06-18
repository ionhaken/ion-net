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
#include <ion/util/Random.h>

namespace ion
{
class SplitMix64
{
public:
	constexpr SplitMix64(uint64_t seed) : x(seed) {}

	/*  Written in 2015 by Sebastiano Vigna (vigna@acm.org)

	To the extent possible under law, the author has dedicated all copyright
	and related and neighboring rights to this software to the public domain
	worldwide. This software is distributed without any warranty.

	See <http://creativecommons.org/publicdomain/zero/1.0/>. */

	/* This is a fixed-increment version of Java 8's SplittableRandom generator
	See http://dx.doi.org/10.1145/2714064.2660195 and
	http://docs.oracle.com/javase/8/docs/api/java/util/SplittableRandom.html

	It is a very fast generator passing BigCrush, and it can be useful if
	for some reason you absolutely want 64 bits of state; otherwise, we
	rather suggest to use a xoroshiro128+ (for moderately parallel
	computations) or xorshift1024* (for massively parallel computations)
	generator. */

	uint64_t x; /* The state can be seeded with any value. */

	uint64_t next()
	{
		uint64_t z = (x += 0x9e3779b97f4a7c15);
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
		return z ^ (z >> 31);
	}
};
}  // namespace ion

ion::Random::Random(uint64_t seed) { Seed(seed, mState); }

void ion::Random::Seed(uint64_t seed, uint64_t* state)
{
	// https://xoroshiro.di.unimi.it/xoroshiro128plus.c
	// The state must be seeded so that it is not everywhere zero.If you have a 64 - bit seed,
	//  we suggest to seed a splitmix64 generator and use its output to fill s.
	SplitMix64 splitMix64(seed);
	state[0] = splitMix64.next();
	ION_ASSERT(state[0] != 0, "Cannot be zero");
	state[1] = splitMix64.next();
	ION_ASSERT(state[1] != 0, "Cannot be zero");

	// https://xoroshiro.di.unimi.it/xoroshiro128plus.c
	// This is the jump function for the generator. It is equivalent
	// to 2^64 calls to Xoroshiro128Plus(); it can be used to generate 2^64
	// non-overlapping subsequences for parallel computations.
	static const uint64_t JUMP[] = {0xbeac0467eba5facb, 0xd86b048b86aa9922};

	uint64_t s0 = 0;
	uint64_t s1 = 0;
	for (int i = 0; i < sizeof JUMP / sizeof *JUMP; i++)
	{
		for (int b = 0; b < 64; b++)
		{
			if (JUMP[i] & UINT64_C(1) << b)
			{
				s0 ^= state[0];
				s1 ^= state[1];
			}
			ion::Random::Xoroshiro128Plus(state);
		}
	}

	state[0] = s0;
	state[1] = s1;
}
