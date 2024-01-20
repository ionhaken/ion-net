#pragma once

namespace ion
{
template <typename T>
struct AABB
{
	AABB() {}
	AABB(const AABB& other) : mMin(other.mMin), mMax(other.mMax) {}
	AABB& operator=(const AABB& other)
	{
		mMin = other.mMin;
		mMax = other.mMax;
		return *this;
	}

	AABB(const T& min, const T& max) : mMin(min), mMax(max) {}

	void Merge(const AABB& other)
	{
		for (int i = 0; i < T::ElementCount; ++i)
		{
			if (mMin[i] > other.mMin[i])
			{
				mMin[i] = other.mMin[i];
			}
			if (mMax[i] < other.mMax[i])
			{
				mMax[i] = other.mMax[i];
			}
		}
	}

	void Clamp(const AABB& other)
	{
		for (int i = 0; i < T::ElementCount; ++i)
		{
			if (mMin[i] < other.mMin[i])
			{
				mMin[i] = other.mMin[i];
			}
			if (mMax[i] > other.mMax[i])
			{
				mMax[i] = other.mMax[i];
			}
		}
	}

	T mMin;
	T mMax;
};

}  // namespace ion
