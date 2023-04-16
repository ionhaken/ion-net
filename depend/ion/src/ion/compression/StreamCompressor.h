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
#include <ion/byte/ByteWriter.h>
#include <ion/byte/ByteBuffer.h>
#include <ion/container/Array.h>
#include <ion/byte/ByteSerialization.h>

namespace ion
{

static constexpr serialization::Tag TagDefault = {0};
static constexpr serialization::Tag TagText = {1};

template<typename BufferWriterType, typename Allocator = GlobalAllocator<ion::u8>>
class CompactWriter
{
public:	
	CompactWriter(ByteBufferBase& buffer, size_t numStreams = 2)
	{
		mWriters.Add(std::move(BufferWriterType(buffer)));
		while (mWriters.Size() < numStreams)
		{
			mSubBuffers.Add(ByteBuffer<0, Allocator>(1500));
			mWriters.Add(std::move(BufferWriterType(mSubBuffers.Back())));
		}
	}

	template <typename T>
	inline bool Process(const T& t, serialization::Tag tag = TagDefault)
	{
		//serialization::Serialize(t, mWriters(Tag::Index));
		return mWriters[tag.mIndex].Process(t);
	}

	void EnsureCapacity(size_t capacity) 
	{ 
		mWriters[0].EnsureCapacity(capacity); 
		mWriters[1].EnsureCapacity(capacity); 
	}

	template<typename Callback>
	void CopyFromSubstreams(Callback&& callback) 	
	{
		SmallVector<size_t, 16> numBytesWritten;
		for (size_t i = 1; i < mWriters.Size(); ++i) 
		{
			mWriters[i].Flush();
		}
		numBytesWritten.Add(callback(mWriters[0], mSubBuffers[0]));
		for (size_t s : numBytesWritten)
		{
			mWriters[0].Write(uint16_t(s));
		}
	}

	size_t TotalSize() const
	{
		size_t s = 0;
		for (size_t i = 0; i < mWriters.Size(); ++i)
		{
			s += mWriters[i].NumBytesUsed();
		}
		return s;
	}


private:
	Vector<ByteBuffer<0, Allocator>> mSubBuffers;
	Vector<BufferWriterType> mWriters;
};

template<typename Allocator = GlobalAllocator<ion::u8>>
class CompactReader
{
public:
	CompactReader(byte* data, size_t len, size_t numStreams = 2)
	{
		size_t pos = len;
		
		SmallVector<ByteReader, 32> tmpReaders;
		while (pos > sizeof(uint16_t) && tmpReaders.Size() < numStreams - 1) 
		{
			pos -= sizeof(uint16_t);
			uint16_t blockLen;
			memcpy(&blockLen, data + pos, sizeof(uint16_t));
			if (pos < blockLen) 
			{			
				ION_ABNORMAL("Invalid data block;len:" << blockLen << ";left:" << pos);
				return;
			}
			pos -= blockLen;
			tmpReaders.Add(std::move(ByteReader(data + pos, blockLen)));
		}
		
		// Reverse order
		mReaders.Reserve(numStreams);
		mReaders.Add(std::move(ByteReader(data, pos)));
		for (int i = tmpReaders.Size() - 1; i >= 0; --i) 
		{
			mReaders.Add(std::move(tmpReaders[i]));
		}
	}

	template <typename T>
	inline bool Process(T& t, serialization::Tag tag = TagDefault)
	{
		return mReaders[tag.mIndex].Process(t);
	}

	template <typename Callback>
	void CopyToSubstreams(Callback&& callback)
	{
		SmallVector<ByteReader, 32> tmpReaders;
		for (size_t i = 1; i < mReaders.Size(); ++i)
		{
			mSubBuffers.Add(ByteBuffer<0, Allocator>());
			{
				ByteWriter writer(mSubBuffers.Back());
				callback(mReaders[i], writer);
			}
			tmpReaders.Add(std::move(ByteReader(mSubBuffers.Back())));
		}

		mReaders.Resize(1);
		for (int i = 0; i < tmpReaders.Size(); ++i)
		{
			mReaders.Add(std::move(tmpReaders[i]));
		}
	}

private:
	Vector<ByteBuffer<0, Allocator>> mSubBuffers;
	Vector<ByteReader> mReaders;
};


template <size_t TNumTags = 1, size_t TSmallSize = 0>
class StreamCompressor
{
	using MultiStreamBuffer = Array<ByteBuffer<TSmallSize>, TNumTags>;

	class MultiStreamWriter
	{
		ION_CLASS_NON_COPYABLE_NOR_MOVABLE(MultiStreamWriter);

	public:
		MultiStreamWriter(MultiStreamBuffer& buffers)
		  : mBuffers(buffers),
			mWriters([&](auto index) { return ByteWriter(mBuffers[index]); })
		{
		}

		~MultiStreamWriter() {}

		template <typename TTag, typename TData>
		inline void Write(TTag tag, const TData& data)
		{
			mWriters[static_cast<size_t>(tag)].template WriteKeepCapacity<TData>(data);
		}

	private:
		MultiStreamBuffer& mBuffers;
		ion::Array<ByteWriter, TNumTags> mWriters;
	};

	class MultiStreamReader
	{
	public:
		MultiStreamReader(MultiStreamBuffer& buffers) : mBuffers(buffers)
		{
			for (size_t i = 0; i < TNumTags; i++)
			{
				mReaders[i] = ByteReader(mBuffers[i]);
			}
		}

		template <typename TData, typename TTag>
		ION_FORCE_INLINE const TData& Read(TTag tag)
		{
			return mReaders[static_cast<size_t>(tag)].template ReadAssumeAvailable<TData>();
		}

		template <typename TData, typename TTag>
		inline void Read(TTag tag, TData& data)
		{
			mReaders[static_cast<size_t>(tag)].template ReadAssumeAvailable<TData>(data);
		}

		template <typename TData, typename TTag>
		inline const TData& Read(TTag tag, const TData& defaultValue)
		{
			if (mReaders[static_cast<size_t>(tag)].Available() >= sizeof(TData))
			{
				return Read<TData>(tag);
			}
			return defaultValue;
		}

		template <typename TData, typename TTag>
		ION_FORCE_INLINE void Read(TTag tag, TData& data, const TData& defaultValue)
		{
			if (mReaders[static_cast<size_t>(tag)].Available() >= sizeof(TData))
			{
				mReaders[static_cast<size_t>(tag)].ReadAssumeAvailable(data);
			}
			else
			{
				data = defaultValue;
			}
		}

	private:
		MultiStreamBuffer& mBuffers;
		ion::Array<ByteReader, TNumTags> mReaders;
	};

	template <typename TWriter = ion::ByteWriter>
	class Writer
	{
	public:
		Writer(TWriter& writer) : mWriter(writer) {}

		template <typename TTag, typename TData>
		inline void Write(TTag /*tag*/, const TData& data)
		{
			mWriter.WriteKeepCapacity(data);
		}

		template <typename TTag, typename TData>
		inline TData& Write(TTag /*tag*/)
		{
			return mWriter.WriteKeepCapacity();
		}

	private:
		TWriter& mWriter;
	};

	template <typename TReader = ByteReader>
	class Reader
	{
	public:
		Reader(TReader& reader) : mReader(reader) {}

		template <typename TData, typename TTag>
		ION_FORCE_INLINE const TData& Read(TTag /*tag*/)
		{
			return mReader.template ReadAssumeAvailable<TData>();
		}

		template <typename TData, typename TTag>
		ION_FORCE_INLINE void Read(TTag /*tag*/, TData& data)
		{
			mReader.ReadAssumeAvailable(data);
		}

		template <typename TData, typename TTag>
		ION_FORCE_INLINE const TData& Read(TTag /*tag*/, const TData& defaultValue)
		{
			if (mReader.Available() >= sizeof(TData))
			{
				return mReader.template ReadAssumeAvailable<TData>();
			}
			return defaultValue;
		}

		template <typename TData, typename TTag>
		ION_FORCE_INLINE void Read(TTag /*tag*/, TData& data, const TData& defaultValue)
		{
			if (mReader.Available() >= sizeof(TData))
			{
				mReader.ReadAssumeAvailable(data);
			}
			else
			{
				data = defaultValue;
			}
		}

	private:
		TReader& mReader;
	};

	class Estimator
	{
	public:
		Estimator() { std::fill(count.Begin(), count.End(), 0); }

		template <typename TTag, typename TData>
		inline void Write(TTag tag, const TData& data)
		{
			count[static_cast<size_t>(tag)] += sizeof(data);
		}

		bool CanFit(size_t size)
		{
			size_t total = 0;
			for (size_t i = 0; i < TNumTags; ++i)
			{
				total += count[i];
			}
			return total <= size;
		}

		bool CanFit(MultiStreamBuffer& buffer) const
		{
			for (size_t i = 0; i < TNumTags; ++i)
			{
				if (count[i] > buffer[i].Capacity())
				{
					return false;
				}
			}
			return true;
		}

	private:
		ion::Array<size_t, TNumTags> count;
	};

public:
	StreamCompressor() {}

	template <typename TTag>
	void Reserve(TTag tag, ByteSizeType numBytes)
	{
		mBuffers[static_cast<size_t>(tag)].Reserve(numBytes);
	}

	template <typename T>
	bool Serialize(T& container, ByteWriter& dst)
	{
		Estimator e;
		container.Serialize(e);

		if (mIsUsingMultiStream && e.CanFit(mBuffers))
		{
			{
				MultiStreamWriter writer(mBuffers);
				container.Serialize(writer);
			}
			return Compress(dst);
		}
		else if (e.CanFit(dst.Available()))
		{
			Writer<> writer(dst);
			container.Serialize(writer);
			return true;
		}
		return false;
	}

	template <typename T>
	bool Deserialize(T& container, ByteReader& src)
	{
		if (mIsUsingMultiStream)
		{
			if (Decompress(src))
			{
				MultiStreamReader reader(mBuffers);
				container.Deserialize(reader);
				return true;
			}
		}
		else
		{
			Reader<> reader(src);
			container.Deserialize(reader);
			return true;
		}
		return false;
	}

	void Clear()
	{
		if (mIsUsingMultiStream)
		{
			for (size_t i = 0; i < mBuffers.Size(); i++)
			{
				mBuffers[i].Rewind();
			}
		}
	}

	void EnableMultiStream() { mIsUsingMultiStream = true; }

	StreamCompressor(StreamCompressor& other) : mBuffers(std::move(other.mBuffers)), mIsUsingMultiStream(other.mIsUsingMultiStream) {}

	StreamCompressor& operator=(const StreamCompressor& other)
	{
		// #TODO: Make class non copyable
		// #TODO: ByteBuffer does not support copy so doing this, fix codegen not to generate copy for streamcompressor
		for (size_t i = 0; i < mBuffers.Size(); i++)
		{
			mBuffers[i].Rewind();
		}

		mIsUsingMultiStream = other.mIsUsingMultiStream;
		return *this;
	}

private:
	bool Compress(ByteWriter& dst)
	{
		ION_ASSERT(mIsUsingMultiStream, "Compress only multi stream");
		bool isCompressed = true;
		{
			for (size_t i = 0; i < mBuffers.Size(); i++)
			{
				if (mBuffers[i].Size() > 0)
				{
					{
						ByteReader src(mBuffers[i]);
						// #TODO: Write buffer size to dst.
						if (!dst.Copy(src))
						{
							isCompressed = false;
						}
					}
					mBuffers[i].Rewind();
				}
			}
		}
		return isCompressed;
	}

	bool Decompress(ByteReader&) { return true; }

	MultiStreamBuffer mBuffers;
	bool mIsUsingMultiStream = false;
};
}  // namespace ion
