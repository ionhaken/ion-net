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
#include <ion/batch/VecBatch.h>
#include <ion/byte/ByteBuffer.h>
#include <ion/util/Bits.h>

namespace ion::compression
{
template <typename TValueType = float, typename TQValueType = int32_t, size_t TBitSize = 20, size_t TRange = 1024, bool TIsBatch = true>
struct QuantizationConfig
{
	static constexpr bool IsBatch = TIsBatch;
	static constexpr size_t BitSize = TBitSize;
	static constexpr size_t ByteSize = ion::BitCountToByteCount(BitSize);
	using ValueType = TValueType;
	using QValueType = TQValueType;

	using PrimitiveType = typename ion::BaseType<TValueType>::type;
	using QPrimitiveType = typename ion::BaseType<TQValueType>::type;

	const QPrimitiveType Mask = static_cast<QPrimitiveType>((static_cast<QPrimitiveType>(1) << (BitSize - 1)) - 1);
	const ValueType Maskf = static_cast<ValueType>(PrimitiveType(Mask));

	const QValueType Max = static_cast<QValueType>((static_cast<uint64_t>(1) << BitSize) - 1);

	PrimitiveType RangeValue = TRange;
	ValueType Range = ValueType(RangeValue);

	//ION_FORCE_INLINE const ValueType Range() const { return RangeValue; }
};

template<typename SourceConfig>
using ScalarConfig = QuantizationConfig<typename SourceConfig::PrimitiveType, typename SourceConfig::QPrimitiveType, SourceConfig::BitSize, SourceConfig::RangeValue, false>;

template <typename QConfig>
ION_FORCE_INLINE typename QConfig::QValueType Quantize(const QConfig& config, const typename QConfig::ValueType& val)
{
	using ValueType = typename QConfig::ValueType;
	using QValueType = typename QConfig::QValueType;

	ValueType abs_offset(ion::Abs(val));
	QValueType packed(static_cast<QValueType>(abs_offset / config.Range * config.Maskf + static_cast<typename QConfig::ValueType>(0.5)));

	return (packed << 1u) | static_cast<QValueType>(val < 0);
}

template <typename QConfig>
ION_FORCE_INLINE typename QConfig::ValueType Dequantize(const QConfig& config, const typename QConfig::QValueType& qval)
{
	using ValueType = typename QConfig::ValueType;
	using QValueType = typename QConfig::QValueType;

	ValueType value(static_cast<ValueType>((qval >> 1) /* & config.Mask */) / config.Maskf);
	QValueType sign = QValueType(1) - ((qval & 1) << 1);
	value *= static_cast<ValueType>(sign) * config.Range;
	return value;
}

template <typename QConfig, typename WriterType>
ION_FORCE_INLINE void Quantize(const QConfig& config, WriterType& writer, const float* flt, size_t num)
{
	writer.EnsureCapacity(ion::ByteSizeType(QConfig::ByteSize * num));

	if constexpr (QConfig::IsBatch)
	{
		auto moduloNum = ion::Mod2(num, QConfig::ValueType::ElementCount);
		auto alignedNum = num - moduloNum;

		const float* last = flt + alignedNum;
		// typename QConfig::QValueType baseline(0);
		while (flt != last)
		{
			typename QConfig::ValueType value(flt, QConfig::ValueType::ElementCount);
			flt += QConfig::ValueType::ElementCount;

			auto qval = Quantize(config, value);
			auto qvalBase = /* baseline ^ */ qval;
			// baseline = qval;
			for (size_t i = 0; i < QConfig::ValueType::ElementCount; ++i)
			{
				uint32_t val = qvalBase[i];
				writer.WriteArrayKeepCapacity(reinterpret_cast<const ion::u8*>(&val), QConfig::ByteSize);
			}
		}
		ScalarConfig<QConfig> configScalar;
		for (size_t i = 0; i < moduloNum; i++)
		{
			uint32_t qval = Quantize(configScalar, flt[i]) /* ^ baseline[i]*/;
			writer.WriteArrayKeepCapacity(reinterpret_cast<const ion::u8*>(&qval), QConfig::ByteSize);
		}
	}
	else 
	{
		/*writer.WriteDirectly(
		  [&](byte* pos, byte* end)
		  {*/
			  typename QConfig::QValueType baseline(0);
		byte ich[QConfig::ByteSize] = {};
			  for (size_t i = 0; i < num; i++)
			  {
				  uint32_t qvalBase = Quantize(config, flt[i]) /* ^ baseline[i]*/;
#if 1
				  uint32_t qval = qvalBase;
				   //baseline ^ qvalBase;
				  //baseline = qvalBase;
				  for (size_t j = 0; j < QConfig::ByteSize-1; ++j)
				  {
					  byte sp((qval >> (j * 8))); 
					  //byte sp((qval >> (2 * 8))); 
					  //ION_LOG_INFO("sp = " << j<< "-" << sp);
					  //sp = sp & 0x1F;
					  //sp = ich[j] + sp;
					  //ich[j] = sp;
					  writer.Process(sp, serialization::Tag{0});
					  //*(pos + (j * num)) = sp;
					  //writer.WriteArrayKeepCapacity(reinterpret_cast<const ion::u8*>(&qval), QConfig::ByteSize);
				  }
				  byte sp((qval >> (2 * 8))); 
				  //sp = ich[QConfig::ByteSize - 1] + sp;
				  //ich[QConfig::ByteSize - 1] = sp;
				  writer.Process(sp, serialization::Tag{1});
				  //++pos;
#else
				  writer.WriteArrayKeepCapacity(reinterpret_cast<const ion::u8*>(&qvalBase), QConfig::ByteSize);

#endif
			 }
			  //return num * QConfig::ByteSize;
		  //});
	}
	

}

template <>
ION_FORCE_INLINE void Quantize(const QuantizationConfig<>& config, ByteWriter& writer, const float* flt, size_t num)
{
	// int32_t baseline = 0;
	writer.EnsureCapacity(ion::ByteSizeType(QuantizationConfig<>::ByteSize * num));
	for (size_t i = 0; i < num; i++)
	{
		auto qval = Quantize(config, flt[i]);
		auto qvalBase = /* baseline ^*/ qval;
		// baseline = qval;
		writer.WriteArrayKeepCapacity(reinterpret_cast<const ion::u8*>(&qvalBase), QuantizationConfig<>::ByteSize);
	}
}

template <typename QConfig, typename Callback>
ION_FORCE_INLINE void Dequantize(const QConfig& config, ByteReader& reader, Callback&& callback)
{
	constexpr const size_t QValSize = QuantizationConfig<>::ByteSize;
	// typename QConfig::QValueType baseline(0);

	size_t leftOver = reader.Available() % (QConfig::ValueType::ElementCount * QValSize);
	size_t numElements = (reader.Available() - leftOver) / (QConfig::ValueType::ElementCount * QValSize);
	for (size_t k = 0; k < numElements; ++k)
	{
		ION_ALIGN(QConfig::ValueType::DefaultAlignment) ion::Vec<int32_t, QConfig::ValueType::ElementCount> val(0);
		typename QConfig::QValueType qval;
		for (size_t i = 0; i < QConfig::ValueType::ElementCount; ++i)
		{
			reader.ReadAssumeAvailable(reinterpret_cast<ion::u8*>(&val[i]), QValSize);
		}
		
		qval.LoadAligned(val);
		/* baseline = baseline ^ qval*/;
		typename QConfig::ValueType dqval = ion::compression::Dequantize(config, /* baseline*/ qval);
		for (size_t i = 0; i < QConfig::ValueType::ElementCount; ++i)
		{
			callback(dqval[i]);
		}
	}

	QuantizationConfig<> configScalar; 
	for (size_t i = 0; i < leftOver; ++i)
	{
		ION_ABNORMAL("Scalar config not derived from original");
		int32_t ival(0);
		reader.ReadAssumeAvailable(reinterpret_cast<ion::u8*>(&ival), QValSize);
		// ival = ival ^ baseline[i];
		auto dqval = ion::compression::Dequantize(configScalar, ival);
		callback(dqval);
	}
}

template <typename Callback>
ION_FORCE_INLINE void Dequantize(const QuantizationConfig<>& config, ByteReader& reader, Callback&& callback)
{
	constexpr size_t QValSize = QuantizationConfig<>::ByteSize;
	// int32_t baseline = 0;
	size_t numElements = reader.Available() / QValSize;
	while (numElements)
	{
		int32_t ival(0);
		reader.ReadAssumeAvailable(reinterpret_cast<ion::u8*>(&ival), QValSize);
		// baseline = baseline ^ ival;
		auto dqval = ion::compression::Dequantize(config, ival /* baseline*/);
		callback(dqval);
		numElements--;
	}
}

}  // namespace ion::compression
