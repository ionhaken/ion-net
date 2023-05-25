
#include <ion/net/NetControlLayer.h>
#include <ion/net/NetInternalTypes.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetPayload.h>
#include <ion/net/NetRemote.h>
#include <ion/net/NetSecure.h>
#include <ion/net/NetSendCommand.h>
#include <ion/net/NetSocketLayer.h>
#include <ion/net/NetTransportLayer.h>

#include <cstddef>
#include <utility>

#define ION_NET_CHANNEL_TUNER_LOG(__msg, ...) ION_NET_LOG_VERBOSE_CHANNEL_TUNER(__msg, __VA_ARGS__)

namespace ion::NetTransportLayer
{
namespace
{
inline NetChannel& IdToChannel(NetTransport& transport, uint8_t channelId) { return transport.mOrderedChannels[transport.mIdToChannel[channelId]]; }

void ResetChannelTuner(NetTransport& transport, ion::TimeMS now, uint8_t newPriorityChannel)
{
	if (transport.mChannelTuner.mPriorityChannel != NetNumberOfChannels)
	{
		NetChannel& prevChannel = IdToChannel(transport, transport.mChannelTuner.mPriorityChannel);
		uint32_t currentSndWnd = prevChannel.mState.snd_wnd;
		NetChannel& newChannel = IdToChannel(transport, newPriorityChannel);
		prevChannel.SndWndSize(MinSndWindowSize);
		newChannel.SndWndSize(currentSndWnd);
	}
	else
	{
		ION_NET_CHANNEL_TUNER_LOG("ChannelTuner: Started");
	}
	transport.mChannelTuner.mPriorityChannel = newPriorityChannel;
	transport.mChannelTuner.mGoodWindowSize = 0;
	transport.mChannelTuner.FinishPeriod(now);
	transport.mChannelTuner.mState = NetTransport::ChannelTuner::State::ScalingUpFast;
}

bool ReconfigureUpstreamChannel(NetTransport& transport, NetChannel& channel, float windowSizeMod)
{
	// Now many packets to send until ACK
	uint32_t snd_wnd = channel.mState.snd_wnd;
	if (windowSizeMod >= 1.00)
	{
		snd_wnd = ion::Max(snd_wnd + 1, static_cast<uint32_t>(float(snd_wnd) * windowSizeMod));
		if (snd_wnd < channel.mState.cwnd)
		{
			snd_wnd = channel.mState.cwnd;
		}
	}
	else if (windowSizeMod <= -1.0f)
	{
		snd_wnd = ion::Min(snd_wnd - 1, static_cast<uint32_t>(float(snd_wnd) / -windowSizeMod));
	}
	else
	{
		snd_wnd = 0;
	}

	uint32_t maxMemoryReserved = 128 * 1024 * 1024;
	uint32_t wndMax = maxMemoryReserved / channel.mState.mss;
	snd_wnd = ion::MinMax(MinSndWindowSize, snd_wnd, wndMax);
	if (channel.mState.snd_wnd != snd_wnd)
	{
		channel.SndWndSize(snd_wnd);
		return true;
	}
	return false;
}

void ReconfigureDownstreamChannel(NetTransport& transport, NetChannel& channel)
{
	// How many packets to buffer.
	uint32_t maxMemoryReserved = 128 * 1024 * 1024;
	uint32_t wndMax = maxMemoryReserved / channel.mState.mss;
	uint32_t rcv_wnd = wndMax;
	channel.RcvWndSize(rcv_wnd);
}

NetPacket* Receive(NetTransport& transport, NetChannel& channel, NetControl& control, NetRemoteSystem& remote)
{
	for (;;)
	{
		if (!channel.mState.mIsBigDataActive)
		{
			NetPacket* packet = channel.Receive(control, remote);
			if (packet == nullptr)
			{
				break;
			}

			if (packet->Data()[0] != NetMessageId::ChannelReconfiguration)	// #TODO: Do this in higher level loop
			{
				packet->mGUID = remote.guid;
				packet->mRemoteId = remote.mId;
				packet->mSource = remote.netSocket;
				return packet;
			}
			else
			{
				uint32_t nextSize = packet->Length();
				constexpr uint32_t MsgSize = sizeof(NetMessageId) + sizeof(uint64_t);
				constexpr uint32_t KeySize = sizeof(remote.netSocket->mBigDataKey);
				if (nextSize == MsgSize || nextSize == (MsgSize + KeySize))
				{
					ByteReader stream((unsigned char*)(&packet->Data()[1]), nextSize);
					uint64_t totalSize;
					stream.Process(totalSize);
					unsigned char bigDataKey[KeySize];
					uint64_t maxSize = 16 * 1024;
					if (nextSize == (MsgSize + KeySize))
					{
						stream.ReadAssumeAvailable(bigDataKey, KeySize);
						auto* receiverBigDataKey = remote.netSocket->mBigDataKey.data;
						if (memcmp(bigDataKey, receiverBigDataKey, KeySize) == 0)
						{
							maxSize = 512 * 1024 * 1024;
						}
						else
						{
							ION_NET_LOG_ABNORMAL("Big data key mismatch;guid=" << remote.guid);
						}
					}

					if (totalSize <= maxSize)
					{
						ION_NET_LOG_VERBOSE("Received big data request from " << remote.guid.Raw() << ";size=" << (totalSize / 1024)
																			  << "KB");
						NetPacket* buffer = ion::NetControlLayer::AllocateUserPacket(control, totalSize);
						if (buffer)
						{
							buffer->mLength = SafeRangeCast<uint32_t>(totalSize);  // #TODO: Support 64-bit packet size
							buffer->mAddress = packet->mAddress;
							buffer->mGUID = remote.guid;
							buffer->mRemoteId = remote.mId;
							buffer->mSource = remote.netSocket;
							ION_ASSERT(channel.mState.mBigDataBuffer.mBuffer == nullptr, "Duplicate buffer");
							channel.mState.mBigDataBuffer.mBuffer = buffer;
							channel.mState.mBigDataBuffer.mTotalReceived = 0;
							channel.mState.mIsBigDataActive = true;
							ReconfigureDownstreamChannel(transport, channel);
						}
						else
						{
							ION_NET_LOG_ABNORMAL("Not enough memory for big data;guid=" << remote.guid);
						}
					}
					else
					{
						ION_NET_LOG_ABNORMAL("Too large packet;guid=" << remote.guid);
					}
				}
				else
				{
					ION_NET_LOG_ABNORMAL("Invalid big data;guid=" << remote.guid);
				}
				NetControlLayer::DeallocateUserPacket(control, packet);
			}
		}
		else
		{
			int nextSize = channel.PeekSize(control, remote);
			if (nextSize <= 0)
			{
				break;
			}
			NetChannel::State::BigDataBuffer& buffer = channel.mState.mBigDataBuffer;
			if (uint32_t(nextSize) + buffer.mTotalReceived <= buffer.mBuffer->mLength)
			{
				[[maybe_unused]] int res = channel.Receive(control, remote, &buffer.mBuffer->mDataPtr[buffer.mTotalReceived], nextSize);
				ION_ASSERT(res >= 0, "Receive failed;code=" << res);
				buffer.mTotalReceived += nextSize;

				if (buffer.mTotalReceived == buffer.mBuffer->mLength)
				{
					auto* packet = buffer.mBuffer;
					buffer.mBuffer = nullptr;
					channel.mState.mIsBigDataActive = false;
					ReconfigureDownstreamChannel(transport, channel);
					return packet;
				}
			}
			else
			{
				ION_NET_LOG_ABNORMAL("Invalid big data;guid=" << remote.guid);
				NetControlLayer::DeallocateUserPacket(control, buffer.mBuffer);
				buffer.mBuffer = nullptr;
				channel.mState.mIsBigDataActive = false;
				ReconfigureDownstreamChannel(transport, channel);
			}
		}
	}

	return nullptr;
}


NetChannel* EnsureChannel(NetTransport& transport, uint32_t conversation, NetRemoteSystem& remote, ion::TimeMS now)
{
	uint8_t channelId = static_cast<uint8_t>(conversation & 0xFF);
	uint8_t channelIdx = transport.mIdToChannel[channelId];
	if (channelIdx == 0xFF)
	{
		channelIdx = uint8_t(transport.mOrderedChannels.Size());
		transport.mOrderedChannels.Add(std::move(NetChannel(conversation, now, remote.PayloadSize())));
		auto* channel = &transport.mOrderedChannels.Back();

		ION_ASSERT(channelIdx < NetNumberOfChannels, "Invalid channel index");
		transport.mIdToChannel[channelId] = channelIdx;

		ReconfigureUpstreamChannel(transport, *channel, 0);
		ReconfigureDownstreamChannel(transport, *channel);
		return channel;
	}
	return &transport.mOrderedChannels[channelIdx];
}


void UpdatePriorityChannelOnInput(NetTransport& transport, NetChannel* stream, uint32_t conversation, ion::TimeMS now)
{
	if (transport.mChannelTuner.mThreshold == NetTransport::ChannelTuner::MinThreshold)
	{
		return;
	}

	uint32_t newThreshold = ion::SafeRangeCast<uint32_t>(stream->mSndQueue.Size() + stream->mSndBuf.Size());
	uint8_t newPriorityChannel = uint8_t(conversation & 0xFF);
	for (size_t i = 0; i < transport.mOrderedChannels.Size(); ++i)
	{
		if (transport.mOrderedChannels[i].mSndBuf.Size() + transport.mOrderedChannels[i].mSndQueue.Size() > newThreshold)
		{
			newPriorityChannel = uint8_t(transport.mOrderedChannels[i].mState.conv);
			newThreshold =
			  ion::SafeRangeCast<uint32_t>(transport.mOrderedChannels[i].mSndBuf.Size() + transport.mOrderedChannels[i].mSndQueue.Size());
		}
	}

	if (newThreshold <= NetTransport::ChannelTuner::MinThreshold)
	{
		transport.mChannelTuner.mThreshold = NetTransport::ChannelTuner::MinThreshold;
		NetChannel& channel = IdToChannel(transport, transport.mChannelTuner.mPriorityChannel);
		channel.SndWndSize(MinSndWindowSize);
		transport.mChannelTuner.mPriorityChannel = NetNumberOfChannels;
		ION_NET_CHANNEL_TUNER_LOG("ChannelTuner: Stopped");
	}
	else
	{
		transport.mChannelTuner.mThreshold = newThreshold;
		if (newPriorityChannel != transport.mChannelTuner.mPriorityChannel)
		{
			ResetChannelTuner(transport, now, newPriorityChannel);
		}
		ION_ASSERT(transport.mChannelTuner.mPriorityChannel < NetNumberOfChannels, "Invalid priority channel");
	}
}

void UpdatePriorityChannelOnSend(NetTransport& transport, NetChannel* stream, uint32_t conversation, ion::TimeMS now)
{
	const size_t numSendPackets = stream->mSndQueue.Size() + stream->mSndBuf.Size();
	if (numSendPackets > transport.mChannelTuner.mThreshold)
	{
		const uint8_t channel = uint8_t(conversation & 0xFF);
		if (channel != transport.mChannelTuner.mPriorityChannel ||
			transport.mChannelTuner.mThreshold == NetTransport::ChannelTuner::MinThreshold)
		{
			ResetChannelTuner(transport, now, channel);
		}
		transport.mChannelTuner.mThreshold = ion::SafeRangeCast<uint32_t>(numSendPackets);
		ION_ASSERT(transport.mChannelTuner.mPriorityChannel < NetNumberOfChannels, "Invalid priority channel");
	}
}


}  // namespace

void Init(NetTransport& transport) { memset(transport.mIdToChannel.data(), 0xFF, sizeof(transport.mIdToChannel)); }

void Deinit([[maybe_unused]] NetTransport& transport) { ION_ASSERT(transport.mRcvQueue.IsEmpty(), "Reassembly queue leaked"); }

void Reset(NetTransport& transport, NetControl& control, NetRemoteSystem& remote)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(transport.mGuard);
	size_t index = 0;
	std::for_each(transport.mIdToChannel.begin(), transport.mIdToChannel.end(),
				  [&](const auto& channelIdx)
				  {
					  if (channelIdx == 0xFF)
					  {
						  index++;
						  return;
					  }
					  auto* channel = &transport.mOrderedChannels[channelIdx];
					  channel->Reset(control, remote);
					  if (channel->mState.mIsBigDataActive)
					  {
						  auto& buffer = channel->mState.mBigDataBuffer;
						  NetControlLayer::DeallocateUserPacket(control, buffer.mBuffer);
						  buffer.mBuffer = nullptr;
						  channel->mState.mIsBigDataActive = false;
					  }
					  index++;
				  });
	transport.mOrderedChannels.Clear();
	memset(transport.mIdToChannel.data(), 0xFF, sizeof(transport.mIdToChannel));
	transport.mChannelTuner = NetTransport::ChannelTuner();
}

bool Input(NetTransport& transport, NetControl& control, NetRemoteSystem& remote, uint32_t conversation,
							  ion::NetSocketReceiveData& recvFromStruct, ion::TimeMS now)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(transport.mGuard);
	ION_ASSERT((conversation & 0xFF) < NetNumberOfChannels, "Invalid channel");
	ION_ASSERT(recvFromStruct.SocketBytesRead() >= NetConnectedProtocolMinOverHead, "Invalid data for KCP");
	size_t length = recvFromStruct.SocketBytesRead();
#if ION_NET_FEATURE_SECURITY
	if (remote.mDataTransferSecurity == NetDataTransferSecurity::EncryptionAndReplayProtection)
	{
		if (length < (NetConnectedProtocolMinOverHead + ion::NetSecure::AuthenticationTagLength))
		{
			ION_NET_LOG_ABNORMAL("Invalid packet size: " << length << "/"
														 << ion::NetConnectedProtocolMinOverHead + ion::NetSecure::AuthenticationTagLength);
			return false;
		}

		unsigned char nonce[ion::NetSecure::NonceLength];
		memcpy(nonce, recvFromStruct.mPayload, NetUnencryptedProtocolBytes);
		memcpy(nonce + NetUnencryptedProtocolBytes, remote.mNonceOffset.Data(), remote.mNonceOffset.ElementCount);

		bool isDecrypted = ion::NetSecure::Decrypt(&recvFromStruct.mPayload[NetUnencryptedProtocolBytes],
												   &recvFromStruct.mPayload[NetUnencryptedProtocolBytes],
												   length - NetUnencryptedProtocolBytes, nonce, remote.mSharedKey);
		if (!isDecrypted)
		{
			ION_NET_LOG_ABNORMAL("Reliable layer decrypt failed");
			return false;
		}

		length = length - ion::NetSecure::AuthenticationTagLength;
	}
#endif
	NetChannel* stream = EnsureChannel(transport, conversation, remote, now);
	if (stream->Input(control, remote, recvFromStruct, now, length, transport.mChannelTuner.mPeriodTotalBytesAcked, transport.mRcvQueue))
	{
		while (NetPacket* nextPacket = Receive(transport, *stream, control, remote))
		{
			transport.mRcvQueue.PushBack(nextPacket);
		}
		UpdatePriorityChannelOnInput(transport, stream, conversation, now);
	}
	return true;
}

bool Send(NetTransport& transport, NetControl& control, TimeMS currentTime, NetRemoteSystem& remote, NetCommand& command,
		  uint32_t conversation)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(transport.mGuard);
	ION_ASSERT((conversation & 0xFF) < NetNumberOfChannels, "Invalid channel:" << (conversation & 0xFF));
	ION_ASSERT(command.mNumberOfBytesToSend > 0, "No data to send");

	NetChannel* stream = EnsureChannel(transport, conversation, remote, currentTime);
	ION_ASSERT(stream->mState.conv == conversation, "Invalid conversation;Expected=" << stream->mState.conv << ";Used=" << conversation);

	auto nextFlush = currentTime + ion::NetChannelPriorityConfigs[size_t(command.mPriority)].workInterval;
	if (ion::DeltaTime(stream->mState.ts_flush, nextFlush) > 0)
	{
		stream->mState.ts_flush = nextFlush;
	}

	if (command.mPriority < stream->mState.currentPriority)
	{
		stream->ReconfigureChannelPriority(command.mPriority);
	}

	int result = stream->Send(remote, command, 0, command.mNumberOfBytesToSend);
	if (result >= 0)
	{
		UpdatePriorityChannelOnSend(transport, stream, conversation, currentTime);
		return true;
	}

	uint32_t SegmentSize = MaxNumberOfFragments * stream->mState.mss;
	ION_ASSERT(command.mNumberOfBytesToSend >= SegmentSize, "Too small for big data");
	{
		NetCommandPtr ptr = MakeArenaPtrRaw<NetCommand>(&control.mMemoryResource, NetCommandHeaderSize + 64);
		ByteBufferView<byte*> view((byte*)&ptr->mData, 64);
		{
			ByteWriter writer(view);
			writer.Process(NetMessageId::ChannelReconfiguration);
			writer.Process(command.mNumberOfBytesToSend);
			if (command.mNumberOfBytesToSend > 16 * 1024)
			{
				writer.WriteArray(remote.netSocket->mBigDataKey.data, sizeof(remote.netSocket->mBigDataKey.data));
			}
		}
		ptr->mNumberOfBytesToSend = view.Size();

		result = stream->Send(remote, *ptr.Release(), 0, view.Size());
		ION_ASSERT(result >= 0, "Send failed");
	}
	uint64_t pos = 0;
	while (pos + SegmentSize <= command.mNumberOfBytesToSend)
	{
		result = stream->Send(remote, command, pos, SegmentSize);
		ION_ASSERT(result >= 0, "Send failed");
		pos += SegmentSize;
	}
	if (command.mNumberOfBytesToSend > pos)
	{
		result = stream->Send(remote, command, pos, command.mNumberOfBytesToSend - pos);
		ION_ASSERT(result >= 0, "Send failed");
	}
	UpdatePriorityChannelOnSend(transport, stream, conversation, currentTime);
	return true;
}

void UpdateChannelTuner(NetTransport& transport, NetRemoteSystem& remoteSystem, ion::TimeMS now)
{
	auto congestionMeasureTs = ion::DeltaTime(now, transport.mChannelTuner.mPeriodStart);
	if (remoteSystem.pingTracker.GetLatestPing() != ion::NetRttTracker::MaxPingTime &&
		congestionMeasureTs > (remoteSystem.pingTracker.GetLatestPing() + 1) * 4 && transport.mChannelTuner.mPeriodTotalBytesAcked > 0)
	{
		double dataPerMillis = 0;
		auto& channel = IdToChannel(transport, transport.mChannelTuner.mPriorityChannel);

		[[maybe_unused]] auto packetsAcked = double(transport.mChannelTuner.mPeriodTotalBytesAcked) / channel.mState.mss;
		dataPerMillis = double(transport.mChannelTuner.mPeriodTotalBytesAcked) / 1024 / double(congestionMeasureTs);

		const uint32_t FastScalingMinWindow = MinSndWindowSize;

		switch (transport.mChannelTuner.mState)
		{
		case NetTransport::ChannelTuner::State::ScalingUpFast:
		{
			if (channel.mState.cwnd < transport.mChannelTuner.mGoodWindowSize / 2)
			{
				ION_NET_CHANNEL_TUNER_LOG("ChannelTuner: Fastscaling completed. "
										  << (transport.mChannelTuner.mGoodWindowSize >= FastScalingMinWindow ? "(Wait)" : "(Slow)")
										  << ";Cwnd=" << channel.mState.cwnd << ";TargetWnd=" << transport.mChannelTuner.mGoodWindowSize
										  << ";Packets acked = " << packetsAcked << ";Mbs=" << dataPerMillis * 8
										  << ";snd_wnd=" << channel.mState.snd_wnd << " remote=" << channel.mState.rmt_wnd
										  << ";QueueSize=" << channel.mSndBuf.Size() + channel.mSndQueue.Size()
										  << ";Threshold=" << transport.mChannelTuner.mThreshold);
				if (transport.mChannelTuner.mGoodWindowSize >= FastScalingMinWindow)
				{
					transport.mChannelTuner.mState = NetTransport::ChannelTuner::State::Waiting;
					transport.mChannelTuner.mGoodWindowSize = transport.mChannelTuner.mGoodWindowSize / 2;
					channel.SndWndSize(ion::Max(MinSndWindowSize, transport.mChannelTuner.mGoodWindowSize));
					channel.mState.cwnd = channel.mState.snd_wnd;
				}
				else
				{
					transport.mChannelTuner.mState = NetTransport::ChannelTuner::State::ScalingUpSlow;
					channel.mState.snd_wnd = MinSndWindowSize;
				}
			}
			else
			{
				if (ReconfigureUpstreamChannel(transport, channel, 2.0))
				{
					transport.mChannelTuner.mGoodWindowSize = channel.mState.snd_wnd / 2;
					ION_NET_CHANNEL_TUNER_LOG("ChannelTuner: Fastscaling: cwnd=" << channel.mState.cwnd
																				 << ";sndBuf=" << channel.mSndBuf.Size()
																				 << ";sndQueue=" << channel.mSndQueue.Size());
				}
				else
				{
					channel.mState.cwnd = channel.mState.snd_wnd;
					ION_NET_CHANNEL_TUNER_LOG("ChannelTuner: Fastscaling completed: Max window size: cwnd=" << channel.mState.cwnd);
					transport.mChannelTuner.mState = NetTransport::ChannelTuner::State::Waiting;
				}
			}

			break;
		}
		case NetTransport::ChannelTuner::State::ScalingUpSlow:
		{
			ION_NET_CHANNEL_TUNER_LOG("ChannelTuner: Slowscaling: cwnd=" << channel.mState.cwnd << ";snd_wnd=" << channel.mState.snd_wnd
																		 << ";sndBuf=" << channel.mSndBuf.Size()
																		 << ";sndQueue=" << channel.mSndQueue.Size()
																		 << ";ping=" << remoteSystem.pingTracker.GetLatestPing());
			if (channel.mState.cwnd >= FastScalingMinWindow)
			{
				ION_NET_CHANNEL_TUNER_LOG("ChannelTuner: Slow scaling completed;cwnd=" << channel.mState.cwnd);
				transport.mChannelTuner.mGoodWindowSize = channel.mState.cwnd;
				transport.mChannelTuner.mState = NetTransport::ChannelTuner::State::ScalingUpFast;
			}
			break;
		}
		case NetTransport::ChannelTuner::State::Waiting:
		{
			const uint32_t WaitingTargetWnd = transport.mChannelTuner.mGoodWindowSize / 2;
			ION_NET_CHANNEL_TUNER_LOG("ChannelTuner Waiting: TargetWnd=" << WaitingTargetWnd << ";cwnd=" << channel.mState.cwnd
																		 << ";sndBuf=" << channel.mSndBuf.Size()
																		 << ";sndQueue=" << channel.mSndQueue.Size());
			if (channel.mState.cwnd < WaitingTargetWnd || channel.mState.cwnd > channel.mState.snd_wnd)
			{
				ION_NET_CHANNEL_TUNER_LOG("ChannelTuner: Waiting completed;cwnd=" << channel.mState.cwnd);
				channel.mState.snd_wnd = ion::Max(MinSndWindowSize, channel.mState.cwnd);
				transport.mChannelTuner.mGoodWindowSize = channel.mState.snd_wnd;
				transport.mChannelTuner.mState = NetTransport::ChannelTuner::State::ScalingUpFast;
			}
			break;
		}
		}
		transport.mChannelTuner.FinishPeriod(now, dataPerMillis);
	}
}

void Update(NetTransport& transport, NetControl& control, NetRemoteSystem& remote, ion::TimeMS now)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(transport.mGuard);
	if (transport.mChannelTuner.mThreshold > NetTransport::ChannelTuner::MinThreshold)
	{
		UpdateChannelTuner(transport, remote, now);
	}

	NetChannelWriteContext context{control, remote, now, nullptr, ByteWriterUnsafe(nullptr)};
	ion::ForEach(transport.mOrderedChannels, [&context](NetChannel& iter) { iter.Update(context); });
}


}  // namespace ion::NetTransportLayer
