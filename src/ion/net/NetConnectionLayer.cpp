#include <ion/net/NetConnectionLayer.h>
#include <ion/net/NetConnections.h>
#include <ion/net/NetControlLayer.h>
#include <ion/net/NetExchangeLayer.h>
#include <ion/net/NetMessageIdentifiers.h>
#include <ion/net/NetPayload.h>
#include <ion/net/NetRawSendCommand.h>
#include <ion/net/NetRequestedConnections.h>
#include <ion/net/NetSecure.h>
#include <ion/net/NetSendCommand.h>
#include <ion/net/NetSocketLayer.h>
#include <ion/net/NetStartupParameters.h>
#include <ion/net/NetTransportLayer.h>

#include <ion/container/ForEach.h>

namespace ion
{
namespace NetConnectionLayer
{
namespace
{
NetPacket* AllocPacket(NetControl& control, unsigned dataSize)
{
	ion::NetPacket* p = ion::NetControlLayer::AllocateUserPacket(control, dataSize);
	p->mSource = nullptr;
	p->mLength = dataSize;
	p->mGUID = NetGuidUnassigned;
	p->mRemoteId = NetRemoteId();
	return p;
}

bool ValidateConnectionParameters(uint16_t mtu)
{
	if (mtu < NetPreferedMtuSize[NetNumMtuSizes - 1] || mtu > NetIpMaxMtuSize)
	{
		ION_NET_LOG_ABNORMAL("Connection parameters has invalid MTU:" << mtu << ";min=" << NetPreferedMtuSize[NetNumMtuSizes - 1]
																	  << ";max=" << NetIpMaxMtuSize);
		return false;
	}
	return true;
}

bool ValidateConnectionParameters(ion::TimeMS timeRead, ion::TimeMS sentTime, ion::TimeMS defaultTimeout, uint16_t mtu)
{
	if (!NetIsTimeInRange(timeRead, sentTime, NetRttTracker::MaxPingTime))
	{
		ION_NET_LOG_ABNORMAL("Connection parameters has invalid RTT");
		return false;
	}
	auto rtt = ion::DeltaTime(timeRead, sentTime);
	if (rtt < 0)
	{
		ION_NET_LOG_ABNORMAL("Connection parameters has invalid RTT");
		return false;
	}
	if (rtt > int32_t(defaultTimeout))
	{
		ION_NET_LOG_ABNORMAL("Connection parameters timed out;rtt=" << rtt);
		return false;
	}
	return ValidateConnectionParameters(mtu);
}

// For packets that are used for checking MTU size, we are using random data to reduce chances for underlaying network layer to be able to
// compress the packet and transmit smaller packet than intended.
void AddPaddingWithRandomData(ByteWriter& writer, size_t count, uint64_t seed)
{
	for (size_t i = 0; i < count; i++)
	{
		constexpr uint8_t Salt = 0xA5;
		writer.WriteKeepCapacity(uint8_t(uint8_t(i) ^ seed ^ Salt));
	}
}

void SendOpenConnectionRequest1(const RequestedConnection& rcs, int MTUSizeIndex, NetSocket* socketToUse, ion::TimeMS now)
{
	const unsigned int MessageSize = ion::NetUdpPayloadSize(NetPreferedMtuSize[MTUSizeIndex]);

	NetRawSendCommand msg(*socketToUse, MessageSize);
	if (msg.HasBuffer())
	{
		{
			ByteWriter writer(msg.Writer());
			writer.Process(NetMessageId::OpenConnectionRequest1);
			writer.Process(NetUnconnectedHeader);
#if ION_NET_FEATURE_SECURITY
			writer.Process(rcs.mNonce);
#endif
			AddPaddingWithRandomData(writer, writer.Available(), now);
		}
		// Tell network we don't want it to fragment packets, but assume minimum size does not get
		// fragmented in any case
		socketToUse->mSocketSendResults.Prepare(rcs.systemAddress);
		msg.Parameters().DoNotFragment(MTUSizeIndex != (NetNumMtuSizes - 1)).StoreSocketSendResult();
		msg.Dispatch(rcs.systemAddress);
	}
}

}  // namespace

void SendOpenConnectionRequests(ion::NetConnections& connections, NetControl& control, NetExchange& exchange, ion::TimeMS now)
{
	connections.mRequestedConnections.Access(
	  [&](ion::RequestedConnections& rc)
	  {
		  ION_PROFILER_SCOPE(Network, "Requested connections");
		  while (!rc.mCancels.IsEmpty())
		  {
			  auto iter = rc.mRequests.Find(rc.mCancels.Back());
			  if (iter != rc.mRequests.End())
			  {
				  ION_NET_LOG_VERBOSE("Connection request canceled by user request");
				  ClearConnectionRequest(connections, iter->second);
				  rc.mRequests.Erase(iter);
			  }
			  rc.mCancels.PopBack();
		  }

		  ion::ForEachErase(
			rc.mRequests,
			[&](std::pair<const ion::NetSocketAddress, ion::RequestedConnection>& item)
			{
				ion::RequestedConnection& rcs = item.second;
				auto remoteSystem = NetExchangeLayer::GetRemoteFromSocketAddress(exchange, rcs.systemAddress, true, true);
				if (remoteSystem != nullptr && remoteSystem->mMode == NetMode::Connected)
				{
					// This can happen on cross-connection cases: we already completed connection request by other end and our own
					// connection request is not needed anymore.
					ION_DBG_TAG(Network, "Connection request canceled: Already connected");
					ClearConnectionRequest(connections, rcs);
					return ion::ForEachOp::Erase;
				}

				if (ion::DeltaTime(rcs.nextRequestTime, now) < 0)
				{
					int MTUSizeIndex = rcs.requestsMade / (rcs.sendConnectionAttemptCount / NetNumMtuSizes);
					if (MTUSizeIndex >= NetNumMtuSizes)
					{
						MTUSizeIndex = NetNumMtuSizes - 1;
					}
					NetSocket* socketToUse;
					if (rcs.socket == 0)
					{
						socketToUse = connections.mSocketList[rcs.socketIndex];
					}
					else
					{
						socketToUse = rcs.socket;
					}

					if (rcs.actionToTake == ion::RequestedConnection::WAIT_FOR_SOCKET_RESULT)
					{
						constexpr ion::TimeMS AbnormalSocketDelay = 5000;
						int socketCode = socketToUse->mSocketSendResults.Get(rcs.systemAddress);
						if (socketCode != 0)
						{
							rcs.requestsMade++;
							rcs.actionToTake = ion::RequestedConnection::CONNECT;
							if (socketCode > 0)
							{
								constexpr ion::TimeMS ReduceMTUSocketDelay = 30 * ion::NetUpdateInterval;
								if (MTUSizeIndex != NetNumMtuSizes - 1 &&  // Don't timeout when already using lowest MTU
									ion::DeltaTime(now, rcs.nextRequestTime) > ReduceMTUSocketDelay)
								{
									// Go to lower MTU size if socket is not responsive
									ION_NET_LOG_VERBOSE("Socket delay;MTU=" << NetPreferedMtuSize[MTUSizeIndex]
																			<< ";Request=" << rcs.requestsMade
																			<< ";Delay=" << ion::DeltaTime(now, rcs.nextRequestTime));
									rcs.requestsMade =
									  (unsigned char)((MTUSizeIndex + 1) * (rcs.sendConnectionAttemptCount / NetNumMtuSizes));
								}
								ION_NET_LOG_VERBOSE("Connection request " << rcs.requestsMade
																		  << " sent;MTU=" << NetPreferedMtuSize[MTUSizeIndex]);
								rcs.nextRequestTime = now + rcs.timeBetweenSendConnectionAttemptsMS;
							}
							else
							{
								ION_NET_LOG_ABNORMAL("Socket send error;MTU " << NetPreferedMtuSize[MTUSizeIndex]
																			  << ";Request=" << rcs.requestsMade << ";Code=" << socketCode);
								if (socketCode == -10040)  // Message too large
								{
									// Don't use this MTU size again
									rcs.requestsMade =
									  (unsigned char)((MTUSizeIndex + 1) * (rcs.sendConnectionAttemptCount / NetNumMtuSizes));
								}
								rcs.nextRequestTime = now;
							}
						}
						else if (ion::DeltaTime(now, rcs.nextRequestTime) >= AbnormalSocketDelay)
						{
							ION_ABNORMAL_ONCE(5.0, "Socket does not respond");
						}
					}
					else
					{
						bool condition1, condition2;
						ION_ASSERT(socketToUse->mSocketSendResults.Get(rcs.systemAddress) == 0, "Old result left");
						condition1 = rcs.requestsMade == rcs.sendConnectionAttemptCount + 1;
						condition2 = (bool)((rcs.systemAddress == NetUnassignedSocketAddress) == 1);
						// If too many requests made or a hole then remove this if possible, otherwise invalidate it
						if (condition1 || condition2)
						{
							if (condition1 && !condition2 && rcs.actionToTake == ion::RequestedConnection::CONNECT)
							{
								ION_NET_LOG_VERBOSE("Connection failed;attempts=" << (rcs.sendConnectionAttemptCount + 1));
								NetPacket* packet = AllocPacket(control, sizeof(char));
								packet->Data()[0] = NetMessageId::ConnectionAttemptFailed;	// Attempted a connection and couldn't
								// packet->bitSize = (sizeof(char) * 8);
								packet->mAddress = rcs.systemAddress;
								NetControlLayer::AddPacketToProducer(control, packet);
							}
							ION_DBG_TAG(Network, "Connection request canceled due to too many requests");
							ClearConnectionRequest(connections, rcs);
							return ion::ForEachOp::Erase;
						}
						else
						{
							rcs.actionToTake = ion::RequestedConnection::WAIT_FOR_SOCKET_RESULT;
							rcs.nextRequestTime = now;
							SendOpenConnectionRequest1(rcs, MTUSizeIndex, socketToUse, now);
						}
					}
				}
				return ion::ForEachOp::Next;
			});
	  });
}

bool ProcessOfflineNetworkPacket(ion::NetConnections& connections, NetControl& control, NetExchange& exchange,
								 ion::NetSocketReceiveData& recvFromStruct, ion::TimeMS timeRead)
{
	auto* netSocket = recvFromStruct.Socket();
	auto& socketAddress = recvFromStruct.Address();
	auto* data = recvFromStruct.mPayload;
	uint32_t length = recvFromStruct.SocketBytesRead();

	ion::NetRemoteSystem* remoteSystem;
	ion::NetPacket* packet;

	switch ((NetMessageId)data[0])
	{
	case NetMessageId::UnconnectedPingOpenConnections:
		[[fallthrough]];
	case NetMessageId::UnconnectedPing:
	{
		if ((NetMessageId)(data)[0] == NetMessageId::UnconnectedPing ||
			NetExchangeLayer::AllowIncomingConnections(exchange))  // Open connections with players
		{
			ion::Time remoteTime;
			NetGUID remoteGuid = NetGuidUnassigned;
			{
				ion::ByteReader reader(data, length);
				reader.SkipBytes(1 + sizeof(NetUnconnectedHeader));
				bool isValid = reader.Process(remoteTime);
				isValid &= reader.Process(remoteGuid);
				if (!isValid)
				{
					break;
				}
			}
			NetRawSendCommand pong(*netSocket);
			{
				ion::ByteWriter writer(pong.Writer());
				writer.Process(NetMessageId::UnconnectedPong);
				writer.Process(NetUnconnectedHeader);
				writer.Process(remoteTime);
				writer.Process(exchange.mGuid);
				writer.WriteArray((const unsigned char*)connections.mOffline.mResponse.Data(), connections.mOffline.mResponseLength);
			}
			pong.Dispatch(socketAddress);

			packet = AllocPacket(control, sizeof(NetMessageId));
			packet->Data()[0] = data[0];
			packet->mAddress = socketAddress;
			packet->mRemoteId = ion::NetExchangeLayer::RemoteId(exchange, socketAddress);
			packet->mGUID = remoteGuid;
			NetControlLayer::AddPacketToProducer(control, packet);
		}
		return true;
	}
	case NetMessageId::UnconnectedPong:
	{
		constexpr size_t PayloadTotalBytes = sizeof(NetMessageId) + sizeof(ion::Time) + NetGUID::size();
		constexpr size_t Headersize = PayloadTotalBytes + sizeof(NetUnconnectedHeader);
		if ((size_t)length <= Headersize + MAX_OFFLINE_DATA_LENGTH && length >= Headersize)
		{
			const size_t UserDataSize = length - Headersize;

			packet = AllocPacket(control, (unsigned int)(UserDataSize + 1 + sizeof(ion::Time)));
			ion::Time sentPingTime;
			{
				ion::ByteReader reader(data, length);
				reader.SkipBytes(sizeof(unsigned char));
				reader.SkipBytes(sizeof(NetUnconnectedHeader));
				reader.ReadAssumeAvailable(sentPingTime);
				reader.ReadAssumeAvailable(packet->mGUID.Raw());

				ByteBufferView<byte*> packetView(packet->Data(), packet->Length());
				ion::ByteWriter writer(packetView);
				writer.Process((unsigned char)NetMessageId::UnconnectedPong);
				writer.Process(sentPingTime);
				writer.Copy(reader);
			}

			packet->mAddress = socketAddress;
			NetControlLayer::AddPacketToProducer(control, packet);
		}
		return true;
	}
	case NetMessageId::OutOfBandInternal:
	{
		constexpr uint32_t HeaderSize = sizeof(NetUnconnectedHeader) + NetGUID::size() + sizeof(NetMessageId);
		if ((size_t)length < MAX_OFFLINE_DATA_LENGTH + HeaderSize && length >= HeaderSize)
		{
			unsigned int dataLength = (unsigned int)(length - HeaderSize);
			ION_NET_ASSERT(dataLength < 1024);
			packet = AllocPacket(control, dataLength + 1);
			ION_NET_ASSERT(packet->Length() < 1024);

			ion::ByteReader bs2((unsigned char*)data, length);
			bs2.SkipBytes(sizeof(NetMessageId));
			bs2.SkipBytes(sizeof(NetUnconnectedHeader));
			bs2.Process(packet->mGUID);

			NetMessageId cmd;
			bs2.Process(cmd);
			if (cmd == NetMessageId::AdvertiseSystem)
			{
				packet->mLength--;
				packet->Data()[0] = (byte)NetMessageId::AdvertiseSystem;
				memcpy(packet->Data() + 1, data + sizeof(NetUnconnectedHeader) + sizeof(NetMessageId) * 2 + NetGUID::size(),
					   dataLength - 1);
			}
			else
			{
				packet->Data()[0] = (byte)NetMessageId::OutOfBandInternal;
				memcpy(packet->Data() + 1, data + sizeof(NetUnconnectedHeader) + sizeof(NetMessageId) + NetGUID::size(), dataLength);
			}

			packet->mAddress = socketAddress;
			NetControlLayer::AddPacketToProducer(control, packet);
		}
		return true;
	}
	case NetMessageId::OpenConnectionReply1:
	{
		uint16_t mtu = ion::SafeRangeCast<uint16_t>(ion::NetMtuSize(length));

		if (!ValidateConnectionParameters(mtu))
		{
			break;
		}

		ion::ByteReader bsIn((unsigned char*)data, length);

		bool wasFound = false;
		connections.mRequestedConnections.Access(
		  [&](ion::RequestedConnections& rcss)
		  {
			  auto iter = rcss.mRequests.Find(socketAddress);
			  if (iter != rcss.mRequests.End())
			  {
				  wasFound = true;

				  /* #if ION_NET_FEATURE_SECURITY
									size_t CryptedDataLen = 13 + ion::NetSecure::AuthenticationTagLength;
									if (length < CryptedDataLen || !ion::NetSecure::Decrypt(bsIn.Begin() + 1, bsIn.Begin() + 1,
					 CryptedDataLen, iter->second.mNonce.Data(), rakPeer.mPeer->mSecretKey))
									{
										ION_NET_SECURITY_AUDIT_PRINTF("AUDIT: Remote message could not be decrypted.");
										packet = rakPeer.AllocPacket(sizeof(char));
										packet->data[0] = NetMessageId::InvalidSecretKey;
										packet->length = sizeof(char);
										packet->systemAddress = iter->second.systemAddress;
										packet->guid = NetGuidUnassigned;
										NetControlLayer::AddPacketToProducer(packet);

 rakPeer.ClearConnectionRequest(iter->second);
										rcss.mRequests.Erase(iter);
										return;
									}
#endif*/

				  bsIn.SkipBytes(sizeof(NetMessageId) + sizeof(NetUnconnectedHeader));
				  NetGUID remoteGuid;
				  bsIn.Process(remoteGuid);

				  if (remoteGuid == exchange.mGuid)
				  {
					  if (!ion::NetExchangeLayer::RegenerateGuid(exchange))
					  {
						  // Filter logging when potentially connecting to self.
						  NetSocketAddress internalId;
						  ion::NetConnectionLayer::GetInternalID(connections, internalId, 0);
						  if (iter->second.systemAddress.GetPort() != internalId.GetPort())
						  {
							  ION_NET_LOG_INFO("GUID collision. Cancel connection attempt;GUID=" << remoteGuid << ";RemoteAddress="
																								 << iter->second.systemAddress
																								 << ";OwnAddress=" << internalId);
						  }
						  else
						  {
							  ION_NET_LOG_VERBOSE("GUID collision or tried to connect to self. Cancel connection attempt");
						  }
						  packet = AllocPacket(control, sizeof(char));
						  packet->Data()[0] = (byte)NetMessageId::ConnectionAttemptFailed;	// Attempted a connection and couldn't
						  packet->mAddress = iter->second.systemAddress;
						  packet->mGUID = remoteGuid;
						  NetControlLayer::AddPacketToProducer(control, packet);

						  ClearConnectionRequest(connections, iter->second);
						  rcss.mRequests.Erase(iter);
						  return;
					  }
					  else
					  {
						  ION_NET_LOG_INFO("Duplicate GUID while not yet connected. Changed GUID to " << exchange.mGuid);
					  }
				  }

				  ion::TimeMS remoteTime;
				  bsIn.Process(remoteTime);

				  NetDataTransferSecurity dataTransferSecurity;
				  bsIn.Process(dataTransferSecurity);

				  auto* rcs = &iter->second;
				  if (exchange.mDataTransferSecurity != dataTransferSecurity)
				  {
					  ION_NET_SECURITY_AUDIT_PRINTF("AUDIT: Remote is not having same data transfer security. Failing.");
					  packet = AllocPacket(control, sizeof(char));
					  packet->Data()[0] = (byte)NetMessageId::ConnectionAttemptFailed;	// Attempted a connection and couldn't
					  packet->mAddress = rcs->systemAddress;
					  packet->mGUID = remoteGuid;
					  NetControlLayer::AddPacketToProducer(control, packet);

					  ClearConnectionRequest(connections, iter->second);
					  rcss.mRequests.Erase(iter);
					  return;
				  }

				  NetRawSendCommand ocr2msg(*netSocket);
				  {
					  ByteWriter ocr2writer(ocr2msg.Writer());
					  ocr2writer.Process(NetMessageId::OpenConnectionRequest2);
					  ocr2writer.Process(NetUnconnectedHeader);
					  ocr2writer.Process(rcs->systemAddress);  // Binding address
					  ocr2writer.Process(timeRead);
					  ocr2writer.Process(remoteTime);
					  ocr2writer.Process(mtu);
					  ocr2writer.Process(exchange.mGuid);
#if ION_NET_FEATURE_SECURITY
					  if (dataTransferSecurity == NetDataTransferSecurity::Secure)
					  {
						  ION_NET_SECURITY_AUDIT_PRINTF("AUDIT: Remote is expecting security. Sending public key.");
						  ocr2writer.WriteArrayKeepCapacity((u8*)netSocket->mCryptoKeys.mPublicKey.data,
															sizeof(netSocket->mCryptoKeys.mPublicKey.data));
						  ocr2writer.WriteArrayKeepCapacity((u8*)netSocket->mNonceOffset.Data(), netSocket->mNonceOffset.ElementCount);
					  }
					  else
#endif
					  {
						  ION_NET_SECURITY_AUDIT_PRINTF("AUDIT: Encryption is not used.");
					  }
				  }
				  ocr2msg.Dispatch(socketAddress);
			  }
		  });
		if (!wasFound)
		{
			ION_NET_LOG_VERBOSE("Connection not found for open connection reply");
		}
		return true;
	}
	case NetMessageId::OpenConnectionReply2:
	{
		ion::NetExchangeLayer::RemoteSystemParameters rsp;
		ion::ByteReader bs((unsigned char*)data, length);
		bs.SkipBytes(sizeof(NetMessageId) + sizeof(NetUnconnectedHeader));
		bool isValid = bs.Process(rsp.guid);
		ion::NetSocketAddress bindingAddress;
		isValid &= bs.Process(bindingAddress);
		ion::Time remoteTime;
		isValid &= bs.Process(remoteTime);
		ion::Time sentPingTime;
		isValid &= bs.Process(sentPingTime);
		isValid &= bs.Process(rsp.incomingMTU);

		isValid &= ValidateConnectionParameters(timeRead, sentPingTime, exchange.mDefaultTimeoutTime, rsp.incomingMTU);

		isValid &= bs.Process(rsp.mDataTransferSecurity);
		isValid &= bs.Process(rsp.mConversationId);
		isValid &= !NetIsUnconnectedId(rsp.mConversationId);

		NetGUID thisGuid;
		isValid &= bs.Process(thisGuid);
		// Got back our own GUID or authority gave as a new GUID.
		isValid &=
		  (thisGuid == exchange.mGuid || (rsp.guid == NetGuidAuthority && exchange.mGuid != NetGuidAuthority)) && thisGuid != rsp.guid;
#if ION_NET_FEATURE_SECURITY
		NetSecure::PublicKey publicKey;
		NetSecure::SharedKey sharedKey;
		decltype(NetRemoteSystem::mNonceOffset) nonceOffset;

		if (rsp.mDataTransferSecurity == NetDataTransferSecurity::Secure)
		{
			isValid &= bs.ReadArray(publicKey.data, NetSecure::PublicKeyLength);
			if (isValid && ion::NetSecure::ComputeSharedCryptoKeys(sharedKey, netSocket->mCryptoKeys, publicKey) == 0)
			{
				ION_NET_SECURITY_AUDIT_PRINTF("AUDIT: Got server response with security parameters");
				isValid &= bs.ReadArray(nonceOffset.Data(), nonceOffset.ElementCount);
			}
			else
			{
				ION_NET_SECURITY_AUDIT_PRINTF("AUDIT: Invalid server public key");
				isValid = false;
			}
		}
#endif
		if (isValid)
		{
			connections.mRequestedConnections.Access(
			  [&](ion::RequestedConnections& data)
			  {
				  auto iter = data.mRequests.Find(socketAddress);
				  if (iter != data.mRequests.End())
				  {
					  const ion::RequestedConnection* rcs = &iter->second;

					  if (thisGuid != exchange.mGuid)
					  {
						  // Authority gave new GUID for us
						  ION_NET_LOG_VERBOSE("GUID changed from " << exchange.mGuid << " to " << thisGuid);
						  exchange.mGuid = thisGuid;
						  if (exchange.mActiveSystemListSize > 0)
						  {
							  ION_NET_LOG_ABNORMAL("GUID changed when already connected");
						  }
					  }

					  // You might get this when already connected because of cross-connections
					  remoteSystem = NetExchangeLayer::GetRemoteFromSocketAddress(exchange, socketAddress, true, true);
					  if (remoteSystem == 0)
					  {
						  rsp.incomingNetSocket = rcs->socket ? rcs->socket : netSocket;
						  rsp.mIsRemoteInitiated = false;
						  bool thisIPConnectedRecently = false; /* Don't care if we connected recently or not */
						  remoteSystem = ion::NetExchangeLayer::AssignSystemAddressToRemoteSystemList(
							exchange, connections, control.mMemoryResource, rsp, socketAddress, bindingAddress, &thisIPConnectedRecently);
					  }
					  else if (remoteSystem->mConversationId != rsp.mConversationId)
					  {
						  // ConversationId clash. System with lower GUID decides.
						  if (remoteSystem->guid < exchange.mGuid)
						  {
							  ION_NET_LOG_VERBOSE("[" << exchange.mGuid << "] Using conversation key from remote " << remoteSystem->guid);
							  if (exchange.mGuid == NetGuidAuthority)
							  {
								  exchange.mAuthorityConversations.RemoveKey(remoteSystem->mConversationId);
								  exchange.mAuthorityConversations.StoreKey(rsp.mConversationId, remoteSystem->mId.load().RemoteIndex());
							  }
							  remoteSystem->mConversationId = rsp.mConversationId;
							  NetTransportLayer::Reset(remoteSystem->mTransport, control, *remoteSystem);
						  }
					  }

					  // Don't check GetRemoteSystemFromGUID, server will verify
					  if (remoteSystem)
					  {
#if ION_NET_FEATURE_SECURITY
						  remoteSystem->mNonceOffset = nonceOffset;
						  remoteSystem->mSharedKey = sharedKey;
#endif

						  // Setup ping tracker so that we have at least approximate for remote clock.
						  remoteSystem->pingTracker.OnPing(sentPingTime);
						  remoteSystem->pingTracker.OnPong(timeRead, sentPingTime, remoteTime);
						  if (!remoteSystem->pingTracker.HasSamples())
						  {
							  ION_NET_LOG_ABNORMAL("Server clock synchronization failed");
							  // New connection attempt via request connection queue
							  return;
						  }
						  else
						  {
							  // We can get here also when we are already connected or handling other's connection request
							  if (remoteSystem->mMode == NetMode::UnverifiedSender || remoteSystem->mMode == NetMode::RequestedConnection)
							  {
								  if (remoteSystem->MTUSize != rsp.incomingMTU ||
									  remoteSystem->mDataTransferSecurity != rsp.mDataTransferSecurity)
								  {
									  ION_NET_LOG_ABNORMAL("Connection parameters renegotiated, flushing reliable channels");
									  remoteSystem->MTUSize = rsp.incomingMTU;
									  remoteSystem->mDataTransferSecurity = rsp.mDataTransferSecurity;
									  NetTransportLayer::Reset(remoteSystem->mTransport, control, *remoteSystem);
								  }

								  ion::NetExchangeLayer::SetMode(exchange, *remoteSystem, NetMode::RequestedConnection);
								  ion::NetExchangeLayer::SetRemoteInitiated(exchange, *remoteSystem, false);
							  }

							  if (rcs->timeoutTimeMs != 0)
							  {
								  remoteSystem->timeoutTime = rcs->timeoutTimeMs;
							  }

							  NetSendCommand cmd(control, socketAddress, 64);
							  if (cmd.HasBuffer())
							  {
								  {
									  ByteWriter writer(cmd.Writer());
									  writer.Process(NetMessageId::ConnectionRequest);
									  writer.Process(exchange.mGuid);
									  writer.Process(timeRead);

									  if (rcs->mPassword.Size() > 0)
									  {
										  writer.WriteArray((u8*)rcs->mPassword.Data(), rcs->mPassword.Size());
									  }
								  }
								  remoteSystem->pingTracker.OnPing(timeRead);

								  cmd.Parameters().mPriority = NetPacketPriority::Immediate;

								  ion::NetExchangeLayer::SendImmediate(exchange, control, cmd.Release(), timeRead);
							  }
						  }
						  ION_NET_LOG_VERBOSE("[" << exchange.mGuid << "] Our connection request to " << remoteSystem->guid
												  << " was accepted");
					  }
					  else
					  {
						  ION_NET_LOG_ABNORMAL("[" << exchange.mGuid << "] Cannot connect " << rsp.guid << ", no connections available");
						  packet = AllocPacket(control, sizeof(char));
						  packet->Data()[0] = NetMessageId::ConnectionAttemptFailed;  // Attempted a connection and couldn't
						  packet->mAddress = rcs->systemAddress;
						  packet->mGUID = rsp.guid;
						  NetControlLayer::AddPacketToProducer(control, packet);
					  }
					  ClearConnectionRequest(connections, iter->second);
					  data.mRequests.Erase(iter);
				  }
			  });
		}
		else
		{
			ION_NET_LOG_ABNORMAL("Invalid message");
		}
		return true;
	}
		MESSAGE_CONNECTION_ATTEMPT_CANCEL
		{
			ion::ByteReader bs((unsigned char*)data, length);
			bs.SkipBytes(sizeof(NetMessageId));
			uint32_t unconnectedHeader;
			bs.Process(unconnectedHeader);
			if ((NetMessageId)(data)[0] == NetMessageId::IncompatibleProtocolVersion)
			{
				ION_NET_LOG_INFO("Remote protocol version=" << (unconnectedHeader >> 24))
			}
			NetGUID guid;
			bs.Process(guid);

			bool connectionAttemptCancelled = false;
			connections.mRequestedConnections.Access(
			  [&](ion::RequestedConnections& rc)
			  {
				  auto iter = rc.mRequests.Find(socketAddress);
				  if (iter != rc.mRequests.End())
				  {
					  if ((NetMessageId)(data)[0] == NetMessageId::GuidReserved)
					  {
						  NetGUID sentGuid;
						  bs.Process(sentGuid);
						  if (sentGuid != exchange.mGuid)
						  {
							  // Ignore response, this is not for our GUID
							  return;
						  }

						  // Workaround for rare edge case of our random GUIDs colliding.
						  if (guid == exchange.mGuid)
						  {
							  // Note that GUID collision was checked first on connection reply 1 handling
							  // If we still have GUID collision it's likely we are connecting to own address
							  ION_NET_LOG_INFO("GUID reserved: Trying to connect own address;Target=" << iter->second.systemAddress);
						  }
						  else if (ion::NetExchangeLayer::RegenerateGuid(exchange))
						  {
							  ION_NET_LOG_INFO("Duplicate GUID while not yet connected. Changed GUID from " << sentGuid << " to "
																											<< exchange.mGuid);
							  return;
						  }
						  else
						  {
							  // Cannot regenerate guid as we are probably already part of mesh->
							  // We'll need to cancel connection attempt and let user use decide what to do.
							  ION_NET_LOG_INFO("GUID reserved: Our guid=" << exchange.mGuid << ";Remote=" << guid);
						  }
					  }
					  ION_NET_LOG_VERBOSE("Connection request canceled due to message " << (unsigned char)(data)[0]);
					  ClearConnectionRequest(connections, iter->second);
					  rc.mRequests.Erase(iter);
				  }
				  connectionAttemptCancelled = true;
			  });

			if (connectionAttemptCancelled)
			{
				// Tell user of connection attempt failed
				packet = AllocPacket(control, sizeof(char));
				packet->Data()[0] = data[0];  // Attempted a connection and couldn't
				packet->mAddress = socketAddress;
				packet->mGUID = guid;
				NetControlLayer::AddPacketToProducer(control, packet);
			}

			return true;
		}
	case NetMessageId::OpenConnectionRequest1:
	{
		ion::ByteReader bs((unsigned char*)data, length);
		bs.SkipBytes(sizeof(NetMessageId));

		bool isValid = true;
		uint32_t remoteProtocolHeader;
		isValid &= bs.Process(remoteProtocolHeader);

#if ION_NET_FEATURE_SECURITY
		ion::Array<unsigned char, ion::NetSecure::NonceLength> nonce;
		isValid &= bs.Process(nonce);
#endif

		if (remoteProtocolHeader != NetUnconnectedHeader)
		{
			ION_NET_LOG_ABNORMAL("Incompatible protocol version: " << remoteProtocolHeader << ";expected:" << NetUnconnectedHeader);
			NetRawSendCommand cmd(*netSocket);
			{
				ByteWriter writer(cmd.Writer());
				writer.Process(NetMessageId::IncompatibleProtocolVersion);
				writer.Process(NetUnconnectedHeader);
				writer.Process(exchange.mGuid);
			}
			cmd.Dispatch(socketAddress);
			return true;
		}

		if (exchange.mMaximumIncomingConnections == 0)
		{
			ION_NET_LOG_ABNORMAL("Connection attempt when not accepting connections");
			NetRawSendCommand cmd(*netSocket);
			{
				ByteWriter writer(cmd.Writer());
				writer.Process(NetMessageId::NoFreeIncomingConnections);
				writer.Process(NetUnconnectedHeader);
				writer.Process(exchange.mGuid);
			}
			cmd.Dispatch(socketAddress);
			return true;
		}

		uint16_t mtu = ion::SafeRangeCast<uint16_t>(ion::NetMtuSize(length));
		if (mtu > NetIpMaxMtuSize)
		{
			// Lower MTU if it exceeds our own limit.
			mtu = NetIpMaxMtuSize;
		}
		if (mtu < NetPreferedMtuSize[NetNumMtuSizes - 1])
		{
			// Assume minimum MTU size
			mtu = NetPreferedMtuSize[NetNumMtuSizes - 1];
		}

		NetRawSendCommand msg(*netSocket, ion::NetUdpPayloadSize(mtu));
		if (msg.HasBuffer())
		{
			{
				ByteWriter writer(msg.Writer());
				writer.Process(NetMessageId::OpenConnectionReply1);
				writer.Process(NetUnconnectedHeader);
				/* #if ION_NET_FEATURE_SECURITY
						bsOut.Write((unsigned char)(rakPeer.mUsingSecurity));
						for (size_t i = 0; i < ion::NetSecure::AuthenticationTagLength; ++i)
						{
							bsOut.Write(uint8_t(0));
						}
				#endif*/
				writer.Process(exchange.mGuid);
				writer.Process(timeRead);
				writer.Process(exchange.mDataTransferSecurity);
				/* [[maybe_unused]] int res = ion::NetSecure::Encrypt(
				  bsOut.Begin() + 1, bsOut.Begin() + 1 + ion::NetSecure::AuthenticationTagLength,
																   13, nonce.Data(), rakPeer.mPeer->mSecretKey);*/
				// Pad response to MTU size so the connection's MTU will be tested in both directions
				AddPaddingWithRandomData(writer, writer.Available(), timeRead);
			}
			msg.Parameters().DoNotFragment(mtu != NetPreferedMtuSize[NetNumMtuSizes - 1]);
			msg.Dispatch(socketAddress);
		}
		return true;
	}
	case NetMessageId::OpenConnectionRequest2:
	{
		bool isValid = true;
		ion::NetSocketAddress bindingAddress;
		NetGUID guid;
		ion::ByteReader bs((unsigned char*)data, length);
		bs.SkipBytes(sizeof(NetMessageId));
		uint32_t unconnectedHeader;
		isValid &= bs.Process(unconnectedHeader);
		if (unconnectedHeader != NetUnconnectedHeader)
		{
			ION_NET_LOG_ABNORMAL("Connection request 2 has invalid protocol header");
			break;
		}
		isValid &= bs.Process(bindingAddress);

		if (!bindingAddress.IsValid())
		{
			ION_NET_LOG_ABNORMAL("Connection request 2 has invalid binding address");
			break;
		}

		ion::Time remoteTime, sentTime;
		isValid &= bs.Process(remoteTime);
		isValid &= bs.Process(sentTime);
		uint16_t mtu;
		isValid &= bs.Process(mtu);

		// AssignRemote() will handle invalid GUID, GUID collisions and reassigning guid if needed
		isValid &= bs.Process(guid);

		if (!isValid || !ValidateConnectionParameters(timeRead, sentTime, exchange.mDefaultTimeoutTime, mtu))
		{
			ION_NET_LOG_ABNORMAL("Invalid OpenConnectionRequest2");
			break;
		}

		ion::NetExchangeLayer::ConnectionResult result = ion::NetExchangeLayer::AssignRemote(
		  exchange, connections, control.mMemoryResource, socketAddress, bindingAddress, netSocket, guid,
		  exchange.mDataTransferSecurity,  // #TODO: Security exceptions
		  mtu);

		NetRawSendCommand reply(*netSocket);
		{
			auto replyWriter = reply.Writer();
			switch (result.outcome)
			{
			case ion::NetExchangeLayer::ConnectionResponse::IPConnectedRecently:
			{
				replyWriter.Process(NetMessageId::IpRecentlyConnected);
				replyWriter.Process(NetUnconnectedHeader);
				replyWriter.Process(exchange.mGuid);
				break;
			}
			case ion::NetExchangeLayer::ConnectionResponse::GUIDReserved:
			{
				// Not an abnormal case as our GUIDs are random so it's normal that there are occasionally duplicates
				replyWriter.Process(NetMessageId::GuidReserved);
				replyWriter.Process(NetUnconnectedHeader);
				replyWriter.Process(exchange.mGuid);
				replyWriter.Process(guid);
				break;
			}
			case ion::NetExchangeLayer::ConnectionResponse::AlreadyConnected:
			{
				// Not an abnormal case as connection response can get lost due to packet loss.
				replyWriter.Process(NetMessageId::AlreadyConnected);
				replyWriter.Process(NetUnconnectedHeader);
				replyWriter.Process(exchange.mGuid);
				break;
			}
			default:
			{
				if (!result.rssFromSA)
				{
					ION_ASSERT(result.outcome == ion::NetExchangeLayer::ConnectionResponse::Ok, "Unhandled outcome");
					ION_NET_LOG_VERBOSE("Out of free connections;Number of remote initiated connections="
										<< unsigned(exchange.mNumberOfIncomingConnections)
										<< ";MaxInconing=" << unsigned(exchange.mMaximumIncomingConnections));
					replyWriter.Process(NetMessageId::NoFreeIncomingConnections);
					replyWriter.Process(NetUnconnectedHeader);
					replyWriter.Process(exchange.mGuid);
					break;
				}

#if ION_NET_FEATURE_SECURITY == 1
				if (exchange.mDataTransferSecurity == NetDataTransferSecurity::Secure)
				{
					ION_NET_SECURITY_AUDIT_PRINTF("AUDIT: Server is using encryption");
					if (result.outcome != ion::NetExchangeLayer::ConnectionResponse::RepeatAnswer)
					{
						ION_ASSERT(result.outcome == ion::NetExchangeLayer::ConnectionResponse::Ok, "Unhandled outcome");
						NetSecure::PublicKey publicKey;
						isValid &= bs.ReadArray(publicKey.data, NetSecure::PublicKeyLength);
						isValid &= bs.ReadArray(result.rssFromSA->mNonceOffset.Data(), result.rssFromSA->mNonceOffset.ElementCount);

						if (!isValid ||
							ion::NetSecure::ComputeSharedCryptoKeys(result.rssFromSA->mSharedKey, netSocket->mCryptoKeys, publicKey) != 0)
						{
							ION_NET_SECURITY_AUDIT_PRINTF("AUDIT: Invalid client public key");

							ion::NetExchangeLayer::ResetRemoteSystem(exchange, control, control.mMemoryResource,
																	 result.rssFromSA->mId.load().RemoteIndex(), timeRead);
							replyWriter.Process(NetMessageId::ConnectionAttemptFailed);
							replyWriter.Process(NetUnconnectedHeader);
							replyWriter.Process(exchange.mGuid);
							replyWriter.Process(guid);
							break;
						}
						else
						{
							ION_NET_SECURITY_AUDIT_PRINTF("AUDIT: Received valid public key from client");
						}
					}
				}
				else
				{
					ION_NET_SECURITY_AUDIT_PRINTF("AUDIT: Server is not using encryption");
				}
#endif

				if (result.outcome != ion::NetExchangeLayer::ConnectionResponse::RepeatAnswer)
				{
					ION_ASSERT(result.outcome == ion::NetExchangeLayer::ConnectionResponse::Ok, "Unhandled outcome");
					auto& rssFromSA = result.rssFromSA;

					// Setup ping tracker
					rssFromSA->pingTracker.OnPing(sentTime);
					rssFromSA->pingTracker.OnPong(timeRead, sentTime, remoteTime);
					if (!rssFromSA->pingTracker.HasSamples())
					{
						ION_NET_LOG_ABNORMAL("Invalid RTT to remote client");
						rssFromSA->pingTracker.OnPing(timeRead - 250);
						rssFromSA->pingTracker.OnPong(timeRead, timeRead - 250, remoteTime);
					}
				}

				replyWriter.Process(NetMessageId::OpenConnectionReply2);
				replyWriter.Process(NetUnconnectedHeader);
				replyWriter.Process(exchange.mGuid);
				replyWriter.Process(socketAddress);
				replyWriter.Process(timeRead);
				replyWriter.Process(remoteTime);
				replyWriter.Process(mtu);
				replyWriter.Process(exchange.mDataTransferSecurity);
				replyWriter.Process(result.rssFromSA->mConversationId);
				replyWriter.Process(result.rssFromSA->guid);
#if ION_NET_FEATURE_SECURITY == 1
				if (exchange.mDataTransferSecurity == NetDataTransferSecurity::Secure)
				{
					ION_NET_SECURITY_AUDIT_PRINTF("AUDIT: Sending server public key.");
					replyWriter.WriteArray((u8*)netSocket->mCryptoKeys.mPublicKey.data, sizeof(netSocket->mCryptoKeys.mPublicKey.data));
					replyWriter.WriteArray((u8*)netSocket->mNonceOffset.Data(), netSocket->mNonceOffset.ElementCount);
				}
#endif
				break;
			}
			}
		}
		reply.Dispatch(socketAddress);
		return true;
	}
	default:
		break;
	}
	return false;
}

bool StartThreads(ion::NetConnections& connections, NetReception& reception, NetControl& control, const NetStartupParameters& parameters)
{
	bool success = true;
	for (unsigned i = 0; i < parameters.mNetSocketDescriptorCount; i++)
	{
#if ION_NET_FEATURE_STREAMSOCKET
		if (socketList[i]->binding.type == SOCK_DGRAM)
#endif
		{
			success &= SocketLayer::StartThreads(*connections.mSocketList[i], connections, reception, control, parameters);
		}
#if ION_NET_FEATURE_STREAMSOCKET
		else if (((RNS2_Berkley*)socketList[i])->binding.port != 0)
		{
			ion::SocketLayer::ListenSocket(*((RNS2_Berkley*)socketList[i]), maxConnections);
			success &= ((RNS2_Berkley*)socketList[i])->ListeningThread(reception, control, *((RNS2_Berkley*)socketList[i]));
		}
#endif
	}
	return success;
}

void CancelThreads(ion::NetConnections& connections)
{
	for (unsigned int i = 0; i < connections.mSocketList.Size(); i++)
	{
		SocketLayer::CancelThreads(*connections.mSocketList[i]);
	}
}

void StopThreads(ion::NetConnections& connections)
{
	for (unsigned int i = 0; i < connections.mSocketList.Size(); i++)
	{
		SocketLayer::StopThreads(*connections.mSocketList[i]);
	}
}

void ClearConnectionRequest(ion::NetConnections& connections, const ion::RequestedConnection& rcs)
{
	if (rcs.actionToTake == ion::RequestedConnection::WAIT_FOR_SOCKET_RESULT)
	{
		NetSocket* socket = rcs.socket == 0 ? connections.mSocketList[rcs.socketIndex] : rcs.socket;
		socket->mSocketSendResults.Clear(rcs.systemAddress);
	}
}

void Reset(ion::NetConnections& connections, NetControl& control)
{
	connections.mRequestedConnections.Access(
	  [&](ion::RequestedConnections& rc)
	  {
		  ion::ForEach(rc.mRequests, [&](const std::pair<ion::NetSocketAddress, ion::RequestedConnection>& pair)
					   { ClearConnectionRequest(connections, pair.second); });
		  rc.mRequests.Clear();
	  });

	ion::AutoLock socketListLock(connections.mSocketListMutex);
	connections.mSocketListFirstBoundAddress = ion::NetUnassignedSocketAddress;
	for (unsigned int i = 0; i < connections.mSocketList.Size(); i++)
	{
		ion::ArenaPtr<NetSocket, ion::NetInterfaceResource> ptr(connections.mSocketList[i]);
		SocketLayer::DeinitSocket(*ptr.Get());
		ion::DeleteArenaPtr(&control.mMemoryResource, ptr);
		NetControlLayer::RunnerUnrequired(control);
	}
	connections.mSocketList.Clear();
	for (unsigned int i = 0; i < NetMaximumNumberOfInternalIds; i++)
	{
		connections.mIpList[i] = NetUnassignedSocketAddress;
	}
	connections.mFirstExternalID = NetUnassignedSocketAddress;
}
void CreateSockets(ion::NetConnections& connections, NetControl& control, const NetStartupParameters& parameters)
{
	ION_ASSERT(connections.mSocketList.Size() == 0, "Unbind sockets first");

	// Create sockets
	{
		ion::AutoLock socketListLock(connections.mSocketListMutex);
		for (unsigned int i = 0; i < parameters.mNetSocketDescriptorCount; i++)
		{
			NetControlLayer::RunnerRequired(control);
			NetSocket* socket = ion::MakeArenaPtr<NetSocket>(&control.mMemoryResource, &control.mMemoryResource).Release();
			SocketLayer::InitSocket(*socket);
#if ION_NET_SIMULATOR
			SocketLayer::ConfigureNetworkSimulator(*socket, connections.mDefaultNetworkSimulatorSettings);
#endif
			connections.mSocketList.Add(socket);
		}
	}

	for (unsigned int i = 0; i < parameters.mNetSocketDescriptorCount; i++)
	{
		NetBindParameters bbp;
		bbp.port = parameters.mNetSocketDescriptors[i].port;
		memcpy(bbp.hostAddress, (char*)parameters.mNetSocketDescriptors[i].hostAddress, 32);
		bbp.addressFamily = parameters.mNetSocketDescriptors[i].socketFamily;
		bbp.type = parameters.mNetSocketDescriptors[i].socketType;
		bbp.protocol = parameters.mNetSocketDescriptors[i].protocol;
		bbp.nonBlockingSocket = false;
		bbp.setBroadcast = true;
		bbp.setIPHdrIncl = false;
		bbp.doNotFragment = false;

		connections.mSocketList[i]->mBindParameters = bbp;
		connections.mSocketList[i]->userConnectionSocketIndex = i;
	}
}

#if ION_NET_SIMULATOR
void UpdateNetworkSim(ion::NetConnections& connections, ion::TimeMS timeMS)
{
	for (unsigned int i = 0; i < connections.mSocketList.Size(); ++i)
	{
		connections.mSocketList[i]->mNetworkSimulator.Update(timeMS);
	}
}
#endif

void FillIPList(NetConnections& connections)
{
	if (connections.mIpList[0] != NetUnassignedSocketAddress)
		return;

	// Fill out ipList structure
	ion::SocketLayer::GetInternalAddresses(connections.mIpList);

	// Sort the addresses from lowest to highest
	int startingIdx = 0;
	while (startingIdx < NetMaximumNumberOfInternalIds - 1 && connections.mIpList[startingIdx] != NetUnassignedSocketAddress)
	{
		int lowestIdx = startingIdx;
		for (int curIdx = startingIdx + 1;
			 curIdx < NetMaximumNumberOfInternalIds - 1 && connections.mIpList[curIdx] != NetUnassignedSocketAddress; curIdx++)
		{
			if (connections.mIpList[curIdx] < connections.mIpList[startingIdx])
			{
				lowestIdx = curIdx;
			}
		}
		if (startingIdx != lowestIdx)
		{
			NetSocketAddress temp = connections.mIpList[startingIdx];
			connections.mIpList[startingIdx] = connections.mIpList[lowestIdx];
			connections.mIpList[lowestIdx] = temp;
		}
		++startingIdx;
	}
}

unsigned int GetNumberOfAddresses(const NetConnections& connections)
{
	unsigned int i = 0;

	while (i < connections.mIpList.Size() && connections.mIpList[i] != NetUnassignedSocketAddress)
	{
		i++;
	}

	return i;
}

bool IsIPV6Only(const NetConnections& connections)
{
	auto num = GetNumberOfAddresses(connections);
	for (size_t i = 0; i < num; ++i)
	{
		if (connections.mIpList[i].GetIPVersion() != 6)
		{
			return false;
		}
	}
	return num != 0;  // True only when IPV6 adresses are available.
}

void GetInternalID(const NetConnections& connections, NetSocketAddress& out, const int index)
{
	out = connections.mIpList[index];
}

void SetInternalID(NetConnections& connections, const NetSocketAddress& address, int index)
{
	ION_ASSERT(index >= 0 && index < NetMaximumNumberOfInternalIds, "invalid id index");
	connections.mIpList[index] = address;
}

void GetExternalID(const NetConnections& connections, NetSocketAddress& out) { out = connections.mFirstExternalID; }

void SetExternalID(NetConnections& connections, const NetSocketAddress& address)
{
	if (connections.mFirstExternalID == NetUnassignedSocketAddress)
	{
		connections.mFirstExternalID = address;
	}
}

bool IsLoopbackAddress(const NetConnections& connections, const NetAddressOrRemoteRef& systemIdentifier, bool matchPort)
{
	if (systemIdentifier.mRemoteId.IsValid())
	{
		return false;
	}

	for (int i = 0; i < NetMaximumNumberOfInternalIds && connections.mIpList[i] != NetUnassignedSocketAddress; i++)
	{
		if (matchPort)
		{
			if (connections.mIpList[i] == systemIdentifier.mAddress)
			{
				return true;
			}
		}
		else
		{
			if (connections.mIpList[i].EqualsExcludingPort(systemIdentifier.mAddress))
			{
				return true;
			}
		}
	}

	return (matchPort == true && systemIdentifier.mAddress == connections.mFirstExternalID) ||
		   (matchPort == false && systemIdentifier.mAddress.EqualsExcludingPort(connections.mFirstExternalID));
}

const NetSocketAddress& GetLoopbackAddress(const NetConnections& connections)
{
	return connections.mIpList[0];
}
}  // namespace NetConnectionLayer
}  // namespace ion
