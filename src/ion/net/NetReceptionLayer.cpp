
#include <ion/net/NetConnectionLayer.h>
#include <ion/net/NetControl.h>
#include <ion/net/NetControlLayer.h>
#include <ion/net/NetExchangeLayer.h>
#include <ion/net/NetInternalTypes.h>
#include <ion/net/NetMessages.h>
#include <ion/net/NetRawSendCommand.h>
#include <ion/net/NetReception.h>
#include <ion/net/NetReceptionLayer.h>
#include <ion/net/NetSendCommand.h>
#include <ion/net/NetSocketLayer.h>
#include <ion/net/NetTransportLayer.h>

#include <ion/jobs/JobScheduler.h>
#include <ion/jobs/TimedJob.h>

#include <ion/string/Hex.h>

namespace ion::NetReceptionLayer
{

namespace
{

NetPacket* ReceiveFromReassebly(NetTransport& transport)
{
	ION_ACCESS_GUARD_WRITE_BLOCK(transport.mGuard);
	if (!transport.mRcvQueue.IsEmpty())
	{
		NetPacket* p = transport.mRcvQueue.Front();
		transport.mRcvQueue.PopFront();
		return p;
	}
	return nullptr;
}

void ParseConnectionRequestPacket(NetReception& reception, NetControl& control, NetExchange& exchange, ion::NetRemoteSystem* remoteSystem,
								  unsigned char* data, int byteSize, ion::TimeMS now)
{
	ion::ByteReader bs(data, byteSize);
	bs.SkipBytes(sizeof(NetMessageId));
	NetGUID guid;
	bool isValid = true;
	isValid &= bs.Process(guid);
	ion::Time incomingTimestamp;
	isValid &= bs.Process(incomingTimestamp);

	size_t passwordLength = bs.Available();
	isValid &= reception.mIncomingPasswordLength == passwordLength;
	if (isValid && passwordLength > 0)
	{
		const unsigned char* password = &bs.ReadAssumeAvailable<unsigned char>();
		isValid &= memcmp(password, reception.mIncomingPassword, reception.mIncomingPasswordLength) == 0;
	}
	if (!isValid)
	{
		NetSendCommand cmd(control, remoteSystem->mId, 16);
		if (cmd.HasBuffer())
		{
			{
				ByteWriter writer(cmd.Writer());
				writer.Process(NetMessageId::InvalidPassword);
				writer.Process(exchange.mGuid);
			}
			cmd.Parameters().mPriority = NetPacketPriority::Immediate;

			ion::NetExchangeLayer::SendImmediate(exchange, control, cmd.Release(), now);
		}
		ion::NetExchangeLayer::SetMode(exchange, *remoteSystem, NetMode::DisconnectAsapSilently);
		return;
	}

	// OK
	ION_ASSERT(remoteSystem->mMode == ion::NetMode::RequestedConnection || remoteSystem->mMode == ion::NetMode::UnverifiedSender,
			   "Invalid connect state");
	ion::NetExchangeLayer::SetMode(exchange, *remoteSystem, NetMode::HandlingConnectionRequest);
	NetExchangeLayer::SendConnectionRequestAccepted(exchange, control, remoteSystem, incomingTimestamp, now);
}

bool RemoteSystemReceive(NetReception& reception, NetControl& control, NetExchange& exchange, const NetConnections& connections,
						 ion::NetRemoteSystem* remoteSystem, ion::TimeMS now, ion::NetPacket* packet)
{
	byte* data = packet->Data();
	int byteSize = int(packet->Length());

	// For unknown senders we only accept a few specific packets
	if (remoteSystem->mMode == ion::NetMode::UnverifiedSender)
	{
		if (data[0] == NetMessageId::ConnectionRequest)
		{
			ION_PROFILER_SCOPE(Network, "Connection Req");
			ParseConnectionRequestPacket(reception, control, exchange, remoteSystem, data, byteSize, now);
		}
		else
		{
			char str1[64];
			remoteSystem->mAddress.ToString(str1, 64, false);
			ION_NET_LOG_ABNORMAL("Temporary " << remoteSystem->timeoutTime << "ms ban " << ion::String(str1)
											  << " for sending nonsense data;GUID=" << remoteSystem->guid
											  << ";packetId=" << (unsigned char)(data[0]));

			AddToBanList(reception, control, str1, remoteSystem->timeoutTime);
			NetTransportLayer::Reset(remoteSystem->mTransport, control, *remoteSystem);

			// Note: Cannot be immediate as we are still using remote system socket.
			NetControlLayer::CloseConnectionInternal(control, exchange, connections, remoteSystem->mId.load(), false, false, 0,
													 NetPacketPriority::Low);
		}
		return false;
	}

	switch ((NetMessageId)(data)[0])
	{
	case NetMessageId::ConnectionRequest:
	{
		// However, if we are connected we still take a connection request in case both systems are trying to connect to each other
		// at the same time

		if (remoteSystem->mMode == ion::NetMode::RequestedConnection)
		{
			ParseConnectionRequestPacket(reception, control, exchange, remoteSystem, data, byteSize, now);
		}
		else
		{
			ion::ByteReader bs(static_cast<unsigned char*>(data) + sizeof(NetMessageId), byteSize - 1);
			NetGUID guid;
			bool isValid = bs.Process(guid);
			isValid &= guid == remoteSystem->guid;
			ion::Time incomingTimestamp;
			isValid &= bs.Process(incomingTimestamp);

			if (isValid)
			{
				// Got a connection request message from someone we are already connected to. Just reply normally.
				// This can happen due to race conditions with the fully connected mesh
				NetExchangeLayer::SendConnectionRequestAccepted(exchange, control, remoteSystem, incomingTimestamp, now);
			}
			else
			{
				// Do not flag this as bad, as GUID can change.
				ION_NET_LOG_ABNORMAL("[" << exchange.mGuid << "] Ignored invalid connection request from " << remoteSystem->guid
										 << " when already connected");
			}
		}
		return false;
	}
	case NetMessageId::NewIncomingConnection:
	{
		if (byteSize <= sizeof(unsigned char) + sizeof(unsigned int) + sizeof(unsigned short) + sizeof(ion::Time) * 2)
		{
			ION_NET_LOG_ABNORMAL("Invalid Message: NewIncomingConnection");
			return false;
		}

		if (remoteSystem->mMode != NetMode::HandlingConnectionRequest)
		{
			// Ignore, already connected. Not abnormal as happens on cross connection case
			ION_NET_LOG_VERBOSE("[" << exchange.mGuid << "] Connect request received from " << remoteSystem->guid
									<< " when already connected");
			return false;
		}

		ion::ByteReader inBitStream((unsigned char*)data, byteSize);
		ion::NetSocketAddress bsSystemAddress;

		inBitStream.SkipBytes(1);
		bool isValid = inBitStream.Process(bsSystemAddress);
		for (unsigned int i = 0; i < NetMaximumNumberOfInternalIds; i++)
		{
			isValid &=
			  inBitStream.Process(exchange.mSystemAddressDetails[remoteSystem->mId.load().RemoteIndex()].mTheirInternalSystemAddress[i]);
		}

		ion::Time sentPingTime, remoteTime;
		isValid &= inBitStream.Process(remoteTime);
		isValid &= inBitStream.Process(sentPingTime);
		if (!isValid)
		{
			ION_NET_LOG_ABNORMAL("Invalid Message: NewIncomingConnection");
			return false;
		}
		ion::NetExchangeLayer::OnConnectedPong(exchange, now, sentPingTime, remoteTime, remoteSystem);

		ion::NetExchangeLayer::SetConnected(exchange, *remoteSystem, bsSystemAddress);
		// PingInternal(systemAddress, true, NetPacketReliability::Unreliable, timeRead);

		// Update again immediately after this tick so the ping goes out right away
		// peer.OnUpdate();

		// Bug: If A connects to B through R, A's mFirstExternalID is set to R. If A tries to send to R, sends to loopback
		// because R==mFirstExternalID Correct fix is to specify in Connect() if target is through a proxy. However, in practice
		// you have to connect to something else first anyway to know about the proxy. So setting once only is good enough
		if (exchange.mFirstExternalID == NetUnassignedSocketAddress)
		{
			exchange.mFirstExternalID = bsSystemAddress;
		}

		// Send this info down to the game
		break;
	}
	case NetMessageId::ConnectedPong:
	{
		if (byteSize == sizeof(unsigned char) + sizeof(ion::Time) * 2)
		{
			ion::Time sentPingTime, remoteTime;

			ion::ByteReader inBitStream((unsigned char*)data, byteSize);
			inBitStream.SkipBytes(1);
			bool isValid = inBitStream.Process(remoteTime);
			isValid &= inBitStream.Process(sentPingTime);
			if (isValid)
			{
				ion::NetExchangeLayer::OnConnectedPong(exchange, now, sentPingTime, remoteTime, remoteSystem);
			}
		}
		return false;
	}
	case NetMessageId::ConnectedPing:
	{
		if (byteSize == sizeof(unsigned char) + sizeof(ion::Time))
		{
			ion::ByteReader inBitStream((unsigned char*)data, byteSize);
			inBitStream.SkipBytes(1);
			ion::Time remoteTime;
			inBitStream.ReadAssumeAvailable(remoteTime);

			NetSendCommand cmd(control, remoteSystem->mId, sizeof(NetMessageId::ConnectedPong) + sizeof(TimeMS) * 2);
			if (cmd.HasBuffer())
			{
				ion::Time sendPongTime = ion::SteadyClock::GetTimeMS();
				{
					ByteWriter writer(cmd.Writer());
					writer.Process(NetMessageId::ConnectedPong);
					writer.Process(sendPongTime);
					writer.Process(remoteTime);
				}

				cmd.Parameters().mReliability = NetPacketReliability::Unreliable;
				cmd.Parameters().mPriority = NetPacketPriority::Immediate;

				ion::NetExchangeLayer::SendImmediate(exchange, control, cmd.Release(), sendPongTime);

				// Update again immediately after this tick so the ping goes out right away
				ion::NetControlLayer::Trigger(control);
			}
		}
		return false;
	}
	case NetMessageId::DisconnectionNotification:
	{
		// We shouldn't close the connection immediately because we need to ack the DisconnectionNotification
		NetMode disconnectMode;
		if (remoteSystem->mMode == NetMode::DisconnectAsap || remoteSystem->mMode == NetMode::DisconnectAsapMutual)
		{
			disconnectMode = NetMode::DisconnectAsapMutual;
		}
		else
		{
			disconnectMode = NetMode::DisconnectOnNoAck;
		}
		ion::NetExchangeLayer::SetMode(exchange, *remoteSystem, disconnectMode);
		return false;
	}
	case NetMessageId::InvalidPassword:
	{
		if (remoteSystem->mMode == NetMode::RequestedConnection)
		{
			ion::NetExchangeLayer::SetMode(exchange, *remoteSystem, NetMode::DisconnectAsapSilently);
			break;
		}
		else
		{
			return false;
		}
	}
	case NetMessageId::ConnectionRequestAccepted:
	{
		if (byteSize <=
			sizeof(ion::NetMessageId) + sizeof(unsigned int) + sizeof(unsigned short) + sizeof(NetRemoteIndex) + sizeof(ion::Time) * 2)
		{
			ION_NET_LOG_ABNORMAL("Version mismatch");
			return false;
		}

		// Make sure this connection accept is from someone we wanted to connect to

		bool allowConnection = (remoteSystem->mMode == NetMode::HandlingConnectionRequest ||
								remoteSystem->mMode == NetMode::RequestedConnection || reception.mAllowConnectionResponseIPMigration);

		if (!allowConnection)
		{
			return false;
		}

		bool alreadyConnected = (remoteSystem->mMode == NetMode::HandlingConnectionRequest);

		ion::NetSocketAddress externalID;
		NetRemoteIndex systemIndex;

		ion::ByteReader reader((unsigned char*)data, byteSize);
		reader.SkipBytes(1);
		bool isValid = reader.Process(externalID);
		isValid &= externalID.IsValid();
		isValid &= reader.Process(systemIndex);
		for (unsigned int i = 0; i < NetMaximumNumberOfInternalIds; i++)
		{
			isValid &=
			  reader.Process(exchange.mSystemAddressDetails[remoteSystem->mId.load().RemoteIndex()].mTheirInternalSystemAddress[i]);
		}

		ion::Time sentPingTime, remoteTime;
		isValid &= reader.Process(remoteTime);
		isValid &= reader.Process(sentPingTime);
		if (!isValid)
		{
			ION_NET_LOG_ABNORMAL("Invalid connection request accepted");
			return false;
		}
		ion::NetExchangeLayer::OnConnectedPong(exchange, now, sentPingTime, remoteTime, remoteSystem);

		ion::NetExchangeLayer::SetConnected(exchange, *remoteSystem, externalID);

		// Bug: If A connects to B through R, A's mFirstExternalID is set to R. If A tries to send to R, sends to loopback
		// because R==mFirstExternalID Correct fix is to specify in Connect() if target is through a proxy. However, in
		// practice you have to connect to something else first anyway to know about the proxy. So setting once only is good
		// enough
		if (exchange.mFirstExternalID == NetUnassignedSocketAddress)
		{
			exchange.mFirstExternalID = externalID;
		}

		// Send the connection request complete to the game
		NetSendCommand cmd(control, remoteSystem->mId, NetMaximumNumberOfInternalIds * sizeof(NetSocketAddress) + 256);
		if (cmd.HasBuffer())
		{
			cmd.Parameters().mPriority = NetPacketPriority::Immediate;
			{
				ByteWriter writer(cmd.Writer());
				writer.Process(NetMessageId::NewIncomingConnection);
				writer.Process(remoteSystem->mAddress);
				for (unsigned int i = 0; i < NetMaximumNumberOfInternalIds; i++)
				{
					writer.Process(exchange.mIpList[i]);
				}
				writer.Process(now);
				writer.Process(remoteTime);
			}
			ion::NetExchangeLayer::SendImmediate(exchange, control, cmd.Release(), now);
		}

		if (alreadyConnected == false)
		{
			ION_NET_LOG_VERBOSE("[" << exchange.mGuid << "] Ping accepting connection " << remoteSystem->guid);
			remoteSystem->pingTracker.OnPing(now);
			NetControlLayer::PingInternal(control, exchange, remoteSystem->mAddress, true, NetPacketReliability::Unreliable, now);
		}
		break;
	}

	// These types are for internal use and should never arrive from a network packet
	case NetMessageId::Invalid:
		[[fallthrough]];
	case NetMessageId::ConnectionAttemptFailed:
		[[fallthrough]];
	default:
	{
		// What do I do if I get a message from a system, before I am fully connected?
		// I can either ignore it or give it to the user
		// It seems like giving it to the user is a better option
		if ((data[0] >= NetMessageId::UserPacket))
		{
			if (remoteSystem->mMode != NetMode::Disconnected)
			{
				break;
			}
		}
		else
		{
			ION_NET_LOG_ABNORMAL("Invalid packet from " << remoteSystem->guid << ";id=" << data[0]);
		}
		return false;
	}
	}

	control.mPacketReturnQueue.Enqueue(std::move(packet));
	return true;
}

void RemoteSystemReceive(NetReception& reception, NetControl& control, NetExchange& exchange, const NetConnections& connections,
						 ion::NetRemoteSystem* remoteSystem, const TimeMS now)
{
	while (ion::NetPacket* packet = ReceiveFromReassebly(remoteSystem->mTransport))
	{
		ION_NET_LOG_VERBOSE_MSG("Msg: Receiving id=" << Hex<uint8_t>(packet->Data()[0]) << ";Length=" << packet->Length()
													 << ";GUID=" << packet->mGUID << ";InternalType=" << packet->mInternalPacketType);
		if (remoteSystem->mMetrics)
		{
			// #TODO: Not always reliable.
			remoteSystem->mMetrics->OnReceived(now, ion::PacketType::UserReliable, packet->Length());
		}
		if (!RemoteSystemReceive(reception, control, exchange, connections, remoteSystem, now, packet))
		{
			ion::NetControlLayer::DeallocateUserPacket(control, packet);
		}
	}
}

// Return true if packet can be deallocated
bool ProcessNetworkPacket(NetReception& reception, NetControl& control, NetExchange& exchange, ion::NetConnections& connections,
						  ion::NetSocketReceiveData& recvFromStruct, TimeMS timeRead)

{
	ION_ASSERT(recvFromStruct.Address().GetPort(), "Invalid routed packet");

	uint32_t length = recvFromStruct.SocketBytesRead();
	byte* data = recvFromStruct.mPayload;
	{
		auto& socketAddress = recvFromStruct.Address();
		auto banStatus = IsBanned(reception, control, socketAddress, timeRead);
		if (banStatus != NetBanStatus::NotBanned)
		{
			if (banStatus != NetBanStatus::BannedRecentlyNotified)
			{
				NetRawSendCommand reply(*recvFromStruct.Socket());
				{
					auto out = reply.Writer();
					out.Process(NetMessageId::ConnectionBanned);
					out.Process(NetUnconnectedHeader);
					out.Process(exchange.mGuid);
				}
				reply.Dispatch(socketAddress);
			}
			return true;
		}
	}

	if (length < ion::NetConnectedProtocolMinOverHead || (data[1] == 'I' && data[2] == 'O' && data[3] == 'N'))
	{
		ion::NetConnectionLayer::ProcessOfflineNetworkPacket(connections, control, exchange, recvFromStruct, timeRead);
		return true;
	}

	// See if this datagram came from a connected system
	ion::NetRemoteSystem* remoteSystem = NetExchangeLayer::GetRemoteFromSocketAddress(exchange, recvFromStruct.Address(), true, true);

	if (uint8_t(data[0]) < NetNumberOfChannels)
	{
		// Reliable data
		uint32_t conversation;
		memcpy(&conversation, data, sizeof(uint32_t));
		if (remoteSystem == nullptr)
		{
			// If this is authority, it can try to find remote system via conversation
			remoteSystem = ion::NetExchangeLayer::GetRemoteSystemFromAuthorityConversation(exchange, conversation);
			if (remoteSystem == nullptr || !remoteSystem->mAllowFastReroute)
			{
				return true;
			}
			// Reroute clients using conversation key, but only if the remote packet is valid.
			if (NetTransportLayer::Input(remoteSystem->mTransport, control, *remoteSystem, conversation, recvFromStruct, timeRead))
			{
				ION_NET_LOG_INFO("Rerouted system " << remoteSystem->mAddress << " to new adress " << recvFromStruct.Address());
				if (remoteSystem->mMetrics)
				{
					remoteSystem->mMetrics->OnReceived(timeRead, ion::PacketType::Raw,
													   ion::NetMtuSize(length, remoteSystem->mAddress.GetIPVersion()));
				}
				remoteSystem->timeLastDatagramArrived = timeRead;
				ion::NetExchangeLayer::ReferenceRemoteSystem(exchange, recvFromStruct.Address(), remoteSystem->mId.load().RemoteIndex());
				return false;
			}
			else
			{
				ION_NET_LOG_ABNORMAL("Invalid conversation key change attempt. Disable fast rerouting as a security measure.");
				remoteSystem->mAllowFastReroute = false;
				return true;
			}
		}

		if (remoteSystem->mMetrics)
		{
			remoteSystem->mMetrics->OnReceived(timeRead, ion::PacketType::Raw,
											   ion::NetMtuSize(length, remoteSystem->mAddress.GetIPVersion()));
		}
		if ((conversation >> 8) == (remoteSystem->mConversationId & 0xFFFFFFu))
		{
			if (NetTransportLayer::Input(remoteSystem->mTransport, control, *remoteSystem, conversation, recvFromStruct, timeRead))
			{
				// Data was stored -> Update reliable metrics for when reading data back
				remoteSystem->timeLastDatagramArrived = timeRead;
				return false;
			}
		}
		// Invalid reliable layer data.
		return true;
	}
	else if (!remoteSystem)
	{
		// No listener
		return true;
	}

	// Unreliable data
	ion::NetPacket* packet = reinterpret_cast<ion::NetPacket*>(&recvFromStruct);
	packet->mDataPtr = NetPacketHeader(packet);
	packet->mRemoteId = remoteSystem->mId;
	packet->mGUID = remoteSystem->guid;
	remoteSystem->timeLastDatagramArrived = timeRead;
	if (remoteSystem->mMetrics)
	{
		remoteSystem->mMetrics->OnReceived(timeRead, ion::PacketType::UserUnreliable, length);
		remoteSystem->mMetrics->OnReceived(timeRead, ion::PacketType::Raw, ion::NetMtuSize(length, remoteSystem->mAddress.GetIPVersion()));
	}
	if (RemoteSystemReceive(reception, control, exchange, connections, remoteSystem, timeRead, packet))
	{
		return false;
	}
	return true;
}

}  // namespace

ion::NetSocketReceiveData* Receive(NetReception& reception, NetControl& control, ion::NetSocketReceiveData* data)
{
	while (reception.mNumBufferedBytes + data->SocketBytesRead() >= ion::NetMaxBufferedReceiveBytes)
	{
		// #TODO: Request remote to slow down.
		ION_ABNORMAL_ONCE(1.0, "Socket receive buffer full");
		ion::Thread::Sleep(ion::NetUpdateInterval * 2);
	}
	reception.mNumBufferedBytes += data->SocketBytesRead();
	reception.mReceiveBuffer.Enqueue(data);
	NetSocketReceiveData* ptr = ion::NetControlLayer::AllocateReceiveBuffer(control);
	reception.mDataBufferedCallback();
	return ptr;
}

void ProcessBufferedPackets(ion::NetReception& reception, NetControl& control, NetExchange& exchange, ion::NetConnections& connections,
							JobScheduler* js, const TimeMS now)
{
	size_t totalBytesHandled = 0;
	ion::NetSocketReceiveData* elem = nullptr;
	while (reception.mReceiveBuffer.Dequeue(elem))
	{
		totalBytesHandled += elem->SocketBytesRead();
		if (ProcessNetworkPacket(reception, control, exchange, connections, *elem, now))
		{
			ion::NetControlLayer::DeallocateReceiveBuffer(control, elem);
		}
	}
	ION_ASSERT(static_cast<size_t>(reception.mNumBufferedBytes) >= totalBytesHandled, "Invalid item count");
	reception.mNumBufferedBytes -= totalBytesHandled;

	if (js != nullptr)
	{
		js->ParallelFor(exchange.mActiveSystems.Get(), exchange.mActiveSystems.Get() + exchange.mActiveSystemListSize,
						[&](ion::NetRemoteIndex index)
						{ RemoteSystemReceive(reception, control, exchange, connections, &exchange.mRemoteSystemList[index], now); });
	}
	else
	{
		for (unsigned int activeSystemListIndex = 0; activeSystemListIndex < exchange.mActiveSystemListSize; ++activeSystemListIndex)
		{
			ion::NetRemoteSystem* remoteSystem = &exchange.mRemoteSystemList[exchange.mActiveSystems[activeSystemListIndex]];
			RemoteSystemReceive(reception, control, exchange, connections, remoteSystem, now);
		}
	}
}

void Reset(NetReception& reception, NetControl& control)
{
	ion::NetSocketReceiveData* elem = nullptr;
	while (reception.mReceiveBuffer.Dequeue(elem))
	{
		reception.mNumBufferedBytes -= elem->SocketBytesRead();
		ion::NetControlLayer::DeallocateReceiveBuffer(control, elem);
	}
}

void AddToBanList(NetReception& reception, NetControl& control, const char* IP, ion::TimeMS milliseconds)
{
	unsigned index;
	ion::TimeMS time = ion::SteadyClock::GetTimeMS();

	if (IP == 0 || IP[0] == 0)
		return;

	auto strLen = strlen(IP) + 1;
	if (strlen(IP) > 16)
	{
		return;
	}

	// If this guy is already in the ban list, do nothing
	index = 0;

	reception.mBanList.Access(
	  [&](NetBanListVector& banList)
	  {
		  for (; index < banList.Size(); index++)
		  {
			  if (strcmp(IP, banList[index]->IP.Data()) == 0)
			  {
				  // Already in the ban list.  Just update the time
				  if (milliseconds == 0)
				  {
					  banList[index]->timeout = 0;	// Infinite
				  }
				  else
				  {
					  banList[index]->timeout = time + milliseconds;
					  if (banList[index]->timeout == 0)
					  {
						  banList[index]->timeout++;
					  }
				  }
				  banList[index]->mNextResponse = time;
				  return;
			  }
		  }
	  });

	ion::NetInterfacePtr<NetBanStruct> banStruct = ion::MakeArenaPtr<NetBanStruct>(&control.mMemoryResource);
	if (milliseconds == 0)
	{
		banStruct->timeout = 0;	 // Infinite
	}
	else
	{
		banStruct->timeout = time + milliseconds;
		if (banStruct->timeout == 0)
		{
			banStruct->timeout++;
		}
	}
	banStruct->mNextResponse = time;
	memcpy(banStruct->IP.Data(), IP, strLen);
	reception.mBanList.Access(
	  [&](NetBanListVector& banList)
	  {
		  banList.Emplace(std::move(banStruct));
		  reception.mIsAnyoneBanned = true;
	  });
}

void RemoveFromBanList(NetReception& reception, NetControl& control, const char* IP)
{
	unsigned index;
	ion::NetInterfacePtr<NetBanStruct> temp;

	if (IP == 0 || IP[0] == 0 || strlen(IP) > 15)
		return;

	index = 0;

	reception.mBanList.Access(
	  [&reception, &index, &temp, &IP](NetBanListVector& banList)
	  {
		  for (; index < banList.Size(); index++)
		  {
			  if (strcmp(IP, banList[index]->IP.Data()) == 0)
			  {
				  temp = std::move(banList[index]);
				  banList[index] = std::move(banList[banList.Size() - 1]);
				  banList.Erase(banList.Size() - 1);
				  reception.mIsAnyoneBanned = banList.Size() != 0;
				  break;
			  }
		  }
	  });

	if (temp)
	{
		ion::DeleteArenaPtr(&control.mMemoryResource, temp);
	}
}

void ClearBanList(NetReception& reception, NetControl& control)
{
	unsigned index;
	index = 0;
	reception.mBanList.Access(
	  [&](NetBanListVector& banList)
	  {
		  for (; index < banList.Size(); index++)
		  {
			  ion::DeleteArenaPtr(&control.mMemoryResource, banList[index]);
		  }
		  banList.Clear();
		  reception.mIsAnyoneBanned = false;
	  });
}

NetBanStatus IsBanned(NetReception& reception, NetControl& control, const char* IP, ion::TimeMS now)
{
	if (!reception.mIsAnyoneBanned)
	{
		return NetBanStatus::NotBanned;
	}

	if (IP == 0 || IP[0] == 0 || StringLen(IP, 16) > 15)
	{
		return NetBanStatus::NotBanned;
	}

	ion::NetInterfacePtr<NetBanStruct> temp;
	NetBanStatus banStatus = NetBanStatus::NotBanned;
	unsigned banListIndex = 0;

	reception.mBanList.Access(
	  [&](NetBanListVector& banList)
	  {
		  while (banListIndex < banList.Size())
		  {
			  if (banList[banListIndex]->timeout != 0 && ion::DeltaTime(banList[banListIndex]->timeout, now) < 0)
			  {
				  // Delete expired ban
				  temp = std::move(banList[banListIndex]);
				  banList[banListIndex] = std::move(banList[banList.Size() - 1]);
				  banList.Erase(banList.Size() - 1);
				  ion::DeleteArenaPtr(&control.mMemoryResource, temp);
				  reception.mIsAnyoneBanned = banList.Size() != 0;
			  }
			  else
			  {
				  unsigned characterIndex = 0;

				  for (;;)
				  {
					  if (banList[banListIndex]->IP[characterIndex] == IP[characterIndex])
					  {
						  // Equal characters

						  if (IP[characterIndex] == 0)
						  {
							  bool shouldResponse = false;

							  if (ion::DeltaTime(banList[banListIndex]->mNextResponse, now) <= 0)
							  {
								  shouldResponse = true;
								  banList[banListIndex]->mNextResponse = now + ion::NetBanNotificationInterval;
							  }
							  // End of the string and the strings match
							  banStatus = shouldResponse ? NetBanStatus::Banned : NetBanStatus::BannedRecentlyNotified;
							  return;
						  }

						  characterIndex++;
					  }

					  else
					  {
						  if (banList[banListIndex]->IP[characterIndex] == 0 || IP[characterIndex] == 0)
						  {
							  // End of one of the strings
							  break;
						  }

						  // Characters do not match
						  if (banList[banListIndex]->IP[characterIndex] == '*')
						  {
							  bool shouldResponse = false;

							  if (ion::DeltaTime(banList[banListIndex]->mNextResponse, now) <= 0)
							  {
								  shouldResponse = true;
								  banList[banListIndex]->mNextResponse = now + ion::NetBanNotificationInterval;
							  }
							  // Domain is banned.
							  banStatus = shouldResponse ? NetBanStatus::Banned : NetBanStatus::BannedRecentlyNotified;
							  return;
						  }

						  // Characters do not match and it is not a *
						  break;
					  }
				  }

				  banListIndex++;
			  }
		  }
	  });
	return banStatus;
}

NetBanStatus IsBanned(NetReception& reception, NetControl& control, const ion::NetSocketAddress& systemAddress, ion::TimeMS now)
{
	char str1[64];
	systemAddress.ToString(str1, 64, false);
	return IsBanned(reception, control, str1, now);
}

void SetIncomingPassword(NetReception& reception, const char* passwordData, int passwordDataLength)
{
	if (passwordDataLength > 255)
	{
		passwordDataLength = 255;
	}

	if (passwordData == 0)
	{
		passwordDataLength = 0;
	}

	if (passwordDataLength > 0)
	{
		memcpy(reception.mIncomingPassword, passwordData, passwordDataLength);
	}
	reception.mIncomingPasswordLength = (unsigned char)passwordDataLength;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void GetIncomingPassword(const NetReception& reception, char* passwordData, int* passwordDataLength)
{
	if (passwordData == 0)
	{
		*passwordDataLength = reception.mIncomingPasswordLength;
		return;
	}

	if (*passwordDataLength > reception.mIncomingPasswordLength)
	{
		*passwordDataLength = reception.mIncomingPasswordLength;
	}

	if (*passwordDataLength > 0)
	{
		memcpy(passwordData, reception.mIncomingPassword, *passwordDataLength);
	}
}

}  // namespace ion::NetReceptionLayer
