#include <ion/net/NetCommand.h>
#include <ion/net/NetConfig.h>
#include <ion/net/NetConnectionLayer.h>
#include <ion/net/NetControlLayer.h>
#include <ion/net/NetExchangeLayer.h>
#include <ion/net/NetGUID.h>
#include <ion/net/NetGlobalClock.h>
#include <ion/net/NetInterface.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetSendCommand.h>
#include <ion/net/NetSocket.h>
#include <ion/net/NetStartupParameters.h>
#include <ion/net/ionnet.h>

#include <ion/time/Clock.h>

#include <ion/memory/AllocatorTraits.h>

namespace ion
{

namespace detail
{

class NetUpdateJob : public ion::TimedJob
{
public:
	NetUpdateJob(ion::NetInterface& netInterface, ion::JobScheduler& js)
	  : ion::TimedJob(ion::tag::Network), mJs(js), mInterface(netInterface)
	{
		Timer().Reset(double(ion::NetUpdateInterval) / 1000);
	}

	void RunTimedTask() final
	{
		if (mInterface.mControl.mIsReceiving)
		{
			mInterface.mControl.mIsReceiving = false;
			ion_net_preupdate((ion_net_peer)&mInterface, (ion_job_scheduler)&mJs);
		}
		auto now = ion::SteadyClock::GetTimeUS();
		auto delta = DeltaTime(now, ion::TimeUS(mNextUpdateUs));
		if (delta >= 0)
		{
			mNextUpdateUs = Timer().Advance(ion::NetUpdateInterval * 1000);
			ion_net_postupdate((ion_net_peer)&mInterface, (ion_job_scheduler)&mJs);
		}
	}

	inline void Update() { mNextUpdateUs = RescheduleImmediately(); }

	ion::JobScheduler& mJs;
	ion::NetInterface& mInterface;
	std::atomic<ion::TimeUS> mNextUpdateUs = ion::SteadyClock::GetTimeUS();
};

class NetUpdateWorker
{
public:
	NetUpdateWorker(ion::NetInterface& netInterface)
	  : mUpdateThread(
		  [&netInterface]
		  {
			  NetControlLayer::RunnerReady(netInterface.mControl);
			  while (netInterface.mControl.mUpdater.mUpdateWorker->myThreadSynchronizer.IsActive())
			  {
				  if (netInterface.mControl.mIsReceiving)
				  {
					  netInterface.mControl.mIsReceiving = false;
					  ion_net_preupdate((ion_net_peer)&netInterface, (ion_job_scheduler) nullptr);
				  }
				  ion_net_postupdate((ion_net_peer)&netInterface, (ion_job_scheduler) nullptr);
				  netInterface.mControl.mUpdater.mUpdateWorker->myThreadSynchronizer.TryWaitFor(ion::NetUpdateInterval * 1000);
			  }
			  NetConnectionLayer::CancelThreads(netInterface.mConnections);
			  NetControlLayer::RunnerExit(netInterface.mControl);
		  })
	{
	}
	ion::SCThreadSynchronizer myThreadSynchronizer;
	ion::Runner mUpdateThread;
};

}  // namespace detail
}  // namespace ion

namespace ion
{
namespace NetControlLayer
{

void Init(NetInterface& net, const NetStartupParameters& pars)
{
	net.mControl.mLastUpdate = SteadyClock::GetTimeMS();
	net.mControl.mUpdateMode = pars.mUpdateMode;
	if (pars.mJobScheduler && pars.mUpdateMode == NetPeerUpdateMode::Job)
	{
		net.mControl.mUpdater.mUpdateJob =
		  ion::MakeArenaPtr<detail::NetUpdateJob, NetInterfaceResource>(&net.mControl.mMemoryResource, net, *pars.mJobScheduler);
	}
	else if (pars.mUpdateMode != NetPeerUpdateMode::User)
	{
		net.mControl.mUpdater.mUpdateWorker =
		  ion::MakeArenaPtr<detail::NetUpdateWorker, NetInterfaceResource>(&net.mControl.mMemoryResource, net);
		net.mControl.mUpdateMode = NetPeerUpdateMode::Worker;  // Degrade mode to Worker mode when no scheduler available.
		RunnerRequired(net.mControl);
	}
}

void ClearBufferedCommands(NetControl& control)
{
	control.mBufferedCommands.DequeueAll([&](ion::NetCommandPtr& bcs) { ion::DeleteArenaPtr(&control.mMemoryResource, bcs); });
}

void Process(NetControl& control, NetExchange& exchange, const NetConnections& connections, ion::TimeMS now)
{
	SmallVector<NetRemoteIndex, 16, NetAllocator<NetRemoteIndex>> remoteIndices;
	ion::NetCommandPtr bcs;
	while (control.mBufferedCommands.Dequeue(bcs))
	{
		if (bcs->mCommand <= NetCommandType::SendRemotes)
		{
			auto connectionMode = bcs->mConnectionMode;
			ION_ASSERT(connectionMode == NetMode::Disconnected ||
						 (bcs->mCommand == NetCommandType::SendRemote || bcs->mCommand == NetCommandType::SendRemotes),
					   "Invalid command to change remote mode");
			ion::NetExchangeLayer::SendImmediate(exchange, control, std::move(bcs), now, remoteIndices);

			// Set the new connection state AFTER we call sendImmediate in case we are setting it to a disconnection state, which does
			// not allow further sends
			if (connectionMode != NetMode::Disconnected)
			{
				ForEach(remoteIndices,
						[&](auto index)
						{
							auto& remoteSystem = exchange.mRemoteSystemList[index];
							ION_ASSERT(remoteSystem.mMode != NetMode::Disconnected, "Invalid remote");
							ion::NetExchangeLayer::SetMode(exchange, remoteSystem, connectionMode);
						});
			}
			remoteIndices.Clear();
			continue;  // Command ownership moved to exchange layer
		}
		else
		{
			switch (bcs->mCommand)
			{
			case NetCommandType::CloseConnection:
			{
				CloseConnectionInternal(control, exchange, connections, NetAddressOrRemoteRef(bcs->mTarget.mRemoteId), false, true,
										bcs->mChannel, bcs->mPriority);
				break;
			}
			case NetCommandType::ChangeSystemAddress:
			{
				ion::NetRemoteSystem* rssFromGuid =
				  ion::NetExchangeLayer::GetRemoteSystem(exchange, *reinterpret_cast<NetRemoteId*>(&bcs->mData), true, true);
				if (rssFromGuid != 0)
				{
					ion::NetRemoteId existingRemote =
					  NetExchangeLayer::GetRemoteIdFromSocketAddress(exchange, rssFromGuid->mAddress, true, false);
					if (existingRemote.IsValid())
					{
						ion::NetExchangeLayer::ReferenceRemoteSystem(exchange, bcs->mTarget.mAddressList.Front(),
																	 existingRemote.RemoteIndex());
					}
				}
				break;
			}
			case NetCommandType::EnableTimeSync:
			{
				ion::GlobalClock* srcClock;
				memcpy((char*)&srcClock, &bcs->mData, sizeof(char*));
				auto remoteSystem = ion::NetExchangeLayer::GetRemoteSystem(exchange, bcs->mTarget.mRemoteId, true, true);
				if (remoteSystem)
				{
					exchange.mGlobalClock = srcClock;
					exchange.mGlobalClock->OnTimeSync(remoteSystem->timeSync.GetClock(), remoteSystem->timeSync.SyncState());
					remoteSystem->timeSync.SetActive(true);
				}
				else
				{
					ION_NET_LOG_ABNORMAL("No remote system for time sync;id=" << bcs->mTarget.mRemoteId);
					srcClock->OnOutOfSync();
					exchange.mGlobalClock = nullptr;
				}
				break;
			}
			case NetCommandType::DisableTimeSync:
			{
				auto remoteSystem = ion::NetExchangeLayer::GetRemoteSystem(exchange, bcs->mTarget.mRemoteId, true, true);
				if (remoteSystem)
				{
					remoteSystem->timeSync.SetActive(false);
				}
				if (exchange.mGlobalClock)
				{
					exchange.mGlobalClock->OnOutOfSync();
					exchange.mGlobalClock = nullptr;
				}
				break;
			}
			case ion::NetCommandType::PingAddress:
			{
				auto* remoteSystem = ion::NetExchangeLayer::GetRemoteSystem(exchange, *bcs->mTarget.mAddressList.Begin(), true, true);
				if (remoteSystem)
				{
					remoteSystem->pingTracker.OnPing(now);
					PingInternal(control, exchange, remoteSystem->mAddress, false, NetPacketReliability::Unreliable, now);
				}
				break;
			}
			case NetCommandType::SendRemote:
			case NetCommandType::SendExcludingAddresses:
			case NetCommandType::SendExcludingRemote:
			case NetCommandType::SendExcludingRemotes:
			case NetCommandType::SendAddresses:
			case NetCommandType::SendRemotes:
				ION_UNREACHABLE("Invalid command");
				break;
			}
		}
		ion::DeleteArenaPtr(&control.mMemoryResource, bcs);
	}
	uint32_t updateDelta = TimeSince(now, control.mLastUpdate);
	if (updateDelta > 200)
	{
		control.mResendExtraDelay = Min(Max(control.mResendExtraDelay, updateDelta * uint32_t(8)), NetMaxResendAlleviation);
		ION_NET_LOG_VERBOSE("Update took " << updateDelta << ", configured interval is " << NetUpdateInterval
										   << ";ResendExtraDelay=" << control.mResendExtraDelay);
	}
	if (control.mResendExtraDelay > 0)
	{
		uint32_t ch = Max(uint32_t(1), control.mResendExtraDelay / 100);
		if (control.mResendExtraDelay > ch)
		{
			control.mResendExtraDelay -= ch;
		}
		else
		{
			control.mResendExtraDelay = 0;
		}
	}
	control.mLastUpdate = now;
}

void CloseConnectionInternal(NetControl& control, NetExchange& exchange, const NetConnections& connections,
							 const NetAddressOrRemoteRef& systemIdentifier, bool sendDisconnectionNotification, bool performImmediate,
							 unsigned char orderingChannel, NetPacketPriority disconnectionNotificationPriority)
{
	ION_ASSERT(orderingChannel < NetNumberOfChannels, "invalid channel");

	NetRemoteId remoteId;
	if (systemIdentifier.mRemoteId.IsValid())
	{
		remoteId = systemIdentifier.mRemoteId;
	}
	else
	{
		ION_ASSERT(systemIdentifier.mAddress != NetUnassignedSocketAddress, "Invalid target");
		NetSocketAddress targetAddress = systemIdentifier.mAddress;
		targetAddress.FixForIPVersion(connections.mSocketList[0]->mBoundAddress.GetIPVersion());
		remoteId = NetExchangeLayer::GetRemoteIdFromSocketAddress(exchange, targetAddress, performImmediate, false);
		if (!remoteId.IsValid())
		{
			return;	 // Already closed
		}
	}

	if (sendDisconnectionNotification)
	{
		NetSendCommand cmd(control, remoteId, 8);
		if (!cmd.HasBuffer())
		{
			return;
		}

		{
			ion::ByteWriter writer(cmd.Writer());
			writer.Process(NetMessageId::DisconnectionNotification);
		}
		cmd.Parameters().mPriority = disconnectionNotificationPriority;
		cmd.Parameters().mChannel = orderingChannel;
		cmd.Parameters().mConnectionMode = NetMode::DisconnectAsap;

		if (performImmediate)
		{
			ion::NetExchangeLayer::SendImmediate(exchange, control, cmd.Release(), ion::SteadyClock::GetTimeMS());
			ion::NetRemoteSystem* rss = ion::NetExchangeLayer::GetRemoteSystem(exchange, remoteId, true, true);
			ION_ASSERT(rss->mMode != NetMode::Disconnected, "Invalid connection to start disconnecting");
			if (rss->mMode == NetMode::DisconnectOnNoAck)
			{
				rss->mMode = NetMode::DisconnectAsapMutual;
			}
			else
			{
				rss->mMode = NetMode::DisconnectAsap;
			}
			if (rss->timeSync.IsActive())
			{
				rss->timeSync.SetActive(false);
				exchange.mGlobalClock->OnOutOfSync();
				exchange.mGlobalClock = nullptr;
			}
		}
		else
		{
			SendBuffered(control, cmd.Release());
		}
	}
	else
	{
		if (performImmediate)
		{
			if (exchange.mRemoteSystemList[remoteId.RemoteIndex()].mMode != NetMode::Disconnected &&
				exchange.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId)
			{
				ion::NetExchangeLayer::ResetRemoteSystem(exchange, control, control.mMemoryResource, remoteId.RemoteIndex(),
														 ion::SteadyClock::GetTimeMS());
				ion::NetExchangeLayer::RemoveFromActiveSystemList(exchange, remoteId.RemoteIndex());
			}
		}
		else
		{
			auto bcs(ion::MakeArenaPtr<ion::NetCommand>(&control.mMemoryResource, remoteId));
			bcs->mCommand = ion::NetCommandType::CloseConnection;
			bcs->mChannel = orderingChannel;
			bcs->mPriority = disconnectionNotificationPriority;
			control.mBufferedCommands.Enqueue(std::move(bcs));
		}
	}
}

constexpr size_t BitsToBytes(size_t bitCount) { return (((bitCount) + 7) >> 3); };

void SendBuffered(NetControl& control, const char* data, size_t numberOfBytesToSend, NetPacketPriority priority,
				  NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier, bool broadcast,
				  NetMode connectionMode)
{
	ION_NET_API_CHECK(!(int(reliability) >= int(NetPacketReliability::Count) || int(reliability) < 0), -1, "Invalid reliability");
	ION_NET_API_CHECK(!(int(priority) > int(NetPacketPriority::Count) || int(priority) < 0), -1, "Invalid priority");
	ION_NET_API_CHECK(!(orderingChannel >= NetNumberOfChannels), -1, "Invalid channel");
	ION_ASSERT(broadcast || !systemIdentifier.IsUndefined(), "Invalid system");

	ION_ASSERT(numberOfBytesToSend > 0, "Invalid data");

	NetCommandPtr bcs;
	size_t cmdSize = ion::ByteAlignPosition(NetCommandHeaderSize + numberOfBytesToSend, alignof(NetCommand));
	if (systemIdentifier.mAddress.IsValid())
	{
		bcs = (ion::MakeArenaPtrRaw<ion::NetCommand>(&control.mMemoryResource, cmdSize, systemIdentifier.mAddress,
													 broadcast ? NetCommand::Targets::Exclude : NetCommand::Targets::Include));
	}
	else if (systemIdentifier.mRemoteId.IsValid())
	{
		bcs = (ion::MakeArenaPtrRaw<ion::NetCommand>(&control.mMemoryResource, cmdSize, systemIdentifier.mRemoteId,
													 broadcast ? NetCommand::Targets::Exclude : NetCommand::Targets::Include));
	}
	else
	{
		ION_ASSERT(broadcast || !systemIdentifier.IsUndefined(), "Invalid system");
		bcs = (ion::MakeArenaPtrRaw<ion::NetCommand>(&control.mMemoryResource, cmdSize));
	}

	if (bcs.Get() == nullptr)
	{
		ion::NotifyOutOfMemory();
		return;
	}

	memcpy(&bcs->mData, data, numberOfBytesToSend);
	bcs->mNumberOfBytesToSend = SafeRangeCast<uint32_t>(numberOfBytesToSend);
	bcs->mPriority = priority;
	bcs->mReliability = reliability;
	bcs->mChannel = orderingChannel;
	bcs->mConnectionMode = connectionMode;
	SendBuffered(control, std::move(bcs));
}

void SendBuffered(NetControl& control, NetCommandPtr&& cmd)
{
	ION_ASSERT(cmd->mChannel < NetNumberOfChannels, "Invalid channel");
	bool isImmediate = NetChannelPriorityConfigs[int(cmd->mPriority)].workInterval == 0;
	control.mBufferedCommands.Enqueue(std::move(cmd));
	if (isImmediate)
	{
		// Forces pending sends to go out now, rather than waiting to the next update interval
		ion::NetControlLayer::Trigger(control);
	}
}

void PingInternal(NetControl& control, NetExchange& exchange, const NetSocketAddress& target, bool performImmediate,
				  NetPacketReliability reliability, ion::TimeMS now)
{
	if (!control.mIsActive)
		return;

	NetSendCommand cmd(control, target, sizeof(unsigned char) + sizeof(ion::TimeMS));
	if (cmd.HasBuffer())
	{
		cmd.Parameters().mReliability = reliability;
		cmd.Parameters().mPriority = NetPacketPriority::Immediate;
		{
			ByteWriter writer(cmd.Writer());
			writer.Process(NetMessageId::ConnectedPing);
			writer.Process(now);
		}

		if (performImmediate)
		{
			ion::NetExchangeLayer::SendImmediate(exchange, control, cmd.Release(), now);
		}
		else
		{
			cmd.Dispatch();
		}
	}
}

int Send(NetControl& control, const NetConnections& connections, const NetExchange& exchange, const char* data, const int length, NetPacketPriority priority,
		 NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier, bool broadcast)
{
	ION_NET_API_CHECK(data && length > 0, -1, "Invalid data");
	ION_NET_API_CHECK(!(int(reliability) >= int(NetPacketReliability::Count) || int(reliability) < 0), -1, "Invalid reliablity");
	ION_NET_API_CHECK(!(int(priority) > int(NetPacketPriority::Count) || int(priority) < 0), -1, "Invalid priority");
	ION_NET_API_CHECK(!(orderingChannel >= NetNumberOfChannels), -1, "Invalid channel");
	ION_ASSERT(control.mIsActive, "Not active");

	if (exchange.mRemoteSystemList == nullptr)
		return 0;

	if (broadcast == false)
	{
		if (systemIdentifier.IsUndefined())
		{
			return 0;
		}
		if (NetConnectionLayer::IsLoopbackAddress(connections, systemIdentifier, true))
		{
			SendLoopback(control, connections, exchange, data, length);
			return 1;
		}
	}
	ion::NetControlLayer::SendBuffered(control, data, length, priority, reliability, orderingChannel, systemIdentifier, broadcast,
									   NetMode::Disconnected);
	return 1;
}

void SendLoopback(NetControl& control, const NetConnections& connections, const NetExchange& exchange, const char* data, const int length)
{
	if (data == 0 || length < 0)
		return;

	ion::NetPacket* packet = ion::NetControlLayer::AllocateUserPacket(control, length);
	packet->mSource = nullptr;
	packet->mLength = length;

	// NetPacket* packet = AllocPacket(length);
	memcpy(packet->Data(), data, length);
	packet->mAddress = ion::NetConnectionLayer::GetLoopbackAddress(connections);
	packet->mGUID = exchange.mGuid;
	packet->mRemoteId = NetRemoteId();
	PushPacket(control, (NetPacket*)packet);
}

bool StartUpdating(NetControl& control, NetReception& reception, ion::Thread::Priority priority)
{
	bool success = true;
	switch (control.mUpdateMode)
	{
	case NetPeerUpdateMode::Worker:
	{
		reception.mDataBufferedCallback = [&control]()
		{
			control.mIsReceiving = true;
			control.mUpdater.mUpdateWorker->myThreadSynchronizer.Signal();
		};
		success = control.mUpdater.mUpdateWorker->mUpdateThread.Start(1024 * 1024, priority);
		break;
	}
	case NetPeerUpdateMode::Job:
	{
		reception.mDataBufferedCallback = [&control]()
		{
			control.mIsReceiving = true;
			control.mUpdater.mUpdateJob->RescheduleImmediately();
		};
		control.mUpdater.mUpdateJob->mJs.PushJob(*control.mUpdater.mUpdateJob.Get());
		break;
	}
	case NetPeerUpdateMode::User:
	{
		reception.mDataBufferedCallback = []() {};
		break;
	}
	}
	control.mIsActive = success;
	return success;
}

void Trigger(NetControl& control)
{
	ION_MEMORY_SCOPE(tag::Network);
	switch (control.mUpdateMode)
	{
	case NetPeerUpdateMode::Job:
		control.mUpdater.mUpdateJob->Update();
		break;
	case NetPeerUpdateMode::User:
	{
		break;
	}
	case NetPeerUpdateMode::Worker:
	{
		control.mUpdater.mUpdateWorker->myThreadSynchronizer.Signal();
		break;
	}
	}
}

void CancelUpdating(NetControl& control)
{
	if (control.mIsActive)
	{
		ION_NET_LOG_VERBOSE("Canceling updating threads");
		if (control.mUpdateMode == NetPeerUpdateMode::Job)
		{
			while(!control.mUpdater.mUpdateJob->Cancel())
			{
				Thread::SleepMs(1);
			}
		}
		else if (control.mUpdateMode == NetPeerUpdateMode::Worker)
		{
			control.mUpdater.mUpdateWorker->myThreadSynchronizer.Stop();
		}
	}
}

void StopUpdating(NetControl& control)
{
	if (control.mIsActive)
	{
		ION_NET_LOG_VERBOSE("Stopping updating threads");
		if (control.mUpdateMode == NetPeerUpdateMode::Job)
		{
			control.mUpdater.mUpdateJob->WaitUntilDone();
		}
		else if (control.mUpdateMode == NetPeerUpdateMode::Worker)
		{
			control.mUpdater.mUpdateWorker->mUpdateThread.Join();
		}
		control.mIsActive = false;
	}
}

void Deinit(NetControl& control)
{
	if (control.mUpdateMode == NetPeerUpdateMode::Job)
	{
		if (control.mUpdater.mUpdateJob)
		{
			ion::DeleteArenaPtr<detail::NetUpdateJob, NetInterfaceResource>(&control.mMemoryResource, control.mUpdater.mUpdateJob);
		}
	}
	else if (control.mUpdateMode == NetPeerUpdateMode::Worker)
	{
		RunnerUnrequired(control);
		if (control.mUpdater.mUpdateWorker)
		{
			ion::DeleteArenaPtr<detail::NetUpdateWorker, NetInterfaceResource>(&control.mMemoryResource, control.mUpdater.mUpdateWorker);
		}
	}
}

ion::NetSocketReceiveData* AllocateReceiveBuffer(NetControl& reception)
{
	ion::NetSocketReceiveData* out = ion::Construct(reception.mReceiveAllocator);
#if (ION_ASSERTS_ENABLED == 1)
	reception.mUserPacketCount++;
#endif
	return out;
}

void DeallocateReceiveBuffer(NetControl& control, ion::NetSocketReceiveData* const rcv)
{
#if (ION_ASSERTS_ENABLED == 1)
	control.mUserPacketCount--;
#endif
	ion::Destroy(control.mReceiveAllocator, rcv);
}

void ClearCommand(NetControl& control, NetCommand*& command)
{
	if (1 == command->mRefCount--)
	{
		NetCommandPtr ptr(command);
		DeleteArenaPtr(&control.mMemoryResource, ptr);
	}
	command = nullptr;
}

void DeallocateSegment(NetControl& control, NetRemoteSystem& remote, NetDownstreamSegment* seg)
{
	if (seg->mOffset == 0)
	{
		remote.Deallocate<NetDownstreamSegment>(seg);
	}
	else
	{
		ion::NetSocketReceiveData* packet = reinterpret_cast<ion::NetSocketReceiveData*>(seg->data - seg->mOffset);
		DeallocateReceiveBuffer(control, packet);
	}
}

ion::NetPacket* AllocateUserPacket(NetControl& control, size_t size)
{
	ion::NetInterfaceAllocator<ion::NetPacket> allocator(control.mReceiveAllocator.GetSource());
	auto packet = allocator.AllocateRaw(ByteAlignPosition(NetPacketPayloadOffset + size, alignof(NetPacket)));
	if (packet)
	{
#if (ION_ASSERTS_ENABLED == 1)
		control.mUserPacketCount++;
#endif
		packet->mFlags = NetPacketFlags::Clear;
		packet->mDataPtr = NetPacketHeader(packet);
	}
	return packet;
}

void DeallocateUserPacket(NetControl& control, NetPacket* packet)
{
	if (packet->IsDirectSocketData())
	{
		DeallocateReceiveBuffer(control, reinterpret_cast<ion::NetSocketReceiveData*>(packet));
	}
	else
	{
#if (ION_ASSERTS_ENABLED == 1)
		control.mUserPacketCount--;
#endif
		ion::NetInterfaceAllocator<ion::NetPacket> allocator(control.mReceiveAllocator.GetSource());
		allocator.DeallocateRaw(packet, packet->mLength + NetPacketPayloadOffset);
	}
}

void SendSocketStatus(NetControl& control, NetMessageId id)
{
	if (NetPacket* packet = ion::NetControlLayer::AllocateUserPacket(control, sizeof(NetMessageId) + sizeof(int)))
	{
		packet->mLength = sizeof(NetMessageId) + sizeof(int);
		packet->mSource = nullptr;
		packet->mRemoteId = NetRemoteId();
		packet->mGUID = NetGuidUnassigned;
		{
			ByteWriterUnsafe writer(packet->Data());
			writer.Write(id);
		}
		PushPacket(control, packet);
	}
}

void RunnerRequired(NetControl& control) { control.mNumTargetActiveThreads++; }

void RunnerUnrequired(NetControl& control) { control.mNumTargetActiveThreads--; }

void RunnerReady(NetControl& control)
{
	auto start = control.mNumActiveThreads++;
	if (start + 1 == control.mNumTargetActiveThreads)
	{
		SendSocketStatus(control, NetMessageId::AsyncStartupOk);
	}
}

void RunnerExit(NetControl& control)
{
	auto result = control.mNumActiveThreads--;
	if (result == 1)
	{
		SendSocketStatus(control, NetMessageId::AsyncStopOk);
	}
}

void RunnerFailed(NetControl& control)
{
	SendSocketStatus(control, NetMessageId::AsyncStartupFailed);
}

void PushPacket(NetControl& control, NetPacket* packet)
{
	for (size_t i = 0; i < control.mPacketPushPlugins.Size(); ++i)
	{
		control.mPacketPushPlugins[i].second(control.mPacketPushPlugins[i].first, packet);
	}
}

void FlushPackets(NetControl& control)
{
	for (size_t i = 0; i < control.mPacketPopPlugins.Size(); ++i)
	{
		while (NetPacket* packet = control.mPacketPopPlugins[i].second(control.mPacketPopPlugins[i].first))
		{
			DeallocateUserPacket(control, packet);
		}
	}
}

}  // namespace NetControlLayer
}  // namespace ion
