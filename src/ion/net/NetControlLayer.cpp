#include <ion/net/NetCommand.h>
#include <ion/net/NetConfig.h>
#include <ion/net/NetControlLayer.h>
#include <ion/net/NetGUID.h>
#include <ion/net/NetGlobalClock.h>
#include <ion/net/NetInterface.h>
#include <ion/net/NetMemory.h>
#include <ion/net/NetRemoteStore.h>
#include <ion/net/NetRemoteStoreLayer.h>
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
	}
}

void ClearBufferedCommands(NetControl& control)
{
	control.mBufferedCommands.DequeueAll([&](ion::NetCommandPtr& bcs) { ion::DeleteArenaPtr(&control.mMemoryResource, bcs); });
}

void Process(NetControl& control, NetRemoteStore& remoteStore, const NetConnections& connections, ion::TimeMS now)
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
			ion::NetRemoteStoreLayer::SendImmediate(remoteStore, control, std::move(bcs), now, remoteIndices);

			// Set the new connection state AFTER we call sendImmediate in case we are setting it to a disconnection state, which does
			// not allow further sends
			if (connectionMode != NetMode::Disconnected)
			{
				ForEach(remoteIndices,
						[&](auto index)
						{
							auto& remoteSystem = remoteStore.mRemoteSystemList[index];
							ION_ASSERT(remoteSystem.mMode != NetMode::Disconnected, "Invalid remote");
							ion::NetRemoteStoreLayer::SetMode(remoteStore, remoteSystem, connectionMode);
						});
			}
			remoteIndices.Clear();
			continue;  // Command ownership moved to remote store
		}
		else
		{
			switch (bcs->mCommand)
			{
			case NetCommandType::CloseConnection:
			{
				CloseConnectionInternal(control, remoteStore, connections, NetAddressOrRemoteRef(bcs->mTarget.mRemoteId), false, true,
										bcs->mChannel, bcs->mPriority);
				break;
			}
			case NetCommandType::ChangeSystemAddress:
			{
				ion::NetRemoteSystem* rssFromGuid =
				  ion::NetRemoteStoreLayer::GetRemoteSystem(remoteStore, *reinterpret_cast<NetRemoteId*>(&bcs->mData), true, true);
				if (rssFromGuid != 0)
				{
					ion::NetRemoteId existingRemote =
					  NetRemoteStoreLayer::GetRemoteIdFromSocketAddress(remoteStore, rssFromGuid->mAddress, true, false);
					if (existingRemote.IsValid())
					{
						ion::NetRemoteStoreLayer::ReferenceRemoteSystem(remoteStore, bcs->mTarget.mAddressList.Front(),
																		existingRemote.RemoteIndex());
					}
				}
				break;
			}
			case NetCommandType::EnableTimeSync:
			{
				ion::GlobalClock* srcClock;
				memcpy((char*)&srcClock, &bcs->mData, sizeof(char*));
				auto remoteSystem = ion::NetRemoteStoreLayer::GetRemoteSystem(remoteStore, bcs->mTarget.mRemoteId, true, true);
				if (remoteSystem)
				{
					remoteStore.mGlobalClock = srcClock;
					remoteStore.mGlobalClock->OnTimeSync(remoteSystem->timeSync.GetClock(), remoteSystem->timeSync.SyncState());
					remoteSystem->timeSync.SetActive(true);
				}
				else
				{
					ION_NET_LOG_ABNORMAL("No remote system for time sync;id=" << bcs->mTarget.mRemoteId);
					srcClock->OnOutOfSync();
					remoteStore.mGlobalClock = nullptr;
				}
				break;
			}
			case NetCommandType::DisableTimeSync:
			{
				auto remoteSystem = ion::NetRemoteStoreLayer::GetRemoteSystem(remoteStore, bcs->mTarget.mRemoteId, true, true);
				if (remoteSystem)
				{
					remoteSystem->timeSync.SetActive(false);
				}
				if (remoteStore.mGlobalClock)
				{
					remoteStore.mGlobalClock->OnOutOfSync();
					remoteStore.mGlobalClock = nullptr;
				}
				break;
			}
			case ion::NetCommandType::PingAddress:
			{
				auto* remoteSystem = ion::NetRemoteStoreLayer::GetRemoteSystem(remoteStore, *bcs->mTarget.mAddressList.Begin(), true, true);
				if (remoteSystem)
				{
					remoteSystem->pingTracker.OnPing(now);
					PingInternal(control, remoteStore, remoteSystem->mAddress, false, NetPacketReliability::Unreliable, now);
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
	if (updateDelta > NetUpdateInterval*2)
	{
		control.mResendExtraDelay = Min(Max(control.mResendExtraDelay, updateDelta * uint32_t(8)), NetMaxResendAlleviation);
		ION_NET_LOG_VERBOSE("Update took " << updateDelta << ", which is longer than update interval " << NetUpdateInterval
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

void CloseConnectionInternal(NetControl& control, NetRemoteStore& remoteStore, const NetConnections& connections,
							 const NetAddressOrRemoteRef& systemIdentifier, bool sendDisconnectionNotification, bool performImmediate,
							 unsigned char orderingChannel, NetPacketPriority disconnectionNotificationPriority)
{
	ION_ASSERT(orderingChannel < 32, "invalid channel");

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
		remoteId = NetRemoteStoreLayer::GetRemoteIdFromSocketAddress(remoteStore, targetAddress, performImmediate, false);
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
			ion::NetRemoteStoreLayer::SendImmediate(remoteStore, control, cmd.Release(), ion::SteadyClock::GetTimeMS());
			ion::NetRemoteSystem* rss = ion::NetRemoteStoreLayer::GetRemoteSystem(remoteStore, remoteId, true, true);
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
				remoteStore.mGlobalClock->OnOutOfSync();
				remoteStore.mGlobalClock = nullptr;
			}
		}
		else
		{
			SendBuffered(control, std::move(cmd.Release()));
		}
	}
	else
	{
		if (performImmediate)
		{
			if (remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mMode != NetMode::Disconnected &&
				remoteStore.mRemoteSystemList[remoteId.RemoteIndex()].mId.load() == remoteId)
			{
				ion::NetRemoteStoreLayer::ResetRemoteSystem(remoteStore, control, control.mMemoryResource, remoteId.RemoteIndex(),
															ion::SteadyClock::GetTimeMS());
				ion::NetRemoteStoreLayer::RemoveFromActiveSystemList(remoteStore, remoteId.RemoteIndex());
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
	bool isImmediate = NetChannelPriorityConfigs[int(cmd->mPriority)].workInterval == 0;
	control.mBufferedCommands.Enqueue(std::move(cmd));
	if (isImmediate)
	{
		// Forces pending sends to go out now, rather than waiting to the next update interval
		ion::NetControlLayer::Trigger(control);
	}
}

void PingInternal(NetControl& control, NetRemoteStore& remoteStore, const NetSocketAddress& target, bool performImmediate,
				  NetPacketReliability reliability, ion::TimeMS now)
{
	if (!control.mIsActive)
		return;

	NetSendCommand cmd(control, target, sizeof(unsigned char) + sizeof(ion::TimeMS));
	if (cmd.HasBuffer())
	{
		{
			ByteWriter writer(cmd.Writer());
			writer.Process(NetMessageId::ConnectedPing);
			writer.Process(now);
		}
		cmd.Parameters().mReliability = reliability;
		cmd.Parameters().mPriority = NetPacketPriority::Immediate;

		if (performImmediate)
		{
			ion::NetRemoteStoreLayer::SendImmediate(remoteStore, control, std::move(cmd.Release()), now);
			return;
		}
	}
	cmd.Dispatch();
}

int Send(NetControl& control, const NetRemoteStore& remoteStore, const char* data, const int length, NetPacketPriority priority,
		 NetPacketReliability reliability, char orderingChannel, const NetAddressOrRemoteRef& systemIdentifier, bool broadcast)
{
	ION_NET_API_CHECK(data && length > 0, -1, "Invalid data");
	ION_NET_API_CHECK(!(int(reliability) >= int(NetPacketReliability::Count) || int(reliability) < 0), -1, "Invalid reliablity");
	ION_NET_API_CHECK(!(int(priority) > int(NetPacketPriority::Count) || int(priority) < 0), -1, "Invalid priority");
	ION_NET_API_CHECK(!(orderingChannel >= NetNumberOfChannels), -1, "Invalid channel");
	ION_ASSERT(control.mIsActive, "Not active");

	if (remoteStore.mRemoteSystemList == nullptr)
		return 0;

	if (broadcast == false)
	{
		if (systemIdentifier.IsUndefined())
		{
			return 0;
		}
		if (ion::NetRemoteStoreLayer::IsLoopbackAddress(remoteStore, systemIdentifier, true))
		{
			SendLoopback(control, remoteStore, data, length);
			return 1;
		}
	}
	ion::NetControlLayer::SendBuffered(control, data, length, priority, reliability, orderingChannel, systemIdentifier, broadcast,
									   NetMode::Disconnected);
	return 1;
}

void SendLoopback(NetControl& control, const NetRemoteStore& remoteStore, const char* data, const int length)
{
	if (data == 0 || length < 0)
		return;

	ion::NetPacket* packet = ion::NetControlLayer::AllocateUserPacket(control, length);
	packet->mSource = nullptr;
	packet->mLength = length;

	// NetPacket* packet = AllocPacket(length);
	memcpy(packet->Data(), data, length);
	packet->mAddress = ion::NetRemoteStoreLayer::GetLoopbackAddress(remoteStore);
	packet->mGUID = remoteStore.mGuid;
	packet->mRemoteId = NetRemoteId();
	control.mPacketReturnQueue.Enqueue(std::move(packet));
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
void StopUpdating(NetControl& control)
{
	if (control.mIsActive)
	{
		if (control.mUpdateMode == NetPeerUpdateMode::Job)
		{
			control.mUpdater.mUpdateJob->WaitUntilDone();
		}
		else if (control.mUpdateMode == NetPeerUpdateMode::Worker)
		{
			control.mUpdater.mUpdateWorker->myThreadSynchronizer.Stop();
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

void ClearCommand(NetControl& control, NetUpstreamSegment* seg)
{
	if (1 == seg->mCommand->mRefCount--)
	{
		NetCommandPtr ptr(seg->mCommand);
		DeleteArenaPtr(&control.mMemoryResource, ptr);
	}
	seg->mCommand = nullptr;
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
		packet->mInternalPacketType = NetInternalPacketType::User;
		packet->mDataPtr = NetPacketHeader(packet);
	}
	return packet;
}

void DeallocateUserPacket(NetControl& control, NetPacket* packet)
{
	if (packet->mInternalPacketType == NetInternalPacketType::DownstreamSegment)
	{
		DeallocateReceiveBuffer(control, reinterpret_cast<ion::NetSocketReceiveData*>(packet));
	}
	else if (packet->mInternalPacketType == NetInternalPacketType::User)
	{
#if (ION_ASSERTS_ENABLED == 1)
		control.mUserPacketCount--;
#endif
		ion::NetInterfaceAllocator<ion::NetPacket> allocator(control.mReceiveAllocator.GetSource());
		allocator.DeallocateRaw(packet, packet->mLength + NetPacketPayloadOffset);
	}
	else
	{
		ION_ASSERT(false, "Invalid packet");
	}
}

void AddPacketToProducer(NetControl& control, ion::NetPacket* p) { control.mPacketReturnQueue.Enqueue(std::move(p)); }

}  // namespace NetControlLayer
}  // namespace ion
