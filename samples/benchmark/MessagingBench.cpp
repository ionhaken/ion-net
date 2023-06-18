#pragma comment(lib, "ws2_32.lib")
#define TEST_MAIN
#define CATCH_CONFIG_ENABLE_BENCHMARKING
#define TEST_RAKNET_REFERENCE 0

#include <ion/debug/CatchTestHelper.h>
#include <ion/debug/Error.h>

#include <ion/string/StringWriter.h>

#include<ion/util/Vec.h>


#if TEST_RAKNET_REFERENCE == 0
	#include <ion/core/Core.h>
	#include <ion/jobs/JobScheduler.h>
	#include <ion/net/NetGenericPeer.h>
	#include <ion/net/NetSecure.h>
	#include <ion/net/NetStartupParameters.h>
	#include <ion/net/NetMessageIdentifiers.h>
namespace BaseLib = ion;
	#define BaseLibTimeMS()			ion::SteadyClock::GetTimeMS()
	#define BaseLibSocketDescriptor ion::NetSocketDescriptor
static constexpr const uint8_t UserPacketId = ion::NetMessageId::UserPacket;
#else
	#include <MessageIdentifiers.h>>
	#include <ion/memory/UniquePtr.h>
	#include <ion/concurrency/Thread.h>
	#include <ion/time/CoreTime.h>
	#include <ion/time/Clock.h>

	#include <GetTime.h>
	#include <RakPeer.h>
static constexpr const uint8_t UserPacketId = ID_USER_PACKET_ENUM;
namespace BaseLib = SLNet;
#endif
namespace test
{

static constexpr const unsigned long PacketSize = 1024 * 1024;

union TestBuffer
{
	struct Header
	{
		uint8_t msgId;
		ion::TimeMS timeStamp;
		uint64_t clientIndex;
		uint64_t burstIndex;
		uint64_t guard;
	};
	Header header;
	char payload[PacketSize];
};

static float gPacketLoss = 0.0f;
static unsigned short gExtraPing = 20;

using PeerInstance = BaseLib::NetGenericPeer;

void PrepareForBenchmark(uint32_t NumClients, ion::Vector<ion::UniquePtr<PeerInstance>>& peerList, ion::UniquePtr<PeerInstance>& server)
{
#if TEST_RAKNET_REFERENCE == 0
	ion::NetworkSimulatorSettings networkSimulatorSettings;
	networkSimulatorSettings.minExtraPing = gExtraPing;
	networkSimulatorSettings.extraPingVariance = 0;
	networkSimulatorSettings.packetloss = gPacketLoss;
#endif
	if (server == nullptr)
	{
		server = ion::MakeUnique<test::PeerInstance>();
		BaseLibSocketDescriptor sd(60000, 0);
#if TEST_RAKNET_REFERENCE == 0
		server->ApplyNetworkSimulator(networkSimulatorSettings);
		ion::NetStartupParameters startupParameters = ion::NetStartupParameters::Create(5000, &sd, 1);
		startupParameters.mJobScheduler = ion::core::gSharedScheduler;
		startupParameters.mEnableSendThread = true;
		
		startupParameters.mUpdateMode = ion::NetPeerUpdateMode::Job;
		startupParameters.mSendThreadPriority = ion::Thread::Priority::Normal;
		startupParameters.mReceiveThreadPriority = ion::Thread::Priority::Normal;
		startupParameters.mUpdateThreadPriority = ion::Thread::Priority::Normal;

		server->Startup(startupParameters);		
		
		server->DisableSecurity(); // Security is not enabled in reference by default
#else
		server->ApplyNetworkSimulator(gPacketLoss, gExtraPing, 0);
		server->Startup(NumClients, &sd, 1);
#endif
	}
	server->SetMaximumIncomingConnections(NumClients);

	while (peerList.Size() < NumClients)
	{
		peerList.Add(ion::MakeUnique<PeerInstance>());
		BaseLibSocketDescriptor sd;
#if TEST_RAKNET_REFERENCE == 0
		peerList.Back()->ApplyNetworkSimulator(networkSimulatorSettings);
		
		peerList.Back()->DisableSecurity();  // Security is not enabled in reference by default

		ion::NetStartupParameters startupParameters{1, &sd, 1};
		startupParameters.mEnableSendThread = false;
		startupParameters.mUpdateMode = ion::NetPeerUpdateMode::User;
		startupParameters.mSendThreadPriority = ion::Thread::Priority::Normal;
		startupParameters.mReceiveThreadPriority = ion::Thread::Priority::Normal;
		startupParameters.mUpdateThreadPriority = ion::Thread::Priority::Normal;
		auto res = peerList.Back()->Startup(startupParameters);
		REQUIRE(res == ion::NetStartupResult::Started);
#else
		peerList.Back()->ApplyNetworkSimulator(gPacketLoss, gExtraPing, 0);
		peerList.Back()->Startup(1, &sd, 1);
#endif
		peerList.Back()->SetMaximumIncomingConnections(1);
	}

	while (server->NumberOfConnections() != NumClients)
	{
		for (size_t i = 0; i < NumClients; ++i)
		{
			peerList[i]->PreUpdate();
			if (auto packet = peerList[i]->Receive())
			{
				if (packet->Data()[0] == ion::NetMessageId::AsyncStartupOk)
				{
					ion::NetConnectionAttemptResult cres = peerList[i]->Connect("127.0.0.1", 60000, nullptr, 0);
					REQUIRE(cres == ion::NetConnectionAttemptResult::Started);
				}
				peerList[i]->DeallocatePacket(packet);
			}
			peerList[i]->PostUpdate();
		}
		ion::Thread::Sleep(10 * 1000);
	}
}

struct Pars
{
	uint32_t packetSize;
	uint32_t NumClients;
	uint32_t NumMessagesPerTarget;
	ion::TimeMS updateInterval;
	ion::NetPacketReliability packetReliability;
	ion::NetPacketPriority packetPriority;
	ion::Vector<ion::UniquePtr<PeerInstance>>& peerList;
	ion::UniquePtr<PeerInstance>& server;
	size_t BurstSize = 1;
	ion::String* strBuffer = nullptr;
	bool isServerSending = false;
};

void ReadAndSend(const Pars& pars, PeerInstance* instance, uint32_t nextSend, ion::NetGUID remoteGUID, ion::TimeMS now,
				  std::atomic<size_t>& totalSamples, std::atomic<size_t>& totalDelta, size_t burstToSend)
{
	while (auto* packet = instance->Receive())
	{
		ion::ByteReader reader(packet->Data(), packet->Length());
		uint8_t msgId;
		bool isValid = reader.Read(msgId);
		if (msgId == UserPacketId)
		{
		
			uint64_t guard;
			isValid &= reader.Process(guard);
			ION_ASSERT(guard == 0xABBAFCED, "Invalid guard");
			ion::TimeMS timeStamp;
			reader.Process(timeStamp);
			totalDelta += ion::DeltaTime(now, timeStamp);
			totalSamples++;
		}
		instance->DeallocatePacket(packet);
		ION_ASSERT(isValid, "Invalid data");
	}
	auto remoteId = instance->GetRemoteId(remoteGUID);

	using BufferType = ion::ByteBuffer<0, ion::TemporaryAllocator<ion::u8>>;


	for (size_t j = 0; j < burstToSend; ++j)
	{
		ion::NetSendCommand cmd = instance->CreateSendCommand(remoteId, pars.packetSize, !remoteId.IsValid());
		if (cmd.HasBuffer())
		{
			cmd.Parameters().mPriority = pars.packetPriority;
			cmd.Parameters().mReliability = pars.packetReliability;
			{
				auto writer = cmd.Writer();
				writer.Write(UserPacketId);
				writer.Process(uint64_t(0xABBAFCED));
				writer.Process(nextSend);
				for (int k = 0; k < (pars.packetSize - 13) / 8; ++k)
				{
					writer.Write(uint64_t(k));
				}
			}
			cmd.Dispatch();
		}
	}
}

float RunBenchmark(const Pars& pars)
{
	float avgLatency = 0.0f;
	std::atomic<size_t> totalEchos = 0;

	do
	{
		auto now = BaseLibTimeMS();
		auto startTime = now;
		auto nextSend = now;

		std::atomic<size_t> totalSamples = 0;
		std::atomic<size_t> totalDelta = 0;
		size_t totalMessages = 0;

		for (; ion::DeltaTime(now, startTime) < pars.NumMessagesPerTarget * pars.updateInterval * pars.NumClients + 3000;
			 now = BaseLibTimeMS())
		{
			bool isSending = totalMessages != pars.NumMessagesPerTarget * pars.BurstSize; 
			if (!isSending)
			{
				if (totalMessages == totalSamples / pars.NumClients)
				{
					break;
				}
			}

			isSending &= ion::DeltaTime(now, nextSend) >= 0;
			
			ion::ParallelInvoke(
			  [&]()
			  {
				  ion::ParallelForIndex(0, pars.NumClients, 16, 16,
								   [&](size_t i) [[msvc::forceinline]]
								   {
									   pars.peerList[i]->PreUpdate();
									   ReadAndSend(pars, pars.peerList[i].get(), nextSend, pars.server->GetMyGUID(), now, totalSamples,
												   totalDelta, !pars.isServerSending && isSending ? pars.BurstSize : 0);
									   pars.peerList[i]->PostUpdate();
								   });
			  },
			  [&]()
			  {
				  ReadAndSend(pars, pars.server.get(), nextSend, ion::NetGuidUnassigned, now, totalSamples, totalDelta,
							  pars.isServerSending && isSending ? pars.BurstSize : 0);
			  });

			if (isSending)
			{
				totalMessages += pars.BurstSize;
				nextSend += pars.updateInterval;
			}
			
		}

		if (totalMessages != totalSamples / pars.NumClients)
		{
			ION_LOG_INFO("Data transmission timed out");
			REQUIRE(false);
			avgLatency = 1000.0f;
			break;
		}

		auto timeSpent = ion::DeltaTime(BaseLibTimeMS(), startTime);
		auto mgsSPC = (float(totalSamples) * 1000 / timeSpent / pars.NumClients);
		avgLatency = (float(totalDelta) / totalSamples);
		if (pars.strBuffer)
		{
			ION_LOG_INFO("" << pars.NumClients << " clients, total messages sent : " << size_t(totalSamples) << "(" << mgsSPC
							<< "msgs / s / client) avg.latency : " << avgLatency << "ms");
		}

		if (pars.strBuffer)
		{
			ion::StringWriter strWriter(*pars.strBuffer);
			strWriter.Write(test::PacketSize);
			strWriter.Write(";");
			strWriter.Write(pars.packetReliability);
			strWriter.Write(";");
			strWriter.Write(pars.NumClients);
			strWriter.Write(";");
			strWriter.Write(avgLatency * 1000);
			strWriter.Write("\n");
		}

	} while (0);

	return avgLatency;
}

}  // namespace test

// Test setup that gives extra time for previous test run to complete. Otherwise, update thread may still be awake from previous run and
// this would give unfair advantage to poor implementation that does not wake up the update.
#define NET_BENCHMARK(__name, __test)                                         \
	BENCHMARK_ADVANCED(__name)                                                \
	(Catch::Benchmark::Chronometer meter)                                     \
	{                                                                         \
		ion::Thread::Sleep((10 + (uint64_t(rand()) * 10 / RAND_MAX)) * 1000); \
		meter.measure([&] { return __test; });                                \
	};

TEST_CASE("client_server_messaging", "[ideal]")
{
	//ion::UniquePtr<ion::JobScheduler> js = ion::MakeUnique<ion::JobScheduler>();
	ion::NetInit();
	test::gExtraPing = 0;
	test::gPacketLoss = 0.0f;
	ion::String strBuffer;

	{
		ion::UniquePtr<test::PeerInstance> server;
		ion::Vector<ion::UniquePtr<test::PeerInstance>> peerList;
		constexpr unsigned short MaxClients = 4;
		peerList.Reserve(MaxClients);

		test::PrepareForBenchmark(1, peerList, server);

		ion::NetPacketPriority packetPriority = ion::NetPacketPriority::Immediate;

		NET_BENCHMARK("400B_unreliable_transmission_immediate",
					  test::RunBenchmark({400, 1, 1, 16, ion::NetPacketReliability::Unreliable, packetPriority, peerList, server}););

		NET_BENCHMARK("400B_reliable_transmission_immediate",
					  test::RunBenchmark({400, 1, 1, 16, ion::NetPacketReliability::Reliable, packetPriority, peerList, server});)

		NET_BENCHMARK("1300Bx20_unreliable_burst",
					  test::RunBenchmark({1300, 1, 1, 16, ion::NetPacketReliability::Unreliable, packetPriority, peerList, server, 20});)

		NET_BENCHMARK("1300Bx20_reliable_burst",
					  test::RunBenchmark({1300, 1, 1, 16, ion::NetPacketReliability::Reliable, packetPriority, peerList, server, 20});)

		NET_BENCHMARK("32KB_reliable_transmission",
					  test::RunBenchmark({32 * 1024, 1, 1, 16, ion::NetPacketReliability::Reliable, packetPriority, peerList, server});)

		test::PrepareForBenchmark(MaxClients, peerList, server);
		NET_BENCHMARK(
		  "1300B_multi_client_reliable_transmission",
		  test::RunBenchmark({1300, MaxClients, 1, 16, ion::NetPacketReliability::Reliable, packetPriority, peerList, server}););

		NET_BENCHMARK("1300B_server_broadcast_reliable_transmission",
					  test::RunBenchmark({1300, MaxClients, 1, 16, ion::NetPacketReliability::Reliable, packetPriority, peerList, server, 1,
										  nullptr, true}););

	}
	ion::NetDeinit();
}

#if !ION_BUILD_DEBUG
TEST_CASE("mass_send", "[ideal]")
{
	ion::UniquePtr<ion::JobScheduler> js = ion::MakeUnique<ion::JobScheduler>();
	ion::NetInit();
	test::gExtraPing = 0;
	test::gPacketLoss = 0.0f;
	ion::String strBuffer;

	{
		ion::Vector<ion::UniquePtr<test::PeerInstance>> peerList;
		ion::UniquePtr<test::PeerInstance> server;
		constexpr unsigned short MaxClients = 4096;

		peerList.Reserve(MaxClients);

		ion::NetPacketPriority packetPriority = ion::NetPacketPriority::Immediate;

		test::PrepareForBenchmark(MaxClients, peerList, server);
		
		{
			ion::NetStats stats;
			server->GetStatistics(ion::NetUnassignedSocketAddress, stats);	// Reset stats
		}

		unsigned long numBytesToSend = 4 * 1024;
		for (int i = 0; i < 20; ++i)
		{
			ion::StopClock c;

			test::RunBenchmark(
			  {numBytesToSend, MaxClients, 1, 20, ion::NetPacketReliability::Reliable, packetPriority, peerList, server, 1, nullptr, true});
			auto totalTime = c.GetMillis();

			ion::NetStats stats;
			server->GetStatistics(ion::NetUnassignedSocketAddress, stats);
			size_t totalSize = (numBytesToSend * MaxClients);
			ION_LOG_INFO("Server sending " << (numBytesToSend / 1024) << "KB to " << MaxClients << " clients in " << totalTime << " ms ("
										   << ((numBytesToSend * MaxClients) / (1000 * 1000)) << " MB) MB - Calculated sent/sec: "
										   << (float(totalSize) / (float(totalTime) / 1000.0)) / (1000 * 1000) << " MB/s"
										   << " Metrics: Raw Sent/sec:" << stats.RawBytesPerSecondSent() / (1000 * 1000) << " MB/s "
										   << " Raw Recv/sec:" << stats.RawBytesPerSecondReceived() / (1000 * 1000) << " MB/s "
										   << " Total Raw Sent:" << stats.RawBytesSent() / (1000 * 1000) << " MB"
										   << " Total Raw Recv:" << stats.RawBytesReceived() / (1000 * 1000) << " MB"
										   << " Total Raw Resent:" << stats.RawBytesResent() / (1000 * 1000) << " MB");
		}
	}
	ion::NetDeinit();
}
#endif

#if ION_BUILD_DEBUG || ION_NET_SIMULATOR
TEST_CASE("no_packet_loss", "[actual]")
{
	ion::NetInit();
	{
		test::gExtraPing = 20;
		test::gPacketLoss = 0.0f;
		ion::String strBuffer;
		constexpr unsigned short MaxClients = 4;

		ion::UniquePtr<test::PeerInstance> server;

		ion::Vector<ion::UniquePtr<test::PeerInstance>> peerList;
		peerList.Reserve(MaxClients);

		test::PrepareForBenchmark(1, peerList, server);

		ion::NetPacketPriority packetPriority = ion::NetPacketPriority::Immediate;

		BENCHMARK("400B_reliable_transmission_immediate")
		{
			float avgLatency = test::RunBenchmark({400, 1, 1, 16, ion::NetPacketReliability::Reliable, packetPriority, peerList, server});
			return avgLatency;
		};
	}
	ion::NetDeinit();
}

TEST_CASE("packet_loss_1", "[actual]")
{
	ion::NetInit();
	{
		ion::UniquePtr<ion::JobScheduler> js = ion::MakeUnique<ion::JobScheduler>();

		test::gExtraPing = 20;
		test::gPacketLoss = 0.01f;
		constexpr unsigned short MaxClients = 4;
		ion::String strBuffer;

		ion::UniquePtr<test::PeerInstance> server;
		ion::Vector<ion::UniquePtr<test::PeerInstance>> peerList;
		peerList.Reserve(MaxClients);

		test::PrepareForBenchmark(1, peerList, server);

		ion::NetPacketPriority packetPriority = ion::NetPacketPriority::Immediate;

		BENCHMARK("400B_reliable_transmission_immediate")
		{
			float avgLatency = test::RunBenchmark({400, 1, 1, 16, ion::NetPacketReliability::Reliable, packetPriority, peerList, server});
			return avgLatency;
		};
	}
	ion::NetDeinit();
}

TEST_CASE("packet_loss_5", "[actual]")
{
	ion::NetInit();
	{
		ion::UniquePtr<ion::JobScheduler> js = ion::MakeUnique<ion::JobScheduler>();

		test::gExtraPing = 20;
		test::gPacketLoss = 0.05f;
		constexpr unsigned short MaxClients = 4;
		ion::String strBuffer;

		ion::UniquePtr<test::PeerInstance> server;
		ion::Vector<ion::UniquePtr<test::PeerInstance>> peerList;
		peerList.Reserve(MaxClients);

		test::PrepareForBenchmark(1, peerList, server);

		ion::NetPacketPriority packetPriority = ion::NetPacketPriority::Immediate;

		BENCHMARK("400B_reliable_transmission_immediate")
		{
			float avgLatency = test::RunBenchmark({400, 1, 1, 16, ion::NetPacketReliability::Reliable, packetPriority, peerList, server});
			return avgLatency;
		};
	}
	ion::NetDeinit();
}
#endif
