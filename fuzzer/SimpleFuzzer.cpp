#pragma comment(lib, "ws2_32.lib")
#define TEST_MAIN
#define CATCH_CONFIG_ENABLE_BENCHMARKING
#include <ion/net/NetSecure.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/debug/CatchTestHelper.h>
#include <ion/debug/Error.h>

#include <ion/net/NetGeneralPeer.h>
#include <ion/string/StringWriter.h>
#include <ion/util/Random.h>

namespace test
{

static constexpr const unsigned long MaxPacketSize = 2 * 1024;

union TestBuffer
{
	char payload[MaxPacketSize];
};

static constexpr const unsigned short MaxClients = 64;

void Prepare(uint32_t NumClients, ion::Vector<ion::UniquePtr<ion::NetGeneralPeer>>& peerList, ion::UniquePtr<ion::NetGeneralPeer>& server)
{
	while (peerList.Size() < NumClients)
	{
		peerList.Add(ion::MakeUnique<ion::NetGeneralPeer>());
		ion::NetSocketDescriptor sd;
		peerList.Back()->DisableSecurity();
		auto res = peerList.Back()->Startup(ion::NetStartupParameters::CreateClient(&sd, 1));
		ION_ASSERT(res == ion::NetStartupResult::Started, "Failed to start");
		peerList.Back()->Connect("127.0.0.1", 60000, nullptr, 0);
	}

	if (server->NumberOfConnections() != NumClients)
	{
		for (size_t i = 0; i < NumClients; ++i)
		{
			// while (peerList[i]->GetIndexFromGuid(server->GetMyGUID()) == ion::NetGUID::InvalidNetRemoteIndex)
			{
				auto res = peerList[i]->Connect("127.0.0.1", 60000, nullptr, 0);

				ION_DBG("Reconnecting;Result=" << res);
			}
		}
	}
}

float Run(uint32_t NumClients, ion::Vector<ion::UniquePtr<ion::NetGeneralPeer>>& peerList, ion::UniquePtr<ion::NetGeneralPeer>& server,
		  TestBuffer& buffer, ion::String* strBuffer = nullptr)
{
	float avgLatency = 0.0f;

	if (ion::Random::FastFloat() < 0.01f)
	{
		for (size_t i = 0; i < NumClients; ++i)
		{
			ion::NetRemoteId serverRemoteId = peerList[i]->GetRemoteId(server->GetMyGUID());
			if (ion::Random::FastFloat() < 0.01f)
			{
				ion::NetStats stats;
				peerList[i]->GetStatistics(serverRemoteId, stats);
			}
			if (serverRemoteId.IsValid())
			{
				if (ion::Random::FastFloat() < 0.1f)
				{
					for (size_t j = 0; j < ion::Random::UInt32Tl() % 2; j++)
					{
						size_t len = (ion::Random::UInt32Tl() % (ion::Random::FastFloat() < 0.1f ? MaxPacketSize : 2048)) + 1;
						for (size_t i = 0; i < len; ++i)
						{
							buffer.payload[i] = uint8_t(ion::Random::UInt32Tl());
						}
						peerList[i]->Send(buffer.payload, len, ion::NetPacketPriority::Immediate,
										  ion::NetPacketReliability(ion::Random::UInt32Tl() % int(ion::NetPacketReliability::Count)), 0,
										  peerList[i]->GetRemoteId(server->GetMyGUID()), ion::Random::FastFloat() < 0.1f);
					}
				}
			}
		}
	}
	if (ion::Random::FastFloat() < 0.01f)
	{
		for (size_t j = 0; j < ion::Random::UInt32Tl() % 2; j++)
		{
			size_t len = ion::Random::UInt32Tl() % MaxPacketSize + 1;
			for (size_t i = 0; i < len; ++i)
			{
				buffer.payload[i] = uint8_t(ion::Random::UInt32Tl());
			}

			size_t target = ion::Random::UInt32Tl() % peerList.Size();
			server->Send(buffer.payload, len, ion::NetPacketPriority::Immediate,
						 ion::NetPacketReliability(ion::Random::UInt32Tl() % int(ion::NetPacketReliability::Count)), 0,
						 server->GetRemoteId(peerList[target]->GetMyGUID()), true);
		}
	}

	ion::Thread::Sleep(10);
	size_t numMessages = 0;
	for (size_t i = 0; i < NumClients; ++i)
	{
		while (auto* packet = peerList[i]->Receive())
		{
			peerList[i]->DeallocatePacket(packet);
			numMessages++;
		}
	}

	while (auto* packet = server->Receive())
	{
		server->DeallocatePacket(packet);
		numMessages++;
	}
	if (numMessages > 0)
	{
		ION_LOG_INFO("Received " << numMessages << " messages;" << server->NumberOfConnections() << " clients connected.");
	}
	return avgLatency;
}

}  // namespace test

TEST_CASE("client_server_randomized_data")
{
	ion::NetInit();
	{
#if (ION_ABORT_ON_FAILURE == 1)
		ion::debug::allowAbnormalCondition = true;
#endif
		ion::UniquePtr<ion::NetGeneralPeer> server = ion::MakeUnique<ion::NetGeneralPeer>();
		ion::UniquePtr<test::TestBuffer> buffer = ion::MakeUnique<test::TestBuffer>();
		ion::NetSocketDescriptor sd(60000, 0);
		server->DisableSecurity();
		server->Startup(ion::NetStartupParameters::Create(test::MaxClients, &sd, 1));

		ion::Vector<ion::UniquePtr<ion::NetGeneralPeer>> peerList;
		peerList.Reserve(test::MaxClients);

		while (!ion::Engine::IsExitRequested())
		{
			test::Prepare(test::MaxClients, peerList, server);
			test::Run(test::MaxClients, peerList, server, *buffer);
		}
	}
	ion::NetDeinit();
}
