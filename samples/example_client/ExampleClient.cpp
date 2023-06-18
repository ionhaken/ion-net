#include <ion/net/NetGenericPeer.h>
#include <ion/net/NetSdk.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/time/Clock.h>

#include <ion/core/Engine.h>
#include <ion/string/Hex.h>

void connect(ion::NetGenericPeer& client)
{
	auto connectResult = client.Connect("127.0.0.1", 60000);
	if (int(connectResult) <= 0)
	{
		ION_LOG_INFO("Cannot connect server;error=" << connectResult);
		exit(EXIT_FAILURE);
	}
}

void tryGracefulDisconnect(ion::NetGenericPeer& client)
{
	static ion::TimeMS startTime = ion::SteadyClock::GetTimeMS();

	int TimeToWaitForDisconnectsMs = 500;
	bool isWaitingForDisconnections = false;

	// Disconnect connected remotes
	if (ion::DeltaTime(ion::SteadyClock::GetTimeMS(), startTime) <= TimeToWaitForDisconnectsMs)
	{
		ion::NetVector<ion::NetRemoteId> remoteIds;
		client.GetSystemList(remoteIds);
		ion::ForEach(remoteIds,
					 [&](ion::NetRemoteId id)
					 {
						 auto connectionState = client.GetConnectionState(id);
						 if (connectionState != ion::NetConnectionState::Disconnected)
						 {
							 if (connectionState == ion::NetConnectionState::Connected)
							 {
								 client.CloseConnection(id, true);
							 }
							 isWaitingForDisconnections = true;
						 }
					 });
	}

	if (!isWaitingForDisconnections)
	{
		client.Stop();	// Do stop until AsyncStopOk is received
	}
}

void update(ion::NetGenericPeer& client)
{
	for (;;)
	{
		if (ion::Engine::IsExitRequested())	 // Loop until ctrl+break
		{
			tryGracefulDisconnect(client);
		}

		// Capture received packets
		while (auto* packet = client.Receive())
		{
			ion::ByteReader reader(packet->Data(), packet->Length());
			ion::NetMessageId id;
			reader.Process(id);

			// Read packet to buffer
			char buffer[256];
			{
				int index = 0;
				while (reader.Available() && index < 256)
				{
					reader.Process(buffer[index]);
					if (buffer[index] < ' ')
					{
						buffer[index] = '.';
					}
					index++;
				}
				buffer[index] = 0;
			}

			ION_LOG_INFO("--- Client received packet id=0x"
						 << ion::Hex<uint8_t>(packet->Data()[0])		   // First element of data is always message identifier
						 << ";lenght=" << packet->Length()				   // Packet length
						 << ";GUID=" << client.GetGuid(packet->mRemoteId)  // You use Remote-Ids to identify peers locally
																		   // GUIDs across connections
						 << ";Address=" << client.GetAddress(packet->mRemoteId));
			ION_LOG_INFO("Payload='" << buffer << "'");

			switch (id)
			case ion::NetMessageId::AsyncStartupOk:
			{
				{
					ION_LOG_INFO("Client started.");
					connect(client);
					break;
				}
			case ion::NetMessageId::AsyncStartupFailed:
				ION_LOG_INFO("Client startup failed.");
				client.DeallocatePacket(packet);
				return;
			case ion::NetMessageId::AsyncStopOk:
				ION_LOG_INFO("Client stopped.");
				client.DeallocatePacket(packet);
				return;
			case ion::NetMessageId::ConnectionAttemptFailed:
			case ion::NetMessageId::ConnectionLost:
			{
				ION_LOG_INFO("Client cannot reach server.");
				connect(client);  // Try to reconnect
				break;
			}
			default:
			{
				// Send back message with string "Hello Server\n"
				ion::NetSendCommand cmd = client.CreateSendCommand(packet->mRemoteId, 64 /* max msg lenght */);
				if (cmd.HasBuffer())
				{
					cmd.Parameters().mChannel = 0;
					cmd.Parameters().mPriority = ion::NetPacketPriority::Low;
					cmd.Parameters().mReliability = ion::NetPacketReliability::Reliable;
					{
						ion::ByteWriter writer = cmd.Writer();
						writer.Write(ion::NetMessageId::UserPacket);
						writer.Write("Hello Server");
					}
					cmd.Dispatch();
				}
				break;
			}
			}
				client.DeallocatePacket(packet);
		}
		ion::Thread::Sleep(ion::NetUpdateInterval * 1000);
	}
}

int main()
{
	int exitCode = EXIT_SUCCESS;
	ion::NetInit();
	{
		ion::UniquePtr<ion::NetGenericPeer> client = ion::MakeUnique<ion::NetGenericPeer>();
		ion::NetSocketDescriptor sd;
		auto startupResult = client->Startup(ion::NetStartupParameters::CreateClient(&sd, 1));
		if (int(startupResult) <= 0)
		{
			exitCode = EXIT_FAILURE;
			ION_LOG_INFO("Cannot start client;error=" << startupResult);
		}
		else
		{
			ion::Engine::InstallHandlers();	 // to detect ctrl+break
			update(*client);
			ion::Engine::ClearHandlers();
		}
	}
	ion::NetDeinit();
	return exitCode;
}
