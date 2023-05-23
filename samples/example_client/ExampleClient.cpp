#include <ion/net/NetGenericPeer.h>
#include <ion/net/NetSdk.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/core/Engine.h>
#include <ion/string/Hex.h>
int main()
{
	ion::NetInit();
	{
		ion::UniquePtr<ion::NetGenericPeer> client = ion::MakeUnique<ion::NetGenericPeer>();
		ion::NetSocketDescriptor sd;
		auto startupResult = client->Startup(ion::NetStartupParameters::CreateClient(&sd, 1));
		if (int(startupResult) <= 0)
		{
			ION_LOG_INFO("Cannot start client;error=" << startupResult);
			exit(EXIT_FAILURE);
		}

		// Loop until ctrl+break
		while (!ion::Engine::IsExitRequested())
		{
			auto connectResult = client->Connect("127.0.0.1", 60000);
			if (int(connectResult) <= 0)
			{
				ION_LOG_INFO("Cannot connect server;error=" << connectResult);
				exit(EXIT_FAILURE);
			}

			// Capture received packets
			while (auto* packet = client->Receive())
			{
				if (packet->Data()[0] == ion::NetMessageId::ConnectionAttemptFailed ||
					packet->Data()[0] == ion::NetMessageId::ConnectionLost)
				{
					ION_LOG_INFO("Cannot reach server");
					continue;
				}

				// Read packet to buffer
				char buffer[256];
				{
					int index = 0;
					ion::ByteReader reader(packet->Data(), packet->Length());
					reader.SkipBytes(1);  // skip message id
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

				ION_LOG_INFO("Client received packet id=0x"
							 << ion::Hex<uint8_t>(packet->Data()[0])			// First element of data is always message identifier
							 << ";lenght=" << packet->Length()					// Packet length
							 << ";GUID=" << client->GetGuid(packet->mRemoteId)	// You use Remote-Ids to identify peers locally
																				// GUIDs across connections
							 << ";Address=" << client->GetAddress(packet->mRemoteId));
				ION_LOG_INFO("Payload='" << buffer << "'");

				// Send back message with string "World\n"
				ion::NetSendCommand cmd = client->CreateSendCommand(packet->mRemoteId, 64 /* max msg lenght */);
				if (cmd.HasBuffer())
				{
					ion::ByteWriter writer = cmd.Writer();
					writer.Write(ion::NetMessageId::UserPacket);
					writer.Write("World");
					cmd.Parameters().mChannel = 16;
					cmd.Parameters().mPriority = ion::NetPacketPriority::Low;
					cmd.Parameters().mReliability = ion::NetPacketReliability::Reliable;
				}
				cmd.Dispatch();

				client->DeallocatePacket(packet);
			}
			ion::Thread::Sleep(5 * 1000);
		}
		ION_LOG_INFO("Ok.");
	}
	ion::NetDeinit();
	return EXIT_SUCCESS;
}
