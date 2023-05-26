
#include <ion/net/NetGenericPeer.h>
#include <ion/net/NetPacketPriority.h>
#include <ion/net/NetSdk.h>
#include <ion/net/NetStartupParameters.h>

#include <ion/core/Engine.h>
#include <ion/string/Hex.h>
int main()
{
	ion::NetInit();
	{
		ion::UniquePtr<ion::NetGenericPeer> server = ion::MakeUnique<ion::NetGenericPeer>();
		ion::NetSocketDescriptor sd(60000, 0);
		auto startupResult = server->Startup(ion::NetStartupParameters::Create(8 /* max connections */, &sd, 1 /* number of socket descriptors */));
		if (int(startupResult) <= 0)
		{
			ION_LOG_INFO("Cannot start server;error=" << startupResult);
			exit(EXIT_FAILURE);
		}

		// Loop until ctrl+break
		while (!ion::Engine::IsExitRequested())
		{
			// Capture received packets
			while (auto* packet = server->Receive())
			{
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

				ION_LOG_INFO("Server received packet id=0x"
							 << ion::Hex<uint8_t>(packet->Data()[0])			// First element of data is always message identifier
							 << ";lenght=" << packet->Length()					// Packet length
							 << ";GUID=" << server->GetGuid(packet->mRemoteId)	// You use Remote-Ids to identify peers locally
																				// GUIDs across connections
							 << ";Address=" << server->GetAddress(packet->mRemoteId));
				ION_LOG_INFO("Payload='" << buffer << "'");

				// Send back message with string "Hello\n"
				ion::NetSendCommand cmd = server->CreateSendCommand(packet->mRemoteId, 64 /* max msg lenght */);
				server->DeallocatePacket(packet);
				if (cmd.HasBuffer())
				{
					cmd.Parameters().mChannel = 16;
					cmd.Parameters().mPriority = ion::NetPacketPriority::Low;
					cmd.Parameters().mReliability = ion::NetPacketReliability::Reliable;
					{
						ion::ByteWriter writer = cmd.Writer();
						writer.Write(ion::NetMessageId::UserPacket);
						writer.Write("Hello");
					}
					cmd.Dispatch();
				}
			}
			ion::Thread::Sleep(5 * 1000);
		}
		ION_LOG_INFO("Ok.");
		server->Shutdown(1000);
	}
	ion::NetDeinit();
}
