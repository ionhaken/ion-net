#pragma once

#include <ion/net/NetMessages.h>

//
// Connection failed messages categorized how to fix them
//

// Canceled: Fix connection
#define MESSAGE_CONNECTION_ATTEMPT_CANCEL_CONNECTION case NetMessageId::ConnectionAttemptFailed:

// Canceled: Fix client
#define MESSAGE_CONNECTION_ATTEMPT_CANCEL_CLIENT \
	case NetMessageId::InvalidPassword:                    \
	case NetMessageId::IncompatibleProtocolVersion:

// Canceled: Fix server
#define MESSAGE_CONNECTION_ATTEMPT_CANCEL_SERVER \
	case NetMessageId::NoFreeIncomingConnections:        \
	case NetMessageId::ConnectionBanned:                   \
	case NetMessageId::AlreadyConnected:                   \
	case NetMessageId::GuidReserved:                       \
	case NetMessageId::CannotProcessRequest:              \
	case NetMessageId::IpRecentlyConnected:

#define MESSAGE_CONNECTION_ATTEMPT_CANCEL        \
	MESSAGE_CONNECTION_ATTEMPT_CANCEL_CONNECTION \
	MESSAGE_CONNECTION_ATTEMPT_CANCEL_CLIENT     \
	MESSAGE_CONNECTION_ATTEMPT_CANCEL_SERVER
