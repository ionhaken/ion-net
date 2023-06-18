#pragma once

#include <ion/net/NetMessages.h>

//
// Connection failed messages categorized how to fix them
//

// Canceled: Cannot reach target. Connection issue?
#define MESSAGE_CONNECTION_ATTEMPT_CANCEL_CONNECTION case NetMessageId::ConnectionAttemptFailed:

// Canceled: Reached target, but got rejected. We are not providing correct parameters?
#define MESSAGE_CONNECTION_ATTEMPT_CANCEL_CLIENT \
	case NetMessageId::InvalidPassword:          \
	case NetMessageId::IncompatibleProtocolVersion:

// Canceled: Reached target, but remote cannot process us. Wait until remote resolves the issue?
#define MESSAGE_CONNECTION_ATTEMPT_CANCEL_SERVER  \
	case NetMessageId::NoFreeIncomingConnections: \
	case NetMessageId::ConnectionBanned:          \
	case NetMessageId::AlreadyConnected:          \
	case NetMessageId::GuidReserved:              \
	case NetMessageId::CannotProcessRequest:      \
	case NetMessageId::IpRecentlyConnected:

#define MESSAGE_CONNECTION_ATTEMPT_CANCEL        \
	MESSAGE_CONNECTION_ATTEMPT_CANCEL_CONNECTION \
	MESSAGE_CONNECTION_ATTEMPT_CANCEL_CLIENT     \
	MESSAGE_CONNECTION_ATTEMPT_CANCEL_SERVER
