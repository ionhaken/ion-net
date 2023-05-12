#ifndef ION_NET_H
#define ION_NET_H

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C"
{
#endif

	enum ion_net_code
	{
		// API failure
		ION_NET_CODE_NOT_ACTIVE = -11,

		// Connection attempt failure
		ION_NET_CODE_CANNOT_RESOLVE_DOMAIN_NAME = -10,
		ION_NET_CODE_ALREADY_CONNECTED_TO_ENDPOINT = -9,
		ION_NET_CODE_NO_FREE_CONNECTIONS = -8,
		ION_NET_CODE_INVALID_PARAMETER = -7,

		// Startup failure
		ION_NET_CODE_INVALID_SOCKET_DESCRIPTORS = -5,
		ION_NET_CODE_INVALID_MAX_CONNECTIONS = -4,
		ION_NET_CODE_SOCKET_FAILED_TO_BIND = -3,
		ION_NET_CODE_SOCKET_FAILED_TEST_SEND = -2,
		ION_NET_CODE_FAILED_TO_CREATE_NETWORK_THREAD = -1,

		// Generic Ok/Fail
		ION_NET_CODE_FAIL = 0,
		ION_NET_CODE_OK = 1,

		// Startup success
		ION_NET_CODE_STARTED,
		ION_NET_CODE_ALREADY_STARTED,

		// Connection attempt success
		ION_NET_CODE_CONNECTION_ATTEMPT_STARTED,
		ION_NET_CODE_CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS
	};

	union ion_net_socket_address_t;
	typedef union ion_net_socket_address_t* ion_net_socket_address;

	union ion_net_guid_t;
	typedef union ion_net_guid_t* ion_net_guid;

	union ion_net_remote_id_t;
	typedef union ion_net_remote_id_t* ion_net_remote_id;

	struct ion_net_connect_target_t;
	typedef struct ion_net_connect_target_t* ion_net_connect_target;

	struct ion_net_peer_t;
	typedef struct ion_net_peer_t* ion_net_peer;

	struct ion_net_public_key_t;
	typedef struct ion_net_public_key_t* ion_net_public_key;

	struct ion_net_memory_resource_t;
	typedef struct ion_net_memory_resource_t* ion_net_memory_resource;

	struct ion_net_socket_t;
	typedef struct ion_net_socket_t* ion_net_socket;

	struct ion_job_scheduler_t;
	typedef struct ion_job_scheduler_t* ion_job_scheduler;

	struct ion_net_startup_parameters_t;
	typedef struct ion_net_startup_parameters_t* ion_net_startup_parameters;

	void ion_net_init();
	void ion_net_deinit();

	ion_net_memory_resource ion_net_create_memory_resource();
	void ion_net_destroy_memory_resource(ion_net_memory_resource);

	ion_net_peer ion_net_create_peer(ion_net_memory_resource);
	void ion_net_destroy_peer(ion_net_peer);

	void ion_net_preupdate(ion_net_peer, ion_job_scheduler);
	void ion_net_postupdate(ion_net_peer, ion_job_scheduler);

	int ion_net_startup(ion_net_peer handle, const ion_net_startup_parameters pars);
	void ion_net_shutdown(ion_net_peer handle, unsigned int blockDuration, unsigned char orderingChannel,
						  unsigned int disconnectionNotificationPriority);

	unsigned int ion_net_user_index_to_socket_index(ion_net_peer handle, unsigned int userIndex);

	int ion_net_send_connection_request(ion_net_peer handle, ion_net_connect_target connect_target, const char* passwordData,
										int passwordDataLength, ion_net_public_key /* #TODO Support sharing public key before connection */,
										unsigned connectionSocketIndex, unsigned int extraData, unsigned sendConnectionAttemptCount,
										unsigned timeBetweenSendConnectionAttemptsMS, uint32_t timeoutTime, ion_net_socket socket);

	int ion_net_connect_with_socket(ion_net_peer handle, const char* host, unsigned short remotePort, const char* passwordData,
									int passwordDataLength, ion_net_socket socket, ion_net_public_key publicKey,
									unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS,
									uint32_t timeoutTime);

	int ion_net_connect(ion_net_peer handle, ion_net_connect_target target, const char* passwordData, int passwordDataLength,
						ion_net_public_key publicKey, unsigned connectionSocketIndex, unsigned sendConnectionAttemptCount,
						unsigned timeBetweenSendConnectionAttemptsMS, uint32_t timeoutTime);

	bool ion_net_ping(ion_net_peer handle, ion_net_connect_target target, bool onlyReplyOnAcceptingConnections,
					  unsigned connectionSocketIndex);

	void ion_net_ping_address(ion_net_peer handle, ion_net_socket_address address);

	void ion_net_add_to_security_exceptions_list(ion_net_peer handle, const char*);

	void ion_net_remove_from_security_exceptions_list(ion_net_peer handle, const char*);

	bool ion_net_is_in_security_exception_list(ion_net_peer handle, const char*);

	void ion_net_get_incoming_password(ion_net_peer handle, char* passwordData, int* passwordDataLength);

	void ion_net_set_incoming_password(ion_net_peer handle, const char* passwordData, int passwordDataLength);

	bool ion_net_is_active(ion_net_peer handle);

	int ion_net_get_connection_list(ion_net_peer handle, ion_net_remote_id remote_ids, unsigned int* number_of_systems);

	unsigned int ion_net_number_of_remote_initiated_connections(ion_net_peer handle);

	unsigned int ion_net_number_of_connections(ion_net_peer handle);

#if defined(__cplusplus)
}
#endif
#endif
