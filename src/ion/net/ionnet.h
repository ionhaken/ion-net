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
		/* API failure */
		ION_NET_CODE_NOT_ACTIVE = -11,

		/* Connection attempt failure */
		ION_NET_CODE_CANNOT_RESOLVE_DOMAIN_NAME = -10,
		ION_NET_CODE_NO_FREE_CONNECTIONS = -8,
		ION_NET_CODE_INVALID_PARAMETER = -7,

		/* Startup failure */
		ION_NET_CODE_INVALID_SOCKET_DESCRIPTORS = -5,
		ION_NET_CODE_INVALID_MAX_CONNECTIONS = -4,
		ION_NET_CODE_SOCKET_FAILED_TO_BIND = -3,
		ION_NET_CODE_SOCKET_FAILED_TEST_SEND = -2,
		ION_NET_CODE_FAILED_TO_CREATE_NETWORK_THREAD = -1,

		/* Generic Ok/Fail */
		ION_NET_CODE_FAIL = 0,
		ION_NET_CODE_OK = 1,

		/* Startup success */
		ION_NET_CODE_STARTED,
		ION_NET_CODE_ALREADY_STARTED,

		/* Connection attempt success */
		ION_NET_CODE_CONNECTION_ATTEMPT_STARTED,
		ION_NET_CODE_CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS,
		ION_NET_CODE_ALREADY_CONNECTED_TO_ENDPOINT,

		/* Connection State */
		ION_NET_CODE_STATE_PENDING,
		ION_NET_CODE_STATE_CONNECTING,
		ION_NET_CODE_STATE_CONNECTED,
		ION_NET_CODE_STATE_DISCONNECTING,
		ION_NET_CODE_STATE_SILENTLY_DISCONNECTING,
		ION_NET_CODE_STATE_DISCONNECTED,
		ION_NET_CODE_STATE_NOT_CONNECTED
	};

	struct ion_net_statistics_t;
	typedef struct ion_net_statistics_t* ion_net_statistics;

	struct ion_net_simulator_settings_t;
	typedef struct ion_net_simulator_settings_t* ion_net_simulator_settings;

	struct ion_net_global_clock_t;
	typedef struct ion_net_global_clock_t* ion_net_global_clock;

	struct ion_net_remote_ref_t;
	typedef struct ion_net_remote_ref_t* ion_net_remote_ref;

	union ion_net_socket_address_t;
	typedef ion_net_socket_address_t* ion_net_socket_address;

	typedef uint64_t ion_net_guid_t;
	typedef ion_net_guid_t* ion_net_guid;

	typedef uint32_t ion_net_remote_id_t;
	typedef ion_net_remote_id_t* ion_net_remote_id;

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

	struct ion_net_packet_t;
	typedef struct ion_net_packet_t* ion_net_packet;

	/*
	 * Start/Stop functions
	 */

	void ion_net_init();
	void ion_net_deinit();

	ion_net_memory_resource ion_net_create_memory_resource();
	void ion_net_destroy_memory_resource(ion_net_memory_resource);

	ion_net_peer ion_net_create_peer(ion_net_memory_resource);
	void ion_net_destroy_peer(ion_net_peer);

	// Request to start peer. Does non-blocking (asynchronous) start of network threads and binding sockets.
	// After startup is complete, AsyncStartupOk packet will be created. If it was not possible to bind all sockets
	// AsyncStartupFailed packet will be created instead of.
	int ion_net_startup(ion_net_peer handle, const ion_net_startup_parameters pars);

	// Request to stop. Does non-blocking stopping of network threads and unbinding of sockets.
	// After stop is complete, AsyncStopOk packet will be created.
	// It's recommended to close remote connections and wait that connections have been closed calling stop.
	void ion_net_stop(ion_net_peer handle);

	// Shuts down all network activities. First of all it will try to close all remote connections and will block
	// for [blockDuration] or until all remotes have been disconnected gracefully. After that, if sockets are still bound and ion_net_stop()
	// was not called to unbind sockets, ion_net_shutdown will block until all sockets are unbound.
	//
	// The ion_net_shutdown() is mandatory to call before ion_net_startup() and ion_net_destroy_peer() can be called for a peer has started
	// with ion_net_startup().
	void ion_net_shutdown(ion_net_peer handle, unsigned int blockDuration, unsigned char orderingChannel,
						  unsigned int disconnectionNotificationPriority);

	/*
	 * Update functions
	 */

	void ion_net_preupdate(ion_net_peer, ion_job_scheduler);
	void ion_net_postupdate(ion_net_peer, ion_job_scheduler);

	/*
	 * Connection management
	 */

	int ion_net_connect(ion_net_peer handle, ion_net_connect_target target, const char* passwordData, int passwordDataLength,
						ion_net_public_key publicKey, unsigned connectionSocketIndex, unsigned sendConnectionAttemptCount,
						unsigned timeBetweenSendConnectionAttemptsMS, uint32_t timeoutTime);

	int ion_net_connect_with_socket(ion_net_peer handle, const char* host, unsigned short remotePort, const char* passwordData,
									int passwordDataLength, ion_net_socket socket, ion_net_public_key publicKey,
									unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS,
									uint32_t timeoutTime);

	void ion_net_cancel_connection_attempt(ion_net_peer handle, ion_net_socket_address address);

	void ion_net_close_connection(ion_net_peer handle, ion_net_remote_ref remote_ref, bool sendDisconnectionNotification,
								  unsigned char orderingChannel, int disconnectionNotificationPriority);

	void ion_net_set_maximum_incoming_connections(ion_net_peer handle, unsigned int numberAllowed);

	unsigned int ion_net_maximum_incoming_connections(ion_net_peer handle);

	void ion_net_allow_connection_response_ip_migration(ion_net_peer handle, bool allow);

	void ion_net_set_timeout_time(ion_net_peer handle, uint32_t timeMS, ion_net_socket_address target);

	uint32_t ion_net_timeout_time(ion_net_peer handle, ion_net_socket_address target);

	/*
	 * Connection information
	 */

	/* Returns ION_NET_CODE_STATE_* for given remote*/
	int ion_net_connection_state(ion_net_peer handle, ion_net_remote_ref remote_ref_ptr);

	/* Returns <= 0 if failed*/
	int ion_net_get_connection_list(ion_net_peer handle, ion_net_remote_id remote_ids, unsigned int* number_of_systems);

	/* Number of remote initiated established connections*/
	unsigned int ion_net_number_of_remote_initiated_connections(ion_net_peer handle);

	/* Number of established connections*/
	unsigned int ion_net_number_of_connections(ion_net_peer handle);

	unsigned int ion_net_maximum_number_of_peers(ion_net_peer handle);

	/* MTU size for remote*/
	unsigned int ion_net_mtu_size(ion_net_peer handle, ion_net_remote_ref remote);

	/*
	 * Addressing
	 */

	ion_net_guid_t ion_net_my_guid(ion_net_peer handle);

	void ion_net_socket_first_bound_address(ion_net_peer handle, ion_net_socket_address out);

	void ion_net_socket_bound_address(ion_net_peer handle, const int socketIndex, ion_net_socket_address out);

	void ion_net_local_ip(ion_net_peer handle, unsigned int index, char* strOut);

	bool ion_net_is_local_ip(ion_net_peer handle, const char* ip);

	void ion_net_external_id(ion_net_peer handle, ion_net_socket_address in, ion_net_socket_address out);

	void ion_net_internal_id(ion_net_peer handle, ion_net_socket_address in, const int index, ion_net_socket_address out);

	bool ion_net_is_ipv6_only(ion_net_peer handle);

	void ion_net_change_system_address(ion_net_peer handle, ion_net_remote_id_t remote_id, ion_net_socket_address address);

	unsigned ion_net_number_of_addresses(ion_net_peer handle);

	/*
	 * GUID/Address/Remote-id conversions
	 */

	ion_net_guid_t ion_net_address_to_guid(ion_net_peer handle, ion_net_socket_address address);

	void ion_net_guid_to_address(ion_net_peer handle, ion_net_guid_t input, ion_net_socket_address out);

	void ion_net_remote_id_to_address(ion_net_peer handle, ion_net_remote_id_t remote, ion_net_socket_address out);

	ion_net_guid_t ion_net_remote_id_to_guid(ion_net_peer handle, ion_net_remote_id_t remote);

	ion_net_remote_id_t ion_net_guid_to_remote_id(ion_net_peer handle, ion_net_guid_t guid);

	/*
	 * Data transfer
	 */

	int ion_net_send(ion_net_peer handle, const char* data, const int length, uint8_t priority, uint8_t reliability, char orderingChannel,
					 ion_net_remote_ref remote_ref, bool broadcast);

	void ion_net_send_loopback(ion_net_peer handle, const char* data, const int length);

	void ion_net_set_socket_big_data_key_code(ion_net_peer handle, unsigned int idx, const unsigned char* data);

	/*
	 * Packet reception queue handling
	 */

	ion_net_packet ion_net_allocate_packet(ion_net_peer handle, unsigned dataSize);

	void ion_net_deallocate_packet(ion_net_peer handle, ion_net_packet packet);

	void ion_net_push_packet(ion_net_peer handle, ion_net_packet packet);

	/*
	 * Ping
	 */

	void ion_net_ping_address(ion_net_peer handle, ion_net_socket_address address);

	bool ion_net_ping(ion_net_peer handle, ion_net_connect_target target, bool onlyReplyOnAcceptingConnections,
					  unsigned connectionSocketIndex);

	bool ion_net_set_offline_ping_response(ion_net_peer handle, const char* data, const unsigned int length);

	void ion_net_offline_ping_response(ion_net_peer handle, char** data, unsigned int* length);

	int ion_net_average_ping(ion_net_peer handle, ion_net_remote_ref remote_ref);

	int ion_net_last_ping(ion_net_peer handle, ion_net_remote_ref remote_ref);

	int ion_net_lowest_ping(ion_net_peer handle, ion_net_remote_ref remote_ref);

	void ion_net_set_occasional_ping(ion_net_peer handle, uint32_t time);

	/*
	 * Security
	 */

	void ion_net_add_to_security_exceptions_list(ion_net_peer handle, const char*);

	void ion_net_remove_from_security_exceptions_list(ion_net_peer handle, const char*);

	bool ion_net_is_in_security_exception_list(ion_net_peer handle, const char*);

	void ion_net_get_incoming_password(ion_net_peer handle, char* passwordData, int* passwordDataLength);

	void ion_net_set_incoming_password(ion_net_peer handle, const char* passwordData, int passwordDataLength);

	void ion_net_set_data_transfer_security_level(ion_net_peer handle, uint8_t level);

	int ion_net_is_banned(ion_net_peer handle, const char* IP);

	void ion_net_add_to_ban_list(ion_net_peer handle, const char* IP, uint32_t milliseconds);

	void ion_net_remove_from_ban_list(ion_net_peer handle, const char* IP);

	void ion_net_clear_ban_list(ion_net_peer handle);

	void ion_net_set_limit_ip_connection_frequency(ion_net_peer handle, bool b);

	/*
	 * Misc
	 */

	bool ion_net_is_active(ion_net_peer handle);

	unsigned int ion_net_user_index_to_socket_index(ion_net_peer handle, unsigned int userIndex);

	bool ion_net_advertise_system(ion_net_peer handle, const char* host, unsigned short remotePort, const char* data, int dataLength,
								  unsigned connectionSocketIndex);

	void ion_net_set_time_synchronization(ion_net_peer handle, ion_net_remote_ref remote, ion_net_global_clock clock);

	void ion_net_send_ttl(ion_net_peer handle, const char* host, unsigned short remotePort, int ttl, unsigned connectionSocketIndex);

	/*
	 *  Statistics
	 */

	bool ion_net_statistics_for_address(ion_net_peer handle, ion_net_socket_address address, ion_net_statistics stats);

	bool ion_net_statistics_for_remote_id(ion_net_peer handle, ion_net_remote_id_t remote, ion_net_statistics stats);

	/*
	 * Debugging
	 */

	void ion_net_set_logging_level(int level);

	void ion_net_apply_network_simulator(ion_net_peer handle, ion_net_simulator_settings settings);

	bool ion_net_is_network_simulator_active();

#if defined(__cplusplus)
}
#endif
#endif
