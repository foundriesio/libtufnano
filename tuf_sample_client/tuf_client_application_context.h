#ifndef __TUF_CLIENT_APPLICATION_CONTEXT_H__
#define __TUF_CLIENT_APPLICATION_CONTEXT_H__

#include <stdint.h>
#include <time.h>
// #include <mbedtls/sha256.h>

#define CONFIG_BOARD BOARD_NAME

#define AKNANO_SLEEP_LENGTH 8

#define AKNANO_SHA256_LEN 32

#define CANCEL_BASE_SIZE 50
#define RECV_BUFFER_SIZE 1640
#define URL_BUFFER_SIZE 300
#define STATUS_BUFFER_SIZE 200
#define RESPONSE_BUFFER_SIZE 1500

#define AKNANO_MAX_TAG_LENGTH 32
#define AKNANO_MAX_UPDATE_AT_LENGTH 32
#define AKNANO_MAX_URI_LENGTH 120

#define AKNANO_MAX_TOKEN_LENGTH 100
#define AKNANO_CERT_BUF_SIZE 1024
#define AKNANO_MAX_DEVICE_NAME_SIZE 100
#define AKNANO_MAX_UUID_LENGTH 100
#define AKNANO_MAX_SERIAL_LENGTH 100
#define AKNANO_MAX_FACTORY_NAME_LENGTH 100
#define AKNANO_MAX_UPDATE_CORRELATION_ID_LENGTH 100

#define TUF_TEST_CLIENT_MAX_PATH_LENGTH 200

struct aknano_target {
	char	updatedAt[AKNANO_MAX_UPDATE_AT_LENGTH];
	char	uri[AKNANO_MAX_URI_LENGTH];
	size_t	expected_size;
	int32_t version;
	uint8_t expected_hash[AKNANO_SHA256_LEN];
};

struct aknano_download {
	int	download_status;
	int	download_progress;
	size_t	downloaded_size;
	size_t	http_content_size;
};

/* Settings are kept between iterations */
struct aknano_settings {
	char		tag[AKNANO_MAX_TAG_LENGTH];
	char		token[AKNANO_MAX_TOKEN_LENGTH];
	char		device_certificate[AKNANO_CERT_BUF_SIZE];
	char		device_priv_key[AKNANO_CERT_BUF_SIZE];
	char		device_name[AKNANO_MAX_DEVICE_NAME_SIZE];
	char		uuid[AKNANO_MAX_UUID_LENGTH];
	char		serial[AKNANO_MAX_SERIAL_LENGTH];
	char		factory_name[AKNANO_MAX_FACTORY_NAME_LENGTH];
	uint32_t	running_version;
	int		last_applied_version;
	int		last_confirmed_version;
	// char running_tag[AKNANO_MAX_TAG_LENGTH];
	int		polling_interval;
	time_t		boot_up_epoch;
	char		ongoing_update_correlation_id[AKNANO_MAX_UPDATE_CORRELATION_ID_LENGTH];
	bool		is_device_registered;
	uint8_t		image_position;
	const char *	hwid;
};

struct aknano_network_context;

/* Context is not kept between iterations */
struct aknano_context {
	int				sock;
	int32_t				action_id;
	uint8_t				response_data[RESPONSE_BUFFER_SIZE];
	// struct aknano_json_data aknano_json_data;
	int32_t				json_action_id;
	size_t				url_buffer_size;
	size_t				status_buffer_size;
	struct aknano_download		dl;
	// struct http_request http_req;
	// struct flash_img_context flash_ctx;
	uint8_t				url_buffer[URL_BUFFER_SIZE];
	uint8_t				status_buffer[STATUS_BUFFER_SIZE];
	uint8_t				recv_buf_tcp[RECV_BUFFER_SIZE];

	int				json_pasring_bracket_level;
	struct aknano_settings *	settings; /* TODO: may not always be set yet */

	struct aknano_target		selected_target;

	/* Connection to the device gateway */
	struct aknano_network_context * dg_network_context;

	// mbedtls_sha256_context sha256_context;
};

struct tuf_client_test_context {
	char			root_provisioning_path[TUF_TEST_CLIENT_MAX_PATH_LENGTH];
	char			remote_files_path[TUF_TEST_CLIENT_MAX_PATH_LENGTH];
	char			local_files_path[TUF_TEST_CLIENT_MAX_PATH_LENGTH];

	struct aknano_context * aknano_context;
};

#endif
