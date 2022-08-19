/*
 * Sample TUF client. The code from this file will be part of aktalizr-nano
 * It still has some code from the original PoC code, separation between app 
 *  and aktalizr-nano is ongoing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include "mbedtls/pem.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_time.h"
#include "core_json.h"



#define CANCEL_BASE_SIZE 50
#define RECV_BUFFER_SIZE 1640
#define URL_BUFFER_SIZE 300
#define STATUS_BUFFER_SIZE 200
#define DOWNLOAD_HTTP_SIZE 200
#define DEPLOYMENT_BASE_SIZE 50
#define RESPONSE_BUFFER_SIZE 1500

#define AKNANO_JSON_BUFFER_SIZE 1024
#define NETWORK_TIMEOUT (2 * MSEC_PER_SEC)
#define AKNANO_RECV_TIMEOUT (300 * MSEC_PER_SEC)

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
// #define AKNANO_MAX_TAG_LENGTH 20


#define AKNANO_FLASH_OFF_DEV_CERTIFICATE 0
#define AKNANO_FLASH_OFF_DEV_KEY 2048
#define AKNANO_FLASH_OFF_DEV_UUID 4096
#define AKNANO_FLASH_OFF_DEV_SERIAL AKNANO_FLASH_OFF_DEV_UUID + 128

// #define AKNANO_FLASH_OFF_REGISTRATION_STATUS 8192
#define AKNANO_FLASH_OFF_STATE_BASE 8192

#define AKNANO_FLASH_OFF_LAST_APPLIED_VERSION AKNANO_FLASH_OFF_STATE_BASE + 0
#define AKNANO_FLASH_OFF_LAST_CONFIRMED_VERSION AKNANO_FLASH_OFF_STATE_BASE + sizeof(int)
#define AKNANO_FLASH_OFF_ONGOING_UPDATE_COR_ID AKNANO_FLASH_OFF_STATE_BASE + sizeof(int) * 2
#define AKNANO_FLASH_OFF_IS_DEVICE_REGISTERED AKNANO_FLASH_OFF_STATE_BASE + sizeof(int) * 2 + AKNANO_MAX_UPDATE_CORRELATION_ID_LENGTH


#define AKNANO_EVENT_SUCCESS_UNDEFINED 0
#define AKNANO_EVENT_SUCCESS_FALSE 1
#define AKNANO_EVENT_SUCCESS_TRUE 2

#define JSON_ARRAY_LIMIT_COUNT 10
// enum aknano_response {
//	 AKNANO_NETWORKING_ERROR,
//	 AKNANO_UNCONFIRMED_IMAGE,
//	 AKNANO_METADATA_ERROR,
//	 AKNANO_DOWNLOAD_ERROR,
//	 AKNANO_OK,
//	 AKNANO_UPDATE_INSTALLED,
//	 AKNANO_NO_UPDATE,
//	 AKNANO_CANCEL_UPDATE,
// };


struct aknano_target {
	char updatedAt[AKNANO_MAX_UPDATE_AT_LENGTH];
	char uri[AKNANO_MAX_URI_LENGTH];
	int32_t version;
};

// struct aknano_json_data {
//	 size_t offset;
//	 uint8_t data[AKNANO_JSON_BUFFER_SIZE];
//	 struct aknano_target selected_target;
// };

// struct aknano_download {
//	 int download_status;
//	 int download_progress;
//	 size_t downloaded_size;
//	 size_t http_content_size;
// };


/* Settings are kept between iterations */
struct aknano_settings {
	char tag[AKNANO_MAX_TAG_LENGTH];
	// char token[AKNANO_MAX_TOKEN_LENGTH];
	const char *hwid;
	// char device_certificate[AKNANO_CERT_BUF_SIZE];
	// char device_priv_key[AKNANO_CERT_BUF_SIZE];
	// char device_name[AKNANO_MAX_DEVICE_NAME_SIZE];
	// char uuid[AKNANO_MAX_UUID_LENGTH];
	// char serial[AKNANO_MAX_SERIAL_LENGTH];
	// char factory_name[AKNANO_MAX_FACTORY_NAME_LENGTH];
	// uint32_t running_version;
	// int last_applied_version;
	// int last_confirmed_version;
	// // char running_tag[AKNANO_MAX_TAG_LENGTH];
	// int polling_interval;
	// time_t boot_up_epoch;
	// char ongoing_update_correlation_id[AKNANO_MAX_UPDATE_CORRELATION_ID_LENGTH];
	// bool is_device_registered;
	// uint8_t image_position;
};

/* Context is not kept between iterations */
struct aknano_context {
	// int sock;
	// int32_t action_id;
	// uint8_t response_data[RESPONSE_BUFFER_SIZE];
	// struct aknano_json_data aknano_json_data;
	// int32_t json_action_id;
	// size_t url_buffer_size;
	// size_t status_buffer_size;
	// struct aknano_download dl;
	// // struct http_request http_req;
	// // struct flash_img_context flash_ctx;
	// uint8_t url_buffer[URL_BUFFER_SIZE];
	// uint8_t status_buffer[STATUS_BUFFER_SIZE];
	// uint8_t recv_buf_tcp[RECV_BUFFER_SIZE];
	// enum aknano_response code_status;

	struct aknano_settings *settings;
	struct aknano_target selected_target;
};

static struct aknano_context aknano_context;
static struct aknano_settings aknano_settings;

#define log_debug printf

int tuf_targets_processing_done(void *application_context)
{
	struct aknano_context *context = (struct aknano_context*)application_context;

	log_debug("tuf_targets_processing_done: highest version %d uri = %s\n", context->selected_target.version, context->selected_target.uri);
	return 0;
}

void *tuf_get_application_context()
{
	memset(&aknano_context, 0, sizeof(aknano_context));
	memset(&aknano_settings, 0, sizeof(aknano_settings));
	aknano_context.settings = &aknano_settings;

	aknano_context.settings->hwid = "MIMXRT1170-EVK";
	strcpy(aknano_context.settings->tag, "devel");
	return &aknano_context;
}

/*
 * TODO: Is there an actual advantage on calling this external function for each target? Or should all targets be parsed at once?
 * Calling the function for each individual target may be more appropriate when processing data as stream, which we do not do yet, and may never do
 */
int tuf_parse_single_target(const char *target_key, size_t targte_key_len, const char *data, size_t len, void *application_context)
{
	struct aknano_context *aknano_context = (struct aknano_context *)application_context;
#if 0
	JSONStatus_t result;
	char *outValue, *outSubValue;//, *uri;
	size_t outValueLength, outSubValueLen;
	// size_t start = 0, next = 0;
	// JSONPair_t pair;
	int ret;
	struct aknano_context *context = (struct aknano_context*)application_context;

	result = JSON_Search(data, len, "custom/version", strlen("custom/version"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("tuf_parse_single_target: \"custom/version\" not found\n");
		return 0;
	}

	int version;
	sscanf(outValue, "%d", &version);
	if (version > context->selected_target.version)
		context->selected_target.version = version;

	return 0;
#endif
	bool foundMatch = false;
	char *outValue, *outSubValue;//, *uri;
	size_t outValueLength, outSubValueLength;
	int i;
	uint32_t version;

	// LogInfo(("handle_json_data: Parsing target data with len=%d", len));
	JSONStatus_t result = JSON_Validate(data, len );
	if( result != JSONSuccess )
	{
		log_debug("handle_json_data: Got invalid targets JSON: %s\n", data);
		return -1;
	}


	foundMatch = false;
	result = JSON_Search(data, len, "custom/version", strlen("custom/version"), &outValue, &outValueLength);
	if (result == JSONSuccess) {
		// LogInfo(("handle_json_data: custom.version=%.*s", outValueLength, outValue));
		sscanf(outValue, "%lu", &version);
		if (version <= aknano_context->selected_target.version) {
			return 0;
		}
	} else {
		log_debug("handle_json_data: custom/version not found\n");
		return -2;
	}

	result = JSON_Search(data, len, "custom/hardwareIds", strlen("custom/hardwareIds"), &outValue, &outValueLength);
	if (result == JSONSuccess) {
		// LogInfo(("handle_json_data: custom.hardwareIds=%.*s", outValueLength, outValue));

		for (i=0; i<JSON_ARRAY_LIMIT_COUNT; i++) {
			char s[10];
			snprintf(s, sizeof(s), "[%d]", i);
			if (JSON_Search(outValue, outValueLength, s, strlen(s), &outSubValue, &outSubValueLength) != JSONSuccess)
					break;
			if (strncmp(outSubValue, aknano_context->settings->hwid, outSubValueLength) == 0) {
				// LogInfo(("Found matching hardwareId" ));
				foundMatch = true;
			}
		}
	} else {
		log_debug("handle_json_data: custom/hardwareIds not found\n");
		return -2;
	}
	if (!foundMatch) {
		// LogInfo(("Matching hardwareId not found (%s)", CONFIG_BOARD));
		return 0;
	}

	foundMatch = false;
	result = JSON_Search((char*)data, len, "custom/tags", strlen("custom/tags"), &outValue, &outValueLength);
	if (result == JSONSuccess) {
		// LogInfo(("handle_json_data: custom.tags=%.*s", outValueLength, outValue));

		for (i=0; i<JSON_ARRAY_LIMIT_COUNT; i++) {
			char s[10];
			snprintf(s, sizeof(s), "[%d]", i);
			if (JSON_Search(outValue, outValueLength, s, strlen(s), &outSubValue, &outSubValueLength) != JSONSuccess)
				break;
			if (strncmp(outSubValue, aknano_context->settings->tag, outSubValueLength) == 0) {
				// LogInfo(("Found matching tag" ));
				foundMatch = true;
			}
		}
	} else {
		log_debug("handle_json_data: custom/tags not found\n");
		return -2;
	}
	if (!foundMatch) {
		// LogInfo(("Matching tag not found (%s)", aknano_context->settings->tag));
		return 0;
	}

	// result = JSON_Search(data, len, "custom.updatedAt", strlen("custom.updatedAt"), &outValue, &outValueLength);
	// if (result == JSONSuccess) {
	//		 LogInfo(("handle_json_data: custom.updatedAt=%.*s", outValueLength, outValue));
	// } else {
	//		 LogWarn(("handle_json_data: custom.updatedAt not found"));
	//		 return -2;
	// }

	result = JSON_Search(data, len, "custom/uri", strlen("custom/uri"), &outValue, &outValueLength);
	if (result == JSONSuccess) {
		// LogInfo(("handle_json_data: custom.uri=%.*s", outValueLength, outValue));
	} else {
		log_debug("handle_json_data: custom/uri not found\n");
		return -2;
	}

	// LogInfo(("Updating highest version to %u %.*s", version, outValueLength, outValue));

	aknano_context->selected_target.version = version;
	strncpy(aknano_context->selected_target.uri, outValue, outValueLength);
	return 0;
}
