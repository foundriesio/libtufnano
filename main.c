#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "mbedtls/md.h"
#include "mbedtls/pem.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_time.h"
#include "core_json.h"
#include "unity.h"
#include "unity_fixture.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define TUF_FILES_PATH "tests/sample_jsons/rsa/"

#define log_debug printf
#define log_info printf
#define log_error printf

/* Fields size limits */
#define MAX_FILE_PATH_LEN 100
#define DATA_BUFFER_LEN 10 * 1024
#define TUF_SIGNATURES_MAX_COUNT 10
#define TUF_SIGNATURE_MAX_LEN 512
#define TUF_SIGNATURE_METHOD_NAME_MAX_LEN 20
#define TUF_KEY_ID_MAX_LEN 65
#define TUF_MAX_KEY_COUNT 10
#define TUF_KEYIDS_PER_ROLE_MAX_COUNT 5

/* TODO: adjust proper size limits on fields */
/* TODO: save space in memory by keeping decoded bytes instead of base64 string */
#define TUF_BIG_CHUNK 1024

/* Error codes */
/* TODO: Add error codes for all relevant situations */
#define TUF_SUCCESS 0
#define TUF_ERROR_ROOT_ROLE_NOT_LOADED -809
#define TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED -810
#define TUF_ERROR_SNAPSHOT_ROLE_NOT_LOADED -811
#define TUF_INVALID_HASH -900
#define TUF_INVALID_HASH_LENGTH -901
#define TUF_HASH_VERIFY_ERROR -902
#define TUF_LENGTH_VERIFY_ERROR -903
#define TUF_INVALID_DATE_TIME -904
#define TUF_ERROR_EXPIRED_METADATA -905
#define TUF_ERROR_BAD_VERSION_NUMBER -905

/*
 * TUF metadata has '.' in field names.
 * We change the key separator for coreJSON to '/' to avoid ambiguity
 * This is currently being done in the Makefile
 *  #define JSON_QUERY_KEY_SEPARATOR '/'
 */

/* Data types */

enum tuf_role {
	ROLE_ROOT = 0,
	ROLE_TIMESTAMP,
	ROLE_SNAPSHOT,
	ROLE_TARGETS,
	TUF_ROLES_COUNT
};

struct tuf_signature {
	char keyid[TUF_KEY_ID_MAX_LEN];
	char method[TUF_SIGNATURE_METHOD_NAME_MAX_LEN];
	unsigned char sig[TUF_SIGNATURE_MAX_LEN];
	bool set;
};

struct tuf_key {
	char id[TUF_BIG_CHUNK];
	char keyval[TUF_BIG_CHUNK];
	char keytype[TUF_BIG_CHUNK];
};

struct tuf_metadata {
	int version;
	char expires[21];
	time_t expires_epoch;
};

struct tuf_role_file {
	enum tuf_role role;
	size_t length;
	unsigned char hash_sha256[65];
	int version;
};

struct tuf_timestamp {
	struct tuf_role_file snapshot_file;
	struct tuf_metadata base;
	bool loaded;
};

struct tuf_snapshot {
	struct tuf_role_file root_file;
	struct tuf_role_file targets_file;
	struct tuf_metadata base;
	bool loaded;
};

struct tuf_target {
	int version;
	char *file_name;
	unsigned char hash_sha256[65];
};

struct tuf_targets {
	struct tuf_target selected_target;
	bool loaded;
};


struct tuf_root_role {
	char keyids[TUF_KEYIDS_PER_ROLE_MAX_COUNT][TUF_KEY_ID_MAX_LEN];
	int threshold;
};

struct tuf_root {
	struct tuf_key keys[TUF_MAX_KEY_COUNT];
	size_t keys_count;
	struct tuf_root_role roles[TUF_ROLES_COUNT];
	struct tuf_metadata base;
	bool loaded;
};

/* Trusted set */
static struct tuf_timestamp current_timestamp;
static struct tuf_targets current_targets;
static struct tuf_snapshot current_snapshot;
static struct tuf_root current_root;

unsigned char data_buffer[DATA_BUFFER_LEN];

time_t datetime_string_to_epoch(const char *s, time_t *epoch)
{
	struct tm tm;
	char *ret;

	/* 2022-09-09T18:13:01Z */
	ret = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
	if (ret == NULL) {
		log_error("Invalid datetime string %s\n", s);
		return TUF_INVALID_DATE_TIME;
	}
	tm.tm_isdst = 0; /* ignore DST */
	*epoch = mktime(&tm);
	if (*epoch < 0)
		return TUF_INVALID_DATE_TIME;
	*epoch += tm.tm_gmtoff; /* compensate locale */
	return TUF_SUCCESS;
}

time_t get_current_gmt_time()
{
	time_t current_time;
	struct tm *tm;

	time(&current_time);
	tm = gmtime(&current_time);
	tm->tm_isdst = 0; /* ignore DST */
	current_time = mktime(tm);
	current_time += tm->tm_gmtoff; /* compensate locale */
	return current_time;
}

void replace_escape_chars_from_b64_string(unsigned char* s)
{
	int i;
	char *p = s;
	bool replace_next = false;
	while (*p) {
		if (replace_next) {
			*p = '\n';
			replace_next = false;
		} else if (*p == '\\') {
			*p = '\n';
			replace_next = true;
		}
		p++;
	}
}

size_t read_file(const char* base_name, char* output_buffer, size_t limit)
{
	char file_path[MAX_FILE_PATH_LEN];
	size_t ret;

	snprintf(file_path, MAX_FILE_PATH_LEN, "%s/%s", TUF_FILES_PATH, base_name);
	FILE *f = fopen(file_path, "r");
	if (f == NULL) {
		log_error("Unable to open file %s: %s - (%d)", file_path, strerror(errno), errno);
		return -1;
	}
	ret = fread(output_buffer, 1, limit, f);
	fclose(f);
	return ret;
}


enum tuf_role role_string_to_enum(const char *role_name, size_t role_name_len)
{
	if (!strncmp(role_name, "snapshot", role_name_len))
		return ROLE_SNAPSHOT;
	if (!strncmp(role_name, "timestamp", role_name_len))
		return ROLE_TIMESTAMP;
	if (!strncmp(role_name, "targets", role_name_len))
		return ROLE_TARGETS;
	if (!strncmp(role_name, "root", role_name_len))
		return ROLE_ROOT;
	return TUF_ROLES_COUNT;
}


int parse_base_metadata(char *data, int len, struct tuf_metadata *base)
{
	char *out_value;
	size_t out_value_len;
	JSONStatus_t result;
	int ret;

	/* Please validate before */
	result = JSON_Search(data, len, "version", strlen("version"), &out_value, &out_value_len);
	if (result != JSONSuccess) {
		log_error("parse_base_metadata: \"version\" not found\n");
		return -2;
	}
	sscanf(out_value, "%d", &base->version);
	result = JSON_Search(data, len, "expires", strlen("expires"), &out_value, &out_value_len);
	if (result != JSONSuccess) {
		log_error("parse_base_metadata: \"expires\" not found\n");
		return -2;
	}
	strncpy(base->expires, out_value, out_value_len);
	ret = datetime_string_to_epoch(base->expires, &base->expires_epoch);
	// log_debug("Converting %.*s => %d\n", out_value_len, out_value, base->expires_epoch);
	if (ret < 0)
		return ret;

	return TUF_SUCCESS;
}

int parse_root_signed_metadata(char *data, int len, struct tuf_root *target)
{
	JSONStatus_t result;
	JSONStatus_t result_internal;
	size_t value_length_internal;
	size_t value_length_internal_2;
	char *outValue, *outSubValue;//, *uri;
	size_t outValueLength;
	size_t start = 0, next = 0;
	size_t start_internal = 0, next_internal = 0;
	JSONPair_t pair, pair_internal;
	int key_index = 0;
	int role_index = 0;
	char *out_value_internal;
	char *out_value_internal_2;

	result = JSON_Validate(data, len);
	if( result != JSONSuccess )
	{
		log_error("split_metadata: Got invalid JSON: %s\n", data);
		return -10;
	}

	result = JSON_Search(data, len, "keys", strlen("keys"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_root_signed_metadata: \"keys\" not found\n");
		return -2;
	}

	/* For each key */
	while (result == JSONSuccess) {
		if (key_index >= TUF_MAX_KEY_COUNT) {
			log_error("More keys than allowed (allowed=%d)\n", TUF_MAX_KEY_COUNT);
			return -3;
		}

		struct tuf_key *current_key = &target->keys[key_index];
		// memset(current_signature, 0, sizeof(*current_signature));
		result = JSON_Iterate(outValue, outValueLength, &start, &next, &pair);
		if (result == JSONSuccess) {
			// log_debug("pair.key=%.*s, pair.Value=%.*s\n", pair.keyLength, pair.key, pair.valueLength, pair.value);

			strncpy(current_key->id, pair.key, pair.keyLength);
			result_internal = JSON_Search(pair.value, pair.valueLength, "keytype", strlen("keytype"), &out_value_internal, &value_length_internal);
			if (result_internal != JSONSuccess) {
				log_error("'keytype' field not found. result_internal=%d\n", result_internal);
				return -2;
			}
			strncpy(current_key->keytype, out_value_internal, value_length_internal);

			result_internal = JSON_Search(pair.value, pair.valueLength, "keyval", strlen("keyval"), &out_value_internal, &value_length_internal);
			if (result_internal != JSONSuccess) {
				log_error("'keyval' field not found. result_internal=%d\n", result_internal);
				return -2;
			}

			result_internal = JSON_Search(out_value_internal, value_length_internal, "public", strlen("public"), &out_value_internal_2, &value_length_internal_2);
			if (result_internal != JSONSuccess) {
				log_error("'keyval' field not found. result_internal=%d\n", result_internal);
				return -2;
			}
			strncpy(current_key->keyval, out_value_internal_2, value_length_internal_2);
			// replace_escape_chars_from_b64_string(current_key->keyval);
			key_index++;
		}
		target->keys_count = key_index;
	}


	result = JSON_Search(data, len, "roles", strlen("roles"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_root_signed_metadata: \"roles\" not found\n");
		return -2;
	}

	start = 0;
	next = 0;
	/* For each role */

	// log_debug("%.*s\n", outValueLength, outValue);
	while (result == JSONSuccess) {
		result = JSON_Iterate(outValue, outValueLength, &start, &next, &pair);
		if (result == JSONSuccess) {
			enum tuf_role role = role_string_to_enum(pair.key, pair.keyLength);
			if (role == TUF_ROLES_COUNT) {
				log_error("Invalid role name \"%.*s\"\n", (int)pair.keyLength, pair.key);
				return -2;
			}

			result_internal = JSON_Search(pair.value, pair.valueLength, "threshold", strlen("threshold"), &out_value_internal, &value_length_internal);
			if (result_internal != JSONSuccess) {
				log_error("'threshold' field not found. result_internal=%d\n", result_internal);
				return -2;
			}
			sscanf(out_value_internal, "%d", &target->roles[role].threshold);

			result_internal = JSON_Search(pair.value, pair.valueLength, "keyids", strlen("keyids"), &out_value_internal, &value_length_internal);
			if (result_internal != JSONSuccess) {
				log_error("'keyids' field not found. result_internal=%d\n", result_internal);
				return -2;
			}

			key_index = 0;
			start_internal = 0;
			next_internal = 0;
			while (result_internal == JSONSuccess) {
				result_internal = JSON_Iterate(out_value_internal, value_length_internal, &start_internal, &next_internal, &pair_internal);
				strncpy(target->roles[role].keyids[key_index], pair_internal.value, pair_internal.valueLength);
				key_index++;
			}
		}
	}
	target->loaded = true;
	return parse_base_metadata(data, len, &target->base);
}

int split_metadata(const char *data, int len, struct tuf_signature *signatures, int signatures_max_count, char **signed_value, int *signed_value_len)
{
	JSONStatus_t result;
	JSONStatus_t result_internal;
	size_t value_length_internal;
	char *outValue, *outSubValue;//, *uri;
	size_t outValueLength;
	size_t start = 0, next = 0;
	JSONPair_t pair;
	int signature_index = 0;
	char *out_value_internal;

	result = JSON_Validate(data, len );
	if( result != JSONSuccess )
	{
		log_error("split_metadata: Got invalid JSON: %s\n", data);
		return -10;
	}
	// log_error("JSON is valid\n");

	bool foundMatch = false;
	result = JSON_Search(data, len, "signatures", strlen("signatures"), &outValue, &outValueLength);
	if (result == JSONSuccess) {
		// log_debug("outValue=\n%.*s\n", (int)outValueLength, outValue);
		while (result == JSONSuccess) {
			if (signature_index >= signatures_max_count) {
				log_error("More signatures than allowed (allowed=%d)\n", signatures_max_count);
				return -3;
			}

			struct tuf_signature *current_signature = &signatures[signature_index];
			memset(current_signature, 0, sizeof(*current_signature));
			result = JSON_Iterate(outValue, outValueLength, &start, &next, &pair);
			if (result == JSONSuccess) {
				// log_debug("start=%ld, next=%d, pair.Value=%.*s\n", start, next, pair.valueLength, pair.value);
				result_internal = JSON_Search(pair.value, pair.valueLength, "keyid", strlen("keyid"), &out_value_internal, &value_length_internal);
				if (result_internal != JSONSuccess) {
					log_error("'keyid' field not found. result_internal=%d\n", result_internal);
					return -2;
				} else {
					strncpy(current_signature->keyid, out_value_internal, value_length_internal);
				}
				// log_debug("keyid=%s\n", current_signature->keyid);
				result_internal = JSON_Search(pair.value, pair.valueLength, "method", strlen("method"), &out_value_internal, &value_length_internal);
				if (result_internal != JSONSuccess) {
					log_error("'method' field not found\n");
					return -2;
				} else {
					if (strncmp(out_value_internal, "rsassa-pss-sha256", value_length_internal) != 0) {
						log_error("unsupported signature method \"%.*s\". Skipping\n", (int)value_length_internal, out_value_internal);
						continue;
					}
					strncpy(current_signature->method, out_value_internal, value_length_internal);
				}

				result_internal = JSON_Search(pair.value, pair.valueLength, "sig", strlen("sig"), &out_value_internal, &value_length_internal);
				if (result_internal != JSONSuccess) {
					log_error("'sig' field not found\n");
					return -2;
				} else {
					strncpy(current_signature->sig, out_value_internal, value_length_internal);
				}
				current_signature->set = true;
				signature_index++;
			}
		}
	} else {
		log_error("handle_json_data: signatures not found\n");
		return -2;
	}

	result = JSON_Search(data, len, "signed", strlen("signed"), &outValue, &outValueLength);
	if (result == JSONSuccess) {
		*signed_value = outValue;
		*signed_value_len = outValueLength;
	} else {
		log_error("handle_json_data: signed not found");
		return -2;
	}

	// log_debug("\nsplit_metadata, signed_value_len=%d   value=%.*s\n", *signed_value_len, *signed_value_len, *signed_value);

	return 0;
}

//     def _load_root(self) -> None:
//         """Load remote root metadata.

//         Sequentially load and persist on local disk every newer root metadata
//         version available on the remote.
//         """

//         # Update the root role
//         lower_bound = self._trusted_set.root.signed.version + 1
//         upper_bound = lower_bound + self.config.max_root_rotations

//         for next_version in range(lower_bound, upper_bound):
//             try:
//                 data = self._download_metadata(
//                     Root.type,
//                     self.config.root_max_length,
//                     next_version,
//                 )
//                 self._trusted_set.update_root(data)
//                 self._persist_metadata(Root.type, data)

//             except exceptions.DownloadHTTPError as exception:
//                 if exception.status_code not in {403, 404}:
//                     raise
//                 # 404/403 means current root is newest available
//                 break

//     # Methods for updating metadata
//     def update_root(self, data: bytes) -> Metadata[Root]:
//         """Verifies and loads ``data`` as new root metadata.

//         Note that an expired intermediate root is considered valid: expiry is
//         only checked for the final root in ``update_timestamp()``.

//         Args:
//             data: Unverified new root metadata as bytes

//         Raises:
//             RuntimeError: This function is called after updating timestamp.
//             RepositoryError: Metadata failed to load or verify. The actual
//                 error type and content will contain more details.

//         Returns:
//             Deserialized and verified root ``Metadata`` object
//         """
//         if self.timestamp is not None:
//             raise RuntimeError("Cannot update root after timestamp")
//         logger.debug("Updating root")

//         new_root = Metadata[Root].from_bytes(data)

//         if new_root.signed.type != Root.type:
//             raise exceptions.RepositoryError(
//                 f"Expected 'root', got '{new_root.signed.type}'"
//             )

//         # Verify that new root is signed by trusted root
//         self.root.verify_delegate(Root.type, new_root)

//         if new_root.signed.version != self.root.signed.version + 1:
//             raise exceptions.BadVersionNumberError(
//                 f"Expected root version {self.root.signed.version + 1}"
//                 f" instead got version {new_root.signed.version}"
//             )

//         # Verify that new root is signed by itself
//         new_root.verify_delegate(Root.type, new_root)

//         self._trusted_set[Root.type] = new_root
//         logger.info("Updated root v%d", new_root.signed.version)

//         return new_root


int fetch_file(const char *file_base_name, unsigned char *target_buffer, size_t target_buffer_len, size_t *file_size)
{
	*file_size = read_file(file_base_name, target_buffer, target_buffer_len);
	if (file_size < 0)
		return -1;

	return 0;
}
static void print_hex(const char *title, const unsigned char buf[], size_t len)
{
	log_debug("%s: ", title);

	for (size_t i = 0; i < len; i++)
		log_debug("%02x", buf[i]);

	log_debug("\r\n");
}

static void hextobin(const char * str, uint8_t * bytes, size_t blen)
{
	uint8_t pos, idx0, idx1;
	/* mapping of ASCII characters to hex values */
	const uint8_t hashmap[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
	};

	memset(bytes, 0, blen);
	for (pos = 0; ((pos < (blen*2)) && (pos < strlen(str))); pos += 2)
	{
		idx0 = ((uint8_t)str[pos+0] & 0x1F) ^ 0x10;
		idx1 = ((uint8_t)str[pos+1] & 0x1F) ^ 0x10;
		bytes[pos/2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	};
}

int verify_data_hash_sha256(char* data, int data_len, unsigned char *hash_b16, size_t hash_b16_len)
{
	unsigned char hash_output[32]; /* SHA-256 outputs 32 bytes */
	unsigned char decoded_hash_input[100];
	size_t decoded_len;

	if (hash_b16_len != 64) {
		log_error("Invalid hash length %ld - %s\n", hash_b16_len, hash_b16);
		return TUF_INVALID_HASH_LENGTH;
	}


	/* 0 here means use the full SHA-256, not the SHA-224 variant */
	mbedtls_sha256(data, data_len, hash_output, 0);

	hextobin(hash_b16, decoded_hash_input, hash_b16_len);
	if (memcmp(decoded_hash_input, hash_output, sizeof(hash_output))) {
		log_debug("Hash Verify Error\n");
		print_hex("Expected", decoded_hash_input, 32);
		print_hex("Got", hash_output, 32);
		return TUF_HASH_VERIFY_ERROR;
	}

	return TUF_SUCCESS;
}

int verify_signature(const char* data, int data_len, unsigned char* signature_bytes, int signature_bytes_len, struct tuf_key *key)
{

	int ret = 1;
	int exit_code = -1;
	size_t i;
	mbedtls_pk_context pk;
	unsigned char hash[32];
	unsigned char *key_pem = key->keyval;

	mbedtls_pk_init( &pk );

	// log_debug("\n\nTrying to verify signature\n%.*s\nwith key\n%s\nfor data\n%.*s\n\n", signature_bytes_len, signature_bytes, key_pem, data_len, data);

	unsigned char cleaned_up_key_b64[TUF_BIG_CHUNK];
	memset(cleaned_up_key_b64, 0, sizeof(cleaned_up_key_b64));
	strcpy(cleaned_up_key_b64, key_pem);
	replace_escape_chars_from_b64_string(cleaned_up_key_b64);

	if ((ret = mbedtls_pk_parse_public_key(&pk, cleaned_up_key_b64, strlen(cleaned_up_key_b64) + 1) ) != 0) {
		log_error("verify_signature: failed. Could not read key. mbedtls_pk_parse_public_keyfile returned %d\n", ret);
		log_error("key: %s\n", cleaned_up_key_b64);
		goto exit;
	}

	if (!mbedtls_pk_can_do( &pk, MBEDTLS_PK_RSA ))	{
		log_error("verify_signature: failed  ! Key is not an RSA key\n");
		goto exit;
	}

	if((ret = mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk),
						MBEDTLS_RSA_PKCS_V21,
						MBEDTLS_MD_SHA256)) != 0) {
		log_error("verify_signature: failed  ! Invalid padding\n");
		goto exit;
	}

	/*
	* Compute the SHA-256 hash of the input file and
	* verify the signature
	*/
	char error_buf[900];

	if ((ret = mbedtls_md(
			mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
			data, data_len, hash ) ) != 0) {
		log_error("verify_signature: failed ! Could not open or read\n");
		goto exit;
	}


	char decoded_bytes[9000];
	size_t decoded_len;

	int ret64 = mbedtls_base64_decode(decoded_bytes, 9000, &decoded_len, signature_bytes, signature_bytes_len);
	mbedtls_strerror(ret64, error_buf, sizeof(error_buf));
	// log_debug("b64 ret = %d (%s) decoded_len=%d\n", ret64, error_buf, decoded_len);

	if ((ret = mbedtls_pk_verify( &pk, MBEDTLS_MD_SHA256, hash, 0,
				decoded_bytes, decoded_len)) != 0) {
		log_error("verify_signature: failed  ! mbedtls_pk_verify returned %d\n", ret );
		exit_code = ret;
		goto exit;
	}

	// log_error("\n  . OK (the signature is valid)\\n");

	exit_code = 0;

exit:
	mbedtls_pk_free( &pk );

	return( exit_code );
}


int get_key_by_id(struct tuf_root *root, const char* key_id, struct tuf_key **key)
{
	int i;

	for (i=0; i<TUF_MAX_KEY_COUNT; i++) {
		if (!strcmp(root->keys[i].id, key_id)) {
			*key = &root->keys[i];
			return 0;
		}
	}
	return -404;
}

// int get_key_by_id_old(struct tuf_root *root, const char* key_id, char **key)
// {
// 	int i;

// 	for (i=0; i<TUF_MAX_KEY_COUNT; i++) {
// 		if (!strcmp(root->keys[i].id, key_id)) {
// 			*key = root->keys[i].keyval;
// 			return 0;
// 		}
// 	}
// 	return -404;
// }

int get_public_key_for_role(struct tuf_root *root, enum tuf_role role, int key_index, struct tuf_key **key)
{
	if (role >= TUF_ROLES_COUNT)
		return -EINVAL;

	if (root == NULL)
		return -EINVAL;

	char *keyid = root->roles[role].keyids[key_index];
	return get_key_by_id(root, keyid, key);
}


int get_public_key_by_id_and_role(struct tuf_root *root, enum tuf_role role, const char* key_id, struct tuf_key **key)
{
	// log_debug("get_public_key_by_id_and_role role=%d key_id=%s\n", role, key_id);

	if (role >= TUF_ROLES_COUNT)
		return -EINVAL;

	if (root == NULL)
		return -EINVAL;

	for (int key_index=0; key_index< TUF_KEYIDS_PER_ROLE_MAX_COUNT; key_index++) {
		char *role_key_id = root->roles[role].keyids[key_index];
		// log_debug("Comparing\n'%s'\n'%s'\n", role_key_id, key_id);
		if (!strcmp(role_key_id, key_id)) {
			return get_key_by_id(root, key_id, key);
		}
	}
	// log_error("key_id %s for role %d not found\n", key_id, role);

	return -405;
}

int verify_data_signature_for_role(const char *signed_value, size_t signed_value_len, struct tuf_signature *signatures, enum tuf_role role, struct tuf_root *root)
{
	int ret = -1;
	int signature_index;
	// char *signed_value;
	// int signed_value_len;
	// struct tuf_signature signatures[TUF_SIGNATURES_MAX_COUNT];

	// ret = split_metadata(data, data_len, signatures, TUF_SIGNATURES_MAX_COUNT, &signed_value, &signed_value_len);
	// if (ret < 0)
	// 	return ret;

	for (signature_index=0; signature_index < TUF_SIGNATURES_MAX_COUNT; signature_index++)
	{
		// log_debug("verify_data_signature_for_role role=%d, signature_index=%d\n", role, signature_index);
		if (!signatures[signature_index].set)
			break;

		struct tuf_key* key;
		ret = get_public_key_by_id_and_role(root, role, signatures[signature_index].keyid, &key);
		if (ret != 0) {
			// log_debug("get_public_key_by_id_and_role: not found. verify_data_signature_for_role role=%d, signature_index=%d\n", role, signature_index);
			continue;
		}
		ret = verify_signature(signed_value, signed_value_len, signatures[signature_index].sig, strlen(signatures[signature_index].sig), key);

		if (!ret) {
			/* Found valid signature */
			// log_debug("found valid signature. verify_data_signature_for_role role=%d, signature_index=%d\n", role, signature_index);
			return ret;
		}
	}
	/* No valid signature found */
	return ret;
}


int get_expected_sha256_and_length_for_role(enum tuf_role role, unsigned char **sha256, size_t *length)
{
	if (role == ROLE_SNAPSHOT) {
		if (!current_timestamp.loaded)
			return TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED;
		*sha256 = current_timestamp.snapshot_file.hash_sha256;
		*length = current_timestamp.snapshot_file.length;
		return TUF_SUCCESS;
	} else if (role == ROLE_TARGETS) {
		if (!current_timestamp.loaded)
			return TUF_ERROR_SNAPSHOT_ROLE_NOT_LOADED;
		*sha256 = current_timestamp.snapshot_file.hash_sha256;
		*length = current_timestamp.snapshot_file.length;
		return TUF_SUCCESS;
	}
	return -EINVAL;
}

int verify_length_and_hashes(const char *data, size_t len, enum tuf_role role)
{
	int ret;
	unsigned char *expected_sha256;
	size_t expected_length;

	ret = get_expected_sha256_and_length_for_role(role, &expected_sha256, &expected_length);
	if (ret != TUF_SUCCESS)
		return ret;
	
	if (len != expected_length)
		return TUF_LENGTH_VERIFY_ERROR;

	ret = verify_data_hash_sha256(data, len, expected_sha256, strlen(expected_sha256));
	if (ret != TUF_SUCCESS)
		return ret;

	return TUF_SUCCESS;
}

int fetch_role_and_check_signature(const unsigned char *file_base_name, enum tuf_role role, struct tuf_signature *signatures, char **signed_value, int *signed_value_len, bool check_signature_and_hashes)
{
	int ret = -1;
	size_t file_size;

	ret = fetch_file(file_base_name, data_buffer, DATA_BUFFER_LEN, &file_size);
	if (ret != 0)
		return ret;

	ret = split_metadata(data_buffer, file_size, signatures, TUF_SIGNATURES_MAX_COUNT, signed_value, signed_value_len);
	if (ret < 0)
		return ret;

	if (role != ROLE_ROOT && !current_root.loaded)
		return TUF_ERROR_ROOT_ROLE_NOT_LOADED;

	if (!check_signature_and_hashes)
		return TUF_SUCCESS;

	if (role == ROLE_SNAPSHOT || role == ROLE_TARGETS) {
		ret = verify_length_and_hashes(data_buffer, file_size, role);
		if (ret != TUF_SUCCESS)
			return ret;
	}

	if (current_root.loaded) {
		// check signature using current root key
		ret = verify_data_signature_for_role(*signed_value, *signed_value_len, signatures, role, &current_root);
		// log_debug("Verifying against current root ret = %d\n", ret);
		if (ret < 0)
			return ret;
	}
	return TUF_SUCCESS;
}


int parse_root(const unsigned char *file_base_name, bool check_signature)
{
	// TODO: make sure check_signature is false only during unit testing

	// size_t file_size;
	int ret = -1;
	int signature_index;
	char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_MAX_COUNT];
	struct tuf_root new_root;

	memset(&new_root, 0, sizeof(new_root));

	ret = fetch_role_and_check_signature(file_base_name, ROLE_ROOT, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	// Parsing ROOT

	ret = parse_root_signed_metadata(signed_value, signed_value_len, &new_root);
	if (ret < 0)
		return ret;

	if (check_signature) {
		// check signature using current new root key
		ret = verify_data_signature_for_role(signed_value, signed_value_len, signatures, ROLE_ROOT, &new_root);
		// log_debug("Verifying against new root ret = %d\n", ret);
		if (ret < 0)
			return ret;
	}

	memcpy(&current_root, &new_root, sizeof(current_root));

	return ret;
}


JSONStatus_t parse_tuf_file_info(char *data, size_t len, struct tuf_role_file *target)
{
	JSONStatus_t result;
	char *outValue;
	size_t outValueLength;

	result = JSON_Search(data, len, "hashes/sha256", strlen("hashes/sha256"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"hashes/sha256\" not found\n");
		return result;
	}
	strncpy((char*)target->hash_sha256, outValue, outValueLength);

	result = JSON_Search(data, len, "length", strlen("length"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"length\" not found\n");
		return result;
	}
	sscanf(outValue, "%ld", &target->length);

	result = JSON_Search(data, len, "version", strlen("version"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"version\" not found\n");
		return result;
	}
	sscanf(outValue, "%d", &target->version);
	return JSONSuccess;
}

int parse_timestamp_signed_metadata(char *data, int len, struct tuf_timestamp *target)
{
	JSONStatus_t result;
	char *outValue, *outSubValue;//, *uri;
	size_t outValueLength, outSubValueLen;

	memset(target, 0, sizeof(*target));
	result = JSON_Validate(data, len);
	if( result != JSONSuccess )
	{
		log_error("parse_timestamp_signed_metadata: Got invalid JSON: %s\n", data);
		return -10;
	}

	result = JSON_Search(data, len, "meta/snapshot.json", strlen("meta/snapshot.json"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"meta/snapshot.json\" not found\n");
		return -2;
	}

	result = parse_tuf_file_info(outValue, outValueLength, &target->snapshot_file);
	if (result != JSONSuccess) {
		return -2;
	}

	target->loaded = true;

	return parse_base_metadata(data, len, &target->base);
}

int parse_timestamp(const unsigned char *file_base_name, bool check_signature)
{
	int ret = -1;
	int signature_index;
	char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_MAX_COUNT];
	struct tuf_timestamp new_timestamp;

	memset(&new_timestamp, 0, sizeof(new_timestamp));

	ret = fetch_role_and_check_signature(file_base_name, ROLE_TIMESTAMP, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	// Parsing Timestamp
	ret = parse_timestamp_signed_metadata(signed_value, signed_value_len, &new_timestamp);
	if (ret < 0)
		return ret;

	memcpy(&current_timestamp, &new_timestamp, sizeof(current_timestamp));
	return ret;
}


int parse_snapshot_signed_metadata(char *data, int len, struct tuf_snapshot *target)
{
	JSONStatus_t result;
	char *outValue, *outSubValue;//, *uri;
	size_t outValueLength, outSubValueLen;

	memset(target, 0, sizeof(*target));
	result = JSON_Validate(data, len);
	if( result != JSONSuccess )
	{
		log_error("parse_snapshot_signed_metadata: Got invalid JSON: %s\n", data);
		return -10;
	}

	result = JSON_Search(data, len, "meta/root.json", strlen("meta/root.json"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"meta/root.json\" not found\n");
		return -2;
	}

	parse_tuf_file_info(outValue, outValueLength, &target->root_file);


	result = JSON_Search(data, len, "meta/targets.json", strlen("meta/targets.json"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"meta/targets.json\" not found\n");
		return -2;
	}

	parse_tuf_file_info(outValue, outValueLength, &target->targets_file);

	target->loaded = true;

	return parse_base_metadata(data, len, &target->base);
}

int parse_snapshot(const unsigned char *file_base_name, bool check_signature)
{
	int ret = -1;
	int signature_index;
	char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_MAX_COUNT];
	struct tuf_snapshot new_snapshot;

	memset(&new_snapshot, 0, sizeof(new_snapshot));

	if (!current_timestamp.loaded)
		return TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED;

	ret = fetch_role_and_check_signature(file_base_name, ROLE_SNAPSHOT, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	ret = parse_snapshot_signed_metadata(signed_value, signed_value_len, &new_snapshot);
	if (ret < 0)
		return ret;

	memcpy(&current_snapshot, &new_snapshot, sizeof(current_snapshot));
	return ret;
}


/* for unit tests only */
int verify_data_signature(const char *data, size_t data_len, const char *signing_public_key_b64, size_t signing_public_key_b64_len)
{
	int ret = -1;
	int signature_index;
	char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_MAX_COUNT];

	ret = split_metadata(data, data_len, signatures, TUF_SIGNATURES_MAX_COUNT, &signed_value, &signed_value_len);
	if (ret < 0)
		return ret;

	for (signature_index=0; signature_index < TUF_SIGNATURES_MAX_COUNT; signature_index++)
	{
		if (!signatures[signature_index].set)
			break;

		struct tuf_key key;
		memset(&key, 0, sizeof(key));
		memcpy(key.keyval, signing_public_key_b64, signing_public_key_b64_len);
		ret = verify_signature(signed_value, signed_value_len, signatures[signature_index].sig, strlen(signatures[signature_index].sig), &key);
		if (!ret) {
			/* Found valid signature */
			return ret;
		}
	}
	/* No valid signature found */
	return ret;
}

/* for unit tests only */
int verify_file_signature(const char *file_base_name, const char *signing_key_file)
{
    	unsigned char signing_public_key_b64[TUF_BIG_CHUNK];
	size_t file_size, key_file_size;

	file_size = read_file(file_base_name, data_buffer, DATA_BUFFER_LEN);
	if (file_size < 0)
		return -1;


	key_file_size = read_file(signing_key_file, signing_public_key_b64, sizeof(signing_public_key_b64));
	if (key_file_size < 0)
		return -20;

	return verify_data_signature(data_buffer, file_size, signing_public_key_b64, key_file_size);
}

/* for unit tests only */
int verify_file_hash(const char *file_base_name, const char *sha256_file)
{
    	unsigned char hash256_b16[TUF_BIG_CHUNK];
	size_t file_size, hash_file_size;

	file_size = read_file(file_base_name, data_buffer, DATA_BUFFER_LEN);
	if (file_size < 0)
		return -1;


	hash_file_size = read_file(sha256_file, hash256_b16, sizeof(hash256_b16));
	if (hash_file_size < 0)
		return -30;

	log_debug("Verifying hash for %s\n", file_base_name);
	return verify_data_hash_sha256(data_buffer, file_size, hash256_b16, hash_file_size-1);
}

/**
 * @brief Test group definition.
 */
TEST_GROUP( Full_LibTufNAno );

TEST_SETUP( Full_LibTufNAno )
{
	memset(&current_root, 0, sizeof(current_root));
	memset(&current_timestamp, 0, sizeof(current_timestamp));
	memset(&current_targets, 0, sizeof(current_targets));
	memset(&current_snapshot, 0, sizeof(current_snapshot));
}

TEST_TEAR_DOWN( Full_LibTufNAno )
{
}

TEST_GROUP_RUNNER( Full_LibTufNAno )
{
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestTimestampSignature );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestMixedSignatures );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestSnapshotSignature );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestTargetSignature );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestRootSignature );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestRoot1Load );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestRoot2Load );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestRootUpdateCheck );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestTimestampLoadWithoutRoot );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestTimestampLoad );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestSnapshotLoadWithoutTimestamp );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestSnapshotLoad );
	RUN_TEST_CASE( Full_LibTufNAno, libTufNano_TestSha256 );
}

TEST( Full_LibTufNAno, libTufNano_TestTimestampSignature )
{
	int ret;

	ret = verify_file_signature("timestamp.json", "timestamp.json.sig_key");
	TEST_ASSERT_EQUAL(0, ret);
}

TEST( Full_LibTufNAno, libTufNano_TestSnapshotSignature )
{
	int ret;

	ret = verify_file_signature("snapshot.json", "snapshot.json.sig_key");
	TEST_ASSERT_EQUAL(0, ret);
}

TEST( Full_LibTufNAno, libTufNano_TestTargetSignature )
{
	int ret;

	ret = verify_file_signature("targets.json", "targets.json.sig_key");
	TEST_ASSERT_EQUAL(0, ret);
}


TEST( Full_LibTufNAno, libTufNano_TestRootSignature )
{
	int ret;

	ret = verify_file_signature("1.root_canonical.json", "1.root_canonical.json.sig_key");
	TEST_ASSERT_EQUAL(0, ret);
}

TEST( Full_LibTufNAno, libTufNano_TestMixedSignatures )
{
	int ret;

	ret = verify_file_signature("timestamp.json", "snapshot.json.sig_key");
	TEST_ASSERT_EQUAL(MBEDTLS_ERR_RSA_INVALID_PADDING, ret);
}

TEST( Full_LibTufNAno, libTufNano_TestRoot1Load )
{
	int ret;

	ret = parse_root("1.root_canonical.json", true);

	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_STRING("2e6d5e7f1469cb08be5f371ff5f211a45005223e5aff20815f36880c9bd418cb", current_root.keys[0].id);
	TEST_ASSERT_EQUAL_STRING("8e126cc4e3ed6eaf4b638216c856c12ae2d8fa36b0b646bad1c98581a3d8e0df", current_root.keys[1].id);
	TEST_ASSERT_EQUAL_STRING("9d99928f808ecd9b10ad171312adc80248d2eb3e58082c2aad239f9928c2479b", current_root.keys[2].id);
	TEST_ASSERT_EQUAL_STRING("c0919e0f82b94be9eef55dcd5f224d8d8b4da80299a4ebef58018ab68fee0a8d", current_root.keys[3].id);

	TEST_ASSERT_EQUAL_STRING("RSA", current_root.keys[0].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", current_root.keys[1].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", current_root.keys[2].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", current_root.keys[3].keytype);

	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstQmVmyZIA2tejyNDkug\\npUsncb2cBGl/vGkrsDJQvxTPpNnmtRQTdQoZ/qqPWonNZ/JEJRVL1xc24ioyx/dS\\nCKvdZzAsIxSoklxoDslSP8jDKwdFLj34snGBgtdDJ+bh44Oei6532GX5iy7Xj3SE\\na5pVoQ6nLWz5AULw7gmR01qIA3J1OZ7oVhR5hF4W/gNc8hAQg1gMRSrm+PUxzRr2\\n5YfZznE9JVsvuTi/e0iMDBeE1cXlUzo1/B2b+7072xlBsGP61tuln6c6kRA7PbIg\\nHX5Q+vs7svBY3wl07an8IxvHi9iZUYW9V8HH67/jJxree04kjC2KhaozEJLITwE0\\n4QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				current_root.keys[0].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkvZdqvdobQJn/L0wLPYC\\nPmZgAvEnvVRaAe7q6aTPCMVXUXLt45jrr9tpvyhNyy/EfUP1RngToHAQAYieG9Wf\\nzzenGNIg57c9F2vT1ga4KwBTwnvk6qsoVINL4nJwQWRAQJbxJfkcuhWDBc1R+OjF\\nze6eYTm71AIyZiz4UR63FsVgXkM5wnCC82/0XhyKpxVI/y7N1l/wQ8toKbb3wF0K\\nIcsna0HfxvaS17lVA20fNr3KSqfg49j7ReuBNEl4QCZWhQ6xY/5zsYLYeMv4N/Bz\\n/AfyMl2QvQVf3gblem4lXoqNeRbDmVcwaNZahP0goYs0o+lCFDOyiftTazetfiat\\nowIDAQAB\\n-----END PUBLIC KEY-----\\n",
				current_root.keys[1].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr3K10h/xn11pGn8DH+vv\\nQ3gK+NB9oVKQ8+6bh4ovo6tEVc64Wwk3pWM3QkqunMmOHusgCeLo+q97LIMcS/IZ\\nYUE+pHTGdxlnJknyJBNscaF74BPQQ5crIuRdBxfcLOgniq3e48drtIN0dlNpsDcT\\nyBCUJHDV4tALOd6tTEV44bnmGacM/VQZdEG+Q4UUnao/AugZ/T+9DaUbPoBUrlPN\\n6Yn5Al5/y/oR22OrPbcNt2dIylqWxy2h21dJJuIt5EOsIuzFwP1uXr+rimIZtme6\\nSJLS7CMJ9DzeACRLr/F+KMSu8XpCvSVp6nSlao1hCzbSGLhK1jaUe01aOSk6xYKs\\n4wIDAQAB\\n-----END PUBLIC KEY-----\\n",
				current_root.keys[2].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX9EqnICo4ewErN82S00\\nWmCPhEfoEDwpG593Kh1E04MDC+PB3YIdkcqFTSeMkZW25GgWclLyDEAuUmGEO6yN\\nrR1S4/e36ImiIW2vEZhlMIX8a/SEb11Rhkvi/GRpt/ZyLp1El4M17nYO/GnYr1dE\\nhn2PCaZIo3jVuxmZ/+nzY/9whanjKoomGRcGlAne927DHYV0XiI1dBt+4gvpMdXp\\nEH8ZCHPQHjsUe0S433niVMIa4pIaQWvdEFliJ703Dqbxn1iVHUi+p8j+z6oh2v1z\\nZz0aiECwKOtRsGUNtJWeZfx5ZOOoeKyE47DZXPsolw7DlJxZRZlGny1KpX8Y0yTA\\n7QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				current_root.keys[3].keyval);

	TEST_ASSERT_EQUAL(1, current_root.roles[ROLE_SNAPSHOT].threshold);
	TEST_ASSERT_EQUAL(1, current_root.roles[ROLE_TARGETS].threshold);
	TEST_ASSERT_EQUAL(1, current_root.roles[ROLE_TIMESTAMP].threshold);
	TEST_ASSERT_EQUAL(1, current_root.roles[ROLE_ROOT].threshold);

	TEST_ASSERT_EQUAL_STRING("2e6d5e7f1469cb08be5f371ff5f211a45005223e5aff20815f36880c9bd418cb", current_root.roles[ROLE_SNAPSHOT].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("9d99928f808ecd9b10ad171312adc80248d2eb3e58082c2aad239f9928c2479b", current_root.roles[ROLE_TARGETS].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("c0919e0f82b94be9eef55dcd5f224d8d8b4da80299a4ebef58018ab68fee0a8d", current_root.roles[ROLE_TIMESTAMP].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("8e126cc4e3ed6eaf4b638216c856c12ae2d8fa36b0b646bad1c98581a3d8e0df", current_root.roles[ROLE_ROOT].keyids[0]);


	TEST_ASSERT_EQUAL_STRING("2022-10-14T19:55:13Z", current_root.base.expires);
	TEST_ASSERT_EQUAL(1665777313, current_root.base.expires_epoch);

	TEST_ASSERT_EQUAL(1, current_root.base.version);

	struct tuf_key *key;
	ret = get_public_key_for_role(&current_root, ROLE_SNAPSHOT, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstQmVmyZIA2tejyNDkug\\npUsncb2cBGl/vGkrsDJQvxTPpNnmtRQTdQoZ/qqPWonNZ/JEJRVL1xc24ioyx/dS\\nCKvdZzAsIxSoklxoDslSP8jDKwdFLj34snGBgtdDJ+bh44Oei6532GX5iy7Xj3SE\\na5pVoQ6nLWz5AULw7gmR01qIA3J1OZ7oVhR5hF4W/gNc8hAQg1gMRSrm+PUxzRr2\\n5YfZznE9JVsvuTi/e0iMDBeE1cXlUzo1/B2b+7072xlBsGP61tuln6c6kRA7PbIg\\nHX5Q+vs7svBY3wl07an8IxvHi9iZUYW9V8HH67/jJxree04kjC2KhaozEJLITwE0\\n4QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				key->keyval);

	ret = get_public_key_for_role(&current_root, ROLE_TARGETS, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr3K10h/xn11pGn8DH+vv\\nQ3gK+NB9oVKQ8+6bh4ovo6tEVc64Wwk3pWM3QkqunMmOHusgCeLo+q97LIMcS/IZ\\nYUE+pHTGdxlnJknyJBNscaF74BPQQ5crIuRdBxfcLOgniq3e48drtIN0dlNpsDcT\\nyBCUJHDV4tALOd6tTEV44bnmGacM/VQZdEG+Q4UUnao/AugZ/T+9DaUbPoBUrlPN\\n6Yn5Al5/y/oR22OrPbcNt2dIylqWxy2h21dJJuIt5EOsIuzFwP1uXr+rimIZtme6\\nSJLS7CMJ9DzeACRLr/F+KMSu8XpCvSVp6nSlao1hCzbSGLhK1jaUe01aOSk6xYKs\\n4wIDAQAB\\n-----END PUBLIC KEY-----\\n",
				key->keyval);


	ret = get_public_key_for_role(&current_root, ROLE_TIMESTAMP, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX9EqnICo4ewErN82S00\\nWmCPhEfoEDwpG593Kh1E04MDC+PB3YIdkcqFTSeMkZW25GgWclLyDEAuUmGEO6yN\\nrR1S4/e36ImiIW2vEZhlMIX8a/SEb11Rhkvi/GRpt/ZyLp1El4M17nYO/GnYr1dE\\nhn2PCaZIo3jVuxmZ/+nzY/9whanjKoomGRcGlAne927DHYV0XiI1dBt+4gvpMdXp\\nEH8ZCHPQHjsUe0S433niVMIa4pIaQWvdEFliJ703Dqbxn1iVHUi+p8j+z6oh2v1z\\nZz0aiECwKOtRsGUNtJWeZfx5ZOOoeKyE47DZXPsolw7DlJxZRZlGny1KpX8Y0yTA\\n7QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				key->keyval);

	ret = get_public_key_for_role(&current_root, ROLE_ROOT, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkvZdqvdobQJn/L0wLPYC\\nPmZgAvEnvVRaAe7q6aTPCMVXUXLt45jrr9tpvyhNyy/EfUP1RngToHAQAYieG9Wf\\nzzenGNIg57c9F2vT1ga4KwBTwnvk6qsoVINL4nJwQWRAQJbxJfkcuhWDBc1R+OjF\\nze6eYTm71AIyZiz4UR63FsVgXkM5wnCC82/0XhyKpxVI/y7N1l/wQ8toKbb3wF0K\\nIcsna0HfxvaS17lVA20fNr3KSqfg49j7ReuBNEl4QCZWhQ6xY/5zsYLYeMv4N/Bz\\n/AfyMl2QvQVf3gblem4lXoqNeRbDmVcwaNZahP0goYs0o+lCFDOyiftTazetfiat\\nowIDAQAB\\n-----END PUBLIC KEY-----\\n",
				key->keyval);

	ret = get_public_key_for_role(&current_root, TUF_ROLES_COUNT, 0, &key);
	TEST_ASSERT_EQUAL(-EINVAL, ret);
}

TEST( Full_LibTufNAno, libTufNano_TestRoot2Load )
{
	int ret;

	ret = parse_root("2.root_canonical.json", false);

	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_STRING("22e8f6d06eec2e4d50187b74ff21ddbc15326fb56e2d62fd68d10c0cb43b4e7e", current_root.keys[0].id);
	TEST_ASSERT_EQUAL_STRING("2e6d5e7f1469cb08be5f371ff5f211a45005223e5aff20815f36880c9bd418cb", current_root.keys[1].id);
	TEST_ASSERT_EQUAL_STRING("91f89e098b6c3ee0878b9f1518c2f88624dad3301ed82f1c688310de952fce0c", current_root.keys[2].id);
	TEST_ASSERT_EQUAL_STRING("c0919e0f82b94be9eef55dcd5f224d8d8b4da80299a4ebef58018ab68fee0a8d", current_root.keys[3].id);

	TEST_ASSERT_EQUAL_STRING("RSA", current_root.keys[0].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", current_root.keys[1].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", current_root.keys[2].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", current_root.keys[3].keytype);

	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsac985OY9LESVVHaRJBU\\nV2i1uHCkocMKHihaUEFZbE1dv6EMwBrdM+Z0b2I4A6E6GXmAJE3FVrsXikatleOb\\n7yau+yzv2b4wiK/7OBgz61hPmVsK1k1QVK1f3v0J27Koa6YeVUbpisXCuTQrrA23\\nczuvZlW9tHtJHY3uD03MfwlcENr+gvppDxEHCUzoUvN16IHsnGGGdgL8q4uNelDq\\n3iJCz/ArhEWOkq613sLZbOq83TyYzVgw0lcxPJ1oX+NA4iAC2Pl/uRLUtVawefUc\\nZ5k4DgpouAy2ot9d4oGRjs2LDnmKFwFiMbLgMQf6nIK8PDcso1cA44UwZuC7xSFU\\n6QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				current_root.keys[0].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstQmVmyZIA2tejyNDkug\\npUsncb2cBGl/vGkrsDJQvxTPpNnmtRQTdQoZ/qqPWonNZ/JEJRVL1xc24ioyx/dS\\nCKvdZzAsIxSoklxoDslSP8jDKwdFLj34snGBgtdDJ+bh44Oei6532GX5iy7Xj3SE\\na5pVoQ6nLWz5AULw7gmR01qIA3J1OZ7oVhR5hF4W/gNc8hAQg1gMRSrm+PUxzRr2\\n5YfZznE9JVsvuTi/e0iMDBeE1cXlUzo1/B2b+7072xlBsGP61tuln6c6kRA7PbIg\\nHX5Q+vs7svBY3wl07an8IxvHi9iZUYW9V8HH67/jJxree04kjC2KhaozEJLITwE0\\n4QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				current_root.keys[1].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmu+MksWTfMScaFw4KUBk\\nwKcSeROX8atN4D8r42BHgCsLr4OcXmHzkDVSuCCymJ2SEkgnd6pJxIaWs+HS0Nni\\nu3Gxqv9+6ZUKiMzG89gFkx6kU4RZRd3TcMZOTZaabWhDuVpg6Gkig759qL6B/jNi\\nK1FBAKNGPp3S0rZ+zghdrvrKzUSlVLmvOqTI0PhddkzoNGDO9v6F40n58NKvlOUY\\nCn8wk1n8DGG36CActHIjoAUoQsueBTRNdUy5vNmX4BuEdhUdwDaaJwEkvIvoU3S/\\nwLNlSexU5EJjqWlNeUEWvUJjbxXpSMqAhTtT1MG5En+yqPhH1tGuzK3w6JCS9aou\\nvQIDAQAB\\n-----END PUBLIC KEY-----\\n",
				current_root.keys[2].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX9EqnICo4ewErN82S00\\nWmCPhEfoEDwpG593Kh1E04MDC+PB3YIdkcqFTSeMkZW25GgWclLyDEAuUmGEO6yN\\nrR1S4/e36ImiIW2vEZhlMIX8a/SEb11Rhkvi/GRpt/ZyLp1El4M17nYO/GnYr1dE\\nhn2PCaZIo3jVuxmZ/+nzY/9whanjKoomGRcGlAne927DHYV0XiI1dBt+4gvpMdXp\\nEH8ZCHPQHjsUe0S433niVMIa4pIaQWvdEFliJ703Dqbxn1iVHUi+p8j+z6oh2v1z\\nZz0aiECwKOtRsGUNtJWeZfx5ZOOoeKyE47DZXPsolw7DlJxZRZlGny1KpX8Y0yTA\\n7QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				current_root.keys[3].keyval);

	TEST_ASSERT_EQUAL(1, current_root.roles[ROLE_SNAPSHOT].threshold);
	TEST_ASSERT_EQUAL(1, current_root.roles[ROLE_TARGETS].threshold);
	TEST_ASSERT_EQUAL(1, current_root.roles[ROLE_TIMESTAMP].threshold);
	TEST_ASSERT_EQUAL(1, current_root.roles[ROLE_ROOT].threshold);

	TEST_ASSERT_EQUAL_STRING("2e6d5e7f1469cb08be5f371ff5f211a45005223e5aff20815f36880c9bd418cb", current_root.roles[ROLE_SNAPSHOT].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("22e8f6d06eec2e4d50187b74ff21ddbc15326fb56e2d62fd68d10c0cb43b4e7e", current_root.roles[ROLE_TARGETS].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("c0919e0f82b94be9eef55dcd5f224d8d8b4da80299a4ebef58018ab68fee0a8d", current_root.roles[ROLE_TIMESTAMP].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("91f89e098b6c3ee0878b9f1518c2f88624dad3301ed82f1c688310de952fce0c", current_root.roles[ROLE_ROOT].keyids[0]);

	TEST_ASSERT_EQUAL_STRING("2022-10-14T19:56:08Z", current_root.base.expires);
	TEST_ASSERT_EQUAL(1665777368, current_root.base.expires_epoch);
	TEST_ASSERT_EQUAL(2, current_root.base.version);

	struct tuf_key *key;
	ret = get_public_key_for_role(&current_root, ROLE_SNAPSHOT, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstQmVmyZIA2tejyNDkug\\npUsncb2cBGl/vGkrsDJQvxTPpNnmtRQTdQoZ/qqPWonNZ/JEJRVL1xc24ioyx/dS\\nCKvdZzAsIxSoklxoDslSP8jDKwdFLj34snGBgtdDJ+bh44Oei6532GX5iy7Xj3SE\\na5pVoQ6nLWz5AULw7gmR01qIA3J1OZ7oVhR5hF4W/gNc8hAQg1gMRSrm+PUxzRr2\\n5YfZznE9JVsvuTi/e0iMDBeE1cXlUzo1/B2b+7072xlBsGP61tuln6c6kRA7PbIg\\nHX5Q+vs7svBY3wl07an8IxvHi9iZUYW9V8HH67/jJxree04kjC2KhaozEJLITwE0\\n4QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				key->keyval);

	ret = get_public_key_for_role(&current_root, ROLE_TARGETS, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsac985OY9LESVVHaRJBU\\nV2i1uHCkocMKHihaUEFZbE1dv6EMwBrdM+Z0b2I4A6E6GXmAJE3FVrsXikatleOb\\n7yau+yzv2b4wiK/7OBgz61hPmVsK1k1QVK1f3v0J27Koa6YeVUbpisXCuTQrrA23\\nczuvZlW9tHtJHY3uD03MfwlcENr+gvppDxEHCUzoUvN16IHsnGGGdgL8q4uNelDq\\n3iJCz/ArhEWOkq613sLZbOq83TyYzVgw0lcxPJ1oX+NA4iAC2Pl/uRLUtVawefUc\\nZ5k4DgpouAy2ot9d4oGRjs2LDnmKFwFiMbLgMQf6nIK8PDcso1cA44UwZuC7xSFU\\n6QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				key->keyval);


	ret = get_public_key_for_role(&current_root, ROLE_TIMESTAMP, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX9EqnICo4ewErN82S00\\nWmCPhEfoEDwpG593Kh1E04MDC+PB3YIdkcqFTSeMkZW25GgWclLyDEAuUmGEO6yN\\nrR1S4/e36ImiIW2vEZhlMIX8a/SEb11Rhkvi/GRpt/ZyLp1El4M17nYO/GnYr1dE\\nhn2PCaZIo3jVuxmZ/+nzY/9whanjKoomGRcGlAne927DHYV0XiI1dBt+4gvpMdXp\\nEH8ZCHPQHjsUe0S433niVMIa4pIaQWvdEFliJ703Dqbxn1iVHUi+p8j+z6oh2v1z\\nZz0aiECwKOtRsGUNtJWeZfx5ZOOoeKyE47DZXPsolw7DlJxZRZlGny1KpX8Y0yTA\\n7QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				key->keyval);

	ret = get_public_key_for_role(&current_root, ROLE_ROOT, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmu+MksWTfMScaFw4KUBk\\nwKcSeROX8atN4D8r42BHgCsLr4OcXmHzkDVSuCCymJ2SEkgnd6pJxIaWs+HS0Nni\\nu3Gxqv9+6ZUKiMzG89gFkx6kU4RZRd3TcMZOTZaabWhDuVpg6Gkig759qL6B/jNi\\nK1FBAKNGPp3S0rZ+zghdrvrKzUSlVLmvOqTI0PhddkzoNGDO9v6F40n58NKvlOUY\\nCn8wk1n8DGG36CActHIjoAUoQsueBTRNdUy5vNmX4BuEdhUdwDaaJwEkvIvoU3S/\\nwLNlSexU5EJjqWlNeUEWvUJjbxXpSMqAhTtT1MG5En+yqPhH1tGuzK3w6JCS9aou\\nvQIDAQAB\\n-----END PUBLIC KEY-----\\n",
				key->keyval);

	ret = get_public_key_for_role(&current_root, TUF_ROLES_COUNT, 0, &key);
	TEST_ASSERT_EQUAL(-EINVAL, ret);
}

TEST( Full_LibTufNAno, libTufNano_TestRootUpdateCheck )
{
	int ret;

	ret = parse_root("1.root_canonical.json", true);

	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_root("2.root_canonical.json", true);

	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

}

TEST( Full_LibTufNAno, libTufNano_TestTimestampLoadWithoutRoot )
{
	int ret;

	ret = parse_timestamp("timestamp.json", true);
	TEST_ASSERT_EQUAL(TUF_ERROR_ROOT_ROLE_NOT_LOADED, ret);
}

TEST( Full_LibTufNAno, libTufNano_TestTimestampLoad )
{
	int ret;

	ret = parse_root("1.root_canonical.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_root("2.root_canonical.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_timestamp("timestamp.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	TEST_ASSERT_EQUAL(true, current_timestamp.loaded);

	TEST_ASSERT_EQUAL(820, current_timestamp.snapshot_file.length);
	TEST_ASSERT_EQUAL(875, current_timestamp.snapshot_file.version);
	TEST_ASSERT_EQUAL_STRING("1119a2d55772f0cd7a94cbc916c8a28183f24542fd2e1377cd06be74f0aa328f", current_timestamp.snapshot_file.hash_sha256);

	TEST_ASSERT_EQUAL_STRING("2022-09-09T18:13:01Z", current_timestamp.base.expires);
	TEST_ASSERT_EQUAL(1662747181, current_timestamp.base.expires_epoch);

	TEST_ASSERT_EQUAL(875, current_timestamp.base.version);
}

TEST( Full_LibTufNAno, libTufNano_TestSnapshotLoadWithoutTimestamp )
{
	int ret;

	ret = parse_root("1.root_canonical.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_root("2.root_canonical.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_snapshot("snapshot.json", true);
	TEST_ASSERT_EQUAL(TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED, ret);
}

TEST( Full_LibTufNAno, libTufNano_TestSnapshotLoad )
{
	int ret;

	ret = parse_root("1.root_canonical.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_root("2.root_canonical.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_timestamp("timestamp.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_snapshot("snapshot.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);
}

TEST( Full_LibTufNAno, libTufNano_TestSha256 )
{
	int ret;

	ret = verify_file_hash("targets.json", "targets.json.sha256");
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = verify_file_hash("timestamp.json", "targets.json.sha256");
	TEST_ASSERT_EQUAL(TUF_HASH_VERIFY_ERROR, ret);
}

int run_full_test( void )
{
	UNITY_BEGIN();

	/* Run the test group. */
	RUN_TEST_GROUP( Full_LibTufNAno );

	int status = UNITY_END();
	return status;
}

int main()
{
	log_debug("get_current_gmt_time=%ld\n", get_current_gmt_time());
	run_full_test();
}
