#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#define __USE_XOPEN
#define _GNU_SOURCE
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

#include "libtufnano.h"
#include "libtufnano_internal.h"


/*
 * TUF metadata has '.' in field names.
 * We change the key separator for coreJSON to '/' to avoid ambiguity
 * This is currently being done in the Makefile
 *  #define JSON_QUERY_KEY_SEPARATOR '/'
 */

struct tuf_updater updater;
static struct tuf_config config;

void load_config()
{
	config.max_root_rotations = 10000;
	config.snapshot_max_length = DATA_BUFFER_LEN;
	config.targets_max_length = DATA_BUFFER_LEN;
}

const char* get_role_name(enum tuf_role role) {
	switch(role) {
		case ROLE_ROOT: return _ROOT;
		case ROLE_SNAPSHOT: return _SNAPSHOT;
		case ROLE_TARGETS: return _TARGETS;
		case ROLE_TIMESTAMP: return _TIMESTAMP;
		default: return "";
	}
}

int remove_all_local_role_files()
{
	// TODO: Restore original 1.root.json
	// remove_local_role_file(ROLE_ROOT);
	remove_local_role_file(ROLE_TIMESTAMP);
	remove_local_role_file(ROLE_SNAPSHOT);
	remove_local_role_file(ROLE_TARGETS);
}

/**/
time_t datetime_string_to_epoch(const char *s, time_t *epoch)
{
	struct tm tm;
	char *ret;

	/* 2022-09-09T18:13:01Z */
	ret = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
	if (ret == NULL) {
		log_error("Invalid datetime string %s\n", s);
		return TUF_ERROR_INVALID_DATE_TIME;
	}
	tm.tm_isdst = 0; /* ignore DST */
	*epoch = mktime(&tm);
	if (*epoch < 0)
		return TUF_ERROR_INVALID_DATE_TIME;
	*epoch += tm.tm_gmtoff; /* compensate locale */
	return TUF_SUCCESS;
}

bool is_expired(time_t expires, time_t reference_time)
{
	return expires < reference_time;
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

enum tuf_role role_string_to_enum(const char *role_name, size_t role_name_len)
{
	if (!strncmp(role_name, _SNAPSHOT, role_name_len))
		return ROLE_SNAPSHOT;
	if (!strncmp(role_name, _TIMESTAMP, role_name_len))
		return ROLE_TIMESTAMP;
	if (!strncmp(role_name, _TARGETS, role_name_len))
		return ROLE_TARGETS;
	if (!strncmp(role_name, _ROOT, role_name_len))
		return ROLE_ROOT;
	return TUF_ROLES_COUNT;
}

int parse_base_metadata(char *data, int len, enum tuf_role role, struct tuf_metadata *base)
{
	char *out_value;
	size_t out_value_len;
	JSONStatus_t result;
	int ret;
	char lower_case_type[12];

	/* Please validate before */
	result = JSON_Search(data, len, "_type", strlen("_type"), &out_value, &out_value_len);
	if (result != JSONSuccess) {
		log_error("parse_root_signed_metadata: \"_type\" not found\n");
		return TUF_ERROR_INVALID_TYPE;
	}

	strncpy(lower_case_type, out_value, sizeof(lower_case_type));
	lower_case_type[0] = tolower(lower_case_type[0]); /* Allowing first char to be upper case */
	if (strncmp(lower_case_type, get_role_name(role), out_value_len)) {
		log_error("parse_root_signed_metadata: Expected \"_type\" = %s, got %.*s instead\n", get_role_name(role), (int)out_value_len, out_value);
		return TUF_ERROR_INVALID_TYPE;
	}

	result = JSON_Search(data, len, "version", strlen("version"), &out_value, &out_value_len);
	if (result != JSONSuccess) {
		log_error("parse_base_metadata: \"version\" not found\n");
		return TUF_ERROR_FIELD_MISSING;
	}
	sscanf(out_value, "%d", &base->version);
	result = JSON_Search(data, len, "expires", strlen("expires"), &out_value, &out_value_len);
	if (result != JSONSuccess) {
		log_error("parse_base_metadata: \"expires\" not found\n");
		return TUF_ERROR_FIELD_MISSING;
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

	if (len <= 0)
		return -EINVAL;
	result = JSON_Validate(data, len);
	if( result != JSONSuccess )
	{
		log_error("split_metadata: Got invalid JSON with len=%d: %.*s\n", len, len, data);
		return TUF_ERROR_INVALID_METADATA;
	}

	result = JSON_Search(data, len, "keys", strlen("keys"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_root_signed_metadata: \"keys\" not found\n");
		return TUF_ERROR_FIELD_MISSING;
	}

	/* For each key */
	while (result == JSONSuccess) {
		if (key_index >= TUF_MAX_KEY_COUNT) {
			log_error("More keys than allowed (allowed=%d)\n", TUF_MAX_KEY_COUNT);
			return TUF_ERROR_FIELD_COUNT_EXCEEDED;
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
				return TUF_ERROR_FIELD_MISSING;
			}
			strncpy(current_key->keytype, out_value_internal, value_length_internal);

			result_internal = JSON_Search(pair.value, pair.valueLength, "keyval", strlen("keyval"), &out_value_internal, &value_length_internal);
			if (result_internal != JSONSuccess) {
				log_error("'keyval' field not found. result_internal=%d\n", result_internal);
				return TUF_ERROR_FIELD_MISSING;
			}

			result_internal = JSON_Search(out_value_internal, value_length_internal, "public", strlen("public"), &out_value_internal_2, &value_length_internal_2);
			if (result_internal != JSONSuccess) {
				log_error("'public' field not found. result_internal=%d\n", result_internal);
				return TUF_ERROR_FIELD_MISSING;
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
		return TUF_ERROR_FIELD_MISSING;
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
				return TUF_ERROR_INVALID_FIELD_VALUE;
			}

			result_internal = JSON_Search(pair.value, pair.valueLength, "threshold", strlen("threshold"), &out_value_internal, &value_length_internal);
			if (result_internal != JSONSuccess) {
				log_error("'threshold' field not found. result_internal=%d\n", result_internal);
				return TUF_ERROR_FIELD_MISSING;
			}
			sscanf(out_value_internal, "%d", &target->roles[role].threshold);

			result_internal = JSON_Search(pair.value, pair.valueLength, "keyids", strlen("keyids"), &out_value_internal, &value_length_internal);
			if (result_internal != JSONSuccess) {
				log_error("'keyids' field not found. result_internal=%d\n", result_internal);
				return TUF_ERROR_FIELD_MISSING;
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
	return parse_base_metadata(data, len, ROLE_ROOT, &target->base);
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

	result = JSON_Validate(data, len);
	if (len <= 0)
		return -EINVAL;
	if( result != JSONSuccess )
	{
		log_error("split_metadata: Got invalid JSON: %s\n", data);
		return TUF_ERROR_INVALID_METADATA;
	}
	// log_error("JSON is valid\n");

	bool foundMatch = false;
	result = JSON_Search(data, len, "signatures", strlen("signatures"), &outValue, &outValueLength);
	if (result == JSONSuccess) {
		// log_debug("outValue=\n%.*s\n", (int)outValueLength, outValue);
		while (result == JSONSuccess) {
			if (signature_index >= signatures_max_count) {
				log_error("More signatures than allowed (allowed=%d)\n", signatures_max_count);
				return TUF_ERROR_FIELD_COUNT_EXCEEDED;
			}

			struct tuf_signature *current_signature = &signatures[signature_index];
			memset(current_signature, 0, sizeof(*current_signature));
			result = JSON_Iterate(outValue, outValueLength, &start, &next, &pair);
			if (result == JSONSuccess) {
				// log_debug("start=%ld, next=%d, pair.Value=%.*s\n", start, next, pair.valueLength, pair.value);
				result_internal = JSON_Search(pair.value, pair.valueLength, "keyid", strlen("keyid"), &out_value_internal, &value_length_internal);
				if (result_internal != JSONSuccess) {
					log_error("'keyid' field not found. result_internal=%d\n", result_internal);
					return TUF_ERROR_FIELD_MISSING;
				} else {
					strncpy(current_signature->keyid, out_value_internal, value_length_internal);
				}
				// log_debug("keyid=%s\n", current_signature->keyid);
				result_internal = JSON_Search(pair.value, pair.valueLength, "method", strlen("method"), &out_value_internal, &value_length_internal);
				if (result_internal != JSONSuccess) {
					log_error("'method' field not found\n");
					return TUF_ERROR_FIELD_MISSING;
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
					return TUF_ERROR_FIELD_MISSING;
				} else {
					strncpy(current_signature->sig, out_value_internal, value_length_internal);
				}
				current_signature->set = true;
				signature_index++;
			}
		}
	} else {
		log_error("handle_json_data: signatures not found\n");
		return TUF_ERROR_FIELD_MISSING;
	}

	result = JSON_Search(data, len, "signed", strlen("signed"), &outValue, &outValueLength);
	if (result == JSONSuccess) {
		*signed_value = outValue;
		*signed_value_len = outValueLength;
	} else {
		log_error("handle_json_data: signed not found");
		return TUF_ERROR_FIELD_MISSING;
	}

	// log_debug("\nsplit_metadata, signed_value_len=%d   value=%.*s\n", *signed_value_len, *signed_value_len, *signed_value);

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
		return TUF_ERROR_INVALID_HASH_LENGTH;
	}


	/* 0 here means use the full SHA-256, not the SHA-224 variant */
	mbedtls_sha256(data, data_len, hash_output, 0);

	hextobin(hash_b16, decoded_hash_input, hash_b16_len);
	if (memcmp(decoded_hash_input, hash_output, sizeof(hash_output))) {
		log_debug("Hash Verify Error\n");
		print_hex("Expected", decoded_hash_input, 32);
		print_hex("Got", hash_output, 32);
		return TUF_ERROR_HASH_VERIFY_ERROR;
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
	return TUF_ERROR_KEY_ID_NOT_FOUND;
}

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

	return TUF_ERROR_KEY_ID_FOR_ROLE_NOT_FOUND;
}

int verify_data_signature_for_role(const char *signed_value, size_t signed_value_len, struct tuf_signature *signatures, enum tuf_role role, struct tuf_root *root)
{
	int ret;
	int signature_index;
	int threshold;
	int valid_signatures_count = 0;

	threshold = updater.root.roles[role].threshold;
	for (signature_index=0; signature_index < TUF_SIGNATURES_MAX_COUNT && valid_signatures_count < threshold; signature_index++)
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
			valid_signatures_count++;
		}
	}

	if (valid_signatures_count < threshold)
		return TUF_ERROR_UNSIGNED_METADATA;
	else
		return TUF_SUCCESS;
}

int get_expected_sha256_and_length_for_role(enum tuf_role role, unsigned char **sha256, size_t *length)
{
	if (role == ROLE_SNAPSHOT) {
		if (!updater.timestamp.loaded)
			return TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED;
		*sha256 = updater.timestamp.snapshot_file.hash_sha256;
		*length = updater.timestamp.snapshot_file.length;
		return TUF_SUCCESS;
	} else if (role == ROLE_TARGETS) {
		if (!updater.snapshot.loaded)
			return TUF_ERROR_SNAPSHOT_ROLE_NOT_LOADED;
		*sha256 = updater.snapshot.targets_file.hash_sha256;
		*length = updater.snapshot.targets_file.length;
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

	if (len != expected_length) {
		log_error("Expected %s length %ld, got %ld\n", get_role_name(role), expected_length, len);
		return TUF_ERROR_LENGTH_VERIFY_ERROR;
	}

	ret = verify_data_hash_sha256(data, len, expected_sha256, strlen(expected_sha256));
	if (ret != TUF_SUCCESS)
		return ret;

	return TUF_SUCCESS;
}

int split_metadata_and_check_signature(const char *data, size_t file_size, enum tuf_role role, struct tuf_signature *signatures, char **signed_value, int *signed_value_len, bool check_signature_and_hashes)
{
	int ret = -1;

	ret = split_metadata(data, file_size, signatures, TUF_SIGNATURES_MAX_COUNT, signed_value, signed_value_len);
	if (ret < 0)
		return ret;

	if (role != ROLE_ROOT && !updater.root.loaded)
		return TUF_ERROR_ROOT_ROLE_NOT_LOADED;

	if (!check_signature_and_hashes)
		return TUF_SUCCESS;

	if (role == ROLE_SNAPSHOT || role == ROLE_TARGETS) {
		ret = verify_length_and_hashes(data, file_size, role);
		if (ret != TUF_SUCCESS)
			return ret;
	}

	if (updater.root.loaded) {
		// check signature using current root key
		ret = verify_data_signature_for_role(*signed_value, *signed_value_len, signatures, role, &updater.root);
		// log_debug("Verifying against current root ret = %d\n", ret);
		if (ret < 0)
			return ret;
	}
	return TUF_SUCCESS;
}

int update_root(const unsigned char *data, size_t len, bool check_signature)
{
	// TODO: make sure check_signature is false only during unit testing

	int ret = -1;
	int signature_index;
	char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_MAX_COUNT];
	struct tuf_root new_root;

	memset(&new_root, 0, sizeof(new_root));
	ret = split_metadata_and_check_signature(data, len, ROLE_ROOT, signatures, &signed_value, &signed_value_len, check_signature);
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

	memcpy(&updater.root, &new_root, sizeof(updater.root));

	return ret;
}

int parse_tuf_file_info(char *data, size_t len, struct tuf_role_file *target)
{
	JSONStatus_t result;
	char *outValue;
	size_t outValueLength;

	result = JSON_Search(data, len, "hashes/sha256", strlen("hashes/sha256"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"hashes/sha256\" not found\n");
		return TUF_ERROR_FIELD_MISSING;
	}
	strncpy((char*)target->hash_sha256, outValue, outValueLength);

	result = JSON_Search(data, len, "length", strlen("length"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"length\" not found\n");
		return TUF_ERROR_FIELD_MISSING;
	}
	sscanf(outValue, "%ld", &target->length);

	result = JSON_Search(data, len, "version", strlen("version"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"version\" not found\n");
		return TUF_ERROR_FIELD_MISSING;
	}
	sscanf(outValue, "%d", &target->version);
	target->loaded = true;
	return TUF_SUCCESS;
}

int parse_timestamp_signed_metadata(char *data, int len, struct tuf_timestamp *target)
{
	JSONStatus_t result;
	char *outValue, *outSubValue;//, *uri;
	size_t outValueLength, outSubValueLen;
	int ret;

	memset(target, 0, sizeof(*target));
	result = JSON_Validate(data, len);
	if( result != JSONSuccess )
	{
		log_error("parse_timestamp_signed_metadata: Got invalid JSON: %s\n", data);
		return TUF_ERROR_INVALID_METADATA;
	}

	result = JSON_Search(data, len, "meta/snapshot.json", strlen("meta/snapshot.json"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"meta/snapshot.json\" not found\n");
		return TUF_ERROR_FIELD_MISSING;
	}

	ret = parse_tuf_file_info(outValue, outValueLength, &target->snapshot_file);
	if (ret < 0) {
		return ret;
	}

	target->loaded = true;

	return parse_base_metadata(data, len, ROLE_TIMESTAMP, &target->base);
}

int update_timestamp(const unsigned char *data, size_t len, bool check_signature)
{
	int ret = -1;
	int signature_index;
	char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_MAX_COUNT];
	struct tuf_timestamp new_timestamp;

	memset(&new_timestamp, 0, sizeof(new_timestamp));

	ret = split_metadata_and_check_signature(data, len, ROLE_TIMESTAMP, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	// Parsing Timestamp
	ret = parse_timestamp_signed_metadata(signed_value, signed_value_len, &new_timestamp);
	if (ret < 0)
		return ret;
	/*
	 * If an existing trusted timestamp is updated,
	 * check for a rollback attack
	 */
	if (updater.timestamp.loaded) {
		/* Prevent rolling back timestamp version */
		if (new_timestamp.base.version < updater.timestamp.base.version) {
			log_error("New timestamp version %d must be >= %d", new_timestamp.base.version, updater.timestamp.base.version);
			return TUF_ERROR_BAD_VERSION_NUMBER;
		}
		/* Keep using old timestamp if versions are equal */
		if (new_timestamp.base.version == updater.timestamp.base.version)
			return TUF_ERROR_SAME_VERSION;

		/* Prevent rolling back snapshot version */
		if (new_timestamp.snapshot_file.version < updater.timestamp.snapshot_file.version) {
			log_error("New snapshot version %d must be >= %d", new_timestamp.snapshot_file.version, updater.timestamp.snapshot_file.version);
			return TUF_ERROR_BAD_VERSION_NUMBER;
		}
	}

        /*
	 * expiry not checked to allow old timestamp to be used for rollback
         * protection of new timestamp: expiry is checked in update_snapshot()
	 */

	memcpy(&updater.timestamp, &new_timestamp, sizeof(updater.timestamp));
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
		return TUF_ERROR_INVALID_METADATA;
	}

	result = JSON_Search(data, len, "meta/root.json", strlen("meta/root.json"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"meta/root.json\" not found\n");
		return TUF_ERROR_FIELD_MISSING;
	}

	parse_tuf_file_info(outValue, outValueLength, &target->root_file);


	result = JSON_Search(data, len, "meta/targets.json", strlen("meta/targets.json"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_timestamp_signed_metadata: \"meta/targets.json\" not found\n");
		return TUF_ERROR_FIELD_MISSING;
	}

	parse_tuf_file_info(outValue, outValueLength, &target->targets_file);

	target->loaded = true;

	return parse_base_metadata(data, len, ROLE_SNAPSHOT, &target->base);
}

int parse_targets_metadata(char *data, int len, struct tuf_targets *target)
{
	JSONStatus_t result;
	char *outValue, *outSubValue;//, *uri;
	size_t outValueLength, outSubValueLen;
	size_t start = 0, next = 0;
	JSONPair_t pair;
	int ret;

	memset(target, 0, sizeof(*target));
	result = JSON_Validate(data, len);
	if( result != JSONSuccess )
	{
		log_error("parse_targets_metadata: Got invalid JSON: %s\n", data);
		return TUF_ERROR_INVALID_METADATA;
	}

	result = JSON_Search(data, len, "targets", strlen("targets"), &outValue, &outValueLength);
	if (result != JSONSuccess) {
		log_error("parse_targets_metadata: \"targets\" not found\n");
		return TUF_ERROR_FIELD_MISSING;
	}

	/* Iterate over each target */
	while (result == JSONSuccess) {
		result = JSON_Iterate(outValue, outValueLength, &start, &next, &pair);
		if (result == JSONSuccess) {
			ret = tuf_parse_single_target(pair.key, pair.keyLength, pair.value, pair.valueLength, updater.application_context);
			if (ret < 0) {
				log_error("Error processing target %.*s\n", (int)pair.keyLength, pair.key);
				break;
			}
		}
	}

	target->loaded = true;

	return parse_base_metadata(data, len, ROLE_TARGETS, &target->base);
}

int check_final_timestamp()
{
        // Return error if timestamp is expired
	if (!updater.timestamp.loaded) {
		log_error("BUG: !updater.timestamp.loaded\n");
		return TUF_ERROR_BUG;
	}

	if (is_expired(updater.timestamp.base.expires_epoch, updater.reference_time)) {
		log_error("timestamp.json is expired\n");
		return TUF_ERROR_EXPIRED_METADATA;
	}

	return TUF_SUCCESS;
}

int check_final_snapshot()
{
        // Return error if snapshot is expired or meta version does not match

	if (!updater.snapshot.loaded) {
		log_error("BUG: !updater.snapshot.loaded\n");
		return TUF_ERROR_BUG;
	}
	if (!updater.timestamp.loaded) {
		log_error("BUG: !updater.timestamp.loaded\n");
		return TUF_ERROR_BUG;
	}

	if (is_expired(updater.snapshot.base.expires_epoch, updater.reference_time)) {
		log_error("snapshot.json is expired\n");
		return TUF_ERROR_EXPIRED_METADATA;
	}

	if (updater.snapshot.base.version != updater.timestamp.snapshot_file.version) {
		log_error("Expected snapshot version %d, got %d", updater.timestamp.snapshot_file.version, updater.snapshot.base.version);
		return TUF_ERROR_BAD_VERSION_NUMBER;
	}
	return TUF_SUCCESS;
}

// TODO: add trusted parameter logic, check if it is required
int update_snapshot(const unsigned char *data, size_t len, bool check_signature)
{
	int ret = -1;
	int signature_index;
	char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_MAX_COUNT];
	struct tuf_snapshot new_snapshot;

	memset(&new_snapshot, 0, sizeof(new_snapshot));

        log_debug("Updating snapshot");

        if (!updater.timestamp.loaded) {
            log_error("Cannot update snapshot before timestamp");
	    return TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED;
	}

        if (updater.targets.loaded) {
            log_error("Cannot update snapshot after targets");
	    return TUF_ERROR_TARGETS_ROLE_LOADED;
	}

        // Snapshot cannot be loaded if final timestamp is expired
        ret = check_final_timestamp();
	if (ret < 0)
		return ret;

	ret = split_metadata_and_check_signature(data, len, ROLE_SNAPSHOT, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	ret = parse_snapshot_signed_metadata(signed_value, signed_value_len, &new_snapshot);
	if (ret < 0)
		return ret;

        // version not checked against meta version to allow old snapshot to be
        // used in rollback protection: it is checked when targets is updated

        // # If an existing trusted snapshot is updated, check for rollback attack
        if (updater.snapshot.loaded) {
		/* Prevent removal of any metadata in meta */
		if (updater.snapshot.root_file.loaded && !new_snapshot.root_file.loaded) {
			log_error("New snapshot is missing info for 'root'\n");
			return TUF_ERROR_REPOSITORY_ERROR;
		}

		/* Prevent rollback of root version */
		if (new_snapshot.root_file.version < updater.snapshot.root_file.version) {
			log_error("Expected root version %d, got %d\n", updater.snapshot.root_file.version, new_snapshot.root_file.version);
			return TUF_ERROR_BAD_VERSION_NUMBER;
		}

		/* Prevent removal of any metadata in meta */
		if (updater.snapshot.targets_file.loaded && !new_snapshot.targets_file.loaded) {
			log_error("New snapshot is missing info for 'targets'\n");
			return TUF_ERROR_REPOSITORY_ERROR;
		}

		/* Prevent rollback of targets version */
		if (new_snapshot.targets_file.version < updater.snapshot.targets_file.version) {
			log_error("Expected targets version >= %d, got %d\n", updater.snapshot.targets_file.version, new_snapshot.targets_file.version);
			return TUF_ERROR_BAD_VERSION_NUMBER;
		}

	}

        // expiry not checked to allow old snapshot to be used for rollback
        // protection of new snapshot: it is checked when targets is updated

	memcpy(&updater.snapshot, &new_snapshot, sizeof(updater.snapshot));
	log_info("Updated snapshot v%d\n", new_snapshot.targets_file.version);

        // snapshot is loaded, but we raise if it's not valid _final_ snapshot
        ret = check_final_snapshot();
	if (ret < 0)
		return ret;

	return ret;
}

int update_targets(const unsigned char *data, size_t len, bool check_signature)
{
	int ret;
	int signature_index;
	char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_MAX_COUNT];
	struct tuf_targets new_targets;

	memset(&new_targets, 0, sizeof(new_targets));

	if (!updater.snapshot.loaded) {
		log_error("Cannot load targets before snapshot");
		return TUF_ERROR_SNAPSHOT_ROLE_NOT_LOADED;
	}

        // Targets cannot be loaded if final snapshot is expired or its version
        // does not match meta version in timestamp
	ret = check_final_snapshot();
	if (ret < 0)
		return ret;


	if (!updater.root.loaded) {
		log_error("Cannot load targets before root");
		return TUF_ERROR_ROOT_ROLE_NOT_LOADED;
	}

	ret = split_metadata_and_check_signature(data, len, ROLE_TARGETS, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	ret = parse_targets_metadata(signed_value, signed_value_len, &new_targets);
	if (ret < 0)
		return ret;

	if (updater.snapshot.targets_file.version != new_targets.base.version) {
		log_error("Expected targets v%d, got v%d\n", updater.snapshot.targets_file.version, new_targets.base.version);
		return TUF_ERROR_BAD_VERSION_NUMBER;
	}

	if (is_expired(new_targets.base.expires_epoch, updater.reference_time))	{
		log_error("New targets is expired\n");
		return TUF_ERROR_EXPIRED_METADATA;
	}

	memcpy(&updater.targets, &new_targets, sizeof(updater.targets));
        log_debug("Updated targets v%d\n", new_targets.base.version);

	return TUF_SUCCESS;
}


/* TODO: Not sure if read_local_file should receive string or enum tuf_role */
int load_local_metadata(enum tuf_role role, char *target_buffer, size_t limit, size_t *file_size)
{
	int ret;

	ret = read_local_file(role, target_buffer, limit, file_size);
	return ret;
}


int persist_metadata(enum tuf_role role, char *data, size_t len)
{
	size_t file_size;
	int ret;

	ret = write_local_file(role, data, len);
	return ret;
}

int download_metadata(enum tuf_role role, char *target_buffer, size_t limit, int version, size_t *file_size)
{
	char *role_name = get_role_name(role);
	char role_file_name[30];
	int ret;

	if (version == 0)
		snprintf(role_file_name, sizeof(role_file_name), "%s.json", role_name);
	else
		snprintf(role_file_name, sizeof(role_file_name), "%d.%s.json", version, role_name);
	ret = fetch_file(role_file_name, target_buffer, limit, file_size);
	return ret;
}

int load_root()
{
	// Update the root role
	size_t file_size;
	int ret;

	ret = load_local_metadata(ROLE_ROOT, updater.data_buffer, updater.data_buffer_len, &file_size);
	if (ret < 0) {
		log_debug("local root not found\n");
		return ret;
	}

	ret = update_root(updater.data_buffer, file_size, true);
	if (ret < 0)
		return ret;

        int lower_bound = updater.root.base.version + 1;
        int upper_bound = lower_bound + config.max_root_rotations;

        for (int next_version = lower_bound; next_version < upper_bound; next_version++) {
		ret = download_metadata(ROLE_ROOT, updater.data_buffer, updater.data_buffer_len, next_version, &file_size);
		if (ret < 0) {
			if (ret == TUF_HTTP_NOT_FOUND || ret == TUF_HTTP_FORBIDDEN)
				break;
			else
				return ret;
		}
		ret = update_root(updater.data_buffer, file_size, true);
		if (ret < 0)
			return ret;
		ret = persist_metadata(ROLE_ROOT, updater.data_buffer, file_size);
		if (ret < 0)
			return ret;
	}

	return TUF_SUCCESS;
}

int load_timestamp()
{
	size_t file_size;
	int ret;

	ret = load_local_metadata(ROLE_TIMESTAMP, updater.data_buffer, updater.data_buffer_len, &file_size);
	if (ret < 0) {
		log_debug("local timestamp not found. Proceeding\n");
	} else {
		ret = update_timestamp(updater.data_buffer, file_size, true);
		if (ret < 0)
			log_debug("local timestamp is not valid. Proceeding\n");
	}

	ret = download_metadata(ROLE_TIMESTAMP, updater.data_buffer, updater.data_buffer_len, 0, &file_size);
	if (ret < 0)
		return ret;
	ret = update_timestamp(updater.data_buffer, file_size, true);
	if (ret < 0)
		return ret;
	ret = persist_metadata(ROLE_TIMESTAMP, updater.data_buffer, file_size);
	if (ret < 0)
		return ret;
}

int load_snapshot()
{
	/* Load local (and if needed remote) snapshot metadata */

	size_t file_size;
	int ret;

	ret = load_local_metadata(ROLE_SNAPSHOT, updater.data_buffer, updater.data_buffer_len, &file_size);
	if (ret < 0) {
		log_debug("local snapshot not found. Proceeding\n");
	} else {
		ret = update_snapshot(updater.data_buffer, file_size, true);
		if (ret < 0)
			log_debug("local snapshot is not valid. Proceeding\n");
		else
			return TUF_SUCCESS;
	}

	if (!updater.timestamp.loaded) {
		log_error("BUG: !updater.timestamp.loaded\n");
		return TUF_ERROR_BUG;
	}

	size_t max_length = config.snapshot_max_length;
	if (updater.timestamp.snapshot_file.length)
		max_length = updater.timestamp.snapshot_file.length;

	ret = download_metadata(ROLE_SNAPSHOT, updater.data_buffer, max_length, 0, &file_size);
	if (ret < 0)
		return ret;
	ret = update_snapshot(updater.data_buffer, file_size, true);
	if (ret < 0)
		return ret;
	ret = persist_metadata(ROLE_SNAPSHOT, updater.data_buffer, file_size);
	if (ret < 0)
		return ret;
}

int load_targets()
{
	log_debug("load_targets: begin\n");
	size_t file_size;
	int ret;

	// Avoid loading 'role' more than once during "get_targetinfo" -> TODO: does this apply to us?
	if (updater.targets.loaded)
		return TUF_SUCCESS;

	ret = load_local_metadata(ROLE_SNAPSHOT, updater.data_buffer, updater.data_buffer_len, &file_size);
	if (ret < 0) {
		log_debug("local targets not found. Proceeding\n");
	} else {
		ret = update_targets(updater.data_buffer, file_size, true);
		if (ret < 0) {
			log_debug("local targets is not valid. Proceeding\n");
		}
		else {
			log_debug("local targets is valid: not downloading new one\n");
			return TUF_SUCCESS;
		}
	}

	if (!updater.snapshot.loaded) {
		log_error("Snapshot role is not loaded");
		return TUF_ERROR_BUG;
	}

	size_t max_length = config.targets_max_length;
	if (updater.snapshot.targets_file.length)
		max_length = updater.snapshot.targets_file.length;

	ret = download_metadata(ROLE_TARGETS, updater.data_buffer, max_length, 0, &file_size);
	if (ret < 0)
		return ret;
	ret = update_targets(updater.data_buffer, file_size, true);
	if (ret < 0)
		return ret;
	ret = persist_metadata(ROLE_TARGETS, updater.data_buffer, file_size);
	if (ret < 0)
		return ret;
}

int refresh()
{
        // static unsigned char data_buffer[DATA_BUFFER_LEN];
	int ret;

	// memset(&updater, 0, sizeof(updater));
	// updater.reference_time = get_current_gmt_time();
	// updater.application_context = tuf_get_application_context();
	// updater.data_buffer = data_buffer;
	// updater.data_buffer_len = sizeof(data_buffer);

	ret = load_root();
	if (ret < 0)
		return ret;

	ret = load_timestamp();
	if (ret < 0)
		return ret;

	ret = load_snapshot();
	if (ret < 0)
		return ret;

	ret = load_targets();
	if (ret < 0)
		return ret;

	tuf_targets_processing_done(updater.application_context);

	return TUF_SUCCESS;
}
