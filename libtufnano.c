#define _GNU_SOURCE
#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

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

struct tuf_updater updater;
static struct tuf_config config;

void load_config()
{
	config.max_root_rotations = 10000;
	config.snapshot_max_length = updater.data_buffer_len;
	config.targets_max_length = updater.data_buffer_len;
}

const char *get_role_name(enum tuf_role role)
{
	switch (role) {
	case ROLE_ROOT: return _ROOT;
	case ROLE_SNAPSHOT: return _SNAPSHOT;
	case ROLE_TARGETS: return _TARGETS;
	case ROLE_TIMESTAMP: return _TIMESTAMP;
	default: return "";
	}
}

/**/
static time_t datetime_string_to_epoch(const char *s, time_t *epoch)
{
	struct tm tm;
	char *ret;

	/* 2022-09-09T18:13:01Z */
	ret = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
	if (ret == NULL) {
		log_error(("Invalid datetime string %s\n", s));
		return TUF_ERROR_INVALID_DATE_TIME;
	}
	tm.tm_isdst = 0; /* ignore DST */
	*epoch = mktime(&tm);
	if (*epoch < 0)
		return TUF_ERROR_INVALID_DATE_TIME;
	*epoch += tm.tm_gmtoff; /* compensate locale */
	return TUF_SUCCESS;
}

static bool is_expired(time_t expires, time_t reference_time)
{
	return expires < reference_time;
}

/*
 * Replace ['\', 'n'] occurences with ['\n', '\n'] to avoid key parsing errors
 * in mbedtls.
 */
static void replace_escape_chars_from_b64_string(unsigned char *s)
{
	unsigned char *p = s;
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

static enum tuf_role role_string_to_enum(const char *role_name, size_t role_name_len)
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

/*
 * Load common metadata fields from JSON "signed" section string into
 * tuf_metadata struct.
 */
static int parse_base_metadata(const char *data, int len, enum tuf_role role, struct tuf_metadata *base)
{
	const char *out_value;
	size_t out_value_len;
	JSONStatus_t result;
	int ret;
	char lower_case_type[12];

	/* Please validate before */
	result = JSON_SearchConst(data, len, "_type", strlen("_type"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_root_signed_metadata: \"_type\" not found\n"));
		return TUF_ERROR_INVALID_TYPE;
	}

	strncpy(lower_case_type, out_value, sizeof(lower_case_type));
	lower_case_type[0] = tolower(lower_case_type[0]); /* Allowing first char to be upper case */
	if (strncmp(lower_case_type, get_role_name(role), out_value_len)) {
		log_error(("parse_root_signed_metadata: Expected \"_type\" = %s, got %.*s instead\n", get_role_name(role), (int)out_value_len, out_value));
		return TUF_ERROR_INVALID_TYPE;
	}

	result = JSON_SearchConst(data, len, "version", strlen("version"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_base_metadata: \"version\" not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}
	sscanf(out_value, "%d", &base->version);
	result = JSON_SearchConst(data, len, "expires", strlen("expires"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_base_metadata: \"expires\" not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}
	strncpy(base->expires, out_value, out_value_len);
	ret = datetime_string_to_epoch(base->expires, &base->expires_epoch);
	// log_debug(("Converting %.*s => %d\n", out_value_len, out_value, base->expires_epoch));
	if (ret < 0)
		return ret;

	return TUF_SUCCESS;
}

/*
 * Load Root metadata fields from JSON "signed" section string into tuf_root
 * struct.
 */
static int parse_root_signed_metadata(const char *data, int len, struct tuf_root *target)
{
	JSONStatus_t result;
	JSONStatus_t result_internal;
	size_t value_length_internal;
	size_t value_length_internal_2;
	const char *out_value;
	size_t out_value_len;
	size_t start, next;
	size_t start_internal, next_internal;
	JSONPair_t pair, pair_internal;
	int key_index = 0;
	const char *out_value_internal;
	const char *out_value_internal_2;

	if (len <= 0)
		return -EINVAL;
	result = JSON_Validate(data, len);
	if (result != JSONSuccess) {
		log_error(("split_metadata: Got invalid JSON with len=%d: %.*s\n", len, len, data));
		return TUF_ERROR_INVALID_METADATA;
	}

	result = JSON_SearchConst(data, len, "keys", strlen("keys"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_root_signed_metadata: \"keys\" not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}

	/* For each key */
	start = 0;
	next = 0;
	while ((result = JSON_Iterate(out_value, out_value_len, &start, &next, &pair)) == JSONSuccess) {
		if (key_index >= TUF_MAX_KEY_COUNT) {
			log_error(("More keys than allowed (allowed=%d)\n", TUF_MAX_KEY_COUNT));
			return TUF_ERROR_FIELD_COUNT_EXCEEDED;
		}

		struct tuf_key *current_key = &target->keys[key_index];
		strncpy(current_key->id, pair.key, pair.keyLength);
		result_internal = JSON_SearchConst(pair.value, pair.valueLength, "keytype", strlen("keytype"), &out_value_internal, &value_length_internal, NULL);
		if (result_internal != JSONSuccess) {
			log_error(("'keytype' field not found. result_internal=%d\n", result_internal));
			return TUF_ERROR_FIELD_MISSING;
		}
		strncpy(current_key->keytype, out_value_internal, value_length_internal);

		result_internal = JSON_SearchConst(pair.value, pair.valueLength, "keyval", strlen("keyval"), &out_value_internal, &value_length_internal, NULL);
		if (result_internal != JSONSuccess) {
			log_error(("'keyval' field not found. result_internal=%d\n", result_internal));
			return TUF_ERROR_FIELD_MISSING;
		}

		result_internal = JSON_SearchConst(out_value_internal, value_length_internal, "public", strlen("public"), &out_value_internal_2, &value_length_internal_2, NULL);
		if (result_internal != JSONSuccess) {
			log_error(("'public' field not found. result_internal=%d\n", result_internal));
			return TUF_ERROR_FIELD_MISSING;
		}
		strncpy(current_key->keyval, out_value_internal_2, value_length_internal_2);
		// replace_escape_chars_from_b64_string(current_key->keyval);
		key_index++;

		target->keys_count = key_index;
	}

	result = JSON_SearchConst(data, len, "roles", strlen("roles"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_root_signed_metadata: \"roles\" not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}

	/* For each role */
	start = 0;
	next = 0;
	while ((result = JSON_Iterate(out_value, out_value_len, &start, &next, &pair)) == JSONSuccess) {
		enum tuf_role role = role_string_to_enum(pair.key, pair.keyLength);
		if (role == TUF_ROLES_COUNT) {
			log_error(("Invalid role name \"%.*s\"\n", (int)pair.keyLength, pair.key));
			return TUF_ERROR_INVALID_FIELD_VALUE;
		}

		result_internal = JSON_SearchConst(pair.value, pair.valueLength, "threshold", strlen("threshold"), &out_value_internal, &value_length_internal, NULL);
		if (result_internal != JSONSuccess) {
			log_error(("'threshold' field not found. result_internal=%d\n", result_internal));
			return TUF_ERROR_FIELD_MISSING;
		}
		sscanf(out_value_internal, "%d", &target->roles[role].threshold);

		result_internal = JSON_SearchConst(pair.value, pair.valueLength, "keyids", strlen("keyids"), &out_value_internal, &value_length_internal, NULL);
		if (result_internal != JSONSuccess) {
			log_error(("'keyids' field not found. result_internal=%d\n", result_internal));
			return TUF_ERROR_FIELD_MISSING;
		}

		key_index = 0;
		start_internal = 0;
		next_internal = 0;
		while ((result_internal = JSON_Iterate(out_value_internal, value_length_internal, &start_internal, &next_internal, &pair_internal)) == JSONSuccess) {
			strncpy(target->roles[role].keyids[key_index], pair_internal.value, pair_internal.valueLength);
			key_index++;
		}
	}
	target->loaded = true;
	return parse_base_metadata(data, len, ROLE_ROOT, &target->base);
}

/*
 * Initial parsing of metadata JSON, loading signatures into signatures array
 * and returning the "signed" section of the metadata as a separate string.
 *
 * The input data is not changed.
 */
static int split_metadata(const unsigned char *data, int len, struct tuf_signature *signatures, int signatures_max_count, const unsigned char **signed_value, int *signed_value_len)
{
	JSONStatus_t result;
	JSONStatus_t result_internal;
	size_t value_length_internal;
	const char *out_value;
	size_t out_value_len;
	size_t start, next;
	JSONPair_t pair;
	int signature_index = 0;
	const char *out_value_internal;
	struct tuf_signature *current_signature;
	int ret;

	result = JSON_Validate((const char *)data, len);
	if (len <= 0)
		return -EINVAL;
	if (result != JSONSuccess) {
		log_error(("split_metadata: Got invalid JSON: %s\n", data));
		return TUF_ERROR_INVALID_METADATA;
	}

	result = JSON_SearchConst((const char *)data, len, "signatures", strlen("signatures"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("handle_json_data: signatures not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}

	start = 0;
	next = 0;
	while ((result = JSON_Iterate(out_value, out_value_len, &start, &next, &pair)) == JSONSuccess) {
		if (signature_index >= signatures_max_count) {
			log_error(("More signatures than allowed (allowed=%d)\n", signatures_max_count));
			return TUF_ERROR_FIELD_COUNT_EXCEEDED;
		}

		current_signature = &signatures[signature_index];
		memset(current_signature, 0, sizeof(*current_signature));

		result_internal = JSON_SearchConst(pair.value, pair.valueLength, "keyid", strlen("keyid"), &out_value_internal, &value_length_internal, NULL);
		if (result_internal != JSONSuccess) {
			log_error(("'keyid' field not found. result_internal=%d\n", result_internal));
			return TUF_ERROR_FIELD_MISSING;
		}
		strncpy(current_signature->keyid, out_value_internal, value_length_internal);

		result_internal = JSON_SearchConst(pair.value, pair.valueLength, "method", strlen("method"), &out_value_internal, &value_length_internal, NULL);
		if (result_internal != JSONSuccess) {
			log_error(("'method' field not found\n"));
			return TUF_ERROR_FIELD_MISSING;
		}

		/* only rsassa-pss-sha256 is supported for now */
		if (strncmp(out_value_internal, "rsassa-pss-sha256", value_length_internal) != 0) {
			log_error(("unsupported signature method \"%.*s\". Skipping\n", (int)value_length_internal, out_value_internal));
			continue;
		}
		strncpy(current_signature->method, out_value_internal, value_length_internal);

		result_internal = JSON_SearchConst(pair.value, pair.valueLength, "sig", strlen("sig"), &out_value_internal, &value_length_internal, NULL);
		if (result_internal != JSONSuccess) {
			log_error(("'sig' field not found\n"));
			return TUF_ERROR_FIELD_MISSING;
		}

		ret = mbedtls_base64_decode(current_signature->sig, sizeof(current_signature->sig), &current_signature->sig_len, (const unsigned char *)out_value_internal, value_length_internal);
		if (ret != 0) {
			log_error(("error decoding base64 string\n"));
			return TUF_ERROR_INVALID_FIELD_VALUE;
		}

		current_signature->set = true;
		signature_index++;
	}

	result = JSON_SearchConst((const char *)data, len, "signed", strlen("signed"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("'signed' field not found"));
		return TUF_ERROR_FIELD_MISSING;
	}
	*signed_value = (unsigned const char *)out_value;
	*signed_value_len = out_value_len;

	return 0;
}

/*
 * Outputs binary data as hex string.
 */
static void print_hex(const char *title, const unsigned char buf[], size_t len)
{
	log_debug(("%s: ", title));

	for (size_t i = 0; i < len; i++)
		log_debug(("%02x", buf[i]));

	log_debug(("\r\n"));
}

/*
 * Convert a hex string in a bytes array.
 */
/* TODO: Verify safety of this function */
static void hextobin(const char *str, uint8_t *bytes, size_t blen)
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
	for (pos = 0; ((pos < (blen * 2)) && (pos < strnlen(str, blen * 2))); pos += 2) {
		idx0 = ((uint8_t)str[pos + 0] & 0x1F) ^ 0x10;
		idx1 = ((uint8_t)str[pos + 1] & 0x1F) ^ 0x10;
		bytes[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	}
}

/*
 * Calculate the SHA-256 hash of teh input data, comparing it to the expected
 * value.
 */
static int verify_data_hash_sha256(const unsigned char *data, int data_len, unsigned char *expected_hash256, size_t hash_len)
{
	unsigned char hash_output[TUF_HASH256_LEN]; /* SHA-256 outputs 32 bytes */

	if (hash_len != TUF_HASH256_LEN) {
		log_error(("Invalid hash length %ld\n", hash_len));
		return TUF_ERROR_INVALID_HASH_LENGTH;
	}

	/* 0 here means use the full SHA-256, not the SHA-224 variant */
	mbedtls_sha256(data, data_len, hash_output, 0);

	if (memcmp(expected_hash256, hash_output, sizeof(hash_output))) {
		log_debug(("Hash Verify Error\n"));
		print_hex("Expected", expected_hash256, TUF_HASH256_LEN);
		print_hex("Got", hash_output, TUF_HASH256_LEN);
		return TUF_ERROR_HASH_VERIFY_ERROR;
	}

	return TUF_SUCCESS;
}

/*
 * Calculates the signature of the input data, using the public key passed as
 * parameter, and compares it to the expected signature.
 *
 * rsassa-pss-sha256 mode only.
 */
static int verify_signature(const unsigned char *data, int data_len, unsigned char *signature_bytes, int signature_bytes_len, struct tuf_key *key)
{
	int ret;
	int exit_code = -1;
	mbedtls_pk_context pk;
	unsigned char hash[TUF_HASH256_LEN];
	const char *key_pem = (const char *)key->keyval;
	char cleaned_up_key_b64[TUF_KEY_VAL_MAX_LEN];

	mbedtls_pk_init(&pk);

	memset(cleaned_up_key_b64, 0, sizeof(cleaned_up_key_b64));
	strncpy(cleaned_up_key_b64, key_pem, TUF_KEY_VAL_MAX_LEN);
	replace_escape_chars_from_b64_string((unsigned char *)cleaned_up_key_b64);

	if ((ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)cleaned_up_key_b64, strlen(cleaned_up_key_b64) + 1)) != 0) {
		log_error(("verify_signature: failed. Could not read key. mbedtls_pk_parse_public_keyfile returned %d\n", ret));
		log_error(("key: %s\n", cleaned_up_key_b64));
		goto exit;
	}

	if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
		log_error(("verify_signature: Key is not an RSA key\n"));
		goto exit;
	}

	if ((ret = mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk),
					   MBEDTLS_RSA_PKCS_V21,
					   MBEDTLS_MD_SHA256)) != 0) {
		log_error(("verify_signature: Invalid padding\n"));
		goto exit;
	}

	/*
	 * Compute the SHA-256 hash of the input file and
	 * verify the signature
	 */
	if ((ret = mbedtls_md(
		     mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		     data, data_len, hash)) != 0) {
		log_error(("verify_signature: Could not open or read\n"));
		goto exit;
	}

	if ((ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0,
				     signature_bytes, signature_bytes_len)) != 0) {
		log_error(("verify_signature: failed  ! mbedtls_pk_verify returned %d\n", ret));
		exit_code = ret;
		goto exit;
	}

	exit_code = 0;

exit:
	mbedtls_pk_free(&pk);

	return exit_code;
}

/*
 * Get the public key from Root based on its keyid.
 */
static int get_key_by_id(struct tuf_root *root, const char *key_id, struct tuf_key **key)
{
	int i;

	for (i = 0; i < TUF_MAX_KEY_COUNT; i++) {
		if (!strcmp(root->keys[i].id, key_id)) {
			*key = &root->keys[i];
			return 0;
		}
	}
	return TUF_ERROR_KEY_ID_NOT_FOUND;
}

/*
 * Get the public key from Root based on its keyid, but only if the key matches
 * the requested role.
 */
static int get_public_key_by_id_and_role(struct tuf_root *root, enum tuf_role role, const char *key_id, struct tuf_key **key)
{
	int key_index;
	char *role_key_id;

	if (role >= TUF_ROLES_COUNT)
		return -EINVAL;

	if (root == NULL)
		return -EINVAL;

	for (key_index = 0; key_index < TUF_KEYIDS_PER_ROLE_MAX_COUNT; key_index++) {
		role_key_id = root->roles[role].keyids[key_index];
		if (!strcmp(role_key_id, key_id))
			return get_key_by_id(root, key_id, key);
	}

	return TUF_ERROR_KEY_ID_FOR_ROLE_NOT_FOUND;
}

/*
 * Verify the metadata signature for the given role.
 *
 * Only return TUF_SUCCESS if the number of valid signatures is >= the role
 * threshold.
 */
static int verify_data_signature_for_role(const unsigned char *signed_value, size_t signed_value_len, struct tuf_signature *signatures, enum tuf_role role, struct tuf_root *root)
{
	int ret;
	int signature_index;
	int threshold;
	int valid_signatures_count;
	struct tuf_key *key;

	threshold = updater.root.roles[role].threshold;
	valid_signatures_count = 0;
	for (signature_index = 0; signature_index < TUF_SIGNATURES_PER_ROLE_MAX_COUNT && valid_signatures_count < threshold; signature_index++) {
		// log_debug(("verify_data_signature_for_role role=%d, signature_index=%d\n", role, signature_index));
		if (!signatures[signature_index].set)
			break;

		ret = get_public_key_by_id_and_role(root, role, signatures[signature_index].keyid, &key);
		if (ret != 0)
			// log_debug(("get_public_key_by_id_and_role: not found. verify_data_signature_for_role role=%d, signature_index=%d\n", role, signature_index));
			continue;
		ret = verify_signature(signed_value, signed_value_len, signatures[signature_index].sig, signatures[signature_index].sig_len, key);

		if (!ret) {
			/* Found valid signature */
			// log_debug(("found valid signature. verify_data_signature_for_role role=%d, signature_index=%d\n", role, signature_index));
			valid_signatures_count++;
		}
	}

	if (valid_signatures_count < threshold)
		return TUF_ERROR_UNSIGNED_METADATA;
	else
		return TUF_SUCCESS;
}

/*
 * Get the expected SHA 256 hash value and length for the given role, based on
 * information available in previously loaded roles.
 *
 * Only valid for Snapshot and Targets role.
 */
static int get_expected_sha256_and_length_for_role(enum tuf_role role, unsigned char **sha256, size_t *length)
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

/*
 * Verify role metadata comparing input data with expected length and hashes.
 */
static int verify_length_and_hashes(const unsigned char *data, size_t len, enum tuf_role role)
{
	int ret;
	unsigned char *expected_sha256;
	size_t expected_length;

	ret = get_expected_sha256_and_length_for_role(role, &expected_sha256, &expected_length);
	if (ret != TUF_SUCCESS)
		return ret;

	if (len != expected_length) {
		log_error(("Expected %s length %ld, got %ld\n", get_role_name(role), expected_length, len));
		return TUF_ERROR_LENGTH_VERIFY_ERROR;
	}

	ret = verify_data_hash_sha256(data, len, expected_sha256, TUF_HASH256_LEN);
	if (ret != TUF_SUCCESS)
		return ret;

	return TUF_SUCCESS;
}

/*
 * Separate metadata signatures from "signed" section, checking if signature is
 * valid.
 *
 * Asssumes "signed" section is a canonical JSON, avoiding the need to parse and
 * re-generate a JSON string before validation.
 */
static int split_metadata_and_check_signature(const unsigned char *data, size_t file_size, enum tuf_role role, struct tuf_signature *signatures, const unsigned char **signed_value, int *signed_value_len, bool check_signature_and_hashes)
{
	int ret;

	ret = split_metadata(data, file_size, signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, signed_value, signed_value_len);
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
		// log_debug(("Verifying against current root ret = %d\n", ret));
		if (ret < 0)
			return ret;
	}
	return TUF_SUCCESS;
}

/*
 * Load the Root role metadata, validating it, and loading the resulting
 * information into updater struct.
 */
static int update_root(const unsigned char *data, size_t len, bool check_signature)
{
	// TODO: make sure check_signature is false only during unit testing
	int ret;
	const unsigned char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_PER_ROLE_MAX_COUNT];
	struct tuf_root new_root;

	memset(&new_root, 0, sizeof(new_root));
	ret = split_metadata_and_check_signature(data, len, ROLE_ROOT, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	// Parsing ROOT
	ret = parse_root_signed_metadata((const char *)signed_value, signed_value_len, &new_root);
	if (ret < 0)
		return ret;

	if (check_signature) {
		// check signature using current new root key
		ret = verify_data_signature_for_role(signed_value, signed_value_len, signatures, ROLE_ROOT, &new_root);
		// log_debug(("Verifying against new root ret = %d\n", ret));
		if (ret < 0)
			return ret;
	}

	memcpy(&updater.root, &new_root, sizeof(updater.root));

	return ret;
}

static int parse_tuf_file_info(const char *data, size_t len, struct tuf_role_file *target)
{
	JSONStatus_t result;
	const char *out_value;
	size_t out_value_len;

	result = JSON_SearchConst(data, len, "hashes" TUF_JSON_QUERY_KEY_SEPARATOR "sha256", strlen("hashes" TUF_JSON_QUERY_KEY_SEPARATOR "sha256"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_timestamp_signed_metadata: \"hashes" TUF_JSON_QUERY_KEY_SEPARATOR "sha256\" not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}

	if (out_value_len != TUF_HASH256_LEN * 2) {
		log_error(("parse_timestamp_signed_metadata: invalid \"hashes" TUF_JSON_QUERY_KEY_SEPARATOR "sha256\" length: %ld\n", out_value_len));
		return TUF_ERROR_INVALID_FIELD_VALUE;
	}
	hextobin(out_value, target->hash_sha256, TUF_HASH256_LEN);

	result = JSON_SearchConst(data, len, "length", strlen("length"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_timestamp_signed_metadata: \"length\" not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}
	sscanf(out_value, "%ld", &target->length);

	result = JSON_SearchConst(data, len, "version", strlen("version"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_timestamp_signed_metadata: \"version\" not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}
	sscanf(out_value, "%d", &target->version);
	target->loaded = true;
	return TUF_SUCCESS;
}

static int parse_timestamp_signed_metadata(const char *data, int len, struct tuf_timestamp *target)
{
	JSONStatus_t result;
	const char *out_value;
	size_t out_value_len;
	int ret;

	memset(target, 0, sizeof(*target));
	result = JSON_Validate(data, len);
	if (result != JSONSuccess) {
		log_error(("parse_timestamp_signed_metadata: Got invalid JSON: %s\n", data));
		return TUF_ERROR_INVALID_METADATA;
	}

	result = JSON_SearchConst(data, len, "meta" TUF_JSON_QUERY_KEY_SEPARATOR "snapshot.json", strlen("meta" TUF_JSON_QUERY_KEY_SEPARATOR "snapshot.json"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_timestamp_signed_metadata: \"meta" TUF_JSON_QUERY_KEY_SEPARATOR "snapshot.json\" not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}

	ret = parse_tuf_file_info(out_value, out_value_len, &target->snapshot_file);
	if (ret < 0)
		return ret;

	target->loaded = true;

	return parse_base_metadata(data, len, ROLE_TIMESTAMP, &target->base);
}

static int update_timestamp(const unsigned char *data, size_t len, bool check_signature)
{
	int ret;
	const unsigned char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_PER_ROLE_MAX_COUNT];
	struct tuf_timestamp new_timestamp;

	memset(&new_timestamp, 0, sizeof(new_timestamp));

	ret = split_metadata_and_check_signature(data, len, ROLE_TIMESTAMP, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	// Parsing Timestamp
	ret = parse_timestamp_signed_metadata((const char *)signed_value, signed_value_len, &new_timestamp);
	if (ret < 0)
		return ret;
	/*
	 * If an existing trusted timestamp is updated,
	 * check for a rollback attack
	 */
	if (updater.timestamp.loaded) {
		/* Prevent rolling back timestamp version */
		if (new_timestamp.base.version < updater.timestamp.base.version) {
			log_error(("New timestamp version %d must be >= %d", new_timestamp.base.version, updater.timestamp.base.version));
			return TUF_ERROR_BAD_VERSION_NUMBER;
		}
		/* Keep using old timestamp if versions are equal */
		if (new_timestamp.base.version == updater.timestamp.base.version)
			return TUF_ERROR_SAME_VERSION;

		/* Prevent rolling back snapshot version */
		if (new_timestamp.snapshot_file.version < updater.timestamp.snapshot_file.version) {
			log_error(("New snapshot version %d must be >= %d", new_timestamp.snapshot_file.version, updater.timestamp.snapshot_file.version));
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


static int parse_snapshot_signed_metadata(const char *data, int len, struct tuf_snapshot *target)
{
	JSONStatus_t result;
	const char *out_value;
	size_t out_value_len;

	memset(target, 0, sizeof(*target));
	result = JSON_Validate(data, len);
	if (result != JSONSuccess) {
		log_error(("parse_snapshot_signed_metadata: Got invalid JSON: %s\n", data));
		return TUF_ERROR_INVALID_METADATA;
	}

	/* Get root.json file info */
	result = JSON_SearchConst(data, len, "meta" TUF_JSON_QUERY_KEY_SEPARATOR "root.json", strlen("meta" TUF_JSON_QUERY_KEY_SEPARATOR "root.json"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_timestamp_signed_metadata: \"meta" TUF_JSON_QUERY_KEY_SEPARATOR "root.json\" not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}
	parse_tuf_file_info(out_value, out_value_len, &target->root_file);

	/* Get targets.json file info */
	result = JSON_SearchConst(data, len, "meta" TUF_JSON_QUERY_KEY_SEPARATOR "targets.json", strlen("meta" TUF_JSON_QUERY_KEY_SEPARATOR "targets.json"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_timestamp_signed_metadata: \"meta" TUF_JSON_QUERY_KEY_SEPARATOR "targets.json\" not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}
	parse_tuf_file_info(out_value, out_value_len, &target->targets_file);

	target->loaded = true;

	return parse_base_metadata(data, len, ROLE_SNAPSHOT, &target->base);
}

static int parse_targets_metadata(const char *data, int len, struct tuf_targets *target)
{
	JSONStatus_t result;
	const char *out_value;
	size_t out_value_len;
	size_t start, next;
	JSONPair_t pair;
	int ret;

	memset(target, 0, sizeof(*target));
	result = JSON_Validate(data, len);
	if (result != JSONSuccess) {
		log_error(("parse_targets_metadata: Got invalid JSON: %s\n", data));
		return TUF_ERROR_INVALID_METADATA;
	}

	result = JSON_SearchConst(data, len, "targets", strlen("targets"), &out_value, &out_value_len, NULL);
	if (result != JSONSuccess) {
		log_error(("parse_targets_metadata: \"targets\" not found\n"));
		return TUF_ERROR_FIELD_MISSING;
	}

	/* Iterate over each target */
	start = 0;
	next = 0;
	while ((result = JSON_Iterate(out_value, out_value_len, &start, &next, &pair)) == JSONSuccess) {
		ret = tuf_parse_single_target(pair.key, pair.keyLength, pair.value, pair.valueLength, updater.application_context);
		if (ret < 0) {
			log_error(("Error processing target %.*s\n", (int)pair.keyLength, pair.key));
			break;
		}
	}

	target->loaded = true;

	return parse_base_metadata(data, len, ROLE_TARGETS, &target->base);
}

static int check_final_timestamp()
{
	// Return error if timestamp is expired
	if (!updater.timestamp.loaded) {
		log_error(("BUG: !updater.timestamp.loaded\n"));
		return TUF_ERROR_BUG;
	}

	if (is_expired(updater.timestamp.base.expires_epoch, updater.reference_time)) {
		log_error(("timestamp.json is expired\n"));
		return TUF_ERROR_EXPIRED_METADATA;
	}

	return TUF_SUCCESS;
}

static int check_final_snapshot()
{
	// Return error if snapshot is expired or meta version does not match

	if (!updater.snapshot.loaded) {
		log_error(("BUG: !updater.snapshot.loaded\n"));
		return TUF_ERROR_BUG;
	}
	if (!updater.timestamp.loaded) {
		log_error(("BUG: !updater.timestamp.loaded\n"));
		return TUF_ERROR_BUG;
	}

	if (is_expired(updater.snapshot.base.expires_epoch, updater.reference_time)) {
		log_error(("snapshot.json is expired\n"));
		return TUF_ERROR_EXPIRED_METADATA;
	}

	if (updater.snapshot.base.version != updater.timestamp.snapshot_file.version) {
		log_error(("Expected snapshot version %d, got %d", updater.timestamp.snapshot_file.version, updater.snapshot.base.version));
		return TUF_ERROR_BAD_VERSION_NUMBER;
	}
	return TUF_SUCCESS;
}

// TODO: add trusted parameter logic, check if it is required
static int update_snapshot(const unsigned char *data, size_t len, bool check_signature)
{
	int ret;
	const unsigned char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_PER_ROLE_MAX_COUNT];
	struct tuf_snapshot new_snapshot;

	memset(&new_snapshot, 0, sizeof(new_snapshot));

	log_debug(("Updating snapshot\n"));

	if (!updater.timestamp.loaded) {
		log_error(("Cannot update snapshot before timestamp\n"));
		return TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED;
	}

	if (updater.targets.loaded) {
		log_error(("Cannot update snapshot after targets\n"));
		return TUF_ERROR_TARGETS_ROLE_LOADED;
	}

	// Snapshot cannot be loaded if final timestamp is expired
	ret = check_final_timestamp();
	if (ret < 0)
		return ret;

	ret = split_metadata_and_check_signature(data, len, ROLE_SNAPSHOT, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	ret = parse_snapshot_signed_metadata((const char *)signed_value, signed_value_len, &new_snapshot);
	if (ret < 0)
		return ret;

	// version not checked against meta version to allow old snapshot to be
	// used in rollback protection: it is checked when targets is updated

	// # If an existing trusted snapshot is updated, check for rollback attack
	if (updater.snapshot.loaded) {
		/* Prevent removal of any metadata in meta */
		if (updater.snapshot.root_file.loaded && !new_snapshot.root_file.loaded) {
			log_error(("New snapshot is missing info for 'root'\n"));
			return TUF_ERROR_REPOSITORY_ERROR;
		}

		/* Prevent rollback of root version */
		if (new_snapshot.root_file.version < updater.snapshot.root_file.version) {
			log_error(("Expected root version %d, got %d\n", updater.snapshot.root_file.version, new_snapshot.root_file.version));
			return TUF_ERROR_BAD_VERSION_NUMBER;
		}

		/* Prevent removal of any metadata in meta */
		if (updater.snapshot.targets_file.loaded && !new_snapshot.targets_file.loaded) {
			log_error(("New snapshot is missing info for 'targets'\n"));
			return TUF_ERROR_REPOSITORY_ERROR;
		}

		/* Prevent rollback of targets version */
		if (new_snapshot.targets_file.version < updater.snapshot.targets_file.version) {
			log_error(("Expected targets version >= %d, got %d\n", updater.snapshot.targets_file.version, new_snapshot.targets_file.version));
			return TUF_ERROR_BAD_VERSION_NUMBER;
		}
	}

	// expiry not checked to allow old snapshot to be used for rollback
	// protection of new snapshot: it is checked when targets is updated

	memcpy(&updater.snapshot, &new_snapshot, sizeof(updater.snapshot));
	log_info(("Updated snapshot v%d\n", new_snapshot.targets_file.version));

	// snapshot is loaded, but we raise if it's not valid _final_ snapshot
	ret = check_final_snapshot();
	if (ret < 0)
		return ret;

	return ret;
}

static int update_targets(const unsigned char *data, size_t len, bool check_signature)
{
	int ret;
	const unsigned char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_PER_ROLE_MAX_COUNT];
	struct tuf_targets new_targets;

	memset(&new_targets, 0, sizeof(new_targets));

	if (!updater.snapshot.loaded) {
		log_error(("Cannot load targets before snapshot"));
		return TUF_ERROR_SNAPSHOT_ROLE_NOT_LOADED;
	}

	// Targets cannot be loaded if final snapshot is expired or its version
	// does not match meta version in timestamp
	ret = check_final_snapshot();
	if (ret < 0)
		return ret;


	if (!updater.root.loaded) {
		log_error(("Cannot load targets before root"));
		return TUF_ERROR_ROOT_ROLE_NOT_LOADED;
	}

	ret = split_metadata_and_check_signature(data, len, ROLE_TARGETS, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	ret = parse_targets_metadata((const char *)signed_value, signed_value_len, &new_targets);
	if (ret < 0)
		return ret;

	if (updater.snapshot.targets_file.version != new_targets.base.version) {
		log_error(("Expected targets v%d, got v%d\n", updater.snapshot.targets_file.version, new_targets.base.version));
		return TUF_ERROR_BAD_VERSION_NUMBER;
	}

	if (is_expired(new_targets.base.expires_epoch, updater.reference_time)) {
		log_error(("New targets is expired\n"));
		return TUF_ERROR_EXPIRED_METADATA;
	}

	memcpy(&updater.targets, &new_targets, sizeof(updater.targets));
	log_debug(("Updated targets v%d\n", new_targets.base.version));

	return TUF_SUCCESS;
}


/* TODO: Not sure if read_local_file should receive string or enum tuf_role */
int load_local_metadata(enum tuf_role role, unsigned char *target_buffer, size_t limit, size_t *file_size)
{
	int ret;

	ret = read_local_file(role, target_buffer, limit, file_size);
	return ret;
}


int persist_metadata(enum tuf_role role, const unsigned char *data, size_t len)
{
	int ret;

	ret = write_local_file(role, data, len);
	return ret;
}

int download_metadata(enum tuf_role role, unsigned char *target_buffer, size_t limit, int version, size_t *file_size)
{
	const char *role_name = get_role_name(role);
	char role_file_name[30];
	int ret;

	if (version == 0)
		snprintf(role_file_name, sizeof(role_file_name), "%s.json", role_name);
	else
		snprintf(role_file_name, sizeof(role_file_name), "%d.%s.json", version, role_name);
	ret = fetch_file(role_file_name, target_buffer, limit, file_size);
	return ret;
}

static int load_root()
{
	// Update the root role
	size_t file_size;
	int ret;
	int lower_bound, upper_bound, next_version;

	ret = load_local_metadata(ROLE_ROOT, updater.data_buffer, updater.data_buffer_len, &file_size);
	if (ret < 0) {
		log_debug(("local root not found\n"));
		return ret;
	}

	ret = update_root(updater.data_buffer, file_size, true);
	if (ret < 0)
		return ret;

	lower_bound = updater.root.base.version + 1;
	upper_bound = lower_bound + config.max_root_rotations;

	for (next_version = lower_bound; next_version < upper_bound; next_version++) {
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

static int load_timestamp()
{
	size_t file_size;
	int ret;

	ret = load_local_metadata(ROLE_TIMESTAMP, updater.data_buffer, updater.data_buffer_len, &file_size);
	if (ret < 0) {
		log_debug(("local timestamp not found. Proceeding\n"));
	} else {
		ret = update_timestamp(updater.data_buffer, file_size, true);
		if (ret < 0)
			log_debug(("local timestamp is not valid. Proceeding\n"));
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

	return TUF_SUCCESS;
}

static int load_snapshot()
{
	/* Load local (and if needed remote) snapshot metadata */
	size_t file_size;
	int ret;
	size_t max_length;

	ret = load_local_metadata(ROLE_SNAPSHOT, updater.data_buffer, updater.data_buffer_len, &file_size);
	if (ret < 0) {
		log_debug(("local snapshot not found. Proceeding\n"));
	} else {
		ret = update_snapshot(updater.data_buffer, file_size, true);
		if (ret < 0)
			log_debug(("local snapshot is not valid. Proceeding\n"));
		else
			return TUF_SUCCESS;
	}

	if (!updater.timestamp.loaded) {
		log_error(("BUG: !updater.timestamp.loaded\n"));
		return TUF_ERROR_BUG;
	}

	max_length = config.snapshot_max_length;
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

	return TUF_SUCCESS;
}

static int load_targets()
{
	size_t file_size;
	int ret;
	size_t max_length;

	log_debug(("load_targets: begin\n"));
	// Avoid loading 'role' more than once during "get_targetinfo" -> TODO: does this apply to us?
	if (updater.targets.loaded)
		return TUF_SUCCESS;

	ret = load_local_metadata(ROLE_TARGETS, updater.data_buffer, updater.data_buffer_len, &file_size);
	if (ret < 0) {
		log_debug(("local targets not found. Proceeding\n"));
	} else {
		ret = update_targets(updater.data_buffer, file_size, true);
		if (ret < 0) {
			log_debug(("local targets is not valid. Proceeding\n"));
		} else {
			log_debug(("local targets is valid: not downloading new one\n"));
			return TUF_SUCCESS;
		}
	}

	if (!updater.snapshot.loaded) {
		log_error(("Snapshot role is not loaded"));
		return TUF_ERROR_BUG;
	}

	max_length = config.targets_max_length;

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

	return TUF_SUCCESS;
}

int tuf_updater_init()
{
	memset(&updater, 0, sizeof(updater));
	updater.reference_time = get_current_gmt_time();
	updater.application_context = tuf_get_application_context();
	tuf_get_application_buffer(&updater.data_buffer, &updater.data_buffer_len);
	return TUF_SUCCESS;
}

int refresh()
{
	int ret;

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
