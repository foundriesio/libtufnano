/*
 * Copyright 2022 Foundries.io
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#define _GNU_SOURCE
#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include "mbedtls/rsa.h"
#include "mbedtls/error.h"

#include "unity.h"
#include "unity_fixture.h"

#include "libtufnano.h"
#include "libtufnano_internal.h"
#include "libtufnano_config.h"
#include "libtufnano_annex.h"

#define TUF_TEST_FILES_PATH "../test/sample_jsons"

extern struct tuf_updater updater;

/* tests only */
int fetch_role_and_check_signature(const char *file_base_name, enum tuf_role role, struct tuf_signature *signatures, const unsigned char **signed_value, int *signed_value_len, bool check_signature_and_hashes)
{
	int ret = -1;
	size_t file_size;

	ret = tuf_client_fetch_file(file_base_name, updater.data_buffer, updater.data_buffer_len, &file_size, updater.application_context);
	if (ret != 0)
		return ret;

	ret = split_metadata_and_check_signature(updater.data_buffer, file_size, role, signatures, signed_value, signed_value_len, check_signature_and_hashes);
	if (ret < 0)
		return ret;
	return TUF_SUCCESS;
}


/* tests only */
int parse_root(const char *file_base_name, bool check_signature)
{
	int ret = -1;
	const unsigned char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_PER_ROLE_MAX_COUNT];
	struct tuf_root new_root;

	memset(&new_root, 0, sizeof(new_root));

	ret = fetch_role_and_check_signature(file_base_name, ROLE_ROOT, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	ret = parse_root_signed_metadata((const char*)signed_value, signed_value_len, &new_root);
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


/* tests only */
int parse_timestamp(const char *file_base_name, bool check_signature)
{
	int ret = -1;
	const unsigned char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_PER_ROLE_MAX_COUNT];
	struct tuf_timestamp new_timestamp;

	memset(&new_timestamp, 0, sizeof(new_timestamp));

	ret = fetch_role_and_check_signature(file_base_name, ROLE_TIMESTAMP, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	// Parsing Timestamp
	ret = parse_timestamp_signed_metadata((const char*)signed_value, signed_value_len, &new_timestamp);
	if (ret < 0)
		return ret;

	memcpy(&updater.timestamp, &new_timestamp, sizeof(updater.timestamp));
	return ret;
}

/* tests only */
int parse_snapshot(const char *file_base_name, bool check_signature)
{
	int ret = -1;
	const unsigned char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_PER_ROLE_MAX_COUNT];
	struct tuf_snapshot new_snapshot;

	memset(&new_snapshot, 0, sizeof(new_snapshot));

	if (!updater.timestamp.loaded)
		return TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED;

	ret = fetch_role_and_check_signature(file_base_name, ROLE_SNAPSHOT, signatures, &signed_value, &signed_value_len, check_signature);
	if (ret != 0)
		return ret;

	ret = parse_snapshot_signed_metadata((const char*)signed_value, signed_value_len, &new_snapshot);
	if (ret < 0)
		return ret;

	memcpy(&updater.snapshot, &new_snapshot, sizeof(updater.snapshot));
	return ret;
}


/* for unit tests only */
int verify_data_signature(const unsigned char *data, size_t data_len, const char *signing_public_key_b64, size_t signing_public_key_b64_len)
{
	int ret = -1;
	int signature_index;
	const unsigned char *signed_value;
	int signed_value_len;
	struct tuf_signature signatures[TUF_SIGNATURES_PER_ROLE_MAX_COUNT];

	memset(&signatures, 0, sizeof(signatures));
	ret = split_metadata(data, data_len, signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	if (ret < 0)
		return ret;

	for (signature_index = 0; signature_index < TUF_SIGNATURES_PER_ROLE_MAX_COUNT; signature_index++) {
		if (!signatures[signature_index].set)
			break;

		struct tuf_key key;
		memset(&key, 0, sizeof(key));
		memcpy(key.keyval, signing_public_key_b64, signing_public_key_b64_len);
		ret = verify_signature(signed_value, signed_value_len, signatures[signature_index].sig, signatures[signature_index].sig_len, &key);
		if (!ret)
			/* Found valid signature */
			return ret;
	}
	/* No valid signature found */
	return ret;
}

/* for unit tests only */
int verify_file_signature(const char *file_base_name, const char *signing_key_file)
{
	unsigned char signing_public_key_b64[TUF_KEY_VAL_MAX_LEN];
	size_t file_size, key_file_size;
	int ret;

	ret = read_file_posix(file_base_name, updater.data_buffer, updater.data_buffer_len, TUF_TEST_FILES_PATH "/rsa", &file_size);
	if (ret < 0)
		return -1;


	ret = read_file_posix(signing_key_file, signing_public_key_b64, sizeof(signing_public_key_b64), TUF_TEST_FILES_PATH "/rsa", &key_file_size);
	if (ret < 0)
		return -20;

	return verify_data_signature(updater.data_buffer, file_size, (const char*)signing_public_key_b64, key_file_size);
}

/* for unit tests only */
int verify_file_hash(const char *file_base_name, const char *sha256_file)
{
	unsigned char hash256_b16[TUF_HASH256_LEN * 2];
	unsigned char hash256[TUF_HASH256_LEN];
	size_t file_size, hash_file_size;
	int ret;

	ret = read_file_posix(file_base_name, updater.data_buffer, updater.data_buffer_len, TUF_TEST_FILES_PATH "/rsa", &file_size);
	if (ret < 0)
		return -1;

	ret = read_file_posix(sha256_file, hash256_b16, sizeof(hash256_b16), TUF_TEST_FILES_PATH "/rsa", &hash_file_size);
	if (ret < 0)
		return -30;

	hex_to_bin((const char*)hash256_b16, hash256, TUF_HASH256_LEN);
	log_debug(("Verifying hash for %s\n", file_base_name));
	return verify_data_hash_sha256(updater.data_buffer, file_size, hash256, TUF_HASH256_LEN);
}


/**
 * @brief Test group definition.
 */


TEST_GROUP(Full_LibTufNAno);

void *tuf_get_application_context(const char *provisioning_path, const char *local_path, const char *remote_path);
int tuf_get_application_buffer(unsigned char **buffer, size_t *buffer_size);

TEST_SETUP(Full_LibTufNAno){
	size_t data_buffer_len;
	unsigned char *data_buffer;

	tuf_get_application_buffer(&data_buffer, &data_buffer_len);
	tuf_updater_init(tuf_get_application_context(NULL, "../test/nvs", TUF_TEST_FILES_PATH "/rsa"), get_current_gmt_time(), data_buffer, data_buffer_len);
}

TEST_TEAR_DOWN(Full_LibTufNAno){
}

TEST_GROUP_RUNNER(Full_LibTufNAno){
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestTimestampSignature);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestMixedSignatures);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestSnapshotSignature);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestTargetSignature);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestRootSignature);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestRoot1Load);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestRoot2Load);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestRootUpdateCheck);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestTimestampLoadWithoutRoot);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestTimestampLoad);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestSnapshotLoadWithoutTimestamp);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestSnapshotLoad);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestSha256);
	// RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestFullLoadRootOperation);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestRefreshOK);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestRefreshEllipticCurveOK);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestRefreshErrors);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestBasicFunctions);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestFinalTimestamp);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestFinalSnapshot);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestRoleCheckingFunctions);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestSplitMetadata);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestParseBaseMetadata);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestParseTufInfo);
	RUN_TEST_CASE(Full_LibTufNAno, libTufNano_TestUpdateSnapshot);
}

TEST(Full_LibTufNAno, libTufNano_TestTimestampSignature){
	int ret;

	ret = verify_file_signature("timestamp.json", "timestamp.json.sig_key");
	TEST_ASSERT_EQUAL(0, ret);
}

TEST(Full_LibTufNAno, libTufNano_TestSnapshotSignature){
	int ret;

	ret = verify_file_signature("snapshot.json", "snapshot.json.sig_key");
	TEST_ASSERT_EQUAL(0, ret);
}

TEST(Full_LibTufNAno, libTufNano_TestTargetSignature){
	int ret;

	ret = verify_file_signature("targets.json", "targets.json.sig_key");
	TEST_ASSERT_EQUAL(0, ret);
}


TEST(Full_LibTufNAno, libTufNano_TestRootSignature){
	int ret;

	ret = verify_file_signature("1.root.json", "1.root.json.sig_key");
	TEST_ASSERT_EQUAL(0, ret);
}

TEST(Full_LibTufNAno, libTufNano_TestMixedSignatures){
	int ret;

	ret = verify_file_signature("timestamp.json", "snapshot.json.sig_key");
	TEST_ASSERT_EQUAL(MBEDTLS_ERR_RSA_INVALID_PADDING, ret);
}

/* tests only */
static int get_public_key_for_role(struct tuf_root *root, enum tuf_role role, int key_index, struct tuf_key **key)
{
	char *keyid;

	if (role >= TUF_ROLES_COUNT)
		return -EINVAL;

	if (root == NULL)
		return -EINVAL;

	keyid = root->roles[role].keyids[key_index];

	return get_key_by_id(root, keyid, key);
}

TEST(Full_LibTufNAno, libTufNano_TestRoot1Load){
	int ret;

	ret = parse_root("1.root.json", true);

	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_STRING("2e6d5e7f1469cb08be5f371ff5f211a45005223e5aff20815f36880c9bd418cb", updater.root.keys[0].id);
	TEST_ASSERT_EQUAL_STRING("8e126cc4e3ed6eaf4b638216c856c12ae2d8fa36b0b646bad1c98581a3d8e0df", updater.root.keys[1].id);
	TEST_ASSERT_EQUAL_STRING("9d99928f808ecd9b10ad171312adc80248d2eb3e58082c2aad239f9928c2479b", updater.root.keys[2].id);
	TEST_ASSERT_EQUAL_STRING("c0919e0f82b94be9eef55dcd5f224d8d8b4da80299a4ebef58018ab68fee0a8d", updater.root.keys[3].id);

	TEST_ASSERT_EQUAL_STRING("RSA", updater.root.keys[0].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", updater.root.keys[1].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", updater.root.keys[2].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", updater.root.keys[3].keytype);

	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstQmVmyZIA2tejyNDkug\\npUsncb2cBGl/vGkrsDJQvxTPpNnmtRQTdQoZ/qqPWonNZ/JEJRVL1xc24ioyx/dS\\nCKvdZzAsIxSoklxoDslSP8jDKwdFLj34snGBgtdDJ+bh44Oei6532GX5iy7Xj3SE\\na5pVoQ6nLWz5AULw7gmR01qIA3J1OZ7oVhR5hF4W/gNc8hAQg1gMRSrm+PUxzRr2\\n5YfZznE9JVsvuTi/e0iMDBeE1cXlUzo1/B2b+7072xlBsGP61tuln6c6kRA7PbIg\\nHX5Q+vs7svBY3wl07an8IxvHi9iZUYW9V8HH67/jJxree04kjC2KhaozEJLITwE0\\n4QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 updater.root.keys[0].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkvZdqvdobQJn/L0wLPYC\\nPmZgAvEnvVRaAe7q6aTPCMVXUXLt45jrr9tpvyhNyy/EfUP1RngToHAQAYieG9Wf\\nzzenGNIg57c9F2vT1ga4KwBTwnvk6qsoVINL4nJwQWRAQJbxJfkcuhWDBc1R+OjF\\nze6eYTm71AIyZiz4UR63FsVgXkM5wnCC82/0XhyKpxVI/y7N1l/wQ8toKbb3wF0K\\nIcsna0HfxvaS17lVA20fNr3KSqfg49j7ReuBNEl4QCZWhQ6xY/5zsYLYeMv4N/Bz\\n/AfyMl2QvQVf3gblem4lXoqNeRbDmVcwaNZahP0goYs0o+lCFDOyiftTazetfiat\\nowIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 updater.root.keys[1].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr3K10h/xn11pGn8DH+vv\\nQ3gK+NB9oVKQ8+6bh4ovo6tEVc64Wwk3pWM3QkqunMmOHusgCeLo+q97LIMcS/IZ\\nYUE+pHTGdxlnJknyJBNscaF74BPQQ5crIuRdBxfcLOgniq3e48drtIN0dlNpsDcT\\nyBCUJHDV4tALOd6tTEV44bnmGacM/VQZdEG+Q4UUnao/AugZ/T+9DaUbPoBUrlPN\\n6Yn5Al5/y/oR22OrPbcNt2dIylqWxy2h21dJJuIt5EOsIuzFwP1uXr+rimIZtme6\\nSJLS7CMJ9DzeACRLr/F+KMSu8XpCvSVp6nSlao1hCzbSGLhK1jaUe01aOSk6xYKs\\n4wIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 updater.root.keys[2].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX9EqnICo4ewErN82S00\\nWmCPhEfoEDwpG593Kh1E04MDC+PB3YIdkcqFTSeMkZW25GgWclLyDEAuUmGEO6yN\\nrR1S4/e36ImiIW2vEZhlMIX8a/SEb11Rhkvi/GRpt/ZyLp1El4M17nYO/GnYr1dE\\nhn2PCaZIo3jVuxmZ/+nzY/9whanjKoomGRcGlAne927DHYV0XiI1dBt+4gvpMdXp\\nEH8ZCHPQHjsUe0S433niVMIa4pIaQWvdEFliJ703Dqbxn1iVHUi+p8j+z6oh2v1z\\nZz0aiECwKOtRsGUNtJWeZfx5ZOOoeKyE47DZXPsolw7DlJxZRZlGny1KpX8Y0yTA\\n7QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 updater.root.keys[3].keyval);

	TEST_ASSERT_EQUAL(1, updater.root.roles[ROLE_SNAPSHOT].threshold);
	TEST_ASSERT_EQUAL(1, updater.root.roles[ROLE_TARGETS].threshold);
	TEST_ASSERT_EQUAL(1, updater.root.roles[ROLE_TIMESTAMP].threshold);
	TEST_ASSERT_EQUAL(1, updater.root.roles[ROLE_ROOT].threshold);

	TEST_ASSERT_EQUAL_STRING("2e6d5e7f1469cb08be5f371ff5f211a45005223e5aff20815f36880c9bd418cb", updater.root.roles[ROLE_SNAPSHOT].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("9d99928f808ecd9b10ad171312adc80248d2eb3e58082c2aad239f9928c2479b", updater.root.roles[ROLE_TARGETS].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("c0919e0f82b94be9eef55dcd5f224d8d8b4da80299a4ebef58018ab68fee0a8d", updater.root.roles[ROLE_TIMESTAMP].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("8e126cc4e3ed6eaf4b638216c856c12ae2d8fa36b0b646bad1c98581a3d8e0df", updater.root.roles[ROLE_ROOT].keyids[0]);


	TEST_ASSERT_EQUAL_STRING("2022-10-14T19:55:13Z", updater.root.base.expires);
	TEST_ASSERT_EQUAL(1665777313, updater.root.base.expires_epoch);

	TEST_ASSERT_EQUAL(1, updater.root.base.version);

	struct tuf_key *key;

	ret = get_public_key_for_role(&updater.root, ROLE_SNAPSHOT, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstQmVmyZIA2tejyNDkug\\npUsncb2cBGl/vGkrsDJQvxTPpNnmtRQTdQoZ/qqPWonNZ/JEJRVL1xc24ioyx/dS\\nCKvdZzAsIxSoklxoDslSP8jDKwdFLj34snGBgtdDJ+bh44Oei6532GX5iy7Xj3SE\\na5pVoQ6nLWz5AULw7gmR01qIA3J1OZ7oVhR5hF4W/gNc8hAQg1gMRSrm+PUxzRr2\\n5YfZznE9JVsvuTi/e0iMDBeE1cXlUzo1/B2b+7072xlBsGP61tuln6c6kRA7PbIg\\nHX5Q+vs7svBY3wl07an8IxvHi9iZUYW9V8HH67/jJxree04kjC2KhaozEJLITwE0\\n4QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 key->keyval);

	ret = get_public_key_for_role(&updater.root, ROLE_TARGETS, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr3K10h/xn11pGn8DH+vv\\nQ3gK+NB9oVKQ8+6bh4ovo6tEVc64Wwk3pWM3QkqunMmOHusgCeLo+q97LIMcS/IZ\\nYUE+pHTGdxlnJknyJBNscaF74BPQQ5crIuRdBxfcLOgniq3e48drtIN0dlNpsDcT\\nyBCUJHDV4tALOd6tTEV44bnmGacM/VQZdEG+Q4UUnao/AugZ/T+9DaUbPoBUrlPN\\n6Yn5Al5/y/oR22OrPbcNt2dIylqWxy2h21dJJuIt5EOsIuzFwP1uXr+rimIZtme6\\nSJLS7CMJ9DzeACRLr/F+KMSu8XpCvSVp6nSlao1hCzbSGLhK1jaUe01aOSk6xYKs\\n4wIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 key->keyval);


	ret = get_public_key_for_role(&updater.root, ROLE_TIMESTAMP, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX9EqnICo4ewErN82S00\\nWmCPhEfoEDwpG593Kh1E04MDC+PB3YIdkcqFTSeMkZW25GgWclLyDEAuUmGEO6yN\\nrR1S4/e36ImiIW2vEZhlMIX8a/SEb11Rhkvi/GRpt/ZyLp1El4M17nYO/GnYr1dE\\nhn2PCaZIo3jVuxmZ/+nzY/9whanjKoomGRcGlAne927DHYV0XiI1dBt+4gvpMdXp\\nEH8ZCHPQHjsUe0S433niVMIa4pIaQWvdEFliJ703Dqbxn1iVHUi+p8j+z6oh2v1z\\nZz0aiECwKOtRsGUNtJWeZfx5ZOOoeKyE47DZXPsolw7DlJxZRZlGny1KpX8Y0yTA\\n7QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 key->keyval);

	ret = get_public_key_for_role(&updater.root, ROLE_ROOT, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkvZdqvdobQJn/L0wLPYC\\nPmZgAvEnvVRaAe7q6aTPCMVXUXLt45jrr9tpvyhNyy/EfUP1RngToHAQAYieG9Wf\\nzzenGNIg57c9F2vT1ga4KwBTwnvk6qsoVINL4nJwQWRAQJbxJfkcuhWDBc1R+OjF\\nze6eYTm71AIyZiz4UR63FsVgXkM5wnCC82/0XhyKpxVI/y7N1l/wQ8toKbb3wF0K\\nIcsna0HfxvaS17lVA20fNr3KSqfg49j7ReuBNEl4QCZWhQ6xY/5zsYLYeMv4N/Bz\\n/AfyMl2QvQVf3gblem4lXoqNeRbDmVcwaNZahP0goYs0o+lCFDOyiftTazetfiat\\nowIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 key->keyval);

	ret = get_public_key_for_role(&updater.root, TUF_ROLES_COUNT, 0, &key);
	TEST_ASSERT_EQUAL(-EINVAL, ret);
}

TEST(Full_LibTufNAno, libTufNano_TestRoot2Load){
	int ret;

	ret = parse_root("2.root.json", false);

	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_STRING("22e8f6d06eec2e4d50187b74ff21ddbc15326fb56e2d62fd68d10c0cb43b4e7e", updater.root.keys[0].id);
	TEST_ASSERT_EQUAL_STRING("2e6d5e7f1469cb08be5f371ff5f211a45005223e5aff20815f36880c9bd418cb", updater.root.keys[1].id);
	TEST_ASSERT_EQUAL_STRING("91f89e098b6c3ee0878b9f1518c2f88624dad3301ed82f1c688310de952fce0c", updater.root.keys[2].id);
	TEST_ASSERT_EQUAL_STRING("c0919e0f82b94be9eef55dcd5f224d8d8b4da80299a4ebef58018ab68fee0a8d", updater.root.keys[3].id);

	TEST_ASSERT_EQUAL_STRING("RSA", updater.root.keys[0].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", updater.root.keys[1].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", updater.root.keys[2].keytype);
	TEST_ASSERT_EQUAL_STRING("RSA", updater.root.keys[3].keytype);

	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsac985OY9LESVVHaRJBU\\nV2i1uHCkocMKHihaUEFZbE1dv6EMwBrdM+Z0b2I4A6E6GXmAJE3FVrsXikatleOb\\n7yau+yzv2b4wiK/7OBgz61hPmVsK1k1QVK1f3v0J27Koa6YeVUbpisXCuTQrrA23\\nczuvZlW9tHtJHY3uD03MfwlcENr+gvppDxEHCUzoUvN16IHsnGGGdgL8q4uNelDq\\n3iJCz/ArhEWOkq613sLZbOq83TyYzVgw0lcxPJ1oX+NA4iAC2Pl/uRLUtVawefUc\\nZ5k4DgpouAy2ot9d4oGRjs2LDnmKFwFiMbLgMQf6nIK8PDcso1cA44UwZuC7xSFU\\n6QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 updater.root.keys[0].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstQmVmyZIA2tejyNDkug\\npUsncb2cBGl/vGkrsDJQvxTPpNnmtRQTdQoZ/qqPWonNZ/JEJRVL1xc24ioyx/dS\\nCKvdZzAsIxSoklxoDslSP8jDKwdFLj34snGBgtdDJ+bh44Oei6532GX5iy7Xj3SE\\na5pVoQ6nLWz5AULw7gmR01qIA3J1OZ7oVhR5hF4W/gNc8hAQg1gMRSrm+PUxzRr2\\n5YfZznE9JVsvuTi/e0iMDBeE1cXlUzo1/B2b+7072xlBsGP61tuln6c6kRA7PbIg\\nHX5Q+vs7svBY3wl07an8IxvHi9iZUYW9V8HH67/jJxree04kjC2KhaozEJLITwE0\\n4QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 updater.root.keys[1].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmu+MksWTfMScaFw4KUBk\\nwKcSeROX8atN4D8r42BHgCsLr4OcXmHzkDVSuCCymJ2SEkgnd6pJxIaWs+HS0Nni\\nu3Gxqv9+6ZUKiMzG89gFkx6kU4RZRd3TcMZOTZaabWhDuVpg6Gkig759qL6B/jNi\\nK1FBAKNGPp3S0rZ+zghdrvrKzUSlVLmvOqTI0PhddkzoNGDO9v6F40n58NKvlOUY\\nCn8wk1n8DGG36CActHIjoAUoQsueBTRNdUy5vNmX4BuEdhUdwDaaJwEkvIvoU3S/\\nwLNlSexU5EJjqWlNeUEWvUJjbxXpSMqAhTtT1MG5En+yqPhH1tGuzK3w6JCS9aou\\nvQIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 updater.root.keys[2].keyval);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX9EqnICo4ewErN82S00\\nWmCPhEfoEDwpG593Kh1E04MDC+PB3YIdkcqFTSeMkZW25GgWclLyDEAuUmGEO6yN\\nrR1S4/e36ImiIW2vEZhlMIX8a/SEb11Rhkvi/GRpt/ZyLp1El4M17nYO/GnYr1dE\\nhn2PCaZIo3jVuxmZ/+nzY/9whanjKoomGRcGlAne927DHYV0XiI1dBt+4gvpMdXp\\nEH8ZCHPQHjsUe0S433niVMIa4pIaQWvdEFliJ703Dqbxn1iVHUi+p8j+z6oh2v1z\\nZz0aiECwKOtRsGUNtJWeZfx5ZOOoeKyE47DZXPsolw7DlJxZRZlGny1KpX8Y0yTA\\n7QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 updater.root.keys[3].keyval);

	TEST_ASSERT_EQUAL(1, updater.root.roles[ROLE_SNAPSHOT].threshold);
	TEST_ASSERT_EQUAL(1, updater.root.roles[ROLE_TARGETS].threshold);
	TEST_ASSERT_EQUAL(1, updater.root.roles[ROLE_TIMESTAMP].threshold);
	TEST_ASSERT_EQUAL(1, updater.root.roles[ROLE_ROOT].threshold);

	TEST_ASSERT_EQUAL_STRING("2e6d5e7f1469cb08be5f371ff5f211a45005223e5aff20815f36880c9bd418cb", updater.root.roles[ROLE_SNAPSHOT].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("22e8f6d06eec2e4d50187b74ff21ddbc15326fb56e2d62fd68d10c0cb43b4e7e", updater.root.roles[ROLE_TARGETS].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("c0919e0f82b94be9eef55dcd5f224d8d8b4da80299a4ebef58018ab68fee0a8d", updater.root.roles[ROLE_TIMESTAMP].keyids[0]);
	TEST_ASSERT_EQUAL_STRING("91f89e098b6c3ee0878b9f1518c2f88624dad3301ed82f1c688310de952fce0c", updater.root.roles[ROLE_ROOT].keyids[0]);

	TEST_ASSERT_EQUAL_STRING("2022-10-14T19:56:08Z", updater.root.base.expires);
	TEST_ASSERT_EQUAL(1665777368, updater.root.base.expires_epoch);
	TEST_ASSERT_EQUAL(2, updater.root.base.version);

	struct tuf_key *key;

	ret = get_public_key_for_role(&updater.root, ROLE_SNAPSHOT, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstQmVmyZIA2tejyNDkug\\npUsncb2cBGl/vGkrsDJQvxTPpNnmtRQTdQoZ/qqPWonNZ/JEJRVL1xc24ioyx/dS\\nCKvdZzAsIxSoklxoDslSP8jDKwdFLj34snGBgtdDJ+bh44Oei6532GX5iy7Xj3SE\\na5pVoQ6nLWz5AULw7gmR01qIA3J1OZ7oVhR5hF4W/gNc8hAQg1gMRSrm+PUxzRr2\\n5YfZznE9JVsvuTi/e0iMDBeE1cXlUzo1/B2b+7072xlBsGP61tuln6c6kRA7PbIg\\nHX5Q+vs7svBY3wl07an8IxvHi9iZUYW9V8HH67/jJxree04kjC2KhaozEJLITwE0\\n4QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 key->keyval);

	ret = get_public_key_for_role(&updater.root, ROLE_TARGETS, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsac985OY9LESVVHaRJBU\\nV2i1uHCkocMKHihaUEFZbE1dv6EMwBrdM+Z0b2I4A6E6GXmAJE3FVrsXikatleOb\\n7yau+yzv2b4wiK/7OBgz61hPmVsK1k1QVK1f3v0J27Koa6YeVUbpisXCuTQrrA23\\nczuvZlW9tHtJHY3uD03MfwlcENr+gvppDxEHCUzoUvN16IHsnGGGdgL8q4uNelDq\\n3iJCz/ArhEWOkq613sLZbOq83TyYzVgw0lcxPJ1oX+NA4iAC2Pl/uRLUtVawefUc\\nZ5k4DgpouAy2ot9d4oGRjs2LDnmKFwFiMbLgMQf6nIK8PDcso1cA44UwZuC7xSFU\\n6QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 key->keyval);


	ret = get_public_key_for_role(&updater.root, ROLE_TIMESTAMP, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX9EqnICo4ewErN82S00\\nWmCPhEfoEDwpG593Kh1E04MDC+PB3YIdkcqFTSeMkZW25GgWclLyDEAuUmGEO6yN\\nrR1S4/e36ImiIW2vEZhlMIX8a/SEb11Rhkvi/GRpt/ZyLp1El4M17nYO/GnYr1dE\\nhn2PCaZIo3jVuxmZ/+nzY/9whanjKoomGRcGlAne927DHYV0XiI1dBt+4gvpMdXp\\nEH8ZCHPQHjsUe0S433niVMIa4pIaQWvdEFliJ703Dqbxn1iVHUi+p8j+z6oh2v1z\\nZz0aiECwKOtRsGUNtJWeZfx5ZOOoeKyE47DZXPsolw7DlJxZRZlGny1KpX8Y0yTA\\n7QIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 key->keyval);

	ret = get_public_key_for_role(&updater.root, ROLE_ROOT, 0, &key);
	TEST_ASSERT_EQUAL(0, ret);
	TEST_ASSERT_EQUAL_STRING("-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmu+MksWTfMScaFw4KUBk\\nwKcSeROX8atN4D8r42BHgCsLr4OcXmHzkDVSuCCymJ2SEkgnd6pJxIaWs+HS0Nni\\nu3Gxqv9+6ZUKiMzG89gFkx6kU4RZRd3TcMZOTZaabWhDuVpg6Gkig759qL6B/jNi\\nK1FBAKNGPp3S0rZ+zghdrvrKzUSlVLmvOqTI0PhddkzoNGDO9v6F40n58NKvlOUY\\nCn8wk1n8DGG36CActHIjoAUoQsueBTRNdUy5vNmX4BuEdhUdwDaaJwEkvIvoU3S/\\nwLNlSexU5EJjqWlNeUEWvUJjbxXpSMqAhTtT1MG5En+yqPhH1tGuzK3w6JCS9aou\\nvQIDAQAB\\n-----END PUBLIC KEY-----\\n",
				 key->keyval);

	ret = get_public_key_for_role(&updater.root, TUF_ROLES_COUNT, 0, &key);
	TEST_ASSERT_EQUAL(-EINVAL, ret);
}

TEST(Full_LibTufNAno, libTufNano_TestRootUpdateCheck){
	int ret;

	ret = parse_root("1.root.json", true);

	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_root("2.root.json", true);

	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);
}

TEST(Full_LibTufNAno, libTufNano_TestTimestampLoadWithoutRoot){
	int ret;

	ret = parse_timestamp("timestamp.json", true);
	TEST_ASSERT_EQUAL(TUF_ERROR_ROOT_ROLE_NOT_LOADED, ret);
}

TEST(Full_LibTufNAno, libTufNano_TestTimestampLoad){
	int ret;

	ret = parse_root("1.root.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_root("2.root.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_timestamp("timestamp.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	TEST_ASSERT_EQUAL(true, updater.timestamp.loaded);

	TEST_ASSERT_EQUAL(820, updater.timestamp.snapshot_file.length);
	TEST_ASSERT_EQUAL(875, updater.timestamp.snapshot_file.version);
	TEST_ASSERT_EQUAL_CHAR_ARRAY("\x11\x19\xa2\xd5\x57\x72\xf0\xcd\x7a\x94\xcb\xc9\x16\xc8\xa2\x81\x83\xf2\x45\x42\xfd\x2e\x13\x77\xcd\x06\xbe\x74\xf0\xaa\x32\x8f", updater.timestamp.snapshot_file.hash_sha256, TUF_HASH256_LEN);

	TEST_ASSERT_EQUAL_STRING("2022-09-09T18:13:01Z", updater.timestamp.base.expires);
	TEST_ASSERT_EQUAL(1662747181, updater.timestamp.base.expires_epoch);

	TEST_ASSERT_EQUAL(875, updater.timestamp.base.version);
}

TEST(Full_LibTufNAno, libTufNano_TestSnapshotLoadWithoutTimestamp){
	int ret;

	ret = parse_root("1.root.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_root("2.root.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_snapshot("snapshot.json", true);
	TEST_ASSERT_EQUAL(TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED", tuf_get_error_string(ret));
}

TEST(Full_LibTufNAno, libTufNano_TestSnapshotLoad){
	int ret;

	ret = parse_root("1.root.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_root("2.root.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_timestamp("timestamp.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = parse_snapshot("snapshot.json", true);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);
}

TEST(Full_LibTufNAno, libTufNano_TestSha256){
	int ret;

	ret = verify_file_hash("targets.json", "targets.json.sha256");
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = verify_file_hash("timestamp.json", "targets.json.sha256");
	TEST_ASSERT_EQUAL(TUF_ERROR_HASH_VERIFY_ERROR, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_HASH_VERIFY_ERROR", tuf_get_error_string(ret));
}

TEST(Full_LibTufNAno, libTufNano_TestBasicFunctions){
	time_t epoch;
	int ret;
	uint8_t dst[100];

	ret = datetime_string_to_epoch("2023-01-30T12:05:06Z", &epoch);
	TEST_ASSERT_EQUAL(1675080306, epoch);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	ret = datetime_string_to_epoch("2023-00-30T12:05:06Z", &epoch);
	TEST_ASSERT_EQUAL(TUF_ERROR_INVALID_DATE_TIME, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_INVALID_DATE_TIME", tuf_get_error_string(ret));

	ret = datetime_string_to_epoch("1960-01-30T12:05:06Z", &epoch);
	TEST_ASSERT_EQUAL(TUF_ERROR_INVALID_DATE_TIME, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_INVALID_DATE_TIME", tuf_get_error_string(ret));

	ret = hex_to_bin("0123456789abcdefABCDEF", dst, 11);
	TEST_ASSERT_EQUAL(0, ret);

	ret = hex_to_bin("\01\01", dst, 1);
	TEST_ASSERT_EQUAL(-1, ret);

	ret = hex_to_bin("GG", dst, 1);
	TEST_ASSERT_EQUAL(-1, ret);

	ret = hex_to_bin("gg", dst, 1);
	TEST_ASSERT_EQUAL(-1, ret);

	enum tuf_role role = role_string_to_enum("INVALID", strlen("INVALID"));
	TEST_ASSERT_EQUAL(TUF_ROLES_COUNT, role);

	const char *role_name = tuf_get_role_name(TUF_ROLES_COUNT);
	TEST_ASSERT_EQUAL_STRING("", role_name);
}

TEST(Full_LibTufNAno, libTufNano_TestRoleCheckingFunctions){
	int ret;
	unsigned char *sha256;
	unsigned char buf[TUF_HASH256_LEN];
	size_t length;

	sha256 = buf;
	memset(&updater, 0, sizeof(updater));

	updater.snapshot.loaded = true;
	updater.timestamp.loaded = false;
	ret = get_expected_sha256_and_length_for_role(ROLE_SNAPSHOT, &sha256, &length);
	TEST_ASSERT_EQUAL(TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED", tuf_get_error_string(ret));

	updater.snapshot.loaded = false;
	updater.timestamp.loaded = true;
	ret = get_expected_sha256_and_length_for_role(ROLE_TARGETS, &sha256, &length);
	TEST_ASSERT_EQUAL(TUF_ERROR_SNAPSHOT_ROLE_NOT_LOADED, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_SNAPSHOT_ROLE_NOT_LOADED", tuf_get_error_string(ret));

	ret = get_expected_sha256_and_length_for_role(ROLE_ROOT, &sha256, &length);
	TEST_ASSERT_EQUAL(-EINVAL, ret);
}

TEST(Full_LibTufNAno, libTufNano_TestParseTufInfo){
	struct tuf_role_file role_file;
	int ret;
	char *data;
	unsigned char hash[TUF_HASH256_LEN];

	ret = hex_to_bin("3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af", hash, sizeof(hash));
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	memset(&role_file, 0, sizeof(role_file));
	data = "{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}";
	ret = parse_tuf_file_info(data, strlen(data), &role_file);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);
	TEST_ASSERT_EQUAL(true, role_file.loaded);
	TEST_ASSERT_EQUAL(428, role_file.length);
	TEST_ASSERT_EQUAL(1038, role_file.version);
	TEST_ASSERT_EQUAL_CHAR_ARRAY(hash, role_file.hash_sha256, sizeof(hash));

	/* typo in "hashes" */
	memset(&role_file, 0, sizeof(role_file));
	data = "{\"hashes_\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}";
	ret = parse_tuf_file_info(data, strlen(data), &role_file);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_MISSING, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_FIELD_MISSING", tuf_get_error_string(ret));
	TEST_ASSERT_EQUAL(false, role_file.loaded);

	/* SHA256 hash too big */
	memset(&role_file, 0, sizeof(role_file));
	data = "{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af00\"},\"length\":428,\"version\":1038}";
	ret = parse_tuf_file_info(data, strlen(data), &role_file);
	TEST_ASSERT_EQUAL(TUF_ERROR_INVALID_FIELD_VALUE, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_INVALID_FIELD_VALUE", tuf_get_error_string(ret));
	TEST_ASSERT_EQUAL(false, role_file.loaded);

	/* typo in "length" */
	memset(&role_file, 0, sizeof(role_file));
	data = "{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length_\":428,\"version\":1038}";
	ret = parse_tuf_file_info(data, strlen(data), &role_file);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_MISSING, ret);
	TEST_ASSERT_EQUAL(false, role_file.loaded);

	/* typo in "version" */
	memset(&role_file, 0, sizeof(role_file));
	data = "{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version_\":1038}";
	ret = parse_tuf_file_info(data, strlen(data), &role_file);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_MISSING, ret);
	TEST_ASSERT_EQUAL(false, role_file.loaded);
}

TEST(Full_LibTufNAno, libTufNano_TestParseBaseMetadata) {
	int ret;
	char *data;
	struct tuf_metadata metadata_base;

	memset(&metadata_base, 0, sizeof(metadata_base));
	data = "{\"_type\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}";
	ret = parse_base_metadata(data, strlen(data), ROLE_TIMESTAMP, &metadata_base);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	/* Typo in "_type" */
	memset(&metadata_base, 0, sizeof(metadata_base));
	data = "{\"_type__\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}";
	ret = parse_base_metadata(data, strlen(data), ROLE_TIMESTAMP, &metadata_base);
	TEST_ASSERT_EQUAL(TUF_ERROR_INVALID_TYPE, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_INVALID_TYPE", tuf_get_error_string(ret));

	/* Wrong "_type" */
	memset(&metadata_base, 0, sizeof(metadata_base));
	data = "{\"_type\":\"Root\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}";
	ret = parse_base_metadata(data, strlen(data), ROLE_TIMESTAMP, &metadata_base);
	TEST_ASSERT_EQUAL(TUF_ERROR_INVALID_TYPE, ret);

	/* Typo in "version" */
	memset(&metadata_base, 0, sizeof(metadata_base));
	data = "{\"_type\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version__\":1038}";
	ret = parse_base_metadata(data, strlen(data), ROLE_TIMESTAMP, &metadata_base);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_MISSING, ret);

	/* Typo in "expires" */
	memset(&metadata_base, 0, sizeof(metadata_base));
	data = "{\"_type\":\"Timestamp\",\"expires__\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}";
	ret = parse_base_metadata(data, strlen(data), ROLE_TIMESTAMP, &metadata_base);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_MISSING, ret);

	/* Invalid "expires" value */
	memset(&metadata_base, 0, sizeof(metadata_base));
	data = "{\"_type\":\"Timestamp\",\"expires\":\"1960-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}";
	ret = parse_base_metadata(data, strlen(data), ROLE_TIMESTAMP, &metadata_base);
	TEST_ASSERT_EQUAL(TUF_ERROR_INVALID_DATE_TIME, ret);
}


TEST(Full_LibTufNAno, libTufNano_TestSplitMetadata) {
	int ret;
	char *data;
	struct tuf_signature signatures[TUF_SIGNATURES_PER_ROLE_MAX_COUNT];
	const unsigned char *signed_value;
	int signed_value_len;

	memset(&signatures[0], 0, sizeof(signatures[0]));
	memset(&signatures[1], 0, sizeof(signatures[1]));
	data = "{\"signatures\":[{\"keyid\":\"9f3295f7859ecc152b7fd6b43e835b02f9970406c00b813a110eeb1cb3b1eb2c\",\"method\":\"ed25519\",\"sig\":\"QUxG74vV95XhXeWfKWTStKddlkq9onIzNFwxOUv9gwXnanudlw2Ik4Pxg/lqO2PFA/12KdS6Xkeqkj17HUKjCQ==\"}],\"signed\":{\"_type\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}}";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);
	TEST_ASSERT_EQUAL(211, signed_value_len);
	TEST_ASSERT_EQUAL(true, signatures[0].set);
	TEST_ASSERT_EQUAL(false, signatures[1].set);

	/* Invalid data with size 0 */
	data = "";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(-EINVAL, ret);

	/* data buffer too small (1 > 0) */
	memset(&updater, 0, sizeof(updater));
	data = " ";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(-EINVAL, ret);

	/* Invalid JSON */
	updater.data_buffer_len = 1000;
	data = " ";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(TUF_ERROR_INVALID_METADATA, ret);

	/* Typo in "signatures" */
	data = "{\"signatures_\":[{\"keyid\":\"9f3295f7859ecc152b7fd6b43e835b02f9970406c00b813a110eeb1cb3b1eb2c\",\"method\":\"ed25519\",\"sig\":\"QUxG74vV95XhXeWfKWTStKddlkq9onIzNFwxOUv9gwXnanudlw2Ik4Pxg/lqO2PFA/12KdS6Xkeqkj17HUKjCQ==\"}],\"signed\":{\"_type\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}}";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_MISSING, ret);

	/* More signatures than supported (limit = 0) */
	data = "{\"signatures\":[{\"keyid\":\"9f3295f7859ecc152b7fd6b43e835b02f9970406c00b813a110eeb1cb3b1eb2c\",\"method\":\"ed25519\",\"sig\":\"QUxG74vV95XhXeWfKWTStKddlkq9onIzNFwxOUv9gwXnanudlw2Ik4Pxg/lqO2PFA/12KdS6Xkeqkj17HUKjCQ==\"}],\"signed\":{\"_type\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}}";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, 0, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_COUNT_EXCEEDED, ret);

	/* Typo in "keyid" */
	data = "{\"signatures\":[{\"keyid_\":\"9f3295f7859ecc152b7fd6b43e835b02f9970406c00b813a110eeb1cb3b1eb2c\",\"method\":\"ed25519\",\"sig\":\"QUxG74vV95XhXeWfKWTStKddlkq9onIzNFwxOUv9gwXnanudlw2Ik4Pxg/lqO2PFA/12KdS6Xkeqkj17HUKjCQ==\"}],\"signed\":{\"_type\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}}";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_MISSING, ret);

	/* Typo in "method" */
	data = "{\"signatures\":[{\"keyid\":\"9f3295f7859ecc152b7fd6b43e835b02f9970406c00b813a110eeb1cb3b1eb2c\",\"method_\":\"ed25519\",\"sig\":\"QUxG74vV95XhXeWfKWTStKddlkq9onIzNFwxOUv9gwXnanudlw2Ik4Pxg/lqO2PFA/12KdS6Xkeqkj17HUKjCQ==\"}],\"signed\":{\"_type\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}}";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_MISSING, ret);

	/* Invalid signature method */
	memset(&signatures[0], 0, sizeof(signatures[0]));
	memset(&signatures[1], 0, sizeof(signatures[1]));
	data = "{\"signatures\":[{\"keyid\":\"9f3295f7859ecc152b7fd6b43e835b02f9970406c00b813a110eeb1cb3b1eb2c\",\"method\":\"ed25519_\",\"sig\":\"QUxG74vV95XhXeWfKWTStKddlkq9onIzNFwxOUv9gwXnanudlw2Ik4Pxg/lqO2PFA/12KdS6Xkeqkj17HUKjCQ==\"}],\"signed\":{\"_type\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}}";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);
	TEST_ASSERT_EQUAL(false, signatures[0].set);

	/* Typo in "sig" */
	data = "{\"signatures\":[{\"keyid\":\"9f3295f7859ecc152b7fd6b43e835b02f9970406c00b813a110eeb1cb3b1eb2c\",\"method\":\"ed25519\",\"sig_\":\"QUxG74vV95XhXeWfKWTStKddlkq9onIzNFwxOUv9gwXnanudlw2Ik4Pxg/lqO2PFA/12KdS6Xkeqkj17HUKjCQ==\"}],\"signed\":{\"_type\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}}";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_MISSING, ret);

	/* Typo in "signed" */
	data = "{\"signatures\":[{\"keyid\":\"9f3295f7859ecc152b7fd6b43e835b02f9970406c00b813a110eeb1cb3b1eb2c\",\"method\":\"ed25519\",\"sig\":\"QUxG74vV95XhXeWfKWTStKddlkq9onIzNFwxOUv9gwXnanudlw2Ik4Pxg/lqO2PFA/12KdS6Xkeqkj17HUKjCQ==\"}],\"signed_\":{\"_type\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}}";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_MISSING, ret);

	/* Invalid base64 in "sig" value */
	data = "{\"signatures\":[{\"keyid\":\"9f3295f7859ecc152b7fd6b43e835b02f9970406c00b813a110eeb1cb3b1eb2c\",\"method\":\"ed25519\",\"sig\":\"_QUxG74vV95XhXeWfKWTStKddlkq9onIzNFwxOUv9gwXnanudlw2Ik4Pxg/lqO2PFA/12KdS6Xkeqkj17HUKjCQ==\"}],\"signed_\":{\"_type\":\"Timestamp\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"snapshot.json\":{\"hashes\":{\"sha256\":\"3a14dab22c54c8c00a490ffb8535ee1b11a9606f46e610e54871d445eba3d3af\"},\"length\":428,\"version\":1038}},\"version\":1038}}";
	ret = split_metadata((unsigned char*)data, strlen(data), signatures, TUF_SIGNATURES_PER_ROLE_MAX_COUNT, &signed_value, &signed_value_len);
	TEST_ASSERT_EQUAL(TUF_ERROR_INVALID_FIELD_VALUE, ret);
}

TEST(Full_LibTufNAno, libTufNano_TestFinalTimestamp){
	int ret;

	memset(&updater, 0, sizeof(updater));

	updater.snapshot.loaded = true;
	updater.timestamp.loaded = false;
	ret = check_final_timestamp();
	TEST_ASSERT_EQUAL(TUF_ERROR_BUG, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_BUG", tuf_get_error_string(TUF_ERROR_BUG));
}

TEST(Full_LibTufNAno, libTufNano_TestFinalSnapshot){
	int ret;

	memset(&updater, 0, sizeof(updater));

	updater.snapshot.loaded = true;
	updater.timestamp.loaded = false;
	ret = check_final_snapshot();
	TEST_ASSERT_EQUAL(TUF_ERROR_BUG, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_BUG", tuf_get_error_string(TUF_ERROR_BUG));

	updater.snapshot.loaded = false;
	updater.timestamp.loaded = true;
	ret = check_final_snapshot();
	TEST_ASSERT_EQUAL(TUF_ERROR_BUG, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_BUG", tuf_get_error_string(TUF_ERROR_BUG));

	updater.snapshot.loaded = true;
	updater.timestamp.loaded = true;
	updater.snapshot.base.expires_epoch = 1612178442; /* February 1, 2021 8:20:42 AM */
	updater.reference_time = 1662678442; /* September 8, 2022 11:07:22 PM */
	ret = check_final_snapshot();
	TEST_ASSERT_EQUAL(TUF_ERROR_EXPIRED_METADATA, ret);

	updater.snapshot.loaded = true;
	updater.timestamp.loaded = true;
	updater.snapshot.base.expires_epoch = 1662678443; /* September 8, 2022 11:07:23 PM */
	updater.reference_time = 1662678442; /* September 8, 2022 11:07:22 PM */
	updater.snapshot.base.version = 1;
	updater.timestamp.snapshot_file.version = 2;
	ret = check_final_snapshot();
	TEST_ASSERT_EQUAL(TUF_ERROR_BAD_VERSION_NUMBER, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_BAD_VERSION_NUMBER", tuf_get_error_string(ret));
}


TEST(Full_LibTufNAno, libTufNano_TestUpdateSnapshot){
	int ret;
	unsigned char buffer[1000];
	char *json = "";

	memset(&updater, 0, sizeof(updater));
	updater.data_buffer_len = sizeof(buffer);
	updater.data_buffer = buffer;
	updater.timestamp.loaded = true;
	updater.timestamp.snapshot_file.version = 1038;
	json = "{\"signatures\":[{\"keyid\":\"5ea2e62cebe20bca3b9cf381a87495a4a4350bb7e05bb40620fb79ff17741910\",\"method\":\"ed25519\",\"sig\":\"kOiJ0no3m0nccLkjWMcyBiyvRYMs0vHTSzkLtVP4Opg/ed7YtWZe5L/temi2meFHTR+SxPPZ8BQh0lXc9JVxCA==\"}],\"signed\":{\"_type\":\"Snapshot\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"targets.json\":{\"hashes\":{\"sha256\":\"baa2025c3723e6e9b11c67e8a854cf687e9f5b9170d8623aa3a5ac2d320bed0a\"},\"length\":299,\"version\":1038}},\"version\":1038}}";
	ret = update_snapshot((unsigned char*)json, strlen(json), false);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);

	memset(&updater, 0, sizeof(updater));
	ret = update_snapshot((unsigned char*)json, strlen(json), false);
	TEST_ASSERT_EQUAL(TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED", tuf_get_error_string(ret));

	updater.timestamp.loaded = true;
	updater.targets.loaded = true;
	ret = update_snapshot((unsigned char*)json, strlen(json), false);
	TEST_ASSERT_EQUAL(TUF_ERROR_TARGETS_ROLE_LOADED, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_TARGETS_ROLE_LOADED", tuf_get_error_string(ret));

	updater.data_buffer_len = sizeof(buffer);
	updater.data_buffer = buffer;
	updater.timestamp.loaded = true;
	updater.targets.loaded = false;
	json = " ";
	ret = update_snapshot((unsigned char*)json, strlen(json), false);
	TEST_ASSERT_EQUAL(TUF_ERROR_INVALID_METADATA, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_INVALID_METADATA", tuf_get_error_string(ret));

	json = "{}";
	ret = update_snapshot((unsigned char*)json, strlen(json), false);
	TEST_ASSERT_EQUAL(TUF_ERROR_FIELD_MISSING, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_FIELD_MISSING", tuf_get_error_string(ret));

	/* Check "Prevent rollback of targets version" */
	memset(&updater, 0, sizeof(updater));
	updater.data_buffer_len = sizeof(buffer);
	updater.data_buffer = buffer;
	updater.timestamp.loaded = true;
	updater.timestamp.snapshot_file.version = 1038;
	updater.snapshot.loaded = true;
	updater.snapshot.targets_file.version = 1039;
	json = "{\"signatures\":[{\"keyid\":\"5ea2e62cebe20bca3b9cf381a87495a4a4350bb7e05bb40620fb79ff17741910\",\"method\":\"ed25519\",\"sig\":\"kOiJ0no3m0nccLkjWMcyBiyvRYMs0vHTSzkLtVP4Opg/ed7YtWZe5L/temi2meFHTR+SxPPZ8BQh0lXc9JVxCA==\"}],\"signed\":{\"_type\":\"Snapshot\",\"expires\":\"2023-07-21T02:49:21Z\",\"meta\":{\"targets.json\":{\"hashes\":{\"sha256\":\"baa2025c3723e6e9b11c67e8a854cf687e9f5b9170d8623aa3a5ac2d320bed0a\"},\"length\":299,\"version\":1038}},\"version\":1038}}";
	ret = update_snapshot((unsigned char*)json, strlen(json), false);
	TEST_ASSERT_EQUAL(TUF_ERROR_BAD_VERSION_NUMBER, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_ERROR_BAD_VERSION_NUMBER", tuf_get_error_string(ret));
}


// TEST(Full_LibTufNAno, libTufNano_TestFullLoadRootOperation){
	// int ret;

	// ret = load_root();
	// TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);
// }

/* tests only */
static int remove_all_local_role_files(const char *path)
{
	remove_local_role_file(path, ROLE_ROOT);
	remove_local_role_file(path, ROLE_TIMESTAMP);
	remove_local_role_file(path, ROLE_SNAPSHOT);
	remove_local_role_file(path, ROLE_TARGETS);

	return TUF_SUCCESS;
}

static int test_refresh_from_path_cust_prov(const char *remote_path, const char *prov_path, time_t reference_time) {
	int ret;
	size_t data_buffer_len;
	unsigned char *data_buffer;
	/* on an actual implementation, get_current_gmt_time() would be used */
	const char *local_path = "../test/nvs";

	remove_all_local_role_files(local_path);

	tuf_get_application_buffer(&data_buffer, &data_buffer_len);
	ret = tuf_refresh(tuf_get_application_context(prov_path, local_path, remote_path), reference_time, data_buffer, data_buffer_len);
	if (ret != TUF_SUCCESS)
		return ret;

	reference_time += 10;
	ret = tuf_refresh(tuf_get_application_context(prov_path, local_path, remote_path), reference_time, data_buffer, data_buffer_len);
	return ret;
}


static int test_refresh_from_path(const char *remote_path, time_t reference_time) {
	return test_refresh_from_path_cust_prov(remote_path, "../test/provisioning/rsa", reference_time);
}

TEST(Full_LibTufNAno, libTufNano_TestRefreshOK)
{
	time_t reference_time = 1662678442; /* September 8, 2022 11:07:22 PM */
	int ret = test_refresh_from_path(TUF_TEST_FILES_PATH "/rsa", reference_time);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_SUCCESS", tuf_get_error_string(ret));
}

TEST(Full_LibTufNAno, libTufNano_TestRefreshEllipticCurveOK)
{
	time_t reference_time = 1687356253; /*  June 21, 2023 2:04:13 PM */
	int ret = test_refresh_from_path_cust_prov(TUF_TEST_FILES_PATH "/ed25519", "../test/provisioning/ed25519", reference_time);
	TEST_ASSERT_EQUAL(TUF_SUCCESS, ret);
	TEST_ASSERT_EQUAL_STRING("TUF_SUCCESS", tuf_get_error_string(ret));
}

TEST(Full_LibTufNAno, libTufNano_TestRefreshErrors)
{
	time_t reference_time = 1662678442; /* September 8, 2022 11:07:22 PM */
	time_t future_reference_time = 1663351215; /* Fri, 16 Sep 2022 18:00:15 GMT */
	int ret;

	/* Test hash errors */
	const char *sha_paths[] = {
		TUF_TEST_FILES_PATH "/error_hash_snapshot",
		TUF_TEST_FILES_PATH "/error_hash_targets",
	};

	for (size_t i=0; i<sizeof(sha_paths) / sizeof(sha_paths[0]); i++) {
		log_info(("\nTesting '%s'...", sha_paths[i]));
		ret = test_refresh_from_path(sha_paths[i], reference_time);
		TEST_ASSERT_EQUAL(TUF_ERROR_HASH_VERIFY_ERROR, ret);
		TEST_ASSERT_EQUAL_STRING("TUF_ERROR_HASH_VERIFY_ERROR", tuf_get_error_string(ret));
	}

	/* Test signature errors (hashes are OK) */
	const char *sig_paths[] = {
		TUF_TEST_FILES_PATH "/error_sig_root_2",
		TUF_TEST_FILES_PATH "/error_sig_root_2_self",
		TUF_TEST_FILES_PATH "/error_sig_timestamp",
		TUF_TEST_FILES_PATH "/error_sig_snapshot",
		TUF_TEST_FILES_PATH "/error_sig_targets",
	};

	for (size_t i=0; i<sizeof(sig_paths) / sizeof(sig_paths[0]); i++) {
		log_info((ANSI_COLOR_YELLOW "\nTesting '%s'..." ANSI_COLOR_RESET, sig_paths[i]));
		ret = test_refresh_from_path(sig_paths[i], reference_time);
		TEST_ASSERT_EQUAL(TUF_ERROR_UNSIGNED_METADATA, ret);
		TEST_ASSERT_EQUAL_STRING("TUF_ERROR_UNSIGNED_METADATA", tuf_get_error_string(ret));
	}

	/* Test version errors */
	const char *version_paths[] = {
		TUF_TEST_FILES_PATH "/error_version_root_2",
	};

	for (size_t i=0; i<sizeof(version_paths) / sizeof(version_paths[0]); i++) {
		log_info((ANSI_COLOR_YELLOW "\nTesting '%s'..." ANSI_COLOR_RESET, version_paths[i]));
		ret = test_refresh_from_path(version_paths[i], reference_time);
		TEST_ASSERT_EQUAL(TUF_ERROR_BAD_VERSION_NUMBER, ret);
		TEST_ASSERT_EQUAL_STRING("TUF_ERROR_BAD_VERSION_NUMBER", tuf_get_error_string(ret));
	}

	/* Test expiration errors */
	const char *ok_paths[] = {
		TUF_TEST_FILES_PATH "/rsa",
	};

	for (size_t i=0; i<sizeof(ok_paths) / sizeof(ok_paths[0]); i++) {
		log_info((ANSI_COLOR_YELLOW "\nTesting '%s'..." ANSI_COLOR_RESET, ok_paths[i]));
		ret = test_refresh_from_path(ok_paths[i], future_reference_time);
		TEST_ASSERT_EQUAL(TUF_ERROR_EXPIRED_METADATA, ret);
		TEST_ASSERT_EQUAL_STRING("TUF_ERROR_EXPIRED_METADATA", tuf_get_error_string(ret));
	}
}

int run_full_test(void)
{
	UNITY_BEGIN();

	/* Run the test group. */
	RUN_TEST_GROUP(Full_LibTufNAno);

	int status = UNITY_END();

	return status;
}

void test_TUF_all( void ) {
	log_debug(("get_current_gmt_time=%ld\n", get_current_gmt_time()));
	run_full_test();
}
/* ============================   UNITY FIXTURES ============================ */
/* Keep the block bellow to avoid a new setUp and tearDown to be added automatically */
#if 0
/* Called before each test method. */
void setUp()
{
}

/* Called after each test method. */
void tearDown()
{
}
#endif

/* Called at the beginning of the whole suite. */
void suiteSetUp()
{
}

/* Called at the end of the whole suite. */
int suiteTearDown( int numFailures )
{
    return numFailures;
}
