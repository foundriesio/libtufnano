/*
 * Copyright 2022 Foundries.io
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __TUF_CLIENT_APPLICATION_CONTEXT_H__
#define __TUF_CLIENT_APPLICATION_CONTEXT_H__

#include <stdint.h>
#include <time.h>

#define CONFIG_BOARD BOARD_NAME

#define AKNANO_SHA256_LEN 32

#define AKNANO_MAX_TAG_LENGTH 32
#define AKNANO_MAX_UPDATE_AT_LENGTH 32
#define AKNANO_MAX_URI_LENGTH 120

#define TUF_TEST_CLIENT_MAX_PATH_LENGTH 200

struct aknano_target {
	char	updatedAt[AKNANO_MAX_UPDATE_AT_LENGTH];
	char	uri[AKNANO_MAX_URI_LENGTH];
	size_t	expected_size;
	int32_t version;
	uint8_t expected_hash[AKNANO_SHA256_LEN];
};

/* Settings are kept between iterations */
struct aknano_settings {
	char		tag[AKNANO_MAX_TAG_LENGTH];
	const char *	hwid;
};

struct aknano_network_context;

/* Context is not kept between iterations */
struct aknano_context {
	size_t				url_buffer_size;
	size_t				status_buffer_size;
	struct aknano_settings *	settings;
	struct aknano_target		selected_target;
};

struct tuf_client_test_context {
	char			root_provisioning_path[TUF_TEST_CLIENT_MAX_PATH_LENGTH];
	char			remote_files_path[TUF_TEST_CLIENT_MAX_PATH_LENGTH];
	char			local_files_path[TUF_TEST_CLIENT_MAX_PATH_LENGTH];

	struct aknano_context * aknano_context;
};

#endif
