/*
 * Copyright 2022 Foundries.io
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Sample TUF client. The code from this file will be part of aktalizr-nano
 * It still has some code from the original PoC code, separation between app
 *  and aktalizr-nano is ongoing
 */

#include <stdarg.h>
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

#include "tuf_client_application_context.h"

static struct aknano_context aknano_context;
static struct aknano_settings aknano_settings;
static struct tuf_client_test_context test_context;

#define log_debug printf

/*
 * Returns the application specific context information used during TUF update
 *
 * provisioning_path: The base path for reading the provisioned root role 
 *                    metadata file (NULL if there is no such path)
 * local_path: The base path for reading and writing the roles metadata to the
 *             local filesystem
 * remote_path: The base path for reading roles metadata when TUF is trying
 *              fetch those files from a remote server
 */
void *tuf_get_application_context(const char *provisioning_path,
				  const char *local_path, const char *remote_path)
{
	memset(&aknano_context, 0, sizeof(aknano_context));
	memset(&aknano_settings, 0, sizeof(aknano_settings));
	memset(&test_context, 0, sizeof(test_context));

	aknano_context.settings = &aknano_settings;
	test_context.aknano_context = &aknano_context;
	strncpy(test_context.local_files_path, local_path, sizeof(test_context.local_files_path));
	strncpy(test_context.remote_files_path, remote_path, sizeof(test_context.remote_files_path));
	if (provisioning_path)
		strncpy(test_context.root_provisioning_path, provisioning_path, sizeof(test_context.root_provisioning_path));

	aknano_context.settings->hwid = "MIMXRT1170-EVK";
	strcpy(aknano_context.settings->tag, "devel");
	return &test_context;
}

#define DATA_BUFFER_LEN 10 * 1024
unsigned char data_buffer[DATA_BUFFER_LEN];
int tuf_get_application_buffer(unsigned char **buffer, size_t *buffer_size)
{
	*buffer = data_buffer;
	*buffer_size = DATA_BUFFER_LEN;
	return 0;
}

void log_tuf_client(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf("\r\n");
}
