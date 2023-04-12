/*
 * Copyright 2022 Foundries.io
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __LIBTUFNANO_H__
#define __LIBTUFNANO_H__

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "libtufnano_config.h"

/*
 * TUF metadata has '.' in field names.
 * We change the key separator for coreJSON to '/' to avoid ambiguity
 * This is currently being done in the Makefile
 *  #define JSON_QUERY_KEY_SEPARATOR '/'
 * The following define needs to be consistent with the character used
 * when compiling coreJSON
 */
#define TUF_JSON_QUERY_KEY_SEPARATOR "/"

/* Error codes */
#define TUF_SUCCESS 0

#define TUF_ERROR_DATA_EXCEEDS_BUFFER_SIZE -800

#define TUF_ERROR_INVALID_HASH -900
#define TUF_ERROR_INVALID_HASH_LENGTH -901
#define TUF_ERROR_HASH_VERIFY_ERROR -902
#define TUF_ERROR_LENGTH_VERIFY_ERROR -903
#define TUF_ERROR_INVALID_DATE_TIME -904
#define TUF_ERROR_EXPIRED_METADATA -930
#define TUF_ERROR_BAD_VERSION_NUMBER -905
#define TUF_ERROR_REPOSITORY_ERROR -906
#define TUF_ERROR_INVALID_TYPE -907
#define TUF_ERROR_FIELD_MISSING -908
#define TUF_ERROR_INVALID_FIELD_VALUE -909
#define TUF_SAME_VERSION -910
#define TUF_ERROR_UNSIGNED_METADATA -911
#define TUF_ERROR_INVALID_METADATA -912
#define TUF_ERROR_FIELD_COUNT_EXCEEDED -913
#define TUF_ERROR_KEY_ID_NOT_FOUND -914
#define TUF_ERROR_KEY_ID_FOR_ROLE_NOT_FOUND -915
#define TUF_ERROR_ROOT_ROLE_NOT_LOADED -920
#define TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED -921
#define TUF_ERROR_SNAPSHOT_ROLE_NOT_LOADED -922
#define TUF_ERROR_TARGETS_ROLE_LOADED -923
#define TUF_ERROR_SNAPSHOT_ROLE_LOADED -924
#define TUF_ERROR_BUG -1000

#define TUF_HTTP_NOT_FOUND -404
#define TUF_HTTP_FORBIDDEN -403

enum tuf_role {
	ROLE_ROOT = 0,
	ROLE_TIMESTAMP,
	ROLE_SNAPSHOT,
	ROLE_TARGETS,
	TUF_ROLES_COUNT
};


/*
 * tuf_refresh is expected to be called periodically by the TUF client application
 *
 * The data_buffer is used during processing of the roles metadata, should big
 * enough to fit every individual role metadata. If any role metada is bugger
 * than data_buffer_len, a TUF_ERROR_DATA_EXCEEDS_BUFFER_SIZE error is returned.
 *
 * data_buffer recommended size is 10KB.
 *
 * If the return value is TUF_SUCCESS, the data_buffer is loaded with a null
 * terminated string corresponding to the latest targets metadata, verified
 * according to the TUF specification
 */
int tuf_refresh(void *application_context, time_t reference_time, unsigned char *data_buffer, size_t data_buffer_len);

/* Functions that might be useful in the TUF client application */
const char *tuf_get_role_name(enum tuf_role role);
const char *tuf_get_error_string(int error);

/*
 * Functions that must be implemented by the tuf client application,
 * and that are called by libtufnano
 */
int tuf_client_read_local_file(enum tuf_role role, unsigned char *target_buffer, size_t target_buffer_len, size_t *file_size, void *application_context);
int tuf_client_write_local_file(enum tuf_role role, const unsigned char *data, size_t len, void *application_context);
int tuf_client_fetch_file(const char *file_base_name, unsigned char *target_buffer, size_t target_buffer_len, size_t *file_size, void *application_context);

#endif
