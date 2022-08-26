#ifndef __LIBTUFNANO_H__
#define __LIBTUFNANO_H__

#include <stdbool.h>
#include <stdint.h>

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
#define TUF_ERROR_EXPIRED_METADATA -905
#define TUF_ERROR_BAD_VERSION_NUMBER -905
#define TUF_ERROR_REPOSITORY_ERROR -906
#define TUF_ERROR_INVALID_TYPE -907
#define TUF_ERROR_FIELD_MISSING -908
#define TUF_ERROR_INVALID_FIELD_VALUE -909
#define TUF_ERROR_SAME_VERSION -910
#define TUF_ERROR_UNSIGNED_METADATA -911
#define TUF_ERROR_INVALID_METADATA -912
#define TUF_ERROR_FIELD_COUNT_EXCEEDED -913
#define TUF_ERROR_KEY_ID_NOT_FOUND -914
#define TUF_ERROR_KEY_ID_FOR_ROLE_NOT_FOUND -915
#define TUF_ERROR_ROOT_ROLE_NOT_LOADED -920
#define TUF_ERROR_TIMESTAMP_ROLE_NOT_LOADED -921
#define TUF_ERROR_SNAPSHOT_ROLE_NOT_LOADED -922
#define TUF_ERROR_TARGETS_ROLE_LOADED -923
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


/* Application specific code */
void *tuf_get_application_context();
int tuf_parse_single_target(const char *target_key, size_t targte_key_len, const char *data, size_t len, void *application_context);
int tuf_targets_processing_done(void *application_context);
int fetch_file(const char *file_base_name, unsigned char *target_buffer, size_t target_buffer_len, size_t *file_size);
int read_local_file(enum tuf_role role, unsigned char *target_buffer, size_t target_buffer_len, size_t *file_size);
int write_local_file(enum tuf_role role, const unsigned char *data, size_t len);
int tuf_get_application_buffer(unsigned char **buffer, size_t *buffer_size);

int refresh();

#endif
