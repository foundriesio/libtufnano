#ifndef __LIBTUFNANO_INTERNAL_H__
#define __LIBTUFNANO_INTERNAL_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "libtufnano.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define _ROOT "root"
#define _SNAPSHOT "snapshot"
#define _TARGETS "targets"
#define _TIMESTAMP "timestamp"

/* Fields size limits */
#ifndef TUF_SIGNATURES_PER_ROLE_MAX_COUNT
#define TUF_SIGNATURES_PER_ROLE_MAX_COUNT 10
#endif

#ifndef TUF_SIGNATURE_MAX_LEN
#define TUF_SIGNATURE_MAX_LEN 512
#endif

#ifndef TUF_MAX_KEY_COUNT
#define TUF_MAX_KEY_COUNT 10
#endif

#ifndef TUF_KEYIDS_PER_ROLE_MAX_COUNT
#define TUF_KEYIDS_PER_ROLE_MAX_COUNT 5
#endif

#ifndef TUF_KEY_VAL_MAX_LEN
/* TODO: save space in memory by keeping decoded key instead of base64 string */
#define TUF_KEY_VAL_MAX_LEN 500
#endif


#define TUF_SIGNATURE_METHOD_NAME_MAX_LEN 20
#define TUF_KEY_ID_MAX_LEN 65
#define TUF_KEY_TYPE_MAX_LEN 10
#define TUF_DATETIME_MAX_LEN 22
#define TUF_HASH256_LEN 32

/* Data types */

struct tuf_signature {
	char		keyid[TUF_KEY_ID_MAX_LEN];
	char		method[TUF_SIGNATURE_METHOD_NAME_MAX_LEN];
	unsigned char	sig[TUF_SIGNATURE_MAX_LEN];
	size_t		sig_len;
	bool		set;
};

struct tuf_key {
	char	id[TUF_KEY_ID_MAX_LEN];
	char	keyval[TUF_KEY_VAL_MAX_LEN];
	char	keytype[TUF_KEY_TYPE_MAX_LEN];
};

struct tuf_metadata {
	int	version;
	char	expires[TUF_DATETIME_MAX_LEN];
	time_t	expires_epoch;
};

struct tuf_role_file {
	enum tuf_role	role;
	size_t		length;
	unsigned char	hash_sha256[TUF_HASH256_LEN];
	int		version;
	bool		loaded;
};

struct tuf_timestamp {
	struct tuf_role_file	snapshot_file;
	struct tuf_metadata	base;
	bool			loaded;
};

struct tuf_snapshot {
	struct tuf_role_file	root_file;
	struct tuf_role_file	targets_file;
	struct tuf_metadata	base;
	bool			loaded;
};

struct tuf_target {
	int		version;
	char *		file_name;
	unsigned char	hash_sha256[TUF_HASH256_LEN];
};

struct tuf_targets {
	struct tuf_target	selected_target;
	struct tuf_metadata	base;
	bool			loaded;
};


struct tuf_root_role {
	char	keyids[TUF_KEYIDS_PER_ROLE_MAX_COUNT][TUF_KEY_ID_MAX_LEN];
	int	threshold;
};

struct tuf_root {
	struct tuf_key		keys[TUF_MAX_KEY_COUNT];
	size_t			keys_count;
	struct tuf_root_role	roles[TUF_ROLES_COUNT];
	struct tuf_metadata	base;
	bool			loaded;
};

/* Trusted set */
struct tuf_updater {
	struct tuf_timestamp	timestamp;
	struct tuf_targets	targets;
	struct tuf_snapshot	snapshot;
	struct tuf_root		root;
	time_t			reference_time;
	void *			application_context;
	unsigned char *		data_buffer;
	size_t			data_buffer_len;
};

struct tuf_config {
	int	max_root_rotations;
	size_t	snapshot_max_length;
	size_t	targets_max_length;
};

time_t get_current_gmt_time();

const char *get_role_name(enum tuf_role role);

size_t read_file_posix(const char *base_name, char *output_buffer, size_t limit, const char *base_path, size_t *file_size);
size_t write_file_posix(const char *base_name, const char *data, size_t len, const char *base_path);
int remove_local_file_posix(const char *base_name, char *base_path);
int remove_local_role_file(enum tuf_role role);

#endif
