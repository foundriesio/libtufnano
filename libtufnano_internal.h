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

#define TUF_TEST_FILES_PATH "tests/sample_jsons/rsa"


#define log_debug printf
#define log_info printf
#define log_error printf

/* Fields size limits */
#define MAX_FILE_PATH_LEN 150
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


/* Data types */

struct tuf_signature {
	char		keyid[TUF_KEY_ID_MAX_LEN];
	char		method[TUF_SIGNATURE_METHOD_NAME_MAX_LEN];
	unsigned char	sig[TUF_SIGNATURE_MAX_LEN];
	bool		set;
};

struct tuf_key {
	char	id[TUF_BIG_CHUNK];
	char	keyval[TUF_BIG_CHUNK];
	char	keytype[TUF_BIG_CHUNK];
};

struct tuf_metadata {
	int	version;
	char	expires[21];
	time_t	expires_epoch;
};

struct tuf_role_file {
	enum tuf_role	role;
	size_t		length;
	unsigned char	hash_sha256[65];
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
	unsigned char	hash_sha256[65];
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
int verify_data_signature_for_role(const char *signed_value, size_t signed_value_len, struct tuf_signature *signatures, enum tuf_role role, struct tuf_root *root);

const char *get_role_name(enum tuf_role role);
int verify_data_hash_sha256(char *data, int data_len, unsigned char *hash_b16, size_t hash_b16_len);
int verify_signature(const char *data, int data_len, unsigned char *signature_bytes, int signature_bytes_len, struct tuf_key *key);

int split_metadata(const char *data, int len, struct tuf_signature *signatures, int signatures_max_count, char **signed_value, int *signed_value_len);
int split_metadata_and_check_signature(const char *data, size_t file_size, enum tuf_role role, struct tuf_signature *signatures, char **signed_value, int *signed_value_len, bool check_signature_and_hashes);

int get_public_key_for_role(struct tuf_root *root, enum tuf_role role, int key_index, struct tuf_key **key);

void load_config();

int load_root();
int load_timestamp();
int load_snapshot();
int load_targets();

int parse_snapshot_signed_metadata(char *data, int len, struct tuf_snapshot *target);
int parse_timestamp_signed_metadata(char *data, int len, struct tuf_timestamp *target);
int parse_root_signed_metadata(char *data, int len, struct tuf_root *target);

size_t read_file_posix(const char *base_name, char *output_buffer, size_t limit, const char *base_path, size_t *file_size);
size_t write_file_posix(const char *base_name, const char *data, size_t len, const char *base_path);
int remove_local_file_posix(const char *base_name, char *base_path);
int remove_local_role_file(enum tuf_role role);
int remove_all_local_role_files();

#endif
