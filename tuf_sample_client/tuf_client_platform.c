#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define ____USE_XOPEN
#define _GNU_SOURCE
#include <time.h>

#include "libtufnano_internal.h"
#include "libtufnano.h"

/*
 * fetch_file, read_local_file and save_local_file will be provided by external application
 */

#define TUF_LOCAL_FILES_PATH "nvs"

/* Platform specific code */
time_t get_current_gmt_time()
{
	time_t current_time;
	struct tm *tm;

	time(&current_time);
	tm = gmtime(&current_time);
	tm->tm_isdst = 0;               /* ignore DST */
	current_time = mktime(tm);
	current_time += tm->tm_gmtoff;  /* compensate locale */
	return current_time;
}

/* read_file function */
size_t read_file_posix(const char *base_name, char *output_buffer, size_t limit, const char *base_path, size_t *file_size)
{
	char file_path[MAX_FILE_PATH_LEN];
	FILE *f;

	if (limit <= 0) {
		log_error("read_file_posix: Invalid limit %ld\n", limit);
		return -EINVAL;
	}

	snprintf(file_path, MAX_FILE_PATH_LEN, "%s/%s", base_path, base_name);
	f = fopen(file_path, "rb");
	if (f == NULL) {
		log_error("Unable to read open file %s: %s - (%d)\n", file_path, strerror(errno), errno);
		return -errno;
	}
	*file_size = fread(output_buffer, 1, limit, f);
	fclose(f);
	if (*file_size == 0) {
		log_error("Unable to read from file %s: %s - (%d)\n", file_path, strerror(errno), errno);
		return -errno;
	}
	return TUF_SUCCESS;
}

size_t write_file_posix(const char *base_name, const char *data, size_t len, const char *base_path)
{
	char file_path[MAX_FILE_PATH_LEN];
	size_t ret;
	FILE *f;

	snprintf(file_path, MAX_FILE_PATH_LEN, "%s/%s", base_path, base_name);
	f = fopen(file_path, "wb");

	if (f == NULL) {
		log_error("Unable to write open file %s: %s - (%d)\n", file_path, strerror(errno), errno);
		return -errno;
	}
	ret = fwrite(data, 1, len, f);
	fclose(f);
	if (ret < len)
		return -1;

	return TUF_SUCCESS;
}

int remove_local_file_posix(const char *base_name, char *base_path)
{
	char file_path[MAX_FILE_PATH_LEN];

	snprintf(file_path, MAX_FILE_PATH_LEN, "%s/%s", base_path, base_name);
	return unlink(file_path);
}

int fetch_file(const char *file_base_name, unsigned char *target_buffer, size_t target_buffer_len, size_t *file_size)
{
	/* For now, simulating files download using local copies */
	int ret = read_file_posix(file_base_name, target_buffer, target_buffer_len, TUF_TEST_FILES_PATH, file_size);

	// log_debug("fetch_file ret=%d\n", ret);
	if (ret < 0)
		return TUF_HTTP_NOT_FOUND;
	return 0;
}

int read_local_file(enum tuf_role role, unsigned char *target_buffer, size_t target_buffer_len, size_t *file_size)
{
	const char *role_name = get_role_name(role);
	char role_file_name[25];
	int ret;

	snprintf(role_file_name, sizeof(role_file_name), "%s.json", role_name);

	ret = read_file_posix(role_file_name, target_buffer, target_buffer_len, TUF_LOCAL_FILES_PATH, file_size);
	if (ret < 0)
		return ret;

	return TUF_SUCCESS;
}

int write_local_file(enum tuf_role role, const char *data, size_t len)
{
	const char *role_name = get_role_name(role);
	char role_file_name[20];
	int ret;

	snprintf(role_file_name, sizeof(role_file_name), "%s.json", role_name);
	ret = write_file_posix(role_file_name, data, len, TUF_LOCAL_FILES_PATH);
	return ret;
}

int remove_local_role_file(enum tuf_role role)
{
	const char *role_name = get_role_name(role);
	char role_file_name[20];

	snprintf(role_file_name, sizeof(role_file_name), "%s.json", role_name);
	return remove_local_file_posix(role_file_name, TUF_LOCAL_FILES_PATH);
}
