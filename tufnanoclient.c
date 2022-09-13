#include "libtufnano_internal.h"

extern void *tuf_get_application_context(const char *provisioning_path, const char *local_path, const char *remote_path);

int main() {
  const size_t buf_size = 1024 * 1024;
  unsigned char buffer[buf_size];

  void* ctx = tuf_get_application_context("prov", "tuf", "cur-tuf");
  time_t cur_time = get_current_gmt_time();
  
  int rc = tuf_refresh(ctx, cur_time, buffer, buf_size);
  if (rc != TUF_SUCCESS)  {
    printf("Failed to refresh TUF metadata: %d", rc);
  }

  return 0;
}
