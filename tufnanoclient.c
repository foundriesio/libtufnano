#include "libtufnano_internal.h"

extern void *tuf_get_application_context();

// 1. load_root: local root not found.
//  Does it require initial version of root metadata to be preprovisioned?
// If so, please, specify the directory/definition in the comment to `tuf_refresh`.

int main() {
  const size_t buf_size = 10 * 1024;
  unsigned char buffer[buf_size];

  void* ctx = tuf_get_application_context();
  time_t cur_time = get_current_gmt_time();

  int rc = tuf_refresh(ctx, cur_time, buffer, buf_size);
  if (rc != TUF_SUCCESS)  {
    printf("Failed to refresh TUF metadata: %d", rc);
  }

  return 0;
}
