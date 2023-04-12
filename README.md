libtufnano - Lightweight TUF library
====================================

This is a lightweight implementation of a subset of 
[The Update Framework (TUF) specification](https://theupdateframework.github.io/specification/latest/),
written in C. 
It was created having in mind usage in restricted environments, such as 
microcontroller units (MCUs).


Dependencies
------------
- [coreJSON](https://github.com/FreeRTOS/coreJSON)
- [mbedtls](https://github.com/Mbed-TLS/mbedtls)
- [Unity](https://github.com/ThrowTheSwitch/Unity.git) for unit testing

All dependencies were added to the current repository as github submodules.


Limitations
-----------
- Metadata must be provided by the TUF server as JSON files, and the `signed`
section must be formatted as canonical JSON
- Only `sha256` hashes are supported for now
- Only `rsassa-pss-sha256` and `ed25519` signatures are supported for now
- No `delegated roles` support
- No `consistent snapshot` mode support


Building and running built-in tests
-----------------------------------
Inside the cloned directory:
```
git submodule init
git submodule update
cmake -S test -B build
cd build
make
make test
make coverage
```

Writing a client application
----------------------------
The client code should:
- `#include "libtufnano.h"`
- Provide a `libtufnano_config.h` file including definitions for `log_debug`, 
`log_info`, and `log_error`. If `ed25519` support is wanted, `TUF_ENABLE_ED25519`
can be defined in this file as well.

- Implement the following functions
```
int tuf_client_read_local_file(enum tuf_role role, unsigned char *target_buffer, size_t target_buffer_len, size_t *file_size, void *application_context);

int tuf_client_write_local_file(enum tuf_role role, const unsigned char *data, size_t len, void *application_context);

int tuf_client_fetch_file(const char *file_base_name, unsigned char *target_buffer, size_t target_buffer_len, size_t *file_size, void *application_context);
```
- Call `tuf_refresh` periodically to fetch the updated metadata
```
int tuf_refresh(void *application_context, time_t reference_time, unsigned char *data_buffer, size_t data_buffer_len);
```
In case of success (returning `TUF_SUCCESS`), the data_buffer will contain a NULL 
terminated string with the content of the `targets.json` metadata file. It is up
to the client application to parse it (using, for example `coreJSON`), and download 
the required artifacts.


Building libtufnano together with the client application
--------------------------------------------------------
If using `cmake`, include tufFilePaths.cmake and add `${TUF_SOURCES}` and, if 
enabling support for `ed25519`, `${TUF_FIAT_SOURCES}` in the list of source files.
`${TUF_INCLUDE_PUBLIC_DIRS}` should be added to the include paths list.

If referencing the libtufnano source files explicitly, just build and link `src/libtufnano.c` 
and (if enabling support for `ed25519`), `ext/fiat/src/curve25519.c` together with 
the main application. `src/include` and `ext/fiat/src/` should be included in the
include path.
