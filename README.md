Lightweight TUF library
=======================

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

Limitations
-----------
- Metadata must be provided by the TUF server as JSON files, and the `signed`
section must be formatted as canonical JSON
- Only `sha256` hashes are supported for now
- Only `rsassa-pss-sha256` and `ed25519` signatures are supported for now
- No `delegated roles` support
- No `consistent snapshot` mode support

Building and running build-in tests
-----------------------------------
Inside the cloned directory:
```
git submodule init
git submodule update
cd tests
cmake -B build
cd build
make
make test
make coverage
```

Writing a client application
----------------------------
TODO
