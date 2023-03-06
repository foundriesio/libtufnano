
# This file is to add source files and include directories
# into variables so that it can be reused from different repositories
# in their Cmake based build system by including this file.
#
# Files specific to the repository such as test runner, platform tests
# are not added to the variables.

# TUF library source files.
set( TUF_SOURCES
     ${CMAKE_CURRENT_LIST_DIR}/src/libtufnano.c )

set( TUF_FIAT_SOURCES
     ${CMAKE_CURRENT_LIST_DIR}/ext/fiat/src/curve25519.c )

# TUF library Public Include directories.
set( TUF_INCLUDE_PUBLIC_DIRS
     ${CMAKE_CURRENT_LIST_DIR}/src/include
     ${CMAKE_CURRENT_LIST_DIR}/ext/fiat/src/ )

