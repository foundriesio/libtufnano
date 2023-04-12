# TUF library source files.
set( TUF_SAMPLE_CLIENT_SOURCES
     ${CMAKE_CURRENT_LIST_DIR}/tuf_client_platform.c
     ${CMAKE_CURRENT_LIST_DIR}/tuf_sample_client.c )

# TUF library Public Include directories.
set( TUF_SAMPLE_CLIENT_INCLUDE_PUBLIC_DIRS
     ${CMAKE_CURRENT_LIST_DIR}/ )

add_compile_definitions(JSON_QUERY_KEY_SEPARATOR='/')
