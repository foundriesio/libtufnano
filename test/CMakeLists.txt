cmake_minimum_required( VERSION 3.13.0 )
project( "libtufnano unit test"
         VERSION 1.0.0
         LANGUAGES C )

# Allow the project to be organized into folders.
set_property( GLOBAL PROPERTY USE_FOLDERS ON )

# Use C11.
set( CMAKE_C_STANDARD 11 )
set( CMAKE_C_STANDARD_REQUIRED ON )

# Do not allow in-source build.
if( ${PROJECT_SOURCE_DIR} STREQUAL ${PROJECT_BINARY_DIR} )
    message( FATAL_ERROR "In-source build is not allowed. Please build in a separate directory, such as ${PROJECT_SOURCE_DIR}/build." )
endif()

# Set global path variables.
get_filename_component(__MODULE_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set( MODULE_ROOT_DIR ${__MODULE_ROOT_DIR} CACHE INTERNAL "libtufnano source root." )
set( UNIT_TEST_DIR ${MODULE_ROOT_DIR}/test/unit-test CACHE INTERNAL "libtufnano unit test directory." )
set( UNITY_DIR ${UNIT_TEST_DIR}/Unity CACHE INTERNAL "Unity library source directory." )
set( MBEDTLS_DIR ${UNIT_TEST_DIR}/mbedtls CACHE INTERNAL "MbedTLS library source directory." )
set( CORE_JSON_DIR ${UNIT_TEST_DIR}/coreJSON CACHE INTERNAL "CoreJSON library source directory." )
set( TUF_SAMPLE_CLIENT_DIR ${MODULE_ROOT_DIR}/tuf_sample_client CACHE INTERNAL "TUF sample client source directory." )

# Configure options to always show in CMake GUI.
option( BUILD_CLONE_SUBMODULES
        "Set this to ON to automatically clone any required Git submodules. When OFF, submodules must be manually cloned."
        OFF )

# Set output directories.
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )

add_compile_definitions(TUF_ENABLE_ED25519)

# ================================ Coverity Analysis Configuration =================================

add_compile_definitions(TUF_JSON_QUERY_KEY_SEPARATOR='/')

# Include filepaths for source and include.
include( ${MODULE_ROOT_DIR}/tufFilePaths.cmake )
include( ${TUF_SAMPLE_CLIENT_DIR}/tufSampleClientFilePaths.cmake )
include( unit-test/mbedtls_build.cmake )
include( unit-test/libtufnano_client.cmake )
include( ${CORE_JSON_DIR}/jsonFilePaths.cmake )

add_mbedtls_targets()
add_libtufnano_client_targets()

# Target for Coverity analysis that builds the library.
add_library( coverity_analysis
             ${TUF_SOURCES}
             ${TUF_FIAT_SOURCES}
             ${JSON_SOURCES}
             ${TUF_SAMPLE_CLIENT_SOURCES} )
# TUF public include path.
target_include_directories( coverity_analysis PUBLIC ${TUF_INCLUDE_PUBLIC_DIRS} ${MBEDTLS_INCLUDE_DIRS} ${JSON_INCLUDE_PUBLIC_DIRS} ${TUF_SAMPLE_CLIENT_INCLUDE_PUBLIC_DIRS} )

# When building the coverity analysis target we disable debug
target_compile_options(coverity_analysis PUBLIC -DNDEBUG )

target_compile_options(coverity_analysis PUBLIC -DTUF_JSON_QUERY_KEY_SEPARATOR='/')

#  ====================================  Test Configuration ========================================

# Include Unity build configuration.
include( unit-test/unity_build.cmake )

# Check if the Unity source directory exists, and if not present, clone the submodule
# if BUILD_CLONE_SUBMODULES configuration is enabled.
if( NOT EXISTS ${UNITY_DIR}/src )
    # Attempt to clone Unity.
    if( ${BUILD_CLONE_SUBMODULES} )
        clone_unity()
    else()
        message( FATAL_ERROR "The required submodule Unity does not exist. Either clone it manually, or set BUILD_CLONE_SUBMODULES to 1 to automatically clone it during build." )
    endif()
endif()

# Add unit test and coverage configuration.

# Use CTest utility for managing test runs. This has to be added BEFORE
# defining test targets with add_test()
enable_testing()

# Add build targets for Unity and Unit, required for unit testing.
add_unity_targets()

# Add function to enable Unity based tests and coverage.
include( ${MODULE_ROOT_DIR}/tools/unity/create_test.cmake )

# Include build configuration for unit tests.
add_subdirectory( unit-test )

#  ==================================== Coverage Analysis configuration ============================

# Add a target for running coverage on tests.
add_custom_target( coverage
    COMMAND ${CMAKE_COMMAND} -DUNITY_DIR=${UNITY_DIR}
    -P ${MODULE_ROOT_DIR}/tools/unity/coverage.cmake
    DEPENDS mbedtls libtufnano_client unity libtufnano_utest
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
