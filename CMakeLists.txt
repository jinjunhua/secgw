cmake_minimum_required(VERSION 3.16)
project(secgw C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(BUILD_TESTS      "Build unit tests"                 ON)
option(BUILD_VPP_PLUGIN "Build VPP plugin"                 OFF)
option(WITH_DPDK        "Link against DPDK"                OFF)

# ------------------------------------------------------------------ #
# Compiler flags                                                       #
# ------------------------------------------------------------------ #
set(WARN_FLAGS "-Wall -Wextra -Wno-unused-parameter -Wno-sign-compare")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARN_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG   "-O0 -g3 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ------------------------------------------------------------------ #
# GM Crypto library (standalone, no external deps)                     #
# ------------------------------------------------------------------ #
add_library(gm_crypto STATIC
    src/crypto/sm2.c
    src/crypto/sm3.c
    src/crypto/sm4.c
)
target_include_directories(gm_crypto PUBLIC src/crypto)

# ------------------------------------------------------------------ #
# DPDK integration (optional)                                          #
# ------------------------------------------------------------------ #
if (WITH_DPDK)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DPDK REQUIRED libdpdk)

    add_library(gm_dpdk STATIC
        src/dpdk/dpdk_gm_crypto.c
    )
    target_compile_definitions(gm_dpdk PRIVATE HAVE_DPDK)
    target_include_directories(gm_dpdk PRIVATE
        src/dpdk
        ${DPDK_INCLUDE_DIRS}
    )
    target_link_libraries(gm_dpdk
        gm_crypto
        ${DPDK_LIBRARIES}
    )
else()
    # Software-only fallback
    add_library(gm_dpdk STATIC
        src/dpdk/dpdk_gm_crypto.c
    )
    target_include_directories(gm_dpdk PRIVATE src/dpdk)
    target_link_libraries(gm_dpdk gm_crypto)
endif()

# ------------------------------------------------------------------ #
# VPP plugin (optional)                                                #
# ------------------------------------------------------------------ #
if (BUILD_VPP_PLUGIN)
    add_subdirectory(src/vpp/gm_ipsec_plugin)
endif()

# ------------------------------------------------------------------ #
# Tests                                                                #
# ------------------------------------------------------------------ #
if (BUILD_TESTS)
    enable_testing()

    # SM3 test
    add_executable(test_sm3 tests/test_sm3.c)
    target_link_libraries(test_sm3 gm_crypto)
    add_test(NAME sm3 COMMAND test_sm3)

    # SM4 test
    add_executable(test_sm4 tests/test_sm4.c)
    target_link_libraries(test_sm4 gm_crypto)
    add_test(NAME sm4 COMMAND test_sm4)

    # SM2 test
    add_executable(test_sm2 tests/test_sm2.c)
    target_link_libraries(test_sm2 gm_crypto)
    add_test(NAME sm2 COMMAND test_sm2)

    # IPSec (software path) test
    add_executable(test_ipsec tests/test_ipsec.c)
    target_link_libraries(test_ipsec gm_dpdk gm_crypto)
    add_test(NAME ipsec COMMAND test_ipsec)

    # Combined runner
    add_executable(test_all
        tests/test_main.c
        tests/test_sm3.c
        tests/test_sm4.c
        tests/test_sm2.c
        tests/test_ipsec.c
    )
    target_compile_definitions(test_all PRIVATE ALL_TESTS)
    target_link_libraries(test_all gm_dpdk gm_crypto)
    add_test(NAME all COMMAND test_all)
endif()

# ------------------------------------------------------------------ #
# Install                                                              #
# ------------------------------------------------------------------ #
install(TARGETS gm_crypto
    ARCHIVE DESTINATION lib)
install(DIRECTORY src/crypto/
    DESTINATION include/gm_crypto
    FILES_MATCHING PATTERN "*.h")
