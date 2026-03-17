cmake_minimum_required(VERSION 3.10)

# VPP plugin CMakeLists
# Build: mkdir build && cd build && cmake -DVPP_INCLUDE_DIR=/usr/include/vpp .. && make

project(gm_ipsec_plugin C)

find_path(VPP_INCLUDE_DIR vnet/vnet.h
    HINTS ${VPP_INCLUDE_DIR} /usr/include/vpp /opt/vpp/include)

if (NOT VPP_INCLUDE_DIR)
    message(WARNING "VPP headers not found - plugin will not be built")
    return()
endif()

add_library(gm_ipsec_plugin MODULE
    gm_ipsec.c
    ../../crypto/sm4.c
    ../../crypto/sm3.c
)

target_include_directories(gm_ipsec_plugin PRIVATE
    ${VPP_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../
)

target_compile_options(gm_ipsec_plugin PRIVATE -Wall -Wextra -O2)
set_target_properties(gm_ipsec_plugin PROPERTIES PREFIX "")

install(TARGETS gm_ipsec_plugin
    LIBRARY DESTINATION /usr/lib/vpp_plugins)
