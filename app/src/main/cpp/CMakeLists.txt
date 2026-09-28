cmake_minimum_required(VERSION 3.22)
project(nvd C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(bytehook REQUIRED CONFIG)

add_library(nvd SHARED
    nvd.cpp
    hide_iface.cpp
    hide_fs.cpp
    hide_net.cpp
    hide_netlink.cpp
    hide_ioctl.cpp
    hide_props.cpp)

target_compile_options(nvd PRIVATE -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden)

if(ANDROID_ABI STREQUAL "arm64-v8a" OR ANDROID_ABI STREQUAL "x86_64")
    target_link_options(nvd PRIVATE "-Wl,-z,max-page-size=16384")
endif()

target_link_libraries(nvd
    log
    dl
    bytehook::bytehook)
