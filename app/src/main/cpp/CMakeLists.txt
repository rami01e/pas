cmake_minimum_required(VERSION 3.22)
project(pas C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(bytehook REQUIRED CONFIG)

add_library(pas SHARED
    pas.cpp
    hide_iface.cpp
    hide_fs.cpp
    hide_net.cpp
    hide_netlink.cpp
    hide_ioctl.cpp
    hide_props.cpp
    hide_gpu.cpp
    hide_vulkan.cpp
    hide_ssl.cpp
    hide_antiemu.cpp
    hook_ssl_arm64.cpp)

target_compile_options(pas PRIVATE -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden)

if(ANDROID_ABI STREQUAL "arm64-v8a" OR ANDROID_ABI STREQUAL "x86_64")
    target_link_options(pas PRIVATE "-Wl,-z,max-page-size=16384")
endif()

# ShadowHook ships only armeabi-v7a and arm64-v8a native libs. Only link it
# for the ARM64 build; on x86_64 the ARM64 SSL hook unit compiles to a no-op
# via the PAS_HAVE_SHADOWHOOK guard below.
if(ANDROID_ABI STREQUAL "arm64-v8a")
    find_package(shadowhook REQUIRED CONFIG)
    target_compile_definitions(pas PRIVATE PAS_HAVE_SHADOWHOOK=1)
endif()

# v2.6.5: the Dobby inline-hook experiment was removed. Device evidence
# (MuMu/Houdini) showed the ARM public-library shim libvulkan.so (45 KB)
# forwards into the real x86_64 loader via Houdini's dlsym-based machinery,
# so the existing dlsym chain - now allowed for Houdini callers via
# CallerAllowDlsymChain - covers ARM-translated apps without any inline
# hooking. The guarded inline-backstop code in hide_vulkan.cpp compiles out
# (PAS_HAVE_DOBBY is no longer defined) and stays as a no-op.

target_link_libraries(pas
    log
    dl
    bytehook::bytehook)

if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_link_libraries(pas shadowhook::shadowhook)
endif()