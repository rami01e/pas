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

# v2.6.3: x86_64-only inline-hook backstop (Dobby) for the Vulkan identity.
# ARM-translated apps (MuMu/Houdini: arm64-only libraries executed through the
# native bridge) resolve Vulkan symbols outside every PLT/GOT surface we can
# patch, so the identity hooks must sit on the x86_64 libvulkan.so function
# bodies themselves. ARM builds are completely unaffected.
if(ANDROID_ABI STREQUAL "x86_64")
    include(FetchContent)
    set(DOBBY_GENERATE_SHARED OFF CACHE BOOL "" FORCE)
    set(DOBBY_DEBUG OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(dobby
        GIT_REPOSITORY https://github.com/jmpews/Dobby.git
        GIT_TAG latest
        GIT_SHALLOW TRUE
        GIT_PROGRESS TRUE)
    FetchContent_GetProperties(dobby)
    if(NOT dobby_POPULATED)
        FetchContent_Populate(dobby)
        # Neutralize EVERY closure-bridge/trampoline .asm in Dobby. They rely
        # on a cdecl macro that only a preprocessing assembler pass would
        # expand, and CMake compiles .asm without preprocessing - so they fail
        # under the NDK on every architecture. The bridges serve only
        # DobbyInstrument, which the PAS inline backstop never calls (plain
        # DobbyHook uses inline trampolines exclusively). Stubs keep the
        # symbols so any stray reference still resolves; unreferenced archive
        # members are never pulled into the final link.
        file(GLOB_RECURSE _pas_dobby_asm_files
            "${dobby_SOURCE_DIR}/source/TrampolineBridge/ClosureTrampolineBridge/*.asm")
        foreach(_asm ${_pas_dobby_asm_files})
            file(WRITE "${_asm}" [==[
# Neutralized by PAS (see app/src/main/cpp/CMakeLists.txt): the closure
# bridges/trampolines are only used by DobbyInstrument, which the PAS inline
# backstop never calls. Symbols kept so any stray reference still resolves.
    .text
    .globl closure_bridge_asm
closure_bridge_asm:
    ret
    .globl closure_bridge_asm_end
closure_bridge_asm_end:
    .globl closure_trampoline_asm
closure_trampoline_asm:
    ret
    .globl closure_trampoline_asm_end
closure_trampoline_asm_end:
]==])
        endforeach()
        add_subdirectory(${dobby_SOURCE_DIR} ${dobby_BINARY_DIR})
    endif()
    target_include_directories(pas PRIVATE ${dobby_SOURCE_DIR}/include)
    target_compile_definitions(pas PRIVATE PAS_HAVE_DOBBY=1)
    target_link_libraries(pas dobby)
endif()

target_link_libraries(pas
    log
    dl
    bytehook::bytehook)

if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_link_libraries(pas shadowhook::shadowhook)
endif()