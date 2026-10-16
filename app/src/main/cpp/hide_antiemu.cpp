// hide_antiemu.cpp - ANTI-EMU native layer (v2.9.0).
//
// Masks the emulator fingerprints the bundled ad SDKs probe outside the
// Java Build.* surface:
//
//   - qemu pipes:    /dev/qemu_pipe, /dev/socket/qemud, /dev/socket/genyd,
//                    /sys/qemu_trace, /system/bin/qemu-props,
//                    /system/lib[64]/libc_malloc_debug_qemu.so
//   - DMI tree:      /sys/class/dmi/**, /sys/devices/virtual/dmi/**
//                    (a real phone has no DMI at all, so returning ENOENT
//                    is what stock Android does)
//   - MuMu dirs:     /data/system/etc/mumu-configs/** - the ROM config tree
//                    sg.bigo-style detectors scan for
//   - emulator props: ro.kernel.qemu, ro.boot.qemu*, ro.chipname,
//                    ro.dalvik.vm.native.bridge, persist.sys.nativebridge,
//                    ro.enable.native.bridge.exec, dalvik.vm.isa.x86.features,
//                    and any key containing nemu / mumu / qemu / goldfish /
//                    ranchu / vbox / geny
//
// Runtime-gated on g_anti_emu; the toggle is delivered from Kotlin via
// nativeSetAntiEmu(). Caller filter is the standard module one
// (CallerAllowHooks), which excludes Houdini / native-bridge libs so
// their own property reads stay raw.
//
// v2.9.0 CI fixes (the first draft failed the GitHub Actions build):
//  - #include <jni.h> added: JNIEnv/JNICALL were unknown type names.
//  - BYTEHOOK_CALL_PREV(MyFStatAt, ...) corrected to MyFstatAt. The macro
//    pastes the hook-function name (decltype(&func) +
//    bytehook_get_prev_func((void*)(&func))), so a case typo is a hard
//    "use of undeclared identifier" error, twice per site.
//  - Coverage: the bare /sys/class/dmi and /sys/devices/virtual/dmi dirs
//    (the prefix rules only matched children), plus goldfish / ranchu /
//    vbox / geny / nemu / mumu path trees and prop-name substrings.

#include "pas.h"

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "bytehook.h"

namespace pas {

static volatile bool g_anti_emu = false;

void SetAntiEmu(bool on) {
    g_anti_emu = on;
    Log("native: anti-emu %s", on ? "on" : "off");
}

bool AntiEmuEnabled() {
    return g_anti_emu;
}

// ---------------------------------------------------------------------------
// path filter
// ---------------------------------------------------------------------------

static bool IsAntiEmuPath(const char* path) {
    if (!g_anti_emu || path == nullptr || path[0] != '/') return false;

    // Exact matches (the SG Bigo / classic emulator-detector list)
    static const char* const kExact[] = {
        "/dev/qemu_pipe",
        "/dev/socket/qemud",
        "/dev/socket/genyd",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/system/lib64/libc_malloc_debug_qemu.so",
        "/sys/class/dmi",             // the DMI dir itself, not only children
        "/sys/devices/virtual/dmi",
    };
    for (const char* p : kExact) {
        if (strcmp(path, p) == 0) return true;
    }

    // Basename patterns (some ROMs relocate these or symlink them)
    if (strstr(path, "qemu_pipe") != nullptr) return true;
    if (strstr(path, "/libc_malloc_debug_qemu") != nullptr) return true;

    // DMI tree (real phones have no DMI; hidden as ENOENT)
    if (strncmp(path, "/sys/class/dmi/", 15) == 0) return true;
    if (strncmp(path, "/sys/devices/virtual/dmi/", 25) == 0) return true;

    // Emulator ROM trees. Slash-prefixed on purpose: a path segment must
    // START with the token, so an app whose own data dir merely contains
    // the token mid-segment (com.mumu.game) is not caught.
    if (strstr(path, "/goldfish") != nullptr) return true;  // /dev/goldfish_pipe
    if (strstr(path, "/ranchu") != nullptr) return true;
    if (strstr(path, "/vbox") != nullptr) return true;      // VirtualBox ROMs
    if (strstr(path, "/geny") != nullptr) return true;
    if (strstr(path, "/nemu") != nullptr) return true;      // MuMu nemu daemons
    if (strstr(path, "/mumu") != nullptr) return true;      // /data/system/etc/mumu-configs/**

    return false;
}

// ---------------------------------------------------------------------------
// open family - every entry point the SDKs use for File.exists() / FileInputStream
// ---------------------------------------------------------------------------

static int MyOpen(const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    mode_t mode = 0;
#if defined(O_TMPFILE)
    // O_TMPFILE is (__O_TMPFILE | O_DIRECTORY); testing the full composite
    // keeps plain O_DIRECTORY opens out of the varargs branch.
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap; va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return BYTEHOOK_CALL_PREV(MyOpen, path, flags, mode);
}

static int MyOpen2(const char* path, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyOpen2, path, flags);
}

static int MyOpenAt(int dirfd, const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    if (path && path[0] == '/' && IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    mode_t mode = 0;
#if defined(O_TMPFILE)
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap; va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return BYTEHOOK_CALL_PREV(MyOpenAt, dirfd, path, flags, mode);
}

static int MyOpenAt2(int dirfd, const char* path, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (path && path[0] == '/' && IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyOpenAt2, dirfd, path, flags);
}

static FILE* MyFopen(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return nullptr; }
    return BYTEHOOK_CALL_PREV(MyFopen, path, mode);
}

static int MyAccess(const char* path, int mode) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyAccess, path, mode);
}

static int MyFAccessAt(int dirfd, const char* path, int mode, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (path && path[0] == '/' && IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyFAccessAt, dirfd, path, mode, flags);
}

static int MyStat(const char* path, struct stat* buf) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyStat, path, buf);
}

static int MyLstat(const char* path, struct stat* buf) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyLstat, path, buf);
}

static int MyFstatAt(int dirfd, const char* path, struct stat* buf, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (path && path[0] == '/' && IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyFstatAt, dirfd, path, buf, flags);
}

// ---------------------------------------------------------------------------
// property filter - Appsflyer / Mintegral / generic emulator probes
// ---------------------------------------------------------------------------

static bool IsAntiEmuProp(const char* name) {
    if (!g_anti_emu || name == nullptr) return false;

    static const char* const kProps[] = {
        "ro.kernel.qemu",
        "ro.boot.qemu",
        "ro.boot.qemu.avd_name",
        "ro.kernel.qemu.gles",
        "ro.chipname",                     // Qualcomm-ism; a real Exynos has none
        "ro.dalvik.vm.native.bridge",      // Houdini indicator (app-level read only;
                                           // native-bridge libs are excluded by
                                           // the caller filter so ART is unaffected)
        "persist.sys.nativebridge",
        "ro.enable.native.bridge.exec",
        "dalvik.vm.isa.x86.features",
    };
    for (const char* p : kProps) {
        if (strcmp(name, p) == 0) return true;
    }
    // Substring catches: every ro.kernel.qemu.* / ro.boot.qemu.* variant,
    // MuMu / Nemu (init.svc_debug_pid.nemuhotd & friends), goldfish / ranchu
    // (AOSP emulators), vbox86 (VirtualBox ROMs), Genymotion (genyd).
    static const char* const kPropSubstr[] = {
        "qemu", "goldfish", "ranchu", "vbox", "geny", "nemu", "mumu",
    };
    for (const char* s : kPropSubstr) {
        if (strstr(name, s) != nullptr) return true;
    }

    return false;
}

static int MyPropGet(const char* name, char* value) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuProp(name)) {
        if (value != nullptr) value[0] = '\0';
        return 0;
    }
    return BYTEHOOK_CALL_PREV(MyPropGet, name, value);
}

static const prop_info* MyPropFind(const char* name) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuProp(name)) return nullptr;
    return BYTEHOOK_CALL_PREV(MyPropFind, name);
}

// ---------------------------------------------------------------------------

void InstallAntiEmuHooks() {
    int okFs = 0;
    struct Spec { const char* sym; void* fn; };
    static const Spec kFsSpecs[] = {
        {"open",       (void*)MyOpen},
        {"__open_2",   (void*)MyOpen2},
        {"openat",     (void*)MyOpenAt},
        {"__openat_2", (void*)MyOpenAt2},
        {"fopen",      (void*)MyFopen},
        {"access",     (void*)MyAccess},
        {"faccessat",  (void*)MyFAccessAt},
        {"stat",       (void*)MyStat},
        {"lstat",      (void*)MyLstat},
        {"fstatat",    (void*)MyFstatAt},
    };
    for (const Spec& s : kFsSpecs) {
        bytehook_stub_t st = bytehook_hook_partial(
            CallerAllowHooks, nullptr, "libc.so", s.sym, s.fn, nullptr, nullptr);
        if (st) okFs++;
    }

    int okProp = 0;
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libc.so", "__system_property_get",
                              (void*)MyPropGet, nullptr, nullptr)) okProp++;
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libc.so", "__system_property_find",
                              (void*)MyPropFind, nullptr, nullptr)) okProp++;

    Log("native: anti-emu hooks installed fs=%d/%d prop=%d/2 (runtime-gated)",
        okFs, (int)(sizeof(kFsSpecs) / sizeof(kFsSpecs[0])), okProp);
}

}  // namespace pas

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetAntiEmu(JNIEnv* env, jobject thiz, jboolean on) {
    (void)env;
    (void)thiz;
    pas::SetAntiEmu(on == JNI_TRUE);
}