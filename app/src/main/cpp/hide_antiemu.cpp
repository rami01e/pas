// hide_antiemu.cpp - ANTI-EMU native layer (v3.0.0).
//
// v3.0.0 is a deliberate scope reduction + reliability fix. The feature now
// owns exactly three things, all runtime-gated on g_anti_emu:
//
//   1. Path masking (unchanged rule set). open/openat/fopen/access/faccessat/
//      stat/lstat/fstatat and the raw syscall() layer answer ENOENT for the
//      qemu/houdini/root/emulator artifact paths and families.
//   2. Ignorable-codepoint normalization of every checked path. Duck
//      Detector's "Android/data Ignorable CodePoint Bypass" inserts invisible
//      Unicode codepoints (U+200B ZWSP, U+00AD soft hyphen, ...) into a path
//      so exact-byte filters do not match while the kernel still resolves the
//      same directory. Every path is now stripped of ignorable codepoints
//      before the rule set runs, closing that bypass class for this layer.
//   3. Emulator-artifact property blanking (ro.kernel.qemu family, MuMu/nemu/
//      goldfish/ranchu/vbox/geny keys) - kept because blanking a value is not
//      an identity rewrite and is what the feature is named for.
//      Plus a minimal ADB-runtime alignment pair (see AntiEmuPropRewrite):
//      init.svc.adbd is reported "running" and persist.sys.usb.config "mtp"
//      so every reader sees one consistent story (adbd really is running on
//      MuMu; the previous stopped-vs-socket-vs-TCP split is what Duck's
//      AdbRuntime detector flags HIGH).
//
// Removed in v3.0.0 (each had a single owner elsewhere or broke apps):
//   - Kernel identity spoofing (uname release/version rewrite, /proc/version
//     serving, the Java os.version property). The raw kernel is reported
//     consistently from every source; contradicting it with a fake release
//     only manufactured an inconsistency the detector could measure.
//   - ALL /proc and /sys content serving (the memfd engine: cpuinfo, status,
//     selinux/enforce, version, maps, smaps, mounts, mountinfo, mountstats).
//     Rewritten maps/mounts lines lied about the app's own split APKs and
//     failed integrity checks; the seccomp/NNP install is gone with it.
//   - The x86 -> ARM property story (ABI/abilist/bionic/dalvik-isa rewrites,
//     the hardware/board family, ro.build.host/user). The CPU and ABI
//     toggles own that identity; per-app duplicates only fought them.
//
// Arming is now race-free: SetAntiEmu(true) installs the hooks itself
// (InstallAntiEmuHooks is idempotent), so a late toggle or a lost
// InitWorker/Java race can no longer leave the gate on with no hooks
// behind it. InitWorker's stage5b call remains as the early-install path.
//
// Caller filter is the standard module one (CallerAllowHooks), which
// excludes Houdini / native-bridge libs so their own property reads stay
// raw and MuMu's injected helpers keep working.

#include "pas.h"

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "bytehook.h"

namespace pas {

// ---------------------------------------------------------------------------
// state
// ---------------------------------------------------------------------------
static volatile bool g_anti_emu = false;

bool AntiEmuEnabled() {
    return g_anti_emu;
}

// Forward declarations: the install block below patches these handlers.
static int MyOpen(const char* path, int flags, ...);
static int MyOpen2(const char* path, int flags);
static int MyOpenAt(int dirfd, const char* path, int flags, ...);
static int MyOpenAt2(int dirfd, const char* path, int flags);
static FILE* MyFopen(const char* path, const char* mode);
static int MyAccess(const char* path, int mode);
static int MyFAccessAt(int dirfd, const char* path, int mode, int flags);
static int MyStat(const char* path, struct stat* buf);
static int MyLstat(const char* path, struct stat* buf);
static int MyFstatAt(int dirfd, const char* path, struct stat* buf, int flags);
static long MySyscall(long number, ...);
static int MyPropGet(const char* name, char* value);
static const prop_info* MyPropFind(const char* name);
static void MyPropReadCallback(const prop_info* pi,
                               void (*cb)(void*, const char*, const char*, uint32_t),
                               void* cookie);
static int MyPropForeach(void (*cb)(const prop_info*, void*), void* cookie);

// ---------------------------------------------------------------------------
// hook installation (idempotent + race-safe)
//
// v3.0.0: the install is guarded per symbol. InitWorker (stage5b) and
// SetAntiEmu(true) both funnel through here; whoever arrives first installs,
// the other is a no-op. This is the P0 fix - previously the hooks were
// installed only if the toggle happened to be on at the exact moment the
// worker reached stage5b, and a later nativeSetAntiEmu(true) only flipped
// the runtime gate, leaving Duck reading every masked surface raw.
//
// Each symbol keeps its own stub: if an attempt lands before bytehook_init
// (Java can arm anti-emu while the InitWorker is still starting), the failed
// symbols stay unhooked and any later call retries exactly those - no
// double-hooking, no lost install.
// ---------------------------------------------------------------------------
struct AeHookSpec {
    const char* sym;
    void* fn;
    bytehook_stub_t stub;
};

static AeHookSpec g_ae_hooks[] = {
    {"open",       (void*)MyOpen,       nullptr},
    {"__open_2",   (void*)MyOpen2,      nullptr},
    {"openat",     (void*)MyOpenAt,     nullptr},
    {"__openat_2", (void*)MyOpenAt2,    nullptr},
    {"fopen",      (void*)MyFopen,      nullptr},
    {"access",     (void*)MyAccess,     nullptr},
    {"faccessat",  (void*)MyFAccessAt,  nullptr},
    {"stat",       (void*)MyStat,       nullptr},
    {"lstat",      (void*)MyLstat,      nullptr},
    {"fstatat",    (void*)MyFstatAt,    nullptr},
    {"__system_property_get",            (void*)MyPropGet,          nullptr},
    {"__system_property_find",           (void*)MyPropFind,         nullptr},
    {"__system_property_read_callback",  (void*)MyPropReadCallback, nullptr},
    {"__system_property_foreach",        (void*)MyPropForeach,      nullptr},
    {"syscall",    (void*)MySyscall,    nullptr},
};

static pthread_mutex_t g_ae_install_mtx = PTHREAD_MUTEX_INITIALIZER;
static bool g_ae_all_installed = false;

void InstallAntiEmuHooks() {
    pthread_mutex_lock(&g_ae_install_mtx);
    if (g_ae_all_installed) {
        pthread_mutex_unlock(&g_ae_install_mtx);
        return;
    }
    const size_t total = sizeof(g_ae_hooks) / sizeof(g_ae_hooks[0]);
    size_t ok = 0;
    for (size_t i = 0; i < total; i++) {
        if (g_ae_hooks[i].stub != nullptr) {
            ok++;
            continue;
        }
        g_ae_hooks[i].stub = bytehook_hook_partial(
            CallerAllowHooks, nullptr, "libc.so", g_ae_hooks[i].sym, g_ae_hooks[i].fn,
            nullptr, nullptr);
        if (g_ae_hooks[i].stub != nullptr) ok++;
    }
    if (ok == total) {
        g_ae_all_installed = true;
        Log("native: anti-emu hooks installed %d/%d (runtime-gated)", (int)ok, (int)total);
    } else {
        // bytehook_init has not run yet or a group failed - leave the latch
        // open so the next arm/stage5b call retries the missing symbols.
        Log("native: anti-emu hooks partial %d/%d - will retry on next arm", (int)ok,
            (int)total);
    }
    pthread_mutex_unlock(&g_ae_install_mtx);
}

// ---------------------------------------------------------------------------
// public entry point
// ---------------------------------------------------------------------------
void SetAntiEmu(bool on) {
    g_anti_emu = on;
    if (on) {
        // v3.0.0 (P0): arming guarantees the hooks exist. Idempotent.
        InstallAntiEmuHooks();
    }
    Log("native: anti-emu %s", on ? "on" : "off");
}

// ---------------------------------------------------------------------------
// ignorable-codepoint normalization (v3.0.0, P5)
//
// Duck Detector builds probe paths like "/sdcard/Android/data\u200B/" and
// "/sdcard\u00AD/Android/data" so exact-byte comparisons (the same technique
// that would defeat any static mask list) miss while the kernel resolves the
// identical directory. Every ignorable codepoint is stripped into a stack
// copy before the rule set below runs. The set is a superset of the code
// points Duck's dangerousapps and kernelcheck probes insert.
// ---------------------------------------------------------------------------

static bool IsIgnorableCp(uint32_t cp) {
    return cp == 0x00AD ||  // soft hyphen
           cp == 0x034F ||  // combining grapheme joiner
           cp == 0x061C ||  // arabic letter mark
           cp == 0x115F || cp == 0x1160 || cp == 0x3164 ||  // hangul fillers
           cp == 0x17B4 || cp == 0x17B5 ||  // khmer vowels (invisible)
           cp == 0x180E ||  // mongolian vowel separator
           (cp >= 0x200B && cp <= 0x200F) ||  // ZW* + LRM/RLM
           (cp >= 0x202A && cp <= 0x202E) ||  // directional formatting
           (cp >= 0x2060 && cp <= 0x2064) ||  // word joiner family
           (cp >= 0x2066 && cp <= 0x206F) ||  // directional isolates
           cp == 0xFEFF ||                    // BOM / ZWNBSP
           (cp >= 0xFE00 && cp <= 0xFE0F) ||  // variation selectors
           cp == 0xFFA0 ||                    // halfwidth hangul filler
           (cp >= 0xFFF9 && cp <= 0xFFFB);    // interlinear annotation
}

// Decodes one UTF-8 sequence. Returns byte length, 0 on invalid input.
static size_t Utf8Decode(const unsigned char* s, size_t avail, uint32_t* out) {
    if (avail == 0 || s[0] < 0x80) return 0;
    uint32_t cp = 0;
    size_t len = 0;
    if ((s[0] & 0xE0) == 0xC0) { len = 2; cp = s[0] & 0x1F; }
    else if ((s[0] & 0xF0) == 0xE0) { len = 3; cp = s[0] & 0x0F; }
    else if ((s[0] & 0xF8) == 0xF0) { len = 4; cp = s[0] & 0x07; }
    else return 0;
    if (avail < len) return 0;
    for (size_t i = 1; i < len; i++) {
        if ((s[i] & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (uint32_t)(s[i] & 0x3F);
    }
    *out = cp;
    return len;
}

static bool PathHasIgnorableCp(const char* path) {
    const unsigned char* p = (const unsigned char*)path;
    while (*p) {
        if (*p < 0x80) {
            p++;
            continue;
        }
        uint32_t cp = 0;
        size_t l = Utf8Decode(p, 4, &cp);
        if (l == 0) {
            p++;
            continue;
        }
        if (IsIgnorableCp(cp)) return true;
        p += l;
    }
    return false;
}

// ---------------------------------------------------------------------------
// path filter (rule set unchanged from 2.x - user-mandated keep)
// ---------------------------------------------------------------------------

// v2.9.7: proper prefix match. strncmp(path, prefix, N) with N > strlen(prefix)
// stops at the pattern NUL and never matches children. This helper compares
// exactly strlen(prefix) bytes and then requires the next path byte to be
// either the terminator or '/'.
static bool StartsWithPrefixSeg(const char* path, const char* prefix, size_t plen) {
    if (strncmp(path, prefix, plen) != 0) return false;
    char n = path[plen];
    return n == '\0' || n == '/';
}

static bool IsAntiEmuPathRaw(const char* path) {
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
        // Houdini / NDK translation / native-bridge artifacts (real ARM
        // phones ship none of these)
        "/system/lib/libhoudini.so",
        "/system/lib64/libhoudini.so",
        "/system/lib/libndk_translation.so",
        "/system/lib64/libndk_translation.so",
        "/system/lib64/libnb.so",
        "/system/lib/arm",
        "/system/lib64/arm",
        "/system/lib/arm64",
        "/system/lib64/arm64",
        "/system/lib/x86_64",
        "/system/lib64/x86_64",
        "/system/etc/cpuinfo.x86_64.txt",

        // Root / privilege artifacts. ENOENT while ANTI-EMU is on.
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/sd/xbin/su",
        "/vendor/bin/su",
        "/su/bin/su",
        "/su/bin",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/app/Superuser.apk",
        "/system/app/Superuser",
        "/system/xbin/busybox",
        "/system/bin/busybox",
        "/data/local/tmp/busybox",
        "/system/bin/magisk",
        "/sbin/magisk",
        "/data/adb",
        "/data/adb/magisk",
        "/data/adb/ksu",
        "/system/bin/ksud",
        "/cache/magisk.log",

        // Writability-probe targets
        "/data/local/tmp",
        "/debug_ramdisk",
        "/data/local",
    };
    for (const char* p : kExact) {
        if (strcmp(path, p) == 0) return true;
    }

    // All children of /data/adb (modules, ksu, magisk, ...)
    if (strncmp(path, "/data/adb/", 10) == 0) return true;

    // Magisk paths under common root locations (JJ probes /sbin/.magisk,
    // /bin/magiskhide, /sbin/magiskinit, etc.)
    if (strncmp(path, "/sbin/", 6) == 0 ||
        strncmp(path, "/bin/", 5) == 0 ||
        strncmp(path, "/system/bin/", 12) == 0 ||
        strncmp(path, "/system/xbin/", 13) == 0) {
        if (strstr(path, "magisk") != nullptr || strstr(path, ".magisk") != nullptr) {
            return true;
        }
    }

    // gre0 sysfs (both exact dir and every child). The Java-side
    // NetworkInterface filter hides gre0, but Unity-style readers open
    // /sys/devices/virtual/net/gre0/ifindex directly.
    static const char kGre0Dev[] = "/sys/devices/virtual/net/gre0";
    static const char kGre0Cls[] = "/sys/class/net/gre0";
    if (StartsWithPrefixSeg(path, kGre0Dev, sizeof(kGre0Dev) - 1)) return true;
    if (StartsWithPrefixSeg(path, kGre0Cls, sizeof(kGre0Cls) - 1)) return true;

    // Basename patterns (some ROMs relocate these or symlink them)
    if (strstr(path, "qemu_pipe") != nullptr) return true;
    if (strstr(path, "/libc_malloc_debug_qemu") != nullptr) return true;
    if (strstr(path, "houdini") != nullptr) return true;
    if (strstr(path, "ndk_translation") != nullptr) return true;

    // DMI tree (real phones have no DMI; hidden as ENOENT)
    if (strncmp(path, "/sys/class/dmi/", 15) == 0) return true;
    if (strncmp(path, "/sys/devices/virtual/dmi/", 25) == 0) return true;

    // Emulator ROM trees. Slash-prefixed on purpose: a path segment must
    // START with the token, so an app whose own data dir merely contains
    // the token mid-segment is not caught.
    if (strstr(path, "/goldfish") != nullptr) return true;  // /dev/goldfish_pipe
    if (strstr(path, "/ranchu") != nullptr) return true;
    if (strstr(path, "/vbox") != nullptr) return true;      // VirtualBox ROMs
    if (strstr(path, "/geny") != nullptr) return true;
    if (strstr(path, "/nemu") != nullptr) return true;      // MuMu nemu daemons
    if (strstr(path, "/mumu") != nullptr) return true;      // /data/system/etc/mumu-configs/**
    if (strstr(path, "/com.mumu") != nullptr) return true;  // tmpfs-mounted priv-apps
    if (strstr(path, "/com.nemu") != nullptr) return true;

    // x86 / bridge artifacts only under system trees. NEVER under
    // /data/app/** - the game's own lib/x86_64/*.so files must stay visible
    // or integrity checks would flag the app itself as tampered.
    if (strncmp(path, "/system/", 8) == 0 || strncmp(path, "/vendor/", 8) == 0 ||
        strncmp(path, "/apex/", 6) == 0 || strncmp(path, "/odm/", 5) == 0 ||
        strncmp(path, "/product/", 9) == 0) {
        if (strstr(path, "/x86") != nullptr) return true;
        if (strstr(path, "/arm64/") != nullptr) return true;
        if (strstr(path, "/arm/") != nullptr) return true;
        if (strstr(path, "/libnb") != nullptr) return true;
    }

    return false;
}

static bool IsAntiEmuPath(const char* path) {
    if (!g_anti_emu || path == nullptr || path[0] != '/') return false;
    if (!PathHasIgnorableCp(path)) return IsAntiEmuPathRaw(path);

    // Normalize (drop ignorable codepoints) and re-check.
    char norm[4096];
    size_t o = 0;
    const unsigned char* p = (const unsigned char*)path;
    while (*p && o < sizeof(norm) - 1) {
        if (*p < 0x80) {
            norm[o++] = (char)*p++;
            continue;
        }
        uint32_t cp = 0;
        size_t l = Utf8Decode(p, 4, &cp);
        if (l == 0) {
            p++;
            continue;
        }
        if (IsIgnorableCp(cp)) {
            p += l;
            continue;
        }
        if (o + l >= sizeof(norm)) break;
        memcpy(norm + o, p, l);
        o += l;
        p += l;
    }
    norm[o] = '\0';
    return IsAntiEmuPathRaw(norm);
}

// ---------------------------------------------------------------------------
// libc open family - every entry point the SDKs use for File.exists() /
// FileInputStream / fopen / ifstream
// ---------------------------------------------------------------------------

static int MyOpen(const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
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
// direct syscall() layer
//
// Installed after hide_fs.cpp's syscall hook (pas.cpp stage 4a vs 5b), so
// this is the OUTER layer: anti-emu paths handled first, then falls through
// via BYTEHOOK_CALL_PREV to hide_fs.MySyscall (CPU freq / interface hiding)
// on every other path.
//
// Bytehook's CallerAllowHooks filter excludes Houdini / native-bridge libs
// (their syscalls are x86_64 host syscalls running ARM-translated code; a
// vararg mismatch there would corrupt the bridge). App code (x86_64) and
// the module itself are the only callers that hit this hook, which is
// exactly what we want.
// ---------------------------------------------------------------------------
static long MySyscall(long number, ...) {
    BYTEHOOK_STACK_SCOPE();

    va_list ap;
    va_start(ap, number);
    long a0 = va_arg(ap, long);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    va_end(ap);

    if (g_anti_emu) {
#if defined(__NR_openat)
        if (number == __NR_openat) {
            const char* path = (const char*)a1;
            if (path != nullptr && path[0] == '/' && IsAntiEmuPath(path)) {
                errno = ENOENT;
                return -1;
            }
        }
#endif
#if defined(__NR_open)
        if (number == __NR_open) {
            const char* path = (const char*)a0;
            if (path != nullptr && path[0] == '/' && IsAntiEmuPath(path)) {
                errno = ENOENT;
                return -1;
            }
        }
#endif
#if defined(__NR_faccessat)
        if (number == __NR_faccessat) {
            const char* path = (const char*)a1;
            if (path != nullptr && path[0] == '/' && IsAntiEmuPath(path)) {
                errno = ENOENT;
                return -1;
            }
        }
#endif
#if defined(__NR_stat)
        if (number == __NR_stat) {
            const char* path = (const char*)a0;
            if (path != nullptr && path[0] == '/' && IsAntiEmuPath(path)) {
                errno = ENOENT;
                return -1;
            }
        }
#endif
#if defined(__NR_lstat)
        if (number == __NR_lstat) {
            const char* path = (const char*)a0;
            if (path != nullptr && path[0] == '/' && IsAntiEmuPath(path)) {
                errno = ENOENT;
                return -1;
            }
        }
#endif
#if defined(__NR_newfstatat)
        if (number == __NR_newfstatat) {
            const char* path = (const char*)a1;
            if (path != nullptr && path[0] == '/' && IsAntiEmuPath(path)) {
                errno = ENOENT;
                return -1;
            }
        }
#endif
    }

    // Fall through to the next hook (hide_fs::MySyscall on this chain, which
    // handles CPU freq / interface hiding), then eventually the real syscall.
    return BYTEHOOK_CALL_PREV(MySyscall, number, a0, a1, a2, a3, a4, a5);
}

// ---------------------------------------------------------------------------
// property layer
//
// Kept from 2.x: the emulator-artifact key blanking (IsAntiEmuProp). Blanking
// ro.kernel.qemu & friends is not an identity rewrite - it removes markers
// that have no business existing on the presented device.
//
// New in v3.0.0 (P4): the ADB-runtime alignment pair. MuMu runs adbd outside
// init (socket + TCP listener alive) while init.svc.adbd reads "stopped" -
// that three-way contradiction is exactly what Duck's AdbRuntime detector
// grades HIGH (INIT_STOPPED_WITH_ADB_PROTOCOL / _INIT_SOCKET / _JDWP_SOCKET).
// MuMu's adb cannot be turned off, so the readable state is aligned to the
// truth instead: adbd "running" (it is) and persist.sys.usb.config "mtp"
// (Duck's retail-expected value; adb-over-TCP then reads as ordinary wireless
// debugging, which Duck treats as plain debugging state, not danger).
// sys.usb.state is deliberately left raw - it feeds Duck's isAdbActive()
// only, never a contradiction check.
// ---------------------------------------------------------------------------

static bool IsAntiEmuProp(const char* name) {
    if (!g_anti_emu || name == nullptr) return false;

    static const char* const kProps[] = {
        "ro.kernel.qemu",
        "ro.boot.qemu",
        "ro.boot.qemu.avd_name",
        "ro.kernel.qemu.gles",
        "ro.chipname",                     // Qualcomm-ism; a real Samsung has none
        "ro.dalvik.vm.native.bridge",      // Houdini indicator (app-level read only;
                                           // native-bridge libs are excluded by
                                           // the caller filter so ART is unaffected)
        "ro.enable.native.bridge.exec",
        "ro.vendor.enable.native.bridge.exec64",
        "persist.sys.nativebridge",
        "ro.kernel.ndk.translation",
        "dalvik.vm.isa.x86.features",
        "dalvik.vm.isa.x86_64.features",
    };
    for (const char* p : kProps) {
        if (strcmp(name, p) == 0) return true;
    }
    // Substring catches: every ro.kernel.qemu.* / ro.boot.qemu.* variant,
    // MuMu / Nemu (init.svc_debug_pid.nemuhotd, ro.build.version.nemux,
    // nemud.player_* & friends), goldfish / ranchu (AOSP emulators),
    // vbox86 (VirtualBox ROMs), Genymotion (genyd), x86 isa props.
    static const char* const kPropSubstr[] = {
        "qemu", "goldfish", "ranchu", "vbox", "geny", "nemu", "mumu", "x86",
    };
    for (const char* s : kPropSubstr) {
        if (strstr(name, s) != nullptr) return true;
    }
    return false;
}

// Returns the aligned value for the P4 ADB-runtime pair, or nullptr.
static const char* AntiEmuPropRewrite(const char* name) {
    if (!g_anti_emu || name == nullptr) return nullptr;
    if (strcmp(name, "init.svc.adbd") == 0) return "running";
    if (strcmp(name, "persist.sys.usb.config") == 0) return "mtp";
    return nullptr;
}

static int MyPropGet(const char* name, char* value) {
    BYTEHOOK_STACK_SCOPE();
    if (name != nullptr && value != nullptr) {
        if (IsAntiEmuProp(name)) {
            value[0] = '\0';
            return 0;
        }
        if (const char* v = AntiEmuPropRewrite(name)) {
            size_t l = strlen(v);
            if (l >= PROP_VALUE_MAX) l = PROP_VALUE_MAX - 1;
            memcpy(value, v, l);
            value[l] = '\0';
            return (int)l;
        }
    }
    return BYTEHOOK_CALL_PREV(MyPropGet, name, value);
}

static const prop_info* MyPropFind(const char* name) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuProp(name)) return nullptr;
    // The P4 pair falls through on purpose: find() succeeds (the real
    // property exists) and the value is aligned at read time.
    return BYTEHOOK_CALL_PREV(MyPropFind, name);
}

struct PropGrab {
    const char* name;
    uint32_t serial;
};

static void PropGrabCb(void* cookie, const char* name, const char* value, uint32_t serial) {
    PropGrab* g = static_cast<PropGrab*>(cookie);
    (void)value;
    g->name = name;
    g->serial = serial;
}

static void MyPropReadCallback(const prop_info* pi,
                               void (*cb)(void*, const char*, const char*, uint32_t),
                               void* cookie) {
    BYTEHOOK_STACK_SCOPE();
    if (pi != nullptr && cb != nullptr) {
        PropGrab g;
        g.name = nullptr;
        g.serial = 0;
        BYTEHOOK_CALL_PREV(MyPropReadCallback, pi, &PropGrabCb, &g);
        if (g.name != nullptr) {
            if (IsAntiEmuProp(g.name)) {
                cb(cookie, g.name, "", g.serial);
                return;
            }
            if (const char* v = AntiEmuPropRewrite(g.name)) {
                cb(cookie, g.name, v, g.serial);
                return;
            }
        }
    }
    BYTEHOOK_CALL_PREV(MyPropReadCallback, pi, cb, cookie);
}

struct PropForeachFwd {
    void (*cb)(const prop_info*, void*);
    void* cookie;
};

static void PropForeachShim(const prop_info* pi, void* cookie) {
    PropForeachFwd* fwd = static_cast<PropForeachFwd*>(cookie);
    if (pi == nullptr) return;
    PropGrab g;
    g.name = nullptr;
    g.serial = 0;
    __system_property_read_callback(pi, &PropGrabCb, &g);
    if (g.name == nullptr) return;
    if (IsAntiEmuProp(g.name)) return;  // vanish from getprop-style sweeps
    // The P4 pair stays in the sweep - it is a normal property on a real
    // device; its VALUE is aligned at read-callback time.
    fwd->cb(pi, fwd->cookie);
}

static int MyPropForeach(void (*cb)(const prop_info*, void*), void* cookie) {
    BYTEHOOK_STACK_SCOPE();
    if (g_anti_emu && cb != nullptr) {
        PropForeachFwd fwd;
        fwd.cb = cb;
        fwd.cookie = cookie;
        return BYTEHOOK_CALL_PREV(MyPropForeach, &PropForeachShim, &fwd);
    }
    return BYTEHOOK_CALL_PREV(MyPropForeach, cb, cookie);
}

// ---------------------------------------------------------------------------

}  // namespace pas

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetAntiEmu(JNIEnv* env, jobject thiz, jboolean on) {
    (void)env;
    (void)thiz;
    pas::SetAntiEmu(on == JNI_TRUE);
}
