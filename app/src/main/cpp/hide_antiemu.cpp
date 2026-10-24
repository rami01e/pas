// hide_antiemu.cpp - ANTI-EMU native layer (v3.1.0).
//
// v3.1.0 keeps the v3.0.0 scope reduction (path masking + prop blanking +
// adb-runtime alignment, install-on-arm) and adds a second, strictly
// target-listed hiding engine for the artifact classes Duck Detector's
// runtime scan still sees in a scoped process. Everything new is gated on
// g_anti_emu and only ever REMOVES or SANITIZES bytes; no identity is
// rewritten, and with anti-emu off the process behaves exactly as v3.0.0.
//
//   1. Path masking (unchanged rule set from 2.x / v3.0.0).
//   2. Ignorable-codepoint normalization of every checked path (unchanged).
//   3. Emulator-artifact property blanking + adb-runtime alignment pair
//      (unchanged).
//   4. NEW kernel-identity sanitization: uname() and the /proc/version +
//      /proc/sys/kernel/{osrelease,version} views are stripped of
//      maintainer-style "@handle" mentions (Duck's MENTION_REGEX
//      "@[A-Za-z0-9_]+"). The release/version numbers themselves stay raw -
//      nothing is contradicted, the builder handles are simply dropped.
//   5. NEW residue-view filtering (memfd serving for a fixed path set):
//        /proc/self/{maps,smaps}          -> module/bytehook/houdini/qemu
//                                            mapping lines dropped
//        /proc/{,self/}mounts|mountinfo   -> /adb/modules + zygisk + module
//                                            cache mounts dropped
//        /proc/{,self/}net/unix           -> lspd / 1spd / xposed socket
//                                            lines dropped
//        /proc/self/environ               -> tainted entries blanked
//        /proc/version + kernel sysctls   -> "@mention" stripped
//      Whole lines of OTHER mappings are never touched, and app-owned lines
//      (/data/app/**, split APKs) always survive - this is drop-only
//      filtering of module/emulator residue, not the maps REWRITING that was
//      removed in v3.0.0.
//   6. NEW runtime-channel scrubbing: readlink/readlinkat answers ENOENT for
//      fd links whose target carries framework residue (the /proc/self/fd
//      scan), getenv returns an empty value for tainted variables, and the
//      process environ is blanked in place once at arm time (System.getenv
//      caches os.environ, so the scrub must happen before first use).
//   7. FIXED (this is the "anti-emu breaks the CPU spoof" bug, Duck item 9):
//      MyPropReadCallback violated ByteHook's once-only BYTEHOOK_CALL_PREV
//      contract - every non-blanked property read called CALL_PREV twice
//      (once to grab the prop name, once to forward). ByteHook's hook-frame
//      stack is per-thread and shared by every hooked symbol, so the second
//      call mis-resolved frames for the whole chain beneath it - including
//      hide_fs's open/read hooks that serve the spoofed /proc/cpuinfo and
//      cpufreq views. DevCheck-style consumers therefore lost their spoofed
//      CPU story exactly when anti-emu armed. The callback now aligns values
//      through a single CALL_PREV with a shim, like every other hook here.
//
// Removed in v3.0.0 (unchanged): kernel release/version spoofing, all
// identity /proc-/sys serving, seccomp/NNP, x86->ARM prop rewrites.
//
// Arming stays race-free: SetAntiEmu(true) installs the hooks itself
// (InstallAntiEmuHooks is idempotent). InitWorker's stage5b call remains as
// the early-install path.
//
// Caller filter is the standard module one (CallerAllowHooks), which
// excludes Houdini / native-bridge libs AND libpas.so itself - so the
// raw-syscall reads inside the serving engine below can never re-enter the
// hooks (same pattern hide_fs.cpp relies on).

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
#include <sys/utsname.h>
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
static int MyUname(struct utsname* buf);
static char* MyGetenv(const char* name);
static ssize_t MyReadlink(const char* path, char* buf, size_t bufsiz);
static ssize_t MyReadlinkAt(int dirfd, const char* path, char* buf, size_t bufsiz);

// v3.1.0 environ scrub (defined below, called from SetAntiEmu).
void ScrubEnvironmentResidue();

// ---------------------------------------------------------------------------
// hook installation (idempotent + race-safe)
//
// Each symbol keeps its own stub: if an attempt lands before bytehook_init
// the failed symbols stay unhooked and any later call retries exactly those.
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
    {"uname",      (void*)MyUname,      nullptr},
    {"getenv",     (void*)MyGetenv,     nullptr},
    {"readlink",   (void*)MyReadlink,   nullptr},
    {"readlinkat", (void*)MyReadlinkAt, nullptr},
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
        // v3.1.0: blank module residue out of the live environ once. libcore
        // caches os.environ for System.getenv() at first use, so the scrub
        // has to happen while arming - not lazily per read. Idempotent by
        // construction (already-blank entries fail the token check).
        ScrubEnvironmentResidue();
    }
    Log("native: anti-emu %s", on ? "on" : "off");
}

// ---------------------------------------------------------------------------
// ignorable-codepoint normalization (v3.0.0, P5 - unchanged)
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

    // v3.1.0: qemu-context SELinux property files. Duck's "direct device
    // nodes" probe opens /dev/__properties__/u:object_r:qemu_sf_lcd_density_
    // prop:s0 directly; the mapping line is already dropped from maps, so
    // the node itself goes ENOENT for direct openers too.
    if (strncmp(path, "/dev/__properties__/u:object_r:qemu", 35) == 0) return true;

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
// v3.1.0 residue token engine
//
// Duck's LSPosed probe scans /proc/self/net/unix, /proc/self/fd and the
// environment for framework residue; its runtime-artifacts scan reads
// /proc/self/maps + mountinfo; its "Mapped translation library" / bytehook
// cards read maps. The token lists below are drop-only filters: a line (or
// env entry, or fd link) carrying one of them vanishes, everything else is
// byte-identical to the real view. Case-insensitive on purpose - Duck
// lowercases before matching, and Linux paths reaching these views are
// lowercase anyway.
// ---------------------------------------------------------------------------

static char AeLowerChar(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

// Case-insensitive substring over a bounded region (no NUL required).
static bool AeRegionHasToken(const char* start, size_t len, const char* tok) {
    const size_t tl = strlen(tok);
    if (tl == 0 || len < tl) return false;
    const size_t last = len - tl;
    for (size_t i = 0; i <= last; i++) {
        size_t k = 0;
        while (k < tl && AeLowerChar(start[i + k]) == tok[k]) k++;
        if (k == tl) return true;
    }
    return false;
}

// LSPosed / Xposed / module-manager residue (mirrors Duck's frameworkTokens
// plus the daemon paths that carry them).
static bool AeHasFrameworkResidue(const char* s, size_t len) {
    static const char* const kTokens[] = {
        "lsposed", "xposed", "edxposed", "lspd", "1spd", "libxposed",
        "zygisk", "/data/adb", ".cli_sock",
    };
    for (const char* t : kTokens) {
        if (AeRegionHasToken(s, len, t)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// v3.1.0 filtered proc-file serving engine
//
// A fixed, hand-picked path set is re-served through a memfd after dropping
// the residue lines listed above. Nothing else is touched: with anti-emu off
// AeSpecialFor always answers None and every open reaches the real file (and
// then hide_fs's own filters) exactly as before.
// ---------------------------------------------------------------------------

enum AeSpecial {
    kAeNone = 0,
    kAeVersion,      // /proc/version                     (@mention strip)
    kAeSysctlVer,    // /proc/sys/kernel/version          (@mention strip)
    kAeSysctlRel,    // /proc/sys/kernel/osrelease        (@mention strip)
    kAeMaps,         // /proc/self/{maps,smaps}           (line drop)
    kAeMounts,       // /proc/{,self/}mounts              (line drop)
    kAeMountinfo,    // /proc/{,self/}mountinfo           (line drop)
    kAeNetUnix,      // /proc/{,self/}net/unix            (line drop)
    kAeEnviron,      // /proc/self/environ                (entry drop)
};

static AeSpecial AeSpecialFor(const char* path) {
    if (!g_anti_emu || path == nullptr || path[0] != '/') return kAeNone;
    if (strcmp(path, "/proc/version") == 0) return kAeVersion;
    if (strcmp(path, "/proc/sys/kernel/version") == 0) return kAeSysctlVer;
    if (strcmp(path, "/proc/sys/kernel/osrelease") == 0) return kAeSysctlRel;
    if (strcmp(path, "/proc/self/maps") == 0 || strcmp(path, "/proc/self/smaps") == 0) {
        return kAeMaps;
    }
    if (strcmp(path, "/proc/mounts") == 0 || strcmp(path, "/proc/self/mounts") == 0) {
        return kAeMounts;
    }
    if (strcmp(path, "/proc/mountinfo") == 0 || strcmp(path, "/proc/self/mountinfo") == 0) {
        return kAeMountinfo;
    }
    if (strcmp(path, "/proc/net/unix") == 0 || strcmp(path, "/proc/self/net/unix") == 0) {
        return kAeNetUnix;
    }
    if (strcmp(path, "/proc/self/environ") == 0) return kAeEnviron;
    return kAeNone;
}

// maps / smaps line filter: module + translation-layer + emulator artifacts.
// The app's own /data/app/** lines carry none of these tokens and always
// survive, so split-APK integrity checks keep seeing their real paths.
static bool AeMapsLineBlocked(const char* s, size_t len) {
    static const char* const kTokens[] = {
        "bytehook", "zygisk", "/data/adb", "lspd", "1spd", "lsposed", "xposed",
        "houdini", "libnb", "ndk_translation", "qemu", "goldfish", "ranchu",
        "nemu", "/mumu", "vbox", "geny",
    };
    for (const char* t : kTokens) {
        if (AeRegionHasToken(s, len, t)) return true;
    }
    return false;
}

// mounts / mountinfo line filter: module bind mounts (Vector's
// /adb/modules/zygisk_vector resource-cache view, lspd, magisk overlays).
static bool AeMountsLineBlocked(const char* s, size_t len) {
    static const char* const kTokens[] = {
        "/adb/modules", "zygisk", "/data/adb", "lspd", "1spd", "lsposed",
        "xposed", "magisk", "resource-cache",
    };
    for (const char* t : kTokens) {
        if (AeRegionHasToken(s, len, t)) return true;
    }
    return false;
}

// /proc/net/unix line filter: the 1spd daemon socket and friends.
static bool AeNetUnixLineBlocked(const char* s, size_t len) {
    return AeHasFrameworkResidue(s, len);
}

// v3.0.0 pattern: raw syscalls inside libpas.so are exempt from the module's
// own PLT hooks by the CallerAllow skip list, so reading the real file here
// cannot re-enter MyOpen/MySyscall (same mechanism hide_fs relies on).
static bool AeReadWhole(const char* path, std::string* out) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return false;
    char buf[16384];
    for (;;) {
        ssize_t n = syscall(SYS_read, fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        out->append(buf, (size_t)n);
        if (out->size() > (8u << 20)) break;  // maps can be large; 8 MB cap
    }
    syscall(SYS_close, fd);
    return true;
}

// "@[A-Za-z0-9_]+" removal - exactly Duck kernelcheck's MENTION_REGEX. The
// '@' survives when not followed by a token character (the regex would not
// match it either). Used on kernel-identity strings only.
static void AeStripAtMentions(std::string* s) {
    if (s == nullptr || s->empty()) return;
    std::string out;
    out.reserve(s->size());
    size_t i = 0;
    const size_t n = s->size();
    while (i < n) {
        if ((*s)[i] == '@' && i + 1 < n) {
            size_t j = i + 1;
            while (j < n) {
                char c = (*s)[j];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '_') {
                    j++;
                } else {
                    break;
                }
            }
            if (j > i + 1) {
                i = j;  // drop "@handle"
                continue;
            }
        }
        out.push_back((*s)[i]);
        i++;
    }
    *s = out;
}

static int AeMemfdFrom(const std::string& content, int flags) {
#ifdef SYS_memfd_create
    int mfd = (int)syscall(SYS_memfd_create, "pas-ae",
                           (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0);
#else
    int mfd = -1;
#endif
    if (mfd < 0) return -1;
    size_t off = 0;
    while (off < content.size()) {
        ssize_t w = syscall(SYS_write, mfd, content.data() + off, content.size() - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            syscall(SYS_close, mfd);
            return -1;
        }
        off += (size_t)w;
    }
    syscall(SYS_lseek, mfd, 0, SEEK_SET);
    return mfd;
}

// Newline-delimited drop filter shared by maps/mounts/net-unix.
static void AeFilterLinesBy(const std::string& raw,
                            bool (*blocked)(const char*, size_t),
                            std::string* out) {
    size_t i = 0;
    const size_t n = raw.size();
    while (i < n) {
        size_t j = raw.find('\n', i);
        j = (j == std::string::npos) ? n : j + 1;
        if (!blocked(raw.data() + i, j - i)) {
            out->append(raw, i, j - i);
        }
        i = j;
    }
}

// NUL-delimited drop filter for /proc/self/environ.
static void AeFilterEnvironContent(const std::string& raw, std::string* out) {
    size_t i = 0;
    const size_t n = raw.size();
    while (i < n) {
        size_t j = i;
        while (j < n && raw[j] != '\0') j++;
        if (j > i && !AeHasFrameworkResidue(raw.data() + i, j - i)) {
            out->append(raw, i, j - i);
            out->push_back('\0');
        }
        i = j + 1;
    }
}

// Returns a memfd holding the filtered view, or -1 (caller falls through to
// the real file; failing open here must never break a reader).
static int AeServeFilteredFd(const char* path, AeSpecial kind, int flags) {
    std::string raw;
    if (!AeReadWhole(path, &raw)) return -1;
    std::string out;
    out.reserve(raw.size());
    switch (kind) {
        case kAeVersion:
        case kAeSysctlVer:
        case kAeSysctlRel:
            out = raw;
            AeStripAtMentions(&out);
            break;
        case kAeMaps:
            AeFilterLinesBy(raw, AeMapsLineBlocked, &out);
            break;
        case kAeMounts:
        case kAeMountinfo:
            AeFilterLinesBy(raw, AeMountsLineBlocked, &out);
            break;
        case kAeNetUnix:
            AeFilterLinesBy(raw, AeNetUnixLineBlocked, &out);
            break;
        case kAeEnviron:
            AeFilterEnvironContent(raw, &out);
            break;
        default:
            return -1;
    }
    if (out.empty() && kind != kAeNetUnix) return -1;  // suspicious - stay raw
    return AeMemfdFrom(out, flags);
}

// Open-family entry: answers a filtered fd for the special set, else -1.
static int AeSpecialOpenFd(const char* path, int flags) {
    AeSpecial kind = AeSpecialFor(path);
    if (kind == kAeNone) return -1;
    if ((flags & O_ACCMODE) != O_RDONLY) return -1;
    return AeServeFilteredFd(path, kind, flags);
}

// ---------------------------------------------------------------------------
// v3.1.0 live-environment scrub
//
// Called once from SetAntiEmu(true). Entries whose KEY carries framework
// residue are blanked entirely (getenv treats an entry without '=' as
// absent); entries whose VALUE carries residue keep the KEY= shape with an
// empty value. In-place because libcore copies os.environ by pointer at
// first System.getenv() use.
// ---------------------------------------------------------------------------
void ScrubEnvironmentResidue() {
    for (char** e = environ; e != nullptr && *e != nullptr; e++) {
        char* entry = *e;
        if (entry == nullptr) continue;
        char* eq = strchr(entry, '=');
        size_t keyLen = eq != nullptr ? (size_t)(eq - entry) : strlen(entry);
        if (keyLen > 0 && AeHasFrameworkResidue(entry, keyLen)) {
            entry[0] = '\0';
            continue;
        }
        if (eq != nullptr && AeHasFrameworkResidue(eq + 1, strlen(eq + 1))) {
            eq[1] = '\0';
        }
    }
}

// ---------------------------------------------------------------------------
// libc open family - every entry point the SDKs use for File.exists() /
// FileInputStream / fopen / ifstream. v3.1.0: after the ENOENT mask, the
// special residue-view set is answered with a filtered memfd (see above).
// ---------------------------------------------------------------------------

static int MyOpen(const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    if (path != nullptr && path[0] == '/') {
        int sfd = AeSpecialOpenFd(path, flags);
        if (sfd >= 0) return sfd;
    }
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
    if (path != nullptr && path[0] == '/') {
        int sfd = AeSpecialOpenFd(path, flags);
        if (sfd >= 0) return sfd;
    }
    return BYTEHOOK_CALL_PREV(MyOpen2, path, flags);
}

static int MyOpenAt(int dirfd, const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    if (path && path[0] == '/' && IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    if (path != nullptr && path[0] == '/') {
        int sfd = AeSpecialOpenFd(path, flags);
        if (sfd >= 0) return sfd;
    }
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
    if (path != nullptr && path[0] == '/') {
        int sfd = AeSpecialOpenFd(path, flags);
        if (sfd >= 0) return sfd;
    }
    return BYTEHOOK_CALL_PREV(MyOpenAt2, dirfd, path, flags);
}

static FILE* MyFopen(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return nullptr; }
    if (path != nullptr && path[0] == '/' && mode != nullptr && mode[0] == 'r' &&
        strchr(mode, '+') == nullptr) {
        int sfd = AeSpecialOpenFd(path, O_RDONLY);
        if (sfd >= 0) {
            FILE* f = fdopen(sfd, "r");
            if (f != nullptr) return f;
            syscall(SYS_close, sfd);
        }
    }
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
// this is the OUTER layer: anti-emu paths + residue views handled first,
// then falls through via BYTEHOOK_CALL_PREV to hide_fs.MySyscall (CPU freq /
// interface hiding) on every other path.
//
// Bytehook's CallerAllowHooks filter excludes Houdini / native-bridge libs
// AND libpas.so itself, so the serving engine's raw syscalls can never
// re-enter this hook. App code (x86_64) and detector libraries are the only
// callers that hit it - exactly what we want.
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
            if (path != nullptr && path[0] == '/') {
                if (IsAntiEmuPath(path)) {
                    errno = ENOENT;
                    return -1;
                }
                int sfd = AeSpecialOpenFd(path, (int)a2);
                if (sfd >= 0) return sfd;
            }
        }
#endif
#if defined(__NR_open)
        if (number == __NR_open) {
            const char* path = (const char*)a0;
            if (path != nullptr && path[0] == '/') {
                if (IsAntiEmuPath(path)) {
                    errno = ENOENT;
                    return -1;
                }
                int sfd = AeSpecialOpenFd(path, (int)a1);
                if (sfd >= 0) return sfd;
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
// v3.1.0 runtime-channel hooks
//
// uname: strip maintainer-style "@handle" mentions from every identity field
// (Duck kernelcheck MENTION_REGEX). The release/version numbers themselves
// stay raw - they agree with every other source, only builder handles are
// dropped. hide_props' HideUname sits underneath on the same chain and keeps
// owning the machine-field ABI story.
// ---------------------------------------------------------------------------
static int MyUname(struct utsname* buf) {
    BYTEHOOK_STACK_SCOPE();
    int rc = BYTEHOOK_CALL_PREV(MyUname, buf);
    if (rc == 0 && buf != nullptr && g_anti_emu) {
        char tmp[sizeof(((struct utsname*)nullptr)->version)];
        char* fields[] = {
            buf->sysname, buf->nodename, buf->release,
            buf->version, buf->machine, buf->domainname,
        };
        (void)tmp;
        for (char* f : fields) {
            if (f == nullptr) continue;
            if (!strchr(f, '@')) continue;
            std::string s(f);
            AeStripAtMentions(&s);
            if (s.size() < sizeof(tmp)) {
                memcpy(f, s.c_str(), s.size() + 1);
            }
        }
    }
    return rc;
}

// getenv: belt-and-braces over the arm-time environ scrub (covers values
// set later with setenv/putenv). getenv results must not be modified by the
// caller, so an empty string literal is returned for tainted values.
static char* MyGetenv(const char* name) {
    BYTEHOOK_STACK_SCOPE();
    char* v = BYTEHOOK_CALL_PREV(MyGetenv, name);
    if (g_anti_emu && v != nullptr && v[0] != '\0' &&
        AeHasFrameworkResidue(v, strlen(v))) {
        return (char*)"";
    }
    return v;
}

// readlink / readlinkat: the /proc/self/fd scan channel. A link whose target
// carries framework residue answers ENOENT - from the scanner's point of
// view the descriptor points at nothing readable, which is what an
// un-hooked clean process shows for closed/transient fds.
static ssize_t MyReadlink(const char* path, char* buf, size_t bufsiz) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t n = BYTEHOOK_CALL_PREV(MyReadlink, path, buf, bufsiz);
    if (g_anti_emu && n > 0 && buf != nullptr && AeHasFrameworkResidue(buf, (size_t)n)) {
        errno = ENOENT;
        return -1;
    }
    return n;
}

static ssize_t MyReadlinkAt(int dirfd, const char* path, char* buf, size_t bufsiz) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t n = BYTEHOOK_CALL_PREV(MyReadlinkAt, dirfd, path, buf, bufsiz);
    if (g_anti_emu && n > 0 && buf != nullptr && AeHasFrameworkResidue(buf, (size_t)n)) {
        errno = ENOENT;
        return -1;
    }
    return n;
}

// ---------------------------------------------------------------------------
// property layer
//
// Kept from 2.x: the emulator-artifact key blanking (IsAntiEmuProp). Blanking
// ro.kernel.qemu & friends is not an identity rewrite - it removes markers
// that have no business existing on the presented device.
//
// Kept from v3.0.0 (P4): the ADB-runtime alignment pair. MuMu runs adbd
// outside init (socket + TCP listener alive) while init.svc.adbd reads
// "stopped" - that three-way contradiction is exactly what Duck's AdbRuntime
// detector grades HIGH. The readable state is aligned to the truth instead:
// adbd "running" (it is) and persist.sys.usb.config "mtp" (the retail-
// expected value; adb-over-TCP then reads as ordinary wireless debugging).
// sys.usb.state stays raw - it feeds Duck's isAdbActive() only, never a
// contradiction check. (The exec'd `getprop` dump channel is aligned on the
// Java side - HookExec's exec shield.)
//
// v3.1.0 FIX (Duck item 9 - "anti-emu on breaks the CPU spoof"): the old
// MyPropReadCallback called BYTEHOOK_CALL_PREV twice per invocation (once
// with a name-grabbing shim, then again to forward the caller's callback)
// for every non-blanked property. ByteHook's hook-frame stack is per-thread
// and shared by ALL hooked symbols, so the second, undocumented call
// mis-resolved frames chain-wide - hide_fs's open/read serving (the spoofed
// /proc/cpuinfo + cpufreq views DevCheck renders) lost its layer on threads
// that had just read a property. The callback now aligns values inside ONE
// CALL_PREV via PropAlignCb, matching the once-only contract every other
// hook in the module follows.
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

// v3.1.0: single-CALL_PREV read-callback shim. The real read callback runs
// exactly once; the shim decides between the blanked / aligned / raw value
// before handing the result to the caller's callback.
struct PropAlign {
    void (*orig)(void* cookie, const char* name, const char* value, uint32_t serial);
    void* cookie;
};

static void PropAlignCb(void* cookie, const char* name, const char* value, uint32_t serial) {
    PropAlign* a = static_cast<PropAlign*>(cookie);
    if (a == nullptr) return;
    if (name != nullptr) {
        if (IsAntiEmuProp(name)) {
            a->orig(a->cookie, name, "", serial);
            return;
        }
        if (const char* v = AntiEmuPropRewrite(name)) {
            a->orig(a->cookie, name, v, serial);
            return;
        }
    }
    a->orig(a->cookie, name, value, serial);
}

static void MyPropReadCallback(const prop_info* pi,
                               void (*cb)(void*, const char*, const char*, uint32_t),
                               void* cookie) {
    BYTEHOOK_STACK_SCOPE();
    if (pi != nullptr && cb != nullptr && g_anti_emu) {
        PropAlign a;
        a.orig = cb;
        a.cookie = cookie;
        BYTEHOOK_CALL_PREV(MyPropReadCallback, pi, &PropAlignCb, &a);
        return;
    }
    BYTEHOOK_CALL_PREV(MyPropReadCallback, pi, cb, cookie);
}

// Name-grab shim: the foreach sweep uses it to inspect the property NAME
// without touching any hook frame.
struct PropGrab {
    const char* name;
    uint32_t serial;
};

static void PropGrabCb(void* cookie, const char* name, const char* value, uint32_t serial) {
    PropGrab* g = static_cast<PropGrab*>(cookie);
    (void)value;
    if (g != nullptr) {
        g->name = name;
        g->serial = serial;
    }
}

struct PropForeachFwd {
    void (*cb)(const prop_info*, void*);
    void* cookie;
};

static void PropForeachShim(const prop_info* pi, void* cookie) {
    PropForeachFwd* fwd = static_cast<PropForeachFwd*>(cookie);
    if (pi == nullptr) return;
    // Name grab via the plain libc symbol: libpas.so's own PLT entries are
    // exempt from the module's hooks (CallerAllow skip list), so this runs
    // the REAL read callback exactly once with no bytehook frame involved -
    // a hook function must never be invoked outside its trampoline, which
    // is precisely the once-only discipline this revision restores.
    PropGrab grab;
    grab.name = nullptr;
    grab.serial = 0;
    __system_property_read_callback(pi, &PropGrabCb, &grab);
    if (grab.name == nullptr) return;
    if (IsAntiEmuProp(grab.name)) return;  // vanish from getprop-style sweeps
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

}  // namespace pas

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetAntiEmu(JNIEnv* env, jobject thiz, jboolean on) {
    (void)env;
    (void)thiz;
    pas::SetAntiEmu(on == JNI_TRUE);
}
