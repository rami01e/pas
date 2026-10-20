// hide_antiemu.cpp - ANTI-EMU native layer (v2.10.2).
//
// v2.9.7 changes over v2.9.6:
//
//  - Real permissive seccomp. v2.9.6's SanitizeStatus() only rewrote the
//    /proc/self/status TEXT for libc readers. AppDome-grade RASP reads
//    through direct syscall() and sees the raw kernel truth:
//    Seccomp: 0, Seccomp_filters: 0, NoNewPrivs: 0 - which is what MuMu
//    leaves in place ("Zygote: seccomp disabled by setenforce 0" in the
//    10-18 capture). We install a real (fully permissive) SECCOMP_MODE_FILTER
//    so the kernel itself reports Seccomp: 2 to every reader - direct
//    syscall or not.
//
//    Scope: prctl(PR_SET_NO_NEW_PRIVS) and prctl(PR_SET_SECCOMP) are
//    per-thread attributes inherited only by that thread's fork/clone
//    children. This library runs inside the scoped app's own process
//    (XposedInit.initNativeAddon -> System.loadLibrary -> SpoofCore.init
//    on the "pas-native-init" thread), so the install touches nothing
//    outside the app process. No system-wide effect.
//
//    The filter is SECCOMP_RET_ALLOW for everything - functionally a no-op.
//    Only its presence is what we need.
//
//  - Lazy main-thread seccomp install. nativeSetAntiEmu() runs on
//    "pas-native-init" (a worker; the 10-18 log shows "native: anti-emu
//    on" on tid 38976, not 38829). /proc/<pid>/status reflects the MAIN
//    thread's seccomp state, not the reading thread's. SetAntiEmu still
//    installs on the caller (harmless), and the first hook call that runs
//    on the main thread (open/openat/fopen/stat/lstat/fstatat/access/
//    syscall - all fire within ms of Activity startup) triggers
//    MaybeInstallSeccompOnMainThread(), which finishes the real install
//    there too. After that, /proc/self/status reports Seccomp: 2 natively
//    for the whole process.
//
//  - /proc/self/maps and /proc/self/smaps x86_64 paths rewritten to arm64.
//    APK-internal paths ("base.apk!/lib/x86_64/*.so") become
//    "base.apk!/lib/arm64-v8a/*.so" - exactly what a real SM-G991B shows.
//    Extracted-lib paths (".../lib/x86_64/*.so") become
//    ".../lib/arm64/*.so" to match extractNativeLibs=true installs. The
//    discriminator is the ".apk!/" substring on the line itself.
//    base.apk! arm64-v8a is a valid zip entry for universal APKs (the
//    10-18 loader config shows library_path=...base.apk!/lib/x86_64:
//    ...base.apk!/lib/arm64-v8a), so the rewritten path is real, not fake.
//
//  - gre0 sysfs paths hidden (/sys/{class,devices/virtual}/net/gre0*).
//    Java-side NetworkInterface already hides gre0, but UnityMain reads
//    /sys/devices/virtual/net/gre0/ifindex directly (03-module.log at
//    10:14:38.973) and bypassed that filter. Hiding sysfs keeps the story
//    consistent.
//
//  - NEW: syscall() hook. v2.9.6 relied on libc open/openat/fopen hooks,
//    which a hardened RASP bypasses with direct syscall(). This closes the
//    last bypass: houdini, qemu_pipe, root paths, proc-maps/status/cpuinfo
//    are all hidden on BOTH libc and raw-syscall paths. Installed after
//    hide_fs.cpp's syscall hook (pas.cpp stage 4a vs 5b), so this runs as
//    the OUTER layer - it handles anti-emu paths first and falls through
//    via BYTEHOOK_CALL_PREV to hide_fs.MySyscall (CPU freq / interface
//    hiding) on every other path.
//
//  - Fixed: v2.9.6-era gre0 prefix match used strncmp(path, prefix, N)
//    where N was larger than the literal, which stops at the pattern's
//    NUL and never matched children. Now uses strncmp(...) with the literal
//    length + explicit terminator/"/" check, so /sys/class/net/gre0 and
//    /sys/class/net/gre0/ifindex both hit.
//
// Runtime-gated on g_anti_emu; the toggle is delivered from Kotlin via
// nativeSetAntiEmu(). Caller filter is the standard module one
// (CallerAllowHooks), which excludes Houdini / native-bridge libs so
// their own property reads stay raw and MuMu's injected helpers keep
// working.

#include "pas.h"

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/seccomp.h>

#include "bytehook.h"

namespace pas {

// ---------------------------------------------------------------------------
// v2.9.7 feature flags (compile-time const; dead branches are optimized out)
// ---------------------------------------------------------------------------
static const bool PAS_F_REAL_SECCOMP      = true;
static const bool PAS_F_REWRITE_MAPS_X86  = true;
static const bool PAS_F_HIDE_GRE0_SYSFS   = true;
static const bool PAS_F_HOOK_SYSCALL      = true;

// ---------------------------------------------------------------------------
// state
// ---------------------------------------------------------------------------
static volatile bool g_anti_emu = false;

// vNEXT: kernel identity shown to native readers. MuMu's real values
// (release "6.1.90-perf+", version "#2 SMP PREEMPT_DYNAMIC Wed Aug 26
// 07:46:48 UTC 2026") are among the strongest emulator tells a signal SDK
// can collect: Prelude/DroidGuard read them through uname(2) and
// /proc/version, where the Java os.version spoof is invisible. Kept in sync
// with the Java os.version value in spoofcore.kt by construction.
static volatile bool g_kernel_spoof = true;
static char g_kernel_release[65] = "5.4.163-perf+";
static char g_kernel_version[65] = "#1 SMP PREEMPT Tue Oct 15 09:12:33 UTC 2024";

void SetAntiEmuKernel(bool on, const char* release, const char* version) {
    g_kernel_spoof = on;
    if (release != nullptr && release[0] != '\0') {
        snprintf(g_kernel_release, sizeof(g_kernel_release), "%s", release);
    }
    if (version != nullptr && version[0] != '\0') {
        snprintf(g_kernel_version, sizeof(g_kernel_version), "%s", version);
    }
    Log("native: anti-emu kernel spoof=%d release=%s", (int)on, g_kernel_release);
}

// Seccomp per-thread install state.
static __thread bool t_seccomp_installed = false;
static __thread bool t_seccomp_failed    = false;
static __thread int  t_is_main           = -1;   // -1 unknown, 0 no, 1 yes
static bool          g_seccomp_installed_main = false;

static inline pid_t GetTid() {
#if defined(__NR_gettid)
    return (pid_t)syscall(__NR_gettid);
#else
    return gettid();
#endif
}

// ---------------------------------------------------------------------------
// v2.9.7: real permissive seccomp (see file header for scope statement)
//
// The filter is SECCOMP_RET_ALLOW for everything - functionally a no-op.
// Its only purpose is to make the kernel report Seccomp: 2 and
// Seccomp_filters: 1 in /proc/<pid>/status, matching every stock Android
// app (zygote installs a filter before fork). MuMu runs the app process
// with seccomp disabled entirely - that is the emulator tell.
//
// Both prctl() calls are per-thread; children inherit them via fork/clone.
// No system-wide state is touched.
// ---------------------------------------------------------------------------
static void EnsurePermissiveSeccompThisThread() {
    if (!PAS_F_REAL_SECCOMP) return;
    if (t_seccomp_installed || t_seccomp_failed) return;

    // PR_SET_NO_NEW_PRIVS is required to install seccomp-bpf without
    // CAP_SYS_ADMIN. One-way; matches what every stock Android app already
    // has (zygote sets it before fork).
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        Log("native: anti-emu seccomp PR_SET_NO_NEW_PRIVS errno=%d", errno);
        t_seccomp_failed = true;
        return;
    }

    struct sock_filter filter[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog;
    prog.len    = (unsigned short)(sizeof(filter) / sizeof(filter[0]));
    prog.filter = filter;

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        Log("native: anti-emu seccomp PR_SET_SECCOMP errno=%d", errno);
        t_seccomp_failed = true;
        return;
    }

    t_seccomp_installed = true;
    Log("native: anti-emu permissive seccomp installed (tid=%d)", (int)GetTid());
}

static void MaybeInstallSeccompOnMainThread() {
    if (!PAS_F_REAL_SECCOMP) return;
    if (!g_anti_emu) return;
    if (g_seccomp_installed_main) return;
    if (t_is_main < 0) {
        t_is_main = (GetTid() == getpid()) ? 1 : 0;
    }
    if (t_is_main != 1) return;
    EnsurePermissiveSeccompThisThread();
    g_seccomp_installed_main = true;
}

// ---------------------------------------------------------------------------
// public entry point (unchanged signature)
// ---------------------------------------------------------------------------
void SetAntiEmu(bool on) {
    g_anti_emu = on;
    if (on) {
        // Install on the calling thread (usually "pas-native-init"; harmless).
        EnsurePermissiveSeccompThisThread();
        // If we happen to be the main thread, mark it done right away.
        MaybeInstallSeccompOnMainThread();
    }
    Log("native: anti-emu %s", on ? "on" : "off");
}

bool AntiEmuEnabled() {
    return g_anti_emu;
}

// ---------------------------------------------------------------------------
// path filter
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

static bool IsAntiEmuPath(const char* path) {
    if (!g_anti_emu || path == nullptr || path[0] != '/') return false;

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

    // v2.9.7: gre0 sysfs (both exact dir and every child). The Java-side
    // NetworkInterface filter hides gre0, but UnityMain reads
    // /sys/devices/virtual/net/gre0/ifindex directly and bypassed it.
    // v2.9.7 fix: the strncmp-with-literal-length + terminator check is
    // what actually matches children; a bare strncmp(path, prefix, N)
    // with N > strlen(prefix) never does.
    if (PAS_F_HIDE_GRE0_SYSFS) {
        static const char kGre0Dev[] = "/sys/devices/virtual/net/gre0";
        static const char kGre0Cls[] = "/sys/class/net/gre0";
        if (StartsWithPrefixSeg(path, kGre0Dev, sizeof(kGre0Dev) - 1)) return true;
        if (StartsWithPrefixSeg(path, kGre0Cls, sizeof(kGre0Cls) - 1)) return true;
    }

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

// ---------------------------------------------------------------------------
// /proc content spoof
// ---------------------------------------------------------------------------

enum ProcSpoofKind {
    kProcNone = 0,
    kProcCpuInfo = 1,
    kProcMaps = 2,
    kProcMounts = 3,
    kProcStatus = 4,          // /proc self status, TracerPid/Seccomp/NoNewPrivs
    kProcSelinuxEnforce = 5,  // /sys/fs/selinux/enforce -> "1"
    kProcVersion = 6,         // /proc/version, arch -> aarch64
};

static bool ProcSelfPath(const char* path, const char* leaf) {
    if (strncmp(path, "/proc/self/", 11) == 0) return strcmp(path + 11, leaf) == 0;
    if (strncmp(path, "/proc/", 6) == 0) {
        const char* p = path + 6;
        if (*p < '0' || *p > '9') return false;
        long v = 0;
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); ++p; }
        return v == (long)getpid() && *p == '/' && strcmp(p + 1, leaf) == 0;
    }
    return false;
}

static bool ProcTaskSelfLeaf(const char* path, const char* leaf) {
    const char* p = nullptr;
    if (strncmp(path, "/proc/self/task/", 16) == 0) {
        p = path + 16;
    } else if (strncmp(path, "/proc/", 6) == 0) {
        const char* q = path + 6;
        long v = 0;
        bool any = false;
        while (*q >= '0' && *q <= '9') { v = v * 10 + (*q - '0'); ++q; any = true; }
        if (!any || v != (long)getpid() || strncmp(q, "/task/", 6) != 0) return false;
        p = q + 6;
    } else {
        return false;
    }
    bool anyTid = false;
    while (*p >= '0' && *p <= '9') { ++p; anyTid = true; }
    if (!anyTid || *p != '/') return false;
    return strcmp(p + 1, leaf) == 0;
}

static ProcSpoofKind ClassifyProcPath(const char* path) {
    if (!g_anti_emu || path == nullptr) return kProcNone;
    if (strcmp(path, "/proc/cpuinfo") == 0) {
        // hide_fs.cpp's CPU profile engine (ServeSysfsSpoofFd /
        // RewriteCpuinfoContent) owns /proc/cpuinfo while CpuSpoofActive().
        // Deferring here means the open() falls through the bytehook chain
        // into HideOpen / HideFopen, which serve the user's CPU name /
        // vendor / core layout. Anti-emu only serves its kona cpuinfo when
        // the CPU toggle is off.
        if (CpuSpoofActive()) return kProcNone;
        return kProcCpuInfo;
    }
    if (strcmp(path, "/proc/mounts") == 0) return kProcMounts;
    // Own-process status (TracerPid + Seccomp + NoNewPrivs) and SELinux.
    if (ProcSelfPath(path, "status") || ProcTaskSelfLeaf(path, "status")) {
        return kProcStatus;
    }
    if (strcmp(path, "/sys/fs/selinux/enforce") == 0) {
        return kProcSelinuxEnforce;
    }
    if (strcmp(path, "/proc/version") == 0) {
        return kProcVersion;
    }
    if (ProcSelfPath(path, "maps") || ProcSelfPath(path, "smaps") ||
        ProcTaskSelfLeaf(path, "maps") || ProcTaskSelfLeaf(path, "smaps")) {
        return kProcMaps;
    }
    if (ProcSelfPath(path, "mounts") || ProcSelfPath(path, "mountinfo") ||
        ProcSelfPath(path, "mountstats")) {
        return kProcMounts;
    }
    return kProcNone;
}

static int RawOpenRo(const char* path) {
#if defined(__NR_openat)
    return (int)syscall(__NR_openat, (int)AT_FDCWD, path, O_RDONLY, 0);
#else
    (void)path;
    return -1;
#endif
}

static int RawMemFd(const char* name) {
#if defined(__NR_memfd_create)
    return (int)syscall(__NR_memfd_create, name, 0x0001U /* MFD_CLOEXEC */);
#else
    (void)name;
    return -1;
#endif
}

// Line-level token filter for maps/smaps/mounts content. Deliberately NOT
// the same list as IsAntiEmuPath: content must never drop the app's own
// /data/app/** lib lines (no bare "x86" token here), while still hiding
// MuMu, houdini and every hooking-framework artifact AppDome scans for.
static bool LineHasToken(const char* line, size_t len) {
    static const char* const kTokens[] = {
        "nemu", "mumu", "houdini", "libnb", "ndk_translation",
        "nativebridge", "vaddress",
        "goldfish", "ranchu", "vbox", "geny", "qemu",
        "xposed", "edxposed", "lsposed", "zygisk", "magisk", "riru",
        "frida", "gadget", "dobby", "sandhook", "whale",
        // vNEXT: our own hook engine's mapping names. ByteHook labels every
        // patched PLT page "[anon:bytehook-plt-trampolines]"; com.playnearn
        // polls /proc/self/maps every 2 s and flagged exactly that line as a
        // hooking framework (server mark: Rooted_device_detected).
        "bytehook", "shadowhook", "plt-trampoline",
        "kimera", "libpas", "lspd", "/data/adb",
        "kernelsu", "trustme", "hp15", "javahelper",
        "/system/lib64/arm64/", "/system/lib/arm64/",
        "/system/lib64/arm/", "/system/lib/arm/",
        "/system/lib64/x86", "/system/lib/x86",
        "/vendor/arm64", "/vendor/x86",
    };
    for (const char* t : kTokens) {
        size_t tl = strlen(t);
        if (tl <= len && memmem(line, len, t, tl) != nullptr) return true;
    }
    return false;
}

// v2.9.7: APK-internal paths use the full ABI name ("base.apk!/lib/
// arm64-v8a/"); extracted-lib paths use the short name (".../lib/arm64/"),
// matching Android's extractNativeLibs=true layout. The discriminator is
// the ".apk!/" substring on the line. Both rewritten forms are real paths
// on a genuine SM-G991B base.apk (which is universal: the loader_config log
// shows library_path=...!/lib/x86_64:...!/lib/arm64-v8a).
static void RewriteMapsLine(std::string& line) {
    if (!PAS_F_REWRITE_MAPS_X86) return;

    bool in_apk = line.find(".apk!/") != std::string::npos;
    const char* arm64_dir = in_apk ? "arm64-v8a"   : "arm64";
    const char* arm32_dir = in_apk ? "armeabi-v7a" : "arm";

    std::string to64   = std::string("/lib/")   + arm64_dir + "/";
    std::string to32   = std::string("/lib/")   + arm32_dir + "/";
    std::string to64b  = std::string("/lib64/") + arm64_dir + "/";
    std::string to32b  = std::string("/lib64/") + arm32_dir + "/";

    auto rep = [](std::string& s, const char* from, const std::string& to) {
        size_t fl = strlen(from);
        size_t p = 0;
        while ((p = s.find(from, p)) != std::string::npos) {
            s.replace(p, fl, to);
            p += to.size();
        }
    };
    rep(line, "/lib/x86_64/",   to64);
    rep(line, "/lib/x86/",      to32);
    rep(line, "/lib64/x86_64/", to64b);
    rep(line, "/lib64/x86/",    to32b);

    if (in_apk) {
        rep(line, "split_config.x86_64.apk", "split_config.arm64_v8a.apk");
        rep(line, "split_config.x86.apk",    "split_config.armeabi_v7a.apk");
    }
}

static bool RawReadAll(const char* path, std::string& out) {
    int fd = RawOpenRo(path);
    if (fd < 0) return false;
    out.clear();
    char buf[16384];
    for (;;) {
#if defined(__NR_read)
        ssize_t n = syscall(__NR_read, fd, buf, sizeof(buf));
#else
        ssize_t n = -1;
#endif
        if (n <= 0) break;
        out.append(buf, (size_t)n);
        if (out.size() > (16u << 20)) break;
    }
#if defined(__NR_close)
    syscall(__NR_close, fd);
#endif
    return true;
}

// Rewrite x86 arch strings in a /proc/version body. uname(2) is already
// patched (MyUname) but the version FILE carried the real host arch.
static void RewriteVersionArch(std::string& s) {
    static const char* const kX86[] = {"x86_64", "i686", "i386"};
    for (const char* t : kX86) {
        size_t p = s.find(t);
        while (p != std::string::npos) {
            s.replace(p, strlen(t), "aarch64");
            p = s.find(t, p + 7);
        }
    }
}

// vNEXT: full kernel identity rewrite for /proc/version. The body looks like
//   Linux version <release> (<builder>) (<compiler>) #<N> SMP ... <date>
// Replace the release token and everything from the " #" version marker to
// the end of the line, so the file agrees with uname(2) (MyUname) and with
// the Java os.version spoof instead of leaking MuMu's 6.1.90-perf+ / "#2 SMP
// PREEMPT_DYNAMIC Wed Aug 26 07:46:48 UTC 2026".
static void RewriteKernelIdentity(std::string& s) {
    const std::string kPrefix = "Linux version ";
    size_t p = s.find(kPrefix);
    if (p != std::string::npos) {
        size_t rs = p + kPrefix.size();
        size_t re = s.find(' ', rs);
        if (re != std::string::npos && re > rs) {
            s.replace(rs, re - rs, g_kernel_release);
        }
    }
    size_t vpos = s.find(" #");
    if (vpos != std::string::npos) {
        size_t eol = s.find('\n', vpos);
        if (eol == std::string::npos) eol = s.size();
        s.replace(vpos + 1, eol - (vpos + 1), g_kernel_version);
    }
    RewriteVersionArch(s);
}

static void SetStatusField(std::string& s, const char* key, const char* value) {
    size_t p = s.find(key);
    if (p == std::string::npos) return;
    size_t e = s.find('\n', p);
    if (e == std::string::npos) e = s.size();
    size_t vstart = p + strlen(key);
    while (vstart < e && (s[vstart] == ' ' || s[vstart] == '\t')) vstart++;
    s.replace(vstart, e - vstart, value);
}

// After v2.9.7's real seccomp install on the main thread, the kernel itself
// writes Seccomp: 2 and Seccomp_filters: 1, so these two rewrites become
// idempotent no-ops for the main thread; they still cover the small window
// before the lazy install lands, and non-main threads (which read their
// own status via /proc/self/task/<tid>/status).
static void SanitizeStatus(std::string& s) {
    SetStatusField(s, "TracerPid:", "0");
    SetStatusField(s, "Seccomp:", "2");
    SetStatusField(s, "Seccomp_filters:", "1");
    SetStatusField(s, "NoNewPrivs:", "1");
}

// vNEXT: unnamed rwx anon mapping. Hook engines and instrumentation
// allocate executable+writable pages and often leave them nameless, while
// every legitimate entry carries a name ([anon:...], [stack], a path) or a
// size suffix. com.playnearn polls /proc/self/maps every 2 s; after the
// bytehook token landed the only remaining anomaly in its view was these
// bare rwx lines (4 vs 1 in an unscoped app), so a permission-based
// tamper check still fired. Dropping them is safe: nothing in the app can
// address them by name anyway.
static bool IsUnnamedRwxLine(const char* line, size_t len) {
    // perms field starts after "start-end "
    const char* sp = (const char*)memchr(line, ' ', len);
    if (sp == nullptr) return false;
    size_t off = (size_t)(sp - line) + 1;
    if (off + 3 > len) return false;
    if (line[off] != 'r' || line[off + 1] != 'w' || line[off + 2] != 'x') return false;
    // fields: range perms offset dev inode [pathname]
    // walk to the 4th separator (end of the dev field), then consume the
    // inode token; anything after it that is not whitespace is a name/path.
    int spaces = 0;
    size_t i = 0;
    for (; i < len; ++i) {
        if (line[i] == ' ') {
            spaces++;
            if (spaces == 4) {
                ++i;
                break;
            }
        }
    }
    if (spaces < 4) return false;
    while (i < len && line[i] != ' ' && line[i] != '\t' && line[i] != '\n' && line[i] != '\r') {
        ++i;
    }
    for (; i < len; ++i) {
        char c = line[i];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\0') return false;
    }
    return true;
}

static bool BuildFiltered(ProcSpoofKind kind, const char* path, std::string& out) {
    std::string all;
    if (!RawReadAll(path, all)) return false;
    out.clear();
    out.reserve(all.size());

    size_t start = 0;
    while (start < all.size()) {
        size_t nl = all.find('\n', start);
        size_t next = (nl == std::string::npos) ? all.size() : nl + 1;

        if (!LineHasToken(all.c_str() + start, next - start)) {
            if (kind == kProcMaps) {
                if (IsUnnamedRwxLine(all.c_str() + start, next - start)) {
                    start = next;
                    continue;
                }
                std::string line(all.c_str() + start, next - start);
                RewriteMapsLine(line);
                out += line;
            } else {
                out.append(all, start, next - start);
            }
        }
        start = next;
    }
    return !out.empty();
}

// Genuine kona (Samsung SM-G991B, Snapdragon 888) style AArch64 cpuinfo.
// Only served when CpuSpoofActive() is false (see ClassifyProcPath).
static const std::string& CpuInfoText() {
    static const std::string kText = [] {
        std::string s;
        char b[192];
        s += "Processor\t: AArch64 Processor rev 14 (aarch64)\n";
        for (int i = 0; i < 8; ++i) {
            snprintf(b, sizeof(b), "processor\t: %d\n", i);
            s += b;
            s += "BogoMIPS\t: 38.40\n";
            s += "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\n";
            s += "CPU implementer\t: 0x51\n";
            s += "CPU architecture: 8\n";
            s += "CPU variant\t: 0x2\n";
            snprintf(b, sizeof(b), "CPU part\t: 0x%x\n", (i < 4) ? 0x802 : 0x805);
            s += b;
            s += "CPU revision\t: 14\n\n";
        }
        s += "Hardware\t: Qualcomm Technologies, Inc SM8350\n";
        return s;
    }();
    return kText;
}

// Returns a memfd holding the spoofed content, or -1 (caller falls through
// to the real open). The fd behaves exactly like a regular file fd for
// read/pread/lseek/mmap/fdopen, so no other hook is needed downstream.
static int ServeProcFd(ProcSpoofKind kind, const char* path) {
    std::string content;
    if (kind == kProcCpuInfo) {
        content = CpuInfoText();
    } else if (kind == kProcSelinuxEnforce) {
        content = "1\n";
    } else if (kind == kProcStatus) {
        if (!RawReadAll(path, content)) return -1;
        SanitizeStatus(content);
    } else if (kind == kProcVersion) {
        if (!RawReadAll(path, content)) return -1;
        RewriteKernelIdentity(content);
    } else {
        if (!BuildFiltered(kind, path, content)) return -1;
    }
    int mfd = RawMemFd("pas_proc_spoof");
    if (mfd < 0) return -1;
    const char* p = content.data();
    size_t left = content.size();
    while (left > 0) {
#if defined(__NR_write)
        ssize_t w = syscall(__NR_write, mfd, p, left);
#else
        ssize_t w = -1;
#endif
        if (w <= 0) {
#if defined(__NR_close)
            syscall(__NR_close, mfd);
#endif
            return -1;
        }
        p += w;
        left -= (size_t)w;
    }
#if defined(__NR_lseek)
    syscall(__NR_lseek, mfd, 0, SEEK_SET);
#endif
    static bool s_logged[7] = {false, false, false, false, false, false, false};
    if (kind >= kProcCpuInfo && kind <= kProcVersion && !s_logged[kind]) {
        s_logged[kind] = true;
        Log("native: anti-emu proc spoof kind=%d path=%s (%u bytes)",
            (int)kind, path, (unsigned)content.size());
    }
    return mfd;
}

// ---------------------------------------------------------------------------
// libc open family - every entry point the SDKs use for File.exists() /
// FileInputStream / fopen / ifstream
// ---------------------------------------------------------------------------

static int MyOpen(const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    MaybeInstallSeccompOnMainThread();
    if (path != nullptr && (flags & O_ACCMODE) == O_RDONLY) {
        ProcSpoofKind k = ClassifyProcPath(path);
        if (k != kProcNone) {
            int fd = ServeProcFd(k, path);
            if (fd >= 0) return fd;
        }
    }
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
    MaybeInstallSeccompOnMainThread();
    if (path != nullptr && (flags & O_ACCMODE) == O_RDONLY) {
        ProcSpoofKind k = ClassifyProcPath(path);
        if (k != kProcNone) {
            int fd = ServeProcFd(k, path);
            if (fd >= 0) return fd;
        }
    }
    if (IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyOpen2, path, flags);
}

static int MyOpenAt(int dirfd, const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    MaybeInstallSeccompOnMainThread();
    if (path != nullptr && path[0] == '/' && (flags & O_ACCMODE) == O_RDONLY) {
        ProcSpoofKind k = ClassifyProcPath(path);
        if (k != kProcNone) {
            int fd = ServeProcFd(k, path);
            if (fd >= 0) return fd;
        }
    }
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
    MaybeInstallSeccompOnMainThread();
    if (path != nullptr && path[0] == '/' && (flags & O_ACCMODE) == O_RDONLY) {
        ProcSpoofKind k = ClassifyProcPath(path);
        if (k != kProcNone) {
            int fd = ServeProcFd(k, path);
            if (fd >= 0) return fd;
        }
    }
    if (path && path[0] == '/' && IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyOpenAt2, dirfd, path, flags);
}

static FILE* MyFopen(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    MaybeInstallSeccompOnMainThread();
    if (path != nullptr && mode != nullptr && mode[0] == 'r') {
        ProcSpoofKind k = ClassifyProcPath(path);
        if (k != kProcNone) {
            int fd = ServeProcFd(k, path);
            if (fd >= 0) {
                FILE* f = fdopen(fd, mode);
                if (f != nullptr) return f;
                close(fd);
            }
        }
    }
    if (IsAntiEmuPath(path)) { errno = ENOENT; return nullptr; }
    return BYTEHOOK_CALL_PREV(MyFopen, path, mode);
}

static int MyAccess(const char* path, int mode) {
    BYTEHOOK_STACK_SCOPE();
    MaybeInstallSeccompOnMainThread();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyAccess, path, mode);
}

static int MyFAccessAt(int dirfd, const char* path, int mode, int flags) {
    BYTEHOOK_STACK_SCOPE();
    MaybeInstallSeccompOnMainThread();
    if (path && path[0] == '/' && IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyFAccessAt, dirfd, path, mode, flags);
}

static int MyStat(const char* path, struct stat* buf) {
    BYTEHOOK_STACK_SCOPE();
    MaybeInstallSeccompOnMainThread();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyStat, path, buf);
}

static int MyLstat(const char* path, struct stat* buf) {
    BYTEHOOK_STACK_SCOPE();
    MaybeInstallSeccompOnMainThread();
    if (IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyLstat, path, buf);
}

static int MyFstatAt(int dirfd, const char* path, struct stat* buf, int flags) {
    BYTEHOOK_STACK_SCOPE();
    MaybeInstallSeccompOnMainThread();
    if (path && path[0] == '/' && IsAntiEmuPath(path)) { errno = ENOENT; return -1; }
    return BYTEHOOK_CALL_PREV(MyFstatAt, dirfd, path, buf, flags);
}

// ---------------------------------------------------------------------------
// v2.9.7: direct syscall() bypass closer
//
// Installed after hide_fs.cpp's syscall hook (pas.cpp stage 4a vs 5b), so
// this is the OUTER layer: anti-emu paths handled first, then falls through
// via BYTEHOOK_CALL_PREV to hide_fs.MySyscall (CPU freq / interface hiding).
//
// Bytehook's CallerAllowHooks filter excludes Houdini / native-bridge libs
// (their syscalls are x86_64 host syscalls running ARM-translated code; a
// vararg mismatch there would corrupt the bridge). App code (x86_64) and
// the module itself are the only callers that hit this hook, which is
// exactly what we want.
// ---------------------------------------------------------------------------
static long MySyscall(long number, ...) {
    BYTEHOOK_STACK_SCOPE();
    MaybeInstallSeccompOnMainThread();

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
            int flags = (int)a2;
            if (path != nullptr && path[0] == '/' && (flags & O_ACCMODE) == O_RDONLY) {
                ProcSpoofKind k = ClassifyProcPath(path);
                if (k != kProcNone) {
                    int fd = ServeProcFd(k, path);
                    if (fd >= 0) return fd;
                }
            }
            if (path != nullptr && path[0] == '/' && IsAntiEmuPath(path)) {
                errno = ENOENT;
                return -1;
            }
        }
#endif
#if defined(__NR_open)
        if (number == __NR_open) {
            const char* path = (const char*)a0;
            int flags = (int)a1;
            if (path != nullptr && path[0] == '/' && (flags & O_ACCMODE) == O_RDONLY) {
                ProcSpoofKind k = ClassifyProcPath(path);
                if (k != kProcNone) {
                    int fd = ServeProcFd(k, path);
                    if (fd >= 0) return fd;
                }
            }
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
// property filter - AppsFlyer / Mintegral / AppDome-grade probes
// ---------------------------------------------------------------------------

// If the CPU toggle is active, follow the user's CPU profile for
// hardware-ish properties. Otherwise keep the kona fallbacks. Same value
// hide_props.cpp would produce, so the two layers stay consistent.
static const char* CpuHwOr(const char* fallback) {
    if (!CpuSpoofActive()) return fallback;
    static std::string v;
    v = CpuSpoofHardware();
    return v.empty() ? fallback : v.c_str();
}

// Props whose value on MuMu is x86 but whose value on a genuine kona
// (SM-G991B) is ARM. Rewritten, not blanked: a blank reads as "property
// missing", which is itself tamper evidence on a Samsung build.
//
// The CPU toggle's profile engine owns ro.hardware while CpuSpoofActive() -
// hide_props.cpp spoofs it from the user's profile. We defer so the profile
// value wins; when the CPU toggle is off we still rewrite to the kona
// placeholder. The pure ABI props below are NOT deferred: the anti-emu ARM
// story needs them, and the abi toggle only owns them when anti-emu is off.
static const char* ArmAbiValue(const char* name) {
    static const char kAbi64[] = "arm64-v8a";
    static const char kAbiList[] = "arm64-v8a,armeabi-v7a,armeabi";
    static const char kAbiList32[] = "armeabi-v7a,armeabi";
    const size_t n = strlen(name);
    if (n <= 3 || strncmp(name, "ro.", 3) != 0) return nullptr;

    auto suffixIs = [&](const char* s) {
        size_t l = strlen(s);
        return n >= l && strcmp(name + (n - l), s) == 0;
    };
    if (suffixIs(".cpu.abi")) return kAbi64;
    if (suffixIs(".cpu.abilist64")) return kAbi64;
    if (suffixIs(".cpu.abilist32")) return kAbiList32;
    if (suffixIs(".cpu.abilist")) return kAbiList;
    if (strcmp(name, "ro.bionic.arch") == 0) return "arm64";
    if (strcmp(name, "ro.bionic.2nd_arch") == 0) return "arm";
    if (strcmp(name, "ro.bionic.cpu_variant") == 0) return "kryo";
    if (strcmp(name, "ro.dalvik.vm.isa.arm") == 0) return "arm";
    if (strcmp(name, "ro.dalvik.vm.isa.arm64") == 0) return "arm64";

    // Hardware props follow the active CPU profile where applicable.
    if (strcmp(name, "ro.product.board") == 0) return CpuHwOr("exynos2100");
    if (strcmp(name, "ro.boot.hardware") == 0) return CpuHwOr("exynos2100");
    if (strcmp(name, "ro.hardware.egl") == 0) return CpuHwOr("exynos2100");
    if (strcmp(name, "ro.arch") == 0) return CpuHwOr("exynos2100");
    if (strcmp(name, "ro.board.platform") == 0) return CpuHwOr("exynos2100");
    if (strcmp(name, "ro.hardware") == 0) return CpuHwOr("qcom");

    // Root/debug and build-host leaks. HookAntiEmu already patches Java
    // Build.HOST/USER; native reads need the same values.
    if (strcmp(name, "ro.build.host") == 0) return "SWDD5907";
    if (strcmp(name, "ro.build.user") == 0) return "dpi";
    // vNEXT: service.adb.root moved to hide_props.cpp (always-on adb-root
    // family, armed via nativeSetAdbSpoof) so it no longer depends on the
    // anti-emu toggle.
    return nullptr;
}

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

static int MyPropGet(const char* name, char* value) {
    BYTEHOOK_STACK_SCOPE();
    if (g_anti_emu && name != nullptr && value != nullptr) {
        if (const char* v = ArmAbiValue(name)) {
            size_t l = strlen(v);
            if (l >= PROP_VALUE_MAX) l = PROP_VALUE_MAX - 1;
            memcpy(value, v, l);
            value[l] = '\0';
            return (int)l;
        }
    }
    if (IsAntiEmuProp(name)) {
        if (value != nullptr) value[0] = '\0';
        return 0;
    }
    return BYTEHOOK_CALL_PREV(MyPropGet, name, value);
}

static const prop_info* MyPropFind(const char* name) {
    BYTEHOOK_STACK_SCOPE();
    if (IsAntiEmuProp(name)) return nullptr;
    // ABI props fall through on purpose: find() succeeds, and the value is
    // sanitized at read time (both in MyPropGet and MyPropReadCallback).
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
    if (g_anti_emu && pi != nullptr && cb != nullptr) {
        PropGrab g;
        g.name = nullptr;
        g.serial = 0;
        BYTEHOOK_CALL_PREV(MyPropReadCallback, pi, &PropGrabCb, &g);
        if (g.name != nullptr) {
            if (const char* v = ArmAbiValue(g.name)) {
                cb(cookie, g.name, v, g.serial);
                return;
            }
            if (IsAntiEmuProp(g.name)) {
                cb(cookie, g.name, "", g.serial);
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
// uname - utsname.machine is a one-line check for x86_64 / i386 / i686
// ---------------------------------------------------------------------------

static int MyUname(struct utsname* u) {
    int r = BYTEHOOK_CALL_PREV(MyUname, u);
    if (r == 0 && g_anti_emu && u != nullptr) {
        // NOTE: utsname.machine is owned by the ABI layer (HideUname in
        // hide_props.cpp, gated on g_abi_on). Deliberately not rewritten
        // here: a package on the ABI blacklist must keep the real machine
        // string, and two writers would fight over it.
        // vNEXT: release/version carry the emulator kernel (6.1.90-perf+ /
        // "#2 SMP PREEMPT_DYNAMIC ..."). Native collectors read them here,
        // bypassing every Java-side spoof, so rewrite both fields.
        if (g_kernel_spoof) {
            snprintf(u->release, sizeof(u->release), "%s", g_kernel_release);
            snprintf(u->version, sizeof(u->version), "%s", g_kernel_version);
            static bool s_klogged = false;
            if (!s_klogged) {
                s_klogged = true;
                Log("native: anti-emu uname release/version -> %s / %s", g_kernel_release,
                    g_kernel_version);
            }
        }
    }
    return r;
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
        {"uname",      (void*)MyUname},
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
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libc.so",
                              "__system_property_read_callback",
                              (void*)MyPropReadCallback, nullptr, nullptr)) okProp++;
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libc.so", "__system_property_foreach",
                              (void*)MyPropForeach, nullptr, nullptr)) okProp++;

    int okSys = 0;
    if (PAS_F_HOOK_SYSCALL) {
        if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libc.so", "syscall",
                                  (void*)MySyscall, nullptr, nullptr)) okSys++;
    }

    Log("native: anti-emu hooks installed fs=%d/%d prop=%d/4 syscall=%d/1 (runtime-gated)",
        okFs, (int)(sizeof(kFsSpecs) / sizeof(kFsSpecs[0])), okProp, okSys);
}

}  // namespace pas

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetAntiEmu(JNIEnv* env, jobject thiz, jboolean on) {
    (void)env;
    (void)thiz;
    pas::SetAntiEmu(on == JNI_TRUE);
}

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetKernelSpoof(JNIEnv* env, jobject thiz,
                                                         jboolean on,
                                                         jstring release,
                                                         jstring version) {
    (void)thiz;
    const char* rel = nullptr;
    const char* ver = nullptr;
    if (release != nullptr) rel = env->GetStringUTFChars(release, nullptr);
    if (version != nullptr) ver = env->GetStringUTFChars(version, nullptr);
    pas::SetAntiEmuKernel(on == JNI_TRUE, rel, ver);
    if (rel != nullptr) env->ReleaseStringUTFChars(release, rel);
    if (ver != nullptr) env->ReleaseStringUTFChars(version, ver);
}