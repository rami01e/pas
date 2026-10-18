// hide_antiemu.cpp - ANTI-EMU native layer (2.10.3).
//
// v2.10.3 changes over v2.10.2 (from jj-appdome-capture 10-18):
//
//  - NEW: dl_iterate_phdr hook. AppDome-grade RASP walks the loaded
//    library list via dl_iterate_phdr() to find libhoudini.so /
//    libndk_translation.so without touching the filesystem at all.
//    v2.9.7 hid those paths from open/stat/syscall, but the enumeration
//    bypassed every hook. v2.9.8 wraps the callback and skips the
//    translation libraries so the enumeration is clean.
//
//  - NEW: prctl hook (libc + __NR_prctl via syscall). v2.9.7 installed
//    real seccomp only lazily on the main thread. A RASP that calls
//    prctl(PR_GET_SECCOMP) directly got 0 before the lazy install
//    landed, and prctl(PR_GET_NO_NEW_PRIVS) returned 0 forever because
//    nothing set it before the check. v2.9.8 intercepts both the libc
//    wrapper and the raw __NR_prctl syscall to always answer
//    SECCOMP_MODE_FILTER (2) and NoNewPrivs (1).
//
//  - NEW: early main-thread seccomp via epoll_wait / epoll_pwait /
//    epoll_pwait2 / pthread_create hooks. The June's Journey activity
//    thread idles in epoll_wait once Unity takes over and stops doing
//    file I/O, so the v2.9.7 lazy hooks (open/openat/fopen/stat/...) never
//    fired on main. epoll_wait fires every time the Looper wakes, which
//    is the earliest reliable main-thread signal. Seccomp installed this
//    way makes /proc/self/status report Seccomp: 2 natively for the whole
//    process, matching every stock Samsung app.
//
//  - NEW: readlink / readlinkat sanitization. MuMu's graphics stack keeps
//    /dev/vaddress fds open (see 08-proc-snapshots: fds 130, 133 ->
//    /dev/vaddress). The RASP opens /proc/self/fd/* and reads each
//    symlink; the targets were leaking MuMu. v2.9.8 rewrites the symlink
//    content to /dev/null for any fd that resolves to a known emulator
//    device.
//
//  - NEW: dlopen hook to make dlopen("libhoudini.so", RTLD_NOLOAD) and
//    friends return NULL/ENOENT, matching a real ARM device.
//
//  - /dev/vaddress, KernelSU paths (/dev/ksu, /sbin/ksu, ...) added to
//    IsAntiEmuPath. The 09-kernel-security log shows KernelSU active;
//    MuMu's /dev/vaddress leaks in fds (see 08).
//
//  - libhoudini.so / libndk_translation.so / libnb.so added to the maps
//    filter (LineHasToken). libnemu* / libmumu* / libhp15 / libjavahelper
//    are added to IsAntiEmuLibName so dl_iterate_phdr also filters them.
//
//  - Runtime-gated on g_anti_emu throughout; caller filter is still
//    CallerAllowHooks so Houdini / native-bridge libs bypass the hooks
//    (their own property and file reads stay raw and MuMu keeps working).
//
// The real seccomp install from v2.9.7 (EnsurePermissiveSeccompThisThread
// with SECCOMP_RET_ALLOW) is retained unchanged. v2.9.8 just delivers it
// to the main thread earlier so the kernel actually reports it.

#include "pas.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <time.h>
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

// Seccomp per-thread install state.
static __thread bool t_seccomp_installed = false;
static __thread bool t_seccomp_failed    = false;
static __thread int  t_is_main           = -1;   // -1 unknown, 0 no, 1 yes
static volatile bool g_seccomp_installed_main = false;

static inline pid_t GetTid() {
#if defined(__NR_gettid)
    return (pid_t)syscall(__NR_gettid);
#else
    return gettid();
#endif
}

// ---------------------------------------------------------------------------
// v2.9.7: real permissive seccomp (see file header for scope statement)
// ---------------------------------------------------------------------------
static void EnsurePermissiveSeccompThisThread() {
    if (!PAS_F_REAL_SECCOMP) return;
    if (t_seccomp_installed || t_seccomp_failed) return;

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
    Log("native: anti-emu seccomp target=MAIN thread (tid=%d)", (int)GetTid());
    EnsurePermissiveSeccompThisThread();
    g_seccomp_installed_main = true;
}

// ---------------------------------------------------------------------------
// public entry point (unchanged signature)
// ---------------------------------------------------------------------------
void SetAntiEmu(bool on) {
    g_anti_emu = on;
    if (on) {
        EnsurePermissiveSeccompThisThread();
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
        "/sys/class/dmi",
        "/sys/devices/virtual/dmi",
        // Houdini / NDK translation / native-bridge artifacts
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

        // Root / privilege artifacts
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

        // v2.9.8: MuMu graphics device + KernelSU artifacts
        "/dev/vaddress",
        "/dev/ksu",
        "/sbin/ksu",
        "/system/bin/ksu",
        "/system/xbin/ksu",
        "/debug_ramdisk/ksu",
        "/debug_ramdisk/su",

        // Writability-probe targets
        "/data/local/tmp",
        "/debug_ramdisk",
        "/data/local",
    };
    for (const char* p : kExact) {
        if (strcmp(path, p) == 0) return true;
    }

    if (strncmp(path, "/data/adb/", 10) == 0) return true;

    if (strncmp(path, "/sbin/", 6) == 0 ||
        strncmp(path, "/bin/", 5) == 0 ||
        strncmp(path, "/system/bin/", 12) == 0 ||
        strncmp(path, "/system/xbin/", 13) == 0) {
        if (strstr(path, "magisk") != nullptr || strstr(path, ".magisk") != nullptr) {
            return true;
        }
        if (strstr(path, "ksu") != nullptr || strstr(path, "ksud") != nullptr) {
            return true;
        }
    }

    if (PAS_F_HIDE_GRE0_SYSFS) {
        static const char kGre0Dev[] = "/sys/devices/virtual/net/gre0";
        static const char kGre0Cls[] = "/sys/class/net/gre0";
        if (StartsWithPrefixSeg(path, kGre0Dev, sizeof(kGre0Dev) - 1)) return true;
        if (StartsWithPrefixSeg(path, kGre0Cls, sizeof(kGre0Cls) - 1)) return true;
    }

    if (strstr(path, "qemu_pipe") != nullptr) return true;
    if (strstr(path, "/libc_malloc_debug_qemu") != nullptr) return true;
    if (strstr(path, "houdini") != nullptr) return true;
    if (strstr(path, "ndk_translation") != nullptr) return true;

    if (strncmp(path, "/sys/class/dmi/", 15) == 0) return true;
    if (strncmp(path, "/sys/devices/virtual/dmi/", 25) == 0) return true;

    if (strstr(path, "/goldfish") != nullptr) return true;
    if (strstr(path, "/ranchu") != nullptr) return true;
    if (strstr(path, "/vbox") != nullptr) return true;
    if (strstr(path, "/geny") != nullptr) return true;
    if (strstr(path, "/nemu") != nullptr) return true;
    if (strstr(path, "/mumu") != nullptr) return true;
    if (strstr(path, "/com.mumu") != nullptr) return true;
    if (strstr(path, "/com.nemu") != nullptr) return true;

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
// v2.9.8: library name filter used by dl_iterate_phdr / dlopen
// ---------------------------------------------------------------------------
static bool IsAntiEmuLibName(const char* name) {
    if (name == nullptr || name[0] == '\0') return false;
    static const char* const kLibs[] = {
        "libhoudini.so",
        "libndk_translation.so",
        "libnb.so",
        "libnemu",
        "libmumu",
        "libhp15",
        "libjavahelper",
    };
    for (const char* p : kLibs) {
        if (strstr(name, p) != nullptr) return true;
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
    kProcStatus = 4,
    kProcSelinuxEnforce = 5,
    kProcVersion = 6,
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
        if (CpuSpoofActive()) return kProcNone;
        return kProcCpuInfo;
    }
    if (strcmp(path, "/proc/mounts") == 0) return kProcMounts;
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

static bool LineHasToken(const char* line, size_t len) {
    static const char* const kTokens[] = {
        "nemu", "mumu", "houdini", "libnb", "ndk_translation",
        "nativebridge", "vaddress",
        "goldfish", "ranchu", "vbox", "geny", "qemu",
        "xposed", "edxposed", "lsposed", "zygisk", "magisk", "riru",
        "frida", "gadget", "dobby", "sandhook", "whale",
        "kimera", "libpas", "lspd", "/data/adb",
        "kernelsu", "trustme", "hp15", "javahelper",
        "/dev/ksu", "ksud",
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

static void SetStatusField(std::string& s, const char* key, const char* value) {
    size_t p = s.find(key);
    if (p == std::string::npos) return;
    size_t e = s.find('\n', p);
    if (e == std::string::npos) e = s.size();
    size_t vstart = p + strlen(key);
    while (vstart < e && (s[vstart] == ' ' || s[vstart] == '\t')) vstart++;
    s.replace(vstart, e - vstart, value);
}

static void SanitizeStatus(std::string& s) {
    SetStatusField(s, "TracerPid:", "0");
    SetStatusField(s, "Seccomp:", "2");
    SetStatusField(s, "Seccomp_filters:", "1");
    SetStatusField(s, "NoNewPrivs:", "1");
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
        RewriteVersionArch(content);
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
// v2.9.8: dl_iterate_phdr hook - hide ARM-translation libs from enumeration
// ---------------------------------------------------------------------------
struct DlIterData {
    int (*cb)(struct dl_phdr_info*, size_t, void*);
    void* data;
};

static int DlIterFilter(struct dl_phdr_info* info, size_t size, void* data) {
    DlIterData* d = static_cast<DlIterData*>(data);
    if (info != nullptr && info->dlpi_name != nullptr &&
        IsAntiEmuLibName(info->dlpi_name)) {
        return 0;  // skip this library, continue iteration
    }
    return d->cb(info, size, d->data);
}

static int MyDlIteratePhdr(int (*cb)(struct dl_phdr_info*, size_t, void*), void* data) {
    BYTEHOOK_STACK_SCOPE();
    if (!g_anti_emu || cb == nullptr) {
        return BYTEHOOK_CALL_PREV(MyDlIteratePhdr, cb, data);
    }
    DlIterData d{cb, data};
    return BYTEHOOK_CALL_PREV(MyDlIteratePhdr, DlIterFilter, &d);
}

// ---------------------------------------------------------------------------
// v2.9.8: dlopen hook - dlopen("libhoudini.so", RTLD_NOLOAD) -> NULL/ENOENT
// ---------------------------------------------------------------------------
static void* MyDlopen(const char* filename, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (g_anti_emu && filename != nullptr && IsAntiEmuLibName(filename)) {
        errno = ENOENT;
        return nullptr;
    }
    return BYTEHOOK_CALL_PREV(MyDlopen, filename, flags);
}

// ---------------------------------------------------------------------------
// libc open family
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
// v2.9.8: readlink/readlinkat - hide /dev/vaddress fd targets
// ---------------------------------------------------------------------------
static bool ShouldSanitizeFdTarget(const char* target, size_t len) {
    static const char* const kSuspicious[] = {
        "/dev/vaddress",
        "/dev/qemu_pipe",
        "/dev/goldfish",
        "/dev/socket/qemud",
        "/dev/socket/genyd",
    };
    for (const char* s : kSuspicious) {
        size_t sl = strlen(s);
        if (sl <= len && memmem(target, len, s, sl) != nullptr) return true;
    }
    return false;
}

static ssize_t MyReadlink(const char* path, char* buf, size_t bufsiz) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t r = BYTEHOOK_CALL_PREV(MyReadlink, path, buf, bufsiz);
    if (g_anti_emu && r > 0 && buf != nullptr &&
        ShouldSanitizeFdTarget(buf, (size_t)r)) {
        const char* safe = "/dev/null";
        size_t l = strlen(safe);
        if (l > bufsiz) l = bufsiz;
        memcpy(buf, safe, l);
        return (ssize_t)l;
    }
    return r;
}

static ssize_t MyReadlinkAt(int dirfd, const char* path, char* buf, size_t bufsiz) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t r = BYTEHOOK_CALL_PREV(MyReadlinkAt, dirfd, path, buf, bufsiz);
    if (g_anti_emu && r > 0 && buf != nullptr &&
        ShouldSanitizeFdTarget(buf, (size_t)r)) {
        const char* safe = "/dev/null";
        size_t l = strlen(safe);
        if (l > bufsiz) l = bufsiz;
        memcpy(buf, safe, l);
        return (ssize_t)l;
    }
    return r;
}

// ---------------------------------------------------------------------------
// v2.9.8: prctl hook - spoof PR_GET_SECCOMP / PR_GET_NO_NEW_PRIVS queries
// ---------------------------------------------------------------------------
static int MyPrctl(int option, ...) {
    BYTEHOOK_STACK_SCOPE();
    if (g_anti_emu) {
        if (option == PR_GET_SECCOMP) return 2;
        if (option == PR_GET_NO_NEW_PRIVS) return 1;
    }
    va_list ap;
    va_start(ap, option);
    unsigned long a2 = va_arg(ap, unsigned long);
    unsigned long a3 = va_arg(ap, unsigned long);
    unsigned long a4 = va_arg(ap, unsigned long);
    unsigned long a5 = va_arg(ap, unsigned long);
    va_end(ap);
    return BYTEHOOK_CALL_PREV(MyPrctl, option, a2, a3, a4, a5);
}

// ---------------------------------------------------------------------------
// v2.9.8: main-thread seccomp early delivery
//
// Once Unity takes over, the June's Journey activity thread idles in
// epoll_wait and never calls open/stat/access again. Without these hooks,
// /proc/self/status stayed at Seccomp: 0 for the whole process (see the
// 08-proc-snapshots captures). epoll_wait fires every time the Looper
// wakes, which is the earliest reliable main-thread signal.
// ---------------------------------------------------------------------------
static int MyPthreadCreate(pthread_t* thread, const pthread_attr_t* attr,
                           void* (*start_routine)(void*), void* arg) {
    BYTEHOOK_STACK_SCOPE();
    MaybeInstallSeccompOnMainThread();
    return BYTEHOOK_CALL_PREV(MyPthreadCreate, thread, attr, start_routine, arg);
}

static int MyEpollWait(int epfd, struct epoll_event* events, int maxevents, int timeout) {
    BYTEHOOK_STACK_SCOPE();
    if (!g_seccomp_installed_main && g_anti_emu) {
        MaybeInstallSeccompOnMainThread();
    }
    return BYTEHOOK_CALL_PREV(MyEpollWait, epfd, events, maxevents, timeout);
}

static int MyEpollPWait(int epfd, struct epoll_event* events, int maxevents,
                        int timeout, const sigset_t* sigmask) {
    BYTEHOOK_STACK_SCOPE();
    if (!g_seccomp_installed_main && g_anti_emu) {
        MaybeInstallSeccompOnMainThread();
    }
    return BYTEHOOK_CALL_PREV(MyEpollPWait, epfd, events, maxevents, timeout, sigmask);
}

static int MyEpollPWait2(int epfd, struct epoll_event* events, int maxevents,
                         const struct timespec* timeout, const sigset_t* sigmask) {
    BYTEHOOK_STACK_SCOPE();
    if (!g_seccomp_installed_main && g_anti_emu) {
        MaybeInstallSeccompOnMainThread();
    }
    return BYTEHOOK_CALL_PREV(MyEpollPWait2, epfd, events, maxevents, timeout, sigmask);
}

// ---------------------------------------------------------------------------
// v2.9.8: direct syscall() bypass closer (extended with __NR_prctl)
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
#if defined(__NR_prctl)
        if (number == __NR_prctl) {
            int opt = (int)a0;
            if (opt == PR_GET_SECCOMP) return 2;
            if (opt == PR_GET_NO_NEW_PRIVS) return 1;
        }
#endif
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

    return BYTEHOOK_CALL_PREV(MySyscall, number, a0, a1, a2, a3, a4, a5);
}

// ---------------------------------------------------------------------------
// property filter
// ---------------------------------------------------------------------------

static const char* CpuHwOr(const char* fallback) {
    if (!CpuSpoofActive()) return fallback;
    static std::string v;
    v = CpuSpoofHardware();
    return v.empty() ? fallback : v.c_str();
}

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

    if (strcmp(name, "ro.product.board") == 0) return CpuHwOr("exynos2100");
    if (strcmp(name, "ro.boot.hardware") == 0) return CpuHwOr("exynos2100");
    if (strcmp(name, "ro.hardware.egl") == 0) return CpuHwOr("exynos2100");
    if (strcmp(name, "ro.arch") == 0) return CpuHwOr("exynos2100");
    if (strcmp(name, "ro.board.platform") == 0) return CpuHwOr("exynos2100");
    if (strcmp(name, "ro.hardware") == 0) return CpuHwOr("qcom");

    if (strcmp(name, "ro.build.host") == 0) return "SWDD5907";
    if (strcmp(name, "ro.build.user") == 0) return "dpi";
    if (strcmp(name, "service.adb.root") == 0) return "0";
    return nullptr;
}

static bool IsAntiEmuProp(const char* name) {
    if (!g_anti_emu || name == nullptr) return false;

    static const char* const kProps[] = {
        "ro.kernel.qemu",
        "ro.boot.qemu",
        "ro.boot.qemu.avd_name",
        "ro.kernel.qemu.gles",
        "ro.chipname",
        "ro.dalvik.vm.native.bridge",
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
    if (IsAntiEmuProp(g.name)) return;
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
// uname
// ---------------------------------------------------------------------------

static int MyUname(struct utsname* u) {
    int r = BYTEHOOK_CALL_PREV(MyUname, u);
    if (r == 0 && g_anti_emu && u != nullptr) {
        if (strstr(u->machine, "x86") != nullptr || strstr(u->machine, "i386") != nullptr ||
            strstr(u->machine, "i686") != nullptr) {
            memset(u->machine, 0, sizeof(u->machine));
            snprintf(u->machine, sizeof(u->machine), "%s", "aarch64");
            static bool s_logged = false;
            if (!s_logged) {
                s_logged = true;
                Log("native: anti-emu uname machine -> aarch64");
            }
        }
    }
    return r;
}

// ---------------------------------------------------------------------------
// v2.9.8: InstallAntiEmuHooks - extended with dl_iterate_phdr / dlopen /
// prctl / pthread_create / epoll_wait / epoll_pwait / epoll_pwait2 /
// readlink / readlinkat
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
        {"readlink",   (void*)MyReadlink},
        {"readlinkat", (void*)MyReadlinkAt},
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

    // v2.9.8 hooks
    int okLib = 0;
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libc.so",
                              "dl_iterate_phdr", (void*)MyDlIteratePhdr,
                              nullptr, nullptr)) okLib++;
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libdl.so",
                              "dl_iterate_phdr", (void*)MyDlIteratePhdr,
                              nullptr, nullptr)) okLib++;
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libdl.so",
                              "dlopen", (void*)MyDlopen,
                              nullptr, nullptr)) okLib++;

    int okSec = 0;
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libc.so",
                              "prctl", (void*)MyPrctl,
                              nullptr, nullptr)) okSec++;
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libc.so",
                              "pthread_create", (void*)MyPthreadCreate,
                              nullptr, nullptr)) okSec++;
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libc.so",
                              "epoll_wait", (void*)MyEpollWait,
                              nullptr, nullptr)) okSec++;
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libc.so",
                              "epoll_pwait", (void*)MyEpollPWait,
                              nullptr, nullptr)) okSec++;
    if (bytehook_hook_partial(CallerAllowHooks, nullptr, "libc.so",
                              "epoll_pwait2", (void*)MyEpollPWait2,
                              nullptr, nullptr)) okSec++;

    Log("native: anti-emu hooks installed fs=%d/%d prop=%d/4 syscall=%d/1 lib=%d/3 sec=%d/5 (runtime-gated)",
        okFs, (int)(sizeof(kFsSpecs) / sizeof(kFsSpecs[0])), okProp, okSys, okLib, okSec);
}

}  // namespace pas

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetAntiEmu(JNIEnv* env, jobject thiz, jboolean on) {
    (void)env;
    (void)thiz;
    pas::SetAntiEmu(on == JNI_TRUE);
}