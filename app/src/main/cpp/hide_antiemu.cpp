// hide_antiemu.cpp - ANTI-EMU native layer (v2.9.4).
//
// v2.9.4 additions over v2.9.2 (AppDome hardening, evidence JJ capture):
//  - ROOT-PATH ENOENT: the target access()-probed /system/xbin/su FOUR
//    times in its first second (classic root check; MuMu ships su in
//    /system/xbin). The standard root/artifact paths now answer ENOENT
//    while ANTI-EMU is on. System callers never reach these wrappers
//    (the bytehook caller filter excludes them), so nothing outside the
//    scoped process is affected.
//  - /proc/self/status (+ /proc/<own-pid>/status, task variants) is served
//    with TracerPid zeroed - the standard anti-debug check.
//  - /sys/fs/selinux/enforce is served as "1" - MuMu boots permissive and
//    the enforcing state is a first-line RASP check.
//  - /proc maps/mounts content filter tokens += kernelsu, trustme, hp15,
//    javahelper (KernelSU manager, injected SSL module, MuMu sidecars).
//
// Masks the emulator fingerprints that bundled ad SDKs - and AppDome-grade
// RASP inside protected games - probe outside the Java Build.* surface.
//
// Evidence base (MuMu 15 / MUMU15, June's Journey 4.15.6):
//   - the ROM's own cpuinfo bind-mount FAILS in the game process:
//     "nativebridge: Failed to bind-mount /system/etc/cpuinfo.x86_64.txt as
//     /proc/cpuinfo" -> every reader sees real Intel cpuinfo
//   - HP (MuMu game hook): "mAbi = x86_64"; ART: "Unexpected CPU variant
//     for x86: x86_64" -> uname/abilist/isa props all say x86
//   - 60 nemu*/nemud* props enumerate through __system_property_foreach
//     even with get/find hooked (v2.9.0 gap)
//   - com.mumu.* priv-app tmpfs mounts and houdini/libnb lines are visible
//     in /proc/{self,<pid>}/{mounts,mountinfo} and {maps,smaps}
//   - VMOSCloud (real ARM) passes AppDome because none of the above exist
//     there; v2.9.1 closes exactly that delta.
//
// v2.9.1 additions over v2.9.0:
//   - /proc CONTENT spoof engine: /proc/cpuinfo is served from a generated
//     kona (SM8350) AArch64 cpuinfo; /proc/{self,<pid>}/{maps,smaps} and
//     /proc/mounts, /proc/{self,<pid>}/{mounts,mountinfo,mountstats} are
//     re-served line-filtered (nemu/mumu/houdini/xposed/magisk/frida/...).
//     Both are delivered as a memfd returned by the open() family, so
//     fopen/fread, read, pread, lseek, mmap and std::ifstream all see the
//     clean content with zero per-read overhead and no fd bookkeeping.
//   - ABI props are REWRITTEN, not blanked: ro.*.product.cpu.abi(list),
//     ro.bionic.arch, ro.bionic.2nd_arch, ro.bionic.cpu_variant,
//     ro.dalvik.vm.isa.arm{,64}, ro.board.platform, ro.hardware now answer
//     with genuine kona values (blank = "prop missing" reads as tampering).
//   - __system_property_foreach: emulator props vanish from enumeration.
//   - __system_property_read_callback: sanitized too, so code holding a
//     cached prop_info* cannot bypass the get/find hooks.
//   - uname(2): machine x86_64/i386/i686 -> aarch64.
//   - File-existence rules extended: houdini / ndk_translation / libnb /
//     /system/lib{,64}/{arm,arm64,x86_64} trees + /com.mumu /com.nemu
//     priv-app trees. x86/arm64 ENOENT rules apply ONLY under /system,
//     /vendor, /apex, /odm, /product - never under /data/app/**, because
//     the game's own lib/x86_64/*.so files must stay visible or integrity
//     checks would flag the app itself as tampered.
//
// v2.9.2 fixes over v2.9.1 (CPU spoofing regression):
//   - MyPropGet() consulted ArmAbiValue() WITHOUT the g_anti_emu gate. The
//     anti-emu prop hook is installed LAST on __system_property_get (stage5b,
//     after InstallPropSpoofHooks), so it runs FIRST and short-circuited
//     ro.hardware -> "qcom", ro.board.platform -> "kona" and the
//     ro.product.cpu.abi* / ro.bionic.* / ro.dalvik.vm.isa.arm* props to
//     hardcoded arm64 values in EVERY process - even with the ANTI-EMU
//     toggle OFF. That shadowed hide_props.cpp (one stage earlier: it could
//     never win the chain) and broke the CPU profile's vendor value and the
//     abi toggle's mode-driven ABI props. The rewrite is now gated on
//     g_anti_emu; with the toggle OFF this whole layer is a pure
//     pass-through, byte-for-byte 2.8.4 behavior on every surface.
//   - /proc/cpuinfo ownership: while the CPU toggle is on, hide_fs.cpp's
//     profile engine (ServeSysfsSpoofFd / RewriteCpuinfoContent) stays the
//     single owner of /proc/cpuinfo, exactly as in 2.8.4 - the user's CPU
//     name / vendor / core layout wins over the static kona text. Anti-emu
//     only serves its generated cpuinfo when the CPU toggle is off.
//   - ArmAbiValue() defers ro.hardware to the CPU engine while
//     CpuSpoofActive() (hide_props spoofs it from the profile); the pure ABI
//     props stay anti-emu's while its toggle is on, per the documented
//     ownership split in spoofcore.kt.
//
// v2.9.0 history (kept): #include <jni.h> fix; MyFstatAt CALL_PREV casing;
// O_TMPFILE varargs composite test; dmi/goldfish/ranchu/vbox/geny/nemu/mumu
// path trees and prop substrings.
//
// Runtime-gated on g_anti_emu; the toggle is delivered from Kotlin via
// nativeSetAntiEmu(). Caller filter is the standard module one
// (CallerAllowHooks), which excludes Houdini / native-bridge libs so their
// own property reads stay raw and MuMu's injected helpers keep working.

#include "pas.h"

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
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

        // v2.9.4: root / privilege artifacts. ENOENT while ANTI-EMU is on.
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
        "/sbin/.magisk",
        "/sbin/magiskhide",
        "/sbin/magiskinit",
        "/sbin/magiskpolicy",
        "/system/bin/.ext/.su",
        "/system/etc/.has_su_daemon",
        "/system/etc/.installed_su_daemon",
        "/data/local/tmp/.su",

        // v2.9.5: writability-probe targets (classic root check: create a
        // file here and it proves the device is an unlocked/emulator image)
        "/data/local/tmp",
        "/debug_ramdisk",
        "/data/local",
    };
    for (const char* p : kExact) {
        if (strcmp(path, p) == 0) return true;
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
// /proc content spoof - detectors read the raw files, not only the props
// ---------------------------------------------------------------------------

enum ProcSpoofKind {
    kProcNone = 0,
    kProcCpuInfo = 1,
    kProcMaps = 2,
    kProcMounts = 3,
    kProcStatus = 4,          // v2.9.4: /proc self status, TracerPid zeroed
    kProcSelinuxEnforce = 5,  // v2.9.4: /sys/fs/selinux/enforce -> "1"
    kProcVersion = 6,         // v2.9.5: /proc/version, arch -> aarch64
};

// /proc/self/<leaf> or /proc/<pid-of-self>/<leaf>
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

// /proc/self/task/<tid>/<leaf> or /proc/<pid-of-self>/task/<tid>/<leaf>
// (any thread of this process shows this process' view)
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
        // v2.9.2: while the CPU toggle is on, hide_fs.cpp's profile engine
        // (ServeSysfsSpoofFd / RewriteCpuinfoContent) owns /proc/cpuinfo -
        // same single-owner behavior as 2.8.4. Deferring here means the
        // open() call falls through the bytehook chain into HideOpen /
        // HideFopen, which serve the user's CPU name / vendor / core
        // layout. Anti-emu only serves its generated kona cpuinfo when the
        // CPU toggle is off.
        if (CpuSpoofActive()) return kProcNone;
        return kProcCpuInfo;
    }
    if (strcmp(path, "/proc/mounts") == 0) return kProcMounts;
    // v2.9.4: own-process status (anti-debug TracerPid) and SELinux state.
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

// Raw syscalls for internal work: no PLT, no re-entry, invisible to every
// other hook (ours included).
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
        "goldfish", "ranchu", "vbox", "geny", "qemu",
        "xposed", "edxposed", "lsposed", "zygisk", "magisk", "riru",
        "frida", "gadget", "dobby", "sandhook", "whale",
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

// v2.9.4: raw full-file read for internal work (no PLT, no re-entry).
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
        if (out.size() > (16u << 20)) break;  // 16 MB sanity cap
    }
#if defined(__NR_close)
    syscall(__NR_close, fd);
#endif
    return true;
}

// v2.9.5: rewrite x86 arch strings in a /proc/version body. uname(2) is
// already patched (MyUname) but the version FILE carried the real host
// arch - a one-line emulator tell.
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

// v2.9.4: zero every TracerPid field in a /proc/<self>/status body.
static void ZeroTracerPid(std::string& s) {
    static const char kKey[] = "TracerPid:";
    size_t p = s.find(kKey);
    while (p != std::string::npos) {
        size_t q = p + sizeof(kKey) - 1;
        while (q < s.size() && (s[q] == ' ' || s[q] == '\t')) q++;
        size_t d = q;
        while (d < s.size() && s[d] >= '0' && s[d] <= '9') d++;
        if (d > q) s.replace(q, d - q, "0");
        p = s.find(kKey, p + sizeof(kKey) - 1);
    }
}

static bool BuildFiltered(const char* path, std::string& out) {
    std::string all;
    if (!RawReadAll(path, all)) return false;
    out.clear();
    size_t start = 0;
    while (start < all.size()) {
        size_t nl = all.find('\n', start);
        size_t next = (nl == std::string::npos) ? all.size() : nl + 1;
        if (!LineHasToken(all.c_str() + start, next - start)) {
            out.append(all, start, next - start);
        }
        start = next;
    }
    return !out.empty();
}

// Genuine kona (Samsung SM-G991B, Snapdragon 888) style AArch64 cpuinfo.
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
        ZeroTracerPid(content);
    } else if (kind == kProcVersion) {
        if (!RawReadAll(path, content)) return -1;
        RewriteVersionArch(content);
    } else {
        if (!BuildFiltered(path, content)) return -1;
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
// open family - every entry point the SDKs use for File.exists() /
// FileInputStream / fopen / ifstream
// ---------------------------------------------------------------------------

static int MyOpen(const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
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
// property filter - Appsflyer / Mintegral / AppDome-grade probes
// ---------------------------------------------------------------------------

// Props whose value on MuMu is x86 but whose value on a genuine kona
// (SM-G991B) device is ARM. Rewritten, not blanked: a blank reads as
// "property missing", which is itself tamper evidence on a Samsung build.
//
// v2.9.2: the CPU toggle's profile engine owns ro.hardware while
// CpuSpoofActive() - hide_props.cpp spoofs it from the user's profile
// (CpuSpoofHardware()). We defer so the profile value wins; when the CPU
// toggle is off we still rewrite to the kona placeholder. The pure ABI
// props below are NOT deferred: the anti-emu ARM story needs them, and the
// abi toggle only owns them when anti-emu is off (documented in
// spoofcore.kt - "the abi toggle owns the Java Build fields, anti-emu owns
// the native side").
static const char* ArmAbiValue(const char* name) {
    static const char kAbi64[] = "arm64-v8a";
    static const char kAbiList[] = "arm64-v8a,armeabi-v7a,armeabi";
    static const char kAbiList32[] = "armeabi-v7a,armeabi";
    const size_t n = strlen(name);
    if (n <= 3 || strncmp(name, "ro.", 3) != 0) return nullptr;
    // v2.9.5: the board/platform keys defer to the CPU profile too - the
    // "kona" placeholder contradicted the Exynos identity the rest of the
    // module presents (hide_props now serves exynos2100 for them).
    if (CpuSpoofActive() && (strcmp(name, "ro.hardware") == 0 ||
                             strcmp(name, "ro.board.platform") == 0 ||
                             strcmp(name, "ro.product.board") == 0)) {
        return nullptr;
    }
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
    if (strcmp(name, "ro.board.platform") == 0) return "kona";
    if (strcmp(name, "ro.hardware") == 0) return "qcom";
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
    // v2.9.2: gate on g_anti_emu BEFORE ArmAbiValue. In 2.9.1 the hardcoded
    // kona values leaked into every process even with the ANTI-EMU toggle
    // OFF, shadowing hide_props.cpp (installed one stage earlier, so our
    // wrapper ran first in the bytehook chain) and breaking the CPU
    // profile's ro.hardware plus the abi toggle's mode-driven ABI props.
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

    Log("native: anti-emu hooks installed fs=%d/%d prop=%d/4 (runtime-gated)",
        okFs, (int)(sizeof(kFsSpecs) / sizeof(kFsSpecs[0])), okProp);
}

}  // namespace pas

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetAntiEmu(JNIEnv* env, jobject thiz, jboolean on) {
    (void)env;
    (void)thiz;
    pas::SetAntiEmu(on == JNI_TRUE);
}
