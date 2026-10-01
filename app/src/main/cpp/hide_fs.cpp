#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "pas.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>

#include "bytehook.h"

namespace pas {

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

// ---------------------------------------------------------------------------
// watched files: /proc/net/* whose content must be filtered.
// Filtering is done by materializing a filtered copy in a memfd at open()
// time - no read/pread/lseek/dup/close interception is needed at all.
//
// The kernel accepts several aliases for the same files; scanners use them to
// dodge naive filters. We treat them all as watched:
//   /proc/net/X  /proc/self/net/X  /proc/thread-self/net/X  /proc/<pid>/net/X
// ---------------------------------------------------------------------------

enum class WatchedFile {
    None,
    Tcp,   // tcp / tcp6
    Udp,   // udp / udp6
    Misc,  // dev / route / if_inet6 / ipv6_route / arp
};

static WatchedFile ResolveWatchedFile(const char* path) {
    if (!path) return WatchedFile::None;
    static const char kProc[] = "/proc/";
    static const char kNet[] = "net/";
    if (strncmp(path, kProc, sizeof(kProc) - 1) != 0) return WatchedFile::None;
    const char* rest = path + sizeof(kProc) - 1;
    const char* netPart = nullptr;
    if (strncmp(rest, kNet, sizeof(kNet) - 1) == 0) {
        netPart = rest + sizeof(kNet) - 1;
    } else if (strncmp(rest, "self/", 5) == 0) {
        rest += 5;
        if (strncmp(rest, kNet, sizeof(kNet) - 1) == 0) netPart = rest + sizeof(kNet) - 1;
    } else if (strncmp(rest, "thread-self/", 12) == 0) {
        rest += 12;
        if (strncmp(rest, kNet, sizeof(kNet) - 1) == 0) netPart = rest + sizeof(kNet) - 1;
    } else {
        // /proc/<pid>/net/...
        const char* slash = strchr(rest, '/');
        if (slash && slash > rest && strncmp(slash + 1, kNet, sizeof(kNet) - 1) == 0) {
            bool digits = true;
            for (const char* c = rest; c < slash; c++) {
                if (*c < '0' || *c > '9') {
                    digits = false;
                    break;
                }
            }
            if (digits) netPart = slash + 1 + sizeof(kNet) - 1;
        }
    }
    if (!netPart) return WatchedFile::None;
    if (strcmp(netPart, "tcp") == 0 || strcmp(netPart, "tcp6") == 0) return WatchedFile::Tcp;
    if (strcmp(netPart, "udp") == 0 || strcmp(netPart, "udp6") == 0) return WatchedFile::Udp;
    if (strcmp(netPart, "dev") == 0 || strcmp(netPart, "route") == 0 ||
        strcmp(netPart, "if_inet6") == 0 || strcmp(netPart, "ipv6_route") == 0 ||
        strcmp(netPart, "arp") == 0) {
        return WatchedFile::Misc;
    }
    return WatchedFile::None;
}

// ---------------------------------------------------------------------------
// Special files: a tiny allow/deny layer used together with the content
// filters. /proc/net/fib_trie is denied with ENOENT (the checker's own code
// treats that as "not available on this kernel"); /sys/fs/selinux/enforce is
// served as "1\n" so the process sees an enforcing kernel.
// ---------------------------------------------------------------------------

enum class SpecialAction { None, NotFound, EnforceOne };

static SpecialAction ResolveSpecial(const char* path) {
    if (!path) return SpecialAction::None;
    if (strcmp(path, "/proc/net/fib_trie") == 0 ||
        strcmp(path, "/proc/self/net/fib_trie") == 0) {
        return SpecialAction::NotFound;
    }
    if (strcmp(path, "/sys/fs/selinux/enforce") == 0) {
        return SpecialAction::EnforceOne;
    }
    return SpecialAction::None;
}

static int CreateMemfdWith(const char* data, size_t len, int flags) {
#ifdef SYS_memfd_create
    int mfd = (int)syscall(SYS_memfd_create, "pas-special",
                           (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0);
#else
    int mfd = -1;
#endif
    if (mfd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = syscall(SYS_write, mfd, data + off, len - off);
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

// ---------------------------------------------------------------------------
// recon logging (diagnostics): when enabled (module GUI toggle), suspicious
// probes made by the scoped app are written to the module log so its detection
// surface can be mapped. Pure logging - no behavior changes; hard-capped so a
// probing loop cannot flood the log.
// ---------------------------------------------------------------------------

static volatile bool g_recon = false;
static volatile int g_recon_emitted = 0;
static volatile bool g_recon_capped = false;

void SetRecon(bool on) {
    g_recon = on;
    Log("native: recon logging %s", on ? "on" : "off");
}

bool ReconEnabled() {
    return g_recon;
}

static const char* const kReconTokens[] = {
    "magisk", "kernelsu", "ksu", "supersu", "superuser", "zygisk", "lsposed", "lspd",
    "shamiko", "riru", "xposed", "edxposed", "frida", "substrate", "gadget", "data/adb",
    "busybox", "selinux", "magiskpolicy", "qemu", "goldfish", "ranchu", "emulator",
    "bluestacks", "vmos", "mumu", "nemu", "netease", "houdini", "nativebridge",
    "libndk", "waydroid", "genymotion", "cuttlefish", "windvane", "self/maps",
    "self/smaps", "self/status", "self/task", "self/cmdline", "self/environ", "self/fd",
    "mountinfo", "/proc/mounts", "proc/net", "tracerpid", "cpuinfo", "cpufreq", "soc0",
    "midr", "identification", "/su", " su", "debuggable", "ro.secure", "ptrace",
    "zygisk-module", "ro.boot", "ro.hardware", "topology", "related_cpus",
    "affected_cpus", "core_id", "cluster", "devicetree", "compatible", "serial",
    "board", "platform", "vendor_id", "bogomips", "physical_package",
};

static bool ReconHit(const char* s) {
    if (s == nullptr || s[0] == '\0') return false;
    char low[192];
    size_t m = 0;
    for (; s[m] != '\0' && m < sizeof(low) - 1; m++) {
        char c = s[m];
        low[m] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    low[m] = '\0';
    for (size_t i = 0; i < sizeof(kReconTokens) / sizeof(kReconTokens[0]); i++) {
        if (strstr(low, kReconTokens[i]) != nullptr) return true;
    }
    return false;
}

void ReconNote(const char* op, const char* detail, long res) {
    if (!g_recon || detail == nullptr) return;
    if (!ReconHit(detail)) return;
    if (g_recon_emitted >= 1500) {
        if (!g_recon_capped) {
            g_recon_capped = true;
            Log("native: recon: emission cap reached (further probes suppressed)");
        }
        return;
    }
    g_recon_emitted++;
    Log("native: recon: %s %s -> %ld", op, detail, res);
}

static void ReconNoteN(const char* op, const char* buf, size_t n, long res) {
    if (!g_recon || buf == nullptr || n == 0) return;
    char tmp[192];
    size_t m = n > sizeof(tmp) - 1 ? sizeof(tmp) - 1 : n;
    for (size_t i = 0; i < m; i++) {
        char c = buf[i];
        tmp[i] = (c == '\n' || c == '\r' || c == '\0') ? ' ' : c;
    }
    tmp[m] = '\0';
    ReconNote(op, tmp, res);
}

static void ReconExec(char* const argv[], const char* path) {
    if (!g_recon) return;
    char buf[192];
    size_t off = 0;
    buf[0] = '\0';
    if (path != nullptr) {
        snprintf(buf, sizeof(buf), "%s", path);
        off = strlen(buf);
    }
    if (argv != nullptr) {
        for (int i = 0; argv[i] != nullptr && i < 8; i++) {
            size_t al = strlen(argv[i]);
            if (off + al + 2 >= sizeof(buf)) break;
            buf[off++] = ' ';
            memcpy(buf + off, argv[i], al);
            off += al;
            buf[off] = '\0';
        }
    }
    ReconNote("exec", buf, 0);
}

// Raw build.prop-style files that integrity checkers read directly. When the
// SDK/ABI spoof is active these are served with the spoof keys rewritten, so
// the file view matches the hooked properties.
static bool IsPropsFile(const char* path) {
    if (!path) return false;
    static const char* const kProps[] = {
        "/system/build.prop",
        "/vendor/build.prop",
        "/odm/etc/build.prop",
        "/product/build.prop",
        "/system_ext/build.prop",
        "/system/etc/prop.default",
    };
    for (const char* k : kProps) {
        if (strcmp(path, k) == 0) return true;
    }
    return false;
}

static void RewritePropsContent(const std::string& raw, std::string* out) {
    size_t i = 0;
    while (i < raw.size()) {
        size_t j = raw.find('\n', i);
        j = (j == std::string::npos) ? raw.size() : j + 1;
        std::string line(raw, i, j - i);
        const char* c = line.c_str();
        const char* p = c;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '#' && *p != '\0' && *p != '\r' && *p != '\n') {
            const char* eq = strchr(p, '=');
            if (eq != nullptr && eq > p) {
                char key[128];
                size_t kl = (size_t)(eq - p);
                if (kl < sizeof(key)) {
                    memcpy(key, p, kl);
                    key[kl] = '\0';
                    // trim trailing spaces on key
                    while (kl > 0 && (key[kl - 1] == ' ' || key[kl - 1] == '\t')) key[--kl] = '\0';
                    char repl[128];
                    if (SpoofRewritePropsLine(key, eq + 1, repl, sizeof(repl))) {
                        out->append(key);
                        out->push_back('=');
                        out->append(repl);
                        out->push_back('\n');
                        i = j;
                        continue;
                    }
                }
            }
        }
        out->append(line);
        i = j;
    }
}

static bool ReadWholeFile(const char* path, std::string* out);

// /proc/cpuinfo rewrite: each per-core block is rebuilt in the kernel's ARM
// style for the selected CPU (model string, BogoMIPS, ARM feature list and
// CPU implementer/architecture/variant/part/revision), so hardware-info
// readers see a coherent ARM device instead of the host's x86 traces.
static bool CpuinfoKeyMatch(const char* line, const char* key) {
    size_t kl = strlen(key);
    if (strncmp(line, key, kl) != 0) return false;
    const char* p = line + kl;
    if (*p != ' ' && *p != '\t' && *p != ':') return false;
    while (*p == ' ' || *p == '\t') p++;
    return *p == ':';
}

static void RewriteCpuinfoContent(const std::string& raw, std::string* out) {
    const std::string model = CpuSpoofCpuinfoModel();
    const std::string features = CpuSpoofFeatures();
    const std::string part = CpuSpoofPart();
    // Keep everything before the first per-core block as is.
    size_t first = std::string::npos;
    {
        size_t p = 0;
        while (p < raw.size()) {
            size_t e = raw.find('\n', p);
            e = (e == std::string::npos) ? raw.size() : e + 1;
            if (CpuinfoKeyMatch(raw.c_str() + p, "processor") && e > p) {
                first = p;
                break;
            }
            p = e;
        }
    }
    if (first == std::string::npos) {
        out->append(raw);
        return;
    }
    out->append(raw, 0, first);
    size_t p = first;
    while (p < raw.size()) {
        size_t e = raw.find('\n', p);
        e = (e == std::string::npos) ? raw.size() : e + 1;
        std::string line(raw, p, e - p);
        if (!CpuinfoKeyMatch(line.c_str(), "processor")) {
            // Hardware/Revision/Serial rows are replaced by the authentic
            // ARM tail appended after the per-core blocks.
            if (CpuinfoKeyMatch(line.c_str(), "Hardware") ||
                CpuinfoKeyMatch(line.c_str(), "Revision") ||
                CpuinfoKeyMatch(line.c_str(), "Serial")) {
                p = e;
                continue;
            }
            out->append(line);
            p = e;
            continue;
        }
        // Extract the core number after the colon.
        std::string num;
        {
            const char* c = line.c_str();
            const char* colon = strchr(c, ':');
            if (colon) {
                colon++;
                while (*colon == ' ' || *colon == '\t') colon++;
                while (*colon && *colon != '\n' && *colon != '\r') num.push_back(*colon++);
            }
            if (num.empty()) num = "0";
        }
        out->append("processor\t: ");
        out->append(num);
        out->push_back('\n');
        out->append("model name\t: ");
        out->append(model);
        out->push_back('\n');
        out->append("BogoMIPS\t: 52.00\n");
        out->append("Features\t: ");
        out->append(features);
        out->push_back('\n');
        out->append("CPU implementer\t: 0x41\n");
        out->append("CPU architecture\t: 8\n");
        out->append("CPU variant\t: 0x0\n");
        out->append("CPU part\t: ");
        out->append(part);
        out->push_back('\n');
        out->append("CPU revision\t: 1\n");
        // Skip the rest of the block up to the following blank line or the
        // next core header.
        p = e;
        while (p < raw.size()) {
            size_t e2 = raw.find('\n', p);
            e2 = (e2 == std::string::npos) ? raw.size() : e2 + 1;
            bool blank = true;
            for (size_t k = p; k < e2; k++) {
                char ch = raw[k];
                if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
                    blank = false;
                    break;
                }
            }
            if (blank) {
                out->push_back('\n');
                p = e2;
                break;
            }
            if (CpuinfoKeyMatch(raw.c_str() + p, "processor")) break;
            p = e2;
        }
    }
    // Authentic ARM tail rows (Samsung-style Hardware string + revision and
    // serial placeholders), so hardware-info readers that inspect the tail
    // section stay consistent with the spoofed model too.
    const std::string hwLine = CpuSpoofHwLine();
    if (CpuSpoofActive() && !hwLine.empty()) {
        out->push_back('\n');
        out->append("Hardware\t: ");
        out->append(hwLine);
        out->push_back('\n');
        out->append("Revision\t: 0000\n");
        out->append("Serial\t\t: 0000000000000000\n");
    }
}

// cpufreq min/max mirrors: served with the selected CPU's clock range so
// frequency rows match the spoofed model (kHz values, same format as sysfs).
static bool CpuFreqSpoofValue(const char* path, char* out, size_t cap) {
    if (CpuSpoofMinKHz() <= 0 || CpuSpoofMaxKHz() <= 0) return false;
    if (strncmp(path, "/sys/devices/system/cpu/", 24) != 0) return false;
    const char* p = strstr(path, "/cpufreq/");
    if (!p) return false;
    const char* leaf = p + 9;
    if (*leaf == '\0' || strchr(leaf, '/') != nullptr) return false;
    int v;
    if (strcmp(leaf, "cpuinfo_min_freq") == 0 || strcmp(leaf, "scaling_min_freq") == 0) {
        v = CpuSpoofMinKHz();
    } else if (strcmp(leaf, "cpuinfo_max_freq") == 0 || strcmp(leaf, "scaling_max_freq") == 0) {
        v = CpuSpoofMaxKHz();
    } else {
        return false;
    }
    snprintf(out, cap, "%d\n", v);
    return true;
}

// Returns true when the call was fully handled by the special layer.
// On NotFound: errno=ENOENT, *fdOut=-1. On EnforceOne: *fdOut is a memfd or -1.
static bool HandleSpecialOpen(const char* path, int flags, int* fdOut) {
    SpecialAction sp = ResolveSpecial(path);
    if (sp == SpecialAction::None) {
        // build.prop-style files: served with the spoof keys rewritten so that
        // anything reading the raw prop files sees the same values as the
        // hooked properties (integrity checkers cross-check these).
        if (SpoofActive() && IsPropsFile(path) && (flags & O_ACCMODE) == O_RDONLY) {
            std::string raw;
            if (!ReadWholeFile(path, &raw)) return false;  // real error wins
            std::string out;
            RewritePropsContent(raw, &out);
            int mfd = CreateMemfdWith(out.data(), out.size(), flags);
            if (mfd < 0) return false;
            *fdOut = mfd;
            return true;
        }
        // /proc/cpuinfo: served as the ARM view of the selected CPU so
        // hardware-info readers see a coherent ARM device.
        if (CpuSpoofActive() && strcmp(path, "/proc/cpuinfo") == 0 &&
            (flags & O_ACCMODE) == O_RDONLY) {
            std::string raw;
            if (!ReadWholeFile(path, &raw)) return false;
            std::string out;
            RewriteCpuinfoContent(raw, &out);
            int mfd = CreateMemfdWith(out.data(), out.size(), flags);
            if (mfd < 0) return false;
            Log("native: cpuinfo served (ARM view)");
            *fdOut = mfd;
            return true;
        }
        // cpufreq min/max: mirrored with the selected CPU's clock range.
        if (CpuSpoofActive() && (flags & O_ACCMODE) == O_RDONLY) {
            char val[32];
            if (CpuFreqSpoofValue(path, val, sizeof(val))) {
                int mfd = CreateMemfdWith(val, strlen(val), flags);
                if (mfd >= 0) {
                    *fdOut = mfd;
                    return true;
                }
            }
        }
        return false;
    }
    if ((flags & O_ACCMODE) != O_RDONLY) return false;
    if (sp == SpecialAction::NotFound) {
        errno = ENOENT;
        *fdOut = -1;
        return true;
    }
    *fdOut = CreateMemfdWith("1\n", 2, flags);
    return true;
}

static bool ReadWholeFile(const char* path, std::string* out) {
#ifdef SYS_openat
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
#else
    int fd = (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
#endif
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
        if (out->size() > (4u << 20)) break;
    }
    syscall(SYS_close, fd);
    return true;
}

static const char* SkipWs(const char* q) {
    while (*q == ' ' || *q == '\t') q++;
    return q;
}

static const char* SkipToken(const char* q) {
    while (*q && *q != ' ' && *q != '\t') q++;
    return q;
}

static bool HexEqCI(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 32);
        if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 32);
        if (ca != cb) return false;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

// Mirrors the checker's "local listeners" parser: a listener row bound to a
// loopback or wildcard address on a port >= 1024. tcp: LISTEN (0A);
// udp: bound rows (07/0A).
static bool IsLoopbackListenerLine(const char* line, bool tcp) {
    if (!line) return false;
    const char* p = SkipWs(line);
    p = SkipToken(p);  // sl
    p = SkipWs(p);
    const char* local = p;
    p = SkipToken(p);
    size_t localLen = (size_t)(p - local);
    p = SkipWs(p);
    p = SkipToken(p);  // remote
    p = SkipWs(p);
    const char* st = p;
    p = SkipToken(p);
    size_t stLen = (size_t)(p - st);
    if (stLen != 2) return false;
    bool listening;
    if (tcp) {
        listening = (st[0] == '0' && (st[1] == 'A' || st[1] == 'a'));
    } else {
        listening = (st[0] == '0' && (st[1] == '7' || st[1] == 'A' || st[1] == 'a'));
    }
    if (!listening) return false;
    const char* colon = nullptr;
    for (size_t i = 0; i < localLen; i++) {
        if (local[i] == ':') colon = local + i;
    }
    if (!colon || colon == local) return false;
    unsigned long port = 0;
    for (const char* c = colon + 1; c < local + localLen; c++) {
        int v;
        if (*c >= '0' && *c <= '9') v = *c - '0';
        else if (*c >= 'A' && *c <= 'F') v = *c - 'A' + 10;
        else if (*c >= 'a' && *c <= 'f') v = *c - 'a' + 10;
        else return false;
        port = port * 16 + (unsigned long)v;
        if (port > 0xFFFF) return false;
    }
    if (port < 1024) return false;
    char host[33];
    size_t hl = (size_t)(colon - local);
    if (hl == 0 || hl > 32) return false;
    memcpy(host, local, hl);
    host[hl] = '\0';
    if (hl == 8) return HexEqCI(host, "00000000") || HexEqCI(host, "0100007F");
    if (hl == 32) {
        return HexEqCI(host, "00000000000000000000000000000000") ||
               HexEqCI(host, "00000000000000000000000001000000");
    }
    return false;
}

static void FilterLines(const std::string& raw, WatchedFile kind, std::string* out) {
    bool tcpLike = (kind == WatchedFile::Tcp || kind == WatchedFile::Udp);
    size_t i = 0;
    while (i < raw.size()) {
        size_t j = raw.find('\n', i);
        j = (j == std::string::npos) ? raw.size() : j + 1;
        std::string line(raw, i, j - i);
        const char* c = line.c_str();
        bool blocked = LineContainsHiddenName(c);
        if (!blocked && tcpLike) blocked = LineContainsProxyPortToken(c);
        if (!blocked && kind == WatchedFile::Tcp) blocked = IsLoopbackListenerLine(c, true);
        if (!blocked && kind == WatchedFile::Udp) blocked = IsLoopbackListenerLine(c, false);
        if (!blocked) out->append(line);
        i = j;
    }
}

// Returns a filtered memfd, -1 for a real error, or -2 to fall through to the
// original function.
static int CreateFilteredFd(const char* path, int flags) {
    WatchedFile kind = ResolveWatchedFile(path);
    if (kind == WatchedFile::None) return -2;
    if ((flags & O_ACCMODE) != O_RDONLY) return -2;
    std::string raw;
    if (!ReadWholeFile(path, &raw)) return -2;
    std::string out;
    FilterLines(raw, kind, &out);
#ifdef SYS_memfd_create
    int mfd = (int)syscall(SYS_memfd_create, "pas-file",
                           (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0);
#else
    int mfd = -1;
#endif
    if (mfd < 0) return -2;
    ssize_t total = (ssize_t)out.size();
    ssize_t off = 0;
    while (off < total) {
        ssize_t w = syscall(SYS_write, mfd, out.data() + off, (size_t)(total - off));
        if (w < 0) {
            if (errno == EINTR) continue;
            syscall(SYS_close, mfd);
            return -2;
        }
        off += w;
    }
    syscall(SYS_lseek, mfd, 0, SEEK_SET);
    return mfd;
}

// ---------------------------------------------------------------------------
// open / openat / fopen
// ---------------------------------------------------------------------------

int HideOpen(const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("open", path, (long)flags);
    mode_t mode = 0;
#ifdef O_TMPFILE
    if (flags & (O_CREAT | O_TMPFILE)) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    {
        int sfd = -2;
        if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
    }
    int mfd = CreateFilteredFd(path, flags);
    if (mfd >= 0) return mfd;
    return BYTEHOOK_CALL_PREV(HideOpen, path, flags, mode);
}

int HideOpen64(const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("open", path, (long)flags);
    mode_t mode = 0;
#ifdef O_TMPFILE
    if (flags & (O_CREAT | O_TMPFILE)) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    {
        int sfd = -2;
        if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
    }
    int mfd = CreateFilteredFd(path, flags);
    if (mfd >= 0) return mfd;
    return BYTEHOOK_CALL_PREV(HideOpen64, path, flags, mode);
}

int HideOpen2(const char* path, int flags) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("open", path, (long)flags);
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    {
        int sfd = -2;
        if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
    }
    int mfd = CreateFilteredFd(path, flags);
    if (mfd >= 0) return mfd;
    return BYTEHOOK_CALL_PREV(HideOpen2, path, flags);
}

int HideOpenAt(int dirfd, const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("openat", path, (long)flags);
    mode_t mode = 0;
#ifdef O_TMPFILE
    if (flags & (O_CREAT | O_TMPFILE)) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path && path[0] == '/') {
        if (IsHiddenPath(path)) {
            errno = ENOENT;
            return -1;
        }
        {
            int sfd = -2;
            if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
        }
        int mfd = CreateFilteredFd(path, flags);
        if (mfd >= 0) return mfd;
    }
    return BYTEHOOK_CALL_PREV(HideOpenAt, dirfd, path, flags, mode);
}

int HideOpenAt64(int dirfd, const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("openat", path, (long)flags);
    mode_t mode = 0;
#ifdef O_TMPFILE
    if (flags & (O_CREAT | O_TMPFILE)) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path && path[0] == '/') {
        if (IsHiddenPath(path)) {
            errno = ENOENT;
            return -1;
        }
        {
            int sfd = -2;
            if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
        }
        int mfd = CreateFilteredFd(path, flags);
        if (mfd >= 0) return mfd;
    }
    return BYTEHOOK_CALL_PREV(HideOpenAt64, dirfd, path, flags, mode);
}

int HideOpenAt2(int dirfd, const char* path, int flags) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("openat", path, (long)flags);
    if (path && path[0] == '/') {
        if (IsHiddenPath(path)) {
            errno = ENOENT;
            return -1;
        }
        {
            int sfd = -2;
            if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
        }
        int mfd = CreateFilteredFd(path, flags);
        if (mfd >= 0) return mfd;
    }
    return BYTEHOOK_CALL_PREV(HideOpenAt2, dirfd, path, flags);
}

FILE* HideFopen(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("fopen", path, 0);
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return nullptr;
    }
    if (mode && mode[0] == 'r' && strchr(mode, '+') == nullptr) {
        {
            int sfd = -2;
            if (HandleSpecialOpen(path, O_RDONLY, &sfd)) {
                if (sfd < 0) return nullptr;
                FILE* f = fdopen(sfd, "r");
                if (f) return f;
                syscall(SYS_close, sfd);
            }
        }
        int mfd = CreateFilteredFd(path, O_RDONLY);
        if (mfd >= 0) {
            FILE* f = fdopen(mfd, "r");
            if (f) return f;
            syscall(SYS_close, mfd);
        }
    }
    return BYTEHOOK_CALL_PREV(HideFopen, path, mode);
}

FILE* HideFopen64(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("fopen", path, 0);
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return nullptr;
    }
    if (mode && mode[0] == 'r' && strchr(mode, '+') == nullptr) {
        {
            int sfd = -2;
            if (HandleSpecialOpen(path, O_RDONLY, &sfd)) {
                if (sfd < 0) return nullptr;
                FILE* f = fdopen(sfd, "r");
                if (f) return f;
                syscall(SYS_close, sfd);
            }
        }
        int mfd = CreateFilteredFd(path, O_RDONLY);
        if (mfd >= 0) {
            FILE* f = fdopen(mfd, "r");
            if (f) return f;
            syscall(SYS_close, mfd);
        }
    }
    return BYTEHOOK_CALL_PREV(HideFopen64, path, mode);
}

// ---------------------------------------------------------------------------
// getdents64: drop VPN-named entries from every directory listing.
// (Stateless: entry names matching VPN interface patterns are simply omitted.)
// ---------------------------------------------------------------------------

struct PasLinuxDirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

ssize_t HideGetDents64(int fd, void* dirp, size_t count) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t total = BYTEHOOK_CALL_PREV(HideGetDents64, fd, dirp, count);
    if (total <= 0) return total;
    char* base = (char*)dirp;
    char* p = base;
    char* end = base + total;
    char* out = base;
    while (p + sizeof(PasLinuxDirent64) <= end) {
        auto* d = (PasLinuxDirent64*)p;
        size_t rl = d->d_reclen;
        if (rl < sizeof(PasLinuxDirent64) || p + rl > end) break;
        if (!IsHiddenIfaceName(d->d_name)) {
            if (out != p) memmove(out, p, rl);
            out += rl;
        }
        p += rl;
    }
    return (ssize_t)(out - base);
}

// ---------------------------------------------------------------------------
// access / stat
// ---------------------------------------------------------------------------

int HideAccess(const char* path, int mode) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("access", path, (long)mode);
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideAccess, path, mode);
}

int HideFAccessAt(int dirfd, const char* path, int mode, int flags) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("faccessat", path, (long)mode);
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideFAccessAt, dirfd, path, mode, flags);
}

int HideStat(const char* path, struct stat* buf) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("stat", path, 0);
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideStat, path, buf);
}

int HideLstat(const char* path, struct stat* buf) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("lstat", path, 0);
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideLstat, path, buf);
}

int HideFStatAt(int dirfd, const char* path, struct stat* buf, int flags) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("fstatat", path, 0);
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideFStatAt, dirfd, path, buf, flags);
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CPU: subprocess readers. Tools spawned via exec* / posix_spawn (for example
// `cat /proc/cpuinfo`) would otherwise read the host file; the exec arguments
// are rewritten to point at a pre-rendered copy so child processes observe
// the same ARM view as the process itself. Active together with the CPU spoof
// only, and fails safe (unmodified exec) whenever the copy cannot be written.
// ---------------------------------------------------------------------------

static std::string g_fake_cpuinfo_path;
static bool g_fake_cpuinfo_probed = false;

static std::string BuildFakeCpuinfoPath() {
    char cmd[256] = {0};
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/cmdline", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return std::string();
    ssize_t n = syscall(SYS_read, fd, cmd, sizeof(cmd) - 1);
    syscall(SYS_close, fd);
    if (n <= 0) return std::string();
    cmd[n] = '\0';
    std::string pkg(cmd);
    size_t colon = pkg.find(':');
    if (colon != std::string::npos) pkg = pkg.substr(0, colon);
    if (pkg.empty()) return std::string();
    static const char* const kBases[] = {"/data/user/0/", "/data/data/"};
    for (const char* b : kBases) {
        std::string dir = std::string(b) + pkg + "/cache";
#ifdef __NR_faccessat
        if (syscall(__NR_faccessat, AT_FDCWD, dir.c_str(), W_OK, 0) == 0) {
            return dir + "/.pas_tmp";
        }
#else
        return dir + "/.pas_tmp";
#endif
    }
    return std::string();
}

static const std::string& FakeCpuinfoPath() {
    if (!g_fake_cpuinfo_probed) {
        g_fake_cpuinfo_probed = true;
        g_fake_cpuinfo_path = BuildFakeCpuinfoPath();
        if (g_fake_cpuinfo_path.empty()) {
            Log("native: cpuinfo redirect target unavailable");
        } else {
            Log("native: cpuinfo redirect target %s", g_fake_cpuinfo_path.c_str());
        }
    }
    return g_fake_cpuinfo_path;
}

static bool WriteFakeCpuinfo(const char* path) {
    std::string raw;
    if (!ReadWholeFile("/proc/cpuinfo", &raw)) {
        Log("native: cpuinfo copy read failed");
        return false;
    }
    std::string out;
    RewriteCpuinfoContent(raw, &out);
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          0600);
    if (fd < 0) {
        Log("native: cpuinfo copy write failed (errno=%d)", errno);
        return false;
    }
    size_t off = 0;
    while (off < out.size()) {
        ssize_t w = syscall(SYS_write, fd, out.data() + off, out.size() - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            syscall(SYS_close, fd);
            return false;
        }
        off += (size_t)w;
    }
    syscall(SYS_close, fd);
    return true;
}

static std::string ReplaceCpuinfoRefs(const char* in, const std::string& fake) {
    static const char kRef[] = "/proc/cpuinfo";
    std::string out;
    if (!in) return out;
    const char* p = in;
    for (;;) {
        const char* hit = strstr(p, kRef);
        if (hit == nullptr) {
            out.append(p);
            break;
        }
        out.append(p, (size_t)(hit - p));
        out.append(fake);
        p = hit + sizeof(kRef) - 1;
    }
    return out;
}

static bool RewriteArgvForCpuinfo(char* const in[], char*** outArgv, int* outCount) {
    if (!CpuSpoofActive() || !in) return false;
    const std::string& fake = FakeCpuinfoPath();
    if (fake.empty()) return false;
    int n = 0;
    while (in[n] != nullptr) n++;
    if (n == 0 || n > 256) return false;
    bool any = false;
    for (int i = 0; i < n; i++) {
        if (in[i] != nullptr && strstr(in[i], "/proc/cpuinfo") != nullptr) {
            any = true;
            break;
        }
    }
    if (!any) return false;
    if (!WriteFakeCpuinfo(fake.c_str())) return false;
    char** na = (char**)calloc((size_t)n + 1, sizeof(char*));
    if (!na) return false;
    for (int i = 0; i < n; i++) {
        std::string s = ReplaceCpuinfoRefs(in[i], fake);
        na[i] = strdup(s.c_str());
        if (!na[i]) {
            for (int k = 0; k < i; k++) free(na[k]);
            free(na);
            return false;
        }
    }
    na[n] = nullptr;
    *outArgv = na;
    *outCount = n;
    return true;
}

static void FreeRewrittenArgv(char** argv, int n) {
    if (!argv) return;
    for (int i = 0; i < n; i++) free(argv[i]);
    free(argv);
}

static int MyExecVe(const char* path, char* const argv[], char* const envp[]) {
    BYTEHOOK_STACK_SCOPE();
    ReconExec(argv, path);
    char** na = nullptr;
    int n = 0;
    if (RewriteArgvForCpuinfo(argv, &na, &n)) {
        Log("native: exec redirect (cpuinfo) via %s", path ? path : "?");
        int rc = BYTEHOOK_CALL_PREV(MyExecVe, path, na, envp);
        FreeRewrittenArgv(na, n);
        return rc;
    }
    return BYTEHOOK_CALL_PREV(MyExecVe, path, argv, envp);
}

static int MyExecV(const char* path, char* const argv[]) {
    BYTEHOOK_STACK_SCOPE();
    ReconExec(argv, path);
    char** na = nullptr;
    int n = 0;
    if (RewriteArgvForCpuinfo(argv, &na, &n)) {
        Log("native: exec redirect (cpuinfo) via %s", path ? path : "?");
        int rc = BYTEHOOK_CALL_PREV(MyExecV, path, na);
        FreeRewrittenArgv(na, n);
        return rc;
    }
    return BYTEHOOK_CALL_PREV(MyExecV, path, argv);
}

static int MyExecVp(const char* file, char* const argv[]) {
    BYTEHOOK_STACK_SCOPE();
    ReconExec(argv, file);
    char** na = nullptr;
    int n = 0;
    if (RewriteArgvForCpuinfo(argv, &na, &n)) {
        Log("native: exec redirect (cpuinfo) via %s", file ? file : "?");
        int rc = BYTEHOOK_CALL_PREV(MyExecVp, file, na);
        FreeRewrittenArgv(na, n);
        return rc;
    }
    return BYTEHOOK_CALL_PREV(MyExecVp, file, argv);
}

static int MyPosixSpawn(pid_t* pid, const char* path, const void* fileActions, const void* attr,
                        char* const argv[], char* const envp[]) {
    BYTEHOOK_STACK_SCOPE();
    ReconExec(argv, path);
    char** na = nullptr;
    int n = 0;
    if (RewriteArgvForCpuinfo(argv, &na, &n)) {
        Log("native: posix_spawn redirect (cpuinfo) via %s", path ? path : "?");
        int rc = BYTEHOOK_CALL_PREV(MyPosixSpawn, pid, path, fileActions, attr, na, envp);
        FreeRewrittenArgv(na, n);
        return rc;
    }
    return BYTEHOOK_CALL_PREV(MyPosixSpawn, pid, path, fileActions, attr, argv, envp);
}

static int MyPosixSpawnP(pid_t* pid, const char* file, const void* fileActions, const void* attr,
                         char* const argv[], char* const envp[]) {
    BYTEHOOK_STACK_SCOPE();
    ReconExec(argv, file);
    char** na = nullptr;
    int n = 0;
    if (RewriteArgvForCpuinfo(argv, &na, &n)) {
        Log("native: posix_spawn redirect (cpuinfo) via %s", file ? file : "?");
        int rc = BYTEHOOK_CALL_PREV(MyPosixSpawnP, pid, file, fileActions, attr, na, envp);
        FreeRewrittenArgv(na, n);
        return rc;
    }
    return BYTEHOOK_CALL_PREV(MyPosixSpawnP, pid, file, fileActions, attr, argv, envp);
}

// Direct syscall() readers: open/openat of /proc/cpuinfo is answered with a
// pre-rendered memfd (some native readers bypass the libc wrappers).
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
#ifdef __NR_openat
    if (number == __NR_openat) ReconNote("syscall-openat", (const char*)a1, 0);
#endif
#ifdef __NR_open
    if (number == __NR_open) ReconNote("syscall-open", (const char*)a0, 0);
#endif
#ifdef __NR_ptrace
    if (number == __NR_ptrace) ReconNote("syscall-ptrace", "ptrace", 0);
#endif
#ifdef __NR_openat
    if (CpuSpoofActive() && number == __NR_openat) {
        const char* cpath = (const char*)a1;
        if (cpath != nullptr && (a2 & O_ACCMODE) == O_RDONLY &&
            strcmp(cpath, "/proc/cpuinfo") == 0) {
            std::string raw;
            if (ReadWholeFile(cpath, &raw)) {
                std::string out;
                RewriteCpuinfoContent(raw, &out);
                int mfd = CreateMemfdWith(out.data(), out.size(), (int)a2);
                if (mfd >= 0) {
                    Log("native: cpuinfo served (direct syscall)");
                    return (long)mfd;
                }
            }
        }
    }
#endif
#ifdef __NR_open
    if (CpuSpoofActive() && number == __NR_open) {
        const char* cpath = (const char*)a0;
        if (cpath != nullptr && (a1 & O_ACCMODE) == O_RDONLY &&
            strcmp(cpath, "/proc/cpuinfo") == 0) {
            std::string raw;
            if (ReadWholeFile(cpath, &raw)) {
                std::string out;
                RewriteCpuinfoContent(raw, &out);
                int mfd = CreateMemfdWith(out.data(), out.size(), (int)a1);
                if (mfd >= 0) {
                    Log("native: cpuinfo served (direct syscall)");
                    return (long)mfd;
                }
            }
        }
    }
#endif
    return BYTEHOOK_CALL_PREV(MySyscall, number, a0, a1, a2, a3, a4, a5);
}

// Some shells receive their commands over a pipe (persistent shell objects,
// libsu-style helpers): the command text passes through write(2) in this
// process, so /proc/cpuinfo references are rewritten there as well.
static bool BufHasCpuinfoRef(const char* p, size_t n) {
    static const char kRef[] = "/proc/cpuinfo";
    const size_t kl = sizeof(kRef) - 1;
    if (n < kl) return false;
    for (size_t i = 0; i + kl <= n; i++) {
        if (p[i] == '/' && memcmp(p + i, kRef, kl) == 0) return true;
    }
    return false;
}

static std::string ReplaceCpuinfoRefsBuf(const char* p, size_t n, const std::string& fake) {
    static const char kRef[] = "/proc/cpuinfo";
    const size_t kl = sizeof(kRef) - 1;
    std::string out;
    out.reserve(n + 64);
    size_t i = 0;
    while (i < n) {
        if (i + kl <= n && p[i] == '/' && memcmp(p + i, kRef, kl) == 0) {
            out.append(fake);
            i += kl;
        } else {
            out.push_back(p[i]);
            i++;
        }
    }
    return out;
}

static ssize_t MyWrite(int fd, const void* buf, size_t count) {
    BYTEHOOK_STACK_SCOPE();
    if (ReconEnabled() && buf != nullptr && count > 0 && count <= 4096) {
        ReconNoteN("pipe-write", (const char*)buf, count, (long)fd);
    }
    if (CpuSpoofActive() && buf != nullptr && count > 0 && count <= 8192 &&
        BufHasCpuinfoRef((const char*)buf, count)) {
        const std::string& fake = FakeCpuinfoPath();
        if (!fake.empty() && WriteFakeCpuinfo(fake.c_str())) {
            std::string out = ReplaceCpuinfoRefsBuf((const char*)buf, count, fake);
            ssize_t w = BYTEHOOK_CALL_PREV(MyWrite, fd, out.data(), out.size());
            if (w >= 0) {
                Log("native: pipe cpuinfo redirect (%u -> %u bytes)", (unsigned)count,
                    (unsigned)out.size());
                return (ssize_t)count;
            }
            return w;
        }
    }
    return BYTEHOOK_CALL_PREV(MyWrite, fd, buf, count);
}

// ---------------------------------------------------------------------------
// pipe / stream cpuinfo catch: some readers (helper processes, root shells,
// libsu-style wrappers) receive the cpuinfo text over a pipe instead of
// opening the file in-process. Those frames pass through read(2) here, so the
// first frame that looks like a raw host dump is swapped for the ARM view;
// the fd keeps serving the fake afterwards (EOF when exhausted). fd reuse is
// guarded by comparing the pipe/file inode.
// ---------------------------------------------------------------------------

#define PAS_RDC_SLOTS 16

struct PasRdcSlot {
    int fd;
    unsigned pos;
    unsigned char mode;
    unsigned long long ino;
};

static PasRdcSlot g_rdc[PAS_RDC_SLOTS];
static volatile int g_rdc_active = 0;
static std::string g_rdc_fake;
static bool g_rdc_fake_ready = false;

static int RdcFind(int fd) {
    for (int i = 0; i < PAS_RDC_SLOTS; i++) {
        if (g_rdc[i].mode == 1 && g_rdc[i].fd == fd) return i;
    }
    return -1;
}

static int RdcClaim(int fd) {
    for (int i = 0; i < PAS_RDC_SLOTS; i++) {
        if (g_rdc[i].mode == 0) {
            g_rdc[i].fd = fd;
            g_rdc[i].pos = 0;
            g_rdc[i].ino = 0;
            g_rdc[i].mode = 1;
            g_rdc_active++;
            return i;
        }
    }
    return -1;
}

static void RdcClear(int idx) {
    if (idx >= 0 && idx < PAS_RDC_SLOTS && g_rdc[idx].mode == 1) {
        g_rdc[idx].mode = 0;
        if (g_rdc_active > 0) g_rdc_active--;
    }
}

static unsigned long long RdcInode(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return 0;
    return (unsigned long long)st.st_ino;
}

static bool RdcMemHas(const char* p, size_t n, const char* tok) {
    size_t tl = strlen(tok);
    if (tl == 0 || n < tl) return false;
    for (size_t i = 0; i + tl <= n; i++) {
        if (p[i] == tok[0] && memcmp(p + i, tok, tl) == 0) return true;
    }
    return false;
}

static bool RdcLooksRaw(const char* p, size_t n) {
    if (n < 96) return false;
    if (memcmp(p, "processor", 9) != 0) return false;
    if (!RdcMemHas(p, n, "vendor_id") && !RdcMemHas(p, n, "model name")) return false;
    if (!RdcMemHas(p, n, "GenuineIntel") && !RdcMemHas(p, n, "AuthenticAMD")) return false;
    if (!RdcMemHas(p, n, "cpu family") && !RdcMemHas(p, n, "stepping")) return false;
    return true;
}

static void RdcBuildFake() {
    g_rdc_fake_ready = true;
    std::string raw;
    if (!ReadWholeFile("/proc/cpuinfo", &raw)) return;
    std::string out;
    RewriteCpuinfoContent(raw, &out);
    if (!out.empty()) g_rdc_fake = out;
}

static ssize_t MyRead(int fd, void* buf, size_t count) {
    BYTEHOOK_STACK_SCOPE();
    if (CpuSpoofActive() && g_rdc_active > 0 && buf != nullptr) {
        int idx = RdcFind(fd);
        if (idx >= 0) {
            unsigned long long ino = RdcInode(fd);
            if (ino != 0 && g_rdc[idx].ino != 0 && ino != g_rdc[idx].ino) {
                RdcClear(idx);  // fd was reused for a different object
            } else {
                size_t len = g_rdc_fake.size();
                if (g_rdc[idx].pos >= len) return 0;
                size_t chunk = len - g_rdc[idx].pos;
                if (chunk > count) chunk = count;
                memcpy(buf, g_rdc_fake.data() + g_rdc[idx].pos, chunk);
                g_rdc[idx].pos += (unsigned)chunk;
                return (ssize_t)chunk;
            }
        }
    }
    ssize_t n = BYTEHOOK_CALL_PREV(MyRead, fd, buf, count);
    if (n >= 96 && CpuSpoofActive() && buf != nullptr) {
        const char* p = (const char*)buf;
        if (p[0] == 'p' && RdcLooksRaw(p, (size_t)n)) {
            if (!g_rdc_fake_ready) RdcBuildFake();
            if (!g_rdc_fake.empty()) {
                int idx = RdcClaim(fd);
                if (idx >= 0) {
                    g_rdc[idx].ino = RdcInode(fd);
                    size_t chunk = g_rdc_fake.size();
                    if (chunk > (size_t)n) chunk = (size_t)n;
                    memcpy(buf, g_rdc_fake.data(), chunk);
                    g_rdc[idx].pos = (unsigned)chunk;
                    Log("native: cpuinfo read-catch fd=%d served ARM view", fd);
                    return (ssize_t)chunk;
                }
            }
        }
    }
    return n;
}

// ---------------------------------------------------------------------------
// recon extras: directory listings (location probes are often done with
// opendir) - logged, never modified.
// ---------------------------------------------------------------------------

static DIR* MyOpendir(const char* name) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("opendir", name, 0);
    return BYTEHOOK_CALL_PREV(MyOpendir, name);
}

void InstallReconHooks() {
    HookLibcSym("opendir", (void*)MyOpendir);
    Log("native: recon hooks installed");
}

// ---------------------------------------------------------------------------
// dlopen tracing (diagnostics)
//
// A game that stalls during loading usually waits inside its last native
// library load (anti-tamper init, encrypted asset loader, license check).
// While recon is on, every dlopen / android_dlopen_ext attempt is logged
// with its flags and the returned handle, so a stall shows up as the final
// entry in the capture. Pure logging - no behavior changes.
// ---------------------------------------------------------------------------

static volatile int g_dlopen_diag = 0;

// Library-load tracing bypasses the recon token filter on purpose: every
// load matters when hunting a loading stall. Own cap so it cannot starve
// the rest of the recon budget.
static void ReconDlopen(const char* op, const char* detail, long res) {
    if (!g_recon || detail == nullptr) return;
    int n = __sync_fetch_and_add(&g_dlopen_diag, 1);
    if (n == 150) {
        Log("native: recon: dlopen trace cap reached");
        return;
    }
    if (n > 150) return;
    Log("native: recon: %s %s -> %ld", op, detail, res);
}

static void* MyDlopen(const char* filename, int flags) {
    BYTEHOOK_STACK_SCOPE();
    ReconDlopen("dlopen", filename ? filename : "(null)", (long)flags);
    void* h = BYTEHOOK_CALL_PREV(MyDlopen, filename, flags);
    ReconDlopen("dlopen-done", filename ? filename : "(null)", (long)(intptr_t)h);
    return h;
}

static void* MyAndroidDlopenExt(const char* filename, int flags, const void* extinfo) {
    BYTEHOOK_STACK_SCOPE();
    ReconDlopen("android-dlopen-ext", filename ? filename : "(null)", (long)flags);
    void* h = BYTEHOOK_CALL_PREV(MyAndroidDlopenExt, filename, flags, extinfo);
    ReconDlopen("android-dlopen-ext-done", filename ? filename : "(null)", (long)(intptr_t)h);
    return h;
}

void InstallFsHooks() {
    HookLibcSym("open", (void*)HideOpen);
    HookLibcSym("open64", (void*)HideOpen64);
    HookLibcSym("__open_2", (void*)HideOpen2);
    HookLibcSym("openat", (void*)HideOpenAt);
    HookLibcSym("openat64", (void*)HideOpenAt64);
    HookLibcSym("__openat_2", (void*)HideOpenAt2);
    HookLibcSym("fopen", (void*)HideFopen);
    HookLibcSym("fopen64", (void*)HideFopen64);
    HookLibcSym("getdents64", (void*)HideGetDents64);
    HookLibcSym("access", (void*)HideAccess);
    HookLibcSym("faccessat", (void*)HideFAccessAt);
    HookLibcSym("stat", (void*)HideStat);
    HookLibcSym("lstat", (void*)HideLstat);
    HookLibcSym("fstatat", (void*)HideFStatAt);

    // Library-load tracing (diagnostics; passthrough when recon is off).
    void* s1 = HookChainStub("libc.so", "dlopen", (void*)MyDlopen);
    void* s2 = HookChainStub("libdl.so", "dlopen", (void*)MyDlopen);
    void* s3 = HookChainStub("libc.so", "android_dlopen_ext", (void*)MyAndroidDlopenExt);
    void* s4 = HookChainStub("libdl.so", "android_dlopen_ext", (void*)MyAndroidDlopenExt);
    Log("native: trace dlopen stubs=%d/%d ext=%d/%d", s1 != nullptr, s2 != nullptr,
        s3 != nullptr, s4 != nullptr);
}

void InstallCpuDeepHooks() {
    HookLibcSym("execve", (void*)MyExecVe);
    HookLibcSym("execv", (void*)MyExecV);
    HookLibcSym("execvp", (void*)MyExecVp);
    HookLibcSym("posix_spawn", (void*)MyPosixSpawn);
    HookLibcSym("posix_spawnp", (void*)MyPosixSpawnP);
    HookLibcSym("syscall", (void*)MySyscall);
    HookLibcSym("write", (void*)MyWrite);
    HookLibcSym("read", (void*)MyRead);
    Log("native: cpu deep hooks installed (exec/syscall/write/read)");
}

}  // namespace pas

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetRecon(JNIEnv* env, jobject thiz,
                                                           jboolean reconOn) {
    (void)env;
    (void)thiz;
    pas::SetRecon(reconOn == JNI_TRUE);
}

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetWebrtcMode(JNIEnv* env, jobject thiz, jint mode) {
    (void)env;
    (void)thiz;
    pas::SetWebRtcMode((int)mode);
}
