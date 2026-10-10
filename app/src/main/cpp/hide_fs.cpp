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

enum class WatchedFile {
    None,
    Tcp,
    Udp,
    Misc,
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

enum class SpecialAction { None, NotFound, EnforceOne, RpFilterOne };

static SpecialAction ResolveSpecial(const char* path) {
    if (!path) return SpecialAction::None;
    if (strcmp(path, "/proc/net/fib_trie") == 0 ||
        strcmp(path, "/proc/self/net/fib_trie") == 0) {
        return SpecialAction::NotFound;
    }
    if (strcmp(path, "/sys/fs/selinux/enforce") == 0) {
        return SpecialAction::EnforceOne;
    }
    {
        static const char kPre[] = "/proc/sys/net/ipv4/conf/";
        static const char kSuf[] = "/rp_filter";
        const size_t pl = sizeof(kPre) - 1;
        const size_t sl = sizeof(kSuf) - 1;
        const size_t n = strlen(path);
        if (n > pl + sl && strncmp(path, kPre, pl) == 0 &&
            strcmp(path + n - sl, kSuf) == 0) {
            return SpecialAction::RpFilterOne;
        }
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
    ".so", "/data/app",
    "zygisk-module", "ro.boot", "ro.hardware", "topology", "related_cpus",
    "affected_cpus", "core_id", "cluster", "devicetree", "compatible", "serial",
    "board", "platform", "vendor_id", "bogomips", "physical_package",
    "libssl", "libcrypto", "boring", "conscrypt", "cacerts",
    ".pem", ".crt", ".cer", "pinning", "truststore",
    "mali", "kgsl", "devfreq", "gpufreq", "gpu_model", "gpuclk",
    "gpu_cores", "core_count", "shader_core", "mp_count", "gpu_available",
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
    const std::string implementer = CpuSpoofImplementer();
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
        out->append("CPU implementer\t: ");
        out->append(implementer);
        out->push_back('\n');
        out->append("CPU architecture\t: 8\n");
        out->append("CPU variant\t: 0x0\n");
        out->append("CPU part\t: ");
        out->append(part);
        out->push_back('\n');
        out->append("CPU revision\t: 1\n");
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

#define PAS_CPU_MAX_CORES 16

static int CpuClusterMap(int* coreCluster, int* coreIndexInCluster) {
    const char* s = CpuSpoofClusters();
    int total = 0;
    int cluster = 0;
    int idxInCluster = 0;
    const char* p = s;
    while (*p != '\0' && total < PAS_CPU_MAX_CORES) {
        if (*p >= '0' && *p <= '9') {
            int n = 0;
            while (*p >= '0' && *p <= '9') {
                n = n * 10 + (*p - '0');
                p++;
            }
            for (int i = 0; i < n && total < PAS_CPU_MAX_CORES; i++) {
                coreCluster[total] = cluster;
                coreIndexInCluster[total] = idxInCluster++;
                total++;
            }
            if (*p == '+') {
                cluster++;
                idxInCluster = 0;
                p++;
            }
        } else {
            p++;
        }
    }
    return total;
}

static int CpuClusterCount() {
    const char* s = CpuSpoofClusters();
    if (!s || !*s) return 0;
    int count = 0;
    bool inNum = false;
    while (*s) {
        if (*s >= '0' && *s <= '9') {
            if (!inNum) { count++; inNum = true; }
        } else {
            inNum = false;
        }
        s++;
    }
    return count;
}

static bool IsHiddenPolicyPath(const char* path) {
    if (!CpuSpoofActive() || !path) return false;
    static const char kPre[] = "/sys/devices/system/cpu/cpufreq/policy";
    if (strncmp(path, kPre, sizeof(kPre) - 1) != 0) return false;
    const char* p = path + sizeof(kPre) - 1;
    int n = 0;
    bool hasN = false;
    while (*p >= '0' && *p <= '9') {
        n = n * 10 + (*p - '0');
        p++;
        hasN = true;
    }
    if (!hasN) return false;
    if (*p != '\0' && *p != '/') return false;
    int clusterCount = CpuClusterCount();
    if (clusterCount <= 0) return false;
    return n >= clusterCount;
}

static bool IsHiddenPolicyDirEntry(const char* name) {
    if (!name || strncmp(name, "policy", 6) != 0) return false;
    const char* p = name + 6;
    if (*p < '0' || *p > '9') return false;
    int n = 0;
    while (*p >= '0' && *p <= '9') {
        n = n * 10 + (*p - '0');
        p++;
    }
    if (*p != '\0') return false;
    int clusterCount = CpuClusterCount();
    if (clusterCount <= 0) return false;
    return n >= clusterCount;
}

static void CpuClusterList(int c, const int* coreCluster, int total, char* out, size_t cap) {
    int first = -1, last = -1;
    for (int i = 0; i < total; i++) {
        if (coreCluster[i] == c) {
            if (first < 0) first = i;
            last = i;
        }
    }
    if (first < 0) {
        snprintf(out, cap, "\n");
    } else if (first == last) {
        snprintf(out, cap, "%d\n", first);
    } else {
        snprintf(out, cap, "%d-%d\n", first, last);
    }
}

static void CpuClusterBitmask(int c, const int* coreCluster, int total, char* out, size_t cap) {
    unsigned long long mask = 0;
    for (int i = 0; i < total && i < 64; i++) {
        if (coreCluster[i] == c) mask |= (1ULL << i);
    }
    int width = (total + 3) / 4;
    if (width < 1) width = 1;
    snprintf(out, cap, "%0*llx\n", width, mask);
}

static void CpuAllList(int total, char* out, size_t cap) {
    if (total <= 0) { snprintf(out, cap, "\n"); return; }
    if (total == 1) { snprintf(out, cap, "0\n"); return; }
    snprintf(out, cap, "0-%d\n", total - 1);
}

static void CpuAllBitmask(int total, char* out, size_t cap) {
    unsigned long long mask = 0;
    for (int i = 0; i < total && i < 64; i++) mask |= (1ULL << i);
    int width = (total + 3) / 4;
    if (width < 1) width = 1;
    snprintf(out, cap, "%0*llx\n", width, mask);
}

static bool CpuFreqSpoofValue(const char* path, char* out, size_t cap) {
    if (CpuSpoofMinKHz() <= 0 || CpuSpoofMaxKHz() <= 0) return false;
    static const char kRoot[] = "/sys/devices/system/cpu/";
    if (strncmp(path, kRoot, sizeof(kRoot) - 1) != 0) return false;
    const char* cpufreq = strstr(path, "cpufreq/");
    if (cpufreq == nullptr) return false;
    const char* slash = strrchr(path, '/');
    if (!slash || slash[1] == '\0') return false;
    const char* leaf = slash + 1;
    int v;
    if (strcmp(leaf, "cpuinfo_min_freq") == 0 || strcmp(leaf, "scaling_min_freq") == 0) {
        v = CpuSpoofMinKHz();
    } else if (strcmp(leaf, "cpuinfo_max_freq") == 0 || strcmp(leaf, "scaling_max_freq") == 0) {
        v = CpuSpoofMaxKHz();
    } else if (strcmp(leaf, "scaling_cur_freq") == 0) {
        v = (CpuSpoofMinKHz() + CpuSpoofMaxKHz()) / 2;
    } else {
        return false;
    }
    snprintf(out, cap, "%d\n", v);
    return true;
}

static bool CpuGovernorSpoofValue(const char* path, char* out, size_t cap) {
    static const char kRoot[] = "/sys/devices/system/cpu/";
    if (strncmp(path, kRoot, sizeof(kRoot) - 1) != 0) return false;
    const char* cpufreq = strstr(path, "cpufreq/");
    if (cpufreq == nullptr) return false;
    const char* slash = strrchr(path, '/');
    if (!slash || slash[1] == '\0') return false;
    if (strcmp(slash + 1, "scaling_governor") != 0) return false;
    snprintf(out, cap, "schedutil\n");
    return true;
}

static bool CpuTopologySpoofValue(const char* path, char* out, size_t cap) {
    if (!CpuSpoofActive()) return false;

    int coreCluster[PAS_CPU_MAX_CORES];
    int coreIdx[PAS_CPU_MAX_CORES];
    int total = CpuClusterMap(coreCluster, coreIdx);
    if (total <= 0) return false;

    static const char kCpuRoot[] = "/sys/devices/system/cpu/";

    {
        static const char kPolicy[] = "/sys/devices/system/cpu/cpufreq/policy";
        if (strncmp(path, kPolicy, sizeof(kPolicy) - 1) == 0) {
            const char* p = path + sizeof(kPolicy) - 1;
            int pol = 0;
            bool hasPol = false;
            while (*p >= '0' && *p <= '9') {
                pol = pol * 10 + (*p - '0');
                p++;
                hasPol = true;
            }
            if (!hasPol || *p != '/') return false;
            const char* leaf = p + 1;
            if (*leaf == '\0' || strchr(leaf, '/') != nullptr) return false;
            if (strcmp(leaf, "affected_cpus") != 0 && strcmp(leaf, "related_cpus") != 0) {
                return false;
            }
            CpuClusterList(pol, coreCluster, total, out, cap);
            return true;
        }
    }

    if (strncmp(path, kCpuRoot, sizeof(kCpuRoot) - 1) != 0) return false;
    const char* p = path + sizeof(kCpuRoot) - 1;
    int core = 0;
    bool hasCore = false;
    while (*p >= '0' && *p <= '9') {
        core = core * 10 + (*p - '0');
        p++;
        hasCore = true;
    }
    if (!hasCore || *p != '/') return false;
    if (core < 0 || core >= total) return false;
    const char* rel = p + 1;
    const int c = coreCluster[core];

    if (strcmp(rel, "affected_cpus") == 0 || strcmp(rel, "related_cpus") == 0) {
        CpuClusterList(c, coreCluster, total, out, cap);
        return true;
    }

    if (strncmp(rel, "cpufreq/", 8) == 0) {
        const char* leaf = rel + 8;
        if (strcmp(leaf, "affected_cpus") == 0 || strcmp(leaf, "related_cpus") == 0) {
            CpuClusterList(c, coreCluster, total, out, cap);
            return true;
        }
        return false;
    }

    if (strncmp(rel, "topology/", 9) != 0) return false;
    const char* leaf = rel + 9;
    if (*leaf == '\0' || strchr(leaf, '/') != nullptr) return false;

    if (strcmp(leaf, "core_id") == 0) {
        snprintf(out, cap, "%d\n", coreIdx[core]);
        return true;
    }
    if (strcmp(leaf, "cluster_id") == 0) {
        snprintf(out, cap, "%d\n", c);
        return true;
    }
    if (strcmp(leaf, "physical_package_id") == 0) {
        snprintf(out, cap, "0\n");
        return true;
    }

    if (strcmp(leaf, "core_cpus_list") == 0 ||
        strcmp(leaf, "thread_siblings_list") == 0 ||
        strcmp(leaf, "cluster_cpus_list") == 0) {
        CpuClusterList(c, coreCluster, total, out, cap);
        return true;
    }
    if (strcmp(leaf, "core_cpus") == 0 ||
        strcmp(leaf, "thread_siblings") == 0 ||
        strcmp(leaf, "cluster_cpus") == 0) {
        CpuClusterBitmask(c, coreCluster, total, out, cap);
        return true;
    }

    if (strcmp(leaf, "package_cpus_list") == 0 ||
        strcmp(leaf, "core_siblings_list") == 0 ||
        strcmp(leaf, "die_cpus_list") == 0) {
        CpuAllList(total, out, cap);
        return true;
    }
    if (strcmp(leaf, "package_cpus") == 0 ||
        strcmp(leaf, "core_siblings") == 0 ||
        strcmp(leaf, "die_cpus") == 0) {
        CpuAllBitmask(total, out, cap);
        return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// v2.4.7: GPU sysfs mirrors.
//
// DevCheck reads GPU physical data from three families of paths:
//   /sys/class/kgsl/kgsl-3d0/*            (Adreno / Qualcomm driver)
//   /sys/class/devfreq/*/*                (generic governor interface)
//   /sys/devices/platform/*.mali/*        (Mali driver)
// The emulator exposes fake values in all of them, so DevCheck aborts
// the "cores / L2 / arch" reconciliation. Serving the spoofed GPU's
// real clock range and model string makes those rows populate.
//
// The "cores" and "L2" values are NOT sysfs-derived on real devices -
// they come through /dev/mali0 ioctl and Vulkan driverInfo. The ioctl
// path is not covered (see note at bottom); the Vulkan driverInfo
// already carries both from v2.4.5.
// ---------------------------------------------------------------------------

static bool GpuSysfsSpoofValue(const char* path, char* out, size_t cap) {
    if (!GpuSpoofActive() || path == nullptr) return false;

    int maxKHz = GpuSpoofMaxFreqKHz();
    int minKHz = GpuSpoofMinFreqKHz();
    if (maxKHz <= 0) maxKHz = 1000000;
    if (minKHz <= 0) minKHz = 200000;

    // --- Qualcomm kgsl-3d0 ----------------------------------------------
    // max_gpuclk: Hz.
    if (strstr(path, "kgsl-3d0/max_gpuclk") != nullptr) {
        snprintf(out, cap, "%d\n", maxKHz * 1000);
        return true;
    }
    // gpu_available_frequencies: space-separated Hz list.
    if (strstr(path, "gpu_available_frequencies") != nullptr) {
        int span = maxKHz - minKHz;
        int step = span > 0 ? span / 3 : 1;
        snprintf(out, cap, "%d %d %d %d\n",
                 minKHz * 1000,
                 (minKHz + step) * 1000,
                 (minKHz + 2 * step) * 1000,
                 maxKHz * 1000);
        return true;
    }
    // gpu_model / gpu_name: the raw Vulkan device name (no ANGLE wrapper).
    if (strstr(path, "kgsl-3d0/gpu_model") != nullptr ||
        strstr(path, "kgsl-3d0/gpu_name") != nullptr) {
        snprintf(out, cap, "%s\n", GpuSpoofVkDeviceName().c_str());
        return true;
    }
    // max_pwrlevel / min_pwrlevel / num_pwrlevels: keep driver metadata
    // internally consistent with the number of freq steps we serve.
    if (strstr(path, "kgsl-3d0/max_pwrlevel") != nullptr) {
        snprintf(out, cap, "0\n");
        return true;
    }
    if (strstr(path, "kgsl-3d0/min_pwrlevel") != nullptr) {
        snprintf(out, cap, "3\n");
        return true;
    }
    if (strstr(path, "kgsl-3d0/num_pwrlevels") != nullptr) {
        snprintf(out, cap, "4\n");
        return true;
    }
    if (strstr(path, "kgsl-3d0/gpu_busy_percentage") != nullptr) {
        snprintf(out, cap, "0 %%\n");
        return true;
    }

    // --- generic devfreq interface (governor paths) ---------------------
    if (strstr(path, "/devfreq/") != nullptr) {
        const char* slash = strrchr(path, '/');
        if (!slash || slash[1] == '\0') return false;
        const char* leaf = slash + 1;
        if (strcmp(leaf, "max_freq") == 0) {
            snprintf(out, cap, "%d\n", maxKHz * 1000);
            return true;
        }
        if (strcmp(leaf, "min_freq") == 0) {
            snprintf(out, cap, "%d\n", minKHz * 1000);
            return true;
        }
        if (strcmp(leaf, "cur_freq") == 0) {
            snprintf(out, cap, "%d\n", (maxKHz * 3 / 4) * 1000);
            return true;
        }
        if (strcmp(leaf, "available_frequencies") == 0) {
            int span = maxKHz - minKHz;
            int step = span > 0 ? span / 3 : 1;
            snprintf(out, cap, "%d %d %d %d\n",
                     minKHz * 1000,
                     (minKHz + step) * 1000,
                     (minKHz + 2 * step) * 1000,
                     maxKHz * 1000);
            return true;
        }
        if (strcmp(leaf, "governor") == 0) {
            snprintf(out, cap, "simple_ondemand\n");
            return true;
        }
        if (strcmp(leaf, "available_governors") == 0) {
            snprintf(out, cap, "simple_ondemand performance powersave\n");
            return true;
        }
        if (strcmp(leaf, "polling_interval") == 0) {
            snprintf(out, cap, "50\n");
            return true;
        }
        if (strcmp(leaf, "trans_stat") == 0) {
            snprintf(out, cap, "     From  :   To\n");
            return true;
        }
    }

    // --- Mali driver (Samsung Exynos) -----------------------------------
    // Samsung exposes the GPU through /sys/devices/platform/*.mali/ and
    // (for some kernels) /sys/class/misc/mali0/. These are typically only
    // readable by the graphics group, but a few fields are world-readable.
    if (strstr(path, ".mali/") != nullptr || strstr(path, "/mali0/") != nullptr) {
        const char* slash = strrchr(path, '/');
        if (!slash || slash[1] == '\0') return false;
        const char* leaf = slash + 1;
        if (strcmp(leaf, "gpu_model") == 0 || strcmp(leaf, "gpu_name") == 0) {
            snprintf(out, cap, "%s\n", GpuSpoofVkDeviceName().c_str());
            return true;
        }
        if (strcmp(leaf, "max_freq") == 0 || strcmp(leaf, "max_clock") == 0) {
            snprintf(out, cap, "%d\n", maxKHz * 1000);
            return true;
        }
        if (strcmp(leaf, "min_freq") == 0 || strcmp(leaf, "min_clock") == 0) {
            snprintf(out, cap, "%d\n", minKHz * 1000);
            return true;
        }
        if (strcmp(leaf, "available_frequencies") == 0) {
            int span = maxKHz - minKHz;
            int step = span > 0 ? span / 3 : 1;
            snprintf(out, cap, "%d %d %d %d\n",
                     minKHz * 1000,
                     (minKHz + step) * 1000,
                     (minKHz + 2 * step) * 1000,
                     maxKHz * 1000);
            return true;
        }
        if (strcmp(leaf, "num_cores") == 0 || strcmp(leaf, "core_count") == 0 ||
            strcmp(leaf, "shader_cores") == 0) {
            snprintf(out, cap, "%d\n", GpuSpoofCores());
            return true;
        }
        if (strcmp(leaf, "l2_cache") == 0 || strcmp(leaf, "l2_size") == 0) {
            snprintf(out, cap, "%d\n", GpuSpoofL2CacheKb());
            return true;
        }
        if (strcmp(leaf, "architecture") == 0) {
            snprintf(out, cap, "%s\n", GpuSpoofArch().c_str());
            return true;
        }
        if (strcmp(leaf, "power_policy") == 0) {
            snprintf(out, cap, "always_on\n");
            return true;
        }
    }

    return false;
}

static long ServeSysfsSpoofFd(const char* path, int flags) {
    if (path == nullptr) return -1;
    if (strcmp(path, "/proc/cpuinfo") == 0 && CpuSpoofActive()) {
        std::string raw;
        if (!ReadWholeFile(path, &raw)) return -1;
        std::string out;
        RewriteCpuinfoContent(raw, &out);
        int mfd = CreateMemfdWith(out.data(), out.size(), flags);
        if (mfd >= 0) Log("native: cpuinfo served (direct syscall)");
        return mfd;
    }
    char val[128];
    if (CpuSpoofActive()) {
        if (CpuFreqSpoofValue(path, val, sizeof(val)) ||
            CpuGovernorSpoofValue(path, val, sizeof(val)) ||
            CpuTopologySpoofValue(path, val, sizeof(val))) {
            return CreateMemfdWith(val, strlen(val), flags);
        }
    }
    if (GpuSpoofActive()) {
        if (GpuSysfsSpoofValue(path, val, sizeof(val))) {
            return CreateMemfdWith(val, strlen(val), flags);
        }
    }
    return -1;
}

static bool HandleSpecialOpen(const char* path, int flags, int* fdOut) {
    SpecialAction sp = ResolveSpecial(path);
    if (sp == SpecialAction::None) {
        if (IsHiddenPolicyPath(path)) {
            errno = ENOENT;
            *fdOut = -1;
            return true;
        }
        if (SpoofActive() && IsPropsFile(path) && (flags & O_ACCMODE) == O_RDONLY) {
            std::string raw;
            if (!ReadWholeFile(path, &raw)) return false;
            std::string out;
            RewritePropsContent(raw, &out);
            int mfd = CreateMemfdWith(out.data(), out.size(), flags);
            if (mfd < 0) return false;
            *fdOut = mfd;
            return true;
        }
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
        if ((flags & O_ACCMODE) == O_RDONLY) {
            char val[128];
            bool handled = false;
            if (CpuSpoofActive()) {
                handled = CpuFreqSpoofValue(path, val, sizeof(val)) ||
                          CpuGovernorSpoofValue(path, val, sizeof(val)) ||
                          CpuTopologySpoofValue(path, val, sizeof(val));
            }
            if (!handled && GpuSpoofActive()) {
                handled = GpuSysfsSpoofValue(path, val, sizeof(val));
            }
            if (handled) {
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
    if (sp == SpecialAction::RpFilterOne) {
        *fdOut = CreateMemfdWith("1\n", 2, flags);
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

static bool IsLoopbackListenerLine(const char* line, bool tcp) {
    if (!line) return false;
    const char* p = SkipWs(line);
    p = SkipToken(p);
    p = SkipWs(p);
    const char* local = p;
    p = SkipToken(p);
    size_t localLen = (size_t)(p - local);
    p = SkipWs(p);
    p = SkipToken(p);
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

static bool LineContainsHiddenToken(const char* line) {
    if (!line) return false;
    char buf[512];
    size_t bl = strlen(line);
    if (bl >= sizeof(buf)) bl = sizeof(buf) - 1;
    memcpy(buf, line, bl);
    buf[bl] = '\0';
    char* p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':') p++;
        if (!*p) break;
        char* start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n' && *p != ':' && *p != '/') p++;
        char save = *p;
        *p = '\0';
        if (IsHiddenIfaceName(start)) return true;
        if (save == '\0') break;
        p++;
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
        bool blocked = LineContainsHiddenName(c) || LineContainsHiddenToken(c);
        if (!blocked && tcpLike) blocked = LineContainsProxyPortToken(c);
        if (!blocked && kind == WatchedFile::Tcp) blocked = IsLoopbackListenerLine(c, true);
        if (!blocked && kind == WatchedFile::Udp) blocked = IsLoopbackListenerLine(c, false);
        if (!blocked) out->append(line);
        i = j;
    }
}

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
        if (!IsHiddenIfaceName(d->d_name) && !IsHiddenPolicyDirEntry(d->d_name)) {
            if (out != p) memmove(out, p, rl);
            out += rl;
        }
        p += rl;
    }
    return (ssize_t)(out - base);
}

int HideAccess(const char* path, int mode) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("access", path, (long)mode);
    if (IsHiddenPath(path) || IsHiddenPolicyPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideAccess, path, mode);
}

int HideFAccessAt(int dirfd, const char* path, int mode, int flags) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("faccessat", path, (long)mode);
    if (IsHiddenPath(path) || IsHiddenPolicyPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideFAccessAt, dirfd, path, mode, flags);
}

int HideStat(const char* path, struct stat* buf) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("stat", path, 0);
    if (IsHiddenPath(path) || IsHiddenPolicyPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideStat, path, buf);
}

int HideLstat(const char* path, struct stat* buf) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("lstat", path, 0);
    if (IsHiddenPath(path) || IsHiddenPolicyPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideLstat, path, buf);
}

int HideFStatAt(int dirfd, const char* path, struct stat* buf, int flags) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("fstatat", path, 0);
    if (IsHiddenPath(path) || IsHiddenPolicyPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideFStatAt, dirfd, path, buf, flags);
}

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
    if (number == __NR_openat) {
        const char* hpath = (const char*)a1;
        if (hpath != nullptr && (a2 & O_ACCMODE) == O_RDONLY && IsHiddenPathFast(hpath)) {
            errno = ENOENT;
            return -1;
        }
        if (hpath != nullptr && IsHiddenPolicyPath(hpath)) {
            errno = ENOENT;
            return -1;
        }
    }
#endif
#ifdef __NR_openat
    if (number == __NR_openat) {
        const char* cpath = (const char*)a1;
        if (cpath != nullptr && (a2 & O_ACCMODE) == O_RDONLY) {
            long mfd = ServeSysfsSpoofFd(cpath, (int)a2);
            if (mfd >= 0) return mfd;
        }
    }
#endif
#ifdef __NR_open
    if (number == __NR_open) {
        const char* hpath = (const char*)a0;
        if (hpath != nullptr && (a1 & O_ACCMODE) == O_RDONLY && IsHiddenPathFast(hpath)) {
            errno = ENOENT;
            return -1;
        }
        if (hpath != nullptr && IsHiddenPolicyPath(hpath)) {
            errno = ENOENT;
            return -1;
        }
    }
    if (number == __NR_open) {
        const char* cpath = (const char*)a0;
        if (cpath != nullptr && (a1 & O_ACCMODE) == O_RDONLY) {
            long mfd = ServeSysfsSpoofFd(cpath, (int)a1);
            if (mfd >= 0) return mfd;
        }
    }
#endif
#ifdef __NR_socket
    if (number == __NR_socket) {
        long rc = BYTEHOOK_CALL_PREV(MySyscall, number, a0, a1, a2, a3, a4, a5);
        if (rc >= 0 && (int)a0 == AF_NETLINK) {
            pas::TrackNetlinkFd((int)rc, (int)a2);
        }
        return rc;
    }
#endif
#ifdef __NR_recvfrom
    if (number == __NR_recvfrom) {
        long rc = BYTEHOOK_CALL_PREV(MySyscall, number, a0, a1, a2, a3, a4, a5);
        if (rc > 0) rc = (long)pas::FilterNetlinkRecv((int)a0, (void*)a1, (ssize_t)rc);
        return rc;
    }
#endif
#ifdef __NR_read
    if (number == __NR_read) {
        long rc = BYTEHOOK_CALL_PREV(MySyscall, number, a0, a1, a2, a3, a4, a5);
        if (rc > 0) rc = (long)pas::FilterNetlinkRecv((int)a0, (void*)a1, (ssize_t)rc);
        return rc;
    }
#endif

    return BYTEHOOK_CALL_PREV(MySyscall, number, a0, a1, a2, a3, a4, a5);
}

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
                RdcClear(idx);
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

static DIR* MyOpendir(const char* name) {
    BYTEHOOK_STACK_SCOPE();
    ReconNote("opendir", name, 0);
    return BYTEHOOK_CALL_PREV(MyOpendir, name);
}

void InstallReconHooks() {
    HookLibcSym("opendir", (void*)MyOpendir);
    Log("native: recon hooks installed");
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