// NoVPNDetect native layer (libnvd.so)
//
// Hides VPN (tun0-style) interfaces from the scoped app process on all
// supported ABIs, including x86_64 emulators. PLT/GOT hooking is provided by
// ByteHook (https://github.com/bytedance/bhook, MIT).
//
// Loaded by LSPosed/Vector via META-INF/xposed/native_init.list ->
// System.loadLibrary("nvd") -> native_init().

#include "nvd.h"

#include <android/log.h>
#include <dlfcn.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mutex>
#include <string>
#include <vector>

#include "bytehook.h"

namespace nvd {

void Log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    __android_log_vprint(ANDROID_LOG_INFO, "NoVPNDetect", fmt, ap);
    va_end(ap);
}

void* RealSym(const char* sym) {
    void* h = dlopen("libc.so", RTLD_NOW);
    if (!h) return nullptr;
    return dlsym(h, sym);
}

// ---------------------------------------------------------------------------
// interface name rules (mirrors common VPN naming schemes)
// ---------------------------------------------------------------------------

static bool AllDigits(const char* s) {
    if (!s || !*s) return false;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return false;
    }
    return true;
}

bool IsHiddenIfaceName(const char* name) {
    if (!name || !*name) return false;
    struct Rule {
        const char* prefix;
        int kind;  // 0 = digits required, 1 = digits optional, 2 = anything
    };
    static const Rule kRules[] = {
        {"tun", 0},   {"tap", 0},    {"wg", 0},       {"gre", 0},    {"l2tp", 0},
        {"ppp", 0},   {"utun", 1},   {"tailscale", 1}, {"svpn", 1},
        {"pptp", 2},  {"zt", 2},     {"he-ipv6", 2},  {"ipsec", 2},  {"xfrm", 2},
    };
    for (const Rule& r : kRules) {
        size_t n = strlen(r.prefix);
        if (strncmp(name, r.prefix, n) != 0) continue;
        const char* rest = name + n;
        if (r.kind == 2) return true;
        if (r.kind == 1) return (*rest == '\0') || AllDigits(rest);
        if (r.kind == 0) return AllDigits(rest);
    }
    return false;
}

bool IsHiddenPath(const char* path) {
    if (!path || path[0] != '/') return false;
    static const char* kDirs[] = {
        "/sys/class/net/",
        "/sys/devices/virtual/net/",
        "/proc/sys/net/ipv4/conf/",
        "/proc/sys/net/ipv6/conf/",
        "/proc/sys/net/ipv4/neigh/",
        "/proc/sys/net/ipv6/neigh/",
    };
    for (const char* dir : kDirs) {
        size_t n = strlen(dir);
        if (strncmp(path, dir, n) != 0) continue;
        const char* rest = path + n;
        size_t seg = strcspn(rest, "/");
        if (seg == 0 || seg > IFNAMSIZ) continue;
        char buf[IFNAMSIZ + 1];
        memcpy(buf, rest, seg);
        buf[seg] = '\0';
        if (IsHiddenIfaceName(buf)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// hidden-name cache (resolved through the real libc, bypassing our hooks)
// ---------------------------------------------------------------------------

using if_nameindex_fn = struct if_nameindex* (*)();
using if_freenameindex_fn = void (*)(struct if_nameindex*);

static std::mutex g_names_mtx;
static std::vector<std::string> g_names;
static std::vector<unsigned int> g_indices;
static long long g_last_refresh_ms = 0;

static long long NowMs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void RefreshHiddenNames(bool force) {
    std::lock_guard<std::mutex> lk(g_names_mtx);
    long long now = NowMs();
    if (!force && (now - g_last_refresh_ms) < 5000) return;
    g_last_refresh_ms = now;
    g_names.clear();
    g_indices.clear();

    auto ni = (if_nameindex_fn)RealSym("if_nameindex");
    auto nf = (if_freenameindex_fn)RealSym("if_freenameindex");
    if (!ni) return;
    struct if_nameindex* arr = ni();
    if (!arr) return;
    for (struct if_nameindex* it = arr; it->if_index != 0 && it->if_name != nullptr; ++it) {
        if (IsHiddenIfaceName(it->if_name)) {
            g_names.emplace_back(it->if_name);
            g_indices.push_back(it->if_index);
        }
    }
    if (nf) nf(arr);
    if (!g_names.empty()) {
        Log("native: hidden interfaces: %zu (first: %s)", g_names.size(), g_names[0].c_str());
    }
}

bool LineContainsHiddenName(const char* line) {
    if (!line) return false;
    std::lock_guard<std::mutex> lk(g_names_mtx);
    for (const std::string& n : g_names) {
        if (strstr(line, n.c_str())) return true;
    }
    return false;
}

bool LineContainsProxyPortToken(const char* line) {
    // 5555 decimal = 0x15B3, procfs prints ports as %04X
    return line && strstr(line, ":15B3") != nullptr;
}

bool IsHiddenIndex(unsigned int ifindex) {
    RefreshHiddenNames(false);
    std::lock_guard<std::mutex> lk(g_names_mtx);
    for (unsigned int idx : g_indices) {
        if (idx == ifindex) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// copy registry (filtered lists handed back to callers)
// ---------------------------------------------------------------------------

static std::mutex g_copy_mtx;
static std::vector<void*> g_copy_heads;

bool RegisterCopy(void* head) {
    std::lock_guard<std::mutex> lk(g_copy_mtx);
    g_copy_heads.push_back(head);
    return true;
}

bool UnregisterCopy(void* head) {
    std::lock_guard<std::mutex> lk(g_copy_mtx);
    for (size_t i = 0; i < g_copy_heads.size(); i++) {
        if (g_copy_heads[i] == head) {
            g_copy_heads[i] = g_copy_heads.back();
            g_copy_heads.pop_back();
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// hook installation
// ---------------------------------------------------------------------------

static void OnHooked(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                     const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub;
    (void)new_func;
    (void)arg;
    Log("native: hook %s <- %s status=%d", sym_name ? sym_name : "?",
        caller_path_name ? caller_path_name : "?", status_code);
}

void HookLibcSym(const char* sym, void* proxy) {
    bytehook_stub_t stub = bytehook_hook_all("libc.so", sym, proxy, OnHooked, nullptr);
    if (!stub) Log("native: bytehook_hook_all failed for %s", sym);
}

static void OnModuleLoadedCb(const char* name, void* handle) {
    (void)name;
    (void)handle;
}

}  // namespace nvd

// ---------------------------------------------------------------------------
// LSPosed native entry point
// ---------------------------------------------------------------------------

extern "C" __attribute__((visibility("default"))) __attribute__((used))
NativeOnModuleLoaded native_init(const NativeAPIEntries* entries) {
    (void)entries;
    int rc = bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
    nvd::Log("native: init rc=%d version=%s mode=%d", rc, bytehook_get_version(),
             bytehook_get_mode());
    nvd::RefreshHiddenNames(true);
    nvd::InstallIfaceHooks();
    nvd::InstallFsHooks();
    nvd::InstallNetHooks();
    nvd::Log("native: hooks installed");
    return nvd::OnModuleLoadedCb;
}
