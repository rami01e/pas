//pas.cpp v2.9.0
// PerAppSpoofer native layer (libpas.so)
//
// Hides VPN (tun0-style) interfaces from the scoped app process on all
// supported ABIs, including x86_64 emulators. PLT/GOT hooking is provided by
// ByteHook (https://github.com/bytedance/bhook, MIT).
//
// v2.9.0:
//  - ANTI-EMU ships: hide_antiemu.cpp carries the native layer and
//    InitWorker installs its hooks (runtime-gated on the Kotlin
//    nativeSetAntiEmu toggle). The DevInfo Vulkan leak fix stays in
//    hide_vulkan.cpp.
//  - The v2.8.0 Kona prop guard experiment stays retired: it force-closed
//    every scoped app at start and the idea was dropped for good.
// v1.2.4 hardening:
//  - native_init() returns immediately and performs ALL initialization on a
//    detached worker thread, so nothing here can ever block app startup.
//  - No dlopen()/dlsym() is used anywhere (the previous version deadlocked on
//    the dynamic linker's mutex because the calls happened inside the loader's
//    own context while loading the module library).
//  - The hidden-interface list is read directly from /proc/net/dev (plus
//    /sys/class/net/<name>/ifindex) via raw syscalls.

#include "pas.h"

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <net/if.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

#include "bytehook.h"

namespace pas {

void Log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    __android_log_vprint(ANDROID_LOG_INFO, "PerAppSpoofer", fmt, ap);
    va_end(ap);
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
    // "WebRTC local IP" relaxed mode keeps every interface visible so
    // browsers can gather local (host) candidates like a clean device.
    // Mode 3 (JAVA) lets the Java layer handle spoofing: the native layer
    // stays fully passthrough so network debugging is unobstructed.
    if (WebRtcMode() == 0) return false;
    if (WebRtcMode() == 3) return false;
    if (WebRtcMode() == 1 && ProcessLooksBrowser()) return false;
    if (!name || !*name) return false;
    struct Rule {
        const char* prefix;
        int kind;  // 0 = digits required, 1 = digits optional, 2 = anything
    };
    static const Rule kRules[] = {
        {"tun", 0},   {"tap", 0},    {"wg", 0},       {"gre", 0},    {"l2tp", 0},
        {"ppp", 0},   {"utun", 1},   {"tailscale", 1}, {"svpn", 1},
        {"pptp", 2},  {"zt", 2},     {"he-ipv6", 2},  {"ipsec", 2},  {"xfrm", 2},
        // Emulator / userspace-tunnel naming: MuMu and several userspace
        // WireGuard backends (wgtunnel, wireguard-go variants) create
        // interfaces named if0, if1, ... ifN. They do not exist on stock
        // Android, so hiding them is safe on real devices and necessary
        // on emulators. Digits required so a hypothetical non-numeric
        // "if..." prefix is left alone.
        {"if", 0},
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

// Syscall-safe variant: no mutexes, no lazy refresh, no recursion into
// hooked APIs. RenderThread calls syscall() while holding graphics locks;
// anything blocking here deadlocks the whole render pipeline (observed as
// RenderProxy::setStopped ANR). Static prefixes only.
bool IsHiddenPathFast(const char* path) {
    if (!path || path[0] != '/') return false;
    if (WebRtcMode() == 0 || WebRtcMode() == 3) return false;
    static const char* kDirs[] = {
        "/sys/class/net/",
        "/sys/devices/virtual/net/",
        "/proc/sys/net/ipv4/conf/",
        "/proc/sys/net/ipv6/conf/",
        "/proc/sys/net/ipv4/neigh/",
        "/proc/sys/net/ipv6/neigh/",
    };
    for (const char* dir : kDirs) {
        if (strncmp(path, dir, strlen(dir)) != 0) continue;
        const char* rest = path + strlen(dir);
        static const char* kIfacePrefixes[] = {
            "tun", "tap", "wg", "gre", "l2tp", "ppp", "pptp", "zt",
            "utun", "tailscale", "svpn", "he-ipv6", "ipsec", "xfrm",
            "if",   // emulator / userspace-tunnel naming (if0, if1, ...)
        };
        for (const char* pre : kIfacePrefixes) {
            size_t n = strlen(pre);
            if (strncmp(rest, pre, n) == 0) return true;
        }
        return false;
    }
    if (strncmp(path, "/proc/net/", 10) == 0) {
        static const char* kNetFiles[] = {
            "dev", "if_inet6", "route", "tcp", "tcp6", "udp", "udp6",
            "unix", "arp", "igmp", "igmp6", "packet", "ptype",
        };
        const char* base = path + 10;
        for (const char* f : kNetFiles) {
            if (strcmp(base, f) == 0) return true;
        }
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
// raw syscall file reading (no libc wrappers, no hooks, no linker involvement)
// ---------------------------------------------------------------------------

static ssize_t SysReadFile(const char* path, char* buf, size_t cap) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    size_t off = 0;
    for (;;) {
        if (off >= cap - 1) break;
        ssize_t n = syscall(SYS_read, fd, buf + off, cap - 1 - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        off += (size_t)n;
    }
    syscall(SYS_close, fd);
    buf[off] = '\0';
    return (ssize_t)off;
}

static bool ReadIfIndexSys(const char* name, unsigned int* out) {
    static const char kPre[] = "/sys/class/net/";
    static const char kSuf[] = "/ifindex";
    char path[256];
    size_t pl = sizeof(kPre) - 1;
    size_t nl = strlen(name);
    size_t sl = sizeof(kSuf) - 1;
    if (pl + nl + sl + 1 > sizeof(path)) return false;
    memcpy(path, kPre, pl);
    memcpy(path + pl, name, nl);
    memcpy(path + pl + nl, kSuf, sl + 1);
    char buf[32];
    ssize_t n = SysReadFile(path, buf, sizeof(buf));
    if (n <= 0) return false;
    unsigned int v = 0;
    bool any = false;
    for (ssize_t i = 0; i < n; i++) {
        char c = buf[i];
        if (c >= '0' && c <= '9') {
            v = v * 10 + (unsigned int)(c - '0');
            any = true;
        } else if (any) {
            break;
        }
    }
    if (!any) return false;
    *out = v;
    return true;
}

// ---------------------------------------------------------------------------
// hidden-name cache (rebuilt from /proc/net/dev - no libc calls at all)
// ---------------------------------------------------------------------------

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

    char* buf = (char*)malloc(65536);
    if (!buf) return;
    ssize_t len = SysReadFile("/proc/net/dev", buf, 65536);
    if (len > 0) {
        char* p = buf;
        while (p && *p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            char* colon = strchr(p, ':');
            if (colon) {
                *colon = '\0';
                char* nm = p;
                while (*nm == ' ' || *nm == '\t') nm++;
                if (*nm && IsHiddenIfaceName(nm)) {
                    g_names.emplace_back(nm);
                    unsigned int idx = 0;
                    if (ReadIfIndexSys(nm, &idx)) g_indices.push_back(idx);
                }
            }
            if (!nl) break;
            p = nl + 1;
        }
    }
    free(buf);
    if (!g_names.empty()) {
        Log("native: hidden interfaces: %zu (first: %s)", g_names.size(), g_names[0].c_str());
    }
}

static std::atomic<int> g_webrtc_mode{1};  // 0 relaxed / 1 balanced (default) / 2 rkn

int WebRtcMode() {
    return g_webrtc_mode.load();
}

void SetWebRtcMode(int mode) {
    if (mode < 0 || mode > 3) mode = 0;
    g_webrtc_mode.store(mode);
    Log("native: webrtc mode=%d", mode);
    RefreshHiddenNames(true);
}

// Net-type spoof (per-app): when cellular is requested, the interface hiding
// layer also renames wlan entries so Java and native views agree that the
// device is on MOBILE/LTE rather than WIFI.
static volatile bool g_net_cellular = false;

void SetNetCellular(bool cellular) {
    g_net_cellular = cellular;
    Log("native: net cellular %s", cellular ? "on (MOBILE/LTE)" : "off (WIFI)");
    RefreshHiddenNames(true);
}

bool NetCellularSpoof() {
    return g_net_cellular;
}

void SetBootloaderValue(const char* value) {
    Log("native: bootloader spoof %s", (value && value[0]) ? value : "(off)");
}

// ---------------------------------------------------------------------------
// balanced mode: browser-caller detection via /proc/self/maps ranges
// ---------------------------------------------------------------------------

struct BrowserRange {
    unsigned long long lo;
    unsigned long long hi;
};

static std::mutex g_bmap_mtx;
static std::vector<BrowserRange> g_browser_ranges;
static long long g_bmap_last = 0;

static void RefreshBrowserRangesLocked() {
    g_browser_ranges.clear();
    size_t cap = 1 << 20;
    char* buf = (char*)malloc(cap);
    if (!buf) return;
    ssize_t len = SysReadFile("/proc/self/maps", buf, cap - 1);
    if (len > 0) {
        buf[len] = '\0';
        char* p = buf;
        while (p && *p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if ((strstr(p, "chrome") || strstr(p, "webviewchromium") ||
                 strstr(p, "monochrome")) &&
                strstr(p, "r-x")) {
                unsigned long long lo = strtoull(p, nullptr, 16);
                char* dash = strchr(p, '-');
                unsigned long long hi = dash ? strtoull(dash + 1, nullptr, 16) : 0;
                if (hi > lo) {
                    BrowserRange r;
                    r.lo = lo;
                    r.hi = hi;
                    g_browser_ranges.push_back(r);
                }
            }
            if (!nl) break;
            p = nl + 1;
        }
    }
    free(buf);
}

static void MaybeRefreshRangesLocked() {
    long long now = NowMs();
    long long span = g_browser_ranges.empty() ? 2000 : 5000;
    if (g_bmap_last == 0 || (now - g_bmap_last) > span) {
        g_bmap_last = now;
        RefreshBrowserRangesLocked();
    }
}

// RKN mode: relax only when the caller is browser-family code (detectors,
// which call from their own libraries, still get the hidden view).
bool BrowserCallerHere(void* ra) {
    if (WebRtcMode() != 2) return false;
    if (ra == nullptr) return false;
    unsigned long long a = (unsigned long long)ra;
    std::lock_guard<std::mutex> lk(g_bmap_mtx);
    MaybeRefreshRangesLocked();
    for (size_t i = 0; i < g_browser_ranges.size(); i++) {
        if (a >= g_browser_ranges[i].lo && a < g_browser_ranges[i].hi) return true;
    }
    return false;
}

static volatile int g_proc_browser_named = -1;  // -1 unknown, 0 no, 1 yes

static bool CmdlineIsBrowserNamed() {
    char buf[256];
    ssize_t n = SysReadFile("/proc/self/cmdline", buf, sizeof(buf) - 1);
    if (n <= 0) return false;
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }
    buf[n] = '\0';
    return strstr(buf, "chrome") != nullptr || strstr(buf, "webview") != nullptr;
}

// Balanced mode: relax the whole process only when it is a browser-owned
// process (Chrome / the WebView provider). Apps that merely embed a WebView
// keep the hidden view so detectors running in them stay consistent.
bool ProcessLooksBrowser() {
    if (WebRtcMode() != 1) return false;
    int named = g_proc_browser_named;
    if (named < 0) {
        named = CmdlineIsBrowserNamed() ? 1 : 0;
        g_proc_browser_named = named;
    }
    if (named != 1) return false;
    std::lock_guard<std::mutex> lk(g_bmap_mtx);
    MaybeRefreshRangesLocked();
    return !g_browser_ranges.empty();
}

bool LineContainsHiddenName(const char* line) {
    if (!line) return false;
    std::lock_guard<std::mutex> lk(g_names_mtx);
    for (const std::string& n : g_names) {
        if (strstr(line, n.c_str())) return true;
    }
    // Net-type spoof: while cellular mode is on, hide WIFI entries from
    // proc/net views so MOBILE is the only reported source.
    if (NetCellularSpoof() && strstr(line, "wlan") != nullptr) return true;
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
// hook installation & async init
// ---------------------------------------------------------------------------

static void OnHooked(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                     const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub;
    (void)new_func;
    (void)prev_func;
    (void)arg;
    // Successful chaining is routine and extremely chatty (hundreds of lines
    // per process); keep only failures on the log. "dlsym" is exempt: its
    // activation is rare and is the key signal while diagnosing GL resolution
    // for browser-style consumers.
    const char* sym = sym_name ? sym_name : "?";
    if (status_code == 0 && strcmp(sym, "dlsym") != 0) return;
    Log("native: hook %s <- %s status=%d", sym, caller_path_name ? caller_path_name : "?",
        status_code);
}

// ---------------------------------------------------------------------------
// caller filter for bytehook: never hook ARM-translated application libraries
// (they execute through the emulator's native bridge; patching their PLT/GOT
// with our x86_64 assumptions corrupts translated code) nor the translation /
// bridge support libraries themselves.
// ---------------------------------------------------------------------------

static void LogSkipOnce(const char* path) {
    static char logged[16][160];
    static int loggedCount = 0;
    for (int i = 0; i < loggedCount; i++) {
        if (strncmp(logged[i], path, sizeof(logged[i]) - 1) == 0) return;
    }
    if (loggedCount < 16) {
        strncpy(logged[loggedCount], path, sizeof(logged[0]) - 1);
        logged[loggedCount][sizeof(logged[0]) - 1] = '\0';
        loggedCount++;
    }
    Log("native: hook skip <- %s", path);
}

static bool CallerAllow(const char* caller_path_name, void* arg) {
    (void)arg;
    if (!caller_path_name) return true;
    static const char* const kSkip[] = {
        "!/lib/arm",        // base.apk!/lib/arm64-v8a/... / armeabi-v7a / armeabi
        "/libnb.so",        // emulator native bridge executor
        "libnativebridge",  // ART native-bridge client
        "libhoudini",       // other emulator translators
        "libndk_translation",
        "libhp",            // emulator shared modules (libhp14_x86_64.so)
        "mumu-configs",
        "libpas.so",        // ourselves
        "libbytehook.so",   // bytehook internals (avoid resolver recursion)
    };
    for (size_t i = 0; i < sizeof(kSkip) / sizeof(kSkip[0]); i++) {
        if (strstr(caller_path_name, kSkip[i]) != nullptr) {
            LogSkipOnce(caller_path_name);
            return false;
        }
    }
    return true;
}

bool CallerAllowHooks(const char* caller_path_name, void* arg) {
    return CallerAllow(caller_path_name, arg);
}

// Graphics-family callers only: used for the dlsym loader chain so the
// process-wide loader stays untouched for unrelated libraries.
bool CallerAllowGfx(const char* caller_path_name, void* arg) {
    if (!CallerAllow(caller_path_name, arg)) return false;
    if (!caller_path_name) return false;
    // The EGL / Vulkan API loaders must keep their own dlsym results raw:
    // their initialization walks the function tables built from them, and a
    // substituted pointer there corrupts display init (observed as SIGSEGV
    // inside egl_display_t::initialize with a non-canonical string pointer).
    // Consumers (engines, hwui, angle, skia) keep the full chain.
    if (strstr(caller_path_name, "/libEGL.so") != nullptr) return false;
    if (strstr(caller_path_name, "/libvulkan.so") != nullptr) return false;
    static const char* const kGfx[] = {
        "GLES", "EGL", "libvulkan", "chrome", "webview", "monochrome", "hwui", "angle", "skia",
    };
    for (size_t i = 0; i < sizeof(kGfx) / sizeof(kGfx[0]); i++) {
        if (strstr(caller_path_name, kGfx[i]) != nullptr) return true;
    }
    return false;
}

void* HookChainStubGfx(const char* owner_regex, const char* sym, void* proxy) {
    return (void*)bytehook_hook_partial(CallerAllowGfx, nullptr, owner_regex, sym, proxy, OnHooked,
                                        nullptr);
}

// v2.6.5: dlsym-chain caller filter. Broader than CallerAllowGfx: Houdini's
// forwarding machinery (libnb.so / libhp*.so / libhoudini.so / mumu helpers)
// resolves the ARM public-library shims' symbols via libc dlsym, and those
// callers were excluded by the translated-code skip list - so ARM-translated
// apps (e.g. DevCheck on MuMu) never received spoofed pointers. The dlsym
// chain never patches translated code: it only substitutes the RETURN VALUE
// of dlsym, which Houdini then bridges into ARM exactly like a real pointer.
// The EGL / Vulkan API loaders keep their own dlsym results raw (same
// display-init corruption guard as CallerAllowGfx).
bool CallerAllowDlsymChain(const char* caller_path_name, void* arg) {
    (void)arg;
    if (!caller_path_name) return true;
    static const char* const kSkip[] = {
        "libpas.so",      // ourselves (recursion guard)
        "libbytehook.so", // bytehook internals
    };
    for (size_t i = 0; i < sizeof(kSkip) / sizeof(kSkip[0]); i++) {
        if (strstr(caller_path_name, kSkip[i]) != nullptr) return false;
    }
    // Keep the API loaders' own dlsym raw (display-init corruption guard).
    if (strstr(caller_path_name, "/libEGL.so") != nullptr) return false;
    if (strstr(caller_path_name, "/libvulkan.so") != nullptr) return false;
    return true;
}

void* HookChainStubDlsymChain(const char* owner_regex, const char* sym, void* proxy) {
    return (void*)bytehook_hook_partial(CallerAllowDlsymChain, nullptr, owner_regex, sym, proxy,
                                        OnHooked, nullptr);
}

void HookLibcSym(const char* sym, void* proxy) {
    bytehook_stub_t stub = bytehook_hook_partial(CallerAllow, nullptr, "libc.so", sym, proxy,
                                                 OnHooked, nullptr);
    if (!stub) Log("native: bytehook_hook_partial failed for %s", sym);
}

void* HookChainStub(const char* owner_regex, const char* sym, void* proxy) {
    return (void*)bytehook_hook_partial(CallerAllow, nullptr, owner_regex, sym, proxy, OnHooked,
                                        nullptr);
}

static void OnModuleLoadedCb(const char* name, void* handle) {
    (void)name;
    (void)handle;
}

// ---------------------------------------------------------------------------
// hook-installation gate (see pas.h)
// ---------------------------------------------------------------------------

static volatile bool g_light_mode = false;

void SetLightMode(bool light) {
    g_light_mode = light;
    Log("native: light mode %s", light ? "on" : "off");
}

static pthread_mutex_t g_cfg_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cfg_cv = PTHREAD_COND_INITIALIZER;
static bool g_cfg_ready = false;
static bool g_cfg_compat = false;
static bool g_cfg_native = true;

void SignalSpoofConfigReady(bool compatMode, bool nativeEnabled) {
    pthread_mutex_lock(&g_cfg_mtx);
    g_cfg_compat = compatMode;
    g_cfg_native = nativeEnabled;
    g_cfg_ready = true;
    pthread_cond_broadcast(&g_cfg_cv);
    pthread_mutex_unlock(&g_cfg_mtx);
}

bool WaitSpoofConfigReady(int timeoutMs, bool* compatOut, bool* nativeOut) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeoutMs / 1000;
    ts.tv_nsec += (long)(timeoutMs % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&g_cfg_mtx);
    while (!g_cfg_ready) {
        if (pthread_cond_timedwait(&g_cfg_cv, &g_cfg_mtx, &ts) != 0) break;
    }
    bool ready = g_cfg_ready;
    if (compatOut) *compatOut = g_cfg_compat;
    if (nativeOut) *nativeOut = g_cfg_native;
    pthread_mutex_unlock(&g_cfg_mtx);
    return ready;
}

static std::string ProcName() {
    char buf[256];
    int fd = (int)syscall(__NR_openat, AT_FDCWD, "/proc/self/cmdline", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return std::string("?");
    ssize_t n = syscall(__NR_read, fd, buf, sizeof(buf) - 1);
    syscall(__NR_close, fd);
    if (n <= 0) return std::string("?");
    buf[n] = '\0';
    return std::string(buf);
}

static void* InitWorker(void* arg) {
    (void)arg;
    Log("native: worker start");

    // Zygote processes only exist to fork children; hooks installed here are
    // inherited by every forked child (this is how sandboxed WebView
    // renderers were getting poisoned). The module never runs in a zygote.
    {
        char cbuf[256];
        ssize_t cn = SysReadFile("/proc/self/cmdline", cbuf, sizeof(cbuf) - 1);
        if (cn > 0) {
            for (ssize_t i = 0; i < cn; i++) {
                if (cbuf[i] == '\0') cbuf[i] = ' ';
            }
            cbuf[cn] = '\0';
            if (strstr(cbuf, "zygote") != nullptr) {
                Log("native: zygote process - module inert (%s)", cbuf);
                return nullptr;
            }
        }
    }

    // v2.5.10: GPU identity hooks go in FIRST - before the config wait and
    // before every other hook group. Chrome's ANGLE resolves its GL function
    // pointers within the first few hundred ms of the GPU process; previously
    // the GL hooks landed last (~400 ms in, after names/iface/fs/cpu), so
    // ANGLE had already cached the real GPU strings (Adreno 640 on MuMu) and
    // our hooks never fired (verified: zero recon glgs/eglgpa lines with
    // recon enabled). All these hooks are runtime-gated (GpuSpoofActive /
    // VulkanSpoofActive / WaitForGpuConfig), so installing them before the
    // config arrives is safe - they pass through until it lands.
    int rc = bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
    Log("native: stage0 bytehook rc=%d version=%s mode=%d", rc, bytehook_get_version(),
        bytehook_get_mode());
    InstallGpuHooks();
    InstallGpuDlsymChain();
    InstallVulkanHooks();
    InstallVulkanInlineBackstop();
    Log("native: stage0g gpu identity hooks installed early (runtime-gated)");

    // The Kotlin side delivers the configuration first: with the native addon
    // disabled nothing is installed at all (module behaves like the original,
    // Java-only); compatibility mode skips just the extended hook groups.
    // Note: if the addon turns out to be disabled here, the GPU hooks above
    // stay installed but inert - every spoof flag is false without a config.
    bool compat = false;
    bool nativeOn = true;
    bool ready = WaitSpoofConfigReady(2500, &compat, &nativeOn);
    Log("native: config ready=%d compat=%d native=%d cpu=%d gpu=%d recon=%d proc=%s",
        (int)ready, (int)compat, (int)nativeOn, (int)CpuSpoofActive(), (int)GpuSpoofActive(),
        (int)ReconEnabled(), ProcName().c_str());
    if (!nativeOn) {
        Log("native: addon disabled by user - no further hooks installed");
        return nullptr;
    }

    // Light mode: identity-only spoof (delivered from Kotlin). Skips the
    // heavyweight groups (recon, net, cpu-deep) - the fast path for bisecting
    // stubborn apps. The GPU identity hooks above stay: they are cheap PLT
    // substitutions and the identity spoof is the point of light mode.
    bool light = g_light_mode;
    if (light) {
        Log("native: light mode - heavy groups skipped");
    }
    RefreshHiddenNames(true);
    Log("native: stage2 names cached");
    // v2.9.5: the prop and anti-emu/anti-root hook groups are fully
    // runtime-gated (the toggle decides at call time), so they install
    // FIRST after the config. The JJ capture showed the target's
    // first-second detection probes (access /system/xbin/su, identity
    // props) racing ahead of the late stage5/stage5b installs and hitting
    // an unhooked process. Nothing else here is order-sensitive; coverage
    // is.
    if (!compat) {
        InstallPropSpoofHooks();
        Log("native: stage2b prop hooks (early)");
    }
    InstallAntiEmuHooks();
    Log("native: stage2c anti-emu hooks (early)");
    if (!light) {
        InstallIfaceHooks();
        Log("native: stage3 iface hooks");
    }
    InstallFsHooks();
    Log("native: stage4 fs hooks");
    if (!light && CpuSpoofActive()) {
        InstallCpuDeepHooks();
        Log("native: stage4a cpu deep hooks");
    } else {
        Log("native: cpu deep hooks skipped (light=%d)", (int)light);
    }
    // v2.5.10: GPU hooks were already installed at stage0g (before the config
    // wait) so Chrome's ANGLE cannot resolve GL identity ahead of them.
    if (!light && ReconEnabled()) {
        InstallReconHooks();
        Log("native: stage4c recon hooks");
    }
    // Native TLS verification bypass (SSL_set_verify / X509_verify_cert).
    if (SslUnpinActive()) {
        InstallSslHooks();
        Log("native: stage4d ssl unpin hooks");
    } else {
        Log("native: ssl unpin off - ssl hooks skipped");
    }
    // ARM64 inline-hook SSL path (ShadowHook). Runs only when the native
    // addon and SSL unpin are both on; harmless no-op otherwise.
    if (SslArm64Active() && SslUnpinActive()) {
        InstallSslArm64Hooks();
        Log("native: stage4e ssl-arm64 hooks");
    } else {
        Log("native: ssl-arm64 hooks skipped");
    }
    // setsockopt (SO_BINDTODEVICE hiding) is a core hiding primitive and stays
    // on in every mode, including compatibility mode.
    InstallNetHooks();
    Log("native: stage5 net hooks");

    if (!compat) {
        InstallNetlinkHooks();
        InstallIoctlHooks();
        Log("native: stage5 extended hooks (netlink/ioctl; props installed early)");
    } else {
        Log("native: compat mode - extended hooks skipped (netlink/ioctl/props)");
    }
    // v2.9.0/v2.9.5: ANTI-EMU (hide_antiemu.cpp) is runtime-gated on the
    // Kotlin toggle (SpoofCore.nativeSetAntiEmu) and now installs early
    // (stage2c) - the toggle is the switch, not compat mode.
    Log("native: all hooks installed");
    return nullptr;
}

void StartInitWorker();

static void SpawnInitWorker() {
    pthread_t t;
    if (pthread_create(&t, nullptr, InitWorker, nullptr) == 0) {
        pthread_detach(t);
    } else {
        Log("native: pthread_create failed");
    }
}

void StartInitWorker() {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, SpawnInitWorker);
}

// --- v2.3.9: raw-syscall netlink tracking ---
void TrackNetlinkFd(int fd, int protocol);
ssize_t FilterNetlinkRecv(int fd, void* buf, ssize_t len);

}  // namespace pas

// ---------------------------------------------------------------------------
// Entry points. JNI_OnLoad is the real entry now: the library is loaded
// lazily from Kotlin (System.loadLibrary) only when the native addon is
// enabled, so with the addon off the process never sees this library at all.
// native_init is kept for compatibility but is no longer advertised through
// native_init.list (which would force Vector to load the library into every
// scoped process).
// ---------------------------------------------------------------------------

extern "C" __attribute__((visibility("default"))) __attribute__((used)) jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)vm;
    (void)reserved;
    pas::Log("native: JNI_OnLoad - starting worker thread");
    pas::StartInitWorker();
    return JNI_VERSION_1_6;
}

extern "C" __attribute__((visibility("default"))) __attribute__((used))
NativeOnModuleLoaded native_init(const NativeAPIEntries* entries) {
    (void)entries;
    pas::Log("native: native_init entry - starting worker thread");
    pas::StartInitWorker();
    return pas::OnModuleLoadedCb;
}