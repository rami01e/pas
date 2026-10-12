// CPU model / GPU (OpenGL) spoof for the scoped process.
//
// v2.4.5: GPU now carries core count, L2 cache and architecture so that
// DevCheck's Mali probe (which reads gpuinfo / core_mask / sysfs) sees a
// coherent device instead of only a name string.

#include "pas.h"

#include <jni.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include "bytehook.h"

namespace pas {

static volatile bool g_cpu_on = false;
static char g_cpu_display[192] = {0};
static char g_cpu_mfr[64] = {0};
static char g_cpu_model[64] = {0};
static char g_cpu_part[16] = {0};
static char g_cpu_implementer[8] = {0};
static char g_cpu_info_model[96] = {0};
static char g_cpu_features[256] = {0};
static char g_cpu_hwline[256] = {0};
static char g_cpu_hardware[64] = {0};
static char g_cpu_clusters[32] = {0};
// v2.5.9: parsed per-cluster table from the catalog clusterSpec string.
static PasCpuCluster g_cpu_cluster_table[8] = {};
static int g_cpu_cluster_count = 0;
static volatile int g_cpu_min_khz = 0;
static volatile int g_cpu_max_khz = 0;

static volatile bool g_gpu_on = false;
// v2.5.9: set once SetGpuConfig has run (whether gpu spoof ends up on or
// off). Early GL/Vulkan identity queries wait briefly for this so the
// target's GL init cannot win the race against the config thread.
static pthread_mutex_t g_gpu_cfg_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_gpu_cfg_cv = PTHREAD_COND_INITIALIZER;
static volatile bool g_gpu_cfg_seen = false;
static volatile bool g_gpu_chain_on = true;
static volatile bool g_gpu_vulkan_on = true;
static char g_gpu_vendor[64] = {0};
static char g_gpu_renderer[192] = {0};
static char g_gpu_vk_device_name[192] = {0};
static char g_gpu_gl_version[192] = {0};
static volatile unsigned long long g_gpu_vendor_id = 0;
static volatile unsigned long long g_gpu_device_id = 0;
static volatile unsigned long long g_gpu_driver_version = 0;
static volatile unsigned long long g_gpu_api_version = 0;
static char g_gpu_driver_name[192] = {0};
static char g_gpu_driver_info[256] = {0};
// v2.4.5: physical characteristics DevCheck probes for Mali GPUs.
static volatile int g_gpu_cores = 1;
static volatile int g_gpu_l2_cache_kb = 64;
static char g_gpu_arch[32] = {0};

static void CopyStr(char* dst, size_t cap, const char* src) {
    snprintf(dst, cap, "%s", src ? src : "");
}

void SetCpuConfig(bool cpuOn, const char* display, const char* mfr, const char* model,
                  const char* part, const char* cpuInfoModel, const char* features, int minKHz,
                  int maxKHz, const char* hwLine, const char* implementer,
                  const char* hardware) {
    g_cpu_on = false;
    CopyStr(g_cpu_display, sizeof(g_cpu_display), display);
    CopyStr(g_cpu_mfr, sizeof(g_cpu_mfr), mfr);
    CopyStr(g_cpu_model, sizeof(g_cpu_model), model);
    CopyStr(g_cpu_part, sizeof(g_cpu_part), part);
    if (implementer != nullptr && implementer[0] != '\0') {
        CopyStr(g_cpu_implementer, sizeof(g_cpu_implementer), implementer);
    } else {
        CopyStr(g_cpu_implementer, sizeof(g_cpu_implementer), "0x41");
    }
    CopyStr(g_cpu_info_model, sizeof(g_cpu_info_model), cpuInfoModel);
    CopyStr(g_cpu_features, sizeof(g_cpu_features), features);
    CopyStr(g_cpu_hwline, sizeof(g_cpu_hwline), hwLine);
    CopyStr(g_cpu_hardware, sizeof(g_cpu_hardware), hardware);
    g_cpu_min_khz = minKHz;
    g_cpu_max_khz = maxKHz;
    g_cpu_on = cpuOn && g_cpu_display[0] != '\0';
    Log("native: cpu config on=%d display=%s part=%s impl=%s hw=%s khz=%d-%d", (int)g_cpu_on,
        g_cpu_display, g_cpu_part, g_cpu_implementer, g_cpu_hardware, (int)g_cpu_min_khz,
        (int)g_cpu_max_khz);
}

void SetCpuClusters(bool cpuOn, const char* clusters, const char* clusterSpec) {
    if (clusters != nullptr && clusters[0] != '\0') {
        CopyStr(g_cpu_clusters, sizeof(g_cpu_clusters), clusters);
    } else {
        CopyStr(g_cpu_clusters, sizeof(g_cpu_clusters), "4+4");
    }
    // v2.5.9: parse "cores:part:minKHz:maxKHz:revision;..." into the cluster
    // table. Segments with unusable numbers are skipped; a spec that yields no
    // valid cluster leaves the table empty so every consumer falls back to the
    // legacy global part / freq values.
    g_cpu_cluster_count = 0;
    int totalBefore = 0;
    if (clusterSpec != nullptr && clusterSpec[0] != '\0') {
        const char* p = clusterSpec;
        while (*p != '\0' && g_cpu_cluster_count < (int)(sizeof(g_cpu_cluster_table) /
                                                          sizeof(g_cpu_cluster_table[0]))) {
            long cores = strtol(p, (char**)&p, 10);
            if (*p != ':' || cores <= 0) break;
            p++;
            const char* partStart = p;
            while (*p != '\0' && *p != ':') p++;
            if (*p != ':' || p == partStart) break;
            size_t partLen = (size_t)(p - partStart);
            p++;
            long minKHz = strtol(p, (char**)&p, 10);
            if (*p != ':' || minKHz <= 0) break;
            p++;
            long maxKHz = strtol(p, (char**)&p, 10);
            if (*p != ':' || maxKHz < minKHz) break;
            p++;
            const char* revStart = p;
            while (*p != '\0' && *p != ';' && *p != ':') p++;
            size_t revLen = (size_t)(p - revStart);
            PasCpuCluster& cl = g_cpu_cluster_table[g_cpu_cluster_count];
            cl.cores = (int)cores;
            cl.totalBefore = totalBefore;
            size_t n = partLen < sizeof(cl.part) - 1 ? partLen : sizeof(cl.part) - 1;
            memcpy(cl.part, partStart, n);
            cl.part[n] = '\0';
            cl.minKHz = (int)minKHz;
            cl.maxKHz = (int)maxKHz;
            n = revLen < sizeof(cl.revision) - 1 ? revLen : sizeof(cl.revision) - 1;
            memcpy(cl.revision, revStart, n);
            cl.revision[n] = '\0';
            g_cpu_cluster_count++;
            totalBefore += (int)cores;
            if (*p == ';') p++;
        }
    }
    Log("native: cpu clusters on=%d layout=%s specClusters=%d", (int)cpuOn, g_cpu_clusters,
        g_cpu_cluster_count);
}

void SetGpuConfig(bool gpuOn, const char* vendor, const char* renderer, const char* glVersion,
                  unsigned long long vendorId, unsigned long long deviceId,
                  unsigned long long driverVersion, unsigned long long apiVersion,
                  const char* driverName, const char* driverInfo,
                  const char* vkDeviceName, int gpuCores, int l2CacheKb,
                  const char* gpuArch) {
    g_gpu_on = false;
    CopyStr(g_gpu_vendor, sizeof(g_gpu_vendor), vendor);
    CopyStr(g_gpu_renderer, sizeof(g_gpu_renderer), renderer);
    if (vkDeviceName != nullptr && vkDeviceName[0] != '\0') {
        CopyStr(g_gpu_vk_device_name, sizeof(g_gpu_vk_device_name), vkDeviceName);
    } else {
        CopyStr(g_gpu_vk_device_name, sizeof(g_gpu_vk_device_name), renderer);
    }
    CopyStr(g_gpu_gl_version, sizeof(g_gpu_gl_version), glVersion);
    CopyStr(g_gpu_driver_name, sizeof(g_gpu_driver_name), driverName);
    CopyStr(g_gpu_driver_info, sizeof(g_gpu_driver_info), driverInfo);
    g_gpu_vendor_id = vendorId;
    g_gpu_device_id = deviceId;
    g_gpu_driver_version = driverVersion;
    g_gpu_api_version = apiVersion;
    g_gpu_cores = gpuCores > 0 ? gpuCores : 1;
    g_gpu_l2_cache_kb = l2CacheKb > 0 ? l2CacheKb : 64;
    CopyStr(g_gpu_arch, sizeof(g_gpu_arch), gpuArch);
    g_gpu_on = gpuOn && g_gpu_renderer[0] != '\0';
    // v2.5.9: release any early GL/Vulkan query that waited for the config.
    pthread_mutex_lock(&g_gpu_cfg_mtx);
    g_gpu_cfg_seen = true;
    pthread_cond_broadcast(&g_gpu_cfg_cv);
    pthread_mutex_unlock(&g_gpu_cfg_mtx);
    Log("native: gpu config on=%d renderer=%s vendorId=0x%llx deviceId=0x%llx cores=%d l2=%dkB arch=%s",
        (int)g_gpu_on, g_gpu_renderer, g_gpu_vendor_id, g_gpu_device_id, g_gpu_cores,
        g_gpu_l2_cache_kb, g_gpu_arch);
}

bool CpuSpoofActive() {
    return g_cpu_on;
}

std::string CpuSpoofDisplay() { return std::string(g_cpu_display); }
std::string CpuSpoofManufacturer() { return std::string(g_cpu_mfr); }
std::string CpuSpoofModel() { return std::string(g_cpu_model); }
std::string CpuSpoofPart() { return std::string(g_cpu_part); }
std::string CpuSpoofImplementer() { return std::string(g_cpu_implementer[0] != '\0' ? g_cpu_implementer : "0x41"); }
std::string CpuSpoofHardware() { return std::string(g_cpu_hardware[0] != '\0' ? g_cpu_hardware : g_cpu_hwline); }
std::string CpuSpoofCpuinfoModel() { return std::string(g_cpu_info_model); }
std::string CpuSpoofFeatures() { return std::string(g_cpu_features); }
std::string CpuSpoofHwLine() { return std::string(g_cpu_hwline); }
int CpuSpoofMinKHz() { return g_cpu_min_khz; }
int CpuSpoofMaxKHz() { return g_cpu_max_khz; }

const char* CpuSpoofClusters() {
    return g_cpu_clusters[0] != '\0' ? g_cpu_clusters : "4+4";
}

// v2.5.9: per-cluster table accessors.
int CpuClusterTableSize() { return g_cpu_cluster_count; }

const PasCpuCluster* CpuClusterTable() { return g_cpu_cluster_table; }

const PasCpuCluster* CpuClusterForCore(int core, int* coreIndexInCluster) {
    for (int i = 0; i < g_cpu_cluster_count; i++) {
        const PasCpuCluster& cl = g_cpu_cluster_table[i];
        if (core >= cl.totalBefore && core < cl.totalBefore + cl.cores) {
            if (coreIndexInCluster) *coreIndexInCluster = core - cl.totalBefore;
            return &cl;
        }
    }
    return nullptr;
}

const char* CpuSpoofClusterPart(int core) {
    const PasCpuCluster* cl = CpuClusterForCore(core, nullptr);
    // Return the static buffer directly - never a temporary std::string.
    return (cl && cl->part[0] != '\0') ? cl->part : g_cpu_part;
}

int CpuSpoofClusterMinKHz(int core) {
    const PasCpuCluster* cl = CpuClusterForCore(core, nullptr);
    return (cl && cl->minKHz > 0) ? cl->minKHz : CpuSpoofMinKHz();
}

int CpuSpoofClusterMaxKHz(int core) {
    const PasCpuCluster* cl = CpuClusterForCore(core, nullptr);
    return (cl && cl->maxKHz > 0) ? cl->maxKHz : CpuSpoofMaxKHz();
}

const char* CpuSpoofClusterRevision(int core) {
    const PasCpuCluster* cl = CpuClusterForCore(core, nullptr);
    return (cl && cl->revision[0] != '\0') ? cl->revision : "";
}

bool GpuSpoofActive() { return g_gpu_on; }

// v2.5.9: bounded wait for the GPU config. Called from early GL/Vulkan
// identity queries so that a fast GL init cannot capture the real GPU before
// the config thread lands (the DEBUG-switch heisenburg: debug logging slowed
// the target enough that the config always won; without it Chrome cached the
// host GPU). Bounded, one-time per process: when the config is disabled or
// late, the caller proceeds after the timeout.
void WaitForGpuConfig(int timeoutMs) {
    if (g_gpu_cfg_seen) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeoutMs / 1000;
    ts.tv_nsec += (long)(timeoutMs % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&g_gpu_cfg_mtx);
    while (!g_gpu_cfg_seen) {
        int r = pthread_cond_timedwait(&g_gpu_cfg_cv, &g_gpu_cfg_mtx, &ts);
        if (r != 0) break;
    }
    pthread_mutex_unlock(&g_gpu_cfg_mtx);
}
bool VulkanSpoofActive() { return g_gpu_vulkan_on; }

void SetGpuOptions(bool chain, bool vulkan) {
    g_gpu_chain_on = chain;
    g_gpu_vulkan_on = vulkan;
    Log("native: gpu options chain=%d vulkan=%d", (int)chain, (int)vulkan);
}

std::string GpuSpoofVendor() { return std::string(g_gpu_vendor); }
std::string GpuSpoofRenderer() { return std::string(g_gpu_renderer); }
std::string GpuSpoofVkDeviceName() { return std::string(g_gpu_vk_device_name[0] != '\0' ? g_gpu_vk_device_name : g_gpu_renderer); }
std::string GpuSpoofGlVersion() { return std::string(g_gpu_gl_version); }
unsigned long long GpuSpoofVendorId() { return g_gpu_vendor_id; }
unsigned long long GpuSpoofDeviceId() { return g_gpu_device_id; }
unsigned long long GpuSpoofDriverVersion() { return g_gpu_driver_version; }
unsigned long long GpuSpoofApiVersion() { return g_gpu_api_version; }
std::string GpuSpoofDriverName() { return std::string(g_gpu_driver_name); }
std::string GpuSpoofDriverInfo() { return std::string(g_gpu_driver_info); }

// v2.4.5: physical characteristics for the DevCheck Mali probe.
int GpuSpoofCores() { return g_gpu_cores; }
int GpuSpoofL2CacheKb() { return g_gpu_l2_cache_kb; }
std::string GpuSpoofArch() { return std::string(g_gpu_arch[0] != '\0' ? g_gpu_arch : "Bifrost"); }

typedef void* (*PasEglGpaFn)(const char*);
typedef const unsigned char* (*PasGlGetStringFn)(unsigned int);
typedef const unsigned char* (*PasGlGetStringiFn)(unsigned int, unsigned int);

#define PAS_GL_SLOTS 8

struct GlChainSlot {
    void* key;
    PasGlGetStringFn get_string;
    PasGlGetStringiFn get_stringi;
    PasEglGpaFn get_proc_addr;
};

static GlChainSlot g_gl_slots[PAS_GL_SLOTS];
static pthread_mutex_t g_gl_slot_mtx = PTHREAD_MUTEX_INITIALIZER;
static volatile unsigned g_gl_chain_logged = 0;
static volatile int g_gl_diag = 0;
static volatile bool g_gl_diag_missing_config = false;

void GpuDiag(const char* tag, const char* detail) {
    if (!ReconEnabled()) return;
    int n = __sync_fetch_and_add(&g_gl_diag, 1);
    if (n == 240) {
        Log("native: recon: gl trace cap reached");
        return;
    }
    if (n > 240) return;
    Log("native: recon: gl %s %s", tag, detail ? detail : "");
}

static void DiagGlStr(const char* tag, unsigned name, int spoofed) {
    if (!ReconEnabled()) return;
    char b[48];
    snprintf(b, sizeof(b), "0x%x spoof=%d", name, spoofed);
    GpuDiag(tag, b);
}

static void GlChainLog(const char* name, const char* how) {
    unsigned bit = (strcmp(name, "glGetString") == 0) ? 1u
                   : (strcmp(name, "glGetStringi") == 0) ? 4u : 2u;
    if (g_gl_chain_logged & bit) return;
    g_gl_chain_logged |= bit;
    Log("native: gl loader-chain %s: %s", how, name);
}

static bool SpoofGlName(unsigned name, const unsigned char** out) {
    if (!g_gpu_on) {
        // v2.5.9: first GL string query may arrive before the config thread
        // has applied the GPU identity. Wait briefly - this closes the race
        // where Chrome cached the real GPU when it initialized GL faster
        // than the config (visible as the DEBUG-switch heisenburg).
        WaitForGpuConfig(1500);
        if (!g_gpu_on) {
            if (!g_gl_diag_missing_config) {
                g_gl_diag_missing_config = true;
                Log("native: gpu diag: glGetString passed through - gpu config absent after wait");
            }
            return false;
        }
    }
    if (name == 0x1F00) { *out = (const unsigned char*)g_gpu_vendor; return true; }
    if (name == 0x1F01) { *out = (const unsigned char*)g_gpu_renderer; return true; }
    if (name == 0x1F02 && g_gpu_gl_version[0] != '\0') {
        *out = (const unsigned char*)g_gpu_gl_version;
        return true;
    }
    return false;
}

static const unsigned char* MyGlGetString(unsigned int name) {
    BYTEHOOK_STACK_SCOPE();
    const unsigned char* spoofed = nullptr;
    bool spoof = SpoofGlName(name, &spoofed);
    DiagGlStr("glgs", name, spoof ? 1 : 0);
    if (spoof) return spoofed;
    return BYTEHOOK_CALL_PREV(MyGlGetString, name);
}

static const unsigned char* RepGlGetStringN(int slot, unsigned int name) {
    const unsigned char* spoofed = nullptr;
    bool spoof = SpoofGlName(name, &spoofed);
    DiagGlStr("glgs", name, spoof ? 1 : 0);
    if (spoof) return spoofed;
    PasGlGetStringFn real = nullptr;
    pthread_mutex_lock(&g_gl_slot_mtx);
    if (slot >= 0 && slot < PAS_GL_SLOTS) real = g_gl_slots[slot].get_string;
    pthread_mutex_unlock(&g_gl_slot_mtx);
    return real ? real(name) : nullptr;
}

static const unsigned char* RepGlGetStringiN(int slot, unsigned int name, unsigned int index) {
    const unsigned char* spoofed = nullptr;
    bool spoof = index == 0 && SpoofGlName(name, &spoofed);
    DiagGlStr("glgsi", name, spoof ? 1 : 0);
    if (spoof) return spoofed;
    PasGlGetStringiFn real = nullptr;
    pthread_mutex_lock(&g_gl_slot_mtx);
    if (slot >= 0 && slot < PAS_GL_SLOTS) real = g_gl_slots[slot].get_stringi;
    pthread_mutex_unlock(&g_gl_slot_mtx);
    return real ? real(name, index) : nullptr;
}

static void* RepEglGetProcAddressN(int slot, const char* name);

static int GlChainSlotFor(void* key, PasGlGetStringFn gs, PasGlGetStringiFn gsi,
                          PasEglGpaFn gpa) {
    if (key == nullptr) return -1;
    pthread_mutex_lock(&g_gl_slot_mtx);
    for (int i = 0; i < PAS_GL_SLOTS; i++) {
        if (g_gl_slots[i].key == key) {
            if (gs != nullptr) g_gl_slots[i].get_string = gs;
            if (gsi != nullptr) g_gl_slots[i].get_stringi = gsi;
            if (gpa != nullptr) g_gl_slots[i].get_proc_addr = gpa;
            pthread_mutex_unlock(&g_gl_slot_mtx);
            return i;
        }
    }
    for (int i = 0; i < PAS_GL_SLOTS; i++) {
        if (g_gl_slots[i].key == nullptr) {
            g_gl_slots[i].key = key;
            g_gl_slots[i].get_string = gs;
            g_gl_slots[i].get_stringi = gsi;
            g_gl_slots[i].get_proc_addr = gpa;
            pthread_mutex_unlock(&g_gl_slot_mtx);
            return i;
        }
    }
    pthread_mutex_unlock(&g_gl_slot_mtx);
    return -1;
}

#define PAS_GL_SLOT_FN(IDX)                                                          \
    static const unsigned char* RepGlGetString_##IDX(unsigned int name) {            \
        return RepGlGetStringN(IDX, name);                                           \
    }                                                                                \
    static const unsigned char* RepGlGetStringi_##IDX(unsigned int name,             \
                                                       unsigned int index) {         \
        return RepGlGetStringiN(IDX, name, index);                                   \
    }                                                                                \
    static void* RepEglGetProcAddress_##IDX(const char* name) {                      \
        return RepEglGetProcAddressN(IDX, name);                                     \
    }

PAS_GL_SLOT_FN(0)
PAS_GL_SLOT_FN(1)
PAS_GL_SLOT_FN(2)
PAS_GL_SLOT_FN(3)
PAS_GL_SLOT_FN(4)
PAS_GL_SLOT_FN(5)
PAS_GL_SLOT_FN(6)
PAS_GL_SLOT_FN(7)

static void* const g_slot_gs[PAS_GL_SLOTS] = {
    (void*)RepGlGetString_0, (void*)RepGlGetString_1, (void*)RepGlGetString_2,
    (void*)RepGlGetString_3, (void*)RepGlGetString_4, (void*)RepGlGetString_5,
    (void*)RepGlGetString_6, (void*)RepGlGetString_7,
};
static void* const g_slot_gsi[PAS_GL_SLOTS] = {
    (void*)RepGlGetStringi_0, (void*)RepGlGetStringi_1, (void*)RepGlGetStringi_2,
    (void*)RepGlGetStringi_3, (void*)RepGlGetStringi_4, (void*)RepGlGetStringi_5,
    (void*)RepGlGetStringi_6, (void*)RepGlGetStringi_7,
};
static void* const g_slot_gpa[PAS_GL_SLOTS] = {
    (void*)RepEglGetProcAddress_0, (void*)RepEglGetProcAddress_1,
    (void*)RepEglGetProcAddress_2, (void*)RepEglGetProcAddress_3,
    (void*)RepEglGetProcAddress_4, (void*)RepEglGetProcAddress_5,
    (void*)RepEglGetProcAddress_6, (void*)RepEglGetProcAddress_7,
};

void* GpuChainResolveDlsym(const char* symbol, void* real) {
    if (symbol == nullptr) return nullptr;
    if (strcmp(symbol, "glGetString") == 0 || strcmp(symbol, "glGetStringi") == 0 ||
        strcmp(symbol, "eglGetProcAddress") == 0) {
        GpuDiag("dlsym", symbol);
    }
    if (!g_gpu_on || !g_gpu_chain_on || real == nullptr) return nullptr;
    if (strcmp(symbol, "glGetString") == 0) {
        int slot = GlChainSlotFor(real, (PasGlGetStringFn)real, nullptr, nullptr);
        if (slot < 0) return nullptr;
        GlChainLog("glGetString", "dlsym");
        return g_slot_gs[slot];
    }
    if (strcmp(symbol, "glGetStringi") == 0) {
        int slot = GlChainSlotFor(real, nullptr, (PasGlGetStringiFn)real, nullptr);
        if (slot < 0) return nullptr;
        GlChainLog("glGetStringi", "dlsym");
        return g_slot_gsi[slot];
    }
    if (strcmp(symbol, "eglGetProcAddress") == 0) {
        int slot = GlChainSlotFor(real, nullptr, nullptr, (PasEglGpaFn)real);
        if (slot < 0) return nullptr;
        return g_slot_gpa[slot];
    }
    return nullptr;
}

static void* RepEglGetProcAddressN(int slot, const char* name) {
    if (name != nullptr) GpuDiag("eglgpa", name);
    PasEglGpaFn real = nullptr;
    pthread_mutex_lock(&g_gl_slot_mtx);
    if (slot >= 0 && slot < PAS_GL_SLOTS) real = g_gl_slots[slot].get_proc_addr;
    pthread_mutex_unlock(&g_gl_slot_mtx);
    void* r = real ? real(name) : nullptr;
    if (!(g_gpu_on && g_gpu_chain_on && name != nullptr)) return r;
    if (strcmp(name, "glGetString") == 0 && r != nullptr) {
        pthread_mutex_lock(&g_gl_slot_mtx);
        if (slot >= 0 && slot < PAS_GL_SLOTS) g_gl_slots[slot].get_string = (PasGlGetStringFn)r;
        pthread_mutex_unlock(&g_gl_slot_mtx);
        GlChainLog("glGetString", "eglGetProcAddress");
        return (slot >= 0 && slot < PAS_GL_SLOTS) ? g_slot_gs[slot] : r;
    }
    if (strcmp(name, "glGetStringi") == 0 && r != nullptr) {
        pthread_mutex_lock(&g_gl_slot_mtx);
        if (slot >= 0 && slot < PAS_GL_SLOTS) g_gl_slots[slot].get_stringi = (PasGlGetStringiFn)r;
        pthread_mutex_unlock(&g_gl_slot_mtx);
        GlChainLog("glGetStringi", "eglGetProcAddress");
        return (slot >= 0 && slot < PAS_GL_SLOTS) ? g_slot_gsi[slot] : r;
    }
    if (strcmp(name, "eglGetProcAddress") == 0 && slot >= 0 && slot < PAS_GL_SLOTS) {
        return g_slot_gpa[slot];
    }
    return r;
}

static const unsigned char* MyGlGetStringi(unsigned int name, unsigned int index) {
    BYTEHOOK_STACK_SCOPE();
    const unsigned char* spoofed = nullptr;
    bool spoof = index == 0 && SpoofGlName(name, &spoofed);
    DiagGlStr("glgsi", name, spoof ? 1 : 0);
    if (spoof) return spoofed;
    return BYTEHOOK_CALL_PREV(MyGlGetStringi, name, index);
}

static void* MyEglGetProcAddress(const char* name) {
    BYTEHOOK_STACK_SCOPE();
    void* real = BYTEHOOK_CALL_PREV(MyEglGetProcAddress, name);
    if (name != nullptr) GpuDiag("eglgpa", name);
    if (!g_gpu_on || !g_gpu_chain_on || name == nullptr) return real;
    if (strcmp(name, "glGetString") == 0) {
        if (real != nullptr) {
            int slot = GlChainSlotFor(real, (PasGlGetStringFn)real, nullptr, nullptr);
            if (slot >= 0) {
                GlChainLog("glGetString", "eglGetProcAddress");
                return g_slot_gs[slot];
            }
        }
        return real;
    }
    if (strcmp(name, "glGetStringi") == 0) {
        if (real != nullptr) {
            int slot = GlChainSlotFor(real, nullptr, (PasGlGetStringiFn)real, nullptr);
            if (slot >= 0) {
                GlChainLog("glGetStringi", "eglGetProcAddress");
                return g_slot_gsi[slot];
            }
        }
        return real;
    }
    if (strcmp(name, "eglGetProcAddress") == 0) {
        if (real != nullptr) {
            int slot = GlChainSlotFor(real, nullptr, nullptr, (PasEglGpaFn)real);
            if (slot >= 0) return g_slot_gpa[slot];
        }
        return real;
    }
    return real;
}

static volatile int g_gpu_hooklog = 0;

static void LogGpuHookActivation(const char* sym, int status, const char* caller) {
    if (g_gpu_hooklog >= 32) return;
    g_gpu_hooklog++;
    char c[128];
    snprintf(c, sizeof(c), "%s", caller ? caller : "?");
    Log("native: gpu hook %s status=%d caller=%s", sym, status, c);
}

static void OnGpuHooked(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                        const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub; (void)sym_name; (void)new_func; (void)prev_func; (void)arg;
    LogGpuHookActivation("glGetString", status_code, caller_path_name);
}

static void OnGpuHookedGsi(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                           const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub; (void)sym_name; (void)new_func; (void)prev_func; (void)arg;
    LogGpuHookActivation("glGetStringi", status_code, caller_path_name);
}

static void OnGpuHookedEgl(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                           const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub; (void)sym_name; (void)new_func; (void)prev_func; (void)arg;
    LogGpuHookActivation("eglGetProcAddress", status_code, caller_path_name);
}

void InstallGpuHooks() {
    bytehook_stub_t stub = bytehook_hook_partial(CallerAllowHooks, nullptr, "libGLES",
                                                 "glGetString", (void*)MyGlGetString,
                                                 OnGpuHooked, nullptr);
    Log("native: gpu hook glGetString stub=%d", stub != nullptr);
    bytehook_stub_t stubI = bytehook_hook_partial(CallerAllowHooks, nullptr, "libGLES",
                                                  "glGetStringi", (void*)MyGlGetStringi,
                                                  OnGpuHookedGsi, nullptr);
    Log("native: gpu hook glGetStringi stub=%d", stubI != nullptr);
    bytehook_stub_t stubEgl = bytehook_hook_partial(CallerAllowHooks, nullptr, "libEGL",
                                                    "eglGetProcAddress",
                                                    (void*)MyEglGetProcAddress, OnGpuHookedEgl,
                                                    nullptr);
    Log("native: gpu hook eglGetProcAddress stub=%d", stubEgl != nullptr);
}

}  // namespace pas

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetCpu(JNIEnv* env, jobject thiz,
                                                         jboolean cpuOn, jstring cpuDisplay,
                                                         jstring cpuMfr, jstring cpuModel,
                                                         jstring cpuPart, jstring cpuInfoModel,
                                                         jstring cpuFeatures, jint minKhz,
                                                         jint maxKhz, jstring cpuHwLine,
                                                         jstring cpuImplementer,
                                                         jstring cpuHardware) {
    (void)thiz;
    auto toStr = [env](jstring s) -> std::string {
        if (!s) return std::string();
        const char* c = env->GetStringUTFChars(s, nullptr);
        std::string out = c ? c : "";
        if (c) env->ReleaseStringUTFChars(s, c);
        return out;
    };
    std::string display = toStr(cpuDisplay);
    std::string mfr = toStr(cpuMfr);
    std::string model = toStr(cpuModel);
    std::string part = toStr(cpuPart);
    std::string infoModel = toStr(cpuInfoModel);
    std::string features = toStr(cpuFeatures);
    std::string hwLine = toStr(cpuHwLine);
    std::string impl = toStr(cpuImplementer);
    std::string hw = toStr(cpuHardware);
    pas::SetCpuConfig(cpuOn == JNI_TRUE, display.c_str(), mfr.c_str(), model.c_str(), part.c_str(),
                      infoModel.c_str(), features.c_str(), (int)minKhz, (int)maxKhz,
                      hwLine.c_str(), impl.c_str(), hw.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetCpuClusters(JNIEnv* env, jobject thiz,
                                                         jboolean cpuOn, jstring cpuClusters,
                                                         jstring cpuClusterSpec) {
    (void)thiz;
    const char* c = cpuClusters ? env->GetStringUTFChars(cpuClusters, nullptr) : nullptr;
    const char* s = cpuClusterSpec ? env->GetStringUTFChars(cpuClusterSpec, nullptr) : nullptr;
    pas::SetCpuClusters(cpuOn == JNI_TRUE, c ? c : "", s ? s : "");
    if (c) env->ReleaseStringUTFChars(cpuClusters, c);
    if (s) env->ReleaseStringUTFChars(cpuClusterSpec, s);
}

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetGpu(JNIEnv* env, jobject thiz,
                                                         jboolean gpuOn, jstring gpuVendor,
                                                         jstring gpuRenderer, jstring gpuGlVersion,
                                                         jlong vendorId, jlong deviceId,
                                                         jlong driverVersion, jlong apiVersion,
                                                         jstring driverName, jstring driverInfo,
                                                         jstring vkDeviceName,
                                                         jint gpuCores, jint l2CacheKb,
                                                         jstring gpuArch) {
    (void)thiz;
    auto toStr = [env](jstring s) -> std::string {
        if (!s) return std::string();
        const char* c = env->GetStringUTFChars(s, nullptr);
        std::string out = c ? c : "";
        if (c) env->ReleaseStringUTFChars(s, c);
        return out;
    };
    std::string vendor = toStr(gpuVendor);
    std::string renderer = toStr(gpuRenderer);
    std::string glVersion = toStr(gpuGlVersion);
    std::string dName = toStr(driverName);
    std::string dInfo = toStr(driverInfo);
    std::string vkName = toStr(vkDeviceName);
    std::string arch = toStr(gpuArch);
    pas::SetGpuConfig(gpuOn == JNI_TRUE, vendor.c_str(), renderer.c_str(), glVersion.c_str(),
                      (unsigned long long)vendorId, (unsigned long long)deviceId,
                      (unsigned long long)driverVersion, (unsigned long long)apiVersion,
                      dName.c_str(), dInfo.c_str(), vkName.c_str(),
                      (int)gpuCores, (int)l2CacheKb, arch.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetGpuProfile(JNIEnv* env, jobject thiz,
                                                        jboolean gpuOn,
                                                        jint confMajor, jint confMinor,
                                                        jint confSub, jint confPatch,
                                                        jint driverId,
                                                        jboolean descriptorIndexing,
                                                        jboolean sparseBinding) {
    (void)env;
    (void)thiz;
    if (gpuOn != JNI_TRUE) {
        pas::SetGpuProfile(1, 3, 1, 0, 0, false, false);
        return;
    }
    pas::SetGpuProfile((int)confMajor, (int)confMinor, (int)confSub, (int)confPatch,
                       (int)driverId, descriptorIndexing == JNI_TRUE,
                       sparseBinding == JNI_TRUE);
}

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetGpuOptions(JNIEnv* env, jobject thiz,
                                                        jboolean chain, jboolean vulkan) {
    (void)env;
    (void)thiz;
    pas::SetGpuOptions(chain == JNI_TRUE, vulkan == JNI_TRUE);
}