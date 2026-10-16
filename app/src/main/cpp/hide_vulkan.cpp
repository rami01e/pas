// hide_vulkan.cpp v2.9.3
// Vulkan identity spoof (GPU) for the scoped process.
//
// v2.9.3 (CPU spoofing regression fix):
//  - The v2.8.5 kgsl sysfs guard is REMOVED from this file. It stacked a
//    second bytehook layer on the SHARED libc open/openat/fopen/access/stat
//    family - the same symbols hide_fs.cpp hooks for the CPU profile engine -
//    so every fall-through open() in every caller library gained an extra
//    hop and the process-wide hook topology diverged from the proven 2.8.4
//    layout. The kgsl ENOENT behavior now lives INSIDE hide_fs.cpp's
//    existing wrappers (single hook layer, exactly like 2.8.4).
//  - ProbeIcdFeasibility() restores the v2.8.4 gate: the ICD's vk bodies are
//    inline-hooked ONLY when vk_icdGetInstanceProcAddr actually resolves.
//    v2.8.5 dropped the gate, so on MuMu (kona ICD resolves no gipa) it
//    began executing an inline-patch pass over emulator-internal code at
//    stage0 that the proven-stable 2.8.4 build never ran. The read-only
//    export probe stays.
//
// v2.8.5 (kgsl/Adreno sysfs + device-node guard, runtime caller-filtered):
//  - DevInfo (native x86_64) does not read Vulkan properties through the
//    loader for its GPU model line. It reads sysfs directly:
//      /sys/class/kgsl/**, /sys/devices/**/kgsl*/**, /sys/module/kgsl/**,
//      /sys/kernel/debug/kgsl/**, /dev/kgsl-3d0, /sys/kernel/gpu/gpu_model
//    Those paths exist on MuMu (Snapdragon "kona" emulation) and make any
//    tool report "Adreno (TM) 640".
//  - The guard answers ENOENT only when the CALLER is an app library. Any
//    /system/, /vendor/, /apex/, /odm/ caller - in particular libEGL_kona,
//    libOpenglSystemCommon_ext, gralloc.exynos2100, libhwui - keeps real
//    access. That is exactly what the v2.8.0 install-time filter could not
//    guarantee, and why every scoped app force-closed at start.
//  - ICD export probe: dlsym every target name on the loaded ICD and log
//    the pointer. MuMu's kona ICD returns null for vk_icdGetInstanceProcAddr
//    on this ROM, but we still need to know what it DOES export.

#include "pas.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <string>

#define VK_NO_PROTOTYPES 1
#include <vulkan/vulkan.h>

#include "bytehook.h"

namespace pas {

static volatile int g_ext_hidden_log = 0;

static bool IsHiddenExtName(const char* name) {
    if (!name) return false;
    if (strstr(name, "NEMU") != nullptr) return true;
    if (strstr(name, "VK_INTEL") != nullptr) return true;
    if (strstr(name, "VK_QCOM") != nullptr) return true;
    if (strstr(name, "VK_AMD") != nullptr) return true;
    if (strstr(name, "VK_NV") != nullptr) return true;
    if (strstr(name, "VK_MESA") != nullptr) return true;
    return false;
}

static volatile int g_gpu_conf_major = 1;
static volatile int g_gpu_conf_minor = 3;
static volatile int g_gpu_conf_sub = 1;
static volatile int g_gpu_conf_patch = 0;
static volatile int g_gpu_driver_id = 0;
static volatile int g_gpu_desc_indexing = 0;
static volatile int g_gpu_sparse_binding = 0;
static volatile bool g_icd_entry_logged = false;
static volatile int g_coreprops_calllog = 0;
static volatile int g_vk_dlsym_log = 0;
static volatile int g_gipa_log = 0;
static volatile int g_vk_proxy_calls = 0;

void ProbeIcdFeasibility();

#if defined(__x86_64__)
static void InstallInlineTargetsFor(void* h, const char* context);
#endif

void SetGpuProfile(int confMajor, int confMinor, int confSub, int confPatch,
                   int driverId, bool descriptorIndexing, bool sparseBinding) {
    g_gpu_conf_major = confMajor;
    g_gpu_conf_minor = confMinor;
    g_gpu_conf_sub = confSub;
    g_gpu_conf_patch = confPatch;
    g_gpu_driver_id = driverId;
    g_gpu_desc_indexing = descriptorIndexing ? 1 : 0;
    g_gpu_sparse_binding = sparseBinding ? 1 : 0;
    Log("native: gpu profile conf=%d.%d.%d.%d driverId=%d descIdx=%d sparse=%d", confMajor,
        confMinor, confSub, confPatch, driverId, (int)descriptorIndexing, (int)sparseBinding);
}

static void PatchCoreProps(VkPhysicalDeviceProperties* p) {
    if (!p) return;
    WaitForGpuConfig(1500);
    char deviceName[256];
    snprintf(deviceName, sizeof(deviceName), "%s", GpuSpoofVkDeviceName().c_str());
    snprintf(p->deviceName, sizeof(p->deviceName), "%s", deviceName);
    p->vendorID = (uint32_t)GpuSpoofVendorId();
    p->deviceID = (uint32_t)GpuSpoofDeviceId();
    p->driverVersion = (uint32_t)GpuSpoofDriverVersion();
    p->apiVersion = (uint32_t)GpuSpoofApiVersion();
    if (g_coreprops_calllog < 6) {
        g_coreprops_calllog++;
        Log("native: vk diag: core props delivered dev='%s' vid=0x%x did=0x%x api=0x%x",
            p->deviceName, p->vendorID, p->deviceID, p->apiVersion);
    }
}

static volatile bool g_drvprops_logged = false;
static volatile bool g_props2_node_diag = false;
static volatile int g_props2_calllog = 0;
static volatile bool g_devidprops_logged = false;

static const uint32_t kPasDriverPropsSType = 1000196000u;
static const uint32_t kPasDeviceIdPropsSType = 1000071004u;

struct PasDriverProps {
    VkStructureType sType;
    void* pNext;
    uint32_t driverID;
    char driverName[256];
    char driverInfo[256];
    uint8_t conformance[4];
};

struct PasDeviceIdProps {
    VkStructureType sType;
    void* pNext;
    uint8_t deviceUUID[16];
    uint8_t driverUUID[16];
    uint8_t deviceLUID[8];
    uint32_t deviceNodeMask;
    VkBool32 deviceLUIDValid;
};

static void PatchDriverPropsNode(void* node) {
    if (node == nullptr || !GpuSpoofActive()) return;
    auto* d = (PasDriverProps*)node;
    if (g_gpu_driver_id > 0) d->driverID = (uint32_t)g_gpu_driver_id;
    snprintf(d->driverName, sizeof(d->driverName), "%s", GpuSpoofDriverName().c_str());
    char info[256];
    snprintf(info, sizeof(info), "%s | %d cores | L2: %d kB | %s",
             GpuSpoofDriverInfo().c_str(), GpuSpoofCores(), GpuSpoofL2CacheKb(),
             GpuSpoofArch().c_str());
    snprintf(d->driverInfo, sizeof(d->driverInfo), "%s", info);
    d->conformance[0] = (uint8_t)g_gpu_conf_major;
    d->conformance[1] = (uint8_t)g_gpu_conf_minor;
    d->conformance[2] = (uint8_t)g_gpu_conf_sub;
    d->conformance[3] = (uint8_t)g_gpu_conf_patch;
    if (!g_drvprops_logged) {
        g_drvprops_logged = true;
        Log("native: vulkan driverprops patched (name='%s' info='%s')",
            d->driverName, d->driverInfo);
    }
}

static void PasFnv1a128(const char* s, uint8_t* out) {
    uint64_t h1 = 1469598103934665603ULL;
    uint64_t h2 = 0x9E3779B97F4A7C15ULL;
    for (const char* p = s; p != nullptr && *p != '\0'; p++) {
        h1 = (h1 ^ (uint64_t)(uint8_t)*p) * 1099511628211ULL;
        h2 = (h2 ^ (uint64_t)(uint8_t)*p) * 0xC2B2AE3D27D4EB4FULL;
    }
    memcpy(out, &h1, 8);
    memcpy(out + 8, &h2, 8);
}

static void PatchDeviceIdPropsNode(void* node) {
    if (node == nullptr || !GpuSpoofActive()) return;
    auto* d = (PasDeviceIdProps*)node;
    PasFnv1a128(GpuSpoofVkDeviceName().c_str(), d->deviceUUID);
    PasFnv1a128(GpuSpoofDriverName().c_str(), d->driverUUID);
    memset(d->deviceLUID, 0, sizeof(d->deviceLUID));
    d->deviceNodeMask = 0;
    d->deviceLUIDValid = VK_FALSE;
    if (!g_devidprops_logged) {
        g_devidprops_logged = true;
        Log("native: vulkan deviceid props patched (uuids derived, luid invalid)");
    }
}

static void PatchProps2(VkPhysicalDeviceProperties2* out) {
    if (!out) return;
    WaitForGpuConfig(1500);
    if (!GpuSpoofActive() || !VulkanSpoofActive()) return;
    PatchCoreProps(&out->properties);
    int guard = 0;
    bool foundDriverProps = false;
    for (VkBaseOutStructure* s = (VkBaseOutStructure*)out->pNext;
         s != nullptr && guard < 32; s = s->pNext, guard++) {
        if ((uint32_t)s->sType == kPasDeviceIdPropsSType) {
            PatchDeviceIdPropsNode((void*)s);
        }
        if ((uint32_t)s->sType == kPasDriverPropsSType) {
            PatchDriverPropsNode((void*)s);
            foundDriverProps = true;
        }
    }
    if (g_props2_calllog < 12) {
        g_props2_calllog++;
        VkBaseOutStructure* s = (VkBaseOutStructure*)out->pNext;
        uint32_t st0 = s ? (uint32_t)s->sType : 0;
        int nodes = 0;
        for (VkBaseOutStructure* t = s; t != nullptr && nodes < 32; t = t->pNext, nodes++) {
        }
        Log("native: vk diag: props2 found=%d nodes=%d firstSType=%u dev='%s' vid=0x%x",
            foundDriverProps ? 1 : 0, nodes, st0, out->properties.deviceName,
            out->properties.vendorID);
    }
    if (!foundDriverProps && !g_props2_node_diag) {
        g_props2_node_diag = true;
        Log("native: vk diag: props2 call without driverprops node");
    }
}

static void PatchFeatures(VkPhysicalDeviceFeatures* f) {
    if (!f) return;
    f->shaderFloat64 = VK_FALSE;
    f->sparseBinding = g_gpu_sparse_binding ? VK_TRUE : VK_FALSE;
}

static void PatchFeatures2(VkPhysicalDeviceFeatures2* out) {
    if (!out) return;
    WaitForGpuConfig(1500);
    if (!GpuSpoofActive() || !VulkanSpoofActive()) return;
    PatchFeatures(&out->features);
    int guard = 0;
    for (VkBaseOutStructure* s = (VkBaseOutStructure*)out->pNext; s != nullptr && guard < 32;
         s = s->pNext, guard++) {
        if (s->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES) {
            ((VkPhysicalDeviceVulkan12Features*)s)->descriptorIndexing =
                g_gpu_desc_indexing ? VK_TRUE : VK_FALSE;
        }
        if (s->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES) {
            auto* f13 = (VkPhysicalDeviceVulkan13Features*)s;
            f13->dynamicRendering = VK_TRUE;
            f13->synchronization2 = VK_TRUE;
        }
    }
}

static void VkProxyHit(const char* fn) {
    int n = __sync_fetch_and_add(&g_vk_proxy_calls, 1);
    if (n < 24) Log("native: vk proxy hit: %s (#%d)", fn, n + 1);
}

static void MyVkGetPhysicalDeviceProperties(VkPhysicalDevice pd, VkPhysicalDeviceProperties* out) {
    BYTEHOOK_STACK_SCOPE();
    VkProxyHit("v1 props");
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceProperties, pd, out);
    if (!out) return;
    WaitForGpuConfig(1500);
    if (!GpuSpoofActive()) return;
    PatchCoreProps(out);
}

static void MyVkGetPhysicalDeviceProperties2(VkPhysicalDevice pd,
                                             VkPhysicalDeviceProperties2* out) {
    BYTEHOOK_STACK_SCOPE();
    VkProxyHit("props2");
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceProperties2, pd, out);
    PatchProps2(out);
}

static void MyVkGetPhysicalDeviceProperties2KHR(VkPhysicalDevice pd,
                                                VkPhysicalDeviceProperties2* out) {
    BYTEHOOK_STACK_SCOPE();
    VkProxyHit("props2KHR");
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceProperties2KHR, pd, out);
    PatchProps2(out);
}

static void MyVkGetPhysicalDeviceFeatures(VkPhysicalDevice pd, VkPhysicalDeviceFeatures* out) {
    BYTEHOOK_STACK_SCOPE();
    VkProxyHit("features");
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceFeatures, pd, out);
    if (!out || !GpuSpoofActive()) return;
    PatchFeatures(out);
}

static void MyVkGetPhysicalDeviceFeatures2(VkPhysicalDevice pd, VkPhysicalDeviceFeatures2* out) {
    BYTEHOOK_STACK_SCOPE();
    VkProxyHit("features2");
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceFeatures2, pd, out);
    PatchFeatures2(out);
}

static void MyVkGetPhysicalDeviceFeatures2KHR(VkPhysicalDevice pd, VkPhysicalDeviceFeatures2* out) {
    BYTEHOOK_STACK_SCOPE();
    VkProxyHit("features2KHR");
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceFeatures2KHR, pd, out);
    PatchFeatures2(out);
}

static VkResult FilterExtList(uint32_t* count, VkExtensionProperties* props, VkResult r) {
    if (!GpuSpoofActive() || !count || !props) return r;
    uint32_t got = *count;
    uint32_t kept = 0;
    for (uint32_t i = 0; i < got; i++) {
        if (IsHiddenExtName(props[i].extensionName)) {
            if (g_ext_hidden_log < 8) {
                g_ext_hidden_log++;
                Log("native: vk ext hidden: '%s'", props[i].extensionName);
            }
            continue;
        }
        if (kept != i) props[kept] = props[i];
        kept++;
    }
    *count = kept;
    return r;
}

static VkResult MyVkEnumerateDeviceExtensionProperties(VkPhysicalDevice pd, const char* layer,
                                                       uint32_t* count,
                                                       VkExtensionProperties* props) {
    BYTEHOOK_STACK_SCOPE();
    VkResult r = BYTEHOOK_CALL_PREV(MyVkEnumerateDeviceExtensionProperties, pd, layer, count, props);
    if (!count) return r;
    if (layer != nullptr && layer[0] != '\0') return r;
    if (props == nullptr) {
        if (!GpuSpoofActive() || *count == 0) return r;
        uint32_t total = *count;
        VkExtensionProperties* tmp =
            (VkExtensionProperties*)malloc(sizeof(VkExtensionProperties) * total);
        if (!tmp) return r;
        uint32_t got = total;
        BYTEHOOK_CALL_PREV(MyVkEnumerateDeviceExtensionProperties, pd, layer, &got, tmp);
        uint32_t hidden = 0;
        for (uint32_t i = 0; i < got; i++) {
            if (IsHiddenExtName(tmp[i].extensionName)) hidden++;
        }
        free(tmp);
        if (hidden > 0) *count = total - hidden;
        return r;
    }
    return FilterExtList(count, props, r);
}

static VkResult MyVkEnumerateInstanceExtensionProperties(const char* layer, uint32_t* count,
                                                         VkExtensionProperties* props) {
    BYTEHOOK_STACK_SCOPE();
    VkResult r = BYTEHOOK_CALL_PREV(MyVkEnumerateInstanceExtensionProperties, layer, count, props);
    if (!count) return r;
    if (layer != nullptr && layer[0] != '\0') return r;
    if (props == nullptr) {
        if (!GpuSpoofActive() || *count == 0) return r;
        uint32_t total = *count;
        VkExtensionProperties* tmp =
            (VkExtensionProperties*)malloc(sizeof(VkExtensionProperties) * total);
        if (!tmp) return r;
        uint32_t got = total;
        BYTEHOOK_CALL_PREV(MyVkEnumerateInstanceExtensionProperties, layer, &got, tmp);
        uint32_t hidden = 0;
        for (uint32_t i = 0; i < got; i++) {
            if (IsHiddenExtName(tmp[i].extensionName)) hidden++;
        }
        free(tmp);
        if (hidden > 0) *count = total - hidden;
        return r;
    }
    return FilterExtList(count, props, r);
}

typedef void* (*PasGipaFn)(VkInstance instance, const char* name);
typedef void* (*PasIcdGipaFn)(void* instance, const char* name);

static void* g_real_gipa = nullptr;
static PasIcdGipaFn g_real_icd_gipa = nullptr;
static volatile unsigned g_chain_logged = 0;

enum VkTargetId {
    VK_T_PROP = 0,
    VK_T_PROP2,
    VK_T_PROP2K,
    VK_T_FEAT,
    VK_T_FEAT2,
    VK_T_FEAT2K,
    VK_T_EXTDEV,
    VK_T_EXTINST,
    VK_T_COUNT
};

static const char* const kVkNames[VK_T_COUNT] = {
    "vkGetPhysicalDeviceProperties",
    "vkGetPhysicalDeviceProperties2",
    "vkGetPhysicalDeviceProperties2KHR",
    "vkGetPhysicalDeviceFeatures",
    "vkGetPhysicalDeviceFeatures2",
    "vkGetPhysicalDeviceFeatures2KHR",
    "vkEnumerateDeviceExtensionProperties",
    "vkEnumerateInstanceExtensionProperties",
};

static void* volatile g_vk_real[VK_T_COUNT] = {nullptr};

static int TargetIndex(const char* name) {
    if (!name || name[0] != 'v' || name[1] != 'k') return -1;
    for (int i = 0; i < VK_T_COUNT; i++) {
        if (strcmp(name, kVkNames[i]) == 0) return i;
    }
    return -1;
}

static void* ResolveRealTarget(int id) {
    void* r = g_vk_real[id];
    if (r) return r;
    PasGipaFn gipa = (PasGipaFn)g_real_gipa;
    if (gipa) {
        r = gipa(VK_NULL_HANDLE, kVkNames[id]);
        if (r) g_vk_real[id] = r;
    }
    return r;
}

static void ChainLog(int id, const char* how) {
    if (g_chain_logged & (1u << id)) return;
    g_chain_logged |= (1u << id);
    Log("native: vulkan loader-chain %s: %s", how, kVkNames[id]);
}

static void VkPropsPtr(VkPhysicalDevice pd, VkPhysicalDeviceProperties* out) {
    auto real = (PFN_vkGetPhysicalDeviceProperties)ResolveRealTarget(VK_T_PROP);
    if (real) real(pd, out);
    if (!out) return;
    WaitForGpuConfig(1500);
    if (GpuSpoofActive()) PatchCoreProps(out);
}

static void VkProps2Ptr(VkPhysicalDevice pd, VkPhysicalDeviceProperties2* out) {
    auto real = (PFN_vkGetPhysicalDeviceProperties2)ResolveRealTarget(VK_T_PROP2);
    if (real) real(pd, out);
    PatchProps2(out);
}

static void VkProps2KhrPtr(VkPhysicalDevice pd, VkPhysicalDeviceProperties2* out) {
    auto real = (PFN_vkGetPhysicalDeviceProperties2)ResolveRealTarget(VK_T_PROP2K);
    if (real) real(pd, out);
    PatchProps2(out);
}

static void VkFeatPtr(VkPhysicalDevice pd, VkPhysicalDeviceFeatures* out) {
    auto real = (PFN_vkGetPhysicalDeviceFeatures)ResolveRealTarget(VK_T_FEAT);
    if (real) real(pd, out);
    if (!out) return;
    WaitForGpuConfig(1500);
    if (GpuSpoofActive()) PatchFeatures(out);
}

static void VkFeat2Ptr(VkPhysicalDevice pd, VkPhysicalDeviceFeatures2* out) {
    auto real = (PFN_vkGetPhysicalDeviceFeatures2)ResolveRealTarget(VK_T_FEAT2);
    if (real) real(pd, out);
    PatchFeatures2(out);
}

static void VkFeat2KhrPtr(VkPhysicalDevice pd, VkPhysicalDeviceFeatures2* out) {
    auto real = (PFN_vkGetPhysicalDeviceFeatures2)ResolveRealTarget(VK_T_FEAT2K);
    if (real) real(pd, out);
    PatchFeatures2(out);
}

static VkResult VkExtDevPtr(VkPhysicalDevice pd, const char* layer, uint32_t* count,
                            VkExtensionProperties* props) {
    auto real = (PFN_vkEnumerateDeviceExtensionProperties)ResolveRealTarget(VK_T_EXTDEV);
    if (!real) return VK_ERROR_INITIALIZATION_FAILED;
    VkResult r = real(pd, layer, count, props);
    if (!count) return r;
    if (layer != nullptr && layer[0] != '\0') return r;
    if (props == nullptr) {
        if (!GpuSpoofActive() || *count == 0) return r;
        uint32_t total = *count;
        VkExtensionProperties* tmp =
            (VkExtensionProperties*)malloc(sizeof(VkExtensionProperties) * total);
        if (!tmp) return r;
        uint32_t got = total;
        real(pd, layer, &got, tmp);
        uint32_t hidden = 0;
        for (uint32_t i = 0; i < got; i++) {
            if (IsHiddenExtName(tmp[i].extensionName)) hidden++;
        }
        free(tmp);
        if (hidden > 0) *count = total - hidden;
        return r;
    }
    return FilterExtList(count, props, r);
}

static VkResult VkExtInstPtr(const char* layer, uint32_t* count, VkExtensionProperties* props) {
    auto real = (PFN_vkEnumerateInstanceExtensionProperties)ResolveRealTarget(VK_T_EXTINST);
    if (!real) return VK_ERROR_INITIALIZATION_FAILED;
    VkResult r = real(layer, count, props);
    if (!count) return r;
    if (layer != nullptr && layer[0] != '\0') return r;
    if (props == nullptr) {
        if (!GpuSpoofActive() || *count == 0) return r;
        uint32_t total = *count;
        VkExtensionProperties* tmp =
            (VkExtensionProperties*)malloc(sizeof(VkExtensionProperties) * total);
        if (!tmp) return r;
        uint32_t got = total;
        real(layer, &got, tmp);
        uint32_t hidden = 0;
        for (uint32_t i = 0; i < got; i++) {
            if (IsHiddenExtName(tmp[i].extensionName)) hidden++;
        }
        free(tmp);
        if (hidden > 0) *count = total - hidden;
        return r;
    }
    return FilterExtList(count, props, r);
}

static void* const kVkProxies[VK_T_COUNT] = {
    (void*)VkPropsPtr,  (void*)VkProps2Ptr,  (void*)VkProps2KhrPtr,
    (void*)VkFeatPtr,   (void*)VkFeat2Ptr,   (void*)VkFeat2KhrPtr,
    (void*)VkExtDevPtr, (void*)VkExtInstPtr,
};

static void* MyVkIcdGetInstanceProcAddr(void* instance, const char* name) {
    PasIcdGipaFn gipa = g_real_icd_gipa;
    if (!gipa) return nullptr;
    void* real = gipa(instance, name);
    if (name != nullptr) {
        int n = __sync_fetch_and_add(&g_gipa_log, 1);
        if (n < 60) Log("native: icd gipa '%s' -> real=%p", name, real);
    }
    if (!real || !name) return real;
    if (!GpuSpoofActive() || !VulkanSpoofActive()) return real;
    int id = TargetIndex(name);
    if (id >= 0) {
        g_vk_real[id] = real;
        ChainLog(id, "icd");
        return kVkProxies[id];
    }
    return real;
}

static void* MyVkGetInstanceProcAddrGOT(VkInstance instance, const char* name) {
    BYTEHOOK_STACK_SCOPE();
    ProbeIcdFeasibility();
    void* real = BYTEHOOK_CALL_PREV(MyVkGetInstanceProcAddrGOT, instance, name);
    if (name != nullptr) {
        int n = __sync_fetch_and_add(&g_gipa_log, 1);
        if (n < 60) Log("native: gipa '%s' -> real=%p", name, real);
    }
    if (!GpuSpoofActive() || !VulkanSpoofActive() || !name || !real) return real;
    int id = TargetIndex(name);
    if (id >= 0) {
        g_vk_real[id] = real;
        ChainLog(id, "hit");
        return kVkProxies[id];
    }
    return real;
}

static void* MyVkGetInstanceProcAddrPtr(VkInstance instance, const char* name) {
    ProbeIcdFeasibility();
    PasGipaFn gipa = (PasGipaFn)g_real_gipa;
    if (!gipa) return nullptr;
    void* real = gipa(instance, name);
    if (name != nullptr) {
        int n = __sync_fetch_and_add(&g_gipa_log, 1);
        if (n < 60) Log("native: gipa(ptr) '%s' -> real=%p", name, real);
    }
    if (!GpuSpoofActive() || !VulkanSpoofActive() || !name || !real) return real;
    int id = TargetIndex(name);
    if (id >= 0) {
        // v2.8.6: the loader legitimately returns DIFFERENT pointers for the
        // same target name depending on how it was queried (loader trampoline
        // via dlsym vs. ICD body via vkGetInstanceProcAddr). Always trust the
        // freshest pointer and always return our proxy - our proxy internally
        // resolves via ResolveRealTarget() which now reads this freshest one.
        g_vk_real[id] = real;
        ChainLog(id, "gipa");
        return kVkProxies[id];
    }
    return real;
}

static __thread int g_dlsym_depth = 0;
static __thread int g_inline_resolving = 0;
static volatile bool g_second_gipa_diag = false;

struct PasIcdFinder {
    char name[256];
    bool found;
};

static int PasIcdPhdrCb(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    auto* f = (PasIcdFinder*)data;
    if (!info->dlpi_name) return 0;
    const char* n = info->dlpi_name;
    if (strstr(n, "vulkan.") == nullptr || strstr(n, ".so") == nullptr) return 0;
    if (strstr(n, "/hw/") == nullptr && strstr(n, "vendor") == nullptr) return 0;
    snprintf(f->name, sizeof(f->name), "%s", n);
    f->found = true;
    return 1;
}

void ProbeIcdFeasibility() {
    static volatile int state = 0;
    if (state == 2) return;
    PasIcdFinder f = {};
    dl_iterate_phdr(PasIcdPhdrCb, &f);
    if (!f.found) {
        if (state == 0) {
            state = 1;
            Log("native: vk icd probe: no vendor ICD loaded yet - deferring");
        }
        return;
    }
    state = 2;
    g_inline_resolving = 1;
    void* icd = dlopen(f.name, RTLD_NOW | RTLD_LOCAL);
    g_inline_resolving = 0;
    if (!icd) {
        Log("native: vk icd probe: ICD '%s' dlopen failed", f.name);
        return;
    }

    // v2.8.5: report every symbol the ICD actually exports.
    static const char* const kProbe[] = {
        "vk_icdGetInstanceProcAddr",
        "vk_icdNegotiateLoaderICDInterfaceVersion",
        "vkGetInstanceProcAddr",
        "vkCreateInstance",
        "vkEnumeratePhysicalDevices",
        "vkGetPhysicalDeviceProperties",
        "vkGetPhysicalDeviceProperties2",
        "vkGetPhysicalDeviceProperties2KHR",
        "vkEnumerateDeviceExtensionProperties",
        "vkEnumerateInstanceExtensionProperties",
    };
    for (const char* s : kProbe) {
        void* p = dlsym(icd, s);
        Log("native: vk icd export '%s' = %p", s, p);
    }

    void* sym = nullptr;
    g_inline_resolving = 1;
    sym = dlsym(icd, "vk_icdGetInstanceProcAddr");
    if (!sym) sym = dlsym(RTLD_DEFAULT, "vk_icdGetInstanceProcAddr");
    g_inline_resolving = 0;
    if (!sym) {
        // v2.9.3: v2.8.5 inline-hooked the ICD bodies here even without the
        // gipa entry point. That pass never ran on 2.8.4 (early return), and
        // on MuMu the kona ICD resolves no gipa, so 2.8.5 began executing an
        // inline-patch pass over emulator-internal code at stage0 that the
        // stable 2.8.4 build never did. The gate is restored: ICD bodies are
        // hooked only when vk_icdGetInstanceProcAddr resolves.
        Log("native: vk icd probe: ICD '%s' loaded but vk_icdGetInstanceProcAddr unresolved",
            f.name);
        return;
    }
    if (g_real_icd_gipa == nullptr) g_real_icd_gipa = (PasIcdGipaFn)sym;
    Log("native: vk icd probe: ICD '%s' loaded; real ICD gipa=%p",
        f.name, (void*)g_real_icd_gipa);

#if defined(__x86_64__)
    if (icd) {
        InstallInlineTargetsFor(icd, f.name);
    }
#endif

    auto icdGipa = (void* (*)(void*, const char*))sym;
    int resolved = 0;
    char missing[320];
    missing[0] = '\0';
    size_t ml = 0;
    for (int i = 0; i < VK_T_COUNT; i++) {
        void* p = icdGipa(nullptr, kVkNames[i]);
        if (p != nullptr) {
            resolved++;
            continue;
        }
        int n = snprintf(missing + ml, sizeof(missing) - ml - 1, "%s%s", ml ? "," : "",
                         kVkNames[i]);
        if (n > 0) ml += (size_t)n;
        if (ml >= sizeof(missing) - 2) break;
    }
    Log("native: vk icd probe: icd gipa(NULL) resolves %d/8 targets%s%s",
        resolved, missing[0] ? "; unresolved: " : "", missing);
}

static void* MyDlsym(void* handle, const char* symbol) {
    BYTEHOOK_STACK_SCOPE();
    void* real = BYTEHOOK_CALL_PREV(MyDlsym, handle, symbol);
    if (g_dlsym_depth > 0 || g_inline_resolving) return real;
    g_dlsym_depth = 1;
    void* out = real;
    do {
        if (real == nullptr) break;

        if (symbol != nullptr && strncmp(symbol, "vk", 2) == 0) {
            int n = __sync_fetch_and_add(&g_vk_dlsym_log, 1);
            if (n < 120) Log("native: vk dlsym '%s' handle=%p real=%p",
                             symbol, handle, real);
        }

        void* sub = GpuChainResolveDlsym(symbol, real);
        if (sub != nullptr) {
            out = sub;
            break;
        }
        if (!symbol || symbol[0] != 'v' || symbol[1] != 'k') break;

        if (strcmp(symbol, "vk_icdGetInstanceProcAddr") == 0) {
            if (g_real_icd_gipa == nullptr) {
                g_real_icd_gipa = (PasIcdGipaFn)real;
                if (!g_icd_entry_logged) {
                    g_icd_entry_logged = true;
                    Log("native: vk diag: vk_icdGetInstanceProcAddr resolved via dlsym - "
                        "installing ICD gipa proxy");
                }
                ProbeIcdFeasibility();
            }
            out = (void*)MyVkIcdGetInstanceProcAddr;
            break;
        }
        if (strncmp(symbol, "vk_icd", 6) == 0) {
            if (!g_icd_entry_logged) {
                g_icd_entry_logged = true;
                Log("native: vk diag: vk_icd entry '%s' resolved via dlsym", symbol);
            }
            ProbeIcdFeasibility();
        }
        if (!GpuSpoofActive() || !VulkanSpoofActive()) break;
        if (strcmp(symbol, "vkGetInstanceProcAddr") == 0) {
            if (g_real_gipa == nullptr) {
                g_real_gipa = real;
            } else if (g_real_gipa != real) {
                if (!g_second_gipa_diag) {
                    g_second_gipa_diag = true;
                    Log("native: vk diag: second gipa address seen - covered by inline body hooks");
                }
            }
            out = (void*)MyVkGetInstanceProcAddrPtr;
            break;
        }
        int id = TargetIndex(symbol);
        if (id >= 0) {
            if (g_vk_real[id] == nullptr) {
                g_vk_real[id] = real;
                ChainLog(id, "dlsym direct");
                out = kVkProxies[id];
            } else if (g_vk_real[id] == real) {
                out = kVkProxies[id];
            }
        }
    } while (0);
    g_dlsym_depth = 0;
    return out;
}

static volatile int g_vk_hooklog = 0;

#if defined(__x86_64__)

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static void* g_inline_orig[VK_T_COUNT] = {nullptr};

// v2.8.5: remember every body we already inline-hooked. When we later resolve
// the same address via the ICD handle (or via a chained thunk), we skip the
// second patch. This is what makes dual coverage safe.
static void* g_hooked_bodies[64] = {};
static int g_hooked_bodies_count = 0;

static bool IsBodyHooked(void* body) {
    for (int i = 0; i < g_hooked_bodies_count; i++) {
        if (g_hooked_bodies[i] == body) return true;
    }
    return false;
}
static void MarkBodyHooked(void* body) {
    if (g_hooked_bodies_count < 64) {
        g_hooked_bodies[g_hooked_bodies_count++] = body;
    }
}

struct PasDecodeFail {
    bool valid;
    size_t offset;
    uint8_t bytes[8];
};

static void FillFail(PasDecodeFail* fail, const uint8_t* at, size_t offset) {
    if (!fail) return;
    fail->valid = true;
    fail->offset = offset;
    for (int k = 0; k < 8; k++) fail->bytes[k] = at[k];
}

static size_t PasDecodeX64(const uint8_t* c, size_t avail, int* ripDispOff) {
    *ripDispOff = -1;
    if (avail < 1) return 0;
    if (avail >= 4 && c[0] == 0xF3 && c[1] == 0x0F && c[2] == 0x1E && c[3] == 0xFA)
        return 4;

    size_t i = 0;
    bool rexW = false;
    int segSkip = 0;
    while (i < avail && (c[i] == 0x64 || c[i] == 0x65)) {
        i++;
        if (++segSkip > 1) return 0;
    }
    if (i >= avail) return 0;
    if (c[i] >= 0x40 && c[i] <= 0x4F) {
        rexW = (c[i] & 0x08) != 0;
        i++;
        if (i >= avail) return 0;
    }

    uint8_t op = c[i];
    i++;

    enum Kind { K_IMM_ONLY, K_MODRM, K_GRP3, K_GRP5 } kind = K_IMM_ONLY;
    bool allowRipRel = false;
    size_t imm = 0;

    switch (op) {
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            return i;
        case 0x90:
            return i;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            imm = rexW ? 8 : 4;
            break;
        case 0x3C: case 0xA8:
            return i + 1;
        case 0x3D: case 0xA9:
            return i + 4;
        case 0x00: case 0x02: case 0x08: case 0x0A:
        case 0x10: case 0x12: case 0x18: case 0x1A:
        case 0x20: case 0x22: case 0x28: case 0x2A:
        case 0x30: case 0x32: case 0x38: case 0x3A:
        case 0x01: case 0x03: case 0x09: case 0x0B:
        case 0x11: case 0x13: case 0x19: case 0x1B:
        case 0x21: case 0x23: case 0x29: case 0x2B:
        case 0x31: case 0x33: case 0x39: case 0x3B:
        case 0x63:
        case 0x84: case 0x85:
        case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8D:
            kind = K_MODRM;
            allowRipRel = true;
            break;
        case 0x80: kind = K_MODRM; imm = 1; break;
        case 0x81: kind = K_MODRM; imm = 4; break;
        case 0x83: kind = K_MODRM; imm = 1; break;
        case 0x69: kind = K_MODRM; imm = 4; break;
        case 0x6B: kind = K_MODRM; imm = 1; break;
        case 0xC7: kind = K_MODRM; imm = 4; break;
        case 0xF6: kind = K_GRP3; imm = 1; allowRipRel = true; break;
        case 0xF7: kind = K_GRP3; imm = 4; allowRipRel = true; break;
        case 0xFF: kind = K_GRP5; break;
        case 0x0F: {
            if (i >= avail) return 0;
            uint8_t op2 = c[i];
            if (op2 == 0x1F) {
                i++;
                kind = K_MODRM;
                allowRipRel = true;
                break;
            }
            if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF ||
                op2 == 0xAF) {
                i++;
                kind = K_MODRM;
                allowRipRel = true;
                break;
            }
            return 0;
        }
        default:
            return 0;
    }

    if (kind == K_IMM_ONLY) {
        if (i + imm > avail) return 0;
        return i + imm;
    }

    if (i > 14 || i >= avail) return 0;
    uint8_t mrm = c[i];
    i++;
    uint8_t mod = (uint8_t)(mrm >> 6);
    uint8_t reg = (uint8_t)((mrm >> 3) & 7);
    uint8_t rm = (uint8_t)(mrm & 7);
    bool isRipRel = (mod == 0 && rm == 5);

    if (kind == K_GRP3 && reg > 1) imm = 0;
    if (kind == K_GRP5) {
        if (reg == 3 || reg == 5 || reg == 7) return 0;
        if (isRipRel && (reg == 2 || reg == 4)) return 0;
        if (isRipRel) allowRipRel = true;
    }

    if (mod == 3) {
    } else if (rm == 4) {
        if (i >= avail) return 0;
        uint8_t sib = c[i];
        i++;
        uint8_t base = (uint8_t)(sib & 7);
        if (mod == 0) {
            if (base == 5) {
                if (i + 4 > avail) return 0;
                i += 4;
            }
        } else {
            i += (mod == 1) ? 1 : 4;
            if (i > avail) return 0;
        }
    } else if (isRipRel) {
        if (!allowRipRel) return 0;
        if (i + 4 > avail) return 0;
        *ripDispOff = (int)i;
        i += 4;
    } else {
        if (mod == 1) {
            if (i + 1 > avail) return 0;
            i += 1;
        } else if (mod == 2) {
            if (i + 4 > avail) return 0;
            i += 4;
        }
    }

    if (i > 15) return 0;
    if (imm) {
        if (i + imm > avail) return 0;
        i += imm;
    }
    if (i > 15) return 0;
    return i;
}

static size_t PasProbeDecodable(const uint8_t* target, size_t want, PasDecodeFail* fail) {
    size_t copied = 0;
    while (copied < want) {
        int ripOff = -1;
        size_t len = PasDecodeX64(target + copied, 16, &ripOff);
        if (len == 0) {
            FillFail(fail, target + copied, copied);
            return copied;
        }
        copied += len;
    }
    return copied;
}

static bool PasBuildTrampoline(const uint8_t* target, size_t needBytes,
                               uint8_t* tramp, size_t trampCap, size_t* copiedOut,
                               PasDecodeFail* fail) {
    size_t copied = 0;
    while (copied < needBytes) {
        int ripOff = -1;
        size_t len = PasDecodeX64(target + copied, 16, &ripOff);
        if (len == 0) {
            FillFail(fail, target + copied, copied);
            return false;
        }
        if (copied + len + 14 > trampCap) return false;
        memcpy(tramp + copied, target + copied, len);
        if (ripOff >= 0) {
            int64_t delta = (int64_t)((uintptr_t)(target + copied) -
                                      (uintptr_t)(tramp + copied));
            uint8_t* d = tramp + copied + (size_t)ripOff;
            int32_t oldDisp;
            memcpy(&oldDisp, d, 4);
            int64_t newDisp = (int64_t)oldDisp + delta;
            if (newDisp < INT32_MIN || newDisp > INT32_MAX) return false;
            memcpy(d, &newDisp, 4);
        }
        copied += len;
    }
    uintptr_t back = (uintptr_t)target + copied;
    tramp[copied++] = 0xFF;
    tramp[copied++] = 0x25;
    memset(tramp + copied, 0, 4);
    copied += 4;
    memcpy(tramp + copied, &back, 8);
    copied += 8;
    *copiedOut = copied;
    return true;
}

static bool PasWriteCode(void* target, const void* data, size_t len) {
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) pageSize = 4096;
    uintptr_t start = (uintptr_t)target & ~(uintptr_t)(pageSize - 1);
    uintptr_t end = ((uintptr_t)target + len + (uintptr_t)pageSize - 1) &
                    ~(uintptr_t)(pageSize - 1);
    if (mprotect((void*)start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        memcpy(target, data, len);
        __builtin___clear_cache((char*)target, (char*)target + len);
        mprotect((void*)start, end - start, PROT_READ | PROT_EXEC);
        return true;
    }
    int err = errno;
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) {
        Log("native: vk inline: mprotect errno=%d and /proc/self/mem open failed", err);
        return false;
    }
    bool ok = lseek(fd, (off_t)(uintptr_t)target, SEEK_SET) != (off_t)-1 &&
              write(fd, data, len) == (ssize_t)len;
    close(fd);
    if (!ok) {
        Log("native: vk inline: /proc/self/mem write failed errno=%d", errno);
        return false;
    }
    __builtin___clear_cache((char*)target, (char*)target + len);
    return true;
}

static uint8_t* FindNearPage(uintptr_t target) {
    for (uintptr_t off = 0x1000000; off <= 0x7F000000; off += 0x1000000) {
        for (int dir = 0; dir < 2; dir++) {
            uintptr_t cand = (dir ? target + off : target - off) & ~(uintptr_t)0xFFF;
            void* p = mmap((void*)cand, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (p != MAP_FAILED) return (uint8_t*)p;
        }
    }
    return nullptr;
}

static bool PasInlineHookX64(void* target, void* wrapper, void** origOut) {
    uint8_t* tramp = (uint8_t*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) return false;
    size_t copied = 0;
    if (!PasBuildTrampoline((const uint8_t*)target, 12, tramp, 4096, &copied, nullptr)) {
        munmap(tramp, 4096);
        return false;
    }
    __builtin___clear_cache((char*)tramp, (char*)tramp + copied);

    uint8_t patch[12];
    patch[0] = 0x48;
    patch[1] = 0xB8;
    memcpy(patch + 2, &wrapper, 8);
    patch[10] = 0xFF;
    patch[11] = 0xE0;
    if (!PasWriteCode(target, patch, sizeof(patch))) {
        munmap(tramp, 4096);
        return false;
    }
    *origOut = tramp;
    return true;
}

static bool PasInlineHookE9(void* body, void* wrapper, void** origOut) {
    uint8_t* page = FindNearPage((uintptr_t)body);
    if (!page) return false;
    size_t copied = 0;
    if (!PasBuildTrampoline((const uint8_t*)body, 5, page + 12, 4096 - 12, &copied,
                            nullptr)) {
        munmap(page, 4096);
        return false;
    }
    page[0] = 0x48;
    page[1] = 0xB8;
    memcpy(page + 2, &wrapper, 8);
    page[10] = 0xFF;
    page[11] = 0xE0;
    __builtin___clear_cache((char*)page, (char*)page + 12 + copied);

    int64_t rel = (int64_t)((uintptr_t)page - ((uintptr_t)body + 5));
    if (rel < INT32_MIN || rel > INT32_MAX) {
        munmap(page, 4096);
        return false;
    }
    uint8_t patch[5];
    patch[0] = 0xE9;
    int32_t r = (int32_t)rel;
    memcpy(patch + 1, &r, 4);
    if (!PasWriteCode(body, patch, sizeof(patch))) {
        munmap(page, 4096);
        return false;
    }
    *origOut = page + 12;
    return true;
}

static void InlineVkGetPhysicalDeviceProperties(VkPhysicalDevice pd,
                                                VkPhysicalDeviceProperties* out) {
    auto orig = (PFN_vkGetPhysicalDeviceProperties)g_inline_orig[VK_T_PROP];
    if (orig) orig(pd, out);
    if (!out) return;
    WaitForGpuConfig(1500);
    if (GpuSpoofActive() && VulkanSpoofActive()) PatchCoreProps(out);
}

static void InlineVkGetPhysicalDeviceProperties2(VkPhysicalDevice pd,
                                                 VkPhysicalDeviceProperties2* out) {
    auto orig = (PFN_vkGetPhysicalDeviceProperties2)g_inline_orig[VK_T_PROP2];
    if (orig) orig(pd, out);
    PatchProps2(out);
}

static void InlineVkGetPhysicalDeviceProperties2KHR(VkPhysicalDevice pd,
                                                    VkPhysicalDeviceProperties2* out) {
    auto orig = (PFN_vkGetPhysicalDeviceProperties2)g_inline_orig[VK_T_PROP2K];
    if (orig) orig(pd, out);
    PatchProps2(out);
}

static void InlineVkGetPhysicalDeviceFeatures(VkPhysicalDevice pd,
                                              VkPhysicalDeviceFeatures* out) {
    auto orig = (PFN_vkGetPhysicalDeviceFeatures)g_inline_orig[VK_T_FEAT];
    if (orig) orig(pd, out);
    if (!out) return;
    WaitForGpuConfig(1500);
    if (GpuSpoofActive() && VulkanSpoofActive()) PatchFeatures(out);
}

static void InlineVkGetPhysicalDeviceFeatures2(VkPhysicalDevice pd,
                                               VkPhysicalDeviceFeatures2* out) {
    auto orig = (PFN_vkGetPhysicalDeviceFeatures2)g_inline_orig[VK_T_FEAT2];
    if (orig) orig(pd, out);
    if (out) PatchFeatures2(out);
}

static void InlineVkGetPhysicalDeviceFeatures2KHR(VkPhysicalDevice pd,
                                                  VkPhysicalDeviceFeatures2* out) {
    auto orig = (PFN_vkGetPhysicalDeviceFeatures2)g_inline_orig[VK_T_FEAT2K];
    if (orig) orig(pd, out);
    if (out) PatchFeatures2(out);
}

static VkResult InlineVkEnumerateDeviceExtensionProperties(VkPhysicalDevice pd,
                                                           const char* layer,
                                                           uint32_t* count,
                                                           VkExtensionProperties* props) {
    auto orig = (PFN_vkEnumerateDeviceExtensionProperties)g_inline_orig[VK_T_EXTDEV];
    if (!orig) return VK_ERROR_INITIALIZATION_FAILED;
    VkResult r = orig(pd, layer, count, props);
    if (!count) return r;
    if (layer != nullptr && layer[0] != '\0') return r;
    if (props == nullptr) {
        if (!GpuSpoofActive() || !VulkanSpoofActive() || *count == 0) return r;
        uint32_t total = *count;
        VkExtensionProperties* tmp =
            (VkExtensionProperties*)malloc(sizeof(VkExtensionProperties) * total);
        if (!tmp) return r;
        uint32_t got = total;
        orig(pd, layer, &got, tmp);
        uint32_t hidden = 0;
        for (uint32_t i = 0; i < got; i++) {
            if (IsHiddenExtName(tmp[i].extensionName)) hidden++;
        }
        free(tmp);
        if (hidden > 0) *count = total - hidden;
        return r;
    }
    return FilterExtList(count, props, r);
}

static VkResult InlineVkEnumerateInstanceExtensionProperties(const char* layer,
                                                             uint32_t* count,
                                                             VkExtensionProperties* props) {
    auto orig = (PFN_vkEnumerateInstanceExtensionProperties)g_inline_orig[VK_T_EXTINST];
    if (!orig) return VK_ERROR_INITIALIZATION_FAILED;
    VkResult r = orig(layer, count, props);
    if (!count) return r;
    if (layer != nullptr && layer[0] != '\0') return r;
    if (props == nullptr) {
        if (!GpuSpoofActive() || !VulkanSpoofActive() || *count == 0) return r;
        uint32_t total = *count;
        VkExtensionProperties* tmp =
            (VkExtensionProperties*)malloc(sizeof(VkExtensionProperties) * total);
        if (!tmp) return r;
        uint32_t got = total;
        orig(layer, &got, tmp);
        uint32_t hidden = 0;
        for (uint32_t i = 0; i < got; i++) {
            if (IsHiddenExtName(tmp[i].extensionName)) hidden++;
        }
        free(tmp);
        if (hidden > 0) *count = total - hidden;
        return r;
    }
    return FilterExtList(count, props, r);
}

// v2.8.5: per-target installer, works for libvulkan.so AND for the ICD handle.
// Skips bodies already hooked (dual-coverage dedup by address).
static void InstallInlineTargetsFor(void* h, const char* context) {
    struct InlineSpec {
        const char* sym;
        int id;
        void* fn;
    };
    static const InlineSpec specs[VK_T_COUNT] = {
        {"vkGetPhysicalDeviceProperties", VK_T_PROP,
         (void*)InlineVkGetPhysicalDeviceProperties},
        {"vkGetPhysicalDeviceProperties2", VK_T_PROP2,
         (void*)InlineVkGetPhysicalDeviceProperties2},
        {"vkGetPhysicalDeviceProperties2KHR", VK_T_PROP2K,
         (void*)InlineVkGetPhysicalDeviceProperties2KHR},
        {"vkGetPhysicalDeviceFeatures", VK_T_FEAT,
         (void*)InlineVkGetPhysicalDeviceFeatures},
        {"vkGetPhysicalDeviceFeatures2", VK_T_FEAT2,
         (void*)InlineVkGetPhysicalDeviceFeatures2},
        {"vkGetPhysicalDeviceFeatures2KHR", VK_T_FEAT2K,
         (void*)InlineVkGetPhysicalDeviceFeatures2KHR},
        {"vkEnumerateDeviceExtensionProperties", VK_T_EXTDEV,
         (void*)InlineVkEnumerateDeviceExtensionProperties},
        {"vkEnumerateInstanceExtensionProperties", VK_T_EXTINST,
         (void*)InlineVkEnumerateInstanceExtensionProperties},
    };

    int ok = 0, already = 0, notExported = 0;
    for (int i = 0; i < VK_T_COUNT; i++) {
        g_inline_resolving = 1;
        void* target = dlsym(h, specs[i].sym);
        g_inline_resolving = 0;
        if (!target) {
            notExported++;
            continue;
        }

        const uint8_t* tb = (const uint8_t*)target;
        void* body = target;
        bool thunk = false;
        for (int hops = 0; ((const uint8_t*)body)[0] == 0xE9 && hops < 4; hops++) {
            int32_t rel;
            memcpy(&rel, (const uint8_t*)body + 1, 4);
            body = (void*)((uintptr_t)body + 5 + (int64_t)rel);
            thunk = true;
        }

        if (IsBodyHooked(body)) {
            already++;
            continue;
        }

        void* origSlot = nullptr;
        PasDecodeFail fail = {};
        size_t dec = PasProbeDecodable((const uint8_t*)body, 12, &fail);
        if (dec >= 12 && PasInlineHookX64(body, specs[i].fn, &origSlot)) {
            if (g_inline_orig[specs[i].id] == nullptr) g_inline_orig[specs[i].id] = origSlot;
            MarkBodyHooked(body);
            ok++;
            Log("native: vk inline [%s]: %s body hooked (12-byte%s)", context,
                specs[i].sym, thunk ? ", thunk target" : "");
            continue;
        }
        if (dec >= 5 && PasInlineHookE9(body, specs[i].fn, &origSlot)) {
            if (g_inline_orig[specs[i].id] == nullptr) g_inline_orig[specs[i].id] = origSlot;
            MarkBodyHooked(body);
            ok++;
            Log("native: vk inline [%s]: %s body hooked (5-byte e9%s)", context,
                specs[i].sym, thunk ? ", thunk target" : "");
            continue;
        }
        if (dec >= 5) {
            Log("native: vk inline [%s]: %s code write failed (%zu bytes decodable)",
                context, specs[i].sym, dec);
        } else if (fail.valid) {
            Log("native: vk inline [%s]: %s body+%zu unsupported bytes "
                "%02x %02x %02x %02x %02x %02x %02x %02x",
                context, specs[i].sym, fail.offset, fail.bytes[0], fail.bytes[1],
                fail.bytes[2], fail.bytes[3], fail.bytes[4], fail.bytes[5],
                fail.bytes[6], fail.bytes[7]);
        }
        if (!thunk) continue;

        uint8_t* nearTramp = FindNearPage((uintptr_t)target);
        if (!nearTramp) continue;
        size_t o = 0;
        nearTramp[o++] = 0x48;
        nearTramp[o++] = 0xB8;
        memcpy(nearTramp + o, &specs[i].fn, 8);
        o += 8;
        nearTramp[o++] = 0xFF;
        nearTramp[o++] = 0xE0;
        __builtin___clear_cache((char*)nearTramp, (char*)nearTramp + o);
        int64_t newRel = (int64_t)((uintptr_t)nearTramp - (uintptr_t)target - 5);
        if (newRel < INT32_MIN || newRel > INT32_MAX) {
            munmap(nearTramp, 4096);
            continue;
        }
        int32_t nr = (int32_t)newRel;
        if (!PasWriteCode((void*)(tb + 1), &nr, 4)) {
            munmap(nearTramp, 4096);
            continue;
        }
        if (g_inline_orig[specs[i].id] == nullptr) g_inline_orig[specs[i].id] = body;
        MarkBodyHooked(body);
        ok++;
        Log("native: vk inline [%s]: %s thunk hooked (fallback)", context, specs[i].sym);
    }
    Log("native: vk inline [%s]: %d newly hooked, %d already hooked, %d not exported",
        context, ok, already, notExported);
}

#endif  // __x86_64__

// ---------------------------------------------------------------------------
// Public install / entry points
// ---------------------------------------------------------------------------

void InstallVulkanInlineBackstop() {
#if defined(__x86_64__)
    static int g_inline_state = 0;
    if (!g_inline_state) {
        g_inline_state = 1;
        void* h = dlopen("libvulkan.so", RTLD_NOW | RTLD_GLOBAL);
        if (!h) {
            Log("native: vulkan inline: libvulkan.so dlopen failed");
        } else {
            InstallInlineTargetsFor(h, "libvulkan");
        }
    }
#endif
    ProbeIcdFeasibility();
}

static void OnVkHooked(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                       const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub; (void)new_func; (void)prev_func; (void)arg;
    if (g_vk_hooklog >= 32) return;
    g_vk_hooklog++;
    char c[128];
    snprintf(c, sizeof(c), "%s", caller_path_name ? caller_path_name : "?");
    Log("native: vulkan hook %s status=%d caller=%s", sym_name ? sym_name : "?", status_code, c);
}

void InstallVulkanHooks() {
    struct HookSpec { const char* sym; void* fn; };
    static const HookSpec kSpecs[] = {
        {"vkGetPhysicalDeviceProperties", (void*)MyVkGetPhysicalDeviceProperties},
        {"vkGetPhysicalDeviceProperties2", (void*)MyVkGetPhysicalDeviceProperties2},
        {"vkGetPhysicalDeviceProperties2KHR", (void*)MyVkGetPhysicalDeviceProperties2KHR},
        {"vkGetPhysicalDeviceFeatures", (void*)MyVkGetPhysicalDeviceFeatures},
        {"vkGetPhysicalDeviceFeatures2", (void*)MyVkGetPhysicalDeviceFeatures2},
        {"vkGetPhysicalDeviceFeatures2KHR", (void*)MyVkGetPhysicalDeviceFeatures2KHR},
        {"vkEnumerateDeviceExtensionProperties", (void*)MyVkEnumerateDeviceExtensionProperties},
        {"vkEnumerateInstanceExtensionProperties", (void*)MyVkEnumerateInstanceExtensionProperties},
        {"vkGetInstanceProcAddr", (void*)MyVkGetInstanceProcAddrGOT},
    };
    int ok = 0;
    for (const HookSpec& s : kSpecs) {
        bytehook_stub_t stub = bytehook_hook_partial(CallerAllowHooks, nullptr, "libvulkan.so",
                                                     s.sym, s.fn, OnVkHooked, nullptr);
        if (stub) ok++;
    }
    Log("native: vulkan hooks installed %d/%d", ok,
        (int)(sizeof(kSpecs) / sizeof(kSpecs[0])));
}

void InstallGpuDlsymChain() {
    void* dStub = HookChainStubDlsymChain("libc.so", "dlsym", (void*)MyDlsym);
    Log("native: dlsym chain libc.so stub=%d", dStub != nullptr);
    void* dStub2 = HookChainStubDlsymChain("libdl.so", "dlsym", (void*)MyDlsym);
    Log("native: dlsym chain libdl.so stub=%d", dStub2 != nullptr);
}

}  // namespace pas