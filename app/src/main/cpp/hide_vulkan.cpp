// Vulkan identity spoof (GPU) for the scoped process.
//
// v2.4.5: VkPhysicalDeviceProperties now carries the spoofed core count and
// L2 cache size so DevCheck's Vulkan path sees a coherent device.

#include "pas.h"

#include <dlfcn.h>
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#define VK_NO_PROTOTYPES 1
#include <vulkan/vulkan.h>

#include "bytehook.h"

namespace pas {

static bool IsHiddenExtName(const char* name) {
    if (!name) return false;
    if (strstr(name, "NEMU") != nullptr) return true;
    return false;
}

static volatile int g_gpu_conf_major = 1;
static volatile int g_gpu_conf_minor = 3;
static volatile int g_gpu_conf_sub = 1;
static volatile int g_gpu_conf_patch = 0;
static volatile int g_gpu_driver_id = 0;
static volatile int g_gpu_desc_indexing = 0;
static volatile int g_gpu_sparse_binding = 0;

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
    // v2.5.9: early queries may precede the config thread; wait briefly so
    // ANGLE/Chrome cannot cache the real GPU identity (same race as GL).
    WaitForGpuConfig(1500);
    // v2.4.5: DevCheck reads the GPU core count and L2 cache from the
    // device name / driver info for Mali. We build a coherent string that
    // carries those values.
    char deviceName[256];
    snprintf(deviceName, sizeof(deviceName), "%s", GpuSpoofVkDeviceName().c_str());
    snprintf(p->deviceName, sizeof(p->deviceName), "%s", deviceName);
    p->vendorID = (uint32_t)GpuSpoofVendorId();
    p->deviceID = (uint32_t)GpuSpoofDeviceId();
    p->driverVersion = (uint32_t)GpuSpoofDriverVersion();
    p->apiVersion = (uint32_t)GpuSpoofApiVersion();
}

static void LogVkHeaderProbes() {
#ifdef VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES
    Log("native: vk probe drvprops=macro");
#else
    Log("native: vk probe drvprops=missing");
#endif
#ifdef VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES
    Log("native: vk probe vk12feat=macro");
#else
    Log("native: vk probe vk12feat=missing");
#endif
#ifdef VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES
    Log("native: vk probe vk13feat=macro");
#else
    Log("native: vk probe vk13feat=missing");
#endif
}

static volatile bool g_drvprops_logged = false;
static volatile bool g_props2_node_diag = false;
static volatile int g_props2_calllog = 0;

static const uint32_t kPasDriverPropsSType = 1000196000u;

struct PasDriverProps {
    VkStructureType sType;
    void* pNext;
    uint32_t driverID;
    char driverName[256];
    char driverInfo[256];
    uint8_t conformance[4];
};

static void PatchDriverPropsNode(void* node) {
    if (node == nullptr || !GpuSpoofActive()) return;
    auto* d = (PasDriverProps*)node;
    if (g_gpu_driver_id > 0) d->driverID = (uint32_t)g_gpu_driver_id;
    snprintf(d->driverName, sizeof(d->driverName), "%s", GpuSpoofDriverName().c_str());
    // v2.4.5: append core count + L2 cache to the driver info so DevCheck's
    // Vulkan path sees the same physical data as the sysfs path.
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
        Log("native: vulkan driverprops patched");
    }
}

static void PatchProps2(VkPhysicalDeviceProperties2* out) {
    if (!out) return;
    WaitForGpuConfig(1500);
    if (!GpuSpoofActive()) return;
    PatchCoreProps(&out->properties);
    int guard = 0;
    bool foundDriverProps = false;
    for (VkBaseOutStructure* s = (VkBaseOutStructure*)out->pNext;
         s != nullptr && guard < 32; s = s->pNext, guard++) {
        if ((uint32_t)s->sType == kPasDriverPropsSType) {
            PatchDriverPropsNode((void*)s);
            foundDriverProps = true;
        }
    }
    // v2.6.5 diag (capped): log the first properties2 calls that reach the
    // proxy, with chain shape, so a tool showing real driver data is
    // attributable: found=1 + real display => display source is elsewhere;
    // no calls logged at all => the tool resolved a raw pointer elsewhere.
    if (g_props2_calllog < 12) {
        g_props2_calllog++;
        VkBaseOutStructure* s = (VkBaseOutStructure*)out->pNext;
        uint32_t st0 = s ? (uint32_t)s->sType : 0;
        int nodes = 0;
        for (VkBaseOutStructure* t = s; t != nullptr && nodes < 32; t = t->pNext, nodes++) {
        }
        Log("native: vk diag: props2 found=%d nodes=%d firstSType=%u",
            foundDriverProps ? 1 : 0, nodes, st0);
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
    if (!out || !GpuSpoofActive()) return;
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

static void MyVkGetPhysicalDeviceProperties(VkPhysicalDevice pd, VkPhysicalDeviceProperties* out) {
    BYTEHOOK_STACK_SCOPE();
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceProperties, pd, out);
    if (!out) return;
    WaitForGpuConfig(1500);
    if (!GpuSpoofActive()) return;
    PatchCoreProps(out);
}

static void MyVkGetPhysicalDeviceProperties2(VkPhysicalDevice pd,
                                             VkPhysicalDeviceProperties2* out) {
    BYTEHOOK_STACK_SCOPE();
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceProperties2, pd, out);
    PatchProps2(out);
}

static void MyVkGetPhysicalDeviceProperties2KHR(VkPhysicalDevice pd,
                                                VkPhysicalDeviceProperties2* out) {
    BYTEHOOK_STACK_SCOPE();
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceProperties2KHR, pd, out);
    PatchProps2(out);
}

static void MyVkGetPhysicalDeviceFeatures(VkPhysicalDevice pd, VkPhysicalDeviceFeatures* out) {
    BYTEHOOK_STACK_SCOPE();
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceFeatures, pd, out);
    if (!out || !GpuSpoofActive()) return;
    PatchFeatures(out);
}

static void MyVkGetPhysicalDeviceFeatures2(VkPhysicalDevice pd, VkPhysicalDeviceFeatures2* out) {
    BYTEHOOK_STACK_SCOPE();
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceFeatures2, pd, out);
    PatchFeatures2(out);
}

static void MyVkGetPhysicalDeviceFeatures2KHR(VkPhysicalDevice pd, VkPhysicalDeviceFeatures2* out) {
    BYTEHOOK_STACK_SCOPE();
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceFeatures2KHR, pd, out);
    PatchFeatures2(out);
}

static VkResult FilterExtList(uint32_t* count, VkExtensionProperties* props, VkResult r) {
    if (!GpuSpoofActive() || !count || !props) return r;
    uint32_t got = *count;
    uint32_t kept = 0;
    for (uint32_t i = 0; i < got; i++) {
        if (IsHiddenExtName(props[i].extensionName)) continue;
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

static void* g_real_gipa = nullptr;
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
    (void*)VkPropsPtr,  (void*)VkProps2Ptr, (void*)VkProps2KhrPtr,
    (void*)VkFeatPtr,   (void*)VkFeat2Ptr,  (void*)VkFeat2KhrPtr,
    (void*)VkExtDevPtr, (void*)VkExtInstPtr,
};

static void* MyVkGetInstanceProcAddrGOT(VkInstance instance, const char* name) {
    BYTEHOOK_STACK_SCOPE();
    void* real = BYTEHOOK_CALL_PREV(MyVkGetInstanceProcAddrGOT, instance, name);
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
    PasGipaFn gipa = (PasGipaFn)g_real_gipa;
    if (!gipa) return nullptr;
    void* real = gipa(instance, name);
    if (!GpuSpoofActive() || !VulkanSpoofActive() || !name || !real) return real;
    int id = TargetIndex(name);
    if (id >= 0) {
        if (g_vk_real[id] == nullptr) {
            g_vk_real[id] = real;
            ChainLog(id, "dlsym hit");
            return kVkProxies[id];
        }
        if (g_vk_real[id] != real) return real;
        return kVkProxies[id];
    }
    return real;
}

static __thread int g_dlsym_depth = 0;
static volatile bool g_second_gipa_diag = false;

static void* MyDlsym(void* handle, const char* symbol) {
    BYTEHOOK_STACK_SCOPE();
    void* real = BYTEHOOK_CALL_PREV(MyDlsym, handle, symbol);
    if (g_dlsym_depth > 0) return real;
    g_dlsym_depth = 1;
    void* out = real;
    do {
        if (real == nullptr) break;
        void* sub = GpuChainResolveDlsym(symbol, real);
        if (sub != nullptr) {
            out = sub;
            break;
        }
        if (!symbol || symbol[0] != 'v' || symbol[1] != 'k') break;
        if (!GpuSpoofActive() || !VulkanSpoofActive()) break;
        if (strcmp(symbol, "vkGetInstanceProcAddr") == 0) {
            if (g_real_gipa == nullptr) {
                g_real_gipa = real;
            } else if (g_real_gipa != real) {
                // v2.6.5 diag: a second, different gipa address was resolved.
                // The current code passes it through raw - if a tool resolves
                // its functions through this one, its queries bypass every
                // proxy (observed as real driver-name leak in DevCheck).
                if (!g_second_gipa_diag) {
                    g_second_gipa_diag = true;
                    Log("native: vk diag: second gipa address seen - passed through raw");
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

// ---------------------------------------------------------------------------
// v2.6.3: x86_64 inline-hook backstop (Dobby).
//
// ARM-translated apps (MuMu/Houdini: arm64-only libraries executed through
// the native bridge) resolve Vulkan symbols outside every PLT/GOT surface the
// caller-side hooks can patch - the ARM linker's GOT is runtime-managed by
// the translation layer and is deliberately not touched - so the real GPU
// identity leaked through (e.g. DevCheck's updated Vulkan probe).
//
// Every Vulkan call, translated or not, eventually executes the real x86_64
// libvulkan.so function bodies. Inline-hooking those exports intercepts
// execution itself and cannot be bypassed by any resolution path (static
// import, dlsym, PLT, translated call). The patch helpers below are
// idempotent, so double coverage (caller PLT hook fires first, inline hook
// fires underneath) is safe and produces identical results.
// ---------------------------------------------------------------------------

#if defined(__x86_64__) && defined(PAS_HAVE_DOBBY)

#include "dobby.h"

static void* g_inline_orig[VK_T_COUNT] = {nullptr};

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
    if (out && GpuSpoofActive() && VulkanSpoofActive()) PatchProps2(out);
}

static void InlineVkGetPhysicalDeviceProperties2KHR(VkPhysicalDevice pd,
                                                    VkPhysicalDeviceProperties2* out) {
    auto orig = (PFN_vkGetPhysicalDeviceProperties2)g_inline_orig[VK_T_PROP2K];
    if (orig) orig(pd, out);
    if (out && GpuSpoofActive() && VulkanSpoofActive()) PatchProps2(out);
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
    if (out && GpuSpoofActive() && VulkanSpoofActive()) PatchFeatures2(out);
}

static void InlineVkGetPhysicalDeviceFeatures2KHR(VkPhysicalDevice pd,
                                                  VkPhysicalDeviceFeatures2* out) {
    auto orig = (PFN_vkGetPhysicalDeviceFeatures2)g_inline_orig[VK_T_FEAT2K];
    if (orig) orig(pd, out);
    if (out && GpuSpoofActive() && VulkanSpoofActive()) PatchFeatures2(out);
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
        // Size query: report the count with hidden extensions subtracted.
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

void InstallVulkanInlineBackstop() {
    static int g_inline_state = 0;  // 0 = not tried, 1 = installed/attempted
    if (g_inline_state) return;
    g_inline_state = 1;

    void* h = dlopen("libvulkan.so", RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        Log("native: vulkan inline: libvulkan.so dlopen failed");
        return;
    }

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

    int ok = 0;
    for (int i = 0; i < VK_T_COUNT; i++) {
        void* target = dlsym(h, specs[i].sym);
        if (!target) {
            Log("native: vulkan inline: %s not found", specs[i].sym);
            continue;
        }
        if (DobbyHook(target, specs[i].fn, &g_inline_orig[specs[i].id]) == 0) {
            ok++;
        } else {
            Log("native: vulkan inline: %s hook failed", specs[i].sym);
        }
    }
    Log("native: vulkan inline hooks installed %d/%d (x86_64 backstop)", ok, VK_T_COUNT);
}

#else

void InstallVulkanInlineBackstop() {
    // Inline backstop is x86_64-only; ARM builds rely on the PLT/dlsym layers.
}

#endif

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
    LogVkHeaderProbes();
    struct HookSpec {
        const char* sym;
        void* fn;
    };
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
    // v2.6.5: use the broadened dlsym-chain filter so Houdini's forwarding
    // machinery (resolving ARM public-library shims on MuMu-style emulators)
    // receives spoofed GL/Vulkan pointers for ARM-translated apps.
    void* dStub = HookChainStubDlsymChain("libc.so", "dlsym", (void*)MyDlsym);
    Log("native: dlsym chain libc.so stub=%d", dStub != nullptr);
    void* dStub2 = HookChainStubDlsymChain("libdl.so", "dlsym", (void*)MyDlsym);
    Log("native: dlsym chain libdl.so stub=%d", dStub2 != nullptr);
}

}  // namespace pas