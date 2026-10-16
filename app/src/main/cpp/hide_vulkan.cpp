// Vulkan identity spoof (GPU) for the scoped process.
//
// v2.4.5: VkPhysicalDeviceProperties now carries the spoofed core count and
// L2 cache size so DevCheck's Vulkan path sees a coherent device.
//
// v2.7.3:
//  - Inline backstop hooks the IMPLEMENTATION BODY (the thunk's jump target
//    when the export is an E9 thunk), not the export entry.
//  - Two patch strategies: 12-byte movabs+jmp when >=12 prologue bytes
//    decode; 5-byte jmp rel32 -> near page otherwise.
//  - Decode stops are logged with offset + bytes.
//  - Trampoline jump-back is RIP-indirect (touches no registers).
//  - WaitForGpuConfig race parity on the features2 path; VulkanSpoofActive
//    is the single gate inside PatchProps2/PatchFeatures2.
//  - LogVkHeaderProbes removed (enum constants are not macros - false alarm).
//
// v2.7.8 (diagnostics + ICD probe, nothing hooked speculatively):
//  - Every core-props patch logs the DELIVERED strings (capped 6/process),
//    including the previously-silent v1 vkGetPhysicalDeviceProperties calls.
//  - The props2 diag line now carries the delivered deviceName + vendorID.
//  - ICD-entry probe: a vk_icd* symbol resolved through the dlsym chain
//    (the loader itself is excluded from this chain) means APP code is
//    dispatching directly into the vendor ICD - the one in-process path no
//    loader-level hook covers, receiving the RAW identity (Adreno/Intel on
//    MuMu). One-shot diag names it.
//  - ICD feasibility probe: finds the loaded vendor ICD
//    (vulkan.<chip>.so) via dl_iterate_phdr, resolves
//    vk_icdGetInstanceProcAddr, and reports how many of the 8 target
//    functions its gipa returns with a NULL instance - the fact that
//    decides the ICD inline-hook layer's design (next step). Pure lookup.

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
// v2.7.8 diagnostics.
static volatile bool g_icd_entry_logged = false;
static volatile int g_coreprops_calllog = 0;

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
    // v2.7.8 diag (capped): the exact strings DELIVERED to the caller -
    // covers the previously-silent v1 vkGetPhysicalDeviceProperties calls
    // too. If a tool displays raw strings while these lines show Mali, the
    // display reads from a source other than any loader-path call.
    if (g_coreprops_calllog < 6) {
        g_coreprops_calllog++;
        Log("native: vk diag: core props delivered dev='%s' vid=0x%x did=0x%x api=0x%x",
            p->deviceName, p->vendorID, p->deviceID, p->apiVersion);
    }
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
        // v2.7.3: name the exact strings delivered, so a capture can prove
        // the node was patched with the spoofed values (not merely reached).
        Log("native: vulkan driverprops patched (name='%s' info='%s')",
            d->driverName, d->driverInfo);
    }
}

static void PatchProps2(VkPhysicalDeviceProperties2* out) {
    if (!out) return;
    WaitForGpuConfig(1500);
    // v2.7.3: VulkanSpoofActive is the single gate for every patch path
    // (PLT proxy, dlsym proxy, inline backstop) - the gpu options "vulkan"
    // toggle is now respected uniformly.
    if (!GpuSpoofActive() || !VulkanSpoofActive()) return;
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
    // v2.6.5 diag (capped; v2.7.8: carries the delivered dev/vid): log the
    // first properties2 calls that reach the proxy, with chain shape and
    // delivered identity, so a tool showing raw driver data is attributable.
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
    // v2.7.3: wait before gating (race parity with PatchProps2).
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
    (void*)VkPropsPtr,  (void*)VkProps2Ptr,  (void*)VkProps2KhrPtr,
    (void*)VkFeatPtr,   (void*)VkFeat2Ptr,   (void*)VkFeat2KhrPtr,
    (void*)VkExtDevPtr, (void*)VkExtInstPtr,
};

static void* MyVkGetInstanceProcAddrGOT(VkInstance instance, const char* name) {
    BYTEHOOK_STACK_SCOPE();
    // v2.7.8: once any vk activity flows through here, the vendor ICD is
    // loaded - run the (idempotent) feasibility probe.
    ProbeIcdFeasibility();
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
    ProbeIcdFeasibility();  // v2.7.8
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
// v2.7.3: set while the inline-backstop installer resolves hook targets via
// dlsym; those calls must receive REAL addresses, never our substituted
// proxies (otherwise we would inline-hook libpas' own wrapper functions).
// Declared outside the __x86_64__ guard: MyDlsym exists on every ABI.
// (CallerAllowDlsymChain already excludes libpas callers - this is a second,
// order-independent line of defense.)
static __thread int g_inline_resolving = 0;
static volatile bool g_second_gipa_diag = false;

// ---------------------------------------------------------------------------
// v2.7.8: vendor-ICD feasibility probe. The one in-process path no
// loader-level hook covers is an app bypassing the loader entirely:
// dlopen the vendor ICD (vulkan.<chip>.so), resolve
// vk_icdGetInstanceProcAddr, and dispatch through the ICD's own pointers -
// receiving the RAW device identity (Adreno name / Intel vendor+driver on
// MuMu). The probe determines (a) whether a vendor ICD is loaded here,
// (b) whether the ICD's gipa resolves our 8 target functions with a NULL
// instance - the feasibility fact for the ICD inline-hook layer that gets
// built on this evidence. Pure lookup: nothing is hooked, nothing is
// spoofed; the module's own dlsym calls run raw via g_inline_resolving.
// ---------------------------------------------------------------------------

struct PasIcdFinder {
    char name[256];
    bool found;
};

static int PasIcdPhdrCb(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    auto* f = (PasIcdFinder*)data;
    if (!info->dlpi_name) return 0;
    const char* n = info->dlpi_name;
    // Match /vendor/lib64/hw/vulkan.<chip>.so (the ICD); exclude the loader
    // (/system/lib64/libvulkan.so) and the ARM shim (/system/lib64/arm64/...)
    // by requiring the /hw/ or vendor path markers.
    if (strstr(n, "vulkan.") == nullptr || strstr(n, ".so") == nullptr) return 0;
    if (strstr(n, "/hw/") == nullptr && strstr(n, "vendor") == nullptr) return 0;
    snprintf(f->name, sizeof(f->name), "%s", n);
    f->found = true;
    return 1;  // stop iterating
}

void ProbeIcdFeasibility() {
    static volatile int state = 0;  // 0 = not run, 1 = deferred (no ICD yet), 2 = done
    if (state == 2) return;
    PasIcdFinder f = {};
    dl_iterate_phdr(PasIcdPhdrCb, &f);
    if (!f.found) {
        if (state == 0) {
            state = 1;
            Log("native: vk icd probe: no vendor ICD loaded yet - deferring "
                "(re-probed on first vk activity)");
        }
        return;
    }
    state = 2;
    g_inline_resolving = 1;
    void* icd = dlopen(f.name, RTLD_NOW | RTLD_LOCAL);
    g_inline_resolving = 0;
    void* sym = nullptr;
    g_inline_resolving = 1;
    if (icd) sym = dlsym(icd, "vk_icdGetInstanceProcAddr");
    if (!sym) sym = dlsym(RTLD_DEFAULT, "vk_icdGetInstanceProcAddr");
    g_inline_resolving = 0;
    if (!sym) {
        Log("native: vk icd probe: ICD '%s' loaded but vk_icdGetInstanceProcAddr unresolved",
            f.name);
        return;
    }
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
    Log("native: vk icd probe: ICD '%s' loaded; icd gipa(NULL) resolves %d/8 targets%s%s",
        f.name, resolved, missing[0] ? "; unresolved: " : "", missing);
}

static void* MyDlsym(void* handle, const char* symbol) {
    BYTEHOOK_STACK_SCOPE();
    void* real = BYTEHOOK_CALL_PREV(MyDlsym, handle, symbol);
    if (g_dlsym_depth > 0 || g_inline_resolving) return real;
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
        // v2.7.8: ICD-direct dispatch probe. The loader itself is excluded
        // from this dlsym chain (CallerAllowDlsymChain skips libvulkan.so
        // callers), so a vk_icd* resolution seen HERE is app code bypassing
        // the loader - the one in-process path no loader-level hook covers.
        if (strncmp(symbol, "vk_icd", 6) == 0) {
            if (!g_icd_entry_logged) {
                g_icd_entry_logged = true;
                Log("native: vk diag: vk_icd entry '%s' resolved via dlsym - "
                    "app-side ICD dispatch bypassing every loader hook", symbol);
            }
            // The ICD is loaded now - probe immediately.
            ProbeIcdFeasibility();
        }
        if (!GpuSpoofActive() || !VulkanSpoofActive()) break;
        if (strcmp(symbol, "vkGetInstanceProcAddr") == 0) {
            if (g_real_gipa == nullptr) {
                g_real_gipa = real;
            } else if (g_real_gipa != real) {
                // v2.6.5 diag; v2.7.3: inline body hooks close this hole
                // structurally - the diag remains for attribution.
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

// ---------------------------------------------------------------------------
// v2.7.3: x86_64 inline-hook backstop (hand-rolled, no dependencies).
//
// ARM-translated apps (MuMu/Houdini: arm64-only libraries executed through
// the native bridge) resolve Vulkan symbols outside every PLT/GOT surface
// the caller-side hooks can patch, and gipa-dispatched calls never execute
// the export thunks. Every Vulkan call, translated or not, eventually
// executes the real x86_64 libvulkan.so IMPLEMENTATION BODIES - inline-
// hooking those intercepts execution itself and cannot be bypassed by any
// resolution path. Patch helpers are idempotent, so double coverage (caller
// PLT/dlsym proxy above, inline hook underneath) is safe.
//
// v2.7.8 note: the analogous ICD-level backstop (hooking the vendor ICD's
// function bodies, covering apps that dispatch straight into the ICD) is
// NOT installed yet - ProbeIcdFeasibility() gathers the facts it needs
// (which functions the ICD's gipa resolves with a NULL instance), and the
// layer lands on that evidence.
// ---------------------------------------------------------------------------

#if defined(__x86_64__)

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static void* g_inline_orig[VK_T_COUNT] = {nullptr};

// Decode-stop description, for failure logging (v2.7.2 failed silently and
// mislabeled decoder stops as "write failed").
struct PasDecodeFail {
    bool valid;       // bytes/offset describe a real decode stop
    size_t offset;    // offset from function start of the undecodable insn
    uint8_t bytes[8]; // the bytes there, for the log line
};

static void FillFail(PasDecodeFail* fail, const uint8_t* at, size_t offset) {
    if (!fail) return;
    fail->valid = true;
    fail->offset = offset;
    for (int k = 0; k < 8; k++) fail->bytes[k] = at[k];
}

// Conservative x86_64 instruction length decoder. Returns the instruction
// length in bytes, or 0 to BAIL. `avail` = safely readable bytes at `c`.
// On success *ripDispOff = byte offset of a [rip+disp32] operand within the
// instruction (relocatable into a trampoline), else -1.
//
// Covers the instruction classes seen in Android -O2 prologues and loader
// dispatch bodies: endbr64, REX push/pop, nop, mov r,imm (B8+r), ModRM
// mov/lea/test/xchg/alu (byte and word forms, incl. adc/sbb), movsxd,
// grp1 imm (80/81/83), imul imm (69/6B), mov r/m,imm (C7), grp3 test/not/
// neg/mul/div (F6/F7), movzx/movsx/imul-rm (0F B6/B7/BE/BF/AF), multi-byte
// nop (0F 1F), cmp/test al/eax,imm (3C/3D/A8/A9), segment-prefixed stack
// canary loads, and register-indirect FF /0 /1 /2 /4 /6 (inc/dec/call/jmp/
// push r/m) - the loader dispatch pattern `mov rax,[rdi+N]; jmp [rax+M]`.
//
// Everything else bails: position-dependent control flow (E8/E9/EB/7x/0F8x,
// RIP-relative call/jmp [rip+disp32], FF /3 /5 /7), ret (C3/C2), shifts,
// string ops, VEX/EVEX, legacy operand/address-size prefixes, unknown bytes.
static size_t PasDecodeX64(const uint8_t* c, size_t avail, int* ripDispOff) {
    *ripDispOff = -1;
    if (avail < 1) return 0;
    if (avail >= 4 && c[0] == 0xF3 && c[1] == 0x0F && c[2] == 0x1E && c[3] == 0xFA)
        return 4;  // endbr64

    size_t i = 0;
    bool rexW = false;
    int segSkip = 0;
    while (i < avail && (c[i] == 0x64 || c[i] == 0x65)) {  // fs/gs canary loads
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
            return i;  // push/pop r
        case 0x90:
            return i;  // nop
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            imm = rexW ? 8 : 4;  // mov r, imm32 / movabs r, imm64
            break;
        case 0x3C: case 0xA8:  // cmp al,imm8 / test al,imm8
            return i + 1;
        case 0x3D: case 0xA9:  // cmp eax,imm32 / test eax,imm32
            return i + 4;
        case 0x00: case 0x02: case 0x08: case 0x0A:
        case 0x10: case 0x12: case 0x18: case 0x1A:
        case 0x20: case 0x22: case 0x28: case 0x2A:
        case 0x30: case 0x32: case 0x38: case 0x3A:  // byte-form alu
        case 0x01: case 0x03: case 0x09: case 0x0B:
        case 0x11: case 0x13: case 0x19: case 0x1B:
        case 0x21: case 0x23: case 0x29: case 0x2B:
        case 0x31: case 0x33: case 0x39: case 0x3B:  // word-form alu
        case 0x63:                                    // movsxd
        case 0x84: case 0x85:                         // test r/m, r
        case 0x86: case 0x87:                         // xchg
        case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8D:
            kind = K_MODRM;
            allowRipRel = true;
            break;
        case 0x80: kind = K_MODRM; imm = 1; break;  // grp1 r/m8, imm8
        case 0x81: kind = K_MODRM; imm = 4; break;  // grp1 r/m,  imm32
        case 0x83: kind = K_MODRM; imm = 1; break;  // grp1 r/m,  imm8
        case 0x69: kind = K_MODRM; imm = 4; break;  // imul r, r/m, imm32
        case 0x6B: kind = K_MODRM; imm = 1; break;  // imul r, r/m, imm8
        case 0xC7: kind = K_MODRM; imm = 4; break;  // mov r/m, imm32
        case 0xF6: kind = K_GRP3; imm = 1; allowRipRel = true; break;
        case 0xF7: kind = K_GRP3; imm = 4; allowRipRel = true; break;
        case 0xFF: kind = K_GRP5; break;
        case 0x0F: {
            if (i >= avail) return 0;
            uint8_t op2 = c[i];
            if (op2 == 0x1F) {  // multi-byte nop (0F 1F /0)
                i++;
                kind = K_MODRM;
                allowRipRel = true;
                break;
            }
            if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF ||
                op2 == 0xAF) {  // movzx / movsx / imul r, r/m
                i++;
                kind = K_MODRM;
                allowRipRel = true;
                break;
            }
            return 0;  // all other 0F opcodes: bail
        }
        default:
            return 0;  // unknown or position-dependent control flow: bail
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

    if (kind == K_GRP3 && reg > 1) imm = 0;  // NOT/NEG/MUL/DIV: no immediate
    if (kind == K_GRP5) {
        // reg 0 inc, 1 dec, 2 call, 4 jmp, 6 push: copyable (register or
        // register-indirect operand; RIP-relative DATA access - inc/dec/push
        // - relocates like any riprel). reg 3 call-far, 5 jmp-far, 7: bail.
        if (reg == 3 || reg == 5 || reg == 7) return 0;
        // call/jmp [rip+disp32]: position-dependent target: bail.
        if (isRipRel && (reg == 2 || reg == 4)) return 0;
        if (isRipRel) allowRipRel = true;
    }

    if (mod == 3) {
        // register operand: nothing further
    } else if (rm == 4) {  // SIB
        if (i >= avail) return 0;
        uint8_t sib = c[i];
        i++;
        uint8_t base = (uint8_t)(sib & 7);
        if (mod == 0) {
            if (base == 5) {
                if (i + 4 > avail) return 0;
                i += 4;  // [index*scale + disp32]: absolute, no relocation
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
        // mod 0, rm 0-3/6/7: register indirect, no displacement
    }

    if (i > 15) return 0;
    if (imm) {
        if (i + imm > avail) return 0;
        i += imm;
    }
    if (i > 15) return 0;
    return i;
}

// How many bytes from the start decode cleanly (stops at `want`, or at the
// first undecodable instruction)? `fail` is filled only on an early stop.
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

// Copy displaced instructions (RIP-relative disp32 operands relocated) into
// the trampoline, then jump back with `jmp qword ptr [rip+0]` + an 8-byte
// address literal - touches no registers. `fail` (optional) is filled when
// decoding stops short of needBytes.
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
            // Relocate: newDisp = oldDisp + (origInsn - trampInsn)
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
    // jump back: jmp qword ptr [rip+0] ; <8-byte address>
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

// Write strategy: mprotect+memcpy first; on hardened targets where adding W
// to file-backed code is denied (TEXTREL/execmod protections), fall back to
// a /proc/self/mem write, which the kernel performs via COW without any
// page-protection change.
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

// mmap one RWX page within rel32 range of `target` (16 MB steps, both
// directions, up to ~2 GB). Returns nullptr when nothing can be placed.
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

// Strategy 1: 12-byte patch `movabs rax, wrapper; jmp rax` at the target;
// *origOut receives the trampoline (displaced code + jump back).
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

// Strategy 2: 5-byte patch `jmp rel32` at the target into a near page that
// holds the entry thunk (movabs rax, wrapper; jmp rax) followed by the
// displaced-code trampoline. Needs only >=5 decodable bytes.
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
    if (rel < INT32_MIN || rel > INT32_MAX) {  // FindNearPage guarantees this
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
    // v2.7.3: no pre-gate - PatchProps2 waits for the config and gates
    // internally.
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
        ProbeIcdFeasibility();
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

    int ok = 0, notExported = 0;
    for (int i = 0; i < VK_T_COUNT; i++) {
        // Real addresses only: g_inline_resolving keeps our own dlsym chain
        // hook from substituting proxies during installation.
        g_inline_resolving = 1;
        void* target = dlsym(h, specs[i].sym);
        g_inline_resolving = 0;
        if (!target) {
            notExported++;
            Log("native: vulkan inline: %s not exported (KHR name resolves via "
                "gipa into the hooked core body)", specs[i].sym);
            continue;
        }

        // Follow E9 thunk chains (export thunks, chained thunks) to the
        // implementation body. Thunks are pure jumps - skipping them when
        // calling orig is safe.
        const uint8_t* tb = (const uint8_t*)target;
        void* body = target;
        bool thunk = false;
        for (int hops = 0; ((const uint8_t*)body)[0] == 0xE9 && hops < 4; hops++) {
            int32_t rel;
            memcpy(&rel, (const uint8_t*)body + 1, 4);
            body = (void*)((uintptr_t)body + 5 + (int64_t)rel);
            thunk = true;
        }

        // Hook the BODY, never just the export: gipa hands out body pointers
        // (loader-internal trampolines), so gipa-dispatched calls never
        // execute the export thunk.
        PasDecodeFail fail = {};
        size_t dec = PasProbeDecodable((const uint8_t*)body, 12, &fail);
        if (dec >= 12 && PasInlineHookX64(body, specs[i].fn, &g_inline_orig[specs[i].id])) {
            ok++;
            Log("native: vulkan inline: %s body hooked (12-byte%s)", specs[i].sym,
                thunk ? ", thunk target" : "");
            continue;
        }
        if (dec >= 5 && PasInlineHookE9(body, specs[i].fn, &g_inline_orig[specs[i].id])) {
            ok++;
            Log("native: vulkan inline: %s body hooked (5-byte e9%s)", specs[i].sym,
                thunk ? ", thunk target" : "");
            continue;
        }
        if (dec >= 5) {
            Log("native: vulkan inline: %s code write failed (%zu bytes decodable; "
                "see PasWriteCode diagnostics)", specs[i].sym, dec);
        } else if (fail.valid) {
            Log("native: vulkan inline: %s body+%zu unsupported bytes "
                "%02x %02x %02x %02x %02x %02x %02x %02x (first %zu bytes decodable)",
                specs[i].sym, fail.offset, fail.bytes[0], fail.bytes[1], fail.bytes[2],
                fail.bytes[3], fail.bytes[4], fail.bytes[5], fail.bytes[6], fail.bytes[7],
                dec);
        }
        if (!thunk) continue;

        // Fallback (export-entry calls ONLY - gipa-dispatched calls bypass
        // it): rewrite the export thunk's rel32 to a near page that jumps to
        // the wrapper. orig = the final hop destination.
        uint8_t* nearTramp = FindNearPage((uintptr_t)target);
        if (!nearTramp) {
            Log("native: vulkan inline: %s no near page for thunk fallback", specs[i].sym);
            continue;
        }
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
            Log("native: vulkan inline: %s thunk fallback out of range", specs[i].sym);
            continue;
        }
        int32_t nr = (int32_t)newRel;
        if (!PasWriteCode((void*)(tb + 1), &nr, 4)) {
            munmap(nearTramp, 4096);
            continue;
        }
        g_inline_orig[specs[i].id] = body;
        ok++;
        Log("native: vulkan inline: %s thunk hooked (fallback: body not hookable - "
            "gipa-dispatched calls NOT covered)", specs[i].sym);
    }
    Log("native: vulkan inline hooks installed %d/%d (%d not exported; those are "
        "covered via the core bodies) (x86_64 backstop)", ok, VK_T_COUNT, notExported);
    // v2.7.8: gather the ICD feasibility facts now that Vulkan is live.
    ProbeIcdFeasibility();
}

#else

void InstallVulkanInlineBackstop() {
    // Inline backstop is x86_64-only; the ICD probe runs everywhere (diag).
    ProbeIcdFeasibility();
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