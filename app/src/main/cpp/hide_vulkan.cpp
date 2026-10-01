// Vulkan identity spoof (GPU) for the scoped process.
//
// The emulator's Vulkan surfaces leak the host GPU: Intel driver strings and
// device IDs, Mesa-style driver versions, and custom extensions such as
// VK_NEMU_api_batch. When the GPU spoof is enabled this layer rewrites the
// identity a scoped app sees:
//   - vkGetPhysicalDeviceProperties(2): deviceName / vendorID / deviceID /
//     driverVersion / apiVersion, plus driverName / driverInfo /
//     conformanceVersion through the VkPhysicalDeviceDriverProperties node
//   - vkGetPhysicalDeviceFeatures(2): feature flags aligned with the
//     reference GPU profile (shaderFloat64 off, descriptorIndexing off,
//     dynamicRendering / synchronization2 on)
//   - extension enumeration: emulator-specific extensions are dropped from
//     the device/instance lists so the reported set stays consistent.
//
// Installed only when the GPU spoof is enabled at process start; only the
// identity is touched - the driver keeps serving its real formats, limits
// and API behavior.

#include "pas.h"

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

// Extensions that never exist on the emulated GPU profile and would unmask
// the emulator on inspection (NetEase MuMu advertises VK_NEMU_api_batch).
static bool IsHiddenExtName(const char* name) {
    if (!name) return false;
    if (strstr(name, "NEMU") != nullptr) return true;
    if (strcmp(name, "VK_KHR_push_descriptor") == 0) return true;
    return false;
}

static void PatchCoreProps(VkPhysicalDeviceProperties* p) {
    if (!p) return;
    snprintf(p->deviceName, sizeof(p->deviceName), "%s", GpuSpoofRenderer().c_str());
    p->vendorID = (uint32_t)GpuSpoofVendorId();
    p->deviceID = (uint32_t)GpuSpoofDeviceId();
    p->driverVersion = (uint32_t)GpuSpoofDriverVersion();
    p->apiVersion = (uint32_t)GpuSpoofApiVersion();
}

// Diagnostics: which Vulkan structure-type names the build's headers expose as
// macros. Modern Vulkan headers declare them as enum members only, so classic
// #ifdef guards are always false and would silently compile patches out.
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

// VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES (1000196000, Vulkan 1.2)
// is matched by value and patched through a local ABI layout
// (driverName / driverInfo are 256 bytes each), so the driver row is fixed
// regardless of how old or new the build's Vulkan headers are.
static volatile bool g_drvprops_logged = false;

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
    snprintf(d->driverName, sizeof(d->driverName), "%s", GpuSpoofDriverName().c_str());
    snprintf(d->driverInfo, sizeof(d->driverInfo), "%s", GpuSpoofDriverInfo().c_str());
    d->conformance[0] = 1;
    d->conformance[1] = 3;
    d->conformance[2] = 1;
    d->conformance[3] = 0;
    if (!g_drvprops_logged) {
        g_drvprops_logged = true;
        Log("native: vulkan driverprops patched");
    }
}

static void PatchProps2(VkPhysicalDeviceProperties2* out) {
    if (!out || !GpuSpoofActive()) return;
    PatchCoreProps(&out->properties);
    int guard = 0;
    for (VkBaseOutStructure* s = (VkBaseOutStructure*)out->pNext; s != nullptr && guard < 32;
         s = s->pNext, guard++) {
        if ((uint32_t)s->sType == kPasDriverPropsSType) {
            PatchDriverPropsNode((void*)s);
        }
    }
}

static void PatchFeatures(VkPhysicalDeviceFeatures* f) {
    if (!f) return;
    f->shaderFloat64 = VK_FALSE;
}

static void PatchFeatures2(VkPhysicalDeviceFeatures2* out) {
    if (!out || !GpuSpoofActive()) return;
    PatchFeatures(&out->features);
    int guard = 0;
    for (VkBaseOutStructure* s = (VkBaseOutStructure*)out->pNext; s != nullptr && guard < 32;
         s = s->pNext, guard++) {
        if (s->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES) {
            ((VkPhysicalDeviceVulkan12Features*)s)->descriptorIndexing = VK_FALSE;
        }
        if (s->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES) {
            auto* f13 = (VkPhysicalDeviceVulkan13Features*)s;
            f13->dynamicRendering = VK_TRUE;
            f13->synchronization2 = VK_TRUE;
        }
    }
}

// ---------------------------------------------------------------------------
// proxies
// ---------------------------------------------------------------------------

static void MyVkGetPhysicalDeviceProperties(VkPhysicalDevice pd, VkPhysicalDeviceProperties* out) {
    BYTEHOOK_STACK_SCOPE();
    BYTEHOOK_CALL_PREV(MyVkGetPhysicalDeviceProperties, pd, out);
    if (!out || !GpuSpoofActive()) return;
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

// Compacts the caller's array in place, dropping hidden extension names; the
// returned count shrinks accordingly.
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
    if (layer != nullptr && layer[0] != '\0') return r;  // layered enumeration untouched
    if (props == nullptr) {
        // First call: report the filtered total so the caller sizes its
        // buffer correctly; probe the hidden entries with a scratch list.
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

// ---------------------------------------------------------------------------
// Loader-chain coverage (Chrome / WebView / ANGLE-style consumers)
//
// Browsers and ANGLE resolve the Vulkan entry points through
// vkGetInstanceProcAddr and dlsym instead of direct PLT calls, which bypasses
// the GOT hooks above. The resolver chain is wrapped as well so the identity
// queries are answered from the spoofed profile on that path too.
// ---------------------------------------------------------------------------

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
    if (out && GpuSpoofActive()) PatchCoreProps(out);
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
    if (out && GpuSpoofActive()) PatchFeatures(out);
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

// vkGetInstanceProcAddr, covered both for direct (GOT) callers and for
// consumers that obtained it through dlsym.
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
        g_vk_real[id] = real;
        ChainLog(id, "dlsym hit");
        return kVkProxies[id];
    }
    return real;
}

static __thread int g_dlsym_depth = 0;

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
            g_real_gipa = real;
            out = (void*)MyVkGetInstanceProcAddrPtr;
            break;
        }
        int id = TargetIndex(symbol);
        if (id >= 0) {
            g_vk_real[id] = real;
            ChainLog(id, "dlsym direct");
            out = kVkProxies[id];
        }
    } while (0);
    g_dlsym_depth = 0;
    return out;
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

static volatile int g_vk_hooklog = 0;

static void OnVkHooked(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                       const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub;
    (void)new_func;
    (void)prev_func;
    (void)arg;
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

// The GL loader chain: engines (Chrome / WebView / ANGLE-style) resolve GL
// entry points through dlsym; cover that path for graphics-family callers
// only (keeps the process-wide loader untouched for unrelated libraries).
void InstallGpuDlsymChain() {
    void* dStub = HookChainStubGfx("libc.so", "dlsym", (void*)MyDlsym);
    Log("native: dlsym chain libc.so stub=%d", dStub != nullptr);
    void* dStub2 = HookChainStubGfx("libdl.so", "dlsym", (void*)MyDlsym);
    Log("native: dlsym chain libdl.so stub=%d", dStub2 != nullptr);
}

}  // namespace pas
