// Vulkan identity spoof (GPU) for the scoped process.
//
// v2.4.5: VkPhysicalDeviceProperties now carries the spoofed core count and
// L2 cache size so DevCheck's Vulkan path sees a coherent device.

#include "pas.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
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

#if defined(__x86_64__)

static void* g_inline_orig[VK_T_COUNT] = {nullptr};

// ---------------------------------------------------------------------------
// Minimal fail-safe x86_64 inline hook engine (no external dependencies).
//
// Trampoline-based: the target's displaced prologue instructions are copied
// into an executable trampoline (RIP-relative disp32 operands relocated),
// followed by an absolute jump back to target+displaced. The target is then
// patched with `movabs rax, wrapper; jmp rax` (12 bytes).
//
// Every displaced instruction must be understood by the conservative decoder
// below or the hook is ABORTED for that function (logged): unknown bytes mean
// "not hooked" (identical to today's behavior), never a crash.
// ---------------------------------------------------------------------------

// Conservative x86_64 instruction length decoder. Returns the instruction
// length in bytes, or 0 to BAIL. `avail` = safely readable bytes at `c`
// (the builder passes 16). On success *ripDispOff = byte offset of a
// [rip+disp32] operand within the instruction (relocatable), else -1.
// Covers exactly the instruction classes seen in Android -O2 prologues:
// endbr64, REX push/pop, nop, mov r,imm, ModRM mov/lea/test/xchg/alu,
// grp1 imm (83/81), imul imm (69/6B), mov r/m,imm (C7), 0F1F multi-byte nop.
// Everything else - control flow (E8/E9/EB/70-7F/0F8x/FF/C3/C2), shifts,
// string ops, VEX/EVEX, unknown - bails.
static size_t PasDecodeX64(const uint8_t* c, size_t avail, int* ripDispOff) {
    *ripDispOff = -1;
    if (avail < 1) return 0;
    if (avail >= 4 && c[0] == 0xF3 && c[1] == 0x0F && c[2] == 0x1E && c[3] == 0xFA)
        return 4;  // endbr64

    size_t i = 0;
    bool rexW = false;
    if (c[0] >= 0x40 && c[0] <= 0x4F) {
        rexW = (c[0] & 0x08) != 0;
        i = 1;
        if (i >= avail) return 0;
    }

    uint8_t op = c[i];
    i++;

    bool modrm = false, allowRipRel = false;
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
        case 0x89: case 0x8B: case 0x8D: case 0x85: case 0x87:
        case 0x01: case 0x03: case 0x09: case 0x0B:
        case 0x21: case 0x23: case 0x29: case 0x2B:
        case 0x31: case 0x33: case 0x39: case 0x3B:
        case 0x63:
            modrm = true; allowRipRel = true;
            break;
        case 0x83: modrm = true; imm = 1; break;
        case 0x81: modrm = true; imm = 4; break;
        case 0x69: modrm = true; imm = 4; break;
        case 0x6B: modrm = true; imm = 1; break;
        case 0xC7: modrm = true; imm = 4; break;
        case 0x0F: {
            if (i >= avail) return 0;
            if (c[i] == 0x1F) {  // multi-byte nop (0F 1F /0)
                i++;
                modrm = true; allowRipRel = true;
                break;
            }
            return 0;  // any other 0F opcode: bail
        }
        default:
            return 0;  // unknown/control flow: bail
    }

    if (i > 15) return 0;

    if (!modrm) return i + imm;

    if (i > 14) return 0;
    if (i >= avail) return 0;
    uint8_t mrm = c[i];
    i++;
    uint8_t mod = (uint8_t)(mrm >> 6);
    uint8_t rm = (uint8_t)(mrm & 7);
    if (mod == 3) {
        // register form, nothing further
    } else if (rm == 4) {
        if (i >= avail) return 0;
        uint8_t sib = c[i];
        i++;
        uint8_t base = (uint8_t)(sib & 7);
        if (mod == 0) {
            if (base == 5) {
                if (i + 4 > avail) return 0;
                i += 4;  // disp32, absolute (no base) - no relocation
            }
        } else {
            i += (mod == 1) ? 1 : 4;
        }
    } else if (mod == 0 && rm == 5) {  // RIP-relative (mod 0 only)
        if (!allowRipRel) return 0;
        if (i + 4 > avail) return 0;
        *ripDispOff = (int)i;
        i += 4;
    } else {
        // mod 1/2: disp8/disp32; mod 0 with rm 0-3, 6, 7: register indirect
        // (no displacement)
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

// Copy the displaced instructions to the trampoline, relocating RIP-relative
// disp32 operands, then append an absolute jump back to target+copied.
static bool PasBuildTrampoline(const uint8_t* target, size_t needBytes,
                               uint8_t* tramp, size_t trampCap, size_t* copiedOut) {
    size_t copied = 0;
    while (copied < needBytes) {
        int ripOff = -1;
        size_t len = PasDecodeX64(target + copied, 16, &ripOff);
        if (len == 0 || copied + len + 13 > trampCap) return false;
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
    // jump back: movabs r11, addr ; jmp r11
    uintptr_t back = (uintptr_t)target + copied;
    tramp[copied++] = 0x49;
    tramp[copied++] = 0xBA;
    memcpy(tramp + copied, &back, 8);
    copied += 8;
    tramp[copied++] = 0x41;
    tramp[copied++] = 0xFF;
    tramp[copied++] = 0xE3;
    *copiedOut = copied;
    return true;
}

// Install an inline hook: target's first >=12 bytes become
// `movabs rax, wrapper; jmp rax`; *origOut receives the trampoline.
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

static bool PasInlineHookX64(void* target, void* wrapper, void** origOut) {
    uint8_t* tramp = (uint8_t*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) return false;
    size_t copied = 0;
    if (!PasBuildTrampoline((const uint8_t*)target, 12, tramp, 4096, &copied)) {
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
        int ripOff = -1;
        size_t firstLen = PasDecodeX64((const uint8_t*)target, 16, &ripOff);
        if (firstLen == 0) {
            const uint8_t* b = (const uint8_t*)target;
            Log("native: vulkan inline: %s unsupported prologue bytes "
                "%02x %02x %02x %02x %02x %02x %02x %02x",
                specs[i].sym, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
            continue;
        }
        if (PasInlineHookX64(target, specs[i].fn, &g_inline_orig[specs[i].id])) {
            ok++;
        } else {
            Log("native: vulkan inline: %s write failed (see prior line)", specs[i].sym);
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