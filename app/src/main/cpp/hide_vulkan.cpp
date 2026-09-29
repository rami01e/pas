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

#include "nvd.h"

#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#define VK_NO_PROTOTYPES 1
#include <vulkan/vulkan.h>

#include "bytehook.h"

namespace nvd {

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

static void PatchProps2(VkPhysicalDeviceProperties2* out) {
    if (!out || !GpuSpoofActive()) return;
    PatchCoreProps(&out->properties);
#ifdef VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES
    int guard = 0;
    for (VkBaseOutStructure* s = (VkBaseOutStructure*)out->pNext; s != nullptr && guard < 32;
         s = s->pNext, guard++) {
        if (s->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES) {
            auto* d = (VkPhysicalDeviceDriverProperties*)s;
            snprintf(d->driverName, sizeof(d->driverName), "%s", GpuSpoofDriverName().c_str());
            snprintf(d->driverInfo, sizeof(d->driverInfo), "%s", GpuSpoofDriverInfo().c_str());
            d->conformanceVersion.major = 1;
            d->conformanceVersion.minor = 3;
            d->conformanceVersion.subminor = 1;
            d->conformanceVersion.patch = 0;
        }
    }
#endif
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
#ifdef VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES
        if (s->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES) {
            ((VkPhysicalDeviceVulkan12Features*)s)->descriptorIndexing = VK_FALSE;
        }
#endif
#ifdef VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES
        if (s->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES) {
            auto* f13 = (VkPhysicalDeviceVulkan13Features*)s;
            f13->dynamicRendering = VK_TRUE;
            f13->synchronization2 = VK_TRUE;
        }
#endif
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
// install
// ---------------------------------------------------------------------------

static void OnVkHooked(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                       const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub;
    (void)caller_path_name;
    (void)new_func;
    (void)prev_func;
    (void)arg;
    Log("native: vulkan hook %s status=%d", sym_name ? sym_name : "?", status_code);
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
    };
    int ok = 0;
    for (const HookSpec& s : kSpecs) {
        bytehook_stub_t stub = bytehook_hook_partial(CallerAllowHooks, nullptr, "libvulkan.so",
                                                     s.sym, s.fn, OnVkHooked, nullptr);
        if (stub) ok++;
    }
    Log("native: vulkan hooks installed %d/%d", ok, (int)(sizeof(kSpecs) / sizeof(kSpecs[0])));
}

}  // namespace nvd
