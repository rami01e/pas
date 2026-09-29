// Per-app SDK / ABI spoofing.
//
// Presents a different Android version and CPU ABI to the scoped app process
// on every surface that native or Java code can read:
//   - __system_property_get / __system_property_read_callback
//       (ro.build.version.sdk, ro.build.version.release,
//        ro.product.cpu.abi*, ro.product.cpu.arch)
//   - uname() (machine: aarch64)
//   - android_getCpuFamily / android_getCpuFeatures
// The Java-side Build fields are additionally patched from Kotlin using
// sun.misc.Unsafe for the surfaces the properties do not cover.
//
// Disabled by default; configured from the module GUI through the Vector
// remote preferences and pushed in with SpoofCore.nativeSetConfig().

#include "nvd.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <jni.h>

#include "bytehook.h"

namespace nvd {

static volatile bool g_sdk_on = false;
static volatile int g_sdk_val = 0;
static char g_sdk_str[8] = {0};
static char g_sdk_release[8] = {0};
static volatile bool g_abi_on = false;
static volatile bool g_abi_arm64 = false;

void SetSpoofConfig(bool sdkOn, int sdkVal, bool abiOn, bool abiArm64, bool compatMode,
                    bool nativeEnabled) {
    if (sdkVal < 21 || sdkVal > 45) sdkOn = false;
    g_sdk_on = false;
    g_abi_on = false;
    if (sdkOn) {
        snprintf(g_sdk_str, sizeof(g_sdk_str), "%d", sdkVal);
        g_sdk_release[0] = '\0';
        const char* rel = nullptr;
        switch (sdkVal) {
            case 29: rel = "10"; break;
            case 30: rel = "11"; break;
            case 31: rel = "12"; break;
            case 32: rel = "12"; break;
            case 33: rel = "13"; break;
            case 34: rel = "14"; break;
            case 35: rel = "15"; break;
            case 36: rel = "16"; break;
            default: break;
        }
        if (rel) snprintf(g_sdk_release, sizeof(g_sdk_release), "%s", rel);
        g_sdk_val = sdkVal;
        g_sdk_on = true;
    }
    if (abiOn) {
        g_abi_arm64 = abiArm64;
        g_abi_on = true;
    }
    Log("native: spoof config sdk=%d(%d) abi=%d arm64=%d compat=%d native=%d", (int)g_sdk_on,
        g_sdk_val, (int)g_abi_on, (int)g_abi_arm64, (int)compatMode, (int)nativeEnabled);
    // Releases the hook-installation worker: with the native addon disabled it
    // installs nothing at all; compat mode skips only the extended groups.
    SignalSpoofConfigReady(compatMode, nativeEnabled);
}

static bool NameIn(const char* name, const char* const* list, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (strcmp(name, list[i]) == 0) return true;
    }
    return false;
}

static bool IsSpoofTarget(const char* name) {
    static const char* const kSdk[] = {
        "ro.build.version.sdk",
        "ro.build.version.release",
        "ro.build.version.release_or_codename",
    };
    static const char* const kAbi[] = {
        "ro.product.cpu.abi",      "ro.product.cpu.abi2", "ro.product.cpu.abilist",
        "ro.product.cpu.abilist64", "ro.product.cpu.abilist32", "ro.product.cpu.arch",
    };
    if (g_sdk_on && NameIn(name, kSdk, sizeof(kSdk) / sizeof(kSdk[0]))) return true;
    if (g_abi_on && NameIn(name, kAbi, sizeof(kAbi) / sizeof(kAbi[0]))) return true;
    return false;
}

static bool SetStr(char* out, size_t cap, size_t* outLen, const char* v) {
    size_t n = strlen(v);
    if (n + 1 > cap) return false;
    memcpy(out, v, n + 1);
    *outLen = n;
    return true;
}

// Returns true when the value was replaced (out/outLen filled).
static bool BuildSpoofValue(const char* name, const char* orig, char* out, size_t cap,
                            size_t* outLen) {
    if (g_sdk_on) {
        if (strcmp(name, "ro.build.version.sdk") == 0) {
            return SetStr(out, cap, outLen, g_sdk_str);
        }
        if ((strcmp(name, "ro.build.version.release") == 0 ||
             strcmp(name, "ro.build.version.release_or_codename") == 0) &&
            g_sdk_release[0]) {
            return SetStr(out, cap, outLen, g_sdk_release);
        }
    }
    if (g_abi_on) {
        const bool a = g_abi_arm64;
        if (strcmp(name, "ro.product.cpu.abi") == 0) {
            return SetStr(out, cap, outLen, a ? "arm64-v8a" : "x86_64");
        }
        if (strcmp(name, "ro.product.cpu.abi2") == 0) {
            // Only keep a value where the device already reports one.
            if (orig && orig[0]) return SetStr(out, cap, outLen, a ? "armeabi-v7a" : "x86");
            return false;
        }
        if (strcmp(name, "ro.product.cpu.abilist") == 0) {
            return SetStr(out, cap, outLen, a ? "arm64-v8a,armeabi-v7a,armeabi" : "x86_64,x86");
        }
        if (strcmp(name, "ro.product.cpu.abilist64") == 0) {
            return SetStr(out, cap, outLen, a ? "arm64-v8a" : "x86_64");
        }
        if (strcmp(name, "ro.product.cpu.abilist32") == 0) {
            return SetStr(out, cap, outLen, a ? "armeabi-v7a,armeabi" : "x86");
        }
        if (strcmp(name, "ro.product.cpu.arch") == 0) {
            return SetStr(out, cap, outLen, a ? "arm64" : "x86_64");
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// bionic property hooks
// ---------------------------------------------------------------------------

int HidePropGet(const char* name, char* value) {
    BYTEHOOK_STACK_SCOPE();
    if (!name || !value || (!g_sdk_on && !g_abi_on)) {
        return BYTEHOOK_CALL_PREV(HidePropGet, name, value);
    }
    if (!IsSpoofTarget(name)) {
        return BYTEHOOK_CALL_PREV(HidePropGet, name, value);
    }
    char orig[PROP_VALUE_MAX];
    orig[0] = '\0';
    int n = BYTEHOOK_CALL_PREV(HidePropGet, name, orig);
    if (n < 0) n = 0;
    if (n > PROP_VALUE_MAX - 1) n = PROP_VALUE_MAX - 1;
    orig[n] = '\0';
    char repl[PROP_VALUE_MAX];
    size_t rl = 0;
    if (BuildSpoofValue(name, orig, repl, sizeof(repl), &rl)) {
        memcpy(value, repl, rl + 1);
        return (int)rl;
    }
    memcpy(value, orig, (size_t)n + 1);
    return n;
}

typedef void (*PropReadCallback)(void* cookie, const char* name, const char* value,
                                 uint32_t serial);

struct ReadCbCtx {
    PropReadCallback orig;
    void* cookie;
};

static void SpoofReadCb(void* cookie, const char* name, const char* value, uint32_t serial) {
    auto* ctx = (ReadCbCtx*)cookie;
    if (name && (!g_sdk_on && !g_abi_on ? false : IsSpoofTarget(name))) {
        char repl[PROP_VALUE_MAX];
        size_t rl = 0;
        if (BuildSpoofValue(name, value ? value : "", repl, sizeof(repl), &rl)) {
            ctx->orig(ctx->cookie, name, repl, serial);
            return;
        }
    }
    ctx->orig(ctx->cookie, name, value, serial);
}

int HidePropReadCb(const prop_info* pi, PropReadCallback cb, void* cookie) {
    BYTEHOOK_STACK_SCOPE();
    if (!cb || (!g_sdk_on && !g_abi_on)) {
        // Spoofing disabled: pass the callback through untouched so the hook
        // is invisible even to aggressive native code.
        return BYTEHOOK_CALL_PREV(HidePropReadCb, pi, cb, cookie);
    }
    ReadCbCtx ctx{cb, cookie};
    return BYTEHOOK_CALL_PREV(HidePropReadCb, pi, SpoofReadCb, &ctx);
}

int HideUname(struct utsname* buf) {
    BYTEHOOK_STACK_SCOPE();
    int rc = BYTEHOOK_CALL_PREV(HideUname, buf);
    if (rc == 0 && buf != nullptr && g_abi_on) {
        const char* m = g_abi_arm64 ? "aarch64" : "x86_64";
        size_t n = strlen(m);
        if (n < sizeof(buf->machine)) {
            memcpy(buf->machine, m, n + 1);
        }
    }
    return rc;
}

// android_getCpuFamily values (cpu-features.h)
#define NVD_CPU_FAMILY_ARM64 4
#define NVD_CPU_FAMILY_X86_64 5

uint64_t HideCpuFamily() {
    BYTEHOOK_STACK_SCOPE();
    if (g_abi_on) {
        return g_abi_arm64 ? NVD_CPU_FAMILY_ARM64 : NVD_CPU_FAMILY_X86_64;
    }
    return BYTEHOOK_CALL_PREV(HideCpuFamily);
}

uint64_t HideCpuFeatures() {
    BYTEHOOK_STACK_SCOPE();
    if (g_abi_on && g_abi_arm64) {
        // Conservative AArch64 baseline: FP | ASIMD. Keep it minimal so code
        // that dispatches on optional features (AES, PMULL, ...) still takes
        // its portable path on the underlying x86 hardware.
        return (1ULL << 0) | (1ULL << 1);
    }
    return BYTEHOOK_CALL_PREV(HideCpuFeatures);
}

void InstallPropSpoofHooks() {
    HookLibcSym("__system_property_get", (void*)HidePropGet);
    HookLibcSym("__system_property_read_callback", (void*)HidePropReadCb);
    HookLibcSym("uname", (void*)HideUname);
    HookLibcSym("android_getCpuFamily", (void*)HideCpuFamily);
    HookLibcSym("android_getCpuFeatures", (void*)HideCpuFeatures);
}

}  // namespace nvd

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_novpndetect_spoof_SpoofCore_nativeSetConfig(JNIEnv* env, jobject thiz,
                                                            jboolean sdkOn, jint sdkVal,
                                                            jboolean abiOn, jboolean abiArm64,
                                                            jboolean compatMode,
                                                            jboolean nativeEnabled) {
    (void)env;
    (void)thiz;
    nvd::SetSpoofConfig(sdkOn == JNI_TRUE, (int)sdkVal, abiOn == JNI_TRUE,
                        abiArm64 == JNI_TRUE, compatMode == JNI_TRUE,
                        nativeEnabled == JNI_TRUE);
}
