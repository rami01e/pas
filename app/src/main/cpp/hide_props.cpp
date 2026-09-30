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

#include "pas.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <jni.h>

#include <string>

#include "bytehook.h"

namespace pas {

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
            case 37: rel = "17"; break;
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
        "ro.system.build.version.sdk",
        "ro.system.build.version.release",
        "ro.vendor.build.version.sdk",
        "ro.vendor.build.version.release",
        "ro.product.build.version.sdk",
        "ro.product.build.version.release",
    };
    static const char* const kAbi[] = {
        "ro.product.cpu.abi",           "ro.product.cpu.abi2",
        "ro.product.cpu.abilist",       "ro.product.cpu.abilist64",
        "ro.product.cpu.abilist32",     "ro.product.cpu.arch",
        "ro.product.system.cpu.abi",    "ro.product.vendor.cpu.abi",
        "ro.product.odm.cpu.abi",       "ro.product.system.cpu.abilist",
        "ro.product.system.cpu.abilist64", "ro.product.system.cpu.abilist32",
    };
    static const char* const kSoc[] = {
        "ro.soc.model",
        "ro.soc.manufacturer",
    };
    if (g_sdk_on && NameIn(name, kSdk, sizeof(kSdk) / sizeof(kSdk[0]))) return true;
    if (g_abi_on && NameIn(name, kAbi, sizeof(kAbi) / sizeof(kAbi[0]))) return true;
    if (CpuSpoofActive() && NameIn(name, kSoc, sizeof(kSoc) / sizeof(kSoc[0]))) return true;
    return false;
}

static bool SetStr(char* out, size_t cap, size_t* outLen, const char* v) {
    size_t n = strlen(v);
    if (n + 1 > cap) return false;
    memcpy(out, v, n + 1);
    *outLen = n;
    return true;
}

bool SpoofActive() {
    return g_sdk_on || g_abi_on || CpuSpoofActive();
}

// Recon value logging: while recon is on, record the RAW values (pre-spoof)
// of the device-identity properties a target app reads, so a capture shows
// exactly what the environment reports on every surface. Capped.
static volatile int g_prop_diag = 0;

static bool PropDiagName(const char* name) {
    if (!name) return false;
    static const char* const kDiag[] = {
        "hardware", "soc", "board", "platform", "egl", "gles", "vulkan", "nemu",
        "qemu", "goldfish", "ranchu", "emulator", "product.model", "product.device",
        "product.name", "product.brand", "product.manufacturer", "arch", "abi",
        "version.sdk", "build.fingerprint", "bootloader", "verifiedboot", "flash",
    };
    char low[160];
    size_t m = 0;
    for (; name[m] != '\0' && m < sizeof(low) - 1; m++) {
        char c = name[m];
        low[m] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    low[m] = '\0';
    for (size_t i = 0; i < sizeof(kDiag) / sizeof(kDiag[0]); i++) {
        if (strstr(low, kDiag[i]) != nullptr) return true;
    }
    return false;
}

// Recon noise control: MuMu/emulator infra properties ("nemud.*") carry no
// detection signal, and repeated reads of an unchanged value add nothing to
// a capture - the value line is emitted only when the value changes.
static bool ReconPropIgnored(const char* name) {
    return name != nullptr && strncmp(name, "nemud.", 6) == 0;
}

// Returns true when (name, value) was already logged before.
static bool ReconPropSeen(const char* name, const char* value) {
    static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
    struct Entry {
        char key[64];
        char val[96];
    };
    static Entry entries[48];
    static size_t count = 0;
    static size_t next = 0;
    if (name == nullptr || value == nullptr) return true;
    char k[64];
    char v[96];
    snprintf(k, sizeof(k), "%s", name);
    snprintf(v, sizeof(v), "%s", value);
    pthread_mutex_lock(&mtx);
    for (size_t i = 0; i < count; i++) {
        if (strcmp(entries[i].key, k) == 0) {
            bool same = strcmp(entries[i].val, v) == 0;
            if (!same) snprintf(entries[i].val, sizeof(entries[i].val), "%s", v);
            pthread_mutex_unlock(&mtx);
            return same;
        }
    }
    {
        // Evict the oldest entry once the table is full so the dedupe keeps
        // working for the whole session.
        size_t slot = (count < 48) ? count++ : next;
        snprintf(entries[slot].key, sizeof(entries[slot].key), "%s", k);
        snprintf(entries[slot].val, sizeof(entries[slot].val), "%s", v);
        next = (slot + 1) % 48;
    }
    pthread_mutex_unlock(&mtx);
    return false;
}

// Returns true when this (kind, key) pair was already reported once.
// First-touch dedupe for the "prop" / "prop-cb" op lines; value changes are
// still reported through ReconPropValue.
static bool ReconPropHitOnce(const char* kind, const char* name) {
    static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
    static char keys[64][80];
    static size_t count = 0;
    static size_t next = 0;
    if (name == nullptr) return true;
    char k[80];
    snprintf(k, sizeof(k), "%s:%s", kind, name);
    pthread_mutex_lock(&mtx);
    for (size_t i = 0; i < count; i++) {
        if (strcmp(keys[i], k) == 0) {
            pthread_mutex_unlock(&mtx);
            return true;
        }
    }
    {
        size_t slot = (count < 64) ? count++ : next;
        snprintf(keys[slot], sizeof(keys[slot]), "%s", k);
        next = (slot + 1) % 64;
    }
    pthread_mutex_unlock(&mtx);
    return false;
}

static void ReconPropValue(const char* name, const char* value) {
    if (!ReconEnabled() || name == nullptr || value == nullptr) return;
    if (ReconPropIgnored(name)) return;
    if (!PropDiagName(name)) return;
    if (ReconPropSeen(name, value)) return;
    if (g_prop_diag >= 400) return;
    g_prop_diag++;
    Log("native: recon: propv %s = %s", name, value);
}

static bool BuildSpoofValue(const char* name, const char* orig, char* out, size_t cap,
                            size_t* outLen);

// Rewrites one "key=value" property pair for build.prop-style files. Returns
// true with outVal filled when the key must present the spoofed value.
bool SpoofRewritePropsLine(const char* key, const char* origVal, char* outVal, size_t cap) {
    if (!key || !outVal || (!g_sdk_on && !g_abi_on && !CpuSpoofActive())) return false;
    size_t rl = 0;
    return BuildSpoofValue(key, origVal ? origVal : "", outVal, cap, &rl);
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
    if (CpuSpoofActive()) {
        if (strcmp(name, "ro.soc.model") == 0) {
            return SetStr(out, cap, outLen, CpuSpoofModel().c_str());
        }
        if (strcmp(name, "ro.soc.manufacturer") == 0) {
            return SetStr(out, cap, outLen, CpuSpoofManufacturer().c_str());
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// bionic property hooks
// ---------------------------------------------------------------------------

int HidePropGet(const char* name, char* value) {
    BYTEHOOK_STACK_SCOPE();
    if (ReconEnabled() && !ReconPropIgnored(name) && !ReconPropHitOnce("prop", name)) {
        ReconNote("prop", name, 0);
    }
    const bool active = g_sdk_on || g_abi_on || CpuSpoofActive();
    if (!name || !value || !active || !IsSpoofTarget(name)) {
        int r = BYTEHOOK_CALL_PREV(HidePropGet, name, value);
        if (value != nullptr && value[0] != '\0') ReconPropValue(name, value);
        return r;
    }
    char orig[PROP_VALUE_MAX];
    orig[0] = '\0';
    int n = BYTEHOOK_CALL_PREV(HidePropGet, name, orig);
    if (n < 0) n = 0;
    if (n > PROP_VALUE_MAX - 1) n = PROP_VALUE_MAX - 1;
    orig[n] = '\0';
    // Record the environment's raw (pre-spoof) value for the capture.
    ReconPropValue(name, orig);
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
    if (ReconEnabled() && !ReconPropIgnored(name) && !ReconPropHitOnce("prop-cb", name)) {
        ReconNote("prop-cb", name, 0);
    }
    ReconPropValue(name, value);
    auto* ctx = (ReadCbCtx*)cookie;
    if (name && ((g_sdk_on || g_abi_on || CpuSpoofActive()) && IsSpoofTarget(name))) {
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
    if (!cb || (!g_sdk_on && !g_abi_on && !CpuSpoofActive())) {
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
#define PAS_CPU_FAMILY_ARM64 4
#define PAS_CPU_FAMILY_X86_64 5

uint64_t HideCpuFamily() {
    BYTEHOOK_STACK_SCOPE();
    if (g_abi_on) {
        return g_abi_arm64 ? PAS_CPU_FAMILY_ARM64 : PAS_CPU_FAMILY_X86_64;
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

}  // namespace pas

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetConfig(JNIEnv* env, jobject thiz,
                                                            jboolean sdkOn, jint sdkVal,
                                                            jboolean abiOn, jboolean abiArm64,
                                                            jboolean compatMode,
                                                            jboolean nativeEnabled) {
    (void)env;
    (void)thiz;
    pas::SetSpoofConfig(sdkOn == JNI_TRUE, (int)sdkVal, abiOn == JNI_TRUE,
                        abiArm64 == JNI_TRUE, compatMode == JNI_TRUE,
                        nativeEnabled == JNI_TRUE);
}
