// CPU model / GPU (OpenGL) spoof for the scoped process.
//
// CPU: the model identity is delivered to hide_fs.cpp (/proc/cpuinfo view,
// cpufreq min/max mirrors, subprocess exec redirect) and hide_props.cpp
// (ro.soc.* properties); the Kotlin side patches the Java Build.SOC_* /
// HARDWARE / BOARD fields.
// GPU: glGetString(GL_VENDOR / GL_RENDERER / GL_VERSION) is replaced for
// native OpenGL readers through this hook; the Java GLES classes are covered
// from Kotlin, and hide_vulkan.cpp covers the Vulkan identity. GL_EXTENSIONS
// keeps its real value so feature detection still works.
//
// The GL / Vulkan hooks are installed only when the GPU spoof is enabled at
// process start (configuration takes effect when a scoped app restarts).
//
// Config values are written once, early, from the module thread; the hot paths
// read plain flags/arrays (same style as hide_props.cpp).

#include "pas.h"

#include <jni.h>
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
static char g_cpu_info_model[96] = {0};
static char g_cpu_features[256] = {0};
static char g_cpu_hwline[256] = {0};
static volatile int g_cpu_min_khz = 0;
static volatile int g_cpu_max_khz = 0;

static volatile bool g_gpu_on = false;
static char g_gpu_vendor[64] = {0};
static char g_gpu_renderer[192] = {0};
static char g_gpu_gl_version[192] = {0};
static volatile unsigned long long g_gpu_vendor_id = 0;
static volatile unsigned long long g_gpu_device_id = 0;
static volatile unsigned long long g_gpu_driver_version = 0;
static volatile unsigned long long g_gpu_api_version = 0;
static char g_gpu_driver_name[192] = {0};
static char g_gpu_driver_info[256] = {0};

static void CopyStr(char* dst, size_t cap, const char* src) {
    snprintf(dst, cap, "%s", src ? src : "");
}

void SetCpuConfig(bool cpuOn, const char* display, const char* mfr, const char* model,
                  const char* part, const char* cpuInfoModel, const char* features, int minKHz,
                  int maxKHz, const char* hwLine) {
    g_cpu_on = false;
    CopyStr(g_cpu_display, sizeof(g_cpu_display), display);
    CopyStr(g_cpu_mfr, sizeof(g_cpu_mfr), mfr);
    CopyStr(g_cpu_model, sizeof(g_cpu_model), model);
    CopyStr(g_cpu_part, sizeof(g_cpu_part), part);
    CopyStr(g_cpu_info_model, sizeof(g_cpu_info_model), cpuInfoModel);
    CopyStr(g_cpu_features, sizeof(g_cpu_features), features);
    CopyStr(g_cpu_hwline, sizeof(g_cpu_hwline), hwLine);
    g_cpu_min_khz = minKHz;
    g_cpu_max_khz = maxKHz;
    g_cpu_on = cpuOn && g_cpu_display[0] != '\0';
    Log("native: cpu config on=%d display=%s part=%s khz=%d-%d", (int)g_cpu_on, g_cpu_display,
        g_cpu_part, (int)g_cpu_min_khz, (int)g_cpu_max_khz);
}

void SetGpuConfig(bool gpuOn, const char* vendor, const char* renderer, const char* glVersion,
                  unsigned long long vendorId, unsigned long long deviceId,
                  unsigned long long driverVersion, unsigned long long apiVersion,
                  const char* driverName, const char* driverInfo) {
    g_gpu_on = false;
    CopyStr(g_gpu_vendor, sizeof(g_gpu_vendor), vendor);
    CopyStr(g_gpu_renderer, sizeof(g_gpu_renderer), renderer);
    CopyStr(g_gpu_gl_version, sizeof(g_gpu_gl_version), glVersion);
    CopyStr(g_gpu_driver_name, sizeof(g_gpu_driver_name), driverName);
    CopyStr(g_gpu_driver_info, sizeof(g_gpu_driver_info), driverInfo);
    g_gpu_vendor_id = vendorId;
    g_gpu_device_id = deviceId;
    g_gpu_driver_version = driverVersion;
    g_gpu_api_version = apiVersion;
    g_gpu_on = gpuOn && g_gpu_renderer[0] != '\0';
    Log("native: gpu config on=%d renderer=%s vendorId=0x%llx deviceId=0x%llx", (int)g_gpu_on,
        g_gpu_renderer, g_gpu_vendor_id, g_gpu_device_id);
}

bool CpuSpoofActive() {
    return g_cpu_on;
}

std::string CpuSpoofDisplay() {
    return std::string(g_cpu_display);
}

std::string CpuSpoofManufacturer() {
    return std::string(g_cpu_mfr);
}

std::string CpuSpoofModel() {
    return std::string(g_cpu_model);
}

std::string CpuSpoofPart() {
    return std::string(g_cpu_part);
}

std::string CpuSpoofCpuinfoModel() {
    return std::string(g_cpu_info_model);
}

std::string CpuSpoofFeatures() {
    return std::string(g_cpu_features);
}

std::string CpuSpoofHwLine() {
    return std::string(g_cpu_hwline);
}

int CpuSpoofMinKHz() {
    return g_cpu_min_khz;
}

int CpuSpoofMaxKHz() {
    return g_cpu_max_khz;
}

bool GpuSpoofActive() {
    return g_gpu_on;
}

std::string GpuSpoofVendor() {
    return std::string(g_gpu_vendor);
}

std::string GpuSpoofRenderer() {
    return std::string(g_gpu_renderer);
}

std::string GpuSpoofGlVersion() {
    return std::string(g_gpu_gl_version);
}

unsigned long long GpuSpoofVendorId() {
    return g_gpu_vendor_id;
}

unsigned long long GpuSpoofDeviceId() {
    return g_gpu_device_id;
}

unsigned long long GpuSpoofDriverVersion() {
    return g_gpu_driver_version;
}

unsigned long long GpuSpoofApiVersion() {
    return g_gpu_api_version;
}

std::string GpuSpoofDriverName() {
    return std::string(g_gpu_driver_name);
}

std::string GpuSpoofDriverInfo() {
    return std::string(g_gpu_driver_info);
}

// ---------------------------------------------------------------------------
// OpenGL glGetString hook (native callers)
// ---------------------------------------------------------------------------

// GL_VENDOR = 0x1F00, GL_RENDERER = 0x1F01, GL_VERSION = 0x1F02
// GL identity entry points are covered on every path ANGLE-style consumers
// use: direct PLT calls (bytehook), eglGetProcAddress resolution and dlsym
// resolution. Resolver results are bytehook-free representatives because
// those pointers are called directly (outside bytehook frames).

typedef void* (*PasEglGpaFn)(const char*);
typedef const unsigned char* (*PasGlGetStringFn)(unsigned int);
typedef const unsigned char* (*PasGlGetStringiFn)(unsigned int, unsigned int);

static void* volatile g_real_gl_get_string = nullptr;
static void* volatile g_real_gl_get_stringi = nullptr;
static void* volatile g_real_egl_gpa = nullptr;
static volatile unsigned g_gl_chain_logged = 0;
static volatile int g_gl_diag = 0;

// Recon-gated GL diagnosis: records which GL/EGL entry points actually flow
// through the module inside this process (capped; driven by the GUI "Recon
// logging" toggle). This is how we see what Chrome's ANGLE really calls.
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

// Maps the identity names to the spoofed strings; false => not handled here.
static bool SpoofGlName(unsigned name, const unsigned char** out) {
    if (!g_gpu_on) return false;
    if (name == 0x1F00) {
        *out = (const unsigned char*)g_gpu_vendor;
        return true;
    }
    if (name == 0x1F01) {
        *out = (const unsigned char*)g_gpu_renderer;
        return true;
    }
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

static const unsigned char* RepGlGetString(unsigned int name) {
    const unsigned char* spoofed = nullptr;
    bool spoof = SpoofGlName(name, &spoofed);
    DiagGlStr("glgs", name, spoof ? 1 : 0);
    if (spoof) return spoofed;
    auto real = (PasGlGetStringFn)g_real_gl_get_string;
    return real ? real(name) : nullptr;
}

static const unsigned char* RepGlGetStringi(unsigned int name, unsigned int index) {
    const unsigned char* spoofed = nullptr;
    bool spoof = index == 0 && SpoofGlName(name, &spoofed);
    DiagGlStr("glgsi", name, spoof ? 1 : 0);
    if (spoof) return spoofed;
    auto real = (PasGlGetStringiFn)g_real_gl_get_stringi;
    return real ? real(name, index) : nullptr;
}

static void* RepEglGetProcAddress(const char* name);

void* GpuChainResolveDlsym(const char* symbol, void* real) {
    if (symbol == nullptr) return nullptr;
    if (strcmp(symbol, "glGetString") == 0 || strcmp(symbol, "glGetStringi") == 0 ||
        strcmp(symbol, "eglGetProcAddress") == 0) {
        GpuDiag("dlsym", symbol);
    }
    if (!g_gpu_on || real == nullptr) return nullptr;
    if (strcmp(symbol, "glGetString") == 0) {
        g_real_gl_get_string = real;
        GlChainLog("glGetString", "dlsym");
        return (void*)RepGlGetString;
    }
    if (strcmp(symbol, "glGetStringi") == 0) {
        g_real_gl_get_stringi = real;
        GlChainLog("glGetStringi", "dlsym");
        return (void*)RepGlGetStringi;
    }
    if (strcmp(symbol, "eglGetProcAddress") == 0) {
        g_real_egl_gpa = real;
        return (void*)RepEglGetProcAddress;
    }
    return nullptr;
}

static void* RepEglGetProcAddress(const char* name) {
    if (name != nullptr) GpuDiag("eglgpa", name);
    if (g_gpu_on && name != nullptr) {
        if (strcmp(name, "glGetString") == 0) {
            auto real = (PasEglGpaFn)g_real_egl_gpa;
            void* r = real ? real(name) : nullptr;
            if (r != nullptr) g_real_gl_get_string = r;
            GlChainLog("glGetString", "eglGetProcAddress");
            return (void*)RepGlGetString;
        }
        if (strcmp(name, "glGetStringi") == 0) {
            auto real = (PasEglGpaFn)g_real_egl_gpa;
            void* r = real ? real(name) : nullptr;
            if (r != nullptr) g_real_gl_get_stringi = r;
            GlChainLog("glGetStringi", "eglGetProcAddress");
            return (void*)RepGlGetStringi;
        }
        if (strcmp(name, "eglGetProcAddress") == 0) {
            return (void*)RepEglGetProcAddress;
        }
    }
    auto real = (PasEglGpaFn)g_real_egl_gpa;
    return real ? real(name) : nullptr;
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
    if (!g_gpu_on || name == nullptr) return real;
    if (strcmp(name, "glGetString") == 0) {
        if (real != nullptr) g_real_gl_get_string = real;
        GlChainLog("glGetString", "eglGetProcAddress");
        return (void*)RepGlGetString;
    }
    if (strcmp(name, "glGetStringi") == 0) {
        if (real != nullptr) g_real_gl_get_stringi = real;
        GlChainLog("glGetStringi", "eglGetProcAddress");
        return (void*)RepGlGetStringi;
    }
    if (strcmp(name, "eglGetProcAddress") == 0) {
        if (real != nullptr) g_real_egl_gpa = real;
        return (void*)RepEglGetProcAddress;
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
    (void)stub;
    (void)sym_name;
    (void)new_func;
    (void)prev_func;
    (void)arg;
    LogGpuHookActivation("glGetString", status_code, caller_path_name);
}

static void OnGpuHookedGsi(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                           const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub;
    (void)sym_name;
    (void)new_func;
    (void)prev_func;
    (void)arg;
    LogGpuHookActivation("glGetStringi", status_code, caller_path_name);
}

static void OnGpuHookedEgl(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                           const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub;
    (void)sym_name;
    (void)new_func;
    (void)prev_func;
    (void)arg;
    LogGpuHookActivation("eglGetProcAddress", status_code, caller_path_name);
}

void InstallGpuHooks() {
    // Same caller filter as the rest of the module: never patch PLT/GOT of
    // ARM-translated application libraries. The owner regexes stay broad so
    // the emulator's driver naming variants (libGLESv2_*.so, libEGL_*.so)
    // match as well.
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
                                                         jint maxKhz, jstring cpuHwLine) {
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
    pas::SetCpuConfig(cpuOn == JNI_TRUE, display.c_str(), mfr.c_str(), model.c_str(), part.c_str(),
                      infoModel.c_str(), features.c_str(), (int)minKhz, (int)maxKhz,
                      hwLine.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetGpu(JNIEnv* env, jobject thiz,
                                                         jboolean gpuOn, jstring gpuVendor,
                                                         jstring gpuRenderer, jstring gpuGlVersion,
                                                         jlong vendorId, jlong deviceId,
                                                         jlong driverVersion, jlong apiVersion,
                                                         jstring driverName, jstring driverInfo) {
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
    pas::SetGpuConfig(gpuOn == JNI_TRUE, vendor.c_str(), renderer.c_str(), glVersion.c_str(),
                      (unsigned long long)vendorId, (unsigned long long)deviceId,
                      (unsigned long long)driverVersion, (unsigned long long)apiVersion,
                      dName.c_str(), dInfo.c_str());
}
