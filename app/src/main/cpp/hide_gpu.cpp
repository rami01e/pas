// CPU model / GPU (OpenGL) spoof for the scoped process.
//
// CPU: the model identity is delivered to hide_fs.cpp (/proc/cpuinfo rewrite)
// and hide_props.cpp (ro.soc.* properties); the Kotlin side patches the Java
// Build.SOC_* fields.
// GPU: glGetString(GL_VENDOR / GL_RENDERER) is replaced for native OpenGL
// readers through this hook; the Java GLES classes are covered from Kotlin.
// Only the two identity strings are touched - GL_EXTENSIONS / GL_VERSION keep
// their real values so feature detection still works.
//
// The GL hook is installed only when the GPU spoof is enabled at process
// start (configuration takes effect when a scoped app restarts).
//
// Config values are written once, early, from the module thread; the hot paths
// read plain flags/arrays (same style as hide_props.cpp).

#include "nvd.h"

#include <jni.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include "bytehook.h"

namespace nvd {

static volatile bool g_cpu_on = false;
static char g_cpu_display[192] = {0};
static char g_cpu_mfr[64] = {0};
static char g_cpu_model[64] = {0};
static volatile bool g_gpu_on = false;
static char g_gpu_vendor[128] = {0};
static char g_gpu_renderer[192] = {0};

void SetCpuGpuConfig(bool cpuOn, const char* cpuDisplay, const char* cpuMfr, const char* cpuModel,
                     bool gpuOn, const char* gpuVendor, const char* gpuRenderer) {
    g_cpu_on = false;
    g_gpu_on = false;
    snprintf(g_cpu_display, sizeof(g_cpu_display), "%s", cpuDisplay ? cpuDisplay : "");
    snprintf(g_cpu_mfr, sizeof(g_cpu_mfr), "%s", cpuMfr ? cpuMfr : "");
    snprintf(g_cpu_model, sizeof(g_cpu_model), "%s", cpuModel ? cpuModel : "");
    snprintf(g_gpu_vendor, sizeof(g_gpu_vendor), "%s", gpuVendor ? gpuVendor : "");
    snprintf(g_gpu_renderer, sizeof(g_gpu_renderer), "%s", gpuRenderer ? gpuRenderer : "");
    g_cpu_on = cpuOn && g_cpu_display[0] != '\0';
    g_gpu_on = gpuOn && g_gpu_renderer[0] != '\0';
    Log("native: cpu/gpu config cpuOn=%d cpu=%s gpuOn=%d renderer=%s", (int)g_cpu_on,
        g_cpu_display, (int)g_gpu_on, g_gpu_renderer);
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

bool GpuSpoofActive() {
    return g_gpu_on;
}

// ---------------------------------------------------------------------------
// OpenGL glGetString hook (native callers)
// ---------------------------------------------------------------------------

// GL_VENDOR = 0x1F00, GL_RENDERER = 0x1F01
static const unsigned char* MyGlGetString(unsigned int name) {
    BYTEHOOK_STACK_SCOPE();
    if (g_gpu_on) {
        if (name == 0x1F00) return (const unsigned char*)g_gpu_vendor;
        if (name == 0x1F01) return (const unsigned char*)g_gpu_renderer;
    }
    return BYTEHOOK_CALL_PREV(MyGlGetString, name);
}

static void OnGpuHooked(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                        const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub;
    (void)caller_path_name;
    (void)sym_name;
    (void)new_func;
    (void)prev_func;
    (void)arg;
    Log("native: gpu hook glGetString status=%d", status_code);
}

void InstallGpuHooks() {
    // Same caller filter as the rest of the module: never patch PLT/GOT of
    // ARM-translated application libraries.
    bytehook_stub_t stub = bytehook_hook_partial(CallerAllowHooks, nullptr, "libGLESv2.so",
                                                 "glGetString", (void*)MyGlGetString,
                                                 OnGpuHooked, nullptr);
    if (!stub) {
        Log("native: glGetString hook failed");
    } else {
        Log("native: glGetString hook installed");
    }
}

}  // namespace nvd

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_novpndetect_spoof_SpoofCore_nativeSetCpuGpu(JNIEnv* env, jobject thiz,
                                                            jboolean cpuOn, jstring cpuDisplay,
                                                            jstring cpuMfr, jstring cpuModel,
                                                            jboolean gpuOn, jstring gpuVendor,
                                                            jstring gpuRenderer) {
    (void)thiz;
    auto toStr = [env](jstring s) -> std::string {
        if (!s) return std::string();
        const char* c = env->GetStringUTFChars(s, nullptr);
        std::string out = c ? c : "";
        if (c) env->ReleaseStringUTFChars(s, c);
        return out;
    };
    std::string cpu = toStr(cpuDisplay);
    std::string mfr = toStr(cpuMfr);
    std::string model = toStr(cpuModel);
    std::string vendor = toStr(gpuVendor);
    std::string renderer = toStr(gpuRenderer);
    nvd::SetCpuGpuConfig(cpuOn == JNI_TRUE, cpu.c_str(), mfr.c_str(), model.c_str(),
                         gpuOn == JNI_TRUE, vendor.c_str(), renderer.c_str());
}
