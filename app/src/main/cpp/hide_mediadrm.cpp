// hide_mediadrm.cpp - WIDEVINE NDK-parity layer (v3.0.0, new file).
//
// P2 fix, option (B): the module's Widevine story is "report L1, never L3".
// The Java surface (hookmediadrm.kt) already answers
//   MediaDrm.getPropertyString("securityLevel") -> "L1"
//   MediaDrm.getPropertyString("maxHdcpLevel")  -> "HDCP-2.2"
//   MediaDrm.getPropertyByteArray("deviceUniqueId") -> spoofed id
// but the NDK surface answered with the real HAL: any native consumer
// calling AMediaDrm_getPropertyString(drm, "securityLevel") on MuMu got "L3".
// Duck Detector reads BOTH surfaces and flags the mismatch
// ("securityLevel(Java=L1, NDK=L3)") - and the L1 claim makes it open an L1
// session the HAL cannot honor, which is accepted collateral of the L1 story
// ("credential session inconclusive" instead of a parity flag).
//
// This layer gives the NDK surface the same story: ByteHook patches the two
// AMediaDrm property getters in libmediandk.so for every allowed caller.
// Duck's widevine probe links libmediandk.so directly, so its calls go
// through the PLT and are intercepted like any other libc-family symbol.
//
// Armed from Kotlin with the SAME toggle and id the Java hooks use:
//   SpoofCore.apply() -> nativeSetWidevineNdk(SpoofState.widevineOn,
//                                             SpoofState.widevineId)
// With the widevine toggle off this layer is fully inert (every handler
// falls through to the real function).
//
// libmediandk.so may not be mapped yet at arm time (it loads with the first
// DRM consumer), so a failed install retries in the background for a few
// seconds. ByteHook's AUTOMATIC mode then also patches every caller that
// loads afterwards.

#include "pas.h"

#include <errno.h>
#include <jni.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include <media/NdkMediaDrm.h>

#include "bytehook.h"

namespace pas {

static volatile bool g_wv_ndk_on = false;

// deviceUniqueId spoof buffer: hex string + decoded bytes. The decoded bytes
// are what AMediaDrm_getPropertyByteArray hands out; the pointer must stay
// valid for the lifetime of the process (readers may keep it).
static char g_wv_id_hex[128] = {0};
static unsigned char g_wv_id_bin[64] = {0};
static size_t g_wv_id_bin_len = 0;

// Stable storage for the property strings we return (the NDK contract hands
// the caller a pointer owned by the CDM, so our replacement needs one too).
static char g_wv_security_level[] = "L1";
static char g_wv_max_hdcp[] = "HDCP-2.2";

static bool HexNibble(char c, unsigned char* out) {
    if (c >= '0' && c <= '9') { *out = (unsigned char)(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { *out = (unsigned char)(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { *out = (unsigned char)(c - 'A' + 10); return true; }
    return false;
}

static void StoreWidevineId(const char* idHex) {
    g_wv_id_hex[0] = '\0';
    g_wv_id_bin_len = 0;
    if (idHex == nullptr) return;
    size_t n = strlen(idHex);
    if (n == 0 || (n % 2) != 0 || n > 128) return;  // mirror isSpoofableHex
    for (size_t i = 0; i < n; i++) {
        unsigned char hi, lo;
        if (!HexNibble(idHex[i], &hi) || !HexNibble(idHex[i + 1], &lo)) return;
        if (g_wv_id_bin_len < sizeof(g_wv_id_bin)) {
            g_wv_id_bin[g_wv_id_bin_len++] = (unsigned char)((hi << 4) | lo);
        }
    }
    memcpy(g_wv_id_hex, idHex, n + 1);
}

// ---------------------------------------------------------------------------
// hooks
// ---------------------------------------------------------------------------

static media_status_t MyMediaDrmGetPropertyString(AMediaDrm* drm, const char* propertyName,
                                                  const char** propertyValue) {
    BYTEHOOK_STACK_SCOPE();
    media_status_t st = BYTEHOOK_CALL_PREV(MyMediaDrmGetPropertyString, drm, propertyName,
                                           propertyValue);
    if (g_wv_ndk_on && propertyName != nullptr && propertyValue != nullptr) {
        if (strcmp(propertyName, "securityLevel") == 0) {
            *propertyValue = g_wv_security_level;
            return AMEDIA_OK;
        }
        if (strcmp(propertyName, "maxHdcpLevel") == 0) {
            *propertyValue = g_wv_max_hdcp;
            return AMEDIA_OK;
        }
        // "systemId" and every other string property stay raw: the Java side
        // does not spoof them either, so both surfaces keep agreeing.
    }
    return st;
}

static media_status_t MyMediaDrmGetPropertyByteArray(AMediaDrm* drm, const char* propertyName,
                                                     AMediaDrmByteArray* propertyValue) {
    BYTEHOOK_STACK_SCOPE();
    media_status_t st = BYTEHOOK_CALL_PREV(MyMediaDrmGetPropertyByteArray, drm, propertyName,
                                           propertyValue);
    if (g_wv_ndk_on && propertyName != nullptr && propertyValue != nullptr &&
        strcmp(propertyName, "deviceUniqueId") == 0 && g_wv_id_bin_len > 0) {
        propertyValue->ptr = g_wv_id_bin;
        propertyValue->length = g_wv_id_bin_len;
        return AMEDIA_OK;
    }
    return st;
}

// ---------------------------------------------------------------------------
// installation (libmediandk.so may load late - retry in the background)
// ---------------------------------------------------------------------------

static pthread_mutex_t g_wv_install_mtx = PTHREAD_MUTEX_INITIALIZER;
static bool g_wv_hooks_ok = false;
static bool g_wv_retry_started = false;

static bool TryInstallWidevineHooks() {
    bool ok1 = bytehook_hook_partial(CallerAllowHooks, nullptr, "libmediandk.so",
                                     "AMediaDrm_getPropertyString",
                                     (void*)MyMediaDrmGetPropertyString, nullptr,
                                     nullptr) != nullptr;
    bool ok2 = bytehook_hook_partial(CallerAllowHooks, nullptr, "libmediandk.so",
                                     "AMediaDrm_getPropertyByteArray",
                                     (void*)MyMediaDrmGetPropertyByteArray, nullptr,
                                     nullptr) != nullptr;
    return ok1 && ok2;
}

static void* WidevineRetryWorker(void*) {
    for (int i = 0; i < 25; i++) {
        usleep(200 * 1000);  // 200 ms
        if (g_wv_hooks_ok) return nullptr;
        pthread_mutex_lock(&g_wv_install_mtx);
        bool done = false;
        if (!g_wv_hooks_ok && TryInstallWidevineHooks()) {
            g_wv_hooks_ok = true;
            done = true;
        }
        pthread_mutex_unlock(&g_wv_install_mtx);
        if (done) {
            Log("native: widevine ndk parity hooks installed (retry %d)", i + 1);
            return nullptr;
        }
    }
    Log("native: widevine ndk parity hooks NOT installed (libmediandk.so never mapped)");
    return nullptr;
}

static void EnsureWidevineHooksInstalled() {
    pthread_mutex_lock(&g_wv_install_mtx);
    if (g_wv_hooks_ok) {
        pthread_mutex_unlock(&g_wv_install_mtx);
        return;
    }
    if (TryInstallWidevineHooks()) {
        g_wv_hooks_ok = true;
        pthread_mutex_unlock(&g_wv_install_mtx);
        Log("native: widevine ndk parity hooks installed");
        return;
    }
    if (!g_wv_retry_started) {
        g_wv_retry_started = true;
        pthread_t t;
        if (pthread_create(&t, nullptr, WidevineRetryWorker, nullptr) == 0) {
            pthread_detach(t);
        } else {
            Log("native: widevine ndk retry thread create failed");
        }
    }
    pthread_mutex_unlock(&g_wv_install_mtx);
}

void SetWidevineNdkSpoof(bool on, const char* idHex) {
    if (on && idHex != nullptr) {
        StoreWidevineId(idHex);
    }
    g_wv_ndk_on = on;
    if (on) {
        EnsureWidevineHooksInstalled();
    }
    Log("native: widevine ndk parity %s (id %s)", on ? "on" : "off",
        g_wv_id_bin_len > 0 ? "spoofed" : "passthrough");
}

}  // namespace pas

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetWidevineNdk(JNIEnv* env, jobject thiz, jboolean on,
                                                         jstring idHex) {
    (void)thiz;
    const char* id = nullptr;
    if (idHex != nullptr) id = env->GetStringUTFChars(idHex, nullptr);
    pas::SetWidevineNdkSpoof(on == JNI_TRUE, id);
    if (id != nullptr) env->ReleaseStringUTFChars(idHex, id);
}
