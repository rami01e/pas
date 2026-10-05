// Native TLS verification bypass (SSL_set_verify / X509_verify_cert).
//
// Complements the Java-side unpinning (HookSslUnpin.kt) by neutralising
// certificate verification inside the process's *native* TLS stack
// (BoringSSL/OpenSSL). SDKs, Cronet, Chromium webviews and some game engines
// perform their chain checks in native code, where Java hooks cannot reach.
//
// v2.3.4: owner match expanded. The chromium/webview TLS stack is BoringSSL
// compiled into libwebviewchromium.so (or libmonochrome.so on newer builds)
// - neither name contains "ssl"/"crypto"/"boring", so v2.3.1..v2.3.3 never
// hooked it. Names added: webviewchromium, monochrome, chromium, mbedtls,
// gnutls. The five original owners are kept for the system libssl/libcrypto
// and game-bundled libraries.
//
// Installed only when the native addon is enabled, in scoped app processes.
//
// Hooks (bytehook, caller-filtered like every other group):
//   SSL_set_verify             -> forces SSL_VERIFY_NONE
//   SSL_CTX_set_verify         -> forces SSL_VERIFY_NONE
//   SSL_set_custom_verify      -> forces SSL_VERIFY_NONE (BoringSSL)
//   SSL_CTX_set_custom_verify  -> forces SSL_VERIFY_NONE (BoringSSL)
//   SSL_get_verify_result      -> returns X509_V_OK
//   X509_verify_cert           -> returns 1 (success)
//   X509_STORE_CTX_get_error   -> returns X509_V_OK
//   X509_STORE_CTX_set_error   -> forced to X509_V_OK
//
// Every intercepted verification call emits one "native: ssl-pin: ..." log
// line (capped at 200 per process), so a Diagnose capture of a stalling app
// shows whether a bundled native SSL stack is running its verify routine
// against the mitmproxy chain.
//
// Known limits:
//   * Only dynamically visible symbols are reachable. A library that
//     statically links BoringSSL with hidden visibility does not export
//     these names and cannot be hooked by name. The ARM64 ShadowHook path
//     (hook_ssl_arm64.cpp) is the second engine for those cases.
//   * Callers living in ARM-translated APK libraries are skipped by the
//     shared CallerAllow filter (patching translated code corrupts it), so
//     on an x86_64 emulator an arm64 game's own bundled SSL stack is out
//     of reach even when the symbols are exported. Native x86_64 libraries
//     in the same process (the webview's libwebviewchromium.so, system
//     libssl.so) are still covered.

#include "pas.h"

#include <dlfcn.h>
#include <jni.h>
#include <stdbool.h>
#include <stdint.h>

#include "bytehook.h"

namespace pas {

// ABI-stable constants, declared locally so the module needs no BoringSSL
// headers (it does not link against them).
static const int kSslVerifyNone = 0x00;  // SSL_VERIFY_NONE
static const int kX509Ok = 0;            // X509_V_OK

static volatile bool g_ssl_unpin = true;  // default ON (scoped apps only)

// Pinning-attempt logger. Every intercepted verification call emits one
// line, capped so a handshake storm cannot flood the log. Feeds Diagnose.
static volatile int g_ssl_log_count = 0;
static void SslPinLog(const char* op) {
    int n = __sync_fetch_and_add(&g_ssl_log_count, 1);
    if (n > 200) {
        if (n == 201) Log("native: ssl-pin: emission cap reached");
        return;
    }
    Log("native: ssl-pin: %s intercepted (verify=NONE)", op);
}

// ---------------------------------------------------------------------------
// proxies - every one forwards the original call and then overrides only the
// verdict, so nothing downstream sees a null where it expected a function.
// ---------------------------------------------------------------------------

static void MySslSetVerify(void* ssl, int mode, void* cb) {
    BYTEHOOK_STACK_SCOPE();
    SslPinLog("SSL_set_verify");
    (void)mode;
    BYTEHOOK_CALL_PREV(MySslSetVerify, ssl, kSslVerifyNone, cb);
}

static void MySslCtxSetVerify(void* ctx, int mode, void* cb) {
    BYTEHOOK_STACK_SCOPE();
    SslPinLog("SSL_CTX_set_verify");
    (void)mode;
    BYTEHOOK_CALL_PREV(MySslCtxSetVerify, ctx, kSslVerifyNone, cb);
}

static void MySslSetCustomVerify(void* ssl, int mode, void* cb) {
    BYTEHOOK_STACK_SCOPE();
    SslPinLog("SSL_set_custom_verify");
    (void)mode;
    BYTEHOOK_CALL_PREV(MySslSetCustomVerify, ssl, kSslVerifyNone, cb);
}

static void MySslCtxSetCustomVerify(void* ctx, int mode, void* cb) {
    BYTEHOOK_STACK_SCOPE();
    SslPinLog("SSL_CTX_set_custom_verify");
    (void)mode;
    BYTEHOOK_CALL_PREV(MySslCtxSetCustomVerify, ctx, kSslVerifyNone, cb);
}

static long MySslGetVerifyResult(const void* ssl) {
    BYTEHOOK_STACK_SCOPE();
    long r = BYTEHOOK_CALL_PREV(MySslGetVerifyResult, ssl);
    (void)r;
    return kX509Ok;
}

static int MyX509VerifyCert(void* ctx) {
    BYTEHOOK_STACK_SCOPE();
    SslPinLog("X509_verify_cert");
    int r = BYTEHOOK_CALL_PREV(MyX509VerifyCert, ctx);
    (void)r;
    return 1;
}

static int MyX509StoreCtxGetError(const void* ctx) {
    BYTEHOOK_STACK_SCOPE();
    int r = BYTEHOOK_CALL_PREV(MyX509StoreCtxGetError, ctx);
    (void)r;
    return kX509Ok;
}

static void MyX509StoreCtxSetError(void* ctx, int err) {
    BYTEHOOK_STACK_SCOPE();
    (void)err;
    BYTEHOOK_CALL_PREV(MyX509StoreCtxSetError, ctx, kX509Ok);
}

// ---------------------------------------------------------------------------
// installation
// ---------------------------------------------------------------------------

static void OnSslHooked(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                        const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub;
    (void)new_func;
    (void)prev_func;
    (void)arg;
    if (status_code == 0) return;
    Log("native: ssl hook %s <- %s status=%d", sym_name ? sym_name : "?",
        caller_path_name ? caller_path_name : "?", status_code);
}

static void HookSslSym(const char* sym, void* proxy) {
    // Owner match is deliberately broad: any library whose name contains
    // one of these substrings is a candidate. A miss in one owner is
    // harmless - bytehook simply does not find the symbol there. The list
    // covers system libssl/libcrypto, game-bundled BoringSSL/OpenSSL, and
    // the chromium/webview TLS stacks where BoringSSL is compiled in.
    static const char* const kOwners[] = {
        "ssl", "crypto", "boring",              // system + bundled OpenSSL/BoringSSL
        "webviewchromium", "monochrome",        // chromium webview TLS (v2.3.4)
        "chromium",                             // generic chromium libs
        "mbedtls", "gnutls",                    // alternate TLS stacks
    };
    for (size_t i = 0; i < sizeof(kOwners) / sizeof(kOwners[0]); i++) {
        bytehook_hook_partial(CallerAllowHooks, nullptr, kOwners[i], sym, proxy, OnSslHooked,
                              nullptr);
    }
}

// Diagnostic: query the process-global symbol table for the SSL/X509 verify
// entry points. If any of these return non-null, that symbol is exported by
// *some* loaded library and bytehook could in principle hook it (subject to
// translation-layer limits). If all return null, the app's SSL is either
// statically linked with hidden visibility or not present by that name -
// in which case no name-based approach will ever reach it.
static void ProbeSslSymbols() {
    static const char* const kProbe[] = {
        "SSL_set_verify", "SSL_CTX_set_verify", "SSL_set_custom_verify",
        "SSL_CTX_set_custom_verify", "SSL_get_verify_result",
        "X509_verify_cert", "X509_STORE_CTX_get_error", "X509_STORE_CTX_set_error",
    };
    for (const char* n : kProbe) {
        void* p = dlsym(RTLD_DEFAULT, n);
        Log("native: ssl probe %s = %p", n, p);
    }
}

void InstallSslHooks() {
    if (!g_ssl_unpin) return;
    ProbeSslSymbols();
    HookSslSym("SSL_set_verify", (void*)MySslSetVerify);
    HookSslSym("SSL_CTX_set_verify", (void*)MySslCtxSetVerify);
    HookSslSym("SSL_set_custom_verify", (void*)MySslSetCustomVerify);
    HookSslSym("SSL_CTX_set_custom_verify", (void*)MySslCtxSetCustomVerify);
    HookSslSym("SSL_get_verify_result", (void*)MySslGetVerifyResult);
    HookSslSym("X509_verify_cert", (void*)MyX509VerifyCert);
    HookSslSym("X509_STORE_CTX_get_error", (void*)MyX509StoreCtxGetError);
    HookSslSym("X509_STORE_CTX_set_error", (void*)MyX509StoreCtxSetError);
    Log("native: ssl unpin hooks installed (verify=NONE, owners=ssl/crypto/boring/webviewchromium/monochrome/chromium/mbedtls/gnutls)");
}

void SetSslUnpin(bool on) {
    g_ssl_unpin = on;
    Log("native: ssl unpin=%d", (int)on);
}

bool SslUnpinActive() {
    return g_ssl_unpin;
}

}  // namespace pas

extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetSslUnpin(JNIEnv* env, jobject thiz, jboolean on) {
    (void)env;
    (void)thiz;
    pas::SetSslUnpin(on == JNI_TRUE);
}

// >>> v2.4.0: flag for the ARM64 inline-hook path. Purely a gate; the actual
// installation is invoked from pas.cpp's InitWorker via InstallSslArm64Hooks.
extern "C" JNIEXPORT void JNICALL
Java_com_kimera_pas_spoof_SpoofCore_nativeSetSslArm64(JNIEnv* env, jobject thiz, jboolean on) {
    (void)env;
    (void)thiz;
    pas::SetSslArm64(on == JNI_TRUE);
}