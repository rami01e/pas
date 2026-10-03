// Native TLS verification bypass (SSL_set_verify / X509_verify_cert).
//
// Complements the Java-side unpinning (HookSslUnpin.kt / OkHttp
// CertificatePinner) by neutralising certificate verification inside the
// process's *native* TLS stack (BoringSSL/OpenSSL). SDKs, Cronet and some
// game engines perform their chain / pinning checks in native code, where
// Java hooks cannot reach.
//
// Scope: installed only in scoped app processes, and only while the native
// addon is enabled. The module never runs anywhere else.
//
// Hooks (bytehook, caller-filtered like every other group):
//   SSL_set_verify             -> forces SSL_VERIFY_NONE
//   SSL_CTX_set_verify         -> forces SSL_VERIFY_NONE
//   SSL_set_custom_verify      -> forces SSL_VERIFY_NONE (BoringSSL)
//   SSL_CTX_set_custom_verify  -> forces SSL_VERIFY_NONE (BoringSSL)
//   SSL_get_verify_result      -> returns X509_V_OK
//   X509_verify_cert           -> returns 1 (success)
//   X509_STORE_CTX_get_error   -> returns X509_V_OK
//
// Known limits (read before expecting miracles):
//   * Only dynamically visible symbols are reachable. A library that
//     statically links BoringSSL with hidden visibility (Chrome's
//     libmonochrome.so, Unity's bundled curl/OpenSSL, Flutter) does not
//     export these names and cannot be hooked by name.
//   * Callers living in ARM-translated APK libraries are skipped by the
//     shared CallerAllow filter (patching translated code corrupts it), so
//     on an x86_64 emulator an arm64 game's own bundled SSL stack is out of
//     reach. The Java-layer unpinning still covers those apps' Java TLS.
//   * Verification is bypassed for every TLS connection in the scoped
//     process, not only a pinned host. That is inherent to unpinning.

#include "pas.h"

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

// ---------------------------------------------------------------------------
// proxies - every one keeps the original callback, only the mode / verdict is
// overridden, so nothing downstream sees a null where it expected a function.
// ---------------------------------------------------------------------------

static void MySslSetVerify(void* ssl, int mode, void* cb) {
    BYTEHOOK_STACK_SCOPE();
    (void)mode;
    BYTEHOOK_CALL_PREV(MySslSetVerify, ssl, kSslVerifyNone, cb);
}

static void MySslCtxSetVerify(void* ctx, int mode, void* cb) {
    BYTEHOOK_STACK_SCOPE();
    (void)mode;
    BYTEHOOK_CALL_PREV(MySslCtxSetVerify, ctx, kSslVerifyNone, cb);
}

static void MySslSetCustomVerify(void* ssl, int mode, void* cb) {
    BYTEHOOK_STACK_SCOPE();
    (void)mode;
    BYTEHOOK_CALL_PREV(MySslSetCustomVerify, ssl, kSslVerifyNone, cb);
}

static void MySslCtxSetCustomVerify(void* ctx, int mode, void* cb) {
    BYTEHOOK_STACK_SCOPE();
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
    // Run the real verification first so the store context is fully
    // populated, then override the verdict. Callers that read the error
    // afterwards get X509_V_OK from MyX509StoreCtxGetError, so the two
    // answers agree.
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

// ---------------------------------------------------------------------------
// installation
// ---------------------------------------------------------------------------

static void OnSslHooked(bytehook_stub_t stub, int status_code, const char* caller_path_name,
                        const char* sym_name, void* new_func, void* prev_func, void* arg) {
    (void)stub;
    (void)new_func;
    (void)prev_func;
    (void)arg;
    // A successful chain is routine (and very chatty); only failures carry
    // signal here.
    if (status_code == 0) return;
    Log("native: ssl hook %s <- %s status=%d", sym_name ? sym_name : "?",
        caller_path_name ? caller_path_name : "?", status_code);
}

static void HookSslSym(const char* sym, void* proxy) {
    // The symbols live in libssl (SSL_*) and libcrypto (X509_*); hooking both
    // owners covers a caller that links either one, and a miss in the other
    // owner simply reports a failure and is ignored.
    static const char* const kOwners[] = {"libssl", "libcrypto"};
    for (size_t i = 0; i < sizeof(kOwners) / sizeof(kOwners[0]); i++) {
        bytehook_hook_partial(CallerAllowHooks, nullptr, kOwners[i], sym, proxy, OnSslHooked,
                              nullptr);
    }
}

void InstallSslHooks() {
    if (!g_ssl_unpin) return;
    HookSslSym("SSL_set_verify", (void*)MySslSetVerify);
    HookSslSym("SSL_CTX_set_verify", (void*)MySslCtxSetVerify);
    HookSslSym("SSL_set_custom_verify", (void*)MySslSetCustomVerify);
    HookSslSym("SSL_CTX_set_custom_verify", (void*)MySslCtxSetCustomVerify);
    HookSslSym("SSL_get_verify_result", (void*)MySslGetVerifyResult);
    HookSslSym("X509_verify_cert", (void*)MyX509VerifyCert);
    HookSslSym("X509_STORE_CTX_get_error", (void*)MyX509StoreCtxGetError);
    Log("native: ssl unpin hooks installed (verify=NONE)");
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