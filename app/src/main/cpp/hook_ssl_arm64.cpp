// hook_ssl_arm64.cpp — ARM64 inline-hook SSL unpinning for Houdini/translation
// environments, built on ShadowHook 1.0.10 (the last version confirmed to work
// on x86 emulators).
//
// Only compiled with the real body on arm64-v8a. ShadowHook ships no x86 or
// x86_64 native library, so on those ABIs the file is a no-op and the three
// entry points below are stubs. The CMake guard (PAS_HAVE_SHADOWHOOK) decides
// which of the two bodies compiles.
//
// On arm64-v8a the file does two things:
//
//   1. Name-based hook via shadowhook_hook_sym_name(). Fast and precise.
//      Works only when the target library exports the SSL symbol (system
//      libssl, some bundled OpenSSL builds).
//
//   2. Pattern-based hook via shadowhook_hook_sym_addr(). Scans the target
//      library's ARM64 code for a function-prologue byte signature, then
//      hooks the discovered address. This is the path that reaches Unity
//      il2cpp games where BoringSSL is statically linked with hidden
//      visibility — the exact case our earlier probes uncovered (all eight
//      SSL symbols resolved to 0x0).
//
// Scope: installed only in scoped app processes, only when the native addon
// and SSL unpin are both enabled. Same caller model as the rest of the module.
//
// Known limits:
//   * ShadowHook 1.0.10 is the last version that runs on x86 emulators.
//     1.1.1+ returns "Init linker mod failed" on MuMu/Memuplay.
//   * The pattern-scan path currently has no signatures loaded — the
//     scanning helper and SigByte plumbing are present so that signature
//     extraction from libil2cpp.so can be dropped in without further
//     structural change.

#include "pas.h"

#ifdef PAS_HAVE_SHADOWHOOK

#include <jni.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include "shadowhook.h"

namespace pas {

static volatile bool g_ssl_arm64_on = true;
static volatile int g_ssl_arm64_logged = 0;

static void SslArm64Log(const char* op, const char* detail) {
    int n = __sync_fetch_and_add(&g_ssl_arm64_logged, 1);
    if (n > 200) return;
    Log("native: ssl-arm64: %s %s", op, detail ? detail : "");
}

// ---------------------------------------------------------------------------
// Proxy functions — same verdicts as hide_ssl.cpp, different engine.
// ---------------------------------------------------------------------------

static void Arm64SslSetVerify_NoCall(void* ssl, int mode, void* cb) {
    (void)ssl; (void)mode; (void)cb;
    SslArm64Log("SSL_set_verify", "forced SSL_VERIFY_NONE");
}

static void Arm64SslCtxSetVerify_NoCall(void* ctx, int mode, void* cb) {
    (void)ctx; (void)mode; (void)cb;
    SslArm64Log("SSL_CTX_set_verify", "forced SSL_VERIFY_NONE");
}

static int Arm64X509VerifyCert_True(void* ctx) {
    (void)ctx;
    SslArm64Log("X509_verify_cert", "forced success");
    return 1;
}

static int Arm64X509StoreCtxGetError_Ok(const void* ctx) {
    (void)ctx;
    return 0;  // X509_V_OK
}

static void Arm64X509StoreCtxSetError_Ok(void* ctx, int err) {
    (void)ctx; (void)err;
}

// ---------------------------------------------------------------------------
// Pattern scanner (ARM64 byte signatures for BoringSSL verify functions)
//
// Signature bytes for the specific BoringSSL version bundled in the target
// library get filled into kSigs[] below. A wildcard byte ("??") tolerates
// register-allocation differences. A miss is logged, never fatal.
// ---------------------------------------------------------------------------

struct SigByte {
    uint8_t value;
    bool wildcard;
};

struct Signature {
    const char* name;
    std::vector<SigByte> bytes;
    void* proxy;
};

// Parse a "AA BB ?? CC" hex string into the byte vector. Unused today (the
// signatures are empty), kept so filling kSigs[] is a one-line change once a
// real prologue dump exists.
static void AddBytes(std::vector<SigByte>* v, const char* hex) {
    const char* p = hex;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?' && p[1] == '?') {
            v->push_back({0, true});
            p += 2;
        } else {
            auto hexval = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return 0;
            };
            uint8_t b = (uint8_t)((hexval(p[0]) << 4) | hexval(p[1]));
            v->push_back({b, false});
            p += 2;
        }
    }
}

// Placeholder — real signature scanning needs the mapped range from
// /proc/self/maps and a byte-comparison loop. Returns nullptr until kSigs[]
// is populated with real signatures extracted from the target library.
static void* ScanLibForSignature(const char* lib_name, const Signature& sig) {
    (void)lib_name;
    (void)sig;
    return nullptr;
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

struct NamedHook {
    const char* lib;
    const char* sym;
    void* proxy;
    void** orig;
};

static void* g_orig_ssl_set_verify = nullptr;
static void* g_orig_ssl_ctx_set_verify = nullptr;
static void* g_orig_x509_verify_cert = nullptr;
static void* g_orig_x509_get_error = nullptr;
static void* g_orig_x509_set_error = nullptr;

static int TryNameHook(const NamedHook& h) {
    void* stub = shadowhook_hook_sym_name(h.lib, h.sym, h.proxy, h.orig);
    if (stub == nullptr) return 0;
    char detail[160];
    snprintf(detail, sizeof(detail), "%s @ %s", h.sym, h.lib);
    SslArm64Log("hooked", detail);
    return 1;
}

void InstallSslArm64Hooks() {
    if (!g_ssl_arm64_on) return;

    int rc = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
    if (rc != 0) {
        int err = shadowhook_get_errno();
        Log("native: ssl-arm64: shadowhook_init failed rc=%d errno=%d (%s)",
            rc, err, shadowhook_to_errmsg(err));
        return;
    }
    SslArm64Log("init", "shadowhook ready");

    int hooked = 0;

    // Pass 1: name-based hooks. These succeed for the system libssl and for
    // any bundled OpenSSL that exports the standard names.
    static const NamedHook kHooks[] = {
        {"libssl.so", "SSL_set_verify", (void*)Arm64SslSetVerify_NoCall, &g_orig_ssl_set_verify},
        {"libssl.so", "SSL_CTX_set_verify", (void*)Arm64SslCtxSetVerify_NoCall, &g_orig_ssl_ctx_set_verify},
        {"libcrypto.so", "X509_verify_cert", (void*)Arm64X509VerifyCert_True, &g_orig_x509_verify_cert},
        {"libcrypto.so", "X509_STORE_CTX_get_error", (void*)Arm64X509StoreCtxGetError_Ok, &g_orig_x509_get_error},
        {"libcrypto.so", "X509_STORE_CTX_set_error", (void*)Arm64X509StoreCtxSetError_Ok, &g_orig_x509_set_error},
        {"libssl_bundled.so", "SSL_set_verify", (void*)Arm64SslSetVerify_NoCall, &g_orig_ssl_set_verify},
        {"libssl_bundled.so", "SSL_CTX_set_verify", (void*)Arm64SslCtxSetVerify_NoCall, &g_orig_ssl_ctx_set_verify},
        {"libssl3.so", "SSL_set_verify", (void*)Arm64SslSetVerify_NoCall, &g_orig_ssl_set_verify},
    };
    for (const NamedHook& h : kHooks) {
        hooked += TryNameHook(h);
    }

    // Pass 2: pattern-based hooks (signatures TBD; see kSigs note above).
    static const Signature kSigs[] = {
        {"X509_verify_cert",  {}, (void*)Arm64X509VerifyCert_True},
        {"X509_STORE_CTX_set_error", {}, (void*)Arm64X509StoreCtxSetError_Ok},
    };
    for (const Signature& s : kSigs) {
        if (s.bytes.empty()) continue;
        void* addr = ScanLibForSignature("libil2cpp.so", s);
        if (addr == nullptr) continue;
        void* stub = shadowhook_hook_sym_addr(addr, s.proxy, nullptr);
        if (stub != nullptr) {
            char detail[160];
            snprintf(detail, sizeof(detail), "%s @ 0x%llx (pattern)",
                     s.name, (unsigned long long)(uintptr_t)addr);
            SslArm64Log("hooked-pattern", detail);
            hooked++;
        }
    }

    Log("native: ssl-arm64 hooks installed (%d active, engine=shadowhook 1.0.10)", hooked);
}

void SetSslArm64(bool on) {
    g_ssl_arm64_on = on;
    Log("native: ssl-arm64=%d", (int)on);
}

bool SslArm64Active() {
    return g_ssl_arm64_on;
}

}  // namespace pas

#else  // !PAS_HAVE_SHADOWHOOK — non-arm64 ABIs

namespace pas {

// Stub implementations so pas.cpp can call these unconditionally on every ABI
// without #ifdef sprinkling. Everything here is a no-op by design: ShadowHook
// does not ship x86 or x86_64 native libraries, so ARM64 inline hooking is not
// available on those ABIs.
void InstallSslArm64Hooks() {
    Log("native: ssl-arm64: skipped (ABI has no shadowhook support)");
}

void SetSslArm64(bool on) {
    (void)on;
}

bool SslArm64Active() {
    return false;
}

}  // namespace pas

#endif  // PAS_HAVE_SHADOWHOOK