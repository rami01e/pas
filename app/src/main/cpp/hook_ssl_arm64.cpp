// hook_ssl_arm64.cpp — ARM64 inline-hook SSL unpinning (ShadowHook 1.0.10)
//
// Bi-arch strategy (hide_ssl.cpp is the x86_64 / x86 engine):
//   * x86_64 / x86 process  -> hide_ssl.cpp (ByteHook PLT hooks; ShadowHook
//     upstream has no x86_64 port - its source carries arch/arm and
//     arch/arm64 only, verified against v1.0.10 and current main).
//   * arm64 process         -> this file (ShadowHook inline hooks). On x86_64
//     emulators this includes ARM-translated apps: the arm64 build of
//     libpas.so (with its libshadowhook.so dependency) is loaded through the
//     native bridge and runs translated in guest space, so it can patch
//     guest ARM64 code directly. That is also why ShadowHook stays pinned at
//     1.0.10 - 1.1.1+ fails to init on MuMu/MemuPlay ("Init linker mod
//     failed").
//
// Three hook passes run on the arm64 leg:
//
//   1. Name-based hooks (shadowhook_hook_sym_name) against every loaded
//      library whose basename matches the same owner substrings as the
//      x86_64 engine (ssl / crypto / boring / cronet / mbedtls / gnutls),
//      plus a small static list of classic names. ShadowHook 1.0.10
//      supports PENDING hooks: registering a hook for a library that is not
//      loaded yet succeeds and completes when the linker dlopens it
//      (verified in sh_task.c / sh_linker.c of the 1.0.10 source), so load
//      order does not matter. ShadowHook also refuses wrong-architecture
//      libraries (SHADOWHOOK_ERRNO_ELF_ARCH_MISMATCH), which makes the
//      name pass safe in translated processes where host x86_64 libraries
//      share the maps with guest ARM64 ones.
//      Symbols: SSL_set_verify, SSL_CTX_set_verify,
//               SSL_set_custom_verify, SSL_CTX_set_custom_verify
//                 (BoringSSL's actual verification path - previously missed),
//               SSL_get_verify_result, X509_verify_cert,
//               X509_STORE_CTX_get_error, X509_STORE_CTX_set_error.
//
//   2. Symtab probe (shadowhook_dlopen + shadowhook_dlsym_symtab) on
//      flutter / il2cpp libraries: builds that keep a .symtab expose their
//      statically linked BoringSSL functions even when hidden from dynsym,
//      and can be hooked by exact address with no signatures.
//
//   3. Pattern scan for statically linked BoringSSL with stripped symbols:
//      nibble-wildcard byte signatures matched over the library's r-x
//      mappings, then hooked by address with shadowhook_hook_func_addr
//      (the raw-address API - hook_sym_addr would reject an address that
//      resolves to no symbol, which is exactly the stripped case).
//      Signatures: published NVISO table for libflutter.so
//      (ssl_verify_peer_cert / ssl_crypto_x509_session_verify_cert_chain),
//      pattern revision "Jun 17 2026", transcribed from
//      https://github.com/NVISOsecurity/disable-flutter-tls-verification
//      and validated against that project's own sample libflutter.so
//      binaries: 5 of 6 arm64 samples match exactly one pattern exactly
//      once, zero multi-matches.
//
// A background watcher re-runs the maps-driven discovery for ~30 s after
// install so libraries that load after module init (Flutter engines and
// game SSL bundles typically load seconds in) are still covered.
//
// Known limits:
//   * Pattern tables age: a Flutter engine newer than the table (or built
//     differently) matches nothing - one sample out of six already does.
//     A miss is logged, never fatal.
//   * Unity libil2cpp.so has no published signature table; only the symtab
//     probe reaches it today. Signatures can be appended to kPatterns as
//     they are extracted.
//   * Translated processes: shadowhook patches guest ARM64 code in place.
//     If the translator already cached a translation of the target
//     function, the patch may not take effect (per-bridge behavior is
//     undocumented). The per-hook log lines make this observable in a
//     capture: "hooked-pattern" proves install, "ssl-arm64: intercepted"
//     lines prove interception.
//   * No x86_64 inline engine exists in this module. x86_64-native apps
//     with statically linked SSL (Flutter apps shipping x86_64 splits) are
//     covered by the Java layer only.

#include "pas.h"

#ifdef PAS_HAVE_SHADOWHOOK

#include <jni.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <utility>
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
// Proxy functions - same verdicts as hide_ssl.cpp, different engine. None of
// them call the original: every one forces an "accept" verdict, so a saved
// orig pointer is never dereferenced (the orig slots exist only to satisfy
// the API).
// ---------------------------------------------------------------------------

static void Arm64SslSetVerify_NoCall(void* ssl, int mode, void* cb) {
    (void)ssl; (void)mode; (void)cb;
    SslArm64Log("intercepted", "SSL_set_verify -> SSL_VERIFY_NONE");
}

static void Arm64SslCtxSetVerify_NoCall(void* ctx, int mode, void* cb) {
    (void)ctx; (void)mode; (void)cb;
    SslArm64Log("intercepted", "SSL_CTX_set_verify -> SSL_VERIFY_NONE");
}

// BoringSSL's replacement for the set_verify family - the path Chromium,
// Cronet, system libssl and every modern BoringSSL consumer actually takes.
static void Arm64SslSetCustomVerify_NoCall(void* ssl, int mode, void* cb) {
    (void)ssl; (void)mode; (void)cb;
    SslArm64Log("intercepted", "SSL_set_custom_verify -> SSL_VERIFY_NONE");
}

static void Arm64SslCtxSetCustomVerify_NoCall(void* ctx, int mode, void* cb) {
    (void)ctx; (void)mode; (void)cb;
    SslArm64Log("intercepted", "SSL_CTX_set_custom_verify -> SSL_VERIFY_NONE");
}

// Post-handshake readback path: apps that swallow the verify-mode call still
// poll SSL_get_verify_result and abort on a non-zero value.
static long Arm64SslGetVerifyResult_Ok(const void* ssl) {
    (void)ssl;
    return 0;  // X509_V_OK
}

static int Arm64X509VerifyCert_True(void* ctx) {
    (void)ctx;
    SslArm64Log("intercepted", "X509_verify_cert -> forced success");
    return 1;
}

static int Arm64X509StoreCtxGetError_Ok(const void* ctx) {
    (void)ctx;
    return 0;  // X509_V_OK
}

static void Arm64X509StoreCtxSetError_Ok(void* ctx, int err) {
    (void)ctx;
    (void)err;
}

// Pattern-path proxies. ssl_verify_peer_cert returns ssl_verify_result_t
// where 0 = ssl_verify_ok; ssl_crypto_x509_session_verify_cert_chain
// returns bool where 1 = verified. Arg counts match the real functions
// (2 and 3 pointer-sized args) though none of them are used.
static int Arm64SslVerifyPeerCert_Ok(void* hs, void* out_alert) {
    (void)hs; (void)out_alert;
    SslArm64Log("intercepted", "ssl_verify_peer_cert -> ssl_verify_ok");
    return 0;
}

static int Arm64SessionVerifyCertChain_True(void* session, void* hs, void* out_alert) {
    (void)session; (void)hs; (void)out_alert;
    SslArm64Log("intercepted", "session_verify_cert_chain -> verified");
    return 1;
}

// ---------------------------------------------------------------------------
// Symbol table (single source of truth for the name pass and the symtab
// probe).
// ---------------------------------------------------------------------------

static void* ProxyForSym(const char* sym) {
    if (sym == nullptr) return nullptr;
    if (strcmp(sym, "SSL_set_verify") == 0) return (void*)Arm64SslSetVerify_NoCall;
    if (strcmp(sym, "SSL_CTX_set_verify") == 0) return (void*)Arm64SslCtxSetVerify_NoCall;
    if (strcmp(sym, "SSL_set_custom_verify") == 0) return (void*)Arm64SslSetCustomVerify_NoCall;
    if (strcmp(sym, "SSL_CTX_set_custom_verify") == 0) return (void*)Arm64SslCtxSetCustomVerify_NoCall;
    if (strcmp(sym, "SSL_get_verify_result") == 0) return (void*)Arm64SslGetVerifyResult_Ok;
    if (strcmp(sym, "X509_verify_cert") == 0) return (void*)Arm64X509VerifyCert_True;
    if (strcmp(sym, "X509_STORE_CTX_get_error") == 0) return (void*)Arm64X509StoreCtxGetError_Ok;
    if (strcmp(sym, "X509_STORE_CTX_set_error") == 0) return (void*)Arm64X509StoreCtxSetError_Ok;
    if (strcmp(sym, "ssl_verify_peer_cert") == 0) return (void*)Arm64SslVerifyPeerCert_Ok;
    if (strcmp(sym, "ssl_crypto_x509_session_verify_cert_chain") == 0)
        return (void*)Arm64SessionVerifyCertChain_True;
    return nullptr;
}

static const char* const kNameSyms[] = {
    "SSL_set_verify",
    "SSL_CTX_set_verify",
    "SSL_set_custom_verify",
    "SSL_CTX_set_custom_verify",
    "SSL_get_verify_result",
    "X509_verify_cert",
    "X509_STORE_CTX_get_error",
    "X509_STORE_CTX_set_error",
};

// Symbols probed in .symtab (not just dynsym) of pattern-target libraries.
static const char* const kSymtabSyms[] = {
    "SSL_set_verify",
    "SSL_CTX_set_verify",
    "SSL_set_custom_verify",
    "SSL_CTX_set_custom_verify",
    "SSL_get_verify_result",
    "X509_verify_cert",
    "X509_STORE_CTX_get_error",
    "X509_STORE_CTX_set_error",
    "ssl_verify_peer_cert",
    "ssl_crypto_x509_session_verify_cert_chain",
};

// orig slots: one per name symbol, shared across libraries. No proxy ever
// calls through them (all proxies are verdict-forcers), so sharing is safe.
static void* g_orig_slots[sizeof(kNameSyms) / sizeof(kNameSyms[0])];

// ---------------------------------------------------------------------------
// /proc/self/maps helpers
// ---------------------------------------------------------------------------

struct MapsRange {
    unsigned long long lo;
    unsigned long long hi;
    bool read;
    bool exec;
    std::string path;
};

static bool ParseMaps(std::vector<MapsRange>* out) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (f == nullptr) return false;
    out->clear();
    char line[1024];
    while (fgets(line, sizeof(line), f) != nullptr) {
        unsigned long long lo = 0, hi = 0;
        char perms[8] = {0};
        char path[512] = {0};
        int n = sscanf(line, "%llx-%llx %7s %*s %*s %*s %511[^\n]", &lo, &hi, perms, path);
        if (n < 3) continue;
        if (path[0] != '/') continue;
        MapsRange r;
        r.lo = lo;
        r.hi = hi;
        r.read = perms[0] == 'r';
        r.exec = perms[2] == 'x';
        r.path = path;
        out->push_back(std::move(r));
    }
    fclose(f);
    return true;
}

static void BasenameOf(const std::string& path, char* out, size_t cap) {
    const char* p = path.c_str();
    const char* slash = strrchr(p, '/');
    const char* base = slash != nullptr ? slash + 1 : p;
    strncpy(out, base, cap - 1);
    out[cap - 1] = '\0';
}

static bool SeenAdd(std::vector<std::string>* seen, const std::string& name) {
    for (const std::string& s : *seen) {
        if (s == name) return false;
    }
    seen->push_back(name);
    return true;
}

// True when the ELF mapped at addr is a 64-bit ARM64 object. Guards every
// raw-address path against host x86_64 libraries that share the maps of a
// translated process (the name pass additionally gets this check inside
// ShadowHook itself: sh_linker_check_arch).
static bool IsArm64ElfAt(unsigned long long addr) {
    const uint8_t* p = (const uint8_t*)(uintptr_t)addr;
    if (p[0] != 0x7F || p[1] != 'E' || p[2] != 'L' || p[3] != 'F') return false;
    if (p[4] != 2) return false;  // ELFCLASS64
    uint16_t machine = (uint16_t)(p[18] | (p[19] << 8));
    return machine == 183;  // EM_AARCH64
}

// Lowest readable mapping of a library = its ELF header page.
static bool LibBaseFor(const std::vector<MapsRange>& maps, const char* base_name,
                       unsigned long long* base_out) {
    unsigned long long base = 0;
    bool have = false;
    for (const MapsRange& r : maps) {
        char b[256];
        BasenameOf(r.path, b, sizeof(b));
        if (strcmp(b, base_name) != 0 || !r.read) continue;
        if (!have || r.lo < base) {
            base = r.lo;
            have = true;
        }
    }
    if (have && base_out != nullptr) *base_out = base;
    return have;
}

// ---------------------------------------------------------------------------
// Pass 1: name-based hooks
// ---------------------------------------------------------------------------

// Keep in sync with hide_ssl.cpp kOwners.
static const char* const kOwnerSubs[] = {
    "ssl", "crypto", "boring", "cronet", "mbedtls", "gnutls",
};

// Ourselves, the hook engines, and the translation/bridge machinery are
// never hook targets. ShadowHook's own ELF-arch check already rejects
// wrong-arch libs; this list avoids pointless attempts and log noise.
static bool LibNameAllowed(const char* base) {
    static const char* const kDeny[] = {
        "libpas", "libshadowhook", "libbytehook", "libnb", "houdini",
        "ndk_translation", "libhp", "mumu",
    };
    for (size_t i = 0; i < sizeof(kDeny) / sizeof(kDeny[0]); i++) {
        if (strstr(base, kDeny[i]) != nullptr) return false;
    }
    return true;
}

static bool LibIsOwnerMatch(const char* base) {
    if (!LibNameAllowed(base)) return false;
    for (size_t i = 0; i < sizeof(kOwnerSubs) / sizeof(kOwnerSubs[0]); i++) {
        if (strstr(base, kOwnerSubs[i]) != nullptr) return true;
    }
    return false;
}

static int HookLibByName(const char* lib) {
    int hooked = 0;
    for (size_t i = 0; i < sizeof(kNameSyms) / sizeof(kNameSyms[0]); i++) {
        void* proxy = ProxyForSym(kNameSyms[i]);
        if (proxy == nullptr) continue;
        void* stub = shadowhook_hook_sym_name(lib, kNameSyms[i], proxy, &g_orig_slots[i]);
        if (stub == nullptr) continue;  // not exported here / arch mismatch: harmless
        char detail[192];
        snprintf(detail, sizeof(detail), "%s @ %s", kNameSyms[i], lib);
        SslArm64Log("hooked", detail);
        hooked++;
    }
    return hooked;
}

// Classic names registered even when not loaded yet: ShadowHook 1.0.10
// keeps them pending and completes them on dlopen (sh_task.c).
static const char* const kClassicLibs[] = {
    "libssl.so", "libcrypto.so", "libssl_bundled.so", "libssl3.so",
};

// Name-pass state. Touched by the install thread first, then only by the
// watcher thread it spawns - sequential by construction, no lock needed.
static std::vector<std::string> g_name_hooked;

static int NamePassMaps() {
    std::vector<MapsRange> maps;
    if (!ParseMaps(&maps)) return 0;
    int hooked = 0;
    for (const MapsRange& r : maps) {
        if (!r.exec) continue;
        char base[256];
        BasenameOf(r.path, base, sizeof(base));
        if (!LibIsOwnerMatch(base)) continue;
        if (!SeenAdd(&g_name_hooked, base)) continue;
        // In a translated process the kernel maps also list host x86_64
        // libraries under owner-matching names. ShadowHook searches the
        // guest linker's module list and arch-checks by itself, but skip
        // host objects here so no pending task is left dangling for a
        // library it can never hook.
        unsigned long long hdr = 0;
        if (!LibBaseFor(maps, base, &hdr) || !IsArm64ElfAt(hdr)) continue;
        hooked += HookLibByName(base);
    }
    return hooked;
}

static int NamePassClassic() {
    int hooked = 0;
    for (size_t i = 0; i < sizeof(kClassicLibs) / sizeof(kClassicLibs[0]); i++) {
        if (!SeenAdd(&g_name_hooked, kClassicLibs[i])) continue;
        hooked += HookLibByName(kClassicLibs[i]);
    }
    return hooked;
}

// ---------------------------------------------------------------------------
// Pass 2 + 3: symtab probe and pattern scan for statically linked BoringSSL
// ---------------------------------------------------------------------------

struct SigByte {
    uint8_t value;
    uint8_t mask;  // per-nibble: set = compare, clear = wildcard
};

struct PatternDef {
    const char* label;   // function label for logs
    const char* lib_sub; // substring matched against the library basename
    const char* hex;     // nibble-wildcard pattern, parsed at runtime
    void* proxy;
};

// Pattern table for libflutter.so: NVISO "Jun 17 2026" arm64 revision,
// https://github.com/NVISOsecurity/disable-flutter-tls-verification
// Validated against that project's sample libflutter.so set (5/6 match
// exactly once, zero multi-matches; the miss is an engine version newer
// than the table). To extend: dump the target function's first ~32 bytes
// from the app's own library, wildcard the register-allocated nibbles, and
// append an entry. Unity il2cpp entries belong here once extracted.
static const PatternDef kPatterns[] = {
    // SIG: ssl_verify_peer_cert
    {"ssl_verify_peer_cert", "flutter",
     "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
     (void*)Arm64SslVerifyPeerCert_Ok},
    // SIG: ssl_verify_peer_cert
    {"ssl_verify_peer_cert", "flutter",
     "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
     (void*)Arm64SslVerifyPeerCert_Ok},
    // SIG: ssl_verify_peer_cert
    {"ssl_verify_peer_cert", "flutter",
     "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
     (void*)Arm64SslVerifyPeerCert_Ok},
    // SIG: ssl_crypto_x509_session_verify_cert_chain (returns bool: 1 = verified)
    {"ssl_crypto_x509_session_verify_cert_chain", "flutter",
     "FF ?3 01 D1 F? ?? 01 A9 ?? ?? ?? 94 ?? ?? ?? 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9",
     (void*)Arm64SessionVerifyCertChain_True},
};

static int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// "F? 0F 1C" -> per-nibble wildcards. "?" skips the nibble, a hex digit
// pins it. Returns false on malformed input (entry skipped, never fatal).
static bool ParsePattern(const char* hex, std::vector<SigByte>* out) {
    out->clear();
    const char* p = hex;
    while (*p != '\0') {
        while (*p == ' ') p++;
        if (*p == '\0') break;
        char h = p[0];
        char l = p[1];
        if (h == '\0' || l == '\0') return false;
        uint8_t v = 0;
        uint8_t m = 0;
        if (h != '?') {
            int x = HexVal(h);
            if (x < 0) return false;
            v |= (uint8_t)(x << 4);
            m |= 0xF0;
        }
        if (l != '?') {
            int x = HexVal(l);
            if (x < 0) return false;
            v |= (uint8_t)x;
            m |= 0x0F;
        }
        out->push_back({v, m});
        p += 2;
    }
    return !out->empty();
}

static void* ScanRangeForSig(const uint8_t* start, size_t len, const std::vector<SigByte>& sig) {
    if (len < sig.size()) return nullptr;
    size_t n = sig.size();
    const uint8_t* end = start + (len - n);
    for (const uint8_t* p = start; p <= end; p++) {
        bool ok = true;
        for (size_t j = 0; j < n; j++) {
            if ((p[j] & sig[j].mask) != sig[j].value) {
                ok = false;
                break;
            }
        }
        if (ok) return (void*)p;
    }
    return nullptr;
}

// Scan every r-x mapping of the library whose basename equals lib_name.
// Returns the first match address (and the library load base for logging),
// or nullptr. The mapped text of a non-PIE-relocating segment is the file
// image, so the validated file-offset semantics carry over.
static void* ScanLibForSig(const char* lib_name, const std::vector<SigByte>& sig,
                           unsigned long long* lib_base_out) {
    std::vector<MapsRange> maps;
    if (!ParseMaps(&maps)) return nullptr;
    unsigned long long base = 0;
    bool have_base = false;
    for (const MapsRange& r : maps) {
        char b[256];
        BasenameOf(r.path, b, sizeof(b));
        if (strcmp(b, lib_name) != 0) continue;
        if (!r.read) continue;  // header page must be readable for the arch check
        if (!have_base || r.lo < base) {
            base = r.lo;
            have_base = true;
        }
    }
    if (!have_base) return nullptr;
    if (lib_base_out != nullptr) *lib_base_out = base;
    if (!IsArm64ElfAt(base)) {
        char detail[256];
        snprintf(detail, sizeof(detail), "%s skipped (not an arm64 ELF)", lib_name);
        SslArm64Log("pattern", detail);
        return nullptr;
    }
    for (const MapsRange& r : maps) {
        char b[256];
        BasenameOf(r.path, b, sizeof(b));
        if (strcmp(b, lib_name) != 0) continue;
        if (!r.exec || !r.read) continue;
        void* hit = ScanRangeForSig((const uint8_t*)(uintptr_t)r.lo, (size_t)(r.hi - r.lo), sig);
        if (hit != nullptr) return hit;
    }
    return nullptr;
}

// Pattern-target libraries: statically linked BoringSSL carriers.
static const char* const kPatternLibSubs[] = {"flutter", "il2cpp"};

// Symtab probe + pattern scan for one library basename. Callers must have
// verified the arm64 ELF header (LibBaseFor + IsArm64ElfAt) so the raw
// symtab/pattern addresses can never point into a wrong-arch object.
static int PatternPassForLib(const char* base) {
    int hooked = 0;

    // Pass 2: .symtab lookup. shadowhook_dlopen uses its own ELF reader
    // (no real dlopen), so this is safe from the worker thread, and a miss
    // (stripped library) is routine.
    void* handle = shadowhook_dlopen(base);
    if (handle != nullptr) {
        for (size_t i = 0; i < sizeof(kSymtabSyms) / sizeof(kSymtabSyms[0]); i++) {
            const char* sym = kSymtabSyms[i];
            void* addr = shadowhook_dlsym_symtab(handle, sym);
            void* proxy = ProxyForSym(sym);
            if (addr == nullptr || proxy == nullptr) continue;
            void* stub = shadowhook_hook_func_addr(addr, proxy, nullptr);
            if (stub == nullptr) continue;
            char detail[256];
            snprintf(detail, sizeof(detail), "%s @ %s (symtab)", sym, base);
            SslArm64Log("hooked", detail);
            hooked++;
        }
        shadowhook_dlclose(handle);
    }

    // Pass 3: byte-pattern scan.
    for (size_t i = 0; i < sizeof(kPatterns) / sizeof(kPatterns[0]); i++) {
        const PatternDef& pd = kPatterns[i];
        if (strstr(base, pd.lib_sub) == nullptr) continue;
        std::vector<SigByte> sig;
        if (!ParsePattern(pd.hex, &sig)) continue;
        unsigned long long lib_base = 0;
        void* addr = ScanLibForSig(base, sig, &lib_base);
        if (addr == nullptr) continue;
        void* stub = shadowhook_hook_func_addr(addr, pd.proxy, nullptr);
        if (stub == nullptr) continue;
        char detail[288];
        snprintf(detail, sizeof(detail), "%s @ %s+0x%llx (pattern)", pd.label, base,
                 (unsigned long long)((uintptr_t)addr - (uintptr_t)lib_base));
        SslArm64Log("hooked-pattern", detail);
        hooked++;
    }
    return hooked;
}

// Pattern-pass state. Same sequential-ownership rule as g_name_hooked.
static std::vector<std::string> g_pattern_scanned;

// Runs the pattern passes for every pattern-target library currently
// loaded and not yet scanned. Each library is scanned once per process.
static int PatternPassMaps() {
    std::vector<MapsRange> maps;
    if (!ParseMaps(&maps)) return 0;
    int hooked = 0;
    for (const MapsRange& r : maps) {
        if (!r.exec) continue;
        char base[256];
        BasenameOf(r.path, base, sizeof(base));
        if (!LibNameAllowed(base)) continue;
        bool target = false;
        for (size_t i = 0; i < sizeof(kPatternLibSubs) / sizeof(kPatternLibSubs[0]); i++) {
            if (strstr(base, kPatternLibSubs[i]) != nullptr) {
                target = true;
                break;
            }
        }
        if (!target) continue;
        if (!SeenAdd(&g_pattern_scanned, base)) continue;
        unsigned long long hdr = 0;
        if (!LibBaseFor(maps, base, &hdr) || !IsArm64ElfAt(hdr)) continue;
        hooked += PatternPassForLib(base);
    }
    return hooked;
}

// ---------------------------------------------------------------------------
// Late-load watcher: games and Flutter apps initialize their engines
// seconds after process start, long after the install pass. Re-run the
// maps-driven discovery every 2 s for ~30 s. A detached thread; exits early
// if the arm64 engine is switched off.
// ---------------------------------------------------------------------------

static void* SslArm64WatchWorker(void* arg) {
    (void)arg;
    static const int kTicks = 15;
    int name_hooked = 0;
    int pattern_hooked = 0;
    for (int t = 0; t < kTicks; t++) {
        usleep(2000000);
        if (!g_ssl_arm64_on) break;
        name_hooked += NamePassMaps();
        pattern_hooked += PatternPassMaps();
    }
    Log("native: ssl-arm64: watcher done (late name=%d late pattern=%d)", name_hooked,
        pattern_hooked);
    return nullptr;
}

static void SpawnSslArm64Watcher() {
    pthread_t t;
    if (pthread_create(&t, nullptr, SslArm64WatchWorker, nullptr) == 0) {
        pthread_detach(t);
    } else {
        Log("native: ssl-arm64: watcher pthread_create failed");
    }
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

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

    // Pass 1a: every owner-matching library that is already loaded.
    int hooked = NamePassMaps();
    // Pass 1b: classic names (pending hooks cover the not-yet-loaded ones).
    hooked += NamePassClassic();
    // Pass 2 + 3 for pattern targets that are already loaded.
    int pattern_hooked = PatternPassMaps();

    Log("native: ssl-arm64 hooks installed (%d active, %d pattern, engine=shadowhook %s)",
        hooked, pattern_hooked, shadowhook_get_version());

    // Late-load watcher for engines and SSL bundles that appear later.
    SpawnSslArm64Watcher();
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
// available on those ABIs (the x86_64/x86 leg is served by hide_ssl.cpp).
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
