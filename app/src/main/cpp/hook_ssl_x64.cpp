// hook_ssl_x64.cpp — x86_64 static-SSL verdict patcher.
//
// Closes the one pinning class the ByteHook PLT engine (hide_ssl.cpp) cannot
// reach on x86_64: BoringSSL statically linked into an app library with
// hidden visibility. libflutter.so is the canonical case - its verify entry
// points are not exported, so no name-based or PLT approach can see them.
//
// Approach: pattern-locate the function entry (same nibble-wildcard
// signatures the ARM64 engine uses, x64 table from NVISO), verify the bytes
// at the match, then rewrite the entry with a constant-return stub:
//
//   ssl_verify_peer_cert  ->  31 C0 C3              (xor eax,eax; ret)
//                              returns 0 = ssl_verify_ok
//
// This is the x86_64 twin of Interceptor.replace(addr, callback returning a
// constant) in the published Frida script, without a trampoline: the goal is
// only to force the verdict, so the original body is never needed. That is
// why no inline-hook engine (Dobby/ShadowHook) is required on this ABI -
// ShadowHook has no x86_64 port at all, and vendoring Dobby would add a
// native dependency plus instruction-relocation risk for a patch that is
// three bytes long.
//
// Safety rules:
//   * only r-x mappings of the target library basename are scanned;
//   * the signature must match exactly at the patch address before writing;
//   * the page is mprotect(RWX) for the write and restored to R-X after;
//   * one patch per (library, signature); misses are logged, never fatal.
//
// Known limits:
//   * Pattern tables age with the engine version; a newer libflutter.so
//     simply will not match (logged "no pattern match"), nothing is patched.
//   * Byte-patching is visible to code that hashes its own text; Flutter
//     apps do not do this in practice, but a hard target could.
//   * il2cpp has no published x64 signature table yet; entries can be
//     appended to kPatches once extracted.

#include "pas.h"

#if defined(__x86_64__)

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

namespace pas {

namespace {

struct SigByte {
    uint8_t value;
    uint8_t mask;  // per-nibble: set = compare, clear = wildcard
};

struct MapsRange {
    unsigned long long lo;
    unsigned long long hi;
    bool read;
    bool exec;
    std::string path;
};

struct PatchDef {
    const char* label;    // function label for logs
    const char* lib_sub;  // substring matched against the library basename
    const char* hex;      // nibble-wildcard signature
    const uint8_t* stub;  // replacement bytes for the function entry
    size_t stub_len;
};

// 31 C0        xor eax, eax
// C3           ret
// -> ssl_verify_result_t ssl_verify_ok (0)
static const uint8_t kRetOk[] = {0x31, 0xC0, 0xC3};

// B8 01 00 00 00   mov eax, 1
// C3               ret
// -> bool true (kept for a future session_verify_cert_chain x64 signature)
static const uint8_t kRetTrue[] __attribute__((unused)) = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};

// NVISO "Jun 17 2026" android x64 table, ssl_verify_peer_cert
// (https://github.com/NVISOsecurity/disable-flutter-tls-verification).
// Each entry must match exactly once; a non-match is a no-op.
static const PatchDef kPatches[] = {
    // SIG: ssl_verify_peer_cert
    {"ssl_verify_peer_cert", "flutter",
     "55 41 57 41 56 41 55 41 54 53 50 49 89 F? 4? 8B ?? 4? 8B 4? 30 4C 8B ?? ?? 0? 00 00 4D 85 ?? 74 1? 4D 8B",
     kRetOk, sizeof(kRetOk)},
    // SIG: ssl_verify_peer_cert
    {"ssl_verify_peer_cert", "flutter",
     "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74",
     kRetOk, sizeof(kRetOk)},
    // SIG: ssl_verify_peer_cert
    {"ssl_verify_peer_cert", "flutter",
     "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB",
     kRetOk, sizeof(kRetOk)},
};

constexpr size_t kMaxPatches = sizeof(kPatches) / sizeof(kPatches[0]);

std::vector<std::string> g_done;  // "<lib>#<label>" dedup list

bool ParseMaps(std::vector<MapsRange>* out) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (f == nullptr) return false;
    out->clear();
    char line[1024];
    while (fgets(line, sizeof(line), f) != nullptr) {
        unsigned long long lo = 0, hi = 0;
        char perms[8] = {0};
        char path[512] = {0};
        int n = sscanf(line, "%llx-%llx %7s %*s %*s %*s %511[^\n]", &lo, &hi, perms, path);
        if (n < 3 || path[0] != '/') continue;
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

void BasenameOf(const std::string& path, char* out, size_t cap) {
    const char* p = path.c_str();
    const char* slash = strrchr(p, '/');
    const char* base = slash != nullptr ? slash + 1 : p;
    strncpy(out, base, cap - 1);
    out[cap - 1] = '\0';
}

int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool ParsePattern(const char* hex, std::vector<SigByte>* out) {
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

void* ScanRange(const uint8_t* start, size_t len, const std::vector<SigByte>& sig) {
    if (len < sig.size()) return nullptr;
    const uint8_t* end = start + (len - sig.size());
    for (const uint8_t* p = start; p <= end; p++) {
        bool ok = true;
        for (size_t j = 0; j < sig.size(); j++) {
            if ((p[j] & sig[j].mask) != sig[j].value) {
                ok = false;
                break;
            }
        }
        if (ok) return (void*)p;
    }
    return nullptr;
}

// True when the ELF at addr is a 64-bit x86_64 object (guards against any
// arm64 library that happens to share the basename in a translated process).
bool IsX64ElfAt(unsigned long long addr) {
    const uint8_t* p = (const uint8_t*)(uintptr_t)addr;
    if (p[0] != 0x7F || p[1] != 'E' || p[2] != 'L' || p[3] != 'F') return false;
    if (p[4] != 2) return false;  // ELFCLASS64
    uint16_t machine = (uint16_t)(p[18] | (p[19] << 8));
    return machine == 62;  // EM_X86_64
}

// Restore the page to R-X after the write; logs only on failure.
void ProtectRx(void* page, size_t len) {
    if (mprotect(page, len, PROT_READ | PROT_EXEC) != 0) {
        Log("native: ssl-x64: mprotect restore failed errno=%d", errno);
    }
}

bool PatchEntry(void* addr, const uint8_t* stub, size_t stub_len) {
    if (addr == nullptr || stub_len == 0) return false;
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return false;
    uintptr_t a = (uintptr_t)addr;
    uintptr_t page = a & ~(uintptr_t)(page_size - 1);
    size_t len = (size_t)(a - page) + stub_len;
    len = (len + (size_t)page_size - 1) & ~(size_t)(page_size - 1);
    if (mprotect((void*)page, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        Log("native: ssl-x64: mprotect RWX failed errno=%d", errno);
        return false;
    }
    memcpy(addr, stub, stub_len);
    __builtin___clear_cache((char*)addr, (char*)addr + stub_len);
    ProtectRx((void*)page, len);
    return true;
}

// One scan pass over every loaded library matching the current definitions.
// Returns the number of entries patched in this pass.
int ScanPass() {
    std::vector<MapsRange> maps;
    if (!ParseMaps(&maps)) return 0;

    int patched = 0;
    for (size_t d = 0; d < kMaxPatches; d++) {
        const PatchDef& def = kPatches[d];
        std::vector<SigByte> sig;
        if (!ParsePattern(def.hex, &sig)) continue;

        // Walk each distinct library basename once per definition: the
        // dedup key is set only after every exec range of that library has
        // been scanned, so a lib with several r-x mappings is fully covered
        // and a version miss is not retried every tick.
        std::vector<std::string> bases;
        for (const MapsRange& r : maps) {
            if (!r.exec) continue;
            char base[256];
            BasenameOf(r.path, base, sizeof(base));
            if (strstr(base, def.lib_sub) == nullptr) continue;
            bool dup = false;
            for (const std::string& b : bases) {
                if (b == base) {
                    dup = true;
                    break;
                }
            }
            if (!dup) bases.push_back(base);
        }

        for (const std::string& base : bases) {
            std::string key = base + "#" + def.label;
            bool already = false;
            for (const std::string& s : g_done) {
                if (s == key) {
                    already = true;
                    break;
                }
            }
            if (already) continue;

            // Library load address = lowest readable mapping of that basename.
            unsigned long long lib_base = 0;
            bool have_base = false;
            for (const MapsRange& m : maps) {
                char b2[256];
                BasenameOf(m.path, b2, sizeof(b2));
                if (b2 != base || !m.read) continue;
                if (!have_base || m.lo < lib_base) {
                    lib_base = m.lo;
                    have_base = true;
                }
            }
            if (!have_base || !IsX64ElfAt(lib_base)) continue;

            void* hit = nullptr;
            for (const MapsRange& r : maps) {
                if (!r.exec || !r.read) continue;
                char b3[256];
                BasenameOf(r.path, b3, sizeof(b3));
                if (b3 != base) continue;
                hit = ScanRange((const uint8_t*)(uintptr_t)r.lo, (size_t)(r.hi - r.lo), sig);
                if (hit != nullptr) break;
            }
            g_done.push_back(key);
            if (hit == nullptr) {
                Log("native: ssl-x64: no pattern match for %s in %s", def.label, base.c_str());
                continue;
            }
            if (!PatchEntry(hit, def.stub, def.stub_len)) continue;
            patched++;
            Log("native: ssl-x64: patched %s @ %s+0x%llx (ret=0)", def.label, base.c_str(),
                (unsigned long long)((uintptr_t)hit - (uintptr_t)lib_base));
        }
    }
    return patched;
}

void* WatchWorker(void* arg) {
    (void)arg;
    static const int kTicks = 15;
    int total = 0;
    for (int t = 0; t < kTicks; t++) {
        usleep(2000000);
        if (!SslUnpinActive()) break;
        total += ScanPass();
    }
    Log("native: ssl-x64: watcher done (patched=%d)", total);
    return nullptr;
}

}  // namespace

void InstallSslX64Patch() {
    if (!SslUnpinActive()) return;

    int patched = ScanPass();
    Log("native: ssl-x64 verdict pass (%d patched, engine=pattern+entry-stub)", patched);

    pthread_t t;
    if (pthread_create(&t, nullptr, WatchWorker, nullptr) == 0) {
        pthread_detach(t);
    } else {
        Log("native: ssl-x64: watcher pthread_create failed");
    }
}

}  // namespace pas

#else  // !__x86_64__ — all other ABIs

namespace pas {

void InstallSslX64Patch() {
    // x86_64-only engine: arm64 is covered by hook_ssl_arm64.cpp (ShadowHook
    // inline hooks), x86 by the ByteHook PLT layer in hide_ssl.cpp.
}

}  // namespace pas

#endif  // __x86_64__
