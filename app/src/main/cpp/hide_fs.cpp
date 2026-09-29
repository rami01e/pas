#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "nvd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>

#include "bytehook.h"

namespace nvd {

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

// ---------------------------------------------------------------------------
// watched files: /proc/net/* whose content must be filtered.
// Filtering is done by materializing a filtered copy in a memfd at open()
// time - no read/pread/lseek/dup/close interception is needed at all.
//
// The kernel accepts several aliases for the same files; scanners use them to
// dodge naive filters. We treat them all as watched:
//   /proc/net/X  /proc/self/net/X  /proc/thread-self/net/X  /proc/<pid>/net/X
// ---------------------------------------------------------------------------

enum class WatchedFile {
    None,
    Tcp,   // tcp / tcp6
    Udp,   // udp / udp6
    Misc,  // dev / route / if_inet6 / ipv6_route / arp
};

static WatchedFile ResolveWatchedFile(const char* path) {
    if (!path) return WatchedFile::None;
    static const char kProc[] = "/proc/";
    static const char kNet[] = "net/";
    if (strncmp(path, kProc, sizeof(kProc) - 1) != 0) return WatchedFile::None;
    const char* rest = path + sizeof(kProc) - 1;
    const char* netPart = nullptr;
    if (strncmp(rest, kNet, sizeof(kNet) - 1) == 0) {
        netPart = rest + sizeof(kNet) - 1;
    } else if (strncmp(rest, "self/", 5) == 0) {
        rest += 5;
        if (strncmp(rest, kNet, sizeof(kNet) - 1) == 0) netPart = rest + sizeof(kNet) - 1;
    } else if (strncmp(rest, "thread-self/", 12) == 0) {
        rest += 12;
        if (strncmp(rest, kNet, sizeof(kNet) - 1) == 0) netPart = rest + sizeof(kNet) - 1;
    } else {
        // /proc/<pid>/net/...
        const char* slash = strchr(rest, '/');
        if (slash && slash > rest && strncmp(slash + 1, kNet, sizeof(kNet) - 1) == 0) {
            bool digits = true;
            for (const char* c = rest; c < slash; c++) {
                if (*c < '0' || *c > '9') {
                    digits = false;
                    break;
                }
            }
            if (digits) netPart = slash + 1 + sizeof(kNet) - 1;
        }
    }
    if (!netPart) return WatchedFile::None;
    if (strcmp(netPart, "tcp") == 0 || strcmp(netPart, "tcp6") == 0) return WatchedFile::Tcp;
    if (strcmp(netPart, "udp") == 0 || strcmp(netPart, "udp6") == 0) return WatchedFile::Udp;
    if (strcmp(netPart, "dev") == 0 || strcmp(netPart, "route") == 0 ||
        strcmp(netPart, "if_inet6") == 0 || strcmp(netPart, "ipv6_route") == 0 ||
        strcmp(netPart, "arp") == 0) {
        return WatchedFile::Misc;
    }
    return WatchedFile::None;
}

// ---------------------------------------------------------------------------
// Special files: a tiny allow/deny layer used together with the content
// filters. /proc/net/fib_trie is denied with ENOENT (the checker's own code
// treats that as "not available on this kernel"); /sys/fs/selinux/enforce is
// served as "1\n" so the process sees an enforcing kernel.
// ---------------------------------------------------------------------------

enum class SpecialAction { None, NotFound, EnforceOne };

static SpecialAction ResolveSpecial(const char* path) {
    if (!path) return SpecialAction::None;
    if (strcmp(path, "/proc/net/fib_trie") == 0 ||
        strcmp(path, "/proc/self/net/fib_trie") == 0) {
        return SpecialAction::NotFound;
    }
    if (strcmp(path, "/sys/fs/selinux/enforce") == 0) {
        return SpecialAction::EnforceOne;
    }
    return SpecialAction::None;
}

static int CreateMemfdWith(const char* data, size_t len, int flags) {
#ifdef SYS_memfd_create
    int mfd = (int)syscall(SYS_memfd_create, "nvd-special",
                           (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0);
#else
    int mfd = -1;
#endif
    if (mfd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = syscall(SYS_write, mfd, data + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            syscall(SYS_close, mfd);
            return -1;
        }
        off += (size_t)w;
    }
    syscall(SYS_lseek, mfd, 0, SEEK_SET);
    return mfd;
}

// Raw build.prop-style files that integrity checkers read directly. When the
// SDK/ABI spoof is active these are served with the spoof keys rewritten, so
// the file view matches the hooked properties.
static bool IsPropsFile(const char* path) {
    if (!path) return false;
    static const char* const kProps[] = {
        "/system/build.prop",
        "/vendor/build.prop",
        "/odm/etc/build.prop",
        "/product/build.prop",
        "/system_ext/build.prop",
        "/system/etc/prop.default",
    };
    for (const char* k : kProps) {
        if (strcmp(path, k) == 0) return true;
    }
    return false;
}

static void RewritePropsContent(const std::string& raw, std::string* out) {
    size_t i = 0;
    while (i < raw.size()) {
        size_t j = raw.find('\n', i);
        j = (j == std::string::npos) ? raw.size() : j + 1;
        std::string line(raw, i, j - i);
        const char* c = line.c_str();
        const char* p = c;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '#' && *p != '\0' && *p != '\r' && *p != '\n') {
            const char* eq = strchr(p, '=');
            if (eq != nullptr && eq > p) {
                char key[128];
                size_t kl = (size_t)(eq - p);
                if (kl < sizeof(key)) {
                    memcpy(key, p, kl);
                    key[kl] = '\0';
                    // trim trailing spaces on key
                    while (kl > 0 && (key[kl - 1] == ' ' || key[kl - 1] == '\t')) key[--kl] = '\0';
                    char repl[128];
                    if (SpoofRewritePropsLine(key, eq + 1, repl, sizeof(repl))) {
                        out->append(key);
                        out->push_back('=');
                        out->append(repl);
                        out->push_back('\n');
                        i = j;
                        continue;
                    }
                }
            }
        }
        out->append(line);
        i = j;
    }
}

static bool ReadWholeFile(const char* path, std::string* out);

// Returns true when the call was fully handled by the special layer.
// On NotFound: errno=ENOENT, *fdOut=-1. On EnforceOne: *fdOut is a memfd or -1.
static bool HandleSpecialOpen(const char* path, int flags, int* fdOut) {
    SpecialAction sp = ResolveSpecial(path);
    if (sp == SpecialAction::None) {
        // build.prop-style files: served with the spoof keys rewritten so that
        // anything reading the raw prop files sees the same values as the
        // hooked properties (integrity checkers cross-check these).
        if (SpoofActive() && IsPropsFile(path) && (flags & O_ACCMODE) == O_RDONLY) {
            std::string raw;
            if (!ReadWholeFile(path, &raw)) return false;  // real error wins
            std::string out;
            RewritePropsContent(raw, &out);
            int mfd = CreateMemfdWith(out.data(), out.size(), flags);
            if (mfd < 0) return false;
            *fdOut = mfd;
            return true;
        }
        return false;
    }
    if ((flags & O_ACCMODE) != O_RDONLY) return false;
    if (sp == SpecialAction::NotFound) {
        errno = ENOENT;
        *fdOut = -1;
        return true;
    }
    *fdOut = CreateMemfdWith("1\n", 2, flags);
    return true;
}

static bool ReadWholeFile(const char* path, std::string* out) {
#ifdef SYS_openat
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
#else
    int fd = (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
#endif
    if (fd < 0) return false;
    char buf[16384];
    for (;;) {
        ssize_t n = syscall(SYS_read, fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        out->append(buf, (size_t)n);
        if (out->size() > (4u << 20)) break;
    }
    syscall(SYS_close, fd);
    return true;
}

static const char* SkipWs(const char* q) {
    while (*q == ' ' || *q == '\t') q++;
    return q;
}

static const char* SkipToken(const char* q) {
    while (*q && *q != ' ' && *q != '\t') q++;
    return q;
}

static bool HexEqCI(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 32);
        if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 32);
        if (ca != cb) return false;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

// Mirrors the checker's "local listeners" parser: a listener row bound to a
// loopback or wildcard address on a port >= 1024. tcp: LISTEN (0A);
// udp: bound rows (07/0A).
static bool IsLoopbackListenerLine(const char* line, bool tcp) {
    if (!line) return false;
    const char* p = SkipWs(line);
    p = SkipToken(p);  // sl
    p = SkipWs(p);
    const char* local = p;
    p = SkipToken(p);
    size_t localLen = (size_t)(p - local);
    p = SkipWs(p);
    p = SkipToken(p);  // remote
    p = SkipWs(p);
    const char* st = p;
    p = SkipToken(p);
    size_t stLen = (size_t)(p - st);
    if (stLen != 2) return false;
    bool listening;
    if (tcp) {
        listening = (st[0] == '0' && (st[1] == 'A' || st[1] == 'a'));
    } else {
        listening = (st[0] == '0' && (st[1] == '7' || st[1] == 'A' || st[1] == 'a'));
    }
    if (!listening) return false;
    const char* colon = nullptr;
    for (size_t i = 0; i < localLen; i++) {
        if (local[i] == ':') colon = local + i;
    }
    if (!colon || colon == local) return false;
    unsigned long port = 0;
    for (const char* c = colon + 1; c < local + localLen; c++) {
        int v;
        if (*c >= '0' && *c <= '9') v = *c - '0';
        else if (*c >= 'A' && *c <= 'F') v = *c - 'A' + 10;
        else if (*c >= 'a' && *c <= 'f') v = *c - 'a' + 10;
        else return false;
        port = port * 16 + (unsigned long)v;
        if (port > 0xFFFF) return false;
    }
    if (port < 1024) return false;
    char host[33];
    size_t hl = (size_t)(colon - local);
    if (hl == 0 || hl > 32) return false;
    memcpy(host, local, hl);
    host[hl] = '\0';
    if (hl == 8) return HexEqCI(host, "00000000") || HexEqCI(host, "0100007F");
    if (hl == 32) {
        return HexEqCI(host, "00000000000000000000000000000000") ||
               HexEqCI(host, "00000000000000000000000001000000");
    }
    return false;
}

static void FilterLines(const std::string& raw, WatchedFile kind, std::string* out) {
    bool tcpLike = (kind == WatchedFile::Tcp || kind == WatchedFile::Udp);
    size_t i = 0;
    while (i < raw.size()) {
        size_t j = raw.find('\n', i);
        j = (j == std::string::npos) ? raw.size() : j + 1;
        std::string line(raw, i, j - i);
        const char* c = line.c_str();
        bool blocked = LineContainsHiddenName(c);
        if (!blocked && tcpLike) blocked = LineContainsProxyPortToken(c);
        if (!blocked && kind == WatchedFile::Tcp) blocked = IsLoopbackListenerLine(c, true);
        if (!blocked && kind == WatchedFile::Udp) blocked = IsLoopbackListenerLine(c, false);
        if (!blocked) out->append(line);
        i = j;
    }
}

// Returns a filtered memfd, -1 for a real error, or -2 to fall through to the
// original function.
static int CreateFilteredFd(const char* path, int flags) {
    WatchedFile kind = ResolveWatchedFile(path);
    if (kind == WatchedFile::None) return -2;
    if ((flags & O_ACCMODE) != O_RDONLY) return -2;
    std::string raw;
    if (!ReadWholeFile(path, &raw)) return -2;
    std::string out;
    FilterLines(raw, kind, &out);
#ifdef SYS_memfd_create
    int mfd = (int)syscall(SYS_memfd_create, "nvd-file",
                           (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0);
#else
    int mfd = -1;
#endif
    if (mfd < 0) return -2;
    ssize_t total = (ssize_t)out.size();
    ssize_t off = 0;
    while (off < total) {
        ssize_t w = syscall(SYS_write, mfd, out.data() + off, (size_t)(total - off));
        if (w < 0) {
            if (errno == EINTR) continue;
            syscall(SYS_close, mfd);
            return -2;
        }
        off += w;
    }
    syscall(SYS_lseek, mfd, 0, SEEK_SET);
    return mfd;
}

// ---------------------------------------------------------------------------
// open / openat / fopen
// ---------------------------------------------------------------------------

int HideOpen(const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    mode_t mode = 0;
#ifdef O_TMPFILE
    if (flags & (O_CREAT | O_TMPFILE)) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    {
        int sfd = -2;
        if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
    }
    int mfd = CreateFilteredFd(path, flags);
    if (mfd >= 0) return mfd;
    return BYTEHOOK_CALL_PREV(HideOpen, path, flags, mode);
}

int HideOpen64(const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    mode_t mode = 0;
#ifdef O_TMPFILE
    if (flags & (O_CREAT | O_TMPFILE)) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    {
        int sfd = -2;
        if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
    }
    int mfd = CreateFilteredFd(path, flags);
    if (mfd >= 0) return mfd;
    return BYTEHOOK_CALL_PREV(HideOpen64, path, flags, mode);
}

int HideOpen2(const char* path, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    {
        int sfd = -2;
        if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
    }
    int mfd = CreateFilteredFd(path, flags);
    if (mfd >= 0) return mfd;
    return BYTEHOOK_CALL_PREV(HideOpen2, path, flags);
}

int HideOpenAt(int dirfd, const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    mode_t mode = 0;
#ifdef O_TMPFILE
    if (flags & (O_CREAT | O_TMPFILE)) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path && path[0] == '/') {
        if (IsHiddenPath(path)) {
            errno = ENOENT;
            return -1;
        }
        {
            int sfd = -2;
            if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
        }
        int mfd = CreateFilteredFd(path, flags);
        if (mfd >= 0) return mfd;
    }
    return BYTEHOOK_CALL_PREV(HideOpenAt, dirfd, path, flags, mode);
}

int HideOpenAt64(int dirfd, const char* path, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    mode_t mode = 0;
#ifdef O_TMPFILE
    if (flags & (O_CREAT | O_TMPFILE)) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path && path[0] == '/') {
        if (IsHiddenPath(path)) {
            errno = ENOENT;
            return -1;
        }
        {
            int sfd = -2;
            if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
        }
        int mfd = CreateFilteredFd(path, flags);
        if (mfd >= 0) return mfd;
    }
    return BYTEHOOK_CALL_PREV(HideOpenAt64, dirfd, path, flags, mode);
}

int HideOpenAt2(int dirfd, const char* path, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (path && path[0] == '/') {
        if (IsHiddenPath(path)) {
            errno = ENOENT;
            return -1;
        }
        {
            int sfd = -2;
            if (HandleSpecialOpen(path, flags, &sfd)) return sfd;
        }
        int mfd = CreateFilteredFd(path, flags);
        if (mfd >= 0) return mfd;
    }
    return BYTEHOOK_CALL_PREV(HideOpenAt2, dirfd, path, flags);
}

FILE* HideFopen(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return nullptr;
    }
    if (mode && mode[0] == 'r' && strchr(mode, '+') == nullptr) {
        {
            int sfd = -2;
            if (HandleSpecialOpen(path, O_RDONLY, &sfd)) {
                if (sfd < 0) return nullptr;
                FILE* f = fdopen(sfd, "r");
                if (f) return f;
                syscall(SYS_close, sfd);
            }
        }
        int mfd = CreateFilteredFd(path, O_RDONLY);
        if (mfd >= 0) {
            FILE* f = fdopen(mfd, "r");
            if (f) return f;
            syscall(SYS_close, mfd);
        }
    }
    return BYTEHOOK_CALL_PREV(HideFopen, path, mode);
}

FILE* HideFopen64(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return nullptr;
    }
    if (mode && mode[0] == 'r' && strchr(mode, '+') == nullptr) {
        {
            int sfd = -2;
            if (HandleSpecialOpen(path, O_RDONLY, &sfd)) {
                if (sfd < 0) return nullptr;
                FILE* f = fdopen(sfd, "r");
                if (f) return f;
                syscall(SYS_close, sfd);
            }
        }
        int mfd = CreateFilteredFd(path, O_RDONLY);
        if (mfd >= 0) {
            FILE* f = fdopen(mfd, "r");
            if (f) return f;
            syscall(SYS_close, mfd);
        }
    }
    return BYTEHOOK_CALL_PREV(HideFopen64, path, mode);
}

// ---------------------------------------------------------------------------
// getdents64: drop VPN-named entries from every directory listing.
// (Stateless: entry names matching VPN interface patterns are simply omitted.)
// ---------------------------------------------------------------------------

struct NvdLinuxDirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

ssize_t HideGetDents64(int fd, void* dirp, size_t count) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t total = BYTEHOOK_CALL_PREV(HideGetDents64, fd, dirp, count);
    if (total <= 0) return total;
    char* base = (char*)dirp;
    char* p = base;
    char* end = base + total;
    char* out = base;
    while (p + sizeof(NvdLinuxDirent64) <= end) {
        auto* d = (NvdLinuxDirent64*)p;
        size_t rl = d->d_reclen;
        if (rl < sizeof(NvdLinuxDirent64) || p + rl > end) break;
        if (!IsHiddenIfaceName(d->d_name)) {
            if (out != p) memmove(out, p, rl);
            out += rl;
        }
        p += rl;
    }
    return (ssize_t)(out - base);
}

// ---------------------------------------------------------------------------
// access / stat
// ---------------------------------------------------------------------------

int HideAccess(const char* path, int mode) {
    BYTEHOOK_STACK_SCOPE();
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideAccess, path, mode);
}

int HideFAccessAt(int dirfd, const char* path, int mode, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideFAccessAt, dirfd, path, mode, flags);
}

int HideStat(const char* path, struct stat* buf) {
    BYTEHOOK_STACK_SCOPE();
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideStat, path, buf);
}

int HideLstat(const char* path, struct stat* buf) {
    BYTEHOOK_STACK_SCOPE();
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideLstat, path, buf);
}

int HideFStatAt(int dirfd, const char* path, struct stat* buf, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideFStatAt, dirfd, path, buf, flags);
}

// ---------------------------------------------------------------------------

void InstallFsHooks() {
    HookLibcSym("open", (void*)HideOpen);
    HookLibcSym("open64", (void*)HideOpen64);
    HookLibcSym("__open_2", (void*)HideOpen2);
    HookLibcSym("openat", (void*)HideOpenAt);
    HookLibcSym("openat64", (void*)HideOpenAt64);
    HookLibcSym("__openat_2", (void*)HideOpenAt2);
    HookLibcSym("fopen", (void*)HideFopen);
    HookLibcSym("fopen64", (void*)HideFopen64);
    HookLibcSym("getdents64", (void*)HideGetDents64);
    HookLibcSym("access", (void*)HideAccess);
    HookLibcSym("faccessat", (void*)HideFAccessAt);
    HookLibcSym("stat", (void*)HideStat);
    HookLibcSym("lstat", (void*)HideLstat);
    HookLibcSym("fstatat", (void*)HideFStatAt);
}

}  // namespace nvd
