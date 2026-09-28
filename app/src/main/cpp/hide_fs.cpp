#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "nvd.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mutex>
#include <string>
#include <unordered_map>

#include "bytehook.h"

namespace nvd {

// ---------------------------------------------------------------------------
// fd / FILE* tracking
// ---------------------------------------------------------------------------

enum class FdKind { None = 0, ReadGen, ReadNet, DirList };

static std::mutex g_fd_mtx;
static std::unordered_map<int, FdKind> g_fd_kinds;
static std::unordered_map<int, std::string> g_read_cache;
static std::unordered_map<int, size_t> g_read_pos;
static std::unordered_map<FILE*, FdKind> g_file_kinds;

static FdKind ClassifyReadFile(const char* path) {
    if (!path) return FdKind::None;
    char buf[256];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(buf)) return FdKind::None;
    memcpy(buf, path, n + 1);
    while (n > 1 && buf[n - 1] == '/') buf[--n] = '\0';
    static const struct {
        const char* p;
        FdKind k;
    } kFiles[] = {
        {"/proc/net/dev", FdKind::ReadGen},
        {"/proc/net/if_inet6", FdKind::ReadGen},
        {"/proc/net/ipv6_route", FdKind::ReadGen},
        {"/proc/net/route", FdKind::ReadGen},
        {"/proc/net/arp", FdKind::ReadGen},
        {"/proc/net/tcp", FdKind::ReadNet},
        {"/proc/net/tcp6", FdKind::ReadNet},
        {"/proc/net/udp", FdKind::ReadNet},
        {"/proc/net/udp6", FdKind::ReadNet},
    };
    for (const auto& e : kFiles) {
        if (strcmp(buf, e.p) == 0) return e.k;
    }
    return FdKind::None;
}

static bool IsDirWatch(const char* path) {
    if (!path) return false;
    char buf[256];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(buf)) return false;
    memcpy(buf, path, n + 1);
    while (n > 1 && buf[n - 1] == '/') buf[--n] = '\0';
    static const char* kDirs[] = {
        "/sys/class/net",
        "/sys/devices/virtual/net",
        "/proc/sys/net/ipv4/conf",
        "/proc/sys/net/ipv6/conf",
        "/proc/sys/net/ipv4/neigh",
        "/proc/sys/net/ipv6/neigh",
    };
    for (const char* d : kDirs) {
        if (strcmp(buf, d) == 0) return true;
    }
    return false;
}

static void TrackFd(int fd, const char* path) {
    if (fd < 0) return;
    FdKind k = ClassifyReadFile(path);
    if (k == FdKind::None && IsDirWatch(path)) k = FdKind::DirList;
    if (k == FdKind::None) return;
    std::lock_guard<std::mutex> lk(g_fd_mtx);
    g_fd_kinds[fd] = k;
    g_read_cache.erase(fd);
    g_read_pos.erase(fd);
}

static void UntrackFd(int fd) {
    std::lock_guard<std::mutex> lk(g_fd_mtx);
    g_fd_kinds.erase(fd);
    g_read_cache.erase(fd);
    g_read_pos.erase(fd);
}

static FdKind KindOfFd(int fd) {
    if (g_fd_kinds.empty()) return FdKind::None;
    std::lock_guard<std::mutex> lk(g_fd_mtx);
    auto it = g_fd_kinds.find(fd);
    return it == g_fd_kinds.end() ? FdKind::None : it->second;
}

static FdKind KindOfFile(FILE* f) {
    if (g_file_kinds.empty() || !f) return FdKind::None;
    std::lock_guard<std::mutex> lk(g_fd_mtx);
    auto it = g_file_kinds.find(f);
    return it == g_file_kinds.end() ? FdKind::None : it->second;
}

static bool LineBlocked(const char* line, FdKind kind) {
    if (!line) return false;
    if (kind == FdKind::ReadNet && LineContainsProxyPortToken(line)) return true;
    return LineContainsHiddenName(line);
}

static void CopyKind(int from, int to) {
    if (to < 0) return;
    std::lock_guard<std::mutex> lk(g_fd_mtx);
    auto it = g_fd_kinds.find(from);
    if (it == g_fd_kinds.end()) {
        g_fd_kinds.erase(to);
    } else {
        g_fd_kinds[to] = it->second;
    }
    g_read_cache.erase(to);
    g_read_pos.erase(to);
}

// ---------------------------------------------------------------------------
// filtered read cache
// ---------------------------------------------------------------------------

static ssize_t (*RealPread64Fn())(int, void*, size_t, off64_t) {
    static ssize_t (*fn)(int, void*, size_t, off64_t) = nullptr;
    if (!fn) fn = (ssize_t (*)(int, void*, size_t, off64_t))RealSym("pread64");
    return fn;
}

static bool BuildCache(int fd, FdKind kind) {
    auto rp = RealPread64Fn();
    if (!rp) return false;
    std::string raw;
    raw.reserve(8192);
    char buf[16384];
    off64_t off = 0;
    for (;;) {
        ssize_t n = rp(fd, buf, sizeof(buf), off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) break;
        raw.append(buf, (size_t)n);
        off += n;
        if (raw.size() > (4u << 20)) break;
    }
    std::string out;
    size_t i = 0;
    while (i < raw.size()) {
        size_t j = raw.find('\n', i);
        j = (j == std::string::npos) ? raw.size() : j + 1;
        std::string line(raw, i, j - i);
        if (!LineBlocked(line.c_str(), kind)) out.append(line);
        i = j;
    }
    std::lock_guard<std::mutex> lk(g_fd_mtx);
    g_read_cache[fd] = std::move(out);
    if (g_read_pos.find(fd) == g_read_pos.end()) g_read_pos[fd] = 0;
    return true;
}

static bool CacheExists(int fd) {
    std::lock_guard<std::mutex> lk(g_fd_mtx);
    return g_read_cache.find(fd) != g_read_cache.end();
}

ssize_t HideRead(int fd, void* buf, size_t count) {
    BYTEHOOK_STACK_SCOPE();
    FdKind kind = KindOfFd(fd);
    if (kind != FdKind::ReadGen && kind != FdKind::ReadNet) {
        return BYTEHOOK_CALL_PREV(HideRead, fd, buf, count);
    }
    if (!CacheExists(fd)) BuildCache(fd, kind);
    bool served = false;
    ssize_t out = -1;
    {
        std::lock_guard<std::mutex> lk(g_fd_mtx);
        auto it = g_read_cache.find(fd);
        if (it != g_read_cache.end()) {
            size_t pos = g_read_pos[fd];
            if (pos >= it->second.size()) {
                out = 0;
            } else {
                size_t n = count < (it->second.size() - pos) ? count : (it->second.size() - pos);
                memcpy(buf, it->second.data() + pos, n);
                g_read_pos[fd] = pos + n;
                out = (ssize_t)n;
            }
            served = true;
        }
    }
    if (served) return out;
    return BYTEHOOK_CALL_PREV(HideRead, fd, buf, count);
}

ssize_t HidePread64(int fd, void* buf, size_t count, off64_t offset) {
    BYTEHOOK_STACK_SCOPE();
    FdKind kind = KindOfFd(fd);
    if (kind != FdKind::ReadGen && kind != FdKind::ReadNet) {
        return BYTEHOOK_CALL_PREV(HidePread64, fd, buf, count, offset);
    }
    if (!CacheExists(fd)) BuildCache(fd, kind);
    bool served = false;
    ssize_t out = -1;
    {
        std::lock_guard<std::mutex> lk(g_fd_mtx);
        auto it = g_read_cache.find(fd);
        if (it != g_read_cache.end()) {
            if ((size_t)offset >= it->second.size()) {
                out = 0;
            } else {
                size_t avail = it->second.size() - (size_t)offset;
                size_t n = count < avail ? count : avail;
                memcpy(buf, it->second.data() + offset, n);
                out = (ssize_t)n;
            }
            served = true;
        }
    }
    if (served) return out;
    return BYTEHOOK_CALL_PREV(HidePread64, fd, buf, count, offset);
}

ssize_t HidePread(int fd, void* buf, size_t count, off_t offset) {
    BYTEHOOK_STACK_SCOPE();
    FdKind kind = KindOfFd(fd);
    if (kind != FdKind::ReadGen && kind != FdKind::ReadNet) {
        return BYTEHOOK_CALL_PREV(HidePread, fd, buf, count, offset);
    }
    if (!CacheExists(fd)) BuildCache(fd, kind);
    bool served = false;
    ssize_t out = -1;
    {
        std::lock_guard<std::mutex> lk(g_fd_mtx);
        auto it = g_read_cache.find(fd);
        if (it != g_read_cache.end()) {
            if ((size_t)offset >= it->second.size()) {
                out = 0;
            } else {
                size_t avail = it->second.size() - (size_t)offset;
                size_t n = count < avail ? count : avail;
                memcpy(buf, it->second.data() + offset, n);
                out = (ssize_t)n;
            }
            served = true;
        }
    }
    if (served) return out;
    return BYTEHOOK_CALL_PREV(HidePread, fd, buf, count, offset);
}

off_t HideLseek(int fd, off_t offset, int whence) {
    BYTEHOOK_STACK_SCOPE();
    off_t r = BYTEHOOK_CALL_PREV(HideLseek, fd, offset, whence);
    if (r >= 0 && KindOfFd(fd) != FdKind::None) {
        std::lock_guard<std::mutex> lk(g_fd_mtx);
        g_read_pos[fd] = (size_t)r;
    }
    return r;
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
    int fd = BYTEHOOK_CALL_PREV(HideOpen, path, flags, mode);
    if (fd >= 0) TrackFd(fd, path);
    return fd;
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
    int fd = BYTEHOOK_CALL_PREV(HideOpen64, path, flags, mode);
    if (fd >= 0) TrackFd(fd, path);
    return fd;
}

int HideOpen2(const char* path, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    int fd = BYTEHOOK_CALL_PREV(HideOpen2, path, flags);
    if (fd >= 0) TrackFd(fd, path);
    return fd;
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
    if (path && path[0] == '/' && IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    int fd = BYTEHOOK_CALL_PREV(HideOpenAt, dirfd, path, flags, mode);
    if (fd >= 0 && path && path[0] == '/') TrackFd(fd, path);
    return fd;
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
    if (path && path[0] == '/' && IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    int fd = BYTEHOOK_CALL_PREV(HideOpenAt64, dirfd, path, flags, mode);
    if (fd >= 0 && path && path[0] == '/') TrackFd(fd, path);
    return fd;
}

int HideOpenAt2(int dirfd, const char* path, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (path && path[0] == '/' && IsHiddenPath(path)) {
        errno = ENOENT;
        return -1;
    }
    int fd = BYTEHOOK_CALL_PREV(HideOpenAt2, dirfd, path, flags);
    if (fd >= 0 && path && path[0] == '/') TrackFd(fd, path);
    return fd;
}

FILE* HideFopen(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return nullptr;
    }
    FILE* f = BYTEHOOK_CALL_PREV(HideFopen, path, mode);
    if (f) {
        FdKind k = ClassifyReadFile(path);
        if (k != FdKind::None) {
            std::lock_guard<std::mutex> lk(g_fd_mtx);
            g_file_kinds[f] = k;
        }
    }
    return f;
}

FILE* HideFopen64(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    if (IsHiddenPath(path)) {
        errno = ENOENT;
        return nullptr;
    }
    FILE* f = BYTEHOOK_CALL_PREV(HideFopen64, path, mode);
    if (f) {
        FdKind k = ClassifyReadFile(path);
        if (k != FdKind::None) {
            std::lock_guard<std::mutex> lk(g_fd_mtx);
            g_file_kinds[f] = k;
        }
    }
    return f;
}

int HideFClose(FILE* f) {
    BYTEHOOK_STACK_SCOPE();
    if (!g_file_kinds.empty() && f) {
        std::lock_guard<std::mutex> lk(g_fd_mtx);
        g_file_kinds.erase(f);
    }
    return BYTEHOOK_CALL_PREV(HideFClose, f);
}

// ---------------------------------------------------------------------------
// fgets / getline
// ---------------------------------------------------------------------------

char* HideFgets(char* s, int size, FILE* stream) {
    BYTEHOOK_STACK_SCOPE();
    FdKind kind = KindOfFile(stream);
    if (kind == FdKind::None) return BYTEHOOK_CALL_PREV(HideFgets, s, size, stream);
    for (int i = 0; i < 4096; i++) {
        char* r = BYTEHOOK_CALL_PREV(HideFgets, s, size, stream);
        if (!r) return nullptr;
        if (!LineBlocked(r, kind)) return r;
    }
    return nullptr;
}

char* HideFgetsUnlocked(char* s, int size, FILE* stream) {
    BYTEHOOK_STACK_SCOPE();
    FdKind kind = KindOfFile(stream);
    if (kind == FdKind::None) return BYTEHOOK_CALL_PREV(HideFgetsUnlocked, s, size, stream);
    for (int i = 0; i < 4096; i++) {
        char* r = BYTEHOOK_CALL_PREV(HideFgetsUnlocked, s, size, stream);
        if (!r) return nullptr;
        if (!LineBlocked(r, kind)) return r;
    }
    return nullptr;
}

ssize_t HideGetline(char** lineptr, size_t* n, FILE* stream) {
    BYTEHOOK_STACK_SCOPE();
    FdKind kind = KindOfFile(stream);
    if (kind == FdKind::None) return BYTEHOOK_CALL_PREV(HideGetline, lineptr, n, stream);
    for (int i = 0; i < 4096; i++) {
        ssize_t r = BYTEHOOK_CALL_PREV(HideGetline, lineptr, n, stream);
        if (r < 0) return r;
        if (!LineBlocked(*lineptr, kind)) return r;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// close / dup
// ---------------------------------------------------------------------------

int HideClose(int fd) {
    BYTEHOOK_STACK_SCOPE();
    if (!g_fd_kinds.empty()) UntrackFd(fd);
    return BYTEHOOK_CALL_PREV(HideClose, fd);
}

int HideDup(int oldfd) {
    BYTEHOOK_STACK_SCOPE();
    int nf = BYTEHOOK_CALL_PREV(HideDup, oldfd);
    CopyKind(oldfd, nf);
    return nf;
}

int HideDup2(int oldfd, int newfd) {
    BYTEHOOK_STACK_SCOPE();
    int r = BYTEHOOK_CALL_PREV(HideDup2, oldfd, newfd);
    CopyKind(oldfd, r);
    return r;
}

int HideDup3(int oldfd, int newfd, int flags) {
    BYTEHOOK_STACK_SCOPE();
    int r = BYTEHOOK_CALL_PREV(HideDup3, oldfd, newfd, flags);
    CopyKind(oldfd, r);
    return r;
}

// ---------------------------------------------------------------------------
// getdents64
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
    if (KindOfFd(fd) != FdKind::DirList) return total;
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
    HookLibcSym("fclose", (void*)HideFClose);
    HookLibcSym("fgets", (void*)HideFgets);
    HookLibcSym("fgets_unlocked", (void*)HideFgetsUnlocked);
    HookLibcSym("getline", (void*)HideGetline);
    HookLibcSym("read", (void*)HideRead);
    HookLibcSym("pread", (void*)HidePread);
    HookLibcSym("pread64", (void*)HidePread64);
    HookLibcSym("lseek", (void*)HideLseek);
    HookLibcSym("close", (void*)HideClose);
    HookLibcSym("dup", (void*)HideDup);
    HookLibcSym("dup2", (void*)HideDup2);
    HookLibcSym("dup3", (void*)HideDup3);
    HookLibcSym("getdents64", (void*)HideGetDents64);
    HookLibcSym("access", (void*)HideAccess);
    HookLibcSym("faccessat", (void*)HideFAccessAt);
    HookLibcSym("stat", (void*)HideStat);
    HookLibcSym("lstat", (void*)HideLstat);
    HookLibcSym("fstatat", (void*)HideFStatAt);
}

}  // namespace nvd
