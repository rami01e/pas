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
// ---------------------------------------------------------------------------

static bool PathIs(const char* path, const char* target) {
    return path && strcmp(path, target) == 0;
}

static bool IsWatchedReadFile(const char* path, bool* net) {
    if (!path) return false;
    *net = false;
    if (PathIs(path, "/proc/net/tcp") || PathIs(path, "/proc/net/tcp6") ||
        PathIs(path, "/proc/net/udp") || PathIs(path, "/proc/net/udp6")) {
        *net = true;
        return true;
    }
    if (PathIs(path, "/proc/net/dev") || PathIs(path, "/proc/net/route") ||
        PathIs(path, "/proc/net/if_inet6") || PathIs(path, "/proc/net/ipv6_route") ||
        PathIs(path, "/proc/net/arp")) {
        return true;
    }
    return false;
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

static void FilterLines(const std::string& raw, bool net, std::string* out) {
    size_t i = 0;
    while (i < raw.size()) {
        size_t j = raw.find('\n', i);
        j = (j == std::string::npos) ? raw.size() : j + 1;
        std::string line(raw, i, j - i);
        bool blocked = LineContainsHiddenName(line.c_str()) ||
                       (net && LineContainsProxyPortToken(line.c_str()));
        if (!blocked) out->append(line);
        i = j;
    }
}

// Returns a filtered memfd, -1 for a real error, or -2 to fall through to the
// original function.
static int CreateFilteredFd(const char* path, int flags) {
    bool net = false;
    if (!IsWatchedReadFile(path, &net)) return -2;
    if ((flags & O_ACCMODE) != O_RDONLY) return -2;
    std::string raw;
    if (!ReadWholeFile(path, &raw)) return -2;
    std::string out;
    FilterLines(raw, net, &out);
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
