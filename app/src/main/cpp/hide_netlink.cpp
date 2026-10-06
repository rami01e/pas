// Netlink response filtering.
//
// Detector probes that enumerate interfaces, addresses, routes, policy rules
// and sockets via NETLINK sockets bypass every libc *file* hook. We track
// NETLINK sockets created by the process and post-process their
// recv()/recvfrom()/recvmsg() results, dropping dump messages that reference
// hidden (VPN) interfaces / VPN policy tables, or that expose a loopback
// SOCKS5/HTTP proxy on well-known ports (127.0.0.1:1080 etc).
//
// Two netlink families are covered:
//   NETLINK_ROUTE      - RTM_NEWLINK / RTM_NEWADDR / RTM_NEWROUTE / RTM_NEWRULE
//   NETLINK_SOCK_DIAG  - SOCK_DIAG_BY_FAMILY (inet_diag_msg entries)
//
// v2.3.10 fix: the "not tracked" sentinel was 0, which collides with
// NETLINK_ROUTE (also 0). Every route/link/rule filter was short-circuiting
// out of FilterNetlinkBuffer and letting the kernel's response pass through
// unfiltered. The sentinel is now -1, and the checks were updated to match.
// (SOCK_DIAG = 4 was never affected, which is why the local-proxy filter
// worked all along.)

#include "pas.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/inet_diag.h>

#include "bytehook.h"

namespace pas {

#ifndef NETLINK_ROUTE
#define NETLINK_ROUTE 0
#endif

#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG 4
#endif

#ifndef SOCK_DIAG_BY_FAMILY
#define SOCK_DIAG_BY_FAMILY 20
#endif

// Sentinel for "fd not tracked" - must be distinct from every valid
// netlink protocol number, and NETLINK_ROUTE is 0.
static const int kProtoUntracked = -1;

// ---------------------------------------------------------------------------
// netlink fd tracking (small fixed table, no allocations)
// ---------------------------------------------------------------------------

static const int kMaxTracked = 32;

struct TrackedFd {
    int fd;
    int protocol;
};

static TrackedFd g_tracked[kMaxTracked];
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static bool g_inited = false;

static void EnsureInitLocked() {
    if (!g_inited) {
        for (int i = 0; i < kMaxTracked; i++) {
            g_tracked[i].fd = -1;
            g_tracked[i].protocol = kProtoUntracked;
        }
        g_inited = true;
    }
}

static void TrackFdImpl(int fd, int protocol) {
    pthread_mutex_lock(&g_mtx);
    EnsureInitLocked();
    for (int i = 0; i < kMaxTracked; i++) {
        if (g_tracked[i].fd == fd) {
            g_tracked[i].protocol = protocol;
            pthread_mutex_unlock(&g_mtx);
            return;
        }
    }
    for (int i = 0; i < kMaxTracked; i++) {
        if (g_tracked[i].fd == -1) {
            g_tracked[i].fd = fd;
            g_tracked[i].protocol = protocol;
            pthread_mutex_unlock(&g_mtx);
            return;
        }
    }
    g_tracked[0].fd = fd;
    g_tracked[0].protocol = protocol;
    pthread_mutex_unlock(&g_mtx);
}

static void UntrackFd(int fd) {
    pthread_mutex_lock(&g_mtx);
    EnsureInitLocked();
    for (int i = 0; i < kMaxTracked; i++) {
        if (g_tracked[i].fd == fd) {
            g_tracked[i].fd = -1;
            g_tracked[i].protocol = kProtoUntracked;
            break;
        }
    }
    pthread_mutex_unlock(&g_mtx);
}

// Returns the netlink protocol for a tracked fd, or kProtoUntracked (-1).
static int TrackedProtocol(int fd) {
    pthread_mutex_lock(&g_mtx);
    EnsureInitLocked();
    int proto = kProtoUntracked;
    for (int i = 0; i < kMaxTracked; i++) {
        if (g_tracked[i].fd == fd) {
            proto = g_tracked[i].protocol;
            break;
        }
    }
    pthread_mutex_unlock(&g_mtx);
    return proto;
}

// Public entry point for the raw-syscall layer.
void TrackNetlinkFd(int fd, int protocol) {
    if (fd < 0) return;
    if (protocol != NETLINK_ROUTE && protocol != NETLINK_SOCK_DIAG) return;
    TrackFdImpl(fd, protocol);
}

// ---------------------------------------------------------------------------
// learned hidden interface indices
// ---------------------------------------------------------------------------

static const int kMaxLearnedIndices = 16;
static unsigned int g_learned_idx[kMaxLearnedIndices];
static int g_learned_count = 0;
static pthread_mutex_t g_learned_mtx = PTHREAD_MUTEX_INITIALIZER;

static void LearnHiddenIndex(unsigned int idx) {
    if (idx == 0) return;
    pthread_mutex_lock(&g_learned_mtx);
    for (int i = 0; i < g_learned_count; i++) {
        if (g_learned_idx[i] == idx) {
            pthread_mutex_unlock(&g_learned_mtx);
            return;
        }
    }
    if (g_learned_count < kMaxLearnedIndices) {
        g_learned_idx[g_learned_count++] = idx;
        Log("native: netlink: learned hidden ifindex=%u", idx);
    }
    pthread_mutex_unlock(&g_learned_mtx);
}

static bool IsLearnedHiddenIndex(unsigned int idx) {
    if (idx == 0) return false;
    pthread_mutex_lock(&g_learned_mtx);
    bool found = false;
    for (int i = 0; i < g_learned_count; i++) {
        if (g_learned_idx[i] == idx) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_learned_mtx);
    return found;
}

static bool IsAnyHiddenIndex(unsigned int idx) {
    return IsHiddenIndex(idx) || IsLearnedHiddenIndex(idx);
}

// ---------------------------------------------------------------------------
// NETLINK_ROUTE message predicates
// ---------------------------------------------------------------------------

struct AttrSink {
    bool hasTable = false;
    unsigned int table = 0;
    bool hasOif = false;
    int oif = 0;
};

static void WalkAttrs(const char* base, int len, AttrSink* sink) {
    const struct rtattr* a = (const struct rtattr*)base;
    while (len >= (int)sizeof(struct rtattr)) {
        if (a->rta_len < (int)sizeof(struct rtattr) || a->rta_len > len) break;
        if (a->rta_type == RTA_TABLE && RTA_PAYLOAD(a) >= 4) {
            unsigned int v;
            memcpy(&v, RTA_DATA(a), sizeof(v));
            sink->table = v;
            sink->hasTable = true;
        } else if (a->rta_type == RTA_OIF && RTA_PAYLOAD(a) >= 4) {
            int v;
            memcpy(&v, RTA_DATA(a), sizeof(v));
            sink->oif = v;
            sink->hasOif = true;
        }
        int alen = RTA_ALIGN(a->rta_len);
        if (alen <= 0) break;
        len -= alen;
        a = (const struct rtattr*)((const char*)a + alen);
    }
}

static bool NewlinkHidden(const struct nlmsghdr* nh) {
    const struct ifinfomsg* ifi = (const struct ifinfomsg*)NLMSG_DATA(nh);
    const unsigned int idx = (unsigned int)ifi->ifi_index;
    int len = (int)(nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)));
    if (len > 0) {
        const struct rtattr* a =
            (const struct rtattr*)((const char*)ifi + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
        while (len >= (int)sizeof(struct rtattr)) {
            if (a->rta_len < (int)sizeof(struct rtattr) || a->rta_len > len) break;
            if (a->rta_type == IFLA_IFNAME) {
                const char* nm = (const char*)RTA_DATA(a);
                size_t max = (size_t)(a->rta_len - sizeof(struct rtattr));
                char name[64];
                size_t n = 0;
                while (n < max && n < sizeof(name) - 1 && nm[n]) {
                    name[n] = nm[n];
                    n++;
                }
                name[n] = '\0';
                if (n > 0 && IsHiddenIfaceName(name)) {
                    LearnHiddenIndex(idx);
                    return true;
                }
                return false;
            }
            int alen = RTA_ALIGN(a->rta_len);
            if (alen <= 0) break;
            len -= alen;
            a = (const struct rtattr*)((const char*)a + alen);
        }
    }
    return IsAnyHiddenIndex(idx);
}

static bool NewaddrHidden(const struct nlmsghdr* nh) {
    const struct ifaddrmsg* ifa = (const struct ifaddrmsg*)NLMSG_DATA(nh);
    return IsAnyHiddenIndex((unsigned int)ifa->ifa_index);
}

static bool NewrouteHidden(const struct nlmsghdr* nh) {
    const struct rtmsg* rtm = (const struct rtmsg*)NLMSG_DATA(nh);
    AttrSink sink;
    int len = (int)(nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg)));
    if (len > 0) WalkAttrs((const char*)rtm + NLMSG_ALIGN(sizeof(struct rtmsg)), len, &sink);
    unsigned int table = rtm->rtm_table;
    if (sink.hasTable) table = sink.table;
    if (table >= 100 && table <= 110) return true;
    if (sink.hasOif && sink.oif > 0 && IsAnyHiddenIndex((unsigned int)sink.oif)) return true;
    return false;
}

static bool NewruleHidden(const struct nlmsghdr* nh) {
    const struct rtmsg* rtm = (const struct rtmsg*)NLMSG_DATA(nh);
    AttrSink sink;
    int len = (int)(nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg)));
    if (len > 0) WalkAttrs((const char*)rtm + NLMSG_ALIGN(sizeof(struct rtmsg)), len, &sink);
    unsigned int table = sink.hasTable ? sink.table : rtm->rtm_table;
    if (table >= 100 && table <= 110) return true;
    if (sink.hasOif && sink.oif > 0 && IsAnyHiddenIndex((unsigned int)sink.oif)) return true;
    return false;
}

// ---------------------------------------------------------------------------
// NETLINK_SOCK_DIAG message predicate
// ---------------------------------------------------------------------------

static const unsigned short kProxyPorts[] = {
    1080, 1081, 1087, 1088, 3128, 4444,
    7890, 7891, 7892, 7893, 7894, 7895, 7896, 7897,
    8118, 8123, 8888, 8889, 9050, 9051, 9090,
    10808, 10809, 10810,
};

static bool IsProxyPort(unsigned short port) {
    for (size_t i = 0; i < sizeof(kProxyPorts) / sizeof(kProxyPorts[0]); i++) {
        if (port == kProxyPorts[i]) return true;
    }
    return false;
}

static bool IsLoopbackV4(const unsigned char* a) {
    return a[0] == 127;
}

static bool IsLoopbackV6(const unsigned char* a) {
    static const unsigned char kLoop6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (memcmp(a, kLoop6, 16) == 0) return true;
    static const unsigned char kMapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    if (memcmp(a, kMapped, 12) == 0 && a[12] == 127) return true;
    return false;
}

static bool InetDiagHidden(const struct nlmsghdr* nh) {
    if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg))) return false;
    const struct inet_diag_msg* d = (const struct inet_diag_msg*)NLMSG_DATA(nh);
    const unsigned short sport = ntohs(d->id.idiag_sport);
    const unsigned short dport = ntohs(d->id.idiag_dport);
    if (d->idiag_family == AF_INET) {
        const unsigned char* src = (const unsigned char*)&d->id.idiag_src[0];
        const unsigned char* dst = (const unsigned char*)&d->id.idiag_dst[0];
        if (IsProxyPort(sport) && IsLoopbackV4(src)) return true;
        if (IsProxyPort(dport) && IsLoopbackV4(dst)) return true;
    } else if (d->idiag_family == AF_INET6) {
        const unsigned char* src = (const unsigned char*)&d->id.idiag_src[0];
        const unsigned char* dst = (const unsigned char*)&d->id.idiag_dst[0];
        if (IsProxyPort(sport) && IsLoopbackV6(src)) return true;
        if (IsProxyPort(dport) && IsLoopbackV6(dst)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// buffer filtering (in place, message-wise compaction)
// ---------------------------------------------------------------------------

static ssize_t FilterNetlinkBuffer(void* buf, ssize_t len, int protocol) {
    if (len <= 0 || protocol < 0) return len;
    char* base = (char*)buf;
    size_t total = (size_t)len;
    size_t off = 0;
    size_t out = 0;
    while (off + sizeof(struct nlmsghdr) <= total) {
        struct nlmsghdr* nh = (struct nlmsghdr*)(base + off);
        if (nh->nlmsg_len < sizeof(struct nlmsghdr) || nh->nlmsg_len > total - off) break;
        size_t aligned = NLMSG_ALIGN(nh->nlmsg_len);
        if (aligned > total - off) aligned = total - off;
        bool drop = false;
        if (protocol == NETLINK_ROUTE) {
            switch (nh->nlmsg_type) {
                case RTM_NEWLINK: drop = NewlinkHidden(nh); break;
                case RTM_NEWADDR: drop = NewaddrHidden(nh); break;
                case RTM_NEWROUTE: drop = NewrouteHidden(nh); break;
                case RTM_NEWRULE: drop = NewruleHidden(nh); break;
                default: break;
            }
        } else if (protocol == NETLINK_SOCK_DIAG) {
            if (nh->nlmsg_type == SOCK_DIAG_BY_FAMILY) {
                drop = InetDiagHidden(nh);
            }
        }
        if (!drop) {
            if (out != off) memmove(base + out, base + off, aligned);
            out += aligned;
        }
        off += aligned;
    }
    if (off < total) {
        size_t trail = total - off;
        if (out != off) memmove(base + out, base + off, trail);
        out += trail;
    }
    return (ssize_t)out;
}

// Public entry point for the raw-syscall layer.
ssize_t FilterNetlinkRecv(int fd, void* buf, ssize_t len) {
    if (len <= 0 || buf == nullptr) return len;
    int proto = TrackedProtocol(fd);
    if (proto < 0) return len;
    return FilterNetlinkBuffer(buf, len, proto);
}

// ---------------------------------------------------------------------------
// hooks
// ---------------------------------------------------------------------------

int HideSocket(int domain, int type, int protocol) {
    BYTEHOOK_STACK_SCOPE();
    int fd = BYTEHOOK_CALL_PREV(HideSocket, domain, type, protocol);
    if (fd >= 0 && domain == AF_NETLINK &&
        (protocol == NETLINK_ROUTE || protocol == NETLINK_SOCK_DIAG)) {
        TrackFdImpl(fd, protocol);
    }
    return fd;
}

int HideClose(int fd) {
    BYTEHOOK_STACK_SCOPE();
    UntrackFd(fd);
    return BYTEHOOK_CALL_PREV(HideClose, fd);
}

ssize_t HideRecv(int fd, void* buf, size_t len, int flags) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t n = BYTEHOOK_CALL_PREV(HideRecv, fd, buf, len, flags);
    if (n > 0) {
        int proto = TrackedProtocol(fd);
        if (proto >= 0) n = FilterNetlinkBuffer(buf, n, proto);
    }
    return n;
}

ssize_t HideRecvFrom(int fd, void* buf, size_t len, int flags, struct sockaddr* addr,
                     socklen_t* addrlen) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t n = BYTEHOOK_CALL_PREV(HideRecvFrom, fd, buf, len, flags, addr, addrlen);
    if (n > 0) {
        int proto = TrackedProtocol(fd);
        if (proto >= 0) n = FilterNetlinkBuffer(buf, n, proto);
    }
    return n;
}

ssize_t HideRecvMsg(int fd, struct msghdr* msg, int flags) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t n = BYTEHOOK_CALL_PREV(HideRecvMsg, fd, msg, flags);
    if (n > 0 && msg && msg->msg_iovlen == 1 && msg->msg_iov) {
        int proto = TrackedProtocol(fd);
        if (proto >= 0) n = FilterNetlinkBuffer(msg->msg_iov[0].iov_base, n, proto);
    }
    return n;
}

void InstallNetlinkHooks() {
    HookLibcSym("socket", (void*)HideSocket);
    HookLibcSym("close", (void*)HideClose);
    HookLibcSym("recv", (void*)HideRecv);
    HookLibcSym("recvfrom", (void*)HideRecvFrom);
    HookLibcSym("recvmsg", (void*)HideRecvMsg);
}

}  // namespace pas