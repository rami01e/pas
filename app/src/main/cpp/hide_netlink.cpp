// Netlink response filtering.
//
// Detector probes enumerate interfaces, addresses, routes and policy rules
// via NETLINK_ROUTE sockets, which bypasses every libc *file* hook. We track
// NETLINK_ROUTE sockets created by the process and post-process their
// recv()/recvfrom()/recvmsg() results, dropping dump messages that reference
// hidden (VPN) interfaces or VPN policy tables so the netlink view matches
// every other hooked path (getifaddrs, /proc/net/*, sysfs, if_indextoname).

#include "nvd.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>

#include "bytehook.h"

namespace nvd {

#ifndef NETLINK_ROUTE
#define NETLINK_ROUTE 0
#endif

// ---------------------------------------------------------------------------
// NETLINK_ROUTE fd tracking (small fixed table, no allocations)
// ---------------------------------------------------------------------------

static const int kMaxTracked = 32;
static int g_tracked[kMaxTracked];
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static bool g_inited = false;

static void EnsureInitLocked() {
    if (!g_inited) {
        for (int i = 0; i < kMaxTracked; i++) g_tracked[i] = -1;
        g_inited = true;
    }
}

static void TrackFd(int fd) {
    pthread_mutex_lock(&g_mtx);
    EnsureInitLocked();
    for (int i = 0; i < kMaxTracked; i++) {
        if (g_tracked[i] == fd) {
            pthread_mutex_unlock(&g_mtx);
            return;
        }
    }
    for (int i = 0; i < kMaxTracked; i++) {
        if (g_tracked[i] == -1) {
            g_tracked[i] = fd;
            pthread_mutex_unlock(&g_mtx);
            return;
        }
    }
    g_tracked[0] = fd;  // table full: replace slot 0 (extremely rare)
    pthread_mutex_unlock(&g_mtx);
}

static void UntrackFd(int fd) {
    pthread_mutex_lock(&g_mtx);
    EnsureInitLocked();
    for (int i = 0; i < kMaxTracked; i++) {
        if (g_tracked[i] == fd) {
            g_tracked[i] = -1;
            break;
        }
    }
    pthread_mutex_unlock(&g_mtx);
}

static bool IsTracked(int fd) {
    pthread_mutex_lock(&g_mtx);
    EnsureInitLocked();
    bool found = false;
    for (int i = 0; i < kMaxTracked; i++) {
        if (g_tracked[i] == fd) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_mtx);
    return found;
}

// ---------------------------------------------------------------------------
// message predicates
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
                return n > 0 && IsHiddenIfaceName(name);
            }
            int alen = RTA_ALIGN(a->rta_len);
            if (alen <= 0) break;
            len -= alen;
            a = (const struct rtattr*)((const char*)a + alen);
        }
    }
    return IsHiddenIndex((unsigned int)ifi->ifi_index);
}

static bool NewaddrHidden(const struct nlmsghdr* nh) {
    const struct ifaddrmsg* ifa = (const struct ifaddrmsg*)NLMSG_DATA(nh);
    return IsHiddenIndex((unsigned int)ifa->ifa_index);
}

static bool NewrouteHidden(const struct nlmsghdr* nh) {
    const struct rtmsg* rtm = (const struct rtmsg*)NLMSG_DATA(nh);
    AttrSink sink;
    int len = (int)(nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg)));
    if (len > 0) WalkAttrs((const char*)rtm + NLMSG_ALIGN(sizeof(struct rtmsg)), len, &sink);
    if (sink.hasOif && sink.oif > 0 && IsHiddenIndex((unsigned int)sink.oif)) return true;
    return false;
}

static bool NewruleHidden(const struct nlmsghdr* nh) {
    const struct rtmsg* rtm = (const struct rtmsg*)NLMSG_DATA(nh);
    AttrSink sink;
    int len = (int)(nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg)));
    if (len > 0) WalkAttrs((const char*)rtm + NLMSG_ALIGN(sizeof(struct rtmsg)), len, &sink);
    unsigned int table = sink.hasTable ? sink.table : rtm->rtm_table;
    // VPN policy tables: wireguard-style 100..110 range (also catches the
    // per-UID tables detectors probe for).
    if (table >= 100 && table <= 110) return true;
    if (sink.hasOif && sink.oif > 0 && IsHiddenIndex((unsigned int)sink.oif)) return true;
    return false;
}

// ---------------------------------------------------------------------------
// buffer filtering (in place, message-wise compaction)
// ---------------------------------------------------------------------------

static ssize_t FilterNetlinkBuffer(void* buf, ssize_t len) {
    if (len <= 0) return len;
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
        switch (nh->nlmsg_type) {
            case RTM_NEWLINK: drop = NewlinkHidden(nh); break;
            case RTM_NEWADDR: drop = NewaddrHidden(nh); break;
            case RTM_NEWROUTE: drop = NewrouteHidden(nh); break;
            case RTM_NEWRULE: drop = NewruleHidden(nh); break;
            default: break;
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

// ---------------------------------------------------------------------------
// hooks
// ---------------------------------------------------------------------------

int HideSocket(int domain, int type, int protocol) {
    BYTEHOOK_STACK_SCOPE();
    int fd = BYTEHOOK_CALL_PREV(HideSocket, domain, type, protocol);
    if (fd >= 0 && domain == AF_NETLINK && protocol == NETLINK_ROUTE) TrackFd(fd);
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
    if (n > 0 && IsTracked(fd)) n = FilterNetlinkBuffer(buf, n);
    return n;
}

ssize_t HideRecvFrom(int fd, void* buf, size_t len, int flags, struct sockaddr* addr,
                     socklen_t* addrlen) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t n = BYTEHOOK_CALL_PREV(HideRecvFrom, fd, buf, len, flags, addr, addrlen);
    if (n > 0 && IsTracked(fd)) n = FilterNetlinkBuffer(buf, n);
    return n;
}

ssize_t HideRecvMsg(int fd, struct msghdr* msg, int flags) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t n = BYTEHOOK_CALL_PREV(HideRecvMsg, fd, msg, flags);
    if (n > 0 && msg && msg->msg_iovlen == 1 && msg->msg_iov &&
        msg->msg_iov[0].iov_len >= (size_t)n && IsTracked(fd)) {
        n = FilterNetlinkBuffer(msg->msg_iov[0].iov_base, n);
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

}  // namespace nvd
