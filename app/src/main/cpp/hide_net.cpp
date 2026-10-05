// hide_net.cpp — socket-level network hiding.
//
// Two mechanisms:
//   1. setsockopt(SO_BINDTODEVICE / SO_BINDTOIFINDEX) is filtered so the
//      scoped process cannot bind a socket to a hidden (VPN) interface by
//      name or index.
//   2. connect() to a loopback address on a well-known proxy port is
//      refused with ECONNREFUSED, so anti-tamper probes that port-scan
//      the local host see "nothing listening" instead of a live SOCKS5
//      or HTTP proxy from a userspace tunnel.
//
// The proxy-port list is deliberately kept in sync with kProxyPorts in
// hide_netlink.cpp: the netlink filter hides the LISTEN entry from socket
// dumps, this connect filter hides the port from direct probe.

#include "pas.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include "bytehook.h"

namespace pas {

#ifndef SO_BINDTODEVICE
#define SO_BINDTODEVICE 25
#endif

// Linux 5.7+; not always defined in bionic headers.
#ifndef SO_BINDTOIFINDEX
#define SO_BINDTOIFINDEX 59
#endif

// ---------------------------------------------------------------------------
// loopback + well-known proxy-port connect refusal
// ---------------------------------------------------------------------------

static bool IsProxyPort(unsigned short port) {
    static const unsigned short kPorts[] = {
        1080,   // SOCKS5 (xray/v2ray/sing-box/neko/cat default)
        1081,   // SOCKS5 alt
        1087,   // SOCKS5 alt
        1088,   // SOCKS5 alt
        3128,   // Squid HTTP
        4444,   // various tunnels
        7890,   // Clash HTTP
        7891,   // Clash SOCKS
        7892,   // Clash alt
        8118,   // Privoxy
        8123,   // Polipo
        8888,   // HTTP proxy alt
        8889,   // HTTP proxy alt
        9050,   // Tor SOCKS
        9051,   // Tor control
        9090,   // Clash dashboard
        10808,  // v2ray default
        10809,  // v2ray default
        10810,  // v2ray alt
    };
    for (size_t i = 0; i < sizeof(kPorts) / sizeof(kPorts[0]); i++) {
        if (port == kPorts[i]) return true;
    }
    return false;
}

static bool IsLoopbackV4(uint32_t addr_network_order) {
    // 127.0.0.0/8, in network byte order
    return (ntohl(addr_network_order) >> 24) == 127;
}

static bool IsLoopbackV6(const struct in6_addr* addr) {
    static const unsigned char kLoop6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (memcmp(addr, kLoop6, 16) == 0) return true;
    // IPv4-mapped loopback ::ffff:127.x.x.x
    static const unsigned char kMapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    if (memcmp(addr, kMapped, 12) == 0 &&
        ((const unsigned char*)addr)[12] == 127) {
        return true;
    }
    return false;
}

static bool IsBlockedProxyTarget(const struct sockaddr* addr, socklen_t len) {
    if (addr == nullptr) return false;
    if (addr->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in* in = (const struct sockaddr_in*)addr;
        return IsProxyPort(ntohs(in->sin_port)) &&
               IsLoopbackV4(in->sin_addr.s_addr);
    }
    if (addr->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6* in6 = (const struct sockaddr_in6*)addr;
        return IsProxyPort(ntohs(in6->sin6_port)) &&
               IsLoopbackV6(&in6->sin6_addr);
    }
    return false;
}

// Capped diagnostic; fires once per blocked attempt, silently drops after 20.
static volatile int g_connect_block_count = 0;

int HideConnect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    BYTEHOOK_STACK_SCOPE();
    if (IsBlockedProxyTarget(addr, addrlen)) {
        int n = __sync_fetch_and_add(&g_connect_block_count, 1);
        if (n < 20) {
            Log("native: net: connect() to loopback proxy port refused");
        }
        errno = ECONNREFUSED;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(HideConnect, sockfd, addr, addrlen);
}

// ---------------------------------------------------------------------------
// setsockopt filtering
// ---------------------------------------------------------------------------

int HideSetSockOpt(int fd, int level, int optname, const void* optval, socklen_t optlen) {
    BYTEHOOK_STACK_SCOPE();
    bool relax = BrowserCallerHere(__builtin_return_address(0));
    if (!relax && level == SOL_SOCKET && optval != nullptr) {
        if (optname == SO_BINDTODEVICE && optlen > 0) {
            const char* name = (const char*)optval;
            bool nul = false;
            size_t max = (size_t)optlen;
            for (size_t i = 0; i < max; i++) {
                if (name[i] == '\0') {
                    nul = true;
                    break;
                }
            }
            if (nul && IsHiddenIfaceName(name)) {
                errno = ENODEV;
                return -1;
            }
        }
        if (optname == SO_BINDTOIFINDEX && optlen >= (socklen_t)sizeof(int)) {
            unsigned int idx = (unsigned int)(*(const int*)optval);
            if (IsHiddenIndex(idx)) {
                errno = ENODEV;
                return -1;
            }
        }
    }
    return BYTEHOOK_CALL_PREV(HideSetSockOpt, fd, level, optname, optval, optlen);
}

void InstallNetHooks() {
    HookLibcSym("setsockopt", (void*)HideSetSockOpt);
    HookLibcSym("connect", (void*)HideConnect);
}

}  // namespace pas