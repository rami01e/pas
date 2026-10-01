#include "pas.h"

#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "bytehook.h"

namespace pas {

// ---------------------------------------------------------------------------
// getifaddrs / freeifaddrs
// ---------------------------------------------------------------------------

static socklen_t SockAddrLen(const struct sockaddr* sa) {
    if (!sa) return 0;
    switch (sa->sa_family) {
        case AF_INET: return sizeof(struct sockaddr_in);
        case AF_INET6: return sizeof(struct sockaddr_in6);
#ifdef AF_PACKET
        case AF_PACKET: return sizeof(struct sockaddr_ll);
#endif
        default: return 128;
    }
}

static struct sockaddr* DupSockAddr(const struct sockaddr* sa) {
    socklen_t len = SockAddrLen(sa);
    if (!len) return nullptr;
    struct sockaddr* n = (struct sockaddr*)malloc(len);
    if (n) memcpy(n, sa, len);
    return n;
}

static struct ifaddrs* DeepCopyNode(const struct ifaddrs* s) {
    struct ifaddrs* n = (struct ifaddrs*)calloc(1, sizeof(struct ifaddrs));
    if (!n) return nullptr;
    if (s->ifa_name) {
        n->ifa_name = strdup(s->ifa_name);
        if (!n->ifa_name) {
            free(n);
            return nullptr;
        }
    }
    n->ifa_flags = s->ifa_flags;
    n->ifa_addr = DupSockAddr(s->ifa_addr);
    n->ifa_netmask = DupSockAddr(s->ifa_netmask);
    if (s->ifa_flags & IFF_POINTOPOINT) {
        n->ifa_dstaddr = DupSockAddr(s->ifa_dstaddr);
    } else {
        n->ifa_broadaddr = DupSockAddr(s->ifa_broadaddr);
    }
    return n;
}

// Frees OUR deep copies: they allocate name/addr/netmask/broadaddr/node
// separately (field-wise).
static void FreeOwnChain(struct ifaddrs* head) {
    while (head) {
        struct ifaddrs* next = head->ifa_next;
        free(head->ifa_name);
        free(head->ifa_addr);
        free(head->ifa_netmask);
        free(head->ifa_broadaddr);  // union: same slot as ifa_dstaddr
        free(head);
        head = next;
    }
}

// Frees a chain returned by the real bionic getifaddrs: bionic stores each
// interface in ONE allocation (the public pointers point into its hidden
// tail), so only the node itself may be freed. Mirrors bionic freeifaddrs.
static void FreeBionicChain(struct ifaddrs* head) {
    while (head) {
        struct ifaddrs* next = head->ifa_next;
        free(head);
        head = next;
    }
}

int HideGetIfaddrs(struct ifaddrs** out) {
    BYTEHOOK_STACK_SCOPE();
    void* caller = __builtin_return_address(0);
    struct ifaddrs* list = nullptr;
    int rc = BYTEHOOK_CALL_PREV(HideGetIfaddrs, &list);
    if (BrowserCallerHere(caller)) {
        if (out) *out = list;
        return rc;
    }
    if (rc != 0 || list == nullptr) {
        if (out) *out = list;
        return rc;
    }
    bool any = false;
    for (struct ifaddrs* it = list; it; it = it->ifa_next) {
        if (it->ifa_name && IsHiddenIfaceName(it->ifa_name)) {
            any = true;
            break;
        }
    }
    if (!any) {
        if (out) *out = list;
        return rc;
    }
    struct ifaddrs* head = nullptr;
    struct ifaddrs** tail = &head;
    for (struct ifaddrs* it = list; it; it = it->ifa_next) {
        if (it->ifa_name && IsHiddenIfaceName(it->ifa_name)) continue;
        struct ifaddrs* n = DeepCopyNode(it);
        if (!n) continue;
        *tail = n;
        tail = &n->ifa_next;
    }
    FreeBionicChain(list);
    RegisterCopy(head);
    if (out) *out = head;
    return 0;
}

void HideFreeIfaddrs(struct ifaddrs* p) {
    BYTEHOOK_STACK_SCOPE();
    if (p && UnregisterCopy(p)) {
        FreeOwnChain(p);
        return;
    }
    BYTEHOOK_CALL_PREV(HideFreeIfaddrs, p);
}

// ---------------------------------------------------------------------------
// if_nameindex / if_freenameindex
// ---------------------------------------------------------------------------

// Frees an if_nameindex array the way bionic's if_freenameindex does for
// arrays produced by the real if_nameindex(): the names are separate
// allocations, the array itself was allocated with new[].
static void FreeBionicNameIndex(struct if_nameindex* arr) {
    if (!arr) return;
    for (struct if_nameindex* it = arr; it->if_index != 0 || it->if_name != nullptr; ++it) {
        free(it->if_name);
    }
    delete[] arr;
}

// Frees OUR copy: the array is calloc'd, names are strdup'd by us.
static void FreeOwnNameIndex(struct if_nameindex* arr) {
    if (!arr) return;
    for (struct if_nameindex* it = arr; it->if_index != 0 || it->if_name != nullptr; ++it) {
        free(it->if_name);
    }
    free(arr);
}

struct if_nameindex* HideIfNameIndex() {
    BYTEHOOK_STACK_SCOPE();
    void* caller = __builtin_return_address(0);
    struct if_nameindex* arr = BYTEHOOK_CALL_PREV(HideIfNameIndex);
    if (!arr) return arr;
    if (BrowserCallerHere(caller)) return arr;
    size_t count = 0;
    while (arr[count].if_index != 0) count++;
    bool any = false;
    for (size_t i = 0; i < count; i++) {
        if (arr[i].if_name && IsHiddenIfaceName(arr[i].if_name)) {
            any = true;
            break;
        }
    }
    if (!any) return arr;
    struct if_nameindex* copy =
        (struct if_nameindex*)calloc(count + 1, sizeof(struct if_nameindex));
    if (!copy) return arr;
    size_t kept = 0;
    for (size_t i = 0; i < count; i++) {
        if (arr[i].if_name && IsHiddenIfaceName(arr[i].if_name)) continue;
        copy[kept].if_index = arr[i].if_index;
        copy[kept].if_name = arr[i].if_name ? strdup(arr[i].if_name) : nullptr;
        kept++;
    }
    RegisterCopy(copy);
    FreeBionicNameIndex(arr);
    return copy;
}

void HideIfFreeNameIndex(struct if_nameindex* arr) {
    BYTEHOOK_STACK_SCOPE();
    if (arr && UnregisterCopy(arr)) {
        FreeOwnNameIndex(arr);
        return;
    }
    BYTEHOOK_CALL_PREV(HideIfFreeNameIndex, arr);
}

// ---------------------------------------------------------------------------
// if_indextoname / if_nametoindex
// ---------------------------------------------------------------------------

char* HideIfIndexToName(unsigned int ifindex, char* buf) {
    BYTEHOOK_STACK_SCOPE();
    void* caller = __builtin_return_address(0);
    char* r = BYTEHOOK_CALL_PREV(HideIfIndexToName, ifindex, buf);
    if (BrowserCallerHere(caller)) return r;
    if (r && IsHiddenIfaceName(r)) {
        errno = ENODEV;
        return nullptr;
    }
    return r;
}

unsigned int HideIfNameToIndex(const char* name) {
    BYTEHOOK_STACK_SCOPE();
    if (BrowserCallerHere(__builtin_return_address(0))) {
        return BYTEHOOK_CALL_PREV(HideIfNameToIndex, name);
    }
    if (name && IsHiddenIfaceName(name)) {
        errno = ENODEV;
        return 0;
    }
    return BYTEHOOK_CALL_PREV(HideIfNameToIndex, name);
}

// ---------------------------------------------------------------------------

void InstallIfaceHooks() {
    HookLibcSym("getifaddrs", (void*)HideGetIfaddrs);
    HookLibcSym("freeifaddrs", (void*)HideFreeIfaddrs);
    HookLibcSym("if_nameindex", (void*)HideIfNameIndex);
    HookLibcSym("if_freenameindex", (void*)HideIfFreeNameIndex);
    HookLibcSym("if_indextoname", (void*)HideIfIndexToName);
    HookLibcSym("if_nametoindex", (void*)HideIfNameToIndex);
}

}  // namespace pas
