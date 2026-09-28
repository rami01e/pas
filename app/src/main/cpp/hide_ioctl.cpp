// ioctl() filtering for interface queries.
//
// Detector probes that miss the getifaddrs/if_indextoname hooks fall back to
// ioctl(SIOCGIFFLAGS / SIOCGIFINDEX / ...) with a fixed interface name, or
// enumerate through SIOCGIFCONF. Both are answered by the kernel directly, so
// they must be filtered here to keep the same view as every other hook.

#include "nvd.h"

#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/sockios.h>

#include "bytehook.h"

namespace nvd {

static bool IfrNameHidden(const struct ifreq* ifr) {
    char name[IFNAMSIZ + 1];
    memcpy(name, ifr->ifr_name, IFNAMSIZ);
    name[IFNAMSIZ] = '\0';
    return IsHiddenIfaceName(name);
}

// Requests that carry an interface name in ifr_name and expect the kernel to
// resolve it.
static bool IsNameQuery(unsigned long req) {
    return req == SIOCGIFFLAGS || req == SIOCGIFINDEX || req == SIOCGIFMTU ||
           req == SIOCGIFHWADDR || req == SIOCGIFADDR || req == SIOCGIFNETMASK ||
           req == SIOCGIFBRDADDR || req == SIOCGIFDSTADDR || req == SIOCGIFTXQLEN ||
           req == SIOCGIFMETRIC || req == SIOCGIFMAP || req == SIOCGIFPFLAGS;
}

static void FilterIfConf(struct ifconf* ifc) {
    if (!ifc || !ifc->ifc_buf || ifc->ifc_len <= 0) return;
    const size_t ent = sizeof(struct ifreq);
    int count = (int)((size_t)ifc->ifc_len / ent);
    char* buf = ifc->ifc_buf;
    char* out = buf;
    int kept = 0;
    for (int i = 0; i < count; i++) {
        char* cur = buf + (size_t)i * ent;
        char name[IFNAMSIZ + 1];
        memcpy(name, cur, IFNAMSIZ);
        name[IFNAMSIZ] = '\0';
        if (IsHiddenIfaceName(name)) continue;
        if (out != cur) memmove(out, cur, ent);
        out += ent;
        kept++;
    }
    ifc->ifc_len = kept * (int)ent;
}

int HideIoctl(int fd, unsigned long request, void* arg) {
    BYTEHOOK_STACK_SCOPE();
    if (arg != nullptr) {
        if (request == SIOCGIFCONF) {
            int rc = BYTEHOOK_CALL_PREV(HideIoctl, fd, request, arg);
            if (rc == 0) FilterIfConf((struct ifconf*)arg);
            return rc;
        }
        if (request == SIOCGIFNAME) {
            // Input: ifr_ifindex. Output: ifr_name.
            struct ifreq* ifr = (struct ifreq*)arg;
            if (IsHiddenIndex((unsigned int)ifr->ifr_ifindex)) {
                errno = ENODEV;
                return -1;
            }
            int rc = BYTEHOOK_CALL_PREV(HideIoctl, fd, request, arg);
            if (rc == 0 && IfrNameHidden(ifr)) {
                errno = ENODEV;
                return -1;
            }
            return rc;
        }
        if (IsNameQuery(request)) {
            struct ifreq* ifr = (struct ifreq*)arg;
            if (IfrNameHidden(ifr)) {
                errno = ENODEV;
                return -1;
            }
        }
    }
    return BYTEHOOK_CALL_PREV(HideIoctl, fd, request, arg);
}

void InstallIoctlHooks() {
    HookLibcSym("ioctl", (void*)HideIoctl);
}

}  // namespace nvd
