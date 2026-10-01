#include "pas.h"

#include <errno.h>
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
}

}  // namespace pas
