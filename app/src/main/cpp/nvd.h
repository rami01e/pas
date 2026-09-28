#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ---- LSPosed native module entry ABI (see LSPosed wiki "Native Hook") ----

typedef int (*HookFunType)(void* func, void* replace, void** backup);
typedef int (*UnhookFunType)(void* func);

typedef void (*NativeOnModuleLoaded)(const char* name, void* handle);

typedef struct {
    uint32_t version;
    HookFunType hook_func;
    UnhookFunType unhook_func;
} NativeAPIEntries;

typedef NativeOnModuleLoaded (*NativeInit)(const NativeAPIEntries* entries);

// ---- shared helpers ----

namespace nvd {

void Log(const char* fmt, ...);

void* RealSym(const char* sym);
void HookLibcSym(const char* sym, void* proxy);

bool IsHiddenIfaceName(const char* name);
bool IsHiddenPath(const char* path);

// Hidden interface name cache (rebuilt from the real interface list).
void RefreshHiddenNames(bool force);
bool LineContainsHiddenName(const char* line);
bool LineContainsProxyPortToken(const char* line);
bool IsHiddenIndex(unsigned int ifindex);

// copy registry shared by getifaddrs / if_nameindex filtering
bool RegisterCopy(void* head);
bool UnregisterCopy(void* head);

// hook installation (called from native_init)
void InstallIfaceHooks();
void InstallFsHooks();
void InstallNetHooks();

}  // namespace nvd
