#pragma once

#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <string>

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

namespace pas {

void Log(const char* fmt, ...);

void HookLibcSym(const char* sym, void* proxy);
// Same as HookLibcSym but with an explicit owner-ELF regex and a stub result
// so callers can log/verify activation ("dlsym" needs the owner probe:
// modern bionic serves dlsym through libdl.so's forwarding stub).
void* HookChainStub(const char* owner_regex, const char* sym, void* proxy);

bool IsHiddenIfaceName(const char* name);
bool IsHiddenPathFast(const char* path);
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
void InstallNetlinkHooks();
void StartInitWorker();
void SetSpoofConfig(bool sdkOn, int sdkVal, bool abiOn, int abiMode, bool compatMode,
                    bool nativeEnabled);

// CPU model / GPU (OpenGL + Vulkan) spoof (hide_gpu.cpp, hide_vulkan.cpp)
void SetCpuConfig(bool cpuOn, const char* display, const char* mfr, const char* model,
                  const char* part, const char* cpuInfoModel, const char* features, int minKHz,
                  int maxKHz, const char* hwLine);
void SetGpuConfig(bool gpuOn, const char* vendor, const char* renderer, const char* glVersion,
                  unsigned long long vendorId, unsigned long long deviceId,
                  unsigned long long driverVersion, unsigned long long apiVersion,
                  const char* driverName, const char* driverInfo);
bool CpuSpoofActive();
std::string CpuSpoofDisplay();
std::string CpuSpoofManufacturer();
std::string CpuSpoofModel();
std::string CpuSpoofPart();
std::string CpuSpoofCpuinfoModel();
std::string CpuSpoofFeatures();
std::string CpuSpoofHwLine();
int CpuSpoofMinKHz();
int CpuSpoofMaxKHz();
bool GpuSpoofActive();
std::string GpuSpoofVendor();
std::string GpuSpoofRenderer();
std::string GpuSpoofGlVersion();
unsigned long long GpuSpoofVendorId();
unsigned long long GpuSpoofDeviceId();
unsigned long long GpuSpoofDriverVersion();
unsigned long long GpuSpoofApiVersion();
std::string GpuSpoofDriverName();
std::string GpuSpoofDriverInfo();
void InstallGpuHooks();
void InstallVulkanHooks();
void InstallCpuDeepHooks();

// recon diagnostics (hide_fs.cpp): suspicious-probe logging, enabled from the
// module GUI; used to map a target app's detection surface.
void SetRecon(bool on);
bool ReconEnabled();
int WebRtcMode();
void SetWebRtcMode(int mode);
bool NetCellularSpoof();
void SetNetCellular(bool cellular);
void SetBootloaderValue(const char* value);
bool BrowserCallerHere(void* ra);
bool ProcessLooksBrowser();
bool CallerAllowGfx(const char* caller_path_name, void* arg);
void* HookChainStubGfx(const char* owner_regex, const char* sym, void* proxy);
void InstallGpuDlsymChain();
bool VulkanSpoofActive();
void SetGpuOptions(bool chain, bool vulkan);
void ReconNote(const char* op, const char* detail, long res);
void InstallReconHooks();

// GL resolver-chain substitution (hide_gpu.cpp), used by the dlsym wrapper in
// hide_vulkan.cpp. Returns the bytehook-free representative for GL entry
// points resolved dynamically, or nullptr when not handled.
void* GpuChainResolveDlsym(const char* symbol, void* real);
// Recon-gated GL/Vulkan resolver tracing (hide_gpu.cpp): logs which entry
// points actually flow through the module while "Recon logging" is on.
void GpuDiag(const char* tag, const char* detail);

// Caller filter shared with the GPU hook installer (defined in pas.cpp).
bool CallerAllowHooks(const char* caller_path_name, void* arg);
void InstallIoctlHooks();
void InstallPropSpoofHooks();
bool SpoofActive();
bool SpoofRewritePropsLine(const char* key, const char* origVal, char* outVal, size_t cap);

// Hook-installation gate: the worker waits briefly for the Kotlin side to
// deliver the config so it can either skip all hook installation (native
// addon disabled) or skip just the extended groups (compatibility mode).
void SignalSpoofConfigReady(bool compatMode, bool nativeEnabled);
bool WaitSpoofConfigReady(int timeoutMs, bool* compatOut, bool* nativeOut);

}  // namespace pas
