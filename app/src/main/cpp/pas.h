#pragma once

#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

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
void* HookChainStub(const char* owner_regex, const char* sym, void* proxy);

bool IsHiddenIfaceName(const char* name);
bool IsHiddenPathFast(const char* path);
bool IsHiddenPath(const char* path);

void RefreshHiddenNames(bool force);
bool LineContainsHiddenName(const char* line);
bool LineContainsProxyPortToken(const char* line);
bool IsHiddenIndex(unsigned int ifindex);

bool RegisterCopy(void* head);
bool UnregisterCopy(void* head);

void InstallIfaceHooks();
void InstallFsHooks();
void InstallNetHooks();
void InstallNetlinkHooks();
void StartInitWorker();
void SetSpoofConfig(bool sdkOn, int sdkVal, bool abiOn, int abiMode, bool compatMode,
                    bool nativeEnabled);

// CPU model / GPU (OpenGL + Vulkan) spoof
void SetCpuConfig(bool cpuOn, const char* display, const char* mfr, const char* model,
                  const char* part, const char* cpuInfoModel, const char* features, int minKHz,
                  int maxKHz, const char* hwLine, const char* implementer,
                  const char* hardware);
void SetCpuClusters(bool cpuOn, const char* clusters, const char* clusterSpec);

// v2.4.5: GPU now carries core count / L2 cache / architecture.
void SetGpuConfig(bool gpuOn, const char* vendor, const char* renderer, const char* glVersion,
                  unsigned long long vendorId, unsigned long long deviceId,
                  unsigned long long driverVersion, unsigned long long apiVersion,
                  const char* driverName, const char* driverInfo, const char* vkDeviceName,
                  int gpuCores, int l2CacheKb, const char* gpuArch);
void SetGpuProfile(int confMajor, int confMinor, int confSub, int confPatch,
                   int driverId, bool descriptorIndexing, bool sparseBinding);

bool CpuSpoofActive();

// v2.5.9: bounded wait for the GPU config (see hide_gpu.cpp). Early GL /
// Vulkan identity queries call this so a fast GL init cannot capture the
// real GPU before the config thread lands.
void WaitForGpuConfig(int timeoutMs);
std::string CpuSpoofDisplay();
std::string CpuSpoofManufacturer();
std::string CpuSpoofModel();
std::string CpuSpoofPart();
std::string CpuSpoofImplementer();
std::string CpuSpoofHardware();
const char* CpuSpoofClusters();
std::string CpuSpoofCpuinfoModel();
std::string CpuSpoofFeatures();
std::string CpuSpoofHwLine();
int CpuSpoofMinKHz();
int CpuSpoofMaxKHz();

// v2.5.9: per-cluster table parsed from the catalog clusterSpec string.
// Accessors take the core's global index; values fall back to the SoC-wide
// part / freq range when no spec (or index out of range) is available.
struct PasCpuCluster {
    int cores;      // number of cores in this cluster
    int totalBefore; // global index of the cluster's first core
    char part[16];  // "0xd4e" style CPU part id
    int minKHz;
    int maxKHz;
    char revision[16]; // "r1p1" style ARM revision
};
int CpuClusterTableSize();
const PasCpuCluster* CpuClusterTable();
const PasCpuCluster* CpuClusterForCore(int core, int* coreIndexInCluster);
const char* CpuSpoofClusterPart(int core);
int CpuSpoofClusterMinKHz(int core);
int CpuSpoofClusterMaxKHz(int core);
const char* CpuSpoofClusterRevision(int core);

bool GpuSpoofActive();
std::string GpuSpoofVendor();
std::string GpuSpoofRenderer();
std::string GpuSpoofVkDeviceName();
std::string GpuSpoofGlVersion();
unsigned long long GpuSpoofVendorId();
unsigned long long GpuSpoofDeviceId();
unsigned long long GpuSpoofDriverVersion();
unsigned long long GpuSpoofApiVersion();
std::string GpuSpoofDriverName();
std::string GpuSpoofDriverInfo();

// v2.4.5: physical GPU characteristics exposed to DevCheck-style readers.
int GpuSpoofCores();
int GpuSpoofL2CacheKb();
std::string GpuSpoofArch();

void InstallGpuHooks();
void InstallVulkanHooks();
// v2.6.3: x86_64-only inline backstop on the real libvulkan.so exports so
// ARM-translated apps (Houdini) cannot bypass the PLT/dlsym layers. No-op on
// other ABIs.
void InstallVulkanInlineBackstop();
void InstallCpuDeepHooks();

// v2.9.0: ANTI-EMU native layer (hide_antiemu.cpp). Installed early, gated
// at runtime on g_anti_emu set from Kotlin via nativeSetAntiEmu().
void InstallAntiEmuHooks();
void SetAntiEmu(bool on);
bool AntiEmuEnabled();

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
bool CallerAllowDlsymChain(const char* caller_path_name, void* arg);
void* HookChainStubGfx(const char* owner_regex, const char* sym, void* proxy);
void* HookChainStubDlsymChain(const char* owner_regex, const char* sym, void* proxy);
void InstallGpuDlsymChain();
bool VulkanSpoofActive();
void SetGpuOptions(bool chain, bool vulkan);
void ReconNote(const char* op, const char* detail, long res);
void InstallReconHooks();

void* GpuChainResolveDlsym(const char* symbol, void* real);
void GpuDiag(const char* tag, const char* detail);

bool CallerAllowHooks(const char* caller_path_name, void* arg);
void InstallIoctlHooks();
void InstallPropSpoofHooks();
bool SpoofActive();
bool SpoofRewritePropsLine(const char* key, const char* origVal, char* outVal, size_t cap);

void InstallSslHooks();
void SetSslUnpin(bool on);
bool SslUnpinActive();

void InstallSslArm64Hooks();
void SetSslArm64(bool on);
bool SslArm64Active();

void TrackNetlinkFd(int fd, int protocol);
ssize_t FilterNetlinkRecv(int fd, void* buf, ssize_t len);

void SignalSpoofConfigReady(bool compatMode, bool nativeEnabled);
bool WaitSpoofConfigReady(int timeoutMs, bool* compatOut, bool* nativeOut);

}  // namespace pas