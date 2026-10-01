package com.kimera.pas.spoof

/**
 * Live spoof state read by the Java hooks (Widevine DRM / GSF ID).
 *
 * Filled by [SpoofCore] from the framework remote preferences and updated
 * live when the settings change; the hooks just read these volatile fields on
 * each call, so toggling a feature takes effect without a process restart.
 */
object SpoofState {

    @Volatile
    var widevineOn: Boolean = false

    /** Widevine deviceUniqueId, lowercase hex (even number of chars). */
    @Volatile
    var widevineId: String = ""

    @Volatile
    var gsfOn: Boolean = false

    /** GSF android_id, digits (served as the numeric gservices value). */
    @Volatile
    var gsfId: String = ""

    @Volatile
    var cpuOn: Boolean = false

    /** CPU display name used for /proc/cpuinfo + Build.SOC_* (e.g. "Qualcomm Snapdragon 855"). */
    @Volatile
    var cpuDisplay: String = ""

    @Volatile
    var cpuManufacturer: String = ""

    /** SoC model code (e.g. "SM8550"), used for ro.soc.model / Build.SOC_MODEL. */
    @Volatile
    var cpuModel: String = ""

    @Volatile
    var gpuOn: Boolean = false

    @Volatile
    var gpuVendor: String = ""

    @Volatile
    var gpuRenderer: String = ""

    /** glGetString(GL_VERSION) replacement for the Java GL readers. */
    @Volatile
    var gpuGlVersion: String = ""

    /** Recon diagnostics logging ("recon_enabled"); read by HookRecon per call. */
    @Volatile
    var reconOn: Boolean = false

    /**
     * "WebRTC local IP" mode: 0 = relaxed (interfaces fully visible),
     * 1 = balanced (relaxed only for browser callers), 2 = RKN (full hiding).
     */
    @Volatile
    var webrtcMode: Int = 0
}
