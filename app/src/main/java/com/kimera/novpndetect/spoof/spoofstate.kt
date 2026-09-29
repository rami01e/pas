package com.kimera.novpndetect.spoof

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
}
