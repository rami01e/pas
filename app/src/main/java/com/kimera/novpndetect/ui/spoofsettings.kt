package com.kimera.novpndetect.ui

import android.content.Context
import android.content.SharedPreferences
import io.github.libxposed.service.XposedService
import io.github.libxposed.service.XposedServiceHelper

/**
 * Module-app side of the spoof settings.
 *
 * Values are written into the framework's remote preferences (group
 * "nvd_spoof") through the Vector service; the scoped processes read them via
 * XposedInterface#getRemotePreferences. A local copy keeps the UI state when
 * the service is not connected.
 */
object SpoofSettings {

    const val GROUP = "nvd_spoof"
    private const val LOCAL = "nvd_spoof_local"

    @Volatile
    private var service: XposedService? = null

    private var listenerRegistered = false

    /** Register once per process. */
    fun ensureListener() {
        if (listenerRegistered) return
        listenerRegistered = true
        runCatching {
            XposedServiceHelper.registerListener(object : XposedServiceHelper.OnServiceListener {
                override fun onServiceBind(service: XposedService) {
                    this@SpoofSettings.service = service
                }

                override fun onServiceDied(service: XposedService) {
                    if (this@SpoofSettings.service === service) {
                        this@SpoofSettings.service = null
                    }
                }
            })
        }
    }

    fun isConnected(): Boolean = service != null

    fun load(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(LOCAL, Context.MODE_PRIVATE)

    /**
     * Saves the values. Returns null on success or a user-facing error string.
     */
    fun save(ctx: Context, sdkOn: Boolean, sdkVal: Int, abiOn: Boolean, abiValue: String): String? {
        load(ctx).edit()
            .putBoolean("sdk_enabled", sdkOn)
            .putInt("sdk_value", sdkVal)
            .putBoolean("abi_enabled", abiOn)
            .putString("abi_value", abiValue)
            .apply()

        val svc = service ?: return "Saved locally — Vector service not connected.\n" +
            "Enable this module in Vector, reopen this app, then save again."

        return try {
            val prefs = svc.getRemotePreferences(GROUP)
            prefs.edit()
                .putBoolean("sdk_enabled", sdkOn)
                .putInt("sdk_value", sdkVal)
                .putBoolean("abi_enabled", abiOn)
                .putString("abi_value", abiValue)
                .apply()
            null
        } catch (t: Throwable) {
            "Save failed: $t"
        }
    }
}
