package com.kimera.novpndetect.ui

import android.content.Context
import android.content.SharedPreferences
import io.github.libxposed.service.XposedService
import io.github.libxposed.service.XposedServiceHelper

/**
 * Module-app side of the settings.
 *
 * Values are written into the framework's remote preferences (group
 * "nvd_spoof") through the Vector service; the scoped processes read them via
 * XposedInterface#getRemotePreferences. A local copy keeps the UI state and
 * is synced to the remote side as soon as the service (re)binds, so a save
 * made while the service was disconnected still reaches the scoped apps.
 */
object SpoofSettings {

    const val GROUP = "nvd_spoof"
    private const val LOCAL = "nvd_spoof_local"

    private val KEYS = arrayOf("sdk_enabled", "sdk_value", "abi_enabled", "abi_value", "safe_mode")

    @Volatile
    private var service: XposedService? = null

    private val listener = object : XposedServiceHelper.OnServiceListener {
        override fun onServiceBind(service: XposedService) {
            this@SpoofSettings.service = service
            syncLocalToRemote(this@SpoofSettings.service)
        }

        override fun onServiceDied(service: XposedService) {
            if (this@SpoofSettings.service === service) {
                this@SpoofSettings.service = null
            }
        }
    }

    private var appContext: Context? = null

    /** Register (or re-register) the service listener. Safe to call repeatedly. */
    fun ensureListener(ctx: Context? = null) {
        if (ctx != null) appContext = ctx.applicationContext
        runCatching { XposedServiceHelper.registerListener(listener) }
    }

    fun isConnected(): Boolean = service != null

    fun load(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(LOCAL, Context.MODE_PRIVATE)

    /**
     * Saves the values locally and (when connected) to the framework.
     * Returns null on full success or a user-facing message.
     */
    fun save(
        ctx: Context,
        sdkOn: Boolean,
        sdkVal: Int,
        abiOn: Boolean,
        abiValue: String,
        safeMode: Boolean
    ): String? {
        load(ctx).edit()
            .putBoolean("sdk_enabled", sdkOn)
            .putInt("sdk_value", sdkVal)
            .putBoolean("abi_enabled", abiOn)
            .putString("abi_value", abiValue)
            .putBoolean("safe_mode", safeMode)
            .apply()

        val svc = service
        if (svc == null) {
            // Keep trying in the background; the sync-on-bind will deliver it.
            ensureListener(ctx)
            return "Saved locally. Vector service not connected right now - " +
                "it will sync automatically once connected. To apply immediately: " +
                "open Vector, then reopen this app."
        }

        return try {
            writeRemote(svc, sdkOn, sdkVal, abiOn, abiValue, safeMode)
            null
        } catch (t: Throwable) {
            "Framework write failed: $t"
        }
    }

    private fun writeRemote(
        svc: XposedService,
        sdkOn: Boolean,
        sdkVal: Int,
        abiOn: Boolean,
        abiValue: String,
        safeMode: Boolean
    ) {
        svc.getRemotePreferences(GROUP).edit()
            .putBoolean("sdk_enabled", sdkOn)
            .putInt("sdk_value", sdkVal)
            .putBoolean("abi_enabled", abiOn)
            .putString("abi_value", abiValue)
            .putBoolean("safe_mode", safeMode)
            .apply()
    }

    /** Push whatever the UI saved while the service was disconnected. */
    private fun syncLocalToRemote(svc: XposedService) {
        val ctx = appContext ?: return
        val sp = load(ctx)
        if (!sp.contains("sdk_enabled")) return
        runCatching {
            writeRemote(
                svc,
                sp.getBoolean("sdk_enabled", false),
                sp.getInt("sdk_value", 0),
                sp.getBoolean("abi_enabled", false),
                sp.getString("abi_value", "x86_64") ?: "x86_64",
                sp.getBoolean("safe_mode", true)
            )
        }
    }
}
