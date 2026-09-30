package com.kimera.pas.ui

import android.content.Context
import android.content.SharedPreferences
import io.github.libxposed.service.XposedService
import io.github.libxposed.service.XposedServiceHelper

/**
 * Module-app side of the settings.
 *
 * Values are written into the framework's remote preferences (group
 * "pas_spoof") through the Vector service; the scoped processes read them via
 * XposedInterface#getRemotePreferences. A local copy keeps the UI state and
 * is synced to the remote side as soon as the service (re)binds, so a save
 * made while the service was disconnected still reaches the scoped apps.
 */
object SpoofSettings {

    const val GROUP = "pas_spoof"
    private const val LOCAL = "pas_spoof_local"

    private val KEYS = arrayOf(
        "native_enabled", "safe_mode",
        "sdk_enabled", "sdk_value",
        "abi_enabled", "abi_value",
        "cpu_enabled", "cpu_value",
        "gpu_enabled", "gpu_value",
        "widevine_enabled", "widevine_id",
        "gsf_enabled", "gsf_id",
        "recon_enabled", "webrtc_localip"
    )

    @Volatile
    private var service: XposedService? = null

    private val listener = object : XposedServiceHelper.OnServiceListener {
        override fun onServiceBind(service: XposedService) {
            this@SpoofSettings.service = service
            syncLocalToRemote(service)
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

    /**
     * The module scope (package names) as reported by the Vector service.
     * Returns null when the service is unavailable or the query fails.
     */
    fun scopePackages(): List<String>? = try {
        service?.scope
    } catch (t: Throwable) {
        null
    }

    fun load(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(LOCAL, Context.MODE_PRIVATE)

    /**
     * Saves the given values locally and (when connected) to the framework.
     * Returns null on full success or a user-facing message.
     */
    fun save(ctx: Context, values: Map<String, Any?>): String? {
        applyTo(load(ctx).edit(), values)

        val svc = service
        if (svc == null) {
            // Keep trying in the background; the sync-on-bind will deliver it.
            ensureListener(ctx)
            return "Saved locally. Vector service not connected right now - " +
                "it will sync automatically once connected."
        }

        return try {
            applyTo(svc.getRemotePreferences(GROUP).edit(), values)
            null
        } catch (t: Throwable) {
            "Framework write failed: $t"
        }
    }

    private fun applyTo(editor: SharedPreferences.Editor, values: Map<String, Any?>) {
        for ((k, v) in values) {
            when (v) {
                is Boolean -> editor.putBoolean(k, v)
                is Int -> editor.putInt(k, v)
                is String -> editor.putString(k, v)
            }
        }
        editor.apply()
    }

    /** Push whatever the UI saved while the service was disconnected. */
    private fun syncLocalToRemote(svc: XposedService) {
        val ctx = appContext ?: return
        val sp = load(ctx)
        if (!sp.contains("sdk_enabled")) return
        val all = sp.all
        val map = HashMap<String, Any?>()
        for (k in KEYS) {
            if (all.containsKey(k)) map[k] = all[k]
        }
        if (map.isEmpty()) return
        runCatching { applyTo(svc.getRemotePreferences(GROUP).edit(), map) }
    }
}
