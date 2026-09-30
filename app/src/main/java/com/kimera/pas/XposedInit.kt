package com.kimera.pas

import android.util.Log
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import java.util.concurrent.atomic.AtomicBoolean
import com.kimera.pas.hooks.HookConnectivityManager
import com.kimera.pas.hooks.HookGsfId
import com.kimera.pas.hooks.HookGpu
import com.kimera.pas.hooks.HookLinkProperties
import com.kimera.pas.hooks.HookMediaDrm
import com.kimera.pas.hooks.HookNetworkCapabilities
import com.kimera.pas.hooks.HookNetworkInfo
import com.kimera.pas.hooks.HookNetworkInterface
import com.kimera.pas.hooks.HookNetworkRequestBuilder
import com.kimera.pas.hooks.HookRecon

const val TAG = "PerAppSpoofer"

/**
 * libxposed API 101 entry point (Vector 2.2+).
 *
 * The framework attaches itself automatically; hooks are installed exactly
 * once per process from onPackageReady.
 */
class XposedInit : XposedModule() {

    private val hooksInstalled = AtomicBoolean(false)

    override fun onModuleLoaded(param: ModuleLoadedParam) {
        log(Log.INFO, TAG, "[PAS] module loaded in ${param.processName}")
    }

    override fun onPackageReady(param: PackageReadyParam) {
        // onPackageReady may fire once for every loaded package in the process;
        // install the hooks exactly once per process.
        if (!hooksInstalled.compareAndSet(false, true)) {
            return
        }
        log(Log.INFO, TAG, "[PAS] onPackageReady: ${param.packageName} - installing hooks")

        initNativeAddon()

        val hooks =
            arrayOf(
                HookConnectivityManager(),
                HookNetworkInterface(),
                HookNetworkCapabilities(),
                HookNetworkInfo(),
                HookNetworkRequestBuilder(),
                HookLinkProperties(),
                HookMediaDrm(),
                HookGsfId(),
                HookGpu(),
                HookRecon(),
            )

        hooks.forEach {
            it.injectHook(this)
        }
    }

    /**
     * Native addon plus spoof config. The native library is loaded lazily and
     * only when enabled; the spoof config is always delivered so the
     * Java-level features (Widevine / GSF) work independently of the addon.
     */
    private fun initNativeAddon() {
        Thread({
            val nativeOn = try {
                getRemotePreferences("pas_spoof").getBoolean("native_enabled", false)
            } catch (t: Throwable) {
                log(Log.INFO, TAG, "[PAS] native: config unavailable ($t) - addon stays off")
                false
            }
            if (nativeOn) {
                try {
                    System.loadLibrary("pas")
                    log(Log.INFO, TAG, "[PAS] native library loaded")
                } catch (t: Throwable) {
                    log(Log.INFO, TAG, "[PAS] native library not loaded: $t")
                }
            } else {
                log(Log.INFO, TAG, "[PAS] native addon disabled - library not loaded")
            }
            runCatching { com.kimera.pas.spoof.SpoofCore.init(this) }
        }, "pas-native-init").start()
    }
}
