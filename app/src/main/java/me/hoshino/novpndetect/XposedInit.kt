package me.hoshino.novpndetect

import android.util.Log
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import java.util.concurrent.atomic.AtomicBoolean
import me.hoshino.novpndetect.hooks.HookConnectivityManager
import me.hoshino.novpndetect.hooks.HookLinkProperties
import me.hoshino.novpndetect.hooks.HookNetworkCapabilities
import me.hoshino.novpndetect.hooks.HookNetworkInfo
import me.hoshino.novpndetect.hooks.HookNetworkInterface
import me.hoshino.novpndetect.hooks.HookNetworkRequestBuilder

const val TAG = "NoVPNDetect"

/**
 * libxposed API 101 entry point (Vector 2.2+).
 *
 * The framework attaches itself automatically; hooks are installed exactly
 * once per process from onPackageReady.
 */
class XposedInit : XposedModule() {

    private val hooksInstalled = AtomicBoolean(false)

    override fun onModuleLoaded(param: ModuleLoadedParam) {
        log(Log.INFO, TAG, "[NVD] module loaded in ${param.processName}")
    }

    override fun onPackageReady(param: PackageReadyParam) {
        // onPackageReady may fire once for every loaded package in the process;
        // install the hooks exactly once per process.
        if (!hooksInstalled.compareAndSet(false, true)) {
            return
        }
        log(Log.INFO, TAG, "[NVD] onPackageReady: ${param.packageName} - installing hooks")

        val hooks =
            arrayOf(
                HookConnectivityManager(),
                HookNetworkInterface(),
                HookNetworkCapabilities(),
                HookNetworkInfo(),
                HookNetworkRequestBuilder(),
                HookLinkProperties(),
            )

        hooks.forEach {
            it.injectHook(this)
        }
    }
}
