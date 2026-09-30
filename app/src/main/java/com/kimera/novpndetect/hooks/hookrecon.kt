package com.kimera.novpndetect.hooks

import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.novpndetect.TAG
import com.kimera.novpndetect.XHook
import com.kimera.novpndetect.hookSafe
import com.kimera.novpndetect.spoof.SpoofState

/**
 * Recon diagnostics: while "Recon logging" is enabled, package-manager and
 * settings probes for common root / hook / emulator indicators are written to
 * the module log, so a target app's detection surface can be mapped per-app.
 * The toggle is checked on every call; with it off these hooks stay inert.
 */
class HookRecon : XHook {

    override val targetKlass: String
        get() = "android.app.ApplicationPackageManager"

    override fun injectHook(module: XposedModule) {
        hookPmQuery(module, "getPackageInfo")
        hookPmQuery(module, "getApplicationInfo")
        hookSettingsGetString(module, "android.provider.Settings\$Global")
        hookSettingsGetString(module, "android.provider.Settings\$Secure")
    }

    private fun hookPmQuery(module: XposedModule, name: String) {
        hookSafe(module, "recon $name") {
            val clazz = Class.forName(targetKlass)
            val method =
                clazz.getDeclaredMethod(name, String::class.java, Int::class.javaPrimitiveType)
            method.isAccessible = true
            module.hook(method).intercept { chain ->
                val pkg = chain.getArg(0) as? String
                if (SpoofState.reconOn && pkg != null && ReconFilter.hitName(pkg)) {
                    module.log(Log.INFO, TAG, "[NVD] recon(java): $name $pkg")
                }
                chain.proceed()
            }
        }
    }

    private fun hookSettingsGetString(module: XposedModule, clazzName: String) {
        hookSafe(module, "recon $clazzName") {
            val clazz = Class.forName(clazzName)
            val method = clazz.getDeclaredMethod(
                "getString",
                Class.forName("android.content.ContentResolver"),
                String::class.java
            )
            method.isAccessible = true
            module.hook(method).intercept { chain ->
                val key = chain.getArg(1) as? String
                if (SpoofState.reconOn && key != null && ReconFilter.hitSettings(key)) {
                    module.log(Log.INFO, TAG, "[NVD] recon(java): settings $key")
                }
                chain.proceed()
            }
        }
    }
}

private object ReconFilter {

    private val NAME_TOKENS = arrayOf(
        "magisk", "supersu", "superuser", "xposed", "frida", "substrate", "kernelsu",
        "ksu", "shamiko", "riru", "lsposed", "momohide", "topjohnwu", "weishu",
        "chainfire", "saurik", "hide", "root", "cheat", "hack", "vmos", "bluestacks",
        "nox", "ldplayer", "memu", "gameloop", "emulator", "island", "shelter"
    )

    fun hitName(pkg: String): Boolean {
        val low = pkg.lowercase()
        for (t in NAME_TOKENS) {
            if (low.contains(t)) return true
        }
        return false
    }

    fun hitSettings(key: String): Boolean {
        val low = key.lowercase()
        return low.contains("adb") || low.contains("development") || low.contains("stay_on") ||
            low.contains("mock")
    }
}
