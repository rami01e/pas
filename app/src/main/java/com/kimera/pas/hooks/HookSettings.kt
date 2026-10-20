package com.kimera.pas.hooks

import android.content.ContentResolver
import android.util.Log
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState
import java.lang.reflect.Method
import java.lang.reflect.Modifier

/**
 * v2.12.7 SETTINGS SHIELD - answers the developer-options / ADB settings
 * probes with the values a stock, non-developer device reports.
 *
 * Evidence (com.playnearn capture, 10-19): the target's dex carries the
 * "development_settings_enabled" key right next to its RootBeer-style root
 * vocabulary (su paths, daemonsu, test-keys, rootcloak). That value lives in
 * Settings.Global - it is not a file and not a system property, so neither
 * the native anti-emu layer (file masks + prop masks) nor the sweep shield
 * (PackageManager) covers it, and HookRecon only LOGS settings reads. MuMu
 * ships with developer options and ADB enabled, so the app read the raw "1"
 * and could treat it as a root / tamper signal.
 *
 * Scope and gating:
 *  - Active only when the ANTI-EMU toggle is on (same ownership as the
 *    sweep shield and the native anti-emu layer). Checked per call, so
 *    toggling takes effect without a process restart.
 *  - Masked keys (answered with 0 / "0" - what a clean user build reports):
 *      development_settings_enabled   (Settings.Global)
 *      adb_enabled                    (Settings.Global)
 *      stay_on_while_plugged_in       (Settings.Global)
 *      mock_location                  (Settings.Secure, legacy key)
 *  - Surfaces covered: Settings$Global and Settings$Secure static getters
 *    getInt / getLong / getFloat / getString and their *ForUser variants -
 *    every declared overload whose first parameter is a ContentResolver.
 *  - android_id and every other key keep their real value: non-masked keys
 *    fall through with chain.proceed() untouched.
 *
 * Framework-mode note: no exception is ever thrown from the interceptor
 * body. Vector runs module hookers in PROTECTIVE exception mode - anything
 * a hooker throws is caught, logged ("Hooker ... crashed before proceed.
 * Skipping.") and the call continues as if no hook existed. This hook only
 * ever RETURNS a replacement value, which is always honored.
 */
class HookSettings : XHook {

    override val targetKlass: String
        get() = "android.provider.Settings\$Global"

    private var hits = 0

    override fun injectHook(module: XposedModule) {
        hookSettingsClass(module, "android.provider.Settings\$Global")
        hookSettingsClass(module, "android.provider.Settings\$Secure")
    }

    private fun hookSettingsClass(module: XposedModule, clazzName: String) {
        hookSafe(module, "settings $clazzName") {
            val clazz = Class.forName(clazzName)
            var installed = 0
            for (m in clazz.declaredMethods) {
                if (!Modifier.isStatic(m.modifiers)) continue
                if (m.parameterTypes.isEmpty() ||
                    m.parameterTypes[0] != ContentResolver::class.java) continue
                if (m.name !in GETTERS) continue
                try {
                    m.isAccessible = true
                    module.hook(m).intercept { chain -> intercept(module, m, chain) }
                    installed++
                } catch (t: Throwable) {
                    // one unsupported overload must not sink the rest
                }
            }
            module.log(Log.INFO, TAG, "[PAS] settings shield: $clazzName x$installed")
        }
    }

    private fun intercept(
        module: XposedModule,
        m: Method,
        chain: XposedInterface.Chain
    ): Any? {
        val key = chain.getArg(1) as? String
        if (!SpoofState.antiEmuOn || key == null || key !in MASKED_KEYS) {
            return chain.proceed()
        }
        if (hits < 16) {
            hits++
            module.log(Log.INFO, TAG, "[PAS] settings shield: '$key' -> 0")
        }
        return when (m.returnType) {
            java.lang.Integer.TYPE -> 0
            java.lang.Long.TYPE -> 0L
            java.lang.Float.TYPE -> 0f
            else -> "0"
        }
    }

    companion object {
        private val GETTERS = setOf(
            "getInt", "getLong", "getFloat", "getString",
            "getIntForUser", "getLongForUser", "getFloatForUser", "getStringForUser"
        )
        private val MASKED_KEYS = setOf(
            "development_settings_enabled",
            "adb_enabled",
            "stay_on_while_plugged_in",
            "mock_location"
        )
    }
}