package com.kimera.pas.hooks

import android.os.Build
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.spoof.SpoofState
import java.lang.reflect.Field

/**
 * ANTI-EMU (v2.9.0) - Java layer.
 *
 * Rewrites the android.os.Build.* static final String fields to the same
 * values the ROM-level properties already report (Samsung Galaxy S21 /
 * Exynos 2100 profile). This defeats every isRunningOnEmulator() /
 * isEmulator() check in the bundled ad SDKs (media3, Amazon APS, AppLovin,
 * Mintegral, InMobi, Appsflyer, Chartboost, Facebook Audience Network,
 * Crashlytics, Google Ads, SafeDK), because they all read one or more of
 * these fields at call time.
 *
 * The native side (hide_antiemu.cpp) masks the qemu pipes, DMI tree and
 * emulator property keys the same SDKs also probe - gated on the same
 * anti_emu_enabled toggle.
 *
 * Called once at package-ready; Build is already loaded by then so we use
 * reflection + sun.misc.Unsafe to overwrite the static final fields.
 */
class HookAntiEmu : XHook {

    override val targetKlass: String
        get() = "android.os.Build"

    override fun injectHook(module: XposedModule) {
        if (!SpoofState.antiEmuOn) {
            module.log(Log.INFO, TAG, "[PAS] ANTI-EMU off - Build.* not touched")
            return
        }
        patchBuild(module)
    }

    private fun patchBuild(module: XposedModule) {
        // Values sourced from the ROM-level properties (already spoofed) with
        // a Galaxy S21 / Exynos 2100 fallback matching the rest of the module.
        val brand    = sysProp("ro.product.brand")        ?: "samsung"
        val mfr      = sysProp("ro.product.manufacturer") ?: "samsung"
        val model    = sysProp("ro.product.model")        ?: "SM-G991B"
        val device   = sysProp("ro.product.device")       ?: "o1s"
        val product  = sysProp("ro.product.name")         ?: "o1sxeea"
        // v2.9.5: BOARD/HARDWARE are canonical o1s values, NOT read from
        // props - MuMu's ro.product.board ('SM-G991B') and ro.hardware
        // ('Samsung') are impossible values on a real S21 and fail
        // device-database validation.
        val board    = "exynos2100"
        val hardware = "exynos2100"
        val fp       = sysProp("ro.build.fingerprint")
            ?: "samsung/o1sxeea/o1s:15/UP1A.231005.007/G991BXXSJHZC2:user/release-keys"
        val id       = sysProp("ro.build.id")             ?: "UP1A.231005.007"
        val disp     = sysProp("ro.build.display.id")     ?: "UP1A.231005.007"
        val tags     = sysProp("ro.build.tags")           ?: "release-keys"
        val type     = sysProp("ro.build.type")           ?: "user"
        // v2.9.5: canonical values (MuMu's ro.build.user='abc' /
        // ro.build.host=<hash> are not what a real o1s build carries).
        val user     = "dpi"
        val host     = "SWDD5907"

        var ok = 0
        var fail = 0

        fun patch(name: String, value: String) {
            val r = unsafeSet(Build::class.java, name, value) ||
                fallbackSet(Build::class.java, name, value)
            if (r) {
                ok++
                module.log(Log.INFO, TAG, "[PAS] ANTI-EMU Build.$name = '$value'")
            } else {
                fail++
                module.log(Log.INFO, TAG, "[PAS] ANTI-EMU Build.$name FAILED")
            }
        }

        // Fields every emulator check reads
        patch("BRAND", brand)
        patch("MANUFACTURER", mfr)
        patch("MODEL", model)
        patch("DEVICE", device)
        patch("PRODUCT", product)
        patch("BOARD", board)
        patch("HARDWARE", hardware)
        patch("FINGERPRINT", fp)
        // Cosmetic identity fields (some integrity tools cross-check these)
        patch("DISPLAY", disp)
        patch("ID", id)
        patch("TAGS", tags)
        patch("TYPE", type)
        patch("USER", user)
        patch("HOST", host)

        module.log(Log.INFO, TAG, "[PAS] ANTI-EMU Build patched ok=$ok fail=$fail")
    }

    private fun sysProp(name: String): String? = runCatching {
        val sp = Class.forName("android.os.SystemProperties")
        (sp.getMethod("get", String::class.java).invoke(null, name) as? String)
            ?.takeIf { it.isNotEmpty() }
    }.getOrNull()

    // ---- reflection / Unsafe helpers (same approach as SpoofCore) ----

    private val unsafe: Any? by lazy {
        runCatching {
            val cls = Class.forName("sun.misc.Unsafe")
            val f = cls.getDeclaredField("theUnsafe")
            f.isAccessible = true
            f.get(null)
        }.getOrNull()
    }

    private val mPutObject by lazy {
        unsafe?.let {
            runCatching {
                it.javaClass.getMethod(
                    "putObject",
                    Any::class.java,
                    Long::class.javaPrimitiveType,
                    Any::class.java
                )
            }.getOrNull()
        }
    }
    private val mStaticBase by lazy {
        unsafe?.let {
            runCatching {
                it.javaClass.getMethod("staticFieldBase", Field::class.java)
            }.getOrNull()
        }
    }
    private val mStaticOffset by lazy {
        unsafe?.let {
            runCatching {
                it.javaClass.getMethod("staticFieldOffset", Field::class.java)
            }.getOrNull()
        }
    }

    private fun unsafeSet(clazz: Class<*>, name: String, value: Any?): Boolean {
        val u = unsafe ?: return false
        val baseM = mStaticBase ?: return false
        val offM = mStaticOffset ?: return false
        val putM = mPutObject ?: return false
        return runCatching {
            val f = clazz.getDeclaredField(name)
            val b = baseM.invoke(u, f)
            val off = (offM.invoke(u, f) as? Long) ?: return false
            putM.invoke(u, b, off, value)
            true
        }.getOrDefault(false)
    }

    private fun fallbackSet(clazz: Class<*>, name: String, value: Any?): Boolean =
        runCatching {
            val f = clazz.getDeclaredField(name)
            f.isAccessible = true
            f.set(null, value)
            true
        }.getOrDefault(false)
}