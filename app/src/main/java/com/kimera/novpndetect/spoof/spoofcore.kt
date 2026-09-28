package com.kimera.novpndetect.spoof

import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import io.github.libxposed.api.XposedModule
import java.lang.reflect.Field

/**
 * Per-app SDK / ABI spoof for the scoped process.
 *
 * The native library covers the C surfaces (system properties, uname, CPU
 * family); this class covers the Java surfaces (android.os.Build fields,
 * os.arch) and pushes the config into the native layer.
 *
 * Disabled by default; configured from the module GUI through Vector remote
 * preferences (group "nvd_spoof").
 */
object SpoofCore {

    private const val TAG = "NoVPNDetect"
    const val GROUP = "nvd_spoof"

    external fun nativeSetConfig(sdkOn: Boolean, sdkVal: Int, abiOn: Boolean, abiArm64: Boolean)

    /** Called from XposedInit.onPackageReady (once per process). */
    fun init(module: XposedModule) {
        Thread({
            try {
                val prefs = module.getRemotePreferences(GROUP)
                apply(prefs)
                runCatching {
                    prefs.registerOnSharedPreferenceChangeListener { _, _ -> apply(prefs) }
                }
                Log.i(TAG, "[NVD] spoof: remote prefs attached")
            } catch (t: Throwable) {
                Log.i(TAG, "[NVD] spoof: not available ($t)")
            }
        }, "nvd-spoof").start()
    }

    private fun apply(prefs: SharedPreferences) {
        val sdkOn = prefs.getBoolean("sdk_enabled", false)
        var sdkVal = prefs.getInt("sdk_value", 0)
        val abiOn = prefs.getBoolean("abi_enabled", false)
        val abiArm64 = prefs.getString("abi_value", "x86_64") == "arm64-v8a"
        if (sdkVal !in 21..45) sdkVal = 0
        val useSdk = sdkOn && sdkVal != 0

        if (useSdk) applySdk(sdkVal)
        if (abiOn) applyAbi(abiArm64)

        runCatching { nativeSetConfig(useSdk, if (useSdk) sdkVal else 0, abiOn, abiArm64) }
        Log.i(TAG, "[NVD] spoof applied: sdk=$useSdk/$sdkVal abi=$abiOn arm64=$abiArm64")
    }

    // ------------------------------------------------------------------
    // Java-level patching (sun.misc.Unsafe, reflection only)
    // ------------------------------------------------------------------

    private val unsafe: Any? by lazy {
        runCatching {
            val cls = Class.forName("sun.misc.Unsafe")
            val f = cls.getDeclaredField("theUnsafe")
            f.isAccessible = true
            f.get(null)
        }.getOrNull()
    }

    private val mPutInt by lazy {
        unsafe?.let { runCatching { it.javaClass.getMethod("putInt", Any::class.java, Long::class.javaPrimitiveType, Int::class.javaPrimitiveType) }.getOrNull() }
    }
    private val mPutObject by lazy {
        unsafe?.let { runCatching { it.javaClass.getMethod("putObject", Any::class.java, Long::class.javaPrimitiveType, Any::class.java) }.getOrNull() }
    }
    private val mStaticBase by lazy {
        unsafe?.let { runCatching { it.javaClass.getMethod("staticFieldBase", Field::class.java) }.getOrNull() }
    }
    private val mStaticOffset by lazy {
        unsafe?.let { runCatching { it.javaClass.getMethod("staticFieldOffset", Field::class.java) }.getOrNull() }
    }

    private fun setStatic(clazz: Class<*>, name: String, value: Any?) {
        val u = unsafe ?: return
        runCatching {
            val f = clazz.getDeclaredField(name)
            val base = mStaticBase?.invoke(u, f)
            val off = (mStaticOffset?.invoke(u, f) as? Long) ?: return
            when (value) {
                is Int -> mPutInt?.invoke(u, base, off, value)
                else -> mPutObject?.invoke(u, base, off, value)
            }
        }
    }

    private fun applySdk(v: Int) {
        runCatching { setStatic(Build.VERSION::class.java, "SDK_INT", v) }
        releaseFor(v)?.let { rel ->
            runCatching { setStatic(Build.VERSION::class.java, "RELEASE", rel) }
        }
    }

    private fun releaseFor(v: Int): String? = when (v) {
        21 -> "5.0"; 22 -> "5.1"; 23 -> "6.0"; 24 -> "7.0"; 25 -> "7.1"
        26 -> "8.0"; 27 -> "8.1"; 28 -> "9"; 29 -> "10"; 30 -> "11"
        31 -> "12"; 32 -> "12"; 33 -> "13"; 34 -> "14"; 35 -> "15"; 36 -> "16"
        else -> null
    }

    private fun applyAbi(arm64: Boolean) {
        val abi = if (arm64) "arm64-v8a" else "x86_64"
        val abi2 = if (arm64) "armeabi-v7a" else "x86"
        val all = if (arm64) arrayOf("arm64-v8a", "armeabi-v7a", "armeabi") else arrayOf("x86_64", "x86")
        val a64 = if (arm64) arrayOf("arm64-v8a") else arrayOf("x86_64")
        val a32 = if (arm64) arrayOf("armeabi-v7a", "armeabi") else arrayOf("x86")
        runCatching { setStatic(Build::class.java, "CPU_ABI", abi) }
        runCatching { setStatic(Build::class.java, "CPU_ABI2", abi2) }
        runCatching { setStatic(Build::class.java, "SUPPORTED_ABIS", all) }
        runCatching { setStatic(Build::class.java, "SUPPORTED_64_BIT_ABIS", a64) }
        runCatching { setStatic(Build::class.java, "SUPPORTED_32_BIT_ABIS", a32) }
        runCatching { System.setProperty("os.arch", if (arm64) "aarch64" else "x86_64") }
    }
}
