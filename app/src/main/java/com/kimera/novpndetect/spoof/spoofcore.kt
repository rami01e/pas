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
 * It also delivers the "compatibility mode" flag: the native worker waits
 * briefly for this config so compatibility mode can skip the extended hook
 * groups (netlink / ioctl / properties / uname / cpu) entirely - the set that
 * heavy apps load best without.
 *
 * Disabled by default; configured from the module GUI through Vector remote
 * preferences (group "nvd_spoof").
 */
object SpoofCore {

    private const val TAG = "NoVPNDetect"
    const val GROUP = "nvd_spoof"

    external fun nativeSetConfig(
        sdkOn: Boolean,
        sdkVal: Int,
        abiOn: Boolean,
        abiArm64: Boolean,
        compatMode: Boolean,
        nativeEnabled: Boolean
    )

    external fun nativeSetCpuGpu(
        cpuOn: Boolean,
        cpuDisplay: String,
        cpuMfr: String,
        cpuModel: String,
        gpuOn: Boolean,
        gpuVendor: String,
        gpuRenderer: String
    )

    /** Called from XposedInit.onPackageReady (once per process). */
    fun init(module: XposedModule) {
        Thread({
            val prefs: SharedPreferences? = try {
                module.getRemotePreferences(GROUP)
            } catch (t: Throwable) {
                Log.i(TAG, "[NVD] spoof: no remote prefs ($t) - defaults")
                null
            }
            if (prefs == null) {
                // Release the native hook gate with safe defaults (addon off).
                runCatching { nativeSetConfig(false, 0, false, false, true, false) }
            } else {
                apply(prefs)
                try {
                    Thread.sleep(5000)
                } catch (_: InterruptedException) {
                }
                apply(prefs)
                Log.i(TAG, "[NVD] spoof: remote prefs attached")
            }
        }, "nvd-spoof").start()
    }

    private fun apply(prefs: SharedPreferences) {
        val nativeOn = prefs.getBoolean("native_enabled", false)
        val sdkOn = prefs.getBoolean("sdk_enabled", false)
        var sdkVal = prefs.getInt("sdk_value", 0)
        val abiOn = prefs.getBoolean("abi_enabled", false)
        val abiArm64 = prefs.getString("abi_value", "x86_64") == "arm64-v8a"
        val compat = prefs.getBoolean("safe_mode", true)
        if (sdkVal !in 21..45) sdkVal = 0
        val useSdk = sdkOn && sdkVal != 0

        // Java-only id spoofs: available regardless of the native addon.
        SpoofState.widevineOn = prefs.getBoolean("widevine_enabled", false)
        SpoofState.widevineId = (prefs.getString("widevine_id", "") ?: "").lowercase()
        SpoofState.gsfOn = prefs.getBoolean("gsf_enabled", false)
        SpoofState.gsfId = (prefs.getString("gsf_id", "") ?: "").trim()
        Log.i(
            TAG,
            "[NVD] id spoof: widevine=${SpoofState.widevineOn} gsf=${SpoofState.gsfOn}"
        )

        // CPU / GPU spoof values (resolved from the shared catalog; active only
        // together with the native addon so all surfaces stay consistent).
        val cpuEntry = DeviceCatalog.cpu(prefs.getString("cpu_value", null))
        val gpuEntry = DeviceCatalog.gpu(prefs.getString("gpu_value", null))
        val cpuOnEff = prefs.getBoolean("cpu_enabled", false) && nativeOn
        val gpuOnEff = prefs.getBoolean("gpu_enabled", false) && nativeOn
        SpoofState.cpuOn = cpuOnEff
        SpoofState.cpuDisplay = cpuEntry.display
        SpoofState.cpuManufacturer = cpuEntry.manufacturer
        SpoofState.cpuModel = cpuEntry.model
        SpoofState.gpuOn = gpuOnEff
        SpoofState.gpuVendor = gpuEntry.vendor
        SpoofState.gpuRenderer = gpuEntry.renderer
        Log.i(
            TAG,
            "[NVD] cpu/gpu spoof: cpu=$cpuOnEff (${cpuEntry.display}) " +
                "gpu=$gpuOnEff (${gpuEntry.renderer})"
        )
        // Delivered before the config gate so the native worker can decide
        // whether to install the GL hooks right away.
        runCatching {
            nativeSetCpuGpu(
                cpuOnEff, cpuEntry.display, cpuEntry.manufacturer, cpuEntry.model,
                gpuOnEff, gpuEntry.vendor, gpuEntry.renderer
            )
        }

        // Always deliver the config first: it releases the native hook gate
        // (native addon on/off + compatibility mode).
        runCatching {
            nativeSetConfig(useSdk, if (useSdk) sdkVal else 0, abiOn, abiArm64, compat, nativeOn)
        }

        if (!nativeOn) {
            Log.i(TAG, "[NVD] spoof: native addon disabled - Java hooks only")
            return
        }

        var ok = 0
        var fail = 0

        fun patch(clazz: Class<*>, name: String, value: Any?, label: String) {
            val r = unsafeSet(clazz, name, value) || fallbackSet(clazz, name, value)
            if (r) {
                ok++
            } else {
                fail++
                Log.i(TAG, "[NVD] spoof: java field FAILED: $label")
            }
        }

        if (useSdk) {
            patch(Build.VERSION::class.java, "SDK_INT", sdkVal, "SDK_INT")
            releaseFor(sdkVal)?.let { patch(Build.VERSION::class.java, "RELEASE", it, "RELEASE") }
        }
        if (cpuOnEff) {
            patch(Build::class.java, "SOC_MANUFACTURER", cpuEntry.manufacturer, "SOC_MANUFACTURER")
            patch(Build::class.java, "SOC_MODEL", cpuEntry.model, "SOC_MODEL")
        }
        if (abiOn) {
            val abi = if (abiArm64) "arm64-v8a" else "x86_64"
            val abi2 = if (abiArm64) "armeabi-v7a" else "x86"
            val all = if (abiArm64) arrayOf("arm64-v8a", "armeabi-v7a", "armeabi") else arrayOf("x86_64", "x86")
            val a64 = if (abiArm64) arrayOf("arm64-v8a") else arrayOf("x86_64")
            val a32 = if (abiArm64) arrayOf("armeabi-v7a", "armeabi") else arrayOf("x86")
            patch(Build::class.java, "CPU_ABI", abi, "CPU_ABI")
            patch(Build::class.java, "CPU_ABI2", abi2, "CPU_ABI2")
            patch(Build::class.java, "SUPPORTED_ABIS", all, "SUPPORTED_ABIS")
            patch(Build::class.java, "SUPPORTED_64_BIT_ABIS", a64, "SUPPORTED_64_BIT_ABIS")
            patch(Build::class.java, "SUPPORTED_32_BIT_ABIS", a32, "SUPPORTED_32_BIT_ABIS")
            runCatching { System.setProperty("os.arch", if (abiArm64) "aarch64" else "x86_64") }
        }
        Log.i(
            TAG,
            "[NVD] spoof applied: sdk=$useSdk/$sdkVal abi=$abiOn arm64=$abiArm64 cpu=$cpuOnEff gpu=$gpuOnEff compat=$compat java ok=$ok fail=$fail"
        )
    }

    // ------------------------------------------------------------------
    // Java-level patching (sun.misc.Unsafe primary, reflection fallback)
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

    private fun unsafeSet(clazz: Class<*>, name: String, value: Any?): Boolean {
        val u = unsafe ?: return false
        val baseM = mStaticBase ?: return false
        val offM = mStaticOffset ?: return false
        return runCatching {
            val f = clazz.getDeclaredField(name)
            val b = baseM.invoke(u, f)
            val off = (offM.invoke(u, f) as? Long) ?: return false
            when (value) {
                is Int -> {
                    val m = mPutInt ?: return false
                    m.invoke(u, b, off, value)
                }
                else -> {
                    val m = mPutObject ?: return false
                    m.invoke(u, b, off, value)
                }
            }
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

    private fun releaseFor(v: Int): String? = when (v) {
        21 -> "5.0"; 22 -> "5.1"; 23 -> "6.0"; 24 -> "7.0"; 25 -> "7.1"
        26 -> "8.0"; 27 -> "8.1"; 28 -> "9"; 29 -> "10"; 30 -> "11"
        31 -> "12"; 32 -> "12"; 33 -> "13"; 34 -> "14"; 35 -> "15"; 36 -> "16"
        37 -> "17"
        else -> null
    }
}
