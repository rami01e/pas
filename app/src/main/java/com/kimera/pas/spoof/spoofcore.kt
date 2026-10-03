package com.kimera.pas.spoof

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
 * preferences (group "pas_spoof").
 */
object SpoofCore {

    private const val TAG = "PerAppSpoofer"
    const val GROUP = "pas_spoof"

    external fun nativeSetConfig(
        sdkOn: Boolean,
        sdkVal: Int,
        abiOn: Boolean,
        abiMode: Int,
        compatMode: Boolean,
        nativeEnabled: Boolean
    )

    external fun nativeSetCpu(
        cpuOn: Boolean,
        cpuDisplay: String,
        cpuMfr: String,
        cpuModel: String,
        cpuPart: String,
        cpuInfoModel: String,
        cpuFeatures: String,
        cpuMinKHz: Int,
        cpuMaxKHz: Int,
        cpuHwLine: String,
        cpuHardware: String
    )

    external fun nativeSetGpu(
        gpuOn: Boolean,
        gpuVendor: String,
        gpuRenderer: String,
        gpuGlVersion: String,
        gpuVendorId: Long,
        gpuDeviceId: Long,
        gpuDriverVersion: Long,
        gpuApiVersion: Long,
        gpuDriverName: String,
        gpuDriverInfo: String
    )

    external fun nativeSetRecon(reconOn: Boolean)

    external fun nativeSetWebrtcMode(mode: Int)

    external fun nativeSetNetCellular(cellular: Boolean)

    external fun nativeSetBootloader(value: String)

    external fun nativeSetGpuOptions(chain: Boolean, vulkan: Boolean)

    // >>> v2.3.0: native TLS verification bypass (hide_ssl.cpp)
    external fun nativeSetSslUnpin(on: Boolean)

    /** Called from XposedInit.onPackageReady (once per process). */
    fun init(module: XposedModule) {
        Thread({
            val prefs: SharedPreferences? = try {
                module.getRemotePreferences(GROUP)
            } catch (t: Throwable) {
                Log.i(TAG, "[PAS] spoof: no remote prefs ($t) - defaults")
                null
            }
            if (prefs == null) {
                // Release the native hook gate with safe defaults (addon off).
                runCatching { nativeSetConfig(false, 0, false, 0, true, false) }
            } else {
                apply(prefs)
                try {
                    Thread.sleep(5000)
                } catch (_: InterruptedException) {
                }
                apply(prefs)
                Log.i(TAG, "[PAS] spoof: remote prefs attached")
            }
        }, "pas-spoof").start()
    }

    private fun apply(prefs: SharedPreferences) {
        val nativeOn = prefs.getBoolean("native_enabled", true)
        val sdkOn = prefs.getBoolean("sdk_enabled", false)
        var sdkVal = prefs.getInt("sdk_value", 0)
        val abiOn = prefs.getBoolean("abi_enabled", false)
        val abiMode = when (prefs.getString("abi_value", "x86_64")) {
            "arm64+armeabi" -> 1
            "arm64-v8a", "mixed" -> 2
            else -> 0
        }
        val compat = prefs.getBoolean("safe_mode", false)
        if (sdkVal !in 21..45) sdkVal = 0
        val useSdk = sdkOn && sdkVal != 0
        // WebView provider safety: Chromium 6432+ needs AconfigPackage.load()
        // (SDK 35+). Reporting lower makes the provider crash and every
        // webview in the app silently die - the Big Farm / Sunshine stall.
        val sdkEff = if (sdkVal < 35) 35 else sdkVal

        // Java-only id spoofs: available regardless of the native addon.
        SpoofState.widevineOn = prefs.getBoolean("widevine_enabled", false)
        SpoofState.widevineId = (prefs.getString("widevine_id", "") ?: "").lowercase()
        SpoofState.gsfOn = prefs.getBoolean("gsf_enabled", false)
        SpoofState.gsfId = (prefs.getString("gsf_id", "") ?: "").trim()
        Log.i(
            TAG,
            "[PAS] id spoof: widevine=${SpoofState.widevineOn} gsf=${SpoofState.gsfOn}"
        )
        SpoofState.netCellular = prefs.getBoolean("net_cellular", false)

        // Recon diagnostics toggle: independent of the native addon gate, but
        // delivered before nativeSetConfig so the native worker can install
        // the recon hook group when it starts.
        val reconOn = prefs.getBoolean("recon_enabled", true)
        SpoofState.reconOn = reconOn
        runCatching { nativeSetRecon(reconOn) }
        Log.i(TAG, "[PAS] recon logging: $reconOn")

        // "WebRTC local IP" option (default: visible/realistic). Consumed live
        // by the network-interface hooks.
        val modeStr = prefs.getString("webrtc_mode", null)
        SpoofState.webrtcMode = when (modeStr) {
            "balanced" -> 1
            "rkn" -> 2
            "java" -> 3
            "relaxed" -> 0
            else -> if (prefs.getBoolean("webrtc_localip", true)) 1 else 2
        }
        runCatching { nativeSetWebrtcMode(SpoofState.webrtcMode) }
        // Bootloader: MuMu reports "unknown"; a real Samsung mirrors
        // ro.build.version.incremental. Mirror it automatically per-app.
        runCatching {
            if (Build.BOOTLOADER == "unknown") {
                val sp = Class.forName("android.os.SystemProperties")
                val inc = sp.getMethod("get", String::class.java)
                    .invoke(null, "ro.build.version.incremental") as? String
                if (!inc.isNullOrBlank()) {
                    SpoofState.bootloader = inc.trim()
                }
            }
        }
        SpoofState.netCellularNative = SpoofState.netCellular
        runCatching { nativeSetNetCellular(SpoofState.netCellular) }
        val procName = try {
            java.io.File("/proc/self/cmdline").readText().replace('\u0000', ' ')
        } catch (t: Throwable) {
            ""
        }
        val browserProc = procName.contains("chrome", true) || procName.contains("webview", true)
        SpoofState.relaxNet = SpoofState.webrtcMode == 0 ||
            (SpoofState.webrtcMode == 1 && browserProc)
        Log.i(TAG, "[PAS] net: relax=${SpoofState.relaxNet} proc=$procName")
        runCatching {
            nativeSetGpuOptions(
                prefs.getBoolean("gpu_chain", true),
                prefs.getBoolean("gpu_vulkan", true)
            )
        }
        // >>> v2.3.0: native TLS verification bypass. Default ON; delivered
        // before nativeSetConfig so the native worker sees it on wake-up.
        val sslUnpin = prefs.getBoolean("ssl_unpin", true)
        runCatching { nativeSetSslUnpin(sslUnpin) }
        Log.i(TAG, "[PAS] ssl unpin: $sslUnpin")
        Log.i(TAG, "[PAS] net: webrtc mode = ${SpoofState.webrtcMode}")

        // CPU / GPU spoof values (resolved from the shared catalog; active only
        // together with the native addon so all surfaces stay consistent).
        val cpuEntry = DeviceCatalog.cpu(prefs.getString("cpu_value", null))
        val gpuEntry = DeviceCatalog.gpu(prefs.getString("gpu_value", null))
        val cpuOnEff = prefs.getBoolean("cpu_enabled", false) && nativeOn
        val gpuOnEff = prefs.getBoolean("gpu_enabled", false) && nativeOn
        SpoofState.cpuOn = cpuOnEff
        SpoofState.cpuDisplay = cpuEntry.display
        SpoofState.cpuManufacturer = cpuEntry.manufacturer
        SpoofState.cpuModel = cpuEntry.socModel
        SpoofState.gpuOn = gpuOnEff
        SpoofState.gpuVendor = gpuEntry.vendor
        SpoofState.gpuRenderer = gpuEntry.renderer
        SpoofState.gpuGlVersion = gpuEntry.glVersion
        Log.i(
            TAG,
            "[PAS] cpu/gpu spoof: cpu=$cpuOnEff (${cpuEntry.display}) " +
                "gpu=$gpuOnEff (${gpuEntry.renderer})"
        )
        // Delivered before the config gate so the native worker can decide
        // whether to install the CPU/GPU hook groups right away.
        runCatching {
            nativeSetCpu(
                cpuOnEff, cpuEntry.display, cpuEntry.manufacturer, cpuEntry.socModel,
                cpuEntry.part, cpuEntry.cpuinfoModel, cpuEntry.features,
                cpuEntry.minKHz, cpuEntry.maxKHz,
                cpuEntry.hardwareLine.ifEmpty {
                    "${cpuEntry.hardware} (Samsung board based on ${cpuEntry.socModel})"
                },
                cpuEntry.hardware
            )
        }
        runCatching {
            nativeSetGpu(
                gpuOnEff, gpuEntry.vendor, gpuEntry.renderer, gpuEntry.glVersion,
                gpuEntry.vendorId, gpuEntry.deviceId, gpuEntry.driverVersion,
                gpuEntry.apiVersion, gpuEntry.driverName, gpuEntry.driverInfo
            )
        }

        // Always deliver the config first: it releases the native hook gate
        // (native addon on/off + compatibility mode).
        runCatching {
            nativeSetConfig(useSdk, if (useSdk) sdkEff else 0, abiOn, abiMode, compat, nativeOn)
        }

        if (!nativeOn) {
            Log.i(TAG, "[PAS] spoof: native addon disabled - Java hooks only")
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
                Log.i(TAG, "[PAS] spoof: java field FAILED: $label")
            }
        }

        // WebView provider safety: Chromium 6432+ calls AconfigPackage.load(),
        // an API that exists only on SDK 35+. Reporting a lower SDK makes the
        // provider crash (NoSuchMethodError) and every webview in the app
        // silently dies - the Big Farm / Sunshine stall. The provider
        // processes see the truth; other processes may still be clamped to
        // the true device SDK as the floor.
        // Legacy Java SDK patch: OFF by default. Chromium reads SDK_INT_FULL
        // and AconfigPackage.load() - APIs tied to the REAL SDK level - so a
        // patched SDK_INT can crash the WebView provider in modern apps.
        // Enable only per-app when a target needs the Java-level number.
        if (useSdk && prefs.getBoolean("sdk_java_enabled", false)) {
            patch(Build.VERSION::class.java, "SDK_INT", sdkEff, "SDK_INT")
            releaseFor(sdkEff)?.let { patch(Build.VERSION::class.java, "RELEASE", it, "RELEASE") }
        }
        if (SpoofState.bootloader.isNotEmpty()) {
            patch(Build::class.java, "BOOTLOADER", SpoofState.bootloader, "BOOTLOADER")
        }
        if (cpuOnEff) {
            patch(Build::class.java, "SOC_MANUFACTURER", cpuEntry.manufacturer, "SOC_MANUFACTURER")
            patch(Build::class.java, "SOC_MODEL", cpuEntry.socModel, "SOC_MODEL")
            patch(Build::class.java, "HARDWARE", cpuEntry.hardware, "HARDWARE")
            patch(Build::class.java, "BOARD", cpuEntry.hardware, "BOARD")
        }
        if (abiOn) {
            val abi = if (abiMode == 0) "x86_64" else "arm64-v8a"
            val abi2 = if (abiMode == 1) "armeabi-v7a" else "arm64-v8a"
            val all = when (abiMode) {
                1 -> arrayOf("arm64-v8a", "armeabi-v7a", "armeabi")
                2 -> arrayOf("arm64-v8a")
                else -> arrayOf("x86_64", "arm64-v8a", "x86")
            }
            val a64 = when (abiMode) {
                1 -> arrayOf("arm64-v8a")
                2 -> arrayOf("arm64-v8a")
                else -> arrayOf("x86_64", "arm64-v8a")
            }
            val a32 = when (abiMode) {
                1 -> arrayOf("armeabi-v7a", "armeabi")
                2 -> emptyArray<String>()
                else -> arrayOf("x86")
            }
            patch(Build::class.java, "CPU_ABI", abi, "CPU_ABI")
            patch(Build::class.java, "CPU_ABI2", abi2, "CPU_ABI2")
            patch(Build::class.java, "SUPPORTED_ABIS", all, "SUPPORTED_ABIS")
            patch(Build::class.java, "SUPPORTED_64_BIT_ABIS", a64, "SUPPORTED_64_BIT_ABIS")
            patch(Build::class.java, "SUPPORTED_32_BIT_ABIS", a32, "SUPPORTED_32_BIT_ABIS")
            runCatching { System.setProperty("os.arch", if (abiMode == 0) "x86_64" else "aarch64") }
        }
        Log.i(
            TAG,
            "[PAS] spoof applied: sdk=$useSdk/$sdkEff abi=$abiOn mode=$abiMode cpu=$cpuOnEff gpu=$gpuOnEff compat=$compat java ok=$ok fail=$fail"
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