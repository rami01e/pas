// spoofcore.kt v2.9.2

package com.kimera.pas.spoof

import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import io.github.libxposed.api.XposedModule
import java.lang.reflect.Field

/**
 * Per-app SDK / ABI spoof for the scoped process.
 *
 * v2.4.5: GPU profile now carries core count, L2 cache and architecture so
 * DevCheck's Mali probe sees a fully coherent device.
 *
 * v2.9.1: ANTI-EMU does NOT duplicate the ABI spoof. The "abi_enabled"
 * toggle stays the single owner of Build.CPU_ABI / CPU_ABI2 /
 * SUPPORTED_*_ABIS / os.arch. The anti-emu Java layer only masks what no
 * other toggle covers (os.version / os.name). For a coherent arm64 story
 * run with BOTH toggles ON: anti-emu owns the native side (props, /proc
 * content, uname), the abi toggle owns the Java Build fields.
 *
 * v2.9.2: init() now runs apply(prefs) SYNCHRONOUSLY before returning, so
 * nativeSetCpu / nativeSetCpuClusters have landed before the target app's
 * main thread can read /proc/cpuinfo. The old 5 s background re-apply left
 * a race in which fast-starting x86_64 apps (e.g. the x86 build of
 * DevCheck) read raw Intel cpuinfo before the cluster table was populated,
 * causing DevCheck to report the host's cores as separate clusters instead
 * of the spoofed ARM cluster layout. A short background re-apply loop
 * remains for late-arriving native state.
 */
object SpoofCore {

    private const val TAG = "PerAppSpoofer"
    const val GROUP = "pas_spoof"

    // vNEXT: kernel identity reported by uname(2) and /proc/version. The
    // native anti-emu layer rewrites both; os.version uses the same release
    // so Java and native readers cannot disagree. Override per device if a
    // specific profile needs an exact vendor string.
    private const val ANTI_EMU_KERNEL_RELEASE = "5.4.163-perf+"
    private const val ANTI_EMU_KERNEL_VERSION = "#1 SMP PREEMPT Tue Oct 15 09:12:33 UTC 2024"

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
        cpuImplementer: String,
        cpuHardware: String
    )

    // v2.5.9: clusters carries the legacy counts string ("2+6"), clusterSpec a
    // per-cluster table "cores:part:minKHz:maxKHz:revision;..." (may be empty).
    external fun nativeSetCpuClusters(cpuOn: Boolean, clusters: String, clusterSpec: String)

    // v2.4.5: GPU now carries core count / L2 cache / architecture.
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
        gpuDriverInfo: String,
        gpuVkDeviceName: String,
        gpuCores: Int,
        l2CacheKb: Int,
        gpuArch: String
    )

    external fun nativeSetGpuProfile(
        gpuOn: Boolean,
        confMajor: Int,
        confMinor: Int,
        confSub: Int,
        confPatch: Int,
        driverId: Int,
        descriptorIndexing: Boolean,
        sparseBinding: Boolean
    )

    external fun nativeSetRecon(reconOn: Boolean)

    external fun nativeSetWebrtcMode(mode: Int)

    external fun nativeSetNetCellular(cellular: Boolean)

    external fun nativeSetBootloader(value: String)

    external fun nativeSetGpuOptions(chain: Boolean, vulkan: Boolean)

    external fun nativeSetSslUnpin(on: Boolean)

    external fun nativeSetSslArm64(on: Boolean)

    // vNEXT: kernel identity for native readers (uname release/version and
    // /proc/version). Must match the Java os.version spoof below.
    external fun nativeSetKernelSpoof(on: Boolean, release: String, version: String)

    // v2.9.0: master switch for the native ANTI-EMU layer (hide_antiemu.cpp).
    // Java-side extras live in applyAntiEmuJavaExtras(); there is deliberately
    // no second ABI toggle here - the abiOn block in apply() remains the only
    // owner of the Java ABI fields.
    external fun nativeSetAntiEmu(on: Boolean)

    // vNEXT: adb-root family prop spoof (service.adb.root / ro.adb.secure / ...).
    // Lives in the always-on prop layer (hide_props.cpp), independent of the
    // anti-emu toggle. Default ON via adb_spoof_enabled.
    external fun nativeSetAdbSpoof(on: Boolean)

    fun init(module: XposedModule) {
        // v2.9.2: apply synchronously. This guarantees nativeSetCpu and
        // nativeSetCpuClusters have run before init() returns, i.e. before
        // the target app's main thread starts touching /proc/cpuinfo. The
        // previous design launched a background thread whose first apply()
        // could lose the race against fast-starting x86_64 apps, producing
        // legacy-layout cpuinfo (host cores shown as separate clusters).
        val prefs: SharedPreferences? = try {
            module.getRemotePreferences(GROUP)
        } catch (t: Throwable) {
            Log.i(TAG, "[PAS] spoof: no remote prefs ($t) - defaults")
            null
        }
        if (prefs == null) {
            runCatching { nativeSetConfig(false, 0, false, 0, true, false) }
            runCatching { nativeSetAntiEmu(false) }
            return
        }

        // Synchronous first apply - no Thread wrapper, no sleep.
        try {
            apply(prefs)
        } catch (t: Throwable) {
            Log.w(TAG, "[PAS] spoof: sync apply failed: ${t.message}")
        }

        // Background short-retry loop: some native setters can land
        // marginally after the sync apply returns (library load order, cold
        // caches). Retry a handful of times with tiny sleeps - total extra
        // latency ~250 ms instead of the previous 5 s.
        Thread({
            repeat(5) {
                try {
                    Thread.sleep(50)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                runCatching { apply(prefs) }
            }
            Log.i(TAG, "[PAS] spoof: remote prefs attached")
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
        val sdkEff = if (sdkVal < 35) 35 else sdkVal

        SpoofState.widevineOn = prefs.getBoolean("widevine_enabled", false)
        SpoofState.widevineId = (prefs.getString("widevine_id", "") ?: "").lowercase()
        SpoofState.gsfOn = prefs.getBoolean("gsf_enabled", false)
        SpoofState.gsfId = (prefs.getString("gsf_id", "") ?: "").trim()
        SpoofState.netCellular = prefs.getBoolean("net_cellular", false)
        SpoofState.antiEmuOn = prefs.getBoolean("anti_emu_enabled", false)

        val reconOn = prefs.getBoolean("recon_enabled", false)
        SpoofState.reconOn = reconOn
        runCatching { nativeSetRecon(reconOn) }

        val modeStr = prefs.getString("webrtc_mode", null)
        SpoofState.webrtcMode = when (modeStr) {
            "balanced" -> 1
            "rkn" -> 2
            "java" -> 3
            "relaxed" -> 0
            else -> if (prefs.getBoolean("webrtc_localip", true)) 1 else 2
        }
        runCatching { nativeSetWebrtcMode(SpoofState.webrtcMode) }

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
        runCatching { nativeSetAntiEmu(SpoofState.antiEmuOn) }
        runCatching {
            nativeSetKernelSpoof(
                SpoofState.antiEmuOn,
                ANTI_EMU_KERNEL_RELEASE,
                ANTI_EMU_KERNEL_VERSION
            )
        }
        if (SpoofState.antiEmuOn) applyAntiEmuJavaExtras()
        // vNEXT: adb-root family (default ON) - service.adb.root=1 is an
        // emulator/root tell; spoof it at the always-on prop layer so it no
        // longer depends on anti_emu_enabled.
        runCatching { nativeSetAdbSpoof(prefs.getBoolean("adb_spoof_enabled", true)) }

        val procName = try {
            java.io.File("/proc/self/cmdline").readText().replace('\u0000', ' ')
        } catch (t: Throwable) {
            ""
        }
        val browserProc = procName.contains("chrome", true) || procName.contains("webview", true)
        SpoofState.relaxNet = SpoofState.webrtcMode == 0 ||
            (SpoofState.webrtcMode == 1 && browserProc)
        runCatching {
            nativeSetGpuOptions(
                prefs.getBoolean("gpu_chain", true),
                prefs.getBoolean("gpu_vulkan", true)
            )
        }

        val sslOn = prefs.getBoolean("ssl_unpin_enabled", false)
        val sslModeStr = prefs.getString("ssl_unpin_mode", "both") ?: "both"
        val sslMode = if (!sslOn) 0 else when (sslModeStr) {
            "java" -> 1
            "native" -> 2
            "both" -> 3
            else -> 3
        }
        SpoofState.sslUnpinMode = sslMode
        runCatching { nativeSetSslUnpin(sslMode == 2 || sslMode == 3) }

        val sslArm64 = sslMode == 2 || sslMode == 3
        runCatching { nativeSetSslArm64(sslArm64) }

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

        runCatching {
            nativeSetCpu(
                cpuOn = cpuOnEff,
                cpuDisplay = cpuEntry.display,
                cpuMfr = cpuEntry.manufacturer,
                cpuModel = cpuEntry.socModel,
                cpuPart = cpuEntry.part,
                cpuInfoModel = cpuEntry.cpuinfoModel,
                cpuFeatures = cpuEntry.features,
                cpuMinKHz = cpuEntry.minKHz,
                cpuMaxKHz = cpuEntry.maxKHz,
                cpuHwLine = cpuEntry.hardwareLine.ifEmpty {
                    "${cpuEntry.hardware} (Samsung board based on ${cpuEntry.socModel})"
                },
                cpuImplementer = cpuEntry.implementer,
                cpuHardware = cpuEntry.hardware
            )
        }
        runCatching {
            nativeSetCpuClusters(
                cpuOn = cpuOnEff,
                clusters = cpuEntry.clusters,
                clusterSpec = DeviceCatalog.clusterSpec(cpuEntry)
            )
        }
        // v2.4.5: pass the new GPU physical-characteristics fields.
        runCatching {
            nativeSetGpu(
                gpuOnEff, gpuEntry.vendor, gpuEntry.renderer, gpuEntry.glVersion,
                gpuEntry.vendorId, gpuEntry.deviceId, gpuEntry.driverVersion,
                gpuEntry.apiVersion, gpuEntry.driverName, gpuEntry.driverInfo,
                gpuEntry.vkDeviceName,
                gpuEntry.gpuCores, gpuEntry.l2CacheKb, gpuEntry.gpuArch
            )
        }
        runCatching {
            nativeSetGpuProfile(
                gpuOnEff,
                (gpuEntry.conformance shr 24) and 0xFF,
                (gpuEntry.conformance shr 16) and 0xFF,
                (gpuEntry.conformance shr 8) and 0xFF,
                gpuEntry.conformance and 0xFF,
                gpuEntry.driverId,
                gpuEntry.descriptorIndexing,
                gpuEntry.sparseBinding
            )
        }

        runCatching {
            nativeSetConfig(useSdk, if (useSdk) sdkEff else 0, abiOn, abiMode, compat, nativeOn)
        }

        if (!nativeOn) return

        var ok = 0
        var fail = 0

        fun patch(clazz: Class<*>, name: String, value: Any?, label: String) {
            val r = unsafeSet(clazz, name, value) || fallbackSet(clazz, name, value)
            if (r) ok++ else { fail++; Log.i(TAG, "[PAS] spoof: java field FAILED: $label") }
        }

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
        Log.i(TAG, "[PAS] spoof applied: sdk=$useSdk/$sdkEff abi=$abiOn mode=$abiMode cpu=$cpuOnEff gpu=$gpuOnEff compat=$compat antiEmu=${SpoofState.antiEmuOn} java ok=$ok fail=$fail")
    }

    /**
     * v2.9.1 ANTI-EMU Java extras. Deliberately does NOT touch
     * Build.CPU_ABI / CPU_ABI2 / SUPPORTED_*_ABIS / os.arch - those already
     * have a single owner (the abiOn block above, driven by its own toggle).
     * Only the uname-derived java.lang.System properties, which no other
     * feature covers, are masked here so MuMu's real x86-host kernel string
     * (6.1.90-perf+) never reaches Java-side probes. System properties are
     * read live via System.getProperty, so a late set is still effective for
     * anything that reads them after module init.
     */
    private fun applyAntiEmuJavaExtras() {
        runCatching {
            System.setProperty("os.version", ANTI_EMU_KERNEL_RELEASE)
            System.setProperty("os.name", "Linux")
        }.onFailure {
            Log.w(TAG, "[PAS] spoof: anti-emu java extras failed: ${it.message}")
        }
    }

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