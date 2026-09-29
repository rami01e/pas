package com.kimera.novpndetect.spoof

/**
 * Shared CPU / GPU model catalogs.
 *
 * The GUI builds its pickers from these lists, and the config core resolves
 * the saved selection into the exact values pushed to the native layer and
 * the Java Build fields, so every surface (cpuinfo, cpufreq, properties,
 * OpenGL, Vulkan) stays consistent.
 *
 * GPU identity values are matched to the reference devices where known
 * (Mali-G52 family: device 0x72120000; Adreno 640/650/660 per the ncnn
 * table); Valhall / PowerVR entries use best-effort values for test scope.
 */
object DeviceCatalog {

    /** arm64-style feature list used for most chips. */
    private const val FEATURES_ARM64 = "fp asimd evtstrm aes pmull sha1 sha2 crc32"

    /** 32-bit style list as printed by the reference Exynos 850 kernel. */
    private const val FEATURES_ARM32 =
        "half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt lpae evtstrm aes pmull sha1 sha2 crc32"

    /** Mali driver info string (r38p1, as reported by the reference device). */
    private const val MALI_INFO =
        "v1.r38p1-01bet0-mbs2v41_0.6d20ec041e51b2f2d25dfc265586ebe8"

    data class Cpu(
        val display: String,
        val manufacturer: String,
        /** Build.SOC_MODEL / ro.soc.model. */
        val socModel: String,
        /** ARM "CPU part" value used in /proc/cpuinfo (hex). */
        val part: String,
        /** /proc/cpuinfo "model name" per core. */
        val cpuinfoModel: String,
        /** /proc/cpuinfo "Features" list. */
        val features: String,
        /** Build.HARDWARE / Build.BOARD platform name. */
        val hardware: String,
        /** /sys cpufreq min/max, kHz. */
        val minKHz: Int,
        val maxKHz: Int
    )

    data class Gpu(
        val vendor: String,
        val renderer: String,
        val vendorId: Long,
        val deviceId: Long,
        /** Packed VkDriverVersion ((major shl 22) or (minor shl 12) or patch). */
        val driverVersion: Long,
        /** Packed Vulkan apiVersion (same packing). */
        val apiVersion: Long,
        val driverName: String,
        val driverInfo: String,
        /** glGetString(GL_VERSION) replacement. */
        val glVersion: String
    )

    private fun vk(major: Int, minor: Int, patch: Int): Long =
        (major.toLong() shl 22) or (minor.toLong() shl 12) or patch.toLong()

    val CPUS = listOf(
        Cpu(
            "Qualcomm Snapdragon 8 Gen 2", "Qualcomm", "SM8550", "0xd4d",
            "AArch64 Processor rev 14 (aarch64)", FEATURES_ARM64, "kalama", 300000, 3200000
        ),
        Cpu(
            "Qualcomm Snapdragon 888", "Qualcomm", "SM8350", "0xd44",
            "AArch64 Processor rev 14 (aarch64)", FEATURES_ARM64, "lahaina", 300000, 2841600
        ),
        Cpu(
            "Qualcomm Snapdragon 855", "Qualcomm", "SM8150", "0xd0b",
            "AArch64 Processor rev 14 (aarch64)", FEATURES_ARM64, "msmnile", 300000, 2841600
        ),
        Cpu(
            "Qualcomm Snapdragon 660", "Qualcomm", "SDM660", "0xd09",
            "AArch64 Processor rev 14 (aarch64)", FEATURES_ARM64, "sdm660", 300000, 2208000
        ),
        Cpu(
            "Samsung Exynos 2200", "Samsung", "S5E9925", "0xd48",
            "AArch64 Processor rev 14 (aarch64)", FEATURES_ARM64, "exynos2200", 500000, 2802000
        ),
        Cpu(
            "Samsung Exynos 850", "Samsung", "S5E3830", "0x0d05",
            "ARMv8 Processor rev 1 (v8)", FEATURES_ARM32, "exynos850", 546000, 2002000
        ),
        Cpu(
            "MediaTek Dimensity 9300", "MediaTek", "MT6989", "0xd4d",
            "AArch64 Processor rev 14 (aarch64)", FEATURES_ARM64, "mt6989", 300000, 3350000
        ),
        Cpu(
            "MediaTek Helio G85", "MediaTek", "MT6769Z", "0xd0a",
            "AArch64 Processor rev 14 (aarch64)", FEATURES_ARM64, "mt6769", 300000, 2000000
        ),
        Cpu(
            "Google Tensor G3", "Google", "Tensor G3", "0xd4d",
            "AArch64 Processor rev 14 (aarch64)", FEATURES_ARM64, "zumapro", 300000, 2916000
        ),
        Cpu(
            "HiSilicon Kirin 990", "HiSilicon", "Kirin 990", "0xd0b",
            "AArch64 Processor rev 14 (aarch64)", FEATURES_ARM64, "kirin990", 300000, 2860000
        ),
    )

    val GPUS = listOf(
        Gpu(
            "Qualcomm", "Adreno (TM) 640", 0x5143L, 0x6040001L, vk(512, 615, 0), vk(1, 3, 0),
            "Qualcomm Technologies Inc. Adreno Vulkan Driver", "Adreno (TM) 640",
            "OpenGL ES 3.2 V@0490.0"
        ),
        Gpu(
            "Qualcomm", "Adreno (TM) 650", 0x5143L, 0x6050002L, vk(512, 615, 0), vk(1, 3, 0),
            "Qualcomm Technologies Inc. Adreno Vulkan Driver", "Adreno (TM) 650",
            "OpenGL ES 3.2 V@0530.0"
        ),
        Gpu(
            "Qualcomm", "Adreno (TM) 660", 0x5143L, 0x6060001L, vk(512, 615, 0), vk(1, 3, 0),
            "Qualcomm Technologies Inc. Adreno Vulkan Driver", "Adreno (TM) 660",
            "OpenGL ES 3.2 V@0571.0"
        ),
        Gpu(
            "ARM", "Mali-G52 MC2", 0x13B5L, 0x72120000L, vk(38, 1, 0), vk(1, 3, 213),
            "Mali-G52 MC2", MALI_INFO,
            "OpenGL ES 3.2 $MALI_INFO"
        ),
        Gpu(
            "ARM", "Mali-G68 MC4", 0x13B5L, 0x90060000L, vk(38, 1, 0), vk(1, 3, 213),
            "Mali-G68 MC4", MALI_INFO,
            "OpenGL ES 3.2 $MALI_INFO"
        ),
        Gpu(
            "ARM", "Mali-G78 MP14", 0x13B5L, 0x90040000L, vk(38, 1, 0), vk(1, 3, 213),
            "Mali-G78 MP14", MALI_INFO,
            "OpenGL ES 3.2 $MALI_INFO"
        ),
        Gpu(
            "ARM", "Mali-G710 MP10", 0x13B5L, 0x90070000L, vk(38, 1, 0), vk(1, 3, 213),
            "Mali-G710 MP10", MALI_INFO,
            "OpenGL ES 3.2 $MALI_INFO"
        ),
        Gpu(
            "Imagination Technologies", "PowerVR Rogue GE8320", 0x1010L, 0x83200000L, vk(24, 2, 0),
            vk(1, 1, 0), "Imagination Technologies", "PowerVR Rogue GE8320",
            "OpenGL ES 3.2 build 24.2"
        ),
    )

    fun cpu(display: String?): Cpu = CPUS.firstOrNull { it.display == display } ?: CPUS[0]

    fun gpu(renderer: String?): Gpu = GPUS.firstOrNull { it.renderer == renderer } ?: GPUS[0]
}
