package com.kimera.novpndetect.spoof

/**
 * Shared CPU / GPU model catalogs.
 *
 * The GUI builds its pickers from these lists, and the config core resolves
 * the saved selection into the exact values pushed to the native layer and
 * the Java Build fields, so every surface (cpuinfo, cpufreq, properties,
 * OpenGL, Vulkan) stays consistent.
 *
 * Catalog scope: Samsung devices released 2022-2026. CPUs = Exynos +
 * Snapdragon (+ the two MediaTek parts used in the budget A-series); GPUs =
 * ARM Mali + Adreno. Note: Exynos 1480 / 1580 / 2200 / 2400 use AMD Xclipse
 * GPUs on real hardware - spoof them with a Mali profile only as a test.
 *
 * GPU identity values are matched to the reference devices where verified
 * (Mali-G52: 0x72120000; Adreno 640/650/660); entries marked "approx" use
 * best-effort values for test scope.
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

    private const val AARCH64_MODEL = "AArch64 Processor rev 14 (aarch64)"

    data class Cpu(
        val display: String,
        val manufacturer: String,
        /** Build.SOC_MODEL / ro.soc.model. */
        val socModel: String,
        /** ARM "CPU part" value used in /proc/cpuinfo (hex; representative core). */
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
        // ---- Exynos (2022-2026 devices + the reference E850) ----
        Cpu(
            "Samsung Exynos 850", "Samsung", "S5E3830", "0x0d05",
            "ARMv8 Processor rev 1 (v8)", FEATURES_ARM32, "exynos850", 546000, 2002000
        ), // Galaxy A13 (reference profile)
        Cpu(
            "Samsung Exynos 1280", "Samsung", "S5E8825", "0xd41",
            AARCH64_MODEL, FEATURES_ARM64, "exynos1280", 300000, 2200000
        ), // A33 / A53 / A25 - Mali-G68
        Cpu(
            "Samsung Exynos 1330", "Samsung", "S5E8535", "0xd41",
            AARCH64_MODEL, FEATURES_ARM64, "exynos1330", 300000, 2400000
        ), // A16 5G - Mali-G68 MP2
        Cpu(
            "Samsung Exynos 1380", "Samsung", "S5E8835", "0xd41",
            AARCH64_MODEL, FEATURES_ARM64, "exynos1380", 300000, 2400000
        ), // A35 / A54 - Mali-G68 MP5
        Cpu(
            "Samsung Exynos 1480", "Samsung", "S5E8845", "0xd41",
            AARCH64_MODEL, FEATURES_ARM64, "exynos1480", 300000, 2750000
        ), // A55 (Xclipse 530 on real hardware)
        Cpu(
            "Samsung Exynos 1580", "Samsung", "S5E8855", "0xd47",
            AARCH64_MODEL, FEATURES_ARM64, "exynos1580", 300000, 2900000
        ), // A56 (Xclipse 550 on real hardware)
        Cpu(
            "Samsung Exynos 2200", "Samsung", "S5E9925", "0xd48",
            AARCH64_MODEL, FEATURES_ARM64, "exynos2200", 300000, 2802000
        ), // S22 global (Xclipse 920)
        Cpu(
            "Samsung Exynos 2400", "Samsung", "S5E9945", "0xd4d",
            AARCH64_MODEL, FEATURES_ARM64, "exynos2400", 300000, 3200000
        ), // S24 / S24+ global, S24 FE (Xclipse 940)

        // ---- Snapdragon (US Samsung flagship / midrange) ----
        Cpu(
            "Qualcomm Snapdragon 888", "Qualcomm", "SM8350", "0xd44",
            AARCH64_MODEL, FEATURES_ARM64, "lahaina", 300000, 2841600
        ), // S21 FE (2022) - Adreno 660
        Cpu(
            "Qualcomm Snapdragon 8 Gen 1", "Qualcomm", "SM8450", "0xd48",
            AARCH64_MODEL, FEATURES_ARM64, "waipio", 300000, 3000000
        ), // S22 US / Tab S8 - Adreno 730
        Cpu(
            "Qualcomm Snapdragon 8+ Gen 1", "Qualcomm", "SM8475", "0xd48",
            AARCH64_MODEL, FEATURES_ARM64, "cape", 300000, 3200000
        ), // Z Fold4 / Flip4 - Adreno 730
        Cpu(
            "Qualcomm Snapdragon 8 Gen 2", "Qualcomm", "SM8550", "0xd4d",
            AARCH64_MODEL, FEATURES_ARM64, "kalama", 300000, 3200000
        ), // S23 US / Z Fold5 - Adreno 740
        Cpu(
            "Qualcomm Snapdragon 8 Gen 3", "Qualcomm", "SM8650", "0xd4d",
            AARCH64_MODEL, FEATURES_ARM64, "pineapple", 300000, 3300000
        ), // S24 US / Z Fold6 - Adreno 750
        Cpu(
            "Qualcomm Snapdragon 8 Elite", "Qualcomm", "SM8750", "0xd4d",
            AARCH64_MODEL, FEATURES_ARM64, "sun", 300000, 4320000
        ), // S25 series US / Z Fold7 - Adreno 830
        Cpu(
            "Qualcomm Snapdragon 778G", "Qualcomm", "SM7325", "0xd41",
            AARCH64_MODEL, FEATURES_ARM64, "yupik", 300000, 2400000
        ), // A73 5G / A52s - Adreno 642L
        Cpu(
            "Qualcomm Snapdragon 695", "Qualcomm", "SM6375", "0xd41",
            AARCH64_MODEL, FEATURES_ARM64, "holi", 300000, 2200000
        ), // A23 5G - Adreno 619
        Cpu(
            "Qualcomm Snapdragon 680", "Qualcomm", "SM6225", "0xd09",
            AARCH64_MODEL, FEATURES_ARM64, "khaje", 300000, 2400000
        ), // A23 4G - Adreno 610

        // ---- MediaTek (budget A-series) ----
        Cpu(
            "MediaTek Helio G85", "MediaTek", "MT6769Z", "0xd0a",
            AARCH64_MODEL, FEATURES_ARM64, "mt6769", 300000, 2000000
        ), // A05 - Mali-G52 MC2
        Cpu(
            "MediaTek Dimensity 6300", "MediaTek", "MT6835", "0xd0b",
            AARCH64_MODEL, FEATURES_ARM64, "mt6835", 300000, 2400000
        ), // A16 5G (regional) - Mali-G57 MC2
    )

    private fun adreno(
        renderer: String,
        deviceId: Long,
        api: Long,
        gl: String
    ) = Gpu(
        "Qualcomm", renderer, 0x5143L, deviceId, vk(512, 615, 0), api,
        "Qualcomm Technologies Inc. Adreno Vulkan Driver", renderer, gl
    )

    private fun mali(renderer: String, deviceId: Long) = Gpu(
        "ARM", renderer, 0x13B5L, deviceId, vk(38, 1, 0), vk(1, 3, 213),
        renderer, MALI_INFO, "OpenGL ES 3.2 $MALI_INFO"
    )

    val GPUS = listOf(
        // ---- ARM Mali (Exynos pairing) ----
        mali("Mali-G52 MC2", 0x72120000L), // Exynos 850 (verified id)
        mali("Mali-G68", 0x90060000L), // Exynos 1280 (approx id)
        mali("Mali-G68 MP2", 0x90060000L), // Exynos 1330 (approx id)
        mali("Mali-G68 MP5", 0x90060000L), // Exynos 1380 (approx id)
        mali("Mali-G76 MP12", 0x72110000L), // older Exynos (approx id)
        mali("Mali-G77 MP11", 0x90030000L), // Exynos 990 (approx id)
        mali("Mali-G78 MP14", 0x90040000L), // Exynos 2100 (approx id)

        // ---- Adreno (Snapdragon pairing) ----
        adreno("Adreno (TM) 640", 0x6040001L, vk(1, 1, 128), "OpenGL ES 3.2 V@0490.0"),
        adreno("Adreno (TM) 650", 0x6050002L, vk(1, 1, 128), "OpenGL ES 3.2 V@0530.0"),
        adreno("Adreno (TM) 660", 0x6060001L, vk(1, 1, 128), "OpenGL ES 3.2 V@0571.0"),
        adreno("Adreno (TM) 610", 0x6010001L, vk(1, 1, 128), "OpenGL ES 3.2 V@0415.0"),
        adreno("Adreno (TM) 619", 0x6019002L, vk(1, 1, 128), "OpenGL ES 3.2 V@0460.0"),
        adreno("Adreno (TM) 642L", 0x6420001L, vk(1, 1, 128), "OpenGL ES 3.2 V@0571.0"),
        adreno("Adreno (TM) 730", 0x7030001L, vk(1, 3, 0), "OpenGL ES 3.2 V@0680.0"),
        adreno("Adreno (TM) 740", 0x7040001L, vk(1, 3, 0), "OpenGL ES 3.2 V@0703.0"),
        adreno("Adreno (TM) 750", 0x7050001L, vk(1, 3, 0), "OpenGL ES 3.2 V@0715.0"),
        adreno("Adreno (TM) 830", 0x8030001L, vk(1, 3, 0), "OpenGL ES 3.2 V@0840.0"),
    )

    fun cpu(display: String?): Cpu = CPUS.firstOrNull { it.display == display } ?: CPUS[0]

    fun gpu(renderer: String?): Gpu = GPUS.firstOrNull { it.renderer == renderer } ?: GPUS[0]
}
