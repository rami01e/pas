package com.kimera.pas.spoof

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
 * ARM Mali + Adreno + Samsung Xclipse (AMD RDNA based, Exynos 1480/1580/
 * 2200/2400/2500/2600/8865).
 *
 * v2.4.0: all GPU identity values (vendorID / deviceID / driverVersion /
 * apiVersion / driverName / driverInfo / conformance / feature flags) and
 * the GL_VERSION strings are taken from real devices - vulkan.gpuinfo.org
 * reports cross-checked against deviceinfohw.ru dumps on current Samsung
 * firmware. Entries marked "approx" use the closest verified sibling value.
 *
 * Xclipse notes: GL_VENDOR is "Samsung Electronics Co., Ltd."; GL_RENDERER
 * carries the ANGLE wrapper "ANGLE ((Samsung Xclipse NNN) on Vulkan x.y.z)"
 * while the RAW Vulkan deviceName is just "Samsung Xclipse NNN" - the two
 * are separate fields here so both surfaces stay authentic. vendorID is
 * 0x144D for every Xclipse; Xclipse 920 keeps an AMD-style ASIC id
 * (0x73A0), the newer parts use Samsung ASIC ids (n300100 midrange /
 * n600200 flagship).
 */
object DeviceCatalog {

    /** arm64-style feature list used for most chips. */
    private const val FEATURES_ARM64 = "fp asimd evtstrm aes pmull sha1 sha2 crc32"

    /** 32-bit style list as printed by the reference Exynos 850 kernel. */
    private const val FEATURES_ARM32 =
        "half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt lpae evtstrm aes pmull sha1 sha2 crc32"

    /** Mali driver info string (r38p1, as reported by the reference A13). */
    private const val MALI_INFO_G52 =
        "v1.r38p1-01bet0-mbs2v41_0.6d20ec041e51b2f2d25dfc265586ebe8"

    /** Mali r38p1 build string as shipped on Exynos 1280/1380 class devices. */
    private const val MALI_INFO_R38_EAC0 =
        "v1.r38p1-01eac0-mbs2v41_0.0b37450fbb12e582df79a7906d0ad856"

    /** Mali r38p1 build string as shipped on the Exynos 990 (S20 series). */
    private const val MALI_INFO_G77 =
        "v1.r38p1-01bet0-mbs2v41_0.8320a750c7c9e2666df3500d139b434f"

    /** Mali r38p0 build string as shipped on the Exynos 2100 (S21 series). */
    private const val MALI_INFO_G78 =
        "v1.r38p0-01eac0-mbs2v41_0.4ef6e1c9ba431853d05b271234c3d1c5"

    private const val AARCH64_MODEL = "AArch64 Processor rev 14 (aarch64)"

    data class Cpu(
        val display: String,
        val manufacturer: String,
        /** Build.SOC_MODEL / ro.soc.model. */
        val socModel: String,
        /** ARM "CPU part" value used in /proc/cpuinfo (hex; representative core). */
        val part: String,
        /** ARM "CPU implementer" in /proc/cpuinfo (0x41 ARM, 0x51 Qualcomm Oryon). */
        val implementer: String = "0x41",
        /** /proc/cpuinfo "model name" per core. */
        val cpuinfoModel: String,
        /** /proc/cpuinfo "Features" list. */
        val features: String,
        /**
         * Build.HARDWARE / Build.BOARD / ro.hardware platform name.
         * Real Samsung values: "s5eXXXX" (Exynos), "qcom" (Snapdragon),
         * "mtXXXX" (MediaTek) - verified via deviceinfohw PLATFORM rows.
         */
        val hardware: String,
        /** /sys cpufreq min/max, kHz. */
        val minKHz: Int,
        val maxKHz: Int,
        /**
         * /proc/cpuinfo "Hardware" row. Samsung kernels print the machine
         * string here (e.g. "exynos850 (Samsung A13 EUR OPEN REV02B board
         * based on EXYNOS850)"); hardware-info apps display it. Empty =>
         * a generic variation is derived in SpoofCore.apply().
         */
        val hardwareLine: String = ""
    )

    data class Gpu(
        /** glGetString(GL_VENDOR). */
        val vendor: String,
        /**
         * glGetString(GL_RENDERER) - also the persisted selection key
         * (gpu_value), so it must stay stable across versions.
         */
        val renderer: String,
        /** Short label for the GUI picker / value row. */
        val label: String,
        /** VkPhysicalDeviceProperties::deviceName (raw Vulkan name). */
        val vkDeviceName: String,
        val vendorId: Long,
        val deviceId: Long,
        /** Packed VkDriverVersion ((major shl 22) or (minor shl 12) or patch). */
        val driverVersion: Long,
        /** Packed Vulkan apiVersion (same packing). */
        val apiVersion: Long,
        val driverName: String,
        val driverInfo: String,
        /** glGetString(GL_VERSION) replacement. */
        val glVersion: String,
        /** Packed VK_KHR_driver_properties conformanceVersion (maj shl 24 | min shl 16 | sub shl 8 | patch). */
        val conformance: Int,
        /** Real VkPhysicalDeviceVulkan12Features::descriptorIndexing. */
        val descriptorIndexing: Boolean,
        /** Real VkPhysicalDeviceFeatures::sparseBinding. */
        val sparseBinding: Boolean
    )

    private fun vk(major: Int, minor: Int, patch: Int): Long =
        (major.toLong() shl 22) or (minor.toLong() shl 12) or patch.toLong()

    private fun conf(major: Int, minor: Int, sub: Int, patch: Int): Int =
        (major shl 24) or (minor shl 16) or (sub shl 8) or patch

    val CPUS = listOf(
        // ---- Exynos (2022-2026 devices + the reference E850) ----
        Cpu(
            "Samsung Exynos 850", "Samsung", "S5E3830", "0xd05",
            "0x41", "ARMv8 Processor rev 1 (v8)", FEATURES_ARM32, "exynos850",
            546000, 2002000,
            "exynos850 (Samsung A13 EUR OPEN REV02B board based on EXYNOS850)"
        ), // Galaxy A13 (reference profile; Hardware row verified on the real device)
        Cpu(
            "Samsung Exynos 1280", "Samsung", "S5E8825", "0xd41",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "s5e8825", 300000, 2400000
        ), // A33 / A53 / A25 - Mali-G68
        Cpu(
            "Samsung Exynos 1330", "Samsung", "S5E8535", "0xd41",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "s5e8535", 300000, 2400000
        ), // A16 5G - Mali-G68 MP2
        Cpu(
            "Samsung Exynos 1380", "Samsung", "S5E8835", "0xd41",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "s5e8835", 300000, 2400000
        ), // A35 / A54 - Mali-G68 MP5
        Cpu(
            "Samsung Exynos 1480", "Samsung", "S5E8845", "0xd41",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "s5e8845", 533000, 2750000
        ), // A55 / A37 - Xclipse 530 (clocks verified: 533-2750)
        Cpu(
            "Samsung Exynos 1580", "Samsung", "S5E8855", "0xd81",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "s5e8855", 533000, 2910000
        ), // A56 - Xclipse 540 (clocks verified: 533-2910; big core = Cortex-A720)
        Cpu(
            "Samsung Exynos 2200", "Samsung", "S5E9925", "0xd48",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "s5e9925", 400000, 2803000
        ), // S22 global / S23 FE - Xclipse 920 (clocks verified: 400-2803)
        Cpu(
            "Samsung Exynos 2400", "Samsung", "S5E9945", "0xd82",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "s5e9945", 400000, 3207000
        ), // S24 / S24+ global, S24 FE, S25 FE - Xclipse 940 (clocks verified: 400-3207)
        Cpu(
            "Samsung Exynos 2500", "Samsung", "S5E9955", "0xd85",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "s5e9955", 400000, 3303000
        ), // Z Flip7 / Z Fold7 SE / S25 Edge - Xclipse 950 (clocks verified: 400-3303; X925 big core)
        Cpu(
            "Samsung Exynos 2600", "Samsung", "S5E9965", "0xd8c",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "s5e9965", 400000, 3801000
        ), // S26 series global - Xclipse 960 (clocks verified: 400-3801; part = C1-Ultra, approx)
        Cpu(
            "Samsung Exynos 8865", "Samsung", "S5E8865", "0xd81",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "s5e8865", 533000, 2910000
        ), // A57 - Xclipse 550 (clocks verified: 533-2910)

        // ---- Snapdragon (US Samsung flagship / midrange) ----
        Cpu(
            "Qualcomm Snapdragon 888", "Qualcomm", "SM8350", "0xd44",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "qcom", 300000, 2841600
        ), // S21 FE (2022) - Adreno 660
        Cpu(
            "Qualcomm Snapdragon 8 Gen 1", "Qualcomm", "SM8450", "0xd48",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "qcom", 307000, 2995000
        ), // S22 US / Tab S8 - Adreno 730 (clocks verified: 307-2995)
        Cpu(
            "Qualcomm Snapdragon 8+ Gen 1", "Qualcomm", "SM8475", "0xd48",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "qcom", 300000, 3200000
        ), // Z Fold4 / Flip4 - Adreno 730
        Cpu(
            "Qualcomm Snapdragon 8 Gen 2", "Qualcomm", "SM8550", "0xd4e",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "qcom", 300000, 3360000
        ), // S23 US / Z Fold5 - Adreno 740 (max clock fixed: 3.36 GHz)
        Cpu(
            "Qualcomm Snapdragon 8 Gen 3", "Qualcomm", "SM8650", "0xd82",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "qcom", 300000, 3300000
        ), // S24 US / Z Fold6 - Adreno 750 (part fixed: Cortex-X4)
        Cpu(
            "Qualcomm Snapdragon 8 Elite", "Qualcomm", "SM8750", "0x001",
            "0x51", AARCH64_MODEL, FEATURES_ARM64, "qcom", 384000, 4473000
        ), // S25 series US / Z Fold7 - Adreno 830 (Oryon: implementer 0x51 part 0x001; clocks verified 384-4473)
        Cpu(
            "Qualcomm Snapdragon 8 Elite Gen 5", "Qualcomm", "SM8850", "0x001",
            "0x51", AARCH64_MODEL, FEATURES_ARM64, "qcom", 384000, 4742000
        ), // S26 series US - Adreno 840 (clocks verified: 384-4742; Oryon-V3 part approx)
        Cpu(
            "Qualcomm Snapdragon 778G", "Qualcomm", "SM7325", "0xd41",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "qcom", 300000, 2400000
        ), // A73 5G / A52s - Adreno 642L
        Cpu(
            "Qualcomm Snapdragon 695", "Qualcomm", "SM6375", "0xd41",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "qcom", 300000, 2200000
        ), // A23 5G - Adreno 619
        Cpu(
            "Qualcomm Snapdragon 680", "Qualcomm", "SM6225", "0xd09",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "qcom", 300000, 2400000
        ), // A23 4G - Adreno 610

        // ---- MediaTek (budget A-series) ----
        Cpu(
            "MediaTek Helio G85", "MediaTek", "MT6769Z", "0xd0a",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "mt6769", 300000, 2000000
        ), // A05 - Mali-G52 MC2
        Cpu(
            "MediaTek Dimensity 6300", "MediaTek", "MT6835", "0xd0b",
            "0x41", AARCH64_MODEL, FEATURES_ARM64, "mt6835", 300000, 2400000
        ), // A16 5G (regional) - Mali-G57 MC2
    )

    // ---- GPU builders -----------------------------------------------------

    /**
     * ARM Mali profile: r38p1 Samsung driver era (GL strings verified on
     * real devices; Vulkan identity from gpuinfo reports of the same family).
     */
    private fun mali(
        renderer: String,
        deviceId: Long,
        info: String = MALI_INFO_R38_EAC0,
        descriptorIndexing: Boolean = true
    ) = Gpu(
        vendor = "ARM",
        renderer = renderer,
        label = renderer,
        vkDeviceName = renderer,
        vendorId = 0x13B5L,
        deviceId = deviceId,
        driverVersion = vk(38, 1, 0),
        apiVersion = vk(1, 3, 219),
        driverName = renderer,
        driverInfo = info,
        glVersion = "OpenGL ES 3.2 $info",
        conformance = conf(1, 3, 1, 0),
        descriptorIndexing = descriptorIndexing,
        sparseBinding = false
    )

    /**
     * Qualcomm Adreno profile. All values from real reports: deviceID from
     * vulkan.gpuinfo.org (matches ANGLE's known-ID list for 740/750),
     * driverVersion + apiVersion + driverInfo from the matching driver
     * build, GL_VERSION from deviceinfohw Samsung dumps where noted.
     */
    private fun adreno(
        renderer: String,
        deviceId: Long,
        drvMaj: Int,
        drvMin: Int,
        drvPatch: Int,
        api: Long,
        gl: String,
        info: String,
        conformance: Int,
        descriptorIndexing: Boolean = true,
        sparseBinding: Boolean = true
    ) = Gpu(
        vendor = "Qualcomm",
        renderer = renderer,
        label = renderer,
        vkDeviceName = renderer,
        vendorId = 0x5143L,
        deviceId = deviceId,
        driverVersion = vk(drvMaj, drvMin, drvPatch),
        apiVersion = api,
        driverName = "Qualcomm Technologies Inc. Adreno Vulkan Driver",
        driverInfo = info,
        glVersion = gl,
        conformance = conformance,
        descriptorIndexing = descriptorIndexing,
        sparseBinding = sparseBinding
    )

    /**
     * Samsung Xclipse profile (AMD RDNA based, ANGLE-on-Vulkan GL stack).
     * GL strings verified on current One UI firmware (deviceinfohw dumps);
     * Vulkan identity verified on vulkan.gpuinfo.org reports per part.
     */
    private fun xclipse(
        num: String,               // e.g. "940"
        deviceId: Long,
        apiText: String,           // e.g. "1.3.279"
        glDrv: String,             // GL driver, e.g. "24.1.307"
        glGit: String,             // GL git hash, e.g. "86f99cfe6317"
        vkDrvText: String,         // Vulkan driver, e.g. "24.0.534"
        vkDrv: Long,               // packed driverVersion
        vkGit: String,             // Vulkan git hash, e.g. "1900168dcb"
        spal: Boolean = false,     // Vulkan 1.4 era drivers prefix "SPAL"
        conformanceV: Int = conf(1, 3, 5, 1)
    ) = Gpu(
        vendor = "Samsung Electronics Co., Ltd.",
        renderer = "ANGLE ((Samsung Xclipse $num) on Vulkan $apiText)",
        label = "Samsung Xclipse $num",
        vkDeviceName = "Samsung Xclipse $num",
        vendorId = 0x144DL,
        deviceId = deviceId,
        driverVersion = vkDrv,
        apiVersion = if (apiText.startsWith("1.4")) vk(1, 4, 304) else vk(1, 3, 279),
        driverName = "Samsung Proprietary driver",
        driverInfo = "${if (spal) "SPAL " else ""}Driver version: $vkDrvText, git hash: $vkGit",
        glVersion = "OpenGL ES 3.2 Driver version: $glDrv git hash: $glGit",
        conformance = conformanceV,
        descriptorIndexing = true,
        sparseBinding = true
    )

    val GPUS = listOf(
        // ---- ARM Mali (Exynos pairing) ----
        mali("Mali-G52 MC2", 0x74021000L, MALI_INFO_G52, descriptorIndexing = false),
            // Exynos 850 (deviceId + driver string verified on the reference A13)
        mali("Mali-G57 MC2", 0x90930010L), // A16 5G (Dimensity 6300) - approx driver string
        mali("Mali-G68", 0x92041010L),     // Exynos 1280 (verified id)
        mali("Mali-G68 MP2", 0x92041010L), // Exynos 1330 (verified id)
        mali("Mali-G68 MP5", 0x92041010L), // Exynos 1380 (verified id)
        mali("Mali-G76 MP12", 0x72110000L, MALI_INFO_R38_EAC0), // Exynos 9820 (verified id)
        mali("Mali-G77 MP11", 0x90800011L, MALI_INFO_G77),      // Exynos 990 (id + driver verified)
        mali("Mali-G78 MP14", 0x92020000L, MALI_INFO_G78),      // Exynos 2100 (id + driver verified)

        // ---- Adreno (Snapdragon pairing) ----
        adreno(
            "Adreno (TM) 610", 0x6010000L, 512, 502, 39, vk(1, 1, 128),
            "OpenGL ES 3.2 V@0502.39.1 (GIT@a22bdbeed1, I9e7c613add, 1749016775) (Date:06/04/25)",
            "Driver Build: a22bdbeed1, I9e7c613add, 1749016775\nDate: 06/04/25\nCompiler Version: EV031.36.08.35\nDriver Branch:",
            conf(1, 2, 7, 2), descriptorIndexing = false, sparseBinding = false
        ), // A23 4G (GL string verified on the real device)
        adreno(
            "Adreno (TM) 619", 0x6010901L, 512, 762, 43, vk(1, 3, 128),
            "OpenGL ES 3.2 V@0762.43 (GIT@3e46547c6d, I05d4d500aa, 1763457967) (Date:11/18/25)",
            "Driver Build: 3e46547c6d, I05d4d500aa, 1763457967\nDate: 11/18/25\nCompiler Version: E031.45.02.26\nDriver Branch:",
            conf(1, 3, 6, 0), sparseBinding = false
        ), // A23 5G (id fixed: 0x6010901, matches ANGLE's Galaxy A23 constant)
        adreno(
            "Adreno (TM) 640", 0x6040001L, 512, 502, 0, vk(1, 1, 128),
            "OpenGL ES 3.2 V@0502.0 (GIT@3dad7f8ed7, I593c16c433, 1633080534) (Date:10/01/21)",
            "Driver Build: 3dad7f8ed7, I593c16c433, 1633080534\nDate: 10/01/21\nCompiler Version: EV031.32.02.02\nDriver Branch:",
            conf(1, 2, 0, 1), sparseBinding = false
        ), // S20 US
        adreno(
            "Adreno (TM) 650", 0x6050002L, 512, 819, 2, vk(1, 3, 295),
            "OpenGL ES 3.2 V@0819.2 (GIT@651341e91d, I8d46b3bbb7, 1754290135) (Date:08/04/25)",
            "Driver Build: 651341e91d, I8d46b3bbb7, 1754290135\nDate: 08/04/25\nCompiler Version: E031.50.02.00\nDriver Branch:",
            conf(1, 4, 0, 0), sparseBinding = false
        ), // S20 FE 5G / S21 US
        adreno(
            "Adreno (TM) 660", 0x6060001L, 512, 530, 0, vk(1, 1, 128),
            "OpenGL ES 3.2 V@0530.0 (GIT@a1cf8ab5e3, I428bf45773, 1699535026) (Date:11/09/23)",
            "Driver Build: a1cf8ab5e3, I428bf45773, 1699535026\nDate: 11/09/23\nCompiler Version: EV031.35.01.12\nDriver Branch:",
            conf(1, 2, 0, 1), sparseBinding = false
        ), // S21 FE (2022)
        adreno(
            "Adreno (TM) 642L", 0x6030500L, 512, 863, 1, vk(1, 3, 295),
            "OpenGL ES 3.2 V@0863.1 (GIT@ffdf890711, I896ce78af2, 1766558511) (Date:12/24/25)",
            "Driver Build: ffdf890711, I896ce78af2, 1766558511\nDate: 12/24/25\nCompiler Version: E031.50.36.00\nDriver Branch:",
            conf(1, 4, 1, 0), sparseBinding = false
        ), // A73 5G / A52s (id fixed: 0x6030500; sparse=false verified)
        adreno(
            "Adreno (TM) 730", 0x7030001L, 512, 615, 98, vk(1, 1, 128),
            "OpenGL ES 3.2 V@0615.98 (GIT@0c393b63cf, I94e2bd5684, 1746191168) (Date:05/02/25)",
            "Driver Build: 0c393b63cf, I94e2bd5684, 1746191168\nDate: 05/02/25\nCompiler Version: EV031.36.08.33\nDriver Branch:",
            conf(1, 2, 7, 2)
        ), // S22 US / Tab S8 (GL string verified on the S22 Ultra)
        adreno(
            "Adreno (TM) 740", 0x43050A01L, 512, 676, 1, vk(1, 3, 128),
            "OpenGL ES 3.2 V@0676.1 (GIT@bad34dcf83, I1064ae0a1f, 1764326394) (Date:11/28/25)",
            "Driver Build: bad34dcf83, I1064ae0a1f, 1764326394\nDate: 11/28/25\nCompiler Version: E031.41.03.64\nDriver Branch:",
            conf(1, 3, 1, 0)
        ), // S23 US / Z Fold5 (id fixed: 0x43050A01, matches ANGLE's Galaxy S23 constant)
        adreno(
            "Adreno (TM) 750", 0x43051401L, 512, 762, 1, vk(1, 3, 128),
            "OpenGL ES 3.2 V@0762.1 (GIT@a0053eb399, I31b05c049d, 1766398679) (Date:12/22/25)",
            "Driver Build: a0053eb399, I31b05c049d, 1766398679\nDate: 12/22/25\nCompiler Version: E031.45.02.25\nDriver Branch:",
            conf(1, 3, 6, 0)
        ), // S24 US / Z Fold6 (id fixed: 0x43051401, matches ANGLE's Adreno 750 constant)
        adreno(
            "Adreno (TM) 830", 0x44050001L, 512, 800, 64, vk(1, 3, 284),
            "OpenGL ES 3.2 V@0800.64.7 (GIT@f61dec9117, I68b0a64d7e, 1774510019) (Date:03/26/26)",
            "Driver Build: f61dec9117, I68b0a64d7e, 1774510019\nDate: 03/26/26\nCompiler Version: E031.47.18.56\nDriver Branch:",
            conf(1, 3, 8, 0)
        ), // S25 series US / Z Fold7 (GL string verified on the S25; id fixed: 0x44050001)
        adreno(
            "Adreno (TM) 840", 0x44050A31L, 512, 842, 19, vk(1, 4, 295),
            "OpenGL ES 3.2 V@0842.19.13 (GIT@089d643e2a, Icecd8f0534, 1782882597) (Date:07/01/26)",
            "Driver Build: 089d643e2a, Icecd8f0534, 1782882597\nDate: 07/01/26\nCompiler Version: E031.50.19.32\nDriver Branch:",
            conf(1, 4, 1, 0)
        ), // S26 series US (GL string verified on the S26 Ultra)

        // ---- Samsung Xclipse (Exynos pairing, v2.4.0) ----
        xclipse(
            "920", 0x73A0L, "1.3.279",
            "24.1.293", "35f6eab5b214",
            "24.0.545", vk(24, 0, 545), "1fc295b0d2"
        ), // Exynos 2200 - S22 global / S23 FE (AMD-style ASIC id, verified on 5+ reports)
        xclipse(
            "940", 0x2600200L, "1.3.279",
            "24.1.307", "86f99cfe6317",
            "24.0.534", vk(24, 0, 534), "1900168dcb"
        ), // Exynos 2400 - S24 / S24+ global, S24 FE, S25 FE
        xclipse(
            "950", 0x3600200L, "1.3.279",
            "24.1.293", "35f6eab5b214",
            "24.0.542", vk(24, 0, 542), "b02432ec77"
        ), // Exynos 2500 - Z Flip7 / Z Fold7 SE / S25 Edge
        xclipse(
            "960", 0x4600200L, "1.4.304",
            "25.6.3", "cbd4f9cf1088",
            "25.2.39", vk(25, 2, 39), "ee686460f4", spal = true,
            conformanceV = conf(1, 4, 1, 1)
        ), // Exynos 2600 - S26 series global (Vulkan 1.4)
        xclipse(
            "530", 0x1300100L, "1.3.279",
            "24.1.306", "6c522b193c69",
            "24.0.539", vk(24, 0, 539), "bd45943d20"
        ), // Exynos 1480 - A55 / A37
        xclipse(
            "540", 0x2300100L, "1.3.279",
            "24.1.305", "e94bc7a33c77",
            "24.0.560", vk(24, 0, 560), "34bb549c57"
        ), // Exynos 1580 - A56 / M56 / Tab (GL string matches the reference SM-A566E dump)
        xclipse(
            "550", 0x3300100L, "1.4.304",
            "25.1.127", "7c9893305eb5",
            "25.4.7", vk(25, 4, 7), "702e7fd271", spal = true,
            conformanceV = conf(1, 4, 1, 1)
        ), // Exynos 8865 - A57 (Vulkan 1.4)
    )

    fun cpu(display: String?): Cpu = CPUS.firstOrNull { it.display == display } ?: CPUS[0]

    fun gpu(renderer: String?): Gpu = GPUS.firstOrNull { it.renderer == renderer } ?: GPUS[0]
}
