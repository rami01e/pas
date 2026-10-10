package com.kimera.pas.spoof

/**
 * Shared CPU / GPU model catalogs.
 *
 * v2.4.7: GPU entries now carry a real min/max clock (kHz) so DevCheck's
 * GPU tab shows a coherent frequency range. Physical specs (cores, L2,
 * arch) already existed but were only exposed through the Vulkan path;
 * DevCheck also reads /sys/class/kgsl and /sys/class/devfreq, so the
 * native side now serves fake values there too.
 */
object DeviceCatalog {

    private const val FEATURES_ARM64 = "fp asimd evtstrm aes pmull sha1 sha2 crc32"

    private const val FEATURES_ARM32 =
        "half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt lpae evtstrm aes pmull sha1 sha2 crc32"

    private const val MALI_INFO_G52 =
        "v1.r38p1-01bet0-mbs2v41_0.6d20ec041e51b2f2d25dfc265586ebe8"

    private const val MALI_INFO_R38_EAC0 =
        "v1.r38p1-01eac0-mbs2v41_0.0b37450fbb12e582df79a7906d0ad856"

    private const val MALI_INFO_G77 =
        "v1.r38p1-01bet0-mbs2v41_0.8320a750c7c9e2666df3500d139b434f"

    private const val MALI_INFO_G78 =
        "v1.r38p0-01eac0-mbs2v41_0.4ef6e1c9ba431853d05b271234c3d1c5"

    private const val AARCH64_MODEL = "AArch64 Processor rev 14 (aarch64)"

    data class Cpu(
        val display: String,
        val manufacturer: String,
        val socModel: String,
        val part: String,
        val implementer: String = "0x41",
        val cpuinfoModel: String,
        val features: String,
        val hardware: String,
        val minKHz: Int,
        val maxKHz: Int,
        val hardwareLine: String = "",
        val clusters: String = "4+4"
    )

    data class Gpu(
        val vendor: String,
        val renderer: String,
        val label: String,
        val vkDeviceName: String,
        val vendorId: Long,
        val deviceId: Long,
        val driverVersion: Long,
        val apiVersion: Long,
        val driverName: String,
        val driverInfo: String,
        val glVersion: String,
        val conformance: Int,
        val driverId: Int,
        val descriptorIndexing: Boolean,
        val sparseBinding: Boolean,
        val gpuCores: Int = 1,
        val l2CacheKb: Int = 64,
        val gpuArch: String = "Bifrost",
        // v2.4.7: physical clock range (kHz) so the GPU tab has a real
        // frequency row instead of relying on the emulator's fake kgsl data.
        val gpuMinFreqKHz: Int = 200000,
        val gpuMaxFreqKHz: Int = 1000000
    )

    private fun vk(major: Int, minor: Int, patch: Int): Long =
        (major.toLong() shl 22) or (minor.toLong() shl 12) or patch.toLong()

    private fun conf(major: Int, minor: Int, sub: Int, patch: Int): Int =
        (major shl 24) or (minor shl 16) or (sub shl 8) or patch

    val CPUS = listOf(
        Cpu(
            display = "Samsung Exynos 850",
            manufacturer = "Samsung",
            socModel = "S5E3830",
            part = "0xd05",
            implementer = "0x41",
            cpuinfoModel = "ARMv8 Processor rev 1 (v8)",
            features = FEATURES_ARM32,
            hardware = "exynos850",
            minKHz = 546000,
            maxKHz = 2002000,
            hardwareLine = "exynos850 (Samsung A13 EUR OPEN REV02B board based on EXYNOS850)",
            clusters = "4+4"
        ),
        Cpu(
            display = "Samsung Exynos 1280",
            manufacturer = "Samsung",
            socModel = "S5E8825",
            part = "0xd41",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "s5e8825",
            minKHz = 300000,
            maxKHz = 2400000,
            clusters = "1+3+4"
        ),
        Cpu(
            display = "Samsung Exynos 1330",
            manufacturer = "Samsung",
            socModel = "S5E8535",
            part = "0xd41",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "s5e8535",
            minKHz = 300000,
            maxKHz = 2400000,
            clusters = "1+3+4"
        ),
        Cpu(
            display = "Samsung Exynos 1380",
            manufacturer = "Samsung",
            socModel = "S5E8835",
            part = "0xd41",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "s5e8835",
            minKHz = 300000,
            maxKHz = 2400000,
            clusters = "1+3+4"
        ),
        Cpu(
            display = "Samsung Exynos 1480",
            manufacturer = "Samsung",
            socModel = "S5E8845",
            part = "0xd41",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "s5e8845",
            minKHz = 533000,
            maxKHz = 2750000,
            clusters = "4+4"
        ),
        Cpu(
            display = "Samsung Exynos 1580",
            manufacturer = "Samsung",
            socModel = "S5E8855",
            part = "0xd81",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "s5e8855",
            minKHz = 533000,
            maxKHz = 2910000,
            clusters = "1+3+4"
        ),
        Cpu(
            display = "Samsung Exynos 2200",
            manufacturer = "Samsung",
            socModel = "S5E9925",
            part = "0xd48",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "s5e9925",
            minKHz = 400000,
            maxKHz = 2803000,
            clusters = "1+3+4"
        ),
        Cpu(
            display = "Samsung Exynos 2400",
            manufacturer = "Samsung",
            socModel = "S5E9945",
            part = "0xd82",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "s5e9945",
            minKHz = 400000,
            maxKHz = 3207000,
            clusters = "1+2+3+4"
        ),
        Cpu(
            display = "Samsung Exynos 2500",
            manufacturer = "Samsung",
            socModel = "S5E9955",
            part = "0xd85",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "s5e9955",
            minKHz = 400000,
            maxKHz = 3303000,
            clusters = "1+2+5+2"
        ),
        Cpu(
            display = "Samsung Exynos 2600",
            manufacturer = "Samsung",
            socModel = "S5E9965",
            part = "0xd8c",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "s5e9965",
            minKHz = 400000,
            maxKHz = 3801000,
            clusters = "1+3+6"
        ),
        Cpu(
            display = "Samsung Exynos 8865",
            manufacturer = "Samsung",
            socModel = "S5E8865",
            part = "0xd81",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "s5e8865",
            minKHz = 533000,
            maxKHz = 2910000,
            clusters = "1+4+3"
        ),
        Cpu(
            display = "Qualcomm Snapdragon 888",
            manufacturer = "Qualcomm",
            socModel = "SM8350",
            part = "0xd44",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "qcom",
            minKHz = 300000,
            maxKHz = 2841600,
            clusters = "1+3+4"
        ),
        Cpu(
            display = "Qualcomm Snapdragon 8 Gen 1",
            manufacturer = "Qualcomm",
            socModel = "SM8450",
            part = "0xd48",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "qcom",
            minKHz = 307000,
            maxKHz = 2995000,
            clusters = "1+3+4"
        ),
        Cpu(
            display = "Qualcomm Snapdragon 8+ Gen 1",
            manufacturer = "Qualcomm",
            socModel = "SM8475",
            part = "0xd48",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "qcom",
            minKHz = 300000,
            maxKHz = 3200000,
            clusters = "1+3+4"
        ),
        Cpu(
            display = "Qualcomm Snapdragon 8 Gen 2",
            manufacturer = "Qualcomm",
            socModel = "SM8550",
            part = "0xd4e",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "qcom",
            minKHz = 300000,
            maxKHz = 3360000,
            clusters = "1+2+2+3"
        ),
        Cpu(
            display = "Qualcomm Snapdragon 8 Gen 3",
            manufacturer = "Qualcomm",
            socModel = "SM8650",
            part = "0xd82",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "qcom",
            minKHz = 300000,
            maxKHz = 3300000,
            clusters = "1+3+2+2"
        ),
        Cpu(
            display = "Qualcomm Snapdragon 8 Elite",
            manufacturer = "Qualcomm",
            socModel = "SM8750",
            part = "0x001",
            implementer = "0x51",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "qcom",
            minKHz = 384000,
            maxKHz = 4473000,
            clusters = "2+6"
        ),
        Cpu(
            display = "Qualcomm Snapdragon 8 Elite Gen 5",
            manufacturer = "Qualcomm",
            socModel = "SM8850",
            part = "0x001",
            implementer = "0x51",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "qcom",
            minKHz = 384000,
            maxKHz = 4742000,
            clusters = "2+6"
        ),
        Cpu(
            display = "Qualcomm Snapdragon 778G",
            manufacturer = "Qualcomm",
            socModel = "SM7325",
            part = "0xd41",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "qcom",
            minKHz = 300000,
            maxKHz = 2400000,
            clusters = "1+3+4"
        ),
        Cpu(
            display = "Qualcomm Snapdragon 695",
            manufacturer = "Qualcomm",
            socModel = "SM6375",
            part = "0xd41",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "qcom",
            minKHz = 300000,
            maxKHz = 2200000,
            clusters = "2+6"
        ),
        Cpu(
            display = "Qualcomm Snapdragon 680",
            manufacturer = "Qualcomm",
            socModel = "SM6225",
            part = "0xd09",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "qcom",
            minKHz = 300000,
            maxKHz = 2400000,
            clusters = "4+4"
        ),
        Cpu(
            display = "MediaTek Helio G85",
            manufacturer = "MediaTek",
            socModel = "MT6769Z",
            part = "0xd0a",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "mt6769",
            minKHz = 300000,
            maxKHz = 2000000,
            clusters = "2+6"
        ),
        Cpu(
            display = "MediaTek Dimensity 6300",
            manufacturer = "MediaTek",
            socModel = "MT6835",
            part = "0xd0b",
            cpuinfoModel = AARCH64_MODEL,
            features = FEATURES_ARM64,
            hardware = "mt6835",
            minKHz = 300000,
            maxKHz = 2400000,
            clusters = "2+6"
        )
    )

    private fun mali(
        renderer: String,
        deviceId: Long,
        info: String = MALI_INFO_R38_EAC0,
        descriptorIndexing: Boolean = true,
        gpuCores: Int = 1,
        l2CacheKb: Int = 64,
        gpuArch: String = "Bifrost",
        minKHz: Int = 200000,
        maxKHz: Int = 1000000
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
        driverId = 9,
        descriptorIndexing = descriptorIndexing,
        sparseBinding = false,
        gpuCores = gpuCores,
        l2CacheKb = l2CacheKb,
        gpuArch = gpuArch,
        gpuMinFreqKHz = minKHz,
        gpuMaxFreqKHz = maxKHz
    )

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
        sparseBinding: Boolean = true,
        gpuCores: Int = 1,
        l2CacheKb: Int = 64,
        minKHz: Int = 200000,
        maxKHz: Int = 1000000
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
        driverId = 8,
        descriptorIndexing = descriptorIndexing,
        sparseBinding = sparseBinding,
        gpuCores = gpuCores,
        l2CacheKb = l2CacheKb,
        gpuArch = "Adreno",
        gpuMinFreqKHz = minKHz,
        gpuMaxFreqKHz = maxKHz
    )

    private fun xclipse(
        num: String,
        deviceId: Long,
        apiText: String,
        glDrv: String,
        glGit: String,
        vkDrvText: String,
        vkDrv: Long,
        vkGit: String,
        spal: Boolean = false,
        conformanceV: Int = conf(1, 3, 5, 1),
        gpuCores: Int = 1,
        l2CacheKb: Int = 64,
        minKHz: Int = 400000,
        maxKHz: Int = 1300000
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
        driverId = 21,
        descriptorIndexing = true,
        sparseBinding = true,
        gpuCores = gpuCores,
        l2CacheKb = l2CacheKb,
        gpuArch = "RDNA",
        gpuMinFreqKHz = minKHz,
        gpuMaxFreqKHz = maxKHz
    )

    val GPUS = listOf(
        // Mali-G52 MC2 (Galaxy A13 reference) - 1001 MHz max verified on
        // the real device (user's own measurement)
        mali("Mali-G52 MC2", 0x74021000L, MALI_INFO_G52,
             descriptorIndexing = false,
             gpuCores = 2, l2CacheKb = 64, gpuArch = "Bifrost",
             minKHz = 100000, maxKHz = 1001000),
        mali("Mali-G57 MC2", 0x90930010L,
             gpuCores = 2, l2CacheKb = 64, gpuArch = "Valhall",
             minKHz = 200000, maxKHz = 950000),
        mali("Mali-G68", 0x92041010L,
             gpuCores = 4, l2CacheKb = 128, gpuArch = "Valhall",
             minKHz = 200000, maxKHz = 1000000),
        mali("Mali-G68 MP2", 0x92041010L,
             gpuCores = 2, l2CacheKb = 64, gpuArch = "Valhall",
             minKHz = 200000, maxKHz = 950000),
        mali("Mali-G68 MP5", 0x92041010L,
             gpuCores = 5, l2CacheKb = 128, gpuArch = "Valhall",
             minKHz = 200000, maxKHz = 1000000),
        mali("Mali-G76 MP12", 0x72110000L, MALI_INFO_R38_EAC0,
             gpuCores = 12, l2CacheKb = 512, gpuArch = "Bifrost",
             minKHz = 200000, maxKHz = 850000),
        mali("Mali-G77 MP11", 0x90800011L, MALI_INFO_G77,
             gpuCores = 11, l2CacheKb = 512, gpuArch = "Valhall",
             minKHz = 200000, maxKHz = 800000),
        mali("Mali-G78 MP14", 0x92020000L, MALI_INFO_G78,
             gpuCores = 14, l2CacheKb = 512, gpuArch = "Valhall",
             minKHz = 200000, maxKHz = 850000),

        adreno("Adreno (TM) 610", 0x6010000L, 512, 502, 39, vk(1, 1, 128),
               "OpenGL ES 3.2 V@0502.39.1 (GIT@a22bdbeed1, I9e7c613add, 1749016775) (Date:06/04/25)",
               "Driver Build: a22bdbeed1, I9e7c613add, 1749016775\nDate: 06/04/25\nCompiler Version: EV031.36.08.35\nDriver Branch:",
               conf(1, 2, 7, 2), descriptorIndexing = false, sparseBinding = false,
               gpuCores = 1, l2CacheKb = 64, minKHz = 200000, maxKHz = 950000),
        adreno("Adreno (TM) 619", 0x6010901L, 512, 762, 43, vk(1, 3, 128),
               "OpenGL ES 3.2 V@0762.43 (GIT@3e46547c6d, I05d4d500aa, 1763457967) (Date:11/18/25)",
               "Driver Build: 3e46547c6d, I05d4d500aa, 1763457967\nDate: 11/18/25\nCompiler Version: E031.45.02.26\nDriver Branch:",
               conf(1, 3, 6, 0), sparseBinding = false,
               gpuCores = 1, l2CacheKb = 128, minKHz = 200000, maxKHz = 950000),
        adreno("Adreno (TM) 640", 0x6040001L, 512, 502, 0, vk(1, 1, 128),
               "OpenGL ES 3.2 V@0502.0 (GIT@3dad7f8ed7, I593c16c433, 1633080534) (Date:10/01/21)",
               "Driver Build: 3dad7f8ed7, I593c16c433, 1633080534\nDate: 10/01/21\nCompiler Version: EV031.32.02.02\nDriver Branch:",
               conf(1, 2, 0, 1), sparseBinding = false,
               gpuCores = 1, l2CacheKb = 256, minKHz = 257000, maxKHz = 585000),
        adreno("Adreno (TM) 650", 0x6050002L, 512, 819, 2, vk(1, 3, 295),
               "OpenGL ES 3.2 V@0819.2 (GIT@651341e91d, I8d46b3bbb7, 1754290135) (Date:08/04/25)",
               "Driver Build: 651341e91d, I8d46b3bbb7, 1754290135\nDate: 08/04/25\nCompiler Version: E031.50.02.00\nDriver Branch:",
               conf(1, 4, 0, 0), sparseBinding = false,
               gpuCores = 2, l2CacheKb = 512, minKHz = 305000, maxKHz = 670000),
        adreno("Adreno (TM) 660", 0x6060001L, 512, 530, 0, vk(1, 1, 128),
               "OpenGL ES 3.2 V@0530.0 (GIT@a1cf8ab5e3, I428bf45773, 1699535026) (Date:11/09/23)",
               "Driver Build: a1cf8ab5e3, I428bf45773, 1699535026\nDate: 11/09/23\nCompiler Version: EV031.35.01.12\nDriver Branch:",
               conf(1, 2, 0, 1), sparseBinding = false,
               gpuCores = 2, l2CacheKb = 512, minKHz = 490000, maxKHz = 840000),
        adreno("Adreno (TM) 642L", 0x6030500L, 512, 863, 1, vk(1, 3, 295),
               "OpenGL ES 3.2 V@0863.1 (GIT@ffdf890711, I896ce78af2, 1766558511) (Date:12/24/25)",
               "Driver Build: ffdf890711, I896ce78af2, 1766558511\nDate: 12/24/25\nCompiler Version: E031.50.36.00\nDriver Branch:",
               conf(1, 4, 1, 0), sparseBinding = false,
               gpuCores = 2, l2CacheKb = 256, minKHz = 300000, maxKHz = 550000),
        adreno("Adreno (TM) 730", 0x7030001L, 512, 615, 98, vk(1, 1, 128),
               "OpenGL ES 3.2 V@0615.98 (GIT@0c393b63cf, I94e2bd5684, 1746191168) (Date:05/02/25)",
               "Driver Build: 0c393b63cf, I94e2bd5684, 1746191168\nDate: 05/02/25\nCompiler Version: EV031.36.08.33\nDriver Branch:",
               conf(1, 2, 7, 2),
               gpuCores = 2, l2CacheKb = 1024, minKHz = 300000, maxKHz = 818000),
        adreno("Adreno (TM) 740", 0x43050A01L, 512, 676, 1, vk(1, 3, 128),
               "OpenGL ES 3.2 V@0676.1 (GIT@bad34dcf83, I1064ae0a1f, 1764326394) (Date:11/28/25)",
               "Driver Build: bad34dcf83, I1064ae0a1f, 1764326394\nDate: 11/28/25\nCompiler Version: E031.41.03.64\nDriver Branch:",
               conf(1, 3, 1, 0),
               gpuCores = 3, l2CacheKb = 1024, minKHz = 300000, maxKHz = 680000),
        adreno("Adreno (TM) 750", 0x43051401L, 512, 762, 1, vk(1, 3, 128),
               "OpenGL ES 3.2 V@0762.1 (GIT@a0053eb399, I31b05c049d, 1766398679) (Date:12/22/25)",
               "Driver Build: a0053eb399, I31b05c049d, 1766398679\nDate: 12/22/25\nCompiler Version: E031.45.02.25\nDriver Branch:",
               conf(1, 3, 6, 0),
               gpuCores = 3, l2CacheKb = 1024, minKHz = 300000, maxKHz = 903000),
        adreno("Adreno (TM) 830", 0x44050001L, 512, 800, 64, vk(1, 3, 284),
               "OpenGL ES 3.2 V@0800.64.7 (GIT@f61dec9117, I68b0a64d7e, 1774510019) (Date:03/26/26)",
               "Driver Build: f61dec9117, I68b0a64d7e, 1774510019\nDate: 03/26/26\nCompiler Version: E031.47.18.56\nDriver Branch:",
               conf(1, 3, 8, 0),
               gpuCores = 4, l2CacheKb = 2048, minKHz = 500000, maxKHz = 1100000),
        adreno("Adreno (TM) 840", 0x44050A31L, 512, 842, 19, vk(1, 4, 295),
               "OpenGL ES 3.2 V@0842.19.13 (GIT@089d643e2a, Icecd8f0534, 1782882597) (Date:07/01/26)",
               "Driver Build: 089d643e2a, Icecd8f0534, 1782882597\nDate: 07/01/26\nCompiler Version: E031.50.19.32\nDriver Branch:",
               conf(1, 4, 1, 0),
               gpuCores = 4, l2CacheKb = 2048, minKHz = 500000, maxKHz = 1100000),

        xclipse("920", 0x73A0L, "1.3.279", "24.1.293", "35f6eab5b214", "24.0.545",
                vk(24, 0, 545), "1fc295b0d2",
                gpuCores = 4, l2CacheKb = 512, minKHz = 400000, maxKHz = 1300000),
        xclipse("940", 0x2600200L, "1.3.279", "24.1.307", "86f99cfe6317", "24.0.534",
                vk(24, 0, 534), "1900168dcb",
                gpuCores = 6, l2CacheKb = 1024, minKHz = 400000, maxKHz = 1095000),
        xclipse("950", 0x3600200L, "1.3.279", "24.1.293", "35f6eab5b214", "24.0.542",
                vk(24, 0, 542), "b02432ec77",
                gpuCores = 6, l2CacheKb = 1024, minKHz = 400000, maxKHz = 1100000),
        xclipse("960", 0x4600200L, "1.4.304", "25.6.3", "cbd4f9cf1088", "25.2.39",
                vk(25, 2, 39), "ee686460f4", spal = true,
                conformanceV = conf(1, 4, 1, 1),
                gpuCores = 8, l2CacheKb = 2048, minKHz = 400000, maxKHz = 1200000),
        xclipse("530", 0x1300100L, "1.3.279", "24.1.306", "6c522b193c69", "24.0.539",
                vk(24, 0, 539), "bd45943d20",
                gpuCores = 4, l2CacheKb = 512, minKHz = 300000, maxKHz = 1200000),
        xclipse("540", 0x2300100L, "1.3.279", "24.1.305", "e94bc7a33c77", "24.0.560",
                vk(24, 0, 560), "34bb549c57",
                gpuCores = 4, l2CacheKb = 512, minKHz = 300000, maxKHz = 1280000),
        xclipse("550", 0x3300100L, "1.4.304", "25.1.127", "7c9893305eb5", "25.4.7",
                vk(25, 4, 7), "702e7fd271", spal = true,
                conformanceV = conf(1, 4, 1, 1),
                gpuCores = 6, l2CacheKb = 1024, minKHz = 300000, maxKHz = 1280000)
    )

    fun cpu(display: String?): Cpu = CPUS.firstOrNull { it.display == display } ?: CPUS[0]

    fun gpu(renderer: String?): Gpu = GPUS.firstOrNull { it.renderer == renderer } ?: GPUS[0]
}