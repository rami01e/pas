package com.kimera.novpndetect.spoof

/**
 * Shared CPU / GPU model catalogs.
 *
 * The GUI builds its pickers from these lists, and the config core resolves
 * the saved selection into the exact values pushed to the native layer and
 * the Java Build fields, so every surface stays consistent.
 */
object DeviceCatalog {

    data class Cpu(val display: String, val manufacturer: String, val model: String)

    data class Gpu(val vendor: String, val renderer: String)

    val CPUS = listOf(
        Cpu("Qualcomm Snapdragon 8 Gen 2", "Qualcomm", "SM8550"),
        Cpu("Qualcomm Snapdragon 888", "Qualcomm", "SM8350"),
        Cpu("Qualcomm Snapdragon 855", "Qualcomm", "SM8150"),
        Cpu("Qualcomm Snapdragon 660", "Qualcomm", "SDM660"),
        Cpu("Samsung Exynos 2200", "Samsung", "S5E9925"),
        Cpu("Samsung Exynos 850", "Samsung", "S5E3830"),
        Cpu("MediaTek Dimensity 9300", "MediaTek", "MT6989"),
        Cpu("MediaTek Helio G85", "MediaTek", "MT6769Z"),
        Cpu("Google Tensor G3", "Google", "Tensor G3"),
        Cpu("HiSilicon Kirin 990", "HiSilicon", "Kirin 990"),
    )

    val GPUS = listOf(
        Gpu("Qualcomm", "Adreno (TM) 640"),
        Gpu("Qualcomm", "Adreno (TM) 650"),
        Gpu("Qualcomm", "Adreno (TM) 660"),
        Gpu("ARM", "Mali-G52 MC2"),
        Gpu("ARM", "Mali-G68 MC4"),
        Gpu("ARM", "Mali-G78 MP14"),
        Gpu("ARM", "Mali-G710 MP10"),
        Gpu("Imagination Technologies", "PowerVR Rogue GE8320"),
    )

    fun cpu(display: String?): Cpu = CPUS.firstOrNull { it.display == display } ?: CPUS[0]

    fun gpu(renderer: String?): Gpu = GPUS.firstOrNull { it.renderer == renderer } ?: GPUS[0]
}
