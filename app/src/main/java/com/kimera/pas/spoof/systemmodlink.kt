// systemmodlink.kt v2.13.0

package com.kimera.pas.spoof

import android.system.Os
import android.util.Log
import java.io.File
import java.util.concurrent.Executors

/**
 * v2.13.0: KERNELSU "SystemMod" LINK -
 * /data/local/SystemMod_config/spoof_hardware.txt
 *
 * Hand-off file between the PAS GUI (this process, plain app UID) and the
 * companion KernelSU module: whenever a CPU model is picked in the GUI and
 * Apply is pressed, the catalog `hardware` value of that selection
 * (s5e9945 for Samsung Exynos 2400, qcom for every Qualcomm SoC, mt6xxx for
 * MediaTek, ...) is mirrored into spoof_hardware.txt with the exact body
 *
 *     ro.hardware=<hardware>
 *     ro.board.platform=<hardware>
 *
 * The KernelSU module reads the file and resetprops both keys system-wide,
 * so ROM-level identity and the per-app CPU spoof (SpoofCore /
 * DeviceCatalog) always agree on the same SoC family.
 *
 * Contract:
 *  - Apply ([sync])    - the file is always (re)written from the current
 *    selection and chmod'ed 644, full overwrite, no merging: the file
 *    mirrors the last applied selection.
 *  - Launch ([ensure]) - repair only: a missing or zero-byte file is
 *    recreated from the saved selection; an existing non-empty file is left
 *    untouched (it may carry a different applied selection, or have been
 *    pre-seeded by the KSU module).
 *
 * Write strategy: direct file IO first (works while the KSU module keeps the
 * config dir writable for app UIDs); on any failure the same operations are
 * retried through `su` (KernelSU - PAS already holds a root grant for the
 * frida / force-stop features), which also covers a root-owned directory or
 * a root-seeded file the app UID cannot truncate. Everything is best-effort
 * and silent: users without the KSU module only get logcat lines under the
 * standard [PAS] tag, never UI errors.
 */
object SystemModLink {

    private const val TAG = "PerAppSpoofer"

    private const val CONFIG_DIR = "/data/local/SystemMod_config"
    private const val FILE_NAME = "spoof_hardware.txt"

    /** Serialized so ensure() (launch) and sync() (apply) cannot interleave. */
    private val io = Executors.newSingleThreadExecutor { r -> Thread(r, "pas-systemmod") }

    /** Apply-side entry (MainActivity#saveSpoof): always mirrors [hardware]. */
    fun sync(hardware: String?) {
        if (hardware.isNullOrBlank()) {
            Log.i(TAG, "[PAS] systemmod: no cpu hardware value - $FILE_NAME untouched")
            return
        }
        io.execute { write(hardware) }
    }

    /** Launch-side entry (MainActivity#onCreate): repairs missing/empty only. */
    fun ensure(hardware: String?) {
        if (hardware.isNullOrBlank()) return
        io.execute {
            val f = File(CONFIG_DIR, FILE_NAME)
            if (f.isFile && f.length() > 0L) return@execute
            write(hardware)
        }
    }

    private fun write(hardware: String) {
        if (hardware.any { !it.isLetterOrDigit() && it != '.' && it != '_' && it != '-' }) {
            Log.w(TAG, "[PAS] systemmod: refusing unsafe hardware value '$hardware'")
            return
        }
        val body = "ro.hardware=$hardware\nro.board.platform=$hardware\n"
        if (directWrite(body)) {
            Log.i(TAG, "[PAS] systemmod: $FILE_NAME <- ro.hardware=$hardware ro.board.platform=$hardware")
            return
        }
        if (suWrite(body)) {
            Log.i(TAG, "[PAS] systemmod: $FILE_NAME (root) <- ro.hardware=$hardware ro.board.platform=$hardware")
            return
        }
        Log.w(TAG, "[PAS] systemmod: could not update $FILE_NAME (no writable $CONFIG_DIR, no root grant)")
    }

    private fun directWrite(body: String): Boolean {
        return try {
            val dir = File(CONFIG_DIR)
            // /data/local itself is not app-writable: the directory must
            // already exist (the KSU module creates it). mkdirs() is a probe
            // for that and cannot create the real directory unprivileged.
            if (!dir.isDirectory && !dir.mkdirs()) {
                false
            } else {
                val f = File(dir, FILE_NAME)
                // A pre-existing root-owned file cannot be truncated by the
                // app UID, but a writable directory allows unlink + re-create
                // to take over ownership.
                if (f.exists() && !f.canWrite()) f.delete()
                f.writeText(body)
                chmod644(f)
                true
            }
        } catch (t: Throwable) {
            Log.i(TAG, "[PAS] systemmod: direct write unavailable: ${t.message}")
            false
        }
    }

    private fun suWrite(body: String): Boolean {
        val dir = File(CONFIG_DIR)
        val file = File(dir, FILE_NAME)
        val cmd = "mkdir -p '${dir.absolutePath}' && printf '$body' > " +
            "'${file.absolutePath}' && chmod 644 '${file.absolutePath}'"
        return try {
            val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().use { it.readText() }
            val ok = p.waitFor() == 0
            if (!ok) Log.i(TAG, "[PAS] systemmod: su write failed: ${out.trim().take(200)}")
            ok
        } catch (t: Throwable) {
            Log.i(TAG, "[PAS] systemmod: su write unavailable: ${t.message}")
            false
        }
    }

    /** Best-effort 0644: fresh files are owned by this UID, so no root needed. */
    private fun chmod644(f: File) {
        try {
            Os.chmod(f.absolutePath, "644".toInt(8))
        } catch (t: Throwable) {
            Log.i(TAG, "[PAS] systemmod: chmod 644 failed: ${t.message}")
        }
    }
}