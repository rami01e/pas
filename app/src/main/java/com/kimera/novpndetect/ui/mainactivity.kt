package com.kimera.novpndetect.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/**
 * Tiny built-in log viewer for debugging.
 *
 * Reads the LSPosed/Vector module log (needs root - KernelSU will prompt)
 * and falls back to logcat. No external dependencies; UI is built in code.
 */
class MainActivity : Activity() {

    private lateinit var logView: TextView
    private lateinit var status: TextView
    private var busy = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }

        root.addView(
            TextView(this).apply {
                text = "NoVPNDetect ${versionName()}"
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f)
                setTypeface(typeface, Typeface.BOLD)
            }
        )

        status = TextView(this).apply {
            text = "Loading\u2026 Root (via KernelSU) is only needed so the app can read the LSPosed/Vector log file."
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(0, pad / 2, 0, pad / 2)
        }
        root.addView(status)

        val buttons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.START
        }
        buttons.addView(button("Reload") { loadLogs() })
        buttons.addView(button("Copy") { copyLogs() })
        buttons.addView(button("Clear") { logView.text = "" })
        root.addView(buttons)

        val scroll = ScrollView(this)
        logView = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        scroll.addView(logView)
        root.addView(
            scroll,
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
        )

        setContentView(root)
        loadLogs()
    }

    private fun button(label: String, onClick: () -> Unit): Button =
        Button(this).apply {
            text = label
            setOnClickListener { onClick() }
        }

    private fun versionName(): String = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: "?"
    } catch (t: Throwable) {
        "?"
    }

    private fun loadLogs() {
        if (busy) return
        busy = true
        status.text = "Loading logs\u2026"
        Thread {
            val out = StringBuilder()
            var rootWorks = false
            try {
                val lspd = runSu(
                    "for D in /data/adb/lspd/log /data/adb/vector/log; do " +
                        "cat \$D/modules_*.log \$D/verbose_*.log 2>/dev/null; done " +
                        "| grep -a NoVPNDetect | tail -n 600"
                )
                if (lspd != null) rootWorks = true
                if (!lspd.isNullOrBlank()) {
                    out.append("=== LSPosed/Vector log ===\n").append(lspd).append("\n\n")
                }
                val lc = runSu("logcat -d -t 4000 | grep -a NoVPNDetect | tail -n 400")
                if (lc != null) rootWorks = true
                if (!lc.isNullOrBlank()) {
                    out.append("=== logcat ===\n").append(lc)
                }
            } catch (t: Throwable) {
                out.append("error: ").append(t.toString())
            }
            val text = out.toString()
            runOnUiThread {
                busy = false
                status.text = when {
                    rootWorks && text.isNotBlank() -> "Loaded (root OK). Latest entries below."
                    rootWorks -> "Root OK, but no [NoVPNDetect] entries found yet. Use Reload after opening a scoped app."
                    else -> "Root unavailable or denied. Grant root to this app in KernelSU, then Reload.\n" + text
                }
                logView.text = text
            }
        }.start()
    }

    private fun runSu(cmd: String): String? = try {
        val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start()
        val text = p.inputStream.bufferedReader().use { it.readText() }
        val code = p.waitFor()
        if (code == 0) text else text + "\n(su exit code $code)"
    } catch (t: Throwable) {
        null
    }

    private fun copyLogs() {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("NoVPNDetect logs", logView.text))
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show()
    }
}
