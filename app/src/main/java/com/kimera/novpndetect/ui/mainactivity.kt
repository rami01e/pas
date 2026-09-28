package com.kimera.novpndetect.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/**
 * Module GUI: spoof settings + built-in log viewer.
 *
 * Spoof settings are written to the framework's remote preferences via the
 * Vector service; scoped apps pick them up on their next process start.
 */
class MainActivity : Activity() {

    private lateinit var logView: TextView
    private lateinit var status: TextView
    private lateinit var spoofStatus: TextView
    private lateinit var sdkCheck: CheckBox
    private lateinit var sdkEdit: EditText
    private lateinit var abiCheck: CheckBox
    private lateinit var abiGroup: RadioGroup
    private lateinit var abiX86: RadioButton
    private lateinit var abiArm64: RadioButton
    private var busy = false

    private val ui = Handler(Looper.getMainLooper())
    private val statusTick = object : Runnable {
        override fun run() {
            refreshSpoofStatus()
            ui.postDelayed(this, 3000)
        }
    }

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

        // ---------------- spoof settings ----------------
        root.addView(sectionLabel("Per-app spoofing (SDK / CPU ABI)", pad))

        sdkCheck = CheckBox(this).apply { text = "Spoof Android version (SDK_INT)" }
        sdkEdit = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(android.os.Build.VERSION.SDK_INT.toString())
            setSingleLine(true)
            setWidth((96 * resources.displayMetrics.density).toInt())
        }
        root.addView(
            LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(sdkCheck)
                addView(sdkEdit)
            }
        )

        abiCheck = CheckBox(this).apply { text = "Spoof CPU ABI" }
        abiX86 = RadioButton(this).apply {
            id = android.view.View.generateViewId()
            text = "x86_64 (current)"
        }
        abiArm64 = RadioButton(this).apply {
            id = android.view.View.generateViewId()
            text = "arm64-v8a"
        }
        abiGroup = RadioGroup(this).apply {
            orientation = RadioGroup.HORIZONTAL
            addView(abiX86)
            addView(abiArm64)
            check(abiX86.id)
        }
        root.addView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                addView(abiCheck)
                addView(abiGroup)
            }
        )

        root.addView(
            button("Save spoof settings") { saveSpoof() }.apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
        )
        spoofStatus = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setPadding(0, pad / 4, 0, pad / 2)
        }
        root.addView(spoofStatus)

        // ---------------- logs ----------------
        root.addView(sectionLabel("Logs", pad))
        status = TextView(this).apply {
            text = "Loading\u2026 Root (via KernelSU) is only needed so the app can read the LSPosed/Vector log file."
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(0, pad / 4, 0, pad / 4)
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

        SpoofSettings.ensureListener()
        loadSpoofValues()
        refreshSpoofStatus()
        loadLogs()
    }

    override fun onStart() {
        super.onStart()
        ui.post(statusTick)
    }

    override fun onStop() {
        super.onStop()
        ui.removeCallbacks(statusTick)
    }

    // ------------------------------------------------------------------

    private fun sectionLabel(text: String, pad: Int): TextView = TextView(this).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, pad / 2, 0, pad / 4)
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

    private fun loadSpoofValues() {
        val sp = SpoofSettings.load(this)
        sdkCheck.isChecked = sp.getBoolean("sdk_enabled", false)
        val v = sp.getInt("sdk_value", 0)
        if (v in 21..45) sdkEdit.setText(v.toString())
        abiCheck.isChecked = sp.getBoolean("abi_enabled", false)
        if (sp.getString("abi_value", "x86_64") == "arm64-v8a") {
            abiGroup.check(abiArm64.id)
        } else {
            abiGroup.check(abiX86.id)
        }
    }

    private fun saveSpoof() {
        val sdkOn = sdkCheck.isChecked
        val sdkVal = sdkEdit.text.toString().trim().toIntOrNull() ?: -1
        if (sdkOn && sdkVal !in 21..45) {
            Toast.makeText(this, "SDK value must be 21-45", Toast.LENGTH_SHORT).show()
            return
        }
        val abiOn = abiCheck.isChecked
        val abiVal = if (abiArm64.isChecked) "arm64-v8a" else "x86_64"
        val err = SpoofSettings.save(this, sdkOn, if (sdkVal > 0) sdkVal else 0, abiOn, abiVal)
        Toast.makeText(
            this,
            err ?: "Saved \u2713 — takes effect when the target app restarts",
            Toast.LENGTH_LONG
        ).show()
        refreshSpoofStatus()
    }

    private fun refreshSpoofStatus() {
        spoofStatus.text =
            if (SpoofSettings.isConnected()) {
                "Vector service: connected \u2713 — changes apply when the scoped app is restarted."
            } else {
                "Vector service: not connected. Enable this module in Vector, then reopen this app."
            }
    }

    // ------------------------------------------------------------------
    // log viewer
    // ------------------------------------------------------------------

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
