package com.kimera.pas.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import com.kimera.pas.spoof.DeviceCatalog
import java.security.SecureRandom

/**
 * Module GUI: spoof settings (SDK / ABI / Widevine / GSF) with floating
 * Apply/Clear buttons and a collapsed log viewer.
 */
class MainActivity : Activity() {

    private lateinit var nativeCheck: CheckBox
    private lateinit var compatCheck: CheckBox
    private lateinit var sdkCheck: CheckBox
    private lateinit var sdkSpinner: Spinner
    private lateinit var abiCheck: CheckBox
    private lateinit var abiGroup: RadioGroup
    private lateinit var abiX86: RadioButton
    private lateinit var abiArm64: RadioButton
    private lateinit var cpuCheck: CheckBox
    private lateinit var cpuSpinner: Spinner
    private lateinit var gpuCheck: CheckBox
    private lateinit var gpuSpinner: Spinner
    private lateinit var wvCheck: CheckBox
    private lateinit var wvEdit: EditText
    private lateinit var gsfCheck: CheckBox
    private lateinit var gsfEdit: EditText
    private lateinit var reconCheck: CheckBox
    private lateinit var spoofStatus: TextView
    private lateinit var logsHeader: TextView
    private lateinit var logsContainer: LinearLayout
    private lateinit var status: TextView
    private lateinit var logView: TextView
    private lateinit var bottomBar: LinearLayout

    private var busy = false
    private var suppressDirty = false
    private var currentSdk = 0
    private val rng = SecureRandom()
    private val sdkValues = ArrayList<Int>()
    private val sdkLabels = ArrayList<String>()

    private val ui = Handler(Looper.getMainLooper())
    private val statusTick = object : Runnable {
        override fun run() {
            refreshSpoofStatus()
            ui.postDelayed(this, 3000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()
        currentSdk = android.os.Build.VERSION.SDK_INT

        val root = FrameLayout(this)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, (72 * density).toInt())
        }

        content.addView(
            TextView(this).apply {
                text = "PerAppSpoofer v${versionName()} by KiMeRa"
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f)
                setTypeface(typeface, Typeface.BOLD)
            }
        )

        spoofStatus = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setPadding(0, pad / 4, 0, pad / 2)
        }
        content.addView(spoofStatus)

        content.addView(sectionLabel("Spoof / native addon", pad))

        // ---------------- native addon ----------------
        nativeCheck = CheckBox(this).apply {
            text = "Enable native addon (advanced VPN-trace hooks)"
        }
        compatCheck = CheckBox(this).apply {
            text = "Compatibility mode (skip extended native hooks)"
        }
        content.addView(nativeCheck)
        content.addView(compatCheck)

        // ---------------- SDK picker ----------------
        buildSdkOptions()
        sdkCheck = CheckBox(this).apply { text = "Spoof SDK" }
        sdkSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity,
                android.R.layout.simple_spinner_item,
                sdkLabels
            ).apply { setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
        }
        content.addView(row(sdkCheck, sdkSpinner, { randomSdk() }, { clearSdk() }))

        // ---------------- ABI ----------------
        abiCheck = CheckBox(this).apply { text = "Spoof CPU ABI" }
        abiX86 = RadioButton(this).apply { id = View.generateViewId(); text = "x86_64" }
        abiArm64 = RadioButton(this).apply { id = View.generateViewId(); text = "arm64-v8a" }
        abiGroup = RadioGroup(this).apply {
            orientation = RadioGroup.HORIZONTAL
            addView(abiX86)
            addView(abiArm64)
            check(abiX86.id)
        }
        content.addView(row(abiCheck, abiGroup, { randomAbi() }, { clearAbi() }))

        // ---------------- CPU ----------------
        cpuCheck = CheckBox(this).apply { text = "Spoof CPU model" }
        cpuSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity,
                android.R.layout.simple_spinner_item,
                DeviceCatalog.CPUS.map { it.display }
            ).apply { setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
        }
        content.addView(row(cpuCheck, cpuSpinner, { randomCpu() }, { clearCpu() }))

        // ---------------- GPU ----------------
        gpuCheck = CheckBox(this).apply { text = "Spoof GPU (OpenGL)" }
        gpuSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity,
                android.R.layout.simple_spinner_item,
                DeviceCatalog.GPUS.map { "${it.vendor} ${it.renderer}" }
            ).apply { setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
        }
        content.addView(row(gpuCheck, gpuSpinner, { randomGpu() }, { clearGpu() }))

        // ---------------- Widevine ----------------
        wvCheck = CheckBox(this).apply { text = "Spoof Widevine (report L1)" }
        wvEdit = EditText(this).apply {
            hint = "deviceUniqueId (hex, 64 chars)"
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        content.addView(
            row(wvCheck, wvEdit, { wvEdit.setText(randomWidevine()) }, { clearWidevine() },
                editWeight = true)
        )

        // ---------------- GSF ----------------
        gsfCheck = CheckBox(this).apply { text = "Spoof GSF ID" }
        gsfEdit = EditText(this).apply {
            hint = "gsf id (digits)"
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        content.addView(
            row(gsfCheck, gsfEdit, { gsfEdit.setText(randomGsf()) }, { clearGsf() },
                editWeight = true)
        )

        // ---------------- Diagnostics ----------------
        content.addView(sectionLabel("Diagnostics", pad))
        reconCheck = CheckBox(this).apply {
            text = "Recon logging (verbose; for diagnosing app detections)"
        }
        content.addView(reconCheck)

        // ---------------- Logs (folded by default) ----------------
        logsHeader = sectionLabel("Logs (tap to expand) \u25B8", pad).apply {
            setOnClickListener { toggleLogs() }
        }
        content.addView(logsHeader)

        logsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        status = TextView(this).apply {
            text = "Root (via KernelSU) is only needed to read the LSPosed/Vector log file."
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        }
        logsContainer.addView(status)
        val logButtons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        logButtons.addView(smallButton("Reload") { loadLogs() })
        logButtons.addView(smallButton("Copy") { copyLogs() })
        logButtons.addView(smallButton("Clear") { logView.text = "" })
        logsContainer.addView(logButtons)
        val logScroll = ScrollView(this)
        logView = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        logScroll.addView(logView)
        logsContainer.addView(
            logScroll,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (240 * density).toInt()
            )
        )
        content.addView(logsContainer)

        // ---------------- root layout ----------------
        val contentScroll = ScrollView(this)
        contentScroll.addView(content)
        root.addView(
            contentScroll,
            FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        )

        bottomBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        bottomBar.addView(
            roundButton("Clear", false) { revertToSaved() },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                .apply { rightMargin = pad / 2 }
        )
        bottomBar.addView(
            roundButton("Apply", true) { saveSpoof() },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                .apply { leftMargin = pad / 2 }
        )
        root.addView(
            bottomBar,
            FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM
            ).apply { setMargins(pad, pad, pad, pad) }
        )

        setContentView(root)

        SpoofSettings.ensureListener(this)
        loadSaved()
        attachListeners()
        updateDirty()
        refreshSpoofStatus()
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
    // layout helpers
    // ------------------------------------------------------------------

    private fun sectionLabel(text: String, pad: Int): TextView = TextView(this).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, pad / 2, 0, pad / 4)
    }

    private fun smallButton(label: String, onClick: () -> Unit): Button =
        Button(this).apply {
            text = label
            setOnClickListener { onClick() }
        }

    private fun roundButton(label: String, filled: Boolean, onClick: () -> Unit): Button =
        Button(this).apply {
            text = label
            setOnClickListener { onClick() }
            val d = resources.displayMetrics.density
            val bg = GradientDrawable().apply {
                cornerRadius = 22f * d
                setColor(if (filled) 0xFF2E7D32.toInt() else 0xFF455A64.toInt())
            }
            background = bg
            setTextColor(Color.WHITE)
            elevation = 6f * d
            minHeight = (44 * d).toInt()
        }

    /**
     * One feature row: the main control (checkbox etc) on top, then the field
     * plus its Random / Clear buttons below.
     */
    private fun row(
        main: View,
        field: View,
        onRandom: () -> Unit,
        onClear: () -> Unit,
        editWeight: Boolean = false
    ): LinearLayout {
        val r = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, (8 * resources.displayMetrics.density).toInt())
        }
        r.addView(main)
        val f = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        if (editWeight) {
            f.addView(
                field,
                LinearLayout.LayoutParams(
                    0,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    1f
                )
            )
        } else {
            f.addView(field)
        }
        f.addView(smallButton("Random") { onRandom() })
        f.addView(smallButton("Clear") { onClear() })
        r.addView(f)
        return r
    }

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
    }

    private fun versionName(): String = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: "?"
    } catch (t: Throwable) {
        "?"
    }

    // ------------------------------------------------------------------
    // SDK picker
    // ------------------------------------------------------------------

    private fun buildSdkOptions() {
        sdkValues.clear()
        sdkLabels.clear()
        sdkValues.add(currentSdk)
        sdkLabels.add("SDK $currentSdk (current)")
        for (v in 32..37) {
            if (v == currentSdk) continue
            sdkValues.add(v)
            sdkLabels.add("SDK $v (Android ${androidVersionFor(v)})")
        }
    }

    private fun androidVersionFor(v: Int): String = when (v) {
        32 -> "12"
        33 -> "13"
        34 -> "14"
        35 -> "15"
        36 -> "16"
        37 -> "17"
        else -> "?"
    }

    private fun sdkIndexFor(v: Int): Int {
        val i = sdkValues.indexOf(v)
        return if (i >= 0) i else 0
    }

    private fun cpuIndexFor(v: String): Int =
        DeviceCatalog.CPUS.indexOfFirst { it.display == v }.coerceAtLeast(0)

    private fun gpuIndexFor(v: String): Int =
        DeviceCatalog.GPUS.indexOfFirst { it.renderer == v }.coerceAtLeast(0)

    private fun sdkValueSelected(): Int =
        sdkValues.getOrElse(sdkSpinner.selectedItemPosition) { currentSdk }

    private fun cpuSelected(): String =
        DeviceCatalog.CPUS.getOrElse(cpuSpinner.selectedItemPosition) { DeviceCatalog.CPUS[0] }.display

    private fun gpuSelected(): String =
        DeviceCatalog.GPUS.getOrElse(gpuSpinner.selectedItemPosition) { DeviceCatalog.GPUS[0] }.renderer

    // ------------------------------------------------------------------
    // random / clear per feature
    // ------------------------------------------------------------------

    private fun randomSdk() {
        sdkSpinner.setSelection(rng.nextInt(sdkValues.size))
    }

    private fun clearSdk() {
        sdkSpinner.setSelection(sdkIndexFor(currentSdk))
        sdkCheck.isChecked = false
    }

    private fun randomAbi() {
        abiGroup.check(if (rng.nextBoolean()) abiX86.id else abiArm64.id)
    }

    private fun clearAbi() {
        abiGroup.check(abiX86.id)
        abiCheck.isChecked = false
    }

    private fun randomCpu() {
        cpuSpinner.setSelection(rng.nextInt(DeviceCatalog.CPUS.size))
    }

    private fun clearCpu() {
        cpuSpinner.setSelection(0)
        cpuCheck.isChecked = false
    }

    private fun randomGpu() {
        gpuSpinner.setSelection(rng.nextInt(DeviceCatalog.GPUS.size))
    }

    private fun clearGpu() {
        gpuSpinner.setSelection(0)
        gpuCheck.isChecked = false
    }

    private fun randomWidevine(): String = buildString {
        repeat(64) { append("0123456789abcdef"[rng.nextInt(16)]) }
    }

    private fun clearWidevine() {
        wvEdit.setText("")
        wvCheck.isChecked = false
    }

    private fun randomGsf(): String {
        val sb = StringBuilder()
        sb.append(('1'.code + rng.nextInt(9)).toChar())
        repeat(15) { sb.append(('0'.code + rng.nextInt(10)).toChar()) }
        return sb.toString()
    }

    private fun clearGsf() {
        gsfEdit.setText("")
        gsfCheck.isChecked = false
    }

    // ------------------------------------------------------------------
    // state: load / save / dirty
    // ------------------------------------------------------------------

    private fun loadSaved() {
        val sp = SpoofSettings.load(this)
        suppressDirty = true
        nativeCheck.isChecked = sp.getBoolean("native_enabled", false)
        compatCheck.isChecked = sp.getBoolean("safe_mode", true)
        sdkCheck.isChecked = sp.getBoolean("sdk_enabled", false)
        sdkSpinner.setSelection(sdkIndexFor(sp.getInt("sdk_value", currentSdk)))
        abiCheck.isChecked = sp.getBoolean("abi_enabled", false)
        abiGroup.check(
            if (sp.getString("abi_value", "x86_64") == "arm64-v8a") abiArm64.id else abiX86.id
        )
        cpuCheck.isChecked = sp.getBoolean("cpu_enabled", false)
        cpuSpinner.setSelection(cpuIndexFor(sp.getString("cpu_value", "") ?: ""))
        gpuCheck.isChecked = sp.getBoolean("gpu_enabled", false)
        gpuSpinner.setSelection(gpuIndexFor(sp.getString("gpu_value", "") ?: ""))
        wvCheck.isChecked = sp.getBoolean("widevine_enabled", false)
        wvEdit.setText(sp.getString("widevine_id", "") ?: "")
        gsfCheck.isChecked = sp.getBoolean("gsf_enabled", false)
        gsfEdit.setText(sp.getString("gsf_id", "") ?: "")
        reconCheck.isChecked = sp.getBoolean("recon_enabled", false)
        suppressDirty = false
    }

    private fun currentMap(): HashMap<String, Any?> = hashMapOf(
        "native_enabled" to nativeCheck.isChecked,
        "safe_mode" to compatCheck.isChecked,
        "sdk_enabled" to sdkCheck.isChecked,
        "sdk_value" to sdkValueSelected(),
        "abi_enabled" to abiCheck.isChecked,
        "abi_value" to (if (abiArm64.isChecked) "arm64-v8a" else "x86_64"),
        "cpu_enabled" to cpuCheck.isChecked,
        "cpu_value" to cpuSelected(),
        "gpu_enabled" to gpuCheck.isChecked,
        "gpu_value" to gpuSelected(),
        "widevine_enabled" to wvCheck.isChecked,
        "widevine_id" to wvEdit.text.toString().trim().lowercase(),
        "gsf_enabled" to gsfCheck.isChecked,
        "gsf_id" to gsfEdit.text.toString().trim(),
        "recon_enabled" to reconCheck.isChecked
    )

    private fun savedMap(): HashMap<String, Any?> {
        val sp = SpoofSettings.load(this)
        return hashMapOf(
            "native_enabled" to sp.getBoolean("native_enabled", false),
            "safe_mode" to sp.getBoolean("safe_mode", true),
            "sdk_enabled" to sp.getBoolean("sdk_enabled", false),
            "sdk_value" to sp.getInt("sdk_value", currentSdk),
            "abi_enabled" to sp.getBoolean("abi_enabled", false),
            "abi_value" to (sp.getString("abi_value", "x86_64") ?: "x86_64"),
            "cpu_enabled" to sp.getBoolean("cpu_enabled", false),
            "cpu_value" to DeviceCatalog.cpu(sp.getString("cpu_value", null)).display,
            "gpu_enabled" to sp.getBoolean("gpu_enabled", false),
            "gpu_value" to DeviceCatalog.gpu(sp.getString("gpu_value", null)).renderer,
            "widevine_enabled" to sp.getBoolean("widevine_enabled", false),
            "widevine_id" to (sp.getString("widevine_id", "") ?: ""),
            "gsf_enabled" to sp.getBoolean("gsf_enabled", false),
            "gsf_id" to (sp.getString("gsf_id", "") ?: ""),
            "recon_enabled" to sp.getBoolean("recon_enabled", false)
        )
    }

    private fun updateDirty() {
        if (suppressDirty || !::bottomBar.isInitialized) return
        val dirty = currentMap() != savedMap()
        bottomBar.visibility = if (dirty) View.VISIBLE else View.GONE
    }

    private fun attachListeners() {
        val watcher = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                updateDirty()
            }
        }
        wvEdit.addTextChangedListener(watcher)
        gsfEdit.addTextChangedListener(watcher)

        val checkListener =
            android.widget.CompoundButton.OnCheckedChangeListener { _, _ -> updateDirty() }
        nativeCheck.setOnCheckedChangeListener(checkListener)
        compatCheck.setOnCheckedChangeListener(checkListener)
        sdkCheck.setOnCheckedChangeListener(checkListener)
        abiCheck.setOnCheckedChangeListener(checkListener)
        cpuCheck.setOnCheckedChangeListener(checkListener)
        gpuCheck.setOnCheckedChangeListener(checkListener)
        wvCheck.setOnCheckedChangeListener(checkListener)
        gsfCheck.setOnCheckedChangeListener(checkListener)
        reconCheck.setOnCheckedChangeListener(checkListener)

        abiGroup.setOnCheckedChangeListener { _, _ -> updateDirty() }
        val spinnerListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>?,
                view: View?,
                position: Int,
                id: Long
            ) {
                updateDirty()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        sdkSpinner.onItemSelectedListener = spinnerListener
        cpuSpinner.onItemSelectedListener = spinnerListener
        gpuSpinner.onItemSelectedListener = spinnerListener
    }

    private fun saveSpoof() {
        // Auto-fill ids when a row is enabled with an empty field.
        if (wvCheck.isChecked && wvEdit.text.isBlank()) {
            wvEdit.setText(randomWidevine())
        }
        if (gsfCheck.isChecked && gsfEdit.text.isBlank()) {
            gsfEdit.setText(randomGsf())
        }

        val wv = wvEdit.text.toString().trim().lowercase()
        if (wvCheck.isChecked && (wv.isEmpty() || wv.length % 2 != 0 || !wv.all { it in "0123456789abcdef" })) {
            toast("Widevine id must be hex, even length (64 chars = 32 bytes)")
            return
        }
        val gsf = gsfEdit.text.toString().trim()
        if (gsfCheck.isChecked && (gsf.isEmpty() || gsf.length !in 8..19 || !gsf.all { it.isDigit() })) {
            toast("GSF id must be digits (8-19)")
            return
        }

        suppressDirty = true
        wvEdit.setText(wv)
        gsfEdit.setText(gsf)
        suppressDirty = false

        val err = SpoofSettings.save(this, currentMap())
        SpoofSettings.ensureListener(this) // apply & reconnect
        toast(err ?: "Saved \u2713 - takes effect when the scoped app restarts")
        updateDirty()
        refreshSpoofStatus()
    }

    private fun revertToSaved() {
        loadSaved()
        updateDirty()
    }

    private fun refreshSpoofStatus() {
        spoofStatus.text =
            if (SpoofSettings.isConnected()) {
                "Vector service: connected \u2713 - changes apply when the scoped app is restarted."
            } else {
                "Vector service: not connected. Enable this module in Vector, then reopen this app."
            }
    }

    // ------------------------------------------------------------------
    // log viewer
    // ------------------------------------------------------------------

    private fun toggleLogs() {
        val show = logsContainer.visibility != View.VISIBLE
        logsContainer.visibility = if (show) View.VISIBLE else View.GONE
        logsHeader.text =
            if (show) "Logs (tap to collapse) \u25BE" else "Logs (tap to expand) \u25B8"
        if (show) loadLogs()
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
                        "| grep -a PerAppSpoofer | tail -n 600"
                )
                if (lspd != null) rootWorks = true
                if (!lspd.isNullOrBlank()) {
                    out.append("=== LSPosed/Vector log ===\n").append(lspd).append("\n\n")
                }
                val lc = runSu("logcat -d -t 4000 | grep -a PerAppSpoofer | tail -n 400")
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
                    rootWorks -> "Root OK, but no [PerAppSpoofer] entries found yet. Use Reload after opening a scoped app."
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
        cm.setPrimaryClip(ClipData.newPlainText("PerAppSpoofer logs", logView.text))
        toast("Copied")
    }
}
