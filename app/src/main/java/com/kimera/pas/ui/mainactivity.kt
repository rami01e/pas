package com.kimera.pas.ui

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Canvas
import android.net.Uri
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.CheckBox
import android.widget.ListView
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.kimera.pas.spoof.DeviceCatalog
import java.security.SecureRandom

/**
 * Module GUI (v2.0.0 revamp) - "mission control" console.
 *
 * Compact telemetry layout: panel sections (Spoof / Network / Scope /
 * Diagnostics / Logs), label rows with monospace value readouts, custom
 * square-knob switches, state chips, floating Apply/Clear bar (dirty only)
 * and a terminal-style log console. All feature semantics are unchanged from
 * the previous GUI; SDK / CPU / GPU values open pick-from-list dialogs.
 */
class MainActivity : Activity() {

    // ------------------------------------------------------------------
    // palette - "mission control" tokens
    // ------------------------------------------------------------------
    private val cBg = 0xFF0B1120.toInt()
    private val cPanel = 0xFF111827.toInt()
    private val cPanelHdr = 0xFF0F1626.toInt()
    private val cBorder = 0xFF1E3A5F.toInt()
    private val cDiv = 0xFF162035.toInt()
    private val cText = 0xFFE8F0FE.toInt()
    private val cText2 = 0xFF8BA3C7.toInt()
    private val cText3 = 0xFF4A6080.toInt()
    private val cAmber = 0xFFFFB800.toInt()
    private val cCyan = 0xFF00D4FF.toInt()
    private val cGreen = 0xFF26DE81.toInt()
    private val cRed = 0xFFFF4757.toInt()
    private val cKnobOff = 0xFF4A6080.toInt()
    private val cTrackOff = 0xFF0D1526.toInt()
    private val cTrackOffBorder = 0xFF2A4468.toInt()
    private val cConsoleBg = 0xFF0A0F1D.toInt()
    private val cConsoleTx = 0xFF7FA3CC.toInt()
    private val cApplyTx = 0xFF08110B.toInt()

    private val density get() = resources.displayMetrics.density
    private fun dp(v: Number): Int = (v.toFloat() * density).toInt()
    private fun withAlpha(c: Int, a: Int): Int = (c and 0x00FFFFFF) or (a shl 24)

    // ------------------------------------------------------------------
    // widgets + state
    // ------------------------------------------------------------------
    private lateinit var content: LinearLayout
    private lateinit var statusText: TextView
    private lateinit var svcChip: TextView
    private lateinit var dirtyChip: TextView
    private lateinit var appliedChip: TextView

    private lateinit var nativeSw: SwitchView
    private lateinit var nativeChip: TextView
    private lateinit var compatSw: SwitchView

    private lateinit var sdkSw: SwitchView
    private lateinit var sdkValue: TextView
    private lateinit var abiSw: SwitchView
    private lateinit var abiValue: TextView
    private lateinit var cpuSw: SwitchView
    private lateinit var cpuValue: TextView
    private lateinit var gpuSw: SwitchView
    private lateinit var gpuValue: TextView
    private lateinit var wvSw: SwitchView
    private lateinit var wvValue: TextView
    private lateinit var gsfSw: SwitchView
    private lateinit var gsfValue: TextView

    private lateinit var vulkanSw: SwitchView
    private lateinit var vulkanChip: TextView
    private lateinit var chainSw: SwitchView
    private lateinit var chainChip: TextView
    private lateinit var webrtcSw: SwitchView
    private lateinit var webrtcChip: TextView
    private var webrtcOn = true
    private lateinit var lightSw: SwitchView
    private lateinit var netSw: SwitchView
    private lateinit var netValue: TextView
    private var netCellularSel = false
    private lateinit var reconSw: SwitchView
    private lateinit var blSw: SwitchView
    private lateinit var blValue: TextView
    private var blEditVal = ""

    private lateinit var scopeChip: TextView

    private lateinit var logsChev: TextView
    private lateinit var logsContainer: LinearLayout
    private lateinit var logsStatus: TextView
    private lateinit var logView: TextView
    private lateinit var logGutter: TextView
    private lateinit var logGutterScroll: ScrollView
    private lateinit var logContentScroll: ScrollView
    private var lastLogText: String = ""
    private lateinit var bottomBar: LinearLayout

    private var busy = false
    private var forceBusy = false
    private var suppressDirty = false
    private var currentSdk = 0

    private var sdkSel = 0
    private var cpuSel = 0
    private var gpuSel = 0
    private var abiModeSel = 0
    private var wvEditVal = ""
    private var gsfEditVal = ""

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
    private val hideApplied = Runnable { appliedChip.visibility = View.GONE }

    // ------------------------------------------------------------------
    // lifecycle
    // ------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        currentSdk = android.os.Build.VERSION.SDK_INT
        window.statusBarColor = cBg
        window.navigationBarColor = cBg

        val root = FrameLayout(this).apply { setBackgroundColor(cBg) }
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(96))
        }
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            addView(content)
        }
        root.addView(
            scroll,
            FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        )

        // ---------------- header ----------------
        val header = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val titleBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        titleBox.addView(
            TextView(this).apply {
                text = "PerAppSpoofer"
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 17f)
                typeface = Typeface.MONOSPACE
                setTypeface(typeface, Typeface.BOLD)
                setTextColor(cText)
                letterSpacing = -0.01f
            }
        )
        titleBox.addView(
            TextView(this).apply {
                text = "v${versionName()} \u00b7 KiMeRa"
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                typeface = Typeface.MONOSPACE
                setTextColor(cText3)
                setPadding(0, dp(3), 0, 0)
            }
        )
        header.addView(
            titleBox,
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        )
        val chipsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        svcChip = chipView("Nominal", cCyan)
        dirtyChip = chipView("Dirty", cAmber).apply { visibility = View.GONE }
        appliedChip = chipView("Applied", cGreen).apply { visibility = View.GONE }
        chipsRow.addView(svcChip)
        chipsRow.addView(
            dirtyChip,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { leftMargin = dp(6) }
        )
        chipsRow.addView(
            appliedChip,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { leftMargin = dp(6) }
        )
        header.addView(chipsRow)
        content.addView(header)

        statusText = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
            setTextColor(cText2)
            setPadding(0, dp(4), 0, dp(10))
        }
        content.addView(statusText)

        // ---------------- utility actions ----------------
        content.addView(
            actionButton("Force-close scoped apps", "Root", false) { forceCloseScoped() },
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
        )
        content.addView(
            actionButton("Open WebGL test page", null, false) { openWebglTest() },
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(12) }
        )

        // ---------------- SCOPE panel ----------------
        scopeChip = chipView("\u2014", cText2)
        val (scopePanel, scopeBody) = panel("Scope", scopeChip, null)
        addPanel(scopePanel)
        addRow(scopeBody, true) {
            addView(
                TextView(this@MainActivity).apply {
                    text = "Manage scope"
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                    setTextColor(cText)
                }
            )
            val line = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            line.addView(
                TextView(this@MainActivity).apply {
                    text = "Pick apps to include or remove"
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
                    typeface = Typeface.MONOSPACE
                    setTextColor(cText3)
                },
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            )
            line.addView(micro("Manage") { openScopeDialog() })
            addView(
                line,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { leftMargin = dp(38); topMargin = dp(6) }
            )
        }

        // ---------------- NATIVE panel ----------------
        val (spoofPanel, spoofBody) = panel("Native", null, null)
        addPanel(spoofPanel)

        sdkSw = SwitchView(this)
        sdkValue = valueTextView()
        valueRow(spoofBody, true, sdkSw, "SDK", sdkValue,
            { pickSdk() }, { randomSdk() }, { clearSdk() })

        abiSw = SwitchView(this)
        abiValue = valueTextView()
        valueRow(spoofBody, false, abiSw, "CPU ABI", abiValue,
            { pickAbi() }, { cycleAbi() }, { clearAbi() })

        cpuSw = SwitchView(this)
        cpuValue = valueTextView()
        valueRow(spoofBody, false, cpuSw, "CPU model", cpuValue,
            { pickCpu() }, { randomCpu() }, { clearCpu() })

        gpuSw = SwitchView(this)
        gpuValue = valueTextView()
        valueRow(spoofBody, false, gpuSw, "GPU", gpuValue,
            { pickGpu() }, { randomGpu() }, { clearGpu() })

        // ---------------- JAVA panel ----------------
        val (javaPanel, javaBody) = panel("Java", null, null)
        addPanel(javaPanel)

        wvSw = SwitchView(this)
        wvValue = valueTextView()
        valueRow(javaBody, true, wvSw, "Widevine", wvValue,
            { editWidevine() }, { wvEditVal = randomWidevine(); updateWvValue(); updateDirty() },
            { clearWidevine() })

        gsfSw = SwitchView(this)
        gsfValue = valueTextView()
        valueRow(javaBody, false, gsfSw, "GSF ID", gsfValue,
            { editGsf() }, { gsfEditVal = randomGsf(); updateGsfValue(); updateDirty() },
            { clearGsf() })

        // ---------------- LOGS panel ----------------
        logsChev = TextView(this).apply {
            text = "\u25B8"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(cText3)
        }
        val logsTrailing = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        logsTrailing.addView(
            TextView(this).apply {
                text = "DEBUG"
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 9.5f)
                typeface = Typeface.DEFAULT_BOLD
                letterSpacing = 0.08f
                setTextColor(cText3)
                setPadding(0, 0, dp(4), 0)
            }
        )
        lightSw = SwitchView(this)
        logsTrailing.addView(lightSw)
        logsTrailing.addView(microIcon("\uD83D\uDD0D\uFE0F") { runDiagnose() })
        logsTrailing.addView(microIcon("\uD83D\uDD04\uFE0F") { loadLogs() })
        logsTrailing.addView(microIcon("\u29C9") { copyLogs() })
        logsTrailing.addView(
            logsChev,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { leftMargin = dp(6) }
        )
        val (logsPanel, logsBody) = panel("Debug", logsTrailing) { toggleLogs() }
        addPanel(logsPanel)

        // Debug toggles: the four former NATIVE switches plus safe mode and
        // recon. All of them fold away with the section; the log console
        // stays below them.
        nativeSw = SwitchView(this)
        nativeChip = chipView("Off", cText2)
        toggleRow(
            logsBody, true, nativeSw, "Native addon",
            "Native hook engine \u2014 VPN-trace + device surfaces", nativeChip
        )

        vulkanSw = SwitchView(this)
        vulkanChip = chipView("On", cCyan)
        toggleRow(
            logsBody, false, vulkanSw, "Vulkan identity",
            "Vulkan driver identity (physical device properties)", vulkanChip
        )

        chainSw = SwitchView(this)
        chainChip = chipView("On", cCyan)
        toggleRow(
            logsBody, false, chainSw, "GL dlsym chain",
            "GL symbol substitution for engines resolving through dlsym / eglGetProcAddress", chainChip
        )

        // WebRTC local IP: on = Balanced (default), off = RKN (strict).
        webrtcSw = SwitchView(this)
        webrtcChip = chipView("REAL", cCyan)
        toggleRow(
            logsBody, false, webrtcSw, "WebRTC local IP",
            "On (default): browsers see your REAL local IP - RKN-clean \u00b7 Off: strict hiding (RKN)",
            webrtcChip
        )

        compatSw = SwitchView(this)
        toggleRow(
            logsBody, false, compatSw, "safe mode",
            "Skip extended hook groups (netlink / ioctl / props)", null
        )

        reconSw = SwitchView(this)
        toggleRow(
            logsBody, false, reconSw, "Recon",
            "Verbose probe capture for detection mapping", null
        )

        // Net type: per-app WIFI / CELLULAR source selection.
        netSw = SwitchView(this)
        netValue = valueTextView()
        valueRow(logsBody, false, netSw, "Net type", netValue,
            { pickNet() }, { cycleNet() }, { clearNet() })

        // Bootloader version (matches real-device Build.BOOTLOADER naming).
        blSw = SwitchView(this)
        blValue = valueTextView()
        valueRow(logsBody, false, blSw, "Bootloader", blValue,
            { editBl() }, { blEditVal = randomBl(); updateBlValue(); updateDirty() },
            { clearBl() })

        logsContainer = logsBody.apply { visibility = View.GONE }
        logsStatus = TextView(this).apply {
            text = "Reload to read the Vector log (root)."
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setTextColor(cText3)
            setPadding(dp(12), dp(2), dp(12), 0)
        }
        logsContainer.addView(
            logsStatus,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(6) }
        )
        val logArea = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = GradientDrawable().apply { setColor(cConsoleBg) }
        }
        logGutterScroll = ScrollView(this).apply {
            isVerticalScrollBarEnabled = false
            isFillViewport = true
        }
        logGutter = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            typeface = Typeface.MONOSPACE
            setTextColor(cText3)
            gravity = Gravity.END
            setIncludeFontPadding(false)
            setLineSpacing(0f, 1.0f)
            setPadding(dp(4), dp(8), dp(8), dp(8))
        }
        logGutterScroll.addView(logGutter)
        logArea.addView(
            logGutterScroll,
            LinearLayout.LayoutParams(dp(42), dp(240))
        )
        logArea.addView(
            View(this).apply { setBackgroundColor(cDiv) },
            LinearLayout.LayoutParams(dp(1), dp(240))
        )
        logContentScroll = ScrollView(this).apply {
            isVerticalScrollBarEnabled = true
            isFillViewport = true
        }
        logContentScroll.setOnScrollChangeListener { _, _, scrollY, _, _ ->
            if (::logGutterScroll.isInitialized) logGutterScroll.scrollTo(0, scrollY)
        }
        val logHScroll = android.widget.HorizontalScrollView(this).apply {
            isHorizontalScrollBarEnabled = true
        }
        logView = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            typeface = Typeface.MONOSPACE
            setTextColor(cConsoleTx)
            setIncludeFontPadding(false)
            setLineSpacing(0f, 1.0f)
            setHorizontallyScrolling(true)
            setPadding(dp(10), dp(8), dp(10), dp(8))
        }
        logHScroll.addView(logView)
        logContentScroll.addView(logHScroll)
        logArea.addView(
            logContentScroll,
            LinearLayout.LayoutParams(0, dp(240), 1f)
        )
        logsContainer.addView(
            logArea,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(4) }
        )

        // ---------------- floating commit bar ----------------
        bottomBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
            setPadding(dp(16), dp(12), dp(16), dp(14))
            background = GradientDrawable().apply {
                setColor(cBg)
                setStroke(dp(1), cBorder)
            }
        }
        bottomBar.addView(
            actionButton("Clear", null, false) { revertToSaved() },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.34f)
                .apply { rightMargin = dp(8) }
        )
        bottomBar.addView(
            actionButton("Apply", null, true) { saveSpoof() },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        )
        root.addView(
            bottomBar,
            FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM
            )
        )

        setContentView(root)

        buildSdkOptions()
        SpoofSettings.ensureListener(this)
        loadSaved()
        attachListeners()
        updateDirty()
        refreshSpoofStatus()
        refreshScopeChip()
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
    // view helpers
    // ------------------------------------------------------------------

    private inner class SwitchView(context: Context) : View(context) {
        var checked = false
            set(value) {
                field = value
                invalidate()
            }
        var onToggle: ((Boolean) -> Unit)? = null

        private val p = Paint(Paint.ANTI_ALIAS_FLAG)
        private val rect = RectF()

        init {
            isClickable = true
            isFocusable = true
            setOnClickListener {
                checked = !checked
                onToggle?.invoke(checked)
                invalidate()
            }
            setOnTouchListener { v, e ->
                when (e.actionMasked) {
                    MotionEvent.ACTION_DOWN -> v.alpha = 0.85f
                    MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> v.alpha = 1f
                }
                false
            }
        }

        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            setMeasuredDimension(dp(32), dp(20))
        }

        override fun onDraw(canvas: Canvas) {
            val w = width.toFloat()
            val h = height.toFloat()
            val r = dp(3).toFloat()
            rect.set(0f, 0f, w, h)
            if (checked) {
                p.style = Paint.Style.FILL
                p.color = withAlpha(cCyan, 0x24)
                canvas.drawRoundRect(rect, r, r, p)
                p.style = Paint.Style.STROKE
                p.strokeWidth = dp(1).toFloat()
                p.color = withAlpha(cCyan, 0x73)
                canvas.drawRoundRect(rect, r, r, p)
            } else {
                p.style = Paint.Style.FILL
                p.color = cTrackOff
                canvas.drawRoundRect(rect, r, r, p)
                p.style = Paint.Style.STROKE
                p.strokeWidth = dp(1).toFloat()
                p.color = cTrackOffBorder
                canvas.drawRoundRect(rect, r, r, p)
            }
            val ks = dp(14).toFloat()
            val kTop = (h - ks) / 2f
            val kLeft = if (checked) w - dp(2) - ks else dp(2).toFloat()
            p.style = Paint.Style.FILL
            p.color = if (checked) cCyan else cKnobOff
            rect.set(kLeft, kTop, kLeft + ks, kTop + ks)
            canvas.drawRoundRect(rect, dp(2).toFloat(), dp(2).toFloat(), p)
        }
    }

    private fun rounded(fill: Int, stroke: Int?, radiusDp: Int): GradientDrawable =
        GradientDrawable().apply {
            setColor(fill)
            cornerRadius = dp(radiusDp).toFloat()
            if (stroke != null) setStroke(dp(1), stroke)
        }

    private fun chipView(text: String, color: Int): TextView = TextView(this).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 9.5f)
        typeface = Typeface.DEFAULT_BOLD
        letterSpacing = 0.08f
        setTextColor(color)
        setPadding(dp(6), dp(3), dp(6), dp(3))
        background = rounded(withAlpha(color, 0x1F), withAlpha(color, 0x52), 2)
    }

    private fun styleChip(tv: TextView, color: Int) {
        tv.setTextColor(color)
        tv.background = rounded(withAlpha(color, 0x1F), withAlpha(color, 0x52), 2)
    }

    private fun divider(): View = View(this).apply { setBackgroundColor(cDiv) }

    private fun dividerLp(): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))

    private fun micro(label: String, onClick: () -> Unit): TextView = TextView(this).apply {
        text = label.uppercase()
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
        typeface = Typeface.DEFAULT_BOLD
        letterSpacing = 0.1f
        setTextColor(cText3)
        setPadding(dp(6), dp(3), dp(6), dp(3))
        isClickable = true
        isFocusable = true
        setOnClickListener { onClick() }
        setOnTouchListener { v, e ->
            when (e.actionMasked) {
                MotionEvent.ACTION_DOWN -> v.alpha = 0.7f
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> v.alpha = 1f
            }
            false
        }
    }

    private fun microIcon(label: String, onClick: () -> Unit): TextView = TextView(this).apply {
        text = label
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
        setTextColor(cText3)
        setPadding(dp(7), dp(2), dp(7), dp(2))
        isClickable = true
        isFocusable = true
        setOnClickListener { onClick() }
        setOnTouchListener { v, e ->
            when (e.actionMasked) {
                MotionEvent.ACTION_DOWN -> v.alpha = 0.6f
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> v.alpha = 1f
            }
            false
        }
    }

    private fun valueTextView(): TextView = TextView(this).apply {
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        typeface = Typeface.MONOSPACE
        setTextColor(cText3)
        isSingleLine = true
        ellipsize = android.text.TextUtils.TruncateAt.END
    }

    private fun actionButton(
        label: String,
        tag: String?,
        filled: Boolean,
        onTap: () -> Unit
    ): LinearLayout {
        val btn = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(10), dp(14), dp(10))
            background =
                if (filled) rounded(cGreen, null, 3)
                else rounded(0x00000000, cBorder, 3)
            isClickable = true
            isFocusable = true
            setOnClickListener { onTap() }
            setOnTouchListener { v, e ->
                when (e.actionMasked) {
                    MotionEvent.ACTION_DOWN -> v.alpha = 0.8f
                    MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> v.alpha = 1f
                }
                false
            }
        }
        btn.addView(
            TextView(this).apply {
                text = label.uppercase()
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                typeface = Typeface.DEFAULT_BOLD
                letterSpacing = 0.08f
                setTextColor(if (filled) cApplyTx else cText)
            },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        )
        if (tag != null) {
            btn.addView(
                TextView(this).apply {
                    text = tag.uppercase()
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 9.5f)
                    letterSpacing = 0.12f
                    setTextColor(if (filled) cApplyTx else cText3)
                }
            )
        }
        return btn
    }

    /** Panel = header (with optional trailing view / click) + body container. */
    private fun panel(
        title: String,
        trailing: View?,
        onHeaderClick: (() -> Unit)?
    ): Pair<LinearLayout, LinearLayout> {
        val wrap = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(cPanel, cBorder, 4)
        }
        val hdr = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(8), dp(12), dp(8))
            background = GradientDrawable().apply { setColor(cPanelHdr) }
            if (onHeaderClick != null) {
                isClickable = true
                setOnClickListener { onHeaderClick() }
            }
        }
        hdr.addView(
            TextView(this).apply {
                text = title.uppercase()
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                typeface = Typeface.DEFAULT_BOLD
                letterSpacing = 0.12f
                setTextColor(cText2)
            },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        )
        if (trailing != null) hdr.addView(trailing)
        wrap.addView(
            hdr,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        )
        wrap.addView(divider(), dividerLp())
        val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        wrap.addView(
            body,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        )
        return wrap to body
    }

    private fun addPanel(p: LinearLayout) {
        content.addView(
            p,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
        )
    }

    private fun addRow(parent: LinearLayout, first: Boolean, build: LinearLayout.() -> Unit) {
        if (!first) parent.addView(divider(), dividerLp())
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(9), dp(12), dp(9))
        }
        row.build()
        parent.addView(
            row,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        )
    }

    private fun rowHead(sw: SwitchView, name: String, chip: TextView?): LinearLayout {
        val head = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        head.addView(
            sw,
            LinearLayout.LayoutParams(dp(32), dp(20)).apply { rightMargin = dp(8) }
        )
        head.addView(
            TextView(this).apply {
                text = name
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f)
                setTextColor(cText)
            },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        )
        if (chip != null) head.addView(chip)
        return head
    }

    private fun toggleRow(
        parent: LinearLayout,
        first: Boolean,
        sw: SwitchView,
        name: String,
        hint: String,
        chip: TextView?
    ) {
        addRow(parent, first) {
            addView(rowHead(sw, name, chip))
            addView(
                TextView(this@MainActivity).apply {
                    text = hint
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                    typeface = Typeface.MONOSPACE
                    setTextColor(cText3)
                },
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { leftMargin = dp(38); topMargin = dp(6) }
            )
        }
    }

    private fun valueRow(
        parent: LinearLayout,
        first: Boolean,
        sw: SwitchView,
        name: String,
        value: TextView,
        onPick: (() -> Unit)?,
        onRandom: () -> Unit,
        onClear: () -> Unit
    ) {
        addRow(parent, first) {
            addView(rowHead(sw, name, null))
            val line = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val valWrap = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                if (onPick != null) {
                    isClickable = true
                    setOnClickListener { onPick() }
                }
            }
            valWrap.addView(value)
            if (onPick != null) {
                valWrap.addView(
                    TextView(this@MainActivity).apply {
                        text = "\u25BE"
                        setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
                        setTextColor(cText3)
                        setPadding(dp(4), 0, 0, 0)
                    }
                )
            }
            line.addView(
                valWrap,
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            )
            line.addView(micro("Random") { onRandom() })
            line.addView(micro("Clear") { onClear() })
            addView(
                line,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { leftMargin = dp(38); topMargin = dp(6) }
            )
        }
    }

    private fun abiModeLabel(idx: Int): String = when (idx) {
        0 -> "x86_64"
        1 -> "arm64+armeabi"
        else -> "arm64-v8a"
    }

    private fun updateAbiValue() {
        abiValue.text = abiModeLabel(abiModeSel)
    }

    private fun pickAbi() {
        val items = arrayOf(abiModeLabel(0), abiModeLabel(1), abiModeLabel(2))
        pick("CPU ABI", items, abiModeSel) { idx ->
            abiModeSel = idx
            updateAbiValue()
            if (idx != 0 && !abiSw.checked) abiSw.checked = true
            refreshRowVisuals()
            updateDirty()
        }
    }

    private fun cycleAbi() {
        abiModeSel = (abiModeSel + 1) % 3
        updateAbiValue()
        if (abiModeSel != 0 && !abiSw.checked) abiSw.checked = true
        refreshRowVisuals()
        updateDirty()
    }

    // ------------------------------------------------------------------
    // list pickers (SDK / CPU / GPU)
    // ------------------------------------------------------------------

    private fun pick(title: String, items: Array<String>, checkedIdx: Int, onPick: (Int) -> Unit) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setSingleChoiceItems(items, checkedIdx) { d, which ->
                d.dismiss()
                onPick(which)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun updateWebrtcChip() {
        webrtcChip.text = if (webrtcOn) "REAL" else "RKN"
        styleChip(webrtcChip, if (webrtcOn) cCyan else cGreen)
    }

    private fun pickSdk() {
        buildSdkOptions()
        pick("SDK", sdkLabels.toTypedArray(), sdkIndexFor(sdkValueSelected())) { idx ->
            sdkSel = idx
            updateSdkValue()
            if (sdkValueSelected() != currentSdk && !sdkSw.checked) sdkSw.checked = true
            refreshRowVisuals()
            updateDirty()
        }
    }

    private fun pickCpu() {
        pick(
            "CPU model",
            DeviceCatalog.CPUS.map { it.display }.toTypedArray(),
            cpuSel
        ) { idx ->
            cpuSel = idx
            updateCpuValue()
            updateDirty()
        }
    }

    private fun pickGpu() {
        pick(
            "GPU",
            DeviceCatalog.GPUS.map { "${it.vendor} ${it.renderer}" }.toTypedArray(),
            gpuSel
        ) { idx ->
            gpuSel = idx
            updateGpuValue()
            updateDirty()
        }
    }

    // ------------------------------------------------------------------
    // value editing dialogs (Widevine / GSF)
    // ------------------------------------------------------------------

    private fun editTextDialog(
        title: String,
        initial: String,
        digitsOnly: Boolean,
        onOk: (String) -> Unit
    ) {
        val et = EditText(this).apply {
            setText(initial)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            typeface = Typeface.MONOSPACE
            setTextColor(cText)
            setSingleLine(true)
            setPadding(dp(16), dp(8), dp(16), dp(8))
            inputType =
                if (digitsOnly) InputType.TYPE_CLASS_NUMBER
                else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        val dlg = AlertDialog.Builder(this)
        dlg.setTitle(title)
        dlg.setView(et)
        dlg.setPositiveButton(
            "OK",
            DialogInterface.OnClickListener { _, _ -> onOk(et.text.toString()) }
        )
        dlg.setNegativeButton("Cancel", null as DialogInterface.OnClickListener?)
        dlg.show()
    }

    private fun editWidevine() {
        editTextDialog("Widevine deviceUniqueId (hex, 64 chars)", wvEditVal, false) { v ->
            wvEditVal = v.trim().lowercase()
            updateWvValue()
            updateDirty()
        }
    }

    private fun editGsf() {
        editTextDialog("GSF ID (digits)", gsfEditVal, true) { v ->
            gsfEditVal = v.trim()
            updateGsfValue()
            updateDirty()
        }
    }

    // ------------------------------------------------------------------
    // text / value updates
    // ------------------------------------------------------------------

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
    }

    private fun versionName(): String = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: "?"
    } catch (t: Throwable) {
        "?"
    }

    private fun buildSdkOptions() {
        sdkValues.clear()
        sdkLabels.clear()
        var defaultAdded = false
        for (v in 32..37) {
            sdkValues.add(v)
            if (v == currentSdk) {
                sdkLabels.add("SDK $v (DEFAULT)")
                defaultAdded = true
            } else {
                sdkLabels.add("SDK $v (Android ${androidVersionFor(v)})")
            }
        }
        if (!defaultAdded) {
            // System SDK outside the catalog range - keep it selectable.
            sdkValues.add(currentSdk)
            sdkLabels.add("SDK $currentSdk (DEFAULT)")
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
        sdkValues.getOrElse(sdkSel) { currentSdk }

    private fun updateSdkValue() {
        val v = sdkValueSelected()
        sdkValue.text = "SDK $v \u00b7 Android ${androidVersionFor(v)}"
    }

    private fun updateCpuValue() {
        cpuValue.text = DeviceCatalog.CPUS.getOrElse(cpuSel) { DeviceCatalog.CPUS[0] }.display
    }

    private fun updateGpuValue() {
        val g = DeviceCatalog.GPUS.getOrElse(gpuSel) { DeviceCatalog.GPUS[0] }
        gpuValue.text = "${g.vendor} ${g.renderer}"
    }

    private fun updateWvValue() {
        wvValue.text = if (wvEditVal.isEmpty()) "not set"
        else "${wvEditVal.take(4)}\u2026${wvEditVal.takeLast(4)} \u00b7 ${wvEditVal.length / 2} bytes"
    }

    private fun updateGsfValue() {
        gsfValue.text = if (gsfEditVal.isEmpty()) "not set" else gsfEditVal
    }

    // ------------------------------------------------------------------
    // random / clear per feature
    // ------------------------------------------------------------------

    private fun randomSdk() {
        sdkSel = rng.nextInt(sdkValues.size)
        updateSdkValue()
        updateDirty()
    }

    private fun clearSdk() {
        sdkSel = sdkIndexFor(currentSdk)
        updateSdkValue()
        sdkSw.checked = false
        refreshRowVisuals()
        updateDirty()
    }

    private fun clearAbi() {
        abiModeSel = 0
        updateAbiValue()
        abiSw.checked = false
        refreshRowVisuals()
        updateDirty()
    }

    private fun randomCpu() {
        cpuSel = rng.nextInt(DeviceCatalog.CPUS.size)
        updateCpuValue()
        updateDirty()
    }

    private fun clearCpu() {
        cpuSel = 0
        updateCpuValue()
        cpuSw.checked = false
        refreshRowVisuals()
        updateDirty()
    }

    private fun randomGpu() {
        gpuSel = rng.nextInt(DeviceCatalog.GPUS.size)
        updateGpuValue()
        updateDirty()
    }

    private fun clearGpu() {
        gpuSel = 0
        updateGpuValue()
        gpuSw.checked = false
        refreshRowVisuals()
        updateDirty()
    }

    private fun randomWidevine(): String = buildString {
        repeat(64) { append("0123456789abcdef"[rng.nextInt(16)]) }
    }

    private fun clearWidevine() {
        wvEditVal = ""
        updateWvValue()
        wvSw.checked = false
        refreshRowVisuals()
        updateDirty()
    }

    private fun randomGsf(): String {
        val sb = StringBuilder()
        sb.append(('1'.code + rng.nextInt(9)).toChar())
        repeat(15) { sb.append(('0'.code + rng.nextInt(10)).toChar()) }
        return sb.toString()
    }

    private fun clearGsf() {
        gsfEditVal = ""
        updateGsfValue()
        gsfSw.checked = false
        refreshRowVisuals()
        updateDirty()
    }

    // ------------------------------------------------------------------
    // state: load / save / dirty / visuals
    // ------------------------------------------------------------------

    private fun loadSaved() {
        val sp = SpoofSettings.load(this)
        suppressDirty = true
        nativeSw.checked = sp.getBoolean("native_enabled", true)
        lightSw.checked = sp.getBoolean("recon_enabled", true)
        compatSw.checked = sp.getBoolean("safe_mode", false)
        sdkSw.checked = sp.getBoolean("sdk_enabled", false)
        sdkSel = sdkIndexFor(sp.getInt("sdk_value", currentSdk))
        updateSdkValue()
        abiSw.checked = sp.getBoolean("abi_enabled", false)
        abiModeSel = when (sp.getString("abi_value", "x86_64")) {
            "arm64+armeabi" -> 1
            "arm64-v8a", "mixed" -> 2
            else -> 0
        }
        updateAbiValue()
        cpuSw.checked = sp.getBoolean("cpu_enabled", false)
        cpuSel = cpuIndexFor(sp.getString("cpu_value", "") ?: "")
        updateCpuValue()
        gpuSw.checked = sp.getBoolean("gpu_enabled", false)
        gpuSel = gpuIndexFor(sp.getString("gpu_value", "") ?: "")
        updateGpuValue()
        wvSw.checked = sp.getBoolean("widevine_enabled", false)
        wvEditVal = sp.getString("widevine_id", "") ?: ""
        updateWvValue()
        gsfSw.checked = sp.getBoolean("gsf_enabled", false)
        gsfEditVal = sp.getString("gsf_id", "") ?: ""
        updateGsfValue()
        val modeStr = sp.getString("webrtc_mode", null)
        webrtcOn = when (modeStr) {
            "rkn" -> false
            "balanced", "relaxed" -> true
            else -> sp.getBoolean("webrtc_localip", true)
        }
        webrtcSw.checked = webrtcOn
        updateWebrtcChip()
        vulkanSw.checked = sp.getBoolean("gpu_vulkan", true)
        chainSw.checked = sp.getBoolean("gpu_chain", true)
        netCellularSel = sp.getBoolean("net_cellular", false)
        netSw.checked = netCellularSel
        updateNetValue()
        blEditVal = sp.getString("bootloader", "") ?: ""
        blSw.checked = blEditVal.isNotEmpty()
        updateBlValue()
        suppressDirty = false
        refreshRowVisuals()
    }

    private fun currentMap(): HashMap<String, Any?> = hashMapOf(
        "native_enabled" to nativeSw.checked,
        "safe_mode" to compatSw.checked,
        "sdk_enabled" to sdkSw.checked,
        "sdk_value" to sdkValueSelected(),
        "abi_enabled" to abiSw.checked,
        "abi_value" to when (abiModeSel) {
            1 -> "arm64+armeabi"
            2 -> "arm64-v8a"
            else -> "x86_64"
        },
        "cpu_enabled" to cpuSw.checked,
        "cpu_value" to DeviceCatalog.CPUS.getOrElse(cpuSel) { DeviceCatalog.CPUS[0] }.display,
        "gpu_enabled" to gpuSw.checked,
        "gpu_value" to DeviceCatalog.GPUS.getOrElse(gpuSel) { DeviceCatalog.GPUS[0] }.renderer,
        "widevine_enabled" to wvSw.checked,
        "widevine_id" to wvEditVal.trim().lowercase(),
        "gsf_enabled" to gsfSw.checked,
        "gsf_id" to gsfEditVal.trim(),
        "webrtc_mode" to if (webrtcOn) "balanced" else "rkn",
        "webrtc_localip" to webrtcOn,
        "net_cellular" to netCellularSel,
        "bootloader" to blEditVal.trim(),
        "recon_enabled" to lightSw.checked,
        "gpu_chain" to chainSw.checked,
        "gpu_vulkan" to vulkanSw.checked
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
            "webrtc_mode" to run {
                val m = sp.getString("webrtc_mode", null)
                when (m) {
                    null -> if (sp.getBoolean("webrtc_localip", true)) "balanced" else "rkn"
                    "relaxed" -> "balanced"
                    else -> m
                }
            },
            "webrtc_localip" to sp.getBoolean("webrtc_localip", true),
            "net_cellular" to sp.getBoolean("net_cellular", false),
            "bootloader" to (sp.getString("bootloader", "") ?: ""),
            "recon_enabled" to sp.getBoolean("recon_enabled", true),
            "gpu_chain" to sp.getBoolean("gpu_chain", true),
            "gpu_vulkan" to sp.getBoolean("gpu_vulkan", true)
        )
    }

    private fun updateDirty() {
        if (suppressDirty || !::bottomBar.isInitialized) return
        val dirty = currentMap() != savedMap()
        bottomBar.visibility = if (dirty) View.VISIBLE else View.GONE
        dirtyChip.visibility = if (dirty) View.VISIBLE else View.GONE
    }

    private fun refreshRowVisuals() {
        fun chip(tv: TextView, text: String, color: Int) {
            tv.text = text
            styleChip(tv, color)
        }
        chip(nativeChip, if (nativeSw.checked) "On" else "Off", if (nativeSw.checked) cCyan else cText2)
        chip(vulkanChip, if (vulkanSw.checked) "On" else "Off", if (vulkanSw.checked) cCyan else cText2)
        chip(chainChip, if (chainSw.checked) "On" else "Off", if (chainSw.checked) cCyan else cText2)
        updateWebrtcChip()
        sdkValue.setTextColor(if (sdkSw.checked) cAmber else cText3)
        cpuValue.setTextColor(if (cpuSw.checked) cAmber else cText3)
        gpuValue.setTextColor(if (gpuSw.checked) cAmber else cText3)
        wvValue.setTextColor(if (wvSw.checked) cAmber else cText3)
        gsfValue.setTextColor(if (gsfSw.checked) cAmber else cText3)
        netValue.setTextColor(if (netSw.checked) cAmber else cText3)
        blValue.setTextColor(if (blSw.checked) cAmber else cText3)
        abiValue.setTextColor(if (abiSw.checked) cAmber else cText3)
    }

    private fun attachListeners() {
        val toggle = { _: Boolean ->
            refreshRowVisuals()
            updateDirty()
        }
        nativeSw.onToggle = toggle
        compatSw.onToggle = toggle
        sdkSw.onToggle = { checked ->
            if (checked && sdkValueSelected() == currentSdk) {
                val iNext = sdkValues.indexOf(currentSdk + 1)
                if (iNext >= 0) {
                    sdkSel = iNext
                    updateSdkValue()
                }
            }
            refreshRowVisuals()
            updateDirty()
        }
        abiSw.onToggle = toggle
        cpuSw.onToggle = toggle
        gpuSw.onToggle = toggle
        wvSw.onToggle = toggle
        gsfSw.onToggle = toggle
        vulkanSw.onToggle = toggle
        lightSw.onToggle = toggle
        chainSw.onToggle = toggle
        webrtcSw.onToggle = { checked ->
            webrtcOn = checked
            refreshRowVisuals()
            updateDirty()
        }
        reconSw.onToggle = toggle
        netSw.onToggle = toggle
        blSw.onToggle = toggle
    }

    private fun saveSpoof() {
        // Auto-fill ids when a row is enabled with an empty field.
        if (wvSw.checked && wvEditVal.isBlank()) wvEditVal = randomWidevine()
        if (gsfSw.checked && gsfEditVal.isBlank()) gsfEditVal = randomGsf()

        val wv = wvEditVal.trim().lowercase()
        if (wvSw.checked && (wv.isEmpty() || wv.length % 2 != 0 || !wv.all { it in "0123456789abcdef" })) {
            toast("Widevine id must be hex, even length (64 chars = 32 bytes)")
            return
        }
        val gsf = gsfEditVal.trim()
        if (gsfSw.checked && (gsf.isEmpty() || gsf.length !in 8..19 || !gsf.all { it.isDigit() })) {
            toast("GSF id must be digits (8-19)")
            return
        }

        wvEditVal = wv
        gsfEditVal = gsf
        updateWvValue()
        updateGsfValue()

        val err = SpoofSettings.save(this, currentMap())
        SpoofSettings.ensureListener(this) // apply & reconnect
        toast(err ?: "Saved \u2713 - takes effect when the scoped app restarts")
        appliedChip.visibility = View.VISIBLE
        ui.removeCallbacks(hideApplied)
        ui.postDelayed(hideApplied, 2600)
        updateDirty()
        refreshSpoofStatus()
        refreshRowVisuals()
    }

    private fun revertToSaved() {
        loadSaved()
        updateDirty()
    }

    private fun refreshSpoofStatus() {
        val connected = SpoofSettings.isConnected()
        statusText.text =
            if (connected) {
                "Vector service connected \u2014 changes apply when the scoped app is restarted."
            } else {
                "Vector service: not connected. Enable this module in Vector, then reopen this app."
            }
        svcChip.text = if (connected) "Nominal" else "Offline"
        styleChip(svcChip, if (connected) cCyan else cRed)
    }

    // ------------------------------------------------------------------
    // scope management
    // ------------------------------------------------------------------

    private fun refreshScopeChip() {
        Thread {
            val n = SpoofSettings.scopePackages()?.size
            runOnUiThread {
                if (!::scopeChip.isInitialized) return@runOnUiThread
                scopeChip.text = if (n == null) "\u2014" else "$n apps"
                styleChip(scopeChip, if ((n ?: 0) > 0) cCyan else cText2)
            }
        }.start()
    }

    private fun openScopeDialog() {
        val scope = SpoofSettings.scopePackages()
        if (scope == null) {
            toast("Vector service not connected - reopen the app and retry.")
            return
        }
        refreshScopeChip()
        val builder = AlertDialog.Builder(this)
            .setTitle("Module scope (${scope.size})")
            .setPositiveButton("Add apps\u2026") { _, _ -> openAddAppsDialog() }
            .setNegativeButton("Close", null)
        if (scope.isNotEmpty()) {
            builder.setSingleChoiceItems(scope.toTypedArray(), -1) { d, which ->
                d.dismiss()
                confirmRemove(scope[which])
            }
        } else {
            builder.setMessage("Scope is empty. Use Add apps\u2026 to pick target apps.")
        }
        builder.show()
    }

    private fun confirmRemove(pkg: String) {
        AlertDialog.Builder(this)
            .setTitle("Remove from scope?")
            .setMessage(pkg)
            .setPositiveButton("Remove") { _, _ ->
                Thread {
                    val ok = SpoofSettings.removeScope(listOf(pkg))
                    runOnUiThread {
                        toast(if (ok) "Removed from scope: $pkg" else "Remove failed")
                        refreshScopeChip()
                    }
                }.start()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private data class AppEntry(val label: String, val pkg: String, val system: Boolean)

    private fun openAddAppsDialog() {
        if (!SpoofSettings.isConnected()) {
            toast("Vector service not connected - reopen the app and retry.")
            return
        }
        toast("Loading apps\u2026")
        Thread {
            val pm = packageManager
            val scope = SpoofSettings.scopePackages() ?: emptyList()
            val list = ArrayList<AppEntry>()
            val seen = HashSet<String>()
            try {
                for (ai in pm.getInstalledApplications(0)) {
                    val p = ai.packageName
                    if (p == packageName || p in scope || !seen.add(p)) continue
                    val label = try {
                        ai.loadLabel(pm).toString()
                    } catch (t: Throwable) {
                        p
                    }
                    val system = (ai.flags and
                        (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
                    list.add(AppEntry(label, p, system))
                }
            } catch (t: Throwable) {
                // keep whatever we managed to collect
            }
            list.sortWith(compareBy({ it.system }, { it.label.lowercase() }))
            runOnUiThread {
                if (isFinishing) return@runOnUiThread
                showAddAppsDialog(list)
            }
        }.start()
    }

    private fun showAddAppsDialog(all: List<AppEntry>) {
        if (all.isEmpty()) {
            toast("No addable apps found")
            return
        }
        val checked = HashSet<String>()
        val filtered = ArrayList<AppEntry>()
        val search = EditText(this).apply {
            hint = "Search label or package\u2026"
            setSingleLine(true)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setTextColor(cText)
            setHintTextColor(cText3)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setPadding(dp(14), dp(10), dp(14), dp(10))
        }
        val listView = ListView(this)
        val adapter = object : BaseAdapter() {
            override fun getCount(): Int = filtered.size
            override fun getItem(position: Int): Any = filtered[position]
            override fun getItemId(position: Int): Long = position.toLong()
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val e = filtered[position]
                val row = LinearLayout(this@MainActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(dp(14), dp(6), dp(14), dp(6))
                }
                val cb = CheckBox(this@MainActivity).apply {
                    isChecked = checked.contains(e.pkg)
                    setOnCheckedChangeListener { _, v ->
                        if (v) checked.add(e.pkg) else checked.remove(e.pkg)
                    }
                }
                val col = LinearLayout(this@MainActivity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(8), 0, 0, 0)
                }
                col.addView(
                    TextView(this@MainActivity).apply {
                        text = e.label
                        setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
                        setTextColor(cText)
                    }
                )
                col.addView(
                    TextView(this@MainActivity).apply {
                        text = e.pkg + if (e.system) "  \u00b7  system" else ""
                        setTextSize(TypedValue.COMPLEX_UNIT_SP, 10.5f)
                        typeface = Typeface.MONOSPACE
                        setTextColor(cText3)
                    }
                )
                row.addView(cb)
                row.addView(
                    col,
                    LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                )
                row.setOnClickListener { cb.isChecked = !cb.isChecked }
                return row
            }
        }
        listView.adapter = adapter
        fun refilter(q: String) {
            filtered.clear()
            val qq = q.trim().lowercase()
            if (qq.isEmpty()) {
                filtered.addAll(all)
            } else {
                for (e in all) {
                    if (e.label.lowercase().contains(qq) || e.pkg.contains(qq)) filtered.add(e)
                }
            }
            adapter.notifyDataSetChanged()
        }
        refilter("")
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                refilter(s?.toString() ?: "")
            }
        })
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        box.addView(
            search,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        )
        box.addView(
            listView,
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(400))
        )
        AlertDialog.Builder(this)
            .setTitle("Add apps to scope (${all.size})")
            .setView(box)
            .setPositiveButton("Request add") { _, _ ->
                val sel = checked.toList()
                if (sel.isEmpty()) {
                    toast("Nothing selected")
                    return@setPositiveButton
                }
                SpoofSettings.requestScope(sel) { ok, detail ->
                    runOnUiThread {
                        toast(
                            if (ok) "Scope updated: $detail"
                            else "Scope request failed: $detail"
                        )
                        refreshScopeChip()
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun openWebglTest() {
        val url = "https://browserleaks.com/webgl"
        AlertDialog.Builder(this)
            .setTitle("WebGL test page")
            .setItems(
                arrayOf(
                    "Open in WebView test app",
                    "Preview with system WebView (here)",
                    "Open with\u2026 (chooser)"
                )
            ) { _, which ->
                when (which) {
                    0 -> openInWebViewApp(url)
                    1 -> previewInWebView(url)
                    else -> chooserOpen(url)
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun chooserOpen(url: String) {
        try {
            startActivity(
                Intent.createChooser(Intent(Intent.ACTION_VIEW, Uri.parse(url)), "Open WebGL test")
            )
        } catch (t: Throwable) {
            toast("No app available to open the link")
        }
    }

    private fun openInWebViewApp(url: String) {
        val test = "com.snc.test.webview2"
        val direct = Intent(Intent.ACTION_VIEW, Uri.parse(url)).setPackage(test)
        if (packageManager.queryIntentActivities(direct, 0).isNotEmpty()) {
            try {
                startActivity(direct)
                return
            } catch (t: Throwable) {
                // fall through
            }
        }
        val launch = packageManager.getLaunchIntentForPackage(test)
        if (launch != null) {
            launch.action = Intent.ACTION_VIEW
            launch.data = Uri.parse(url)
            launch.putExtra("url", url)
            launch.putExtra("URL", url)
            try {
                startActivity(launch)
                toast("If it didn't load, paste: $url")
                return
            } catch (t: Throwable) {
                // fall through
            }
        }
        toast("WebView test app not found")
    }

    private fun previewInWebView(url: String) {
        val web = android.webkit.WebView(this)
        web.settings.javaScriptEnabled = true
        web.loadUrl(url)
        val box = FrameLayout(this).apply { setPadding(dp(8), dp(8), dp(8), 0) }
        box.addView(
            web,
            FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                dp(420)
            )
        )
        AlertDialog.Builder(this)
            .setView(box)
            .setPositiveButton("Close", null)
            .show()
    }

    // ------------------------------------------------------------------
    // force-close scoped apps
    // ------------------------------------------------------------------

    private fun forceCloseScoped() {
        if (forceBusy) return
        val scope = SpoofSettings.scopePackages()
        if (scope == null) {
            toast("Scope unavailable - Vector service not connected. Reopen the app and retry.")
            return
        }
        val targets = scope.filter { it.isNotBlank() && it != packageName }
        if (targets.isEmpty()) {
            toast("Scope is empty - add target apps in Vector first.")
            return
        }
        forceBusy = true
        toast("Force-closing ${targets.size} scoped app(s)\u2026")
        Thread {
            val cmd = targets.joinToString("; ") { "am force-stop '$it'" }
            val out = runSu(cmd)
            val ok = out != null && !out.contains("su exit code")
            runOnUiThread {
                forceBusy = false
                toast(
                    if (ok) "Force-closed ${targets.size} scoped app(s)"
                    else "Force-close failed - root denied or su error."
                )
            }
        }.start()
    }

    // ------------------------------------------------------------------
    // log viewer
    // ------------------------------------------------------------------

    private fun toggleLogs() {
        val show = logsContainer.visibility != View.VISIBLE
        logsContainer.visibility = if (show) View.VISIBLE else View.GONE
        logsChev.text = if (show) "\u25BE" else "\u25B8"
        if (show) loadLogs()
    }

    private fun loadLogs() {
        if (busy) return
        busy = true
        logsStatus.text = "Loading logs\u2026"
        Thread {
            val out = StringBuilder()
            var rootWorks = false
            try {
                val lspd = runSu(
                    "for D in /data/adb/lspd/log /data/adb/vector/log; do " +
                        "cat \$D/modules_*.log \$D/verbose_*.log 2>/dev/null; done " +
                        "| grep -a PerAppSpoofer | grep -av 'native: recon: ' | tail -n 500"
                )
                if (lspd != null) rootWorks = true
                if (!lspd.isNullOrBlank()) {
                    out.append("=== LSPosed/Vector log (core) ===\n").append(lspd).append("\n\n")
                }
                val focus = runSu(
                    "logcat -d -t 20000 | grep -a PerAppSpoofer | " +
                        "grep -aE 'MediaDrm|LinkProperties|getByName|webrtc|spoof applied|hook failed|avail|gl loader-chain' | tail -n 250"
                )
                if (focus != null) rootWorks = true
                if (!focus.isNullOrBlank()) {
                    out.append("=== focus (media / interfaces) ===\n").append(focus).append("\n\n")
                }
                val core = runSu(
                    "logcat -d -t 20000 | grep -a PerAppSpoofer | grep -av 'native: recon: ' | " +
                        "grep -av 'recon(java)' | tail -n 400"
                )
                if (core != null) rootWorks = true
                if (!core.isNullOrBlank()) {
                    out.append("=== logcat (core) ===\n").append(core).append("\n\n")
                }
                val recon = runSu(
                    "logcat -d -t 20000 | grep -a PerAppSpoofer | " +
                        "grep -aE 'native: recon: |recon\\(java\\)' | tail -n 200"
                )
                if (recon != null) rootWorks = true
                if (!recon.isNullOrBlank()) {
                    out.append("=== recon tail ===\n").append(recon)
                }
            } catch (t: Throwable) {
                out.append("error: ").append(t.toString())
            }
            val text = out.toString()
            runOnUiThread {
                busy = false
                logsStatus.text = when {
                    rootWorks && text.isNotBlank() -> "Loaded (root OK). Latest entries below."
                    rootWorks -> "Root OK, but no [PerAppSpoofer] entries found yet. Use Reload after opening a scoped app."
                    else -> "Root unavailable or denied. Grant root to this app in KernelSU, then Reload.\n" + text
                }
                renderLogs(text)
            }
        }.start()
    }

    /** One-tap diagnosis of a stalling app: thread wait-states, ANR dir,
     *  crash buffer and the game's own logcat tail, captured in one go. */
    private fun runDiagnose() {
        if (busy) return
        busy = true
        logsStatus.text = "Diagnosing\u2026"
        logsContainer.visibility = View.VISIBLE
        logsChev.text = "\u25BE"
        Thread {
            val sb = StringBuilder()
            try {
                val pkg = "com.newmoonproduction.bigfarmhomestead"
                val psLine = runSu("ps -A -o PID,NAME 2>/dev/null | grep -a $pkg; ps -A 2>/dev/null | grep -a $pkg")
                sb.append("=== process ===\n").append(psLine ?: "(not found)")
                val zy = runSu("ps -A -o PID,NAME 2>/dev/null | grep -a zygote")
                sb.append("\n\n=== zygotes (should be clean of libpas) ===\n").append(zy ?: "(none)")
                var pid = ""
                if (!psLine.isNullOrBlank()) {
                    for (tok in psLine.trim().split(Regex("\\s+"))) {
                        if (tok.length >= 3 && tok.all { it.isDigit() }) {
                            pid = tok
                            break
                        }
                    }
                }
                if (pid.isNotEmpty()) {
                    val wait = runSu(
                        "for t in /proc/$pid/task/*; do " +
                            "n=\$(cat \$t/comm 2>/dev/null); w=\$(cat \$t/wchan 2>/dev/null); " +
                            "s=\$(cat \$t/stat 2>/dev/null | awk '{print \$3}'); " +
                            "echo \"\${n:-?} state=\${s:-?} wait=\${w:-?}\"; done | sort | head -n 90"
                    )
                    sb.append("\n\n=== threads (state/wait) ===\n").append(wait ?: "(failed)")
                    val anr = runSu("ls -lt /data/anr/ 2>/dev/null | head -6")
                    sb.append("\n\n=== /data/anr ===\n").append(anr ?: "(none)")
                } else {
                    sb.append("\n(process not running - start the game, wait for the stall, then tap again)")
                }
                val crash = runSu("logcat -d -b crash -t 200 2>/dev/null")
                sb.append("\n\n=== crash buffer ===\n").append(crash?.take(6000) ?: "(empty)")
                val game = runSu(
                    "logcat -d -t 600 2>/dev/null | grep -a -e bigfarm -e newmoon -e chromium -e FATAL -e ANR -e tombstone -e sandboxed | tail -n 160"
                )
                sb.append("\n\n=== game + fatal tail ===\n").append(game?.take(9000) ?: "(none)")
                val events = runSu("logcat -d -b events -t 120 2>/dev/null")
                sb.append("\n\n=== events buffer (am_proc / wm) ===\n").append(events?.take(5000) ?: "(empty)")
                val anrNew = runSu("ls -t /data/anr/ 2>/dev/null | head -2")
                if (!anrNew.isNullOrBlank()) {
                    val f = anrNew.trim().lineSequence().firstOrNull { it.isNotBlank() }
                    if (f != null) {
                        val head = runSu("head -n 80 '/data/anr/$f' 2>/dev/null")
                        sb.append("\n\n=== newest ANR ($f) head ===\n").append(head ?: "(unreadable)")
                    }
                }
                val tbNew = runSu("ls -t /data/tombstones/ 2>/dev/null | head -2")
                if (!tbNew.isNullOrBlank()) {
                    val f = tbNew.trim().lineSequence().firstOrNull { it.isNotBlank() }
                    if (f != null) {
                        val head = runSu("head -n 60 '/data/tombstones/$f' 2>/dev/null")
                        sb.append("\n\n=== newest tombstone ($f) head ===\n").append(head ?: "(unreadable)")
                    }
                }
                val dls = runSu(
                    "logcat -d -t 3000 2>/dev/null | grep -a 'native: recon: dlopen' | tail -n 80"
                )
                sb.append("\n\n=== dlopen trace (last loads) ===\n").append(dls ?: "(recon off or no entries)")
            } catch (t: Throwable) {
                sb.append("\nerror: ").append(t.toString())
            }
            val text = sb.toString()
            runOnUiThread {
                busy = false
                logsStatus.text = "Diagnose snapshot ready."
                renderLogs(text)
            }
        }.start()
    }

    private fun netLabel(): String = if (netCellularSel) "MOBILE (LTE)" else "WIFI"

    private fun updateNetValue() {
        netValue.text = netLabel()
    }

    private fun pickNet() {
        val items = arrayOf("WIFI (default)", "MOBILE (LTE)")
        pick("Net type", items, if (netCellularSel) 1 else 0) { idx ->
            netCellularSel = idx == 1
            netSw.checked = netCellularSel
            updateNetValue()
            refreshRowVisuals()
            updateDirty()
        }
    }

    private fun cycleNet() {
        netCellularSel = !netCellularSel
        netSw.checked = netCellularSel
        updateNetValue()
        refreshRowVisuals()
        updateDirty()
    }

    private fun clearNet() {
        netCellularSel = false
        netSw.checked = false
        updateNetValue()
        refreshRowVisuals()
        updateDirty()
    }

    private fun updateBlValue() {
        blValue.text = if (blEditVal.isEmpty()) "not set" else blEditVal
    }

    private fun editBl() {
        editTextDialog("Bootloader version (e.g. A135FXXSEEZB2)", blEditVal, false) { v ->
            blEditVal = v.trim()
            updateBlValue()
            updateDirty()
        }
    }

    private fun randomBl(): String {
        val suffixes = arrayOf("A", "B", "C", "D")
        return "A135FXXS" + suffixes[rng.nextInt(suffixes.size)] + "EZB" + (2 + rng.nextInt(8))
    }

    private fun clearBl() {
        blEditVal = ""
        updateBlValue()
        blSw.checked = false
        refreshRowVisuals()
        updateDirty()
    }

    private fun renderLogs(raw: String) {
        lastLogText = raw
        val lines = raw.split("\n")
        val nums = StringBuilder()
        for (i in lines.indices) {
            nums.append(i + 1).append('\n')
        }
        logGutter.text = nums.toString()
        logView.text = raw
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
        cm.setPrimaryClip(ClipData.newPlainText("PerAppSpoofer logs", lastLogText.ifEmpty { logView.text }))
        toast("Copied")
    }
}
