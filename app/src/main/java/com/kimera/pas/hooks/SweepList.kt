package com.kimera.pas.hooks

import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG

/**
 * Shared hidden-package list for the anti-emu layer.
 *
 * vNEXT: introduced after the com.playnearn capture (2026-10-20) showed the
 * app reporting usage stats - not just PackageManager - and leaking
 * me.weishu.kernelsu, org.frknkrc44.hma_oss, com.kimera.pas, com.termux,
 * flar2.devcheck, gr.nikolasspyr.integritycheck, krypton.tbsafetychecker,
 * com.android1500.gpssetter, com.mumu.store, com.zaneschepke.wireguardautotunnel
 * and com.android.vpndialogs to its backend. Those entries produced both the
 * "rooted device" and the "VPN" verdicts.
 *
 * Two consumers:
 *   - HookSweep      -> PackageManager lists / lookups
 *   - HookUsageStats -> UsageStatsManager.queryUsageStats /
 *                       queryAndAggregateUsageStats / queryEvents
 *
 * Matching is exact-name first, then token based, because managers get
 * repackaged under new names (this device ships org.lsposed.corepatch).
 */
object SweepList {

    const val GROUP = "pas_spoof"
    const val PREF_HIDDEN = "hidden_packages"

    /** Names that must stay invisible to the scoped app. */
    private const val DEFAULT_HIDDEN =
        "me.weishu.kernelsu,hk.kirk.trustme,com.kimera.pas,com.kimera.carrierspoof," +
            "org.lsposed.corepatch,de.robv.android.xposed.installer,org.lsposed.manager," +
            "io.github.lsposed.manager,com.topjohnwu.magisk,eu.chainfire.supersu," +
            "com.mumu.store,com.dergoogler.mmrl.wx,org.frknkrc44.hma_oss," +
            "com.android.vpndialogs,com.termux,flar2.devcheck," +
            "gr.nikolasspyr.integritycheck,krypton.tbsafetychecker," +
            "com.android1500.gpssetter,com.mantle.verify," +
            "com.zaneschepke.wireguardautotunnel"

    /**
     * Substring rules. Kept narrow on purpose: each token names a hook
     * framework, a root manager or a device-integrity tool, so a legitimate
     * store app is never caught by accident.
     */
    private val TOKENS = arrayOf(
        "lsposed", "xposed", "magisk", "kernelsu", "apatch",
        "mma", "mmrl", "hma_oss", "wireguard", "vpndialogs",
        "integritycheck", "safetychecker", "gpssetter", "devcheck",
        "termux", "mumu", "kimera", "carrierspoof", "libpas"
    )

    fun load(module: XposedModule): Set<String> {
        val raw = try {
            module.getRemotePreferences(GROUP)
                .getString(PREF_HIDDEN, DEFAULT_HIDDEN) ?: DEFAULT_HIDDEN
        } catch (t: Throwable) {
            module.log(Log.INFO, TAG, "[PAS] hidden list: prefs unavailable ($t)")
            DEFAULT_HIDDEN
        }
        return raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()
    }

    fun isHidden(pkg: String, hidden: Set<String>): Boolean {
        if (pkg in hidden) return true
        for (t in TOKENS) {
            if (pkg.contains(t, ignoreCase = true)) return true
        }
        return false
    }

    /** Runs [block] for every hidden package hit; logs only the first few. */
    private var logged = 0
    fun logHit(module: XposedModule, kind: String, pkg: String) {
        if (logged >= 20) return
        logged++
        module.log(Log.INFO, TAG, "[PAS] hidden from $kind: '$pkg'")
    }
}
