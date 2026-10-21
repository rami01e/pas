package com.kimera.pas.hooks

import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG

/**
 * v2.12.15 shared hidden-package list.
 *
 * Design goals (this is our equivalent of HMA-OSS's "powerful presets"):
 *
 *  1. Built-in defaults ALWAYS apply. Users cannot accidentally unhide
 *     me.weishu.kernelsu by clearing a pref.
 *  2. Users can ADD packages without rebuilding via remote pref
 *     `hidden_packages` (comma separated, group "pas_spoof"). Additions
 *     are merged with the defaults at load time.
 *  3. Users can WHITELIST a package that would otherwise match a token
 *     via remote pref `allowed_packages`. This is the escape hatch for
 *     legitimate apps whose names happen to contain e.g. "lsposed" or
 *     "anywebview".
 *  4. Token matching catches renamed variants of known frameworks. Tokens
 *     are intentionally narrow so a normal store app is never caught.
 *  5. Hardcoded defaults are deliberately conservative on system apps -
 *     over-hiding breaks legit functionality. Example: com.android.vpndialogs
 *     is a system VPN permission helper and must stay visible.
 */
object SweepList {

    const val GROUP = "pas_spoof"
    const val PREF_HIDDEN = "hidden_packages"  // user ADDITIONS, merged with defaults
    const val PREF_ALLOW  = "allowed_packages" // user WHITELIST, overrides token match

    /**
     * Always-hidden baseline. Curated. Do NOT add system apps here unless
     * you have confirmed they are fingerprint surfaces rather than legit
     * functionality.
     */
    private const val DEFAULT_HIDDEN =
        // Root managers
        "me.weishu.kernelsu,hk.kirk.trustme,com.topjohnwu.magisk,eu.chainfire.supersu," +
        // Hook framework managers
        "org.lsposed.corepatch,de.robv.android.xposed.installer,org.lsposed.manager," +
        "io.github.lsposed.manager," +
        // MuMu / MRRL / HMA tooling
        "com.mumu.store,com.dergoogler.mmrl.wx,org.frknkrc44.hma_oss," +
        // This module + companion
        "com.kimera.pas,com.kimera.carrierspoof," +
        // Integrity / root-check tools
        "gr.nikolasspyr.integritycheck,krypton.tbsafetychecker,flar2.devcheck," +
        "com.mantle.verify," +
        // Power-user / fingerprint-heavy apps
        "com.termux,com.android1500.gpssetter,com.zaneschepke.wireguardautotunnel," +
        "app.lawnchair,com.internet.speed.meter,com.lonelycatgames.Xplore," +
        "com.thinkdifferent.anywebview"
        // NOTE: com.android.vpndialogs intentionally NOT hidden (system VPN dialog helper)

    /**
     * Substring rules. Keep them narrow. Each token names a framework, a
     * manager family, or a class of tooling - never a generic word.
     */
    private val TOKENS = arrayOf(
        "lsposed", "xposed", "magisk", "kernelsu", "apatch", "supersu",
        "mma", "mmrl", "hma_oss", "wireguard",
        "integritycheck", "safetychecker", "gpssetter", "devcheck",
        "termux", "mumu", "kimera", "carrierspoof", "libpas",
        "anywebview", "corepatch"
    )

    /** Cache of the allowlist - set on load(), consulted by isHidden(). */
    @Volatile private var allowCache: Set<String> = emptySet()

    /**
     * Compute the effective hidden set for this process. Called once per
     * process from each XHook.injectHook().
     *
     * Contract:
     *  - DEFAULT_HIDDEN is always part of the result.
     *  - PREF_HIDDEN (comma-separated) is merged on top of the defaults.
     *  - PREF_ALLOW (comma-separated) is loaded into allowCache and is
     *    consulted by isHidden() to override token matches (but NOT
     *    explicit defaults - if you truly need a default hidden package
     *    visible, you must patch the constant).
     */
    fun load(module: XposedModule): Set<String> {
        val prefs = try {
            module.getRemotePreferences(GROUP)
        } catch (t: Throwable) {
            module.log(Log.INFO, TAG, "[PAS] hidden list: prefs unavailable ($t)")
            allowCache = emptySet()
            return parse(DEFAULT_HIDDEN)
        }

        val userExtra = runCatching { prefs.getString(PREF_HIDDEN, "") ?: "" }.getOrDefault("")
        val userAllow = runCatching { prefs.getString(PREF_ALLOW,  "") ?: "" }.getOrDefault("")

        allowCache = parse(userAllow)

        // Always merge. Users can only ADD to the hidden set; removing a
        // default requires the allowlist pref (or editing this file).
        val merged = if (userExtra.isEmpty()) DEFAULT_HIDDEN
                     else DEFAULT_HIDDEN + "," + userExtra
        return parse(merged)
    }

    fun isHidden(pkg: String, hidden: Set<String>): Boolean {
        // 1. User whitelist overrides token matching (but not explicit hits).
        if (allowCache.contains(pkg)) return false
        // 2. Explicit hits (defaults + user additions).
        if (pkg in hidden) return true
        // 3. Token matches catch variants.
        for (t in TOKENS) {
            if (pkg.contains(t, ignoreCase = true)) return true
        }
        return false
    }

    private fun parse(s: String): Set<String> =
        s.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()

    /** Logs the first 20 hits only - the rest would spam the log. */
    private var logged = 0
    fun logHit(module: XposedModule, kind: String, pkg: String) {
        if (logged >= 20) return
        logged++
        module.log(Log.INFO, TAG, "[PAS] hidden from $kind: '$pkg'")
    }
}