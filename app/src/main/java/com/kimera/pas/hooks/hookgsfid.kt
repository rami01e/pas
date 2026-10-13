package com.kimera.pas.hooks

import android.content.ContentResolver
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import android.os.CancellationSignal
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState

/**
 * GSF ID (Google Services Framework android_id) spoof.
 *
 * Covered read paths (all in the scoped app's process):
 *  1. query(content://com.google.android.gsf.gservices, ..., args=["android_id"])
 *     - 4-arg, Bundle/cancellation (5-arg) and CancellationSignal (6-arg) overloads.
 *  2. Path-style URI: content://com.google.android.gsf.gservices/android_id
 *     (key in the URI path, no selection args) - used by fingerprint libraries.
 *  3. ContentResolver.call() on the gservices authority ("getValue"-style),
 *     both the Uri and the authority-string overloads - the returned Bundle's
 *     android_id entry is rewritten, everything else is passed through.
 *
 * Not reachable from an in-process hook: reads performed by GMS inside its own
 * process (com.google.android.gms is not in module scope).
 */
class HookGsfId : XHook {

    override val targetKlass: String
        get() = "android.content.ContentResolver"

    // v2.6.3 diag: one-shot counter for gsf-authority queries that do NOT
    // match any spoofed shape - the next capture names the uncovered path.
    private var unmatchedLogged = 0

    private fun logUnmatchedGsf(module: XposedModule, shape: String) {
        if (unmatchedLogged >= 3) return
        unmatchedLogged++
        module.log(Log.INFO, TAG, "[PAS] GSF diag: gsf query NOT spoofed: $shape")
    }

    override fun injectHook(module: XposedModule) {
        hookQuery(module)
        hookQueryBundle(module)
        hookQueryCancellation(module)
        hookCallUri(module)
        hookCallAuthority(module)
    }

    // ------------------------------------------------------------------
    // matching helpers
    // ------------------------------------------------------------------

    private fun gsfOn(): Boolean = SpoofState.gsfOn && SpoofState.gsfId.isNotEmpty()

    private fun isGsfAuthority(uri: Uri?): Boolean =
        gsfOn() && uri != null && uri.authority == "com.google.android.gsf.gservices"

    private fun isGsfAuthorityName(authority: String?): Boolean =
        gsfOn() && authority == "com.google.android.gsf.gservices"

    /** Does this query reference the android_id key (selection, args, path or extras)? */
    private fun refsAndroidId(uri: Uri?, selection: String?, args: Array<*>?): Boolean {
        if (uri != null && uri.lastPathSegment == "android_id") return true
        if (selection != null && selection.contains("android_id")) return true
        if (args != null && args.any { it == "android_id" }) return true
        return false
    }

    private fun refsAndroidIdInBundle(bundle: Bundle?): Boolean {
        if (bundle == null) return false
        if (bundle.containsKey("android_id")) return true
        val selection = bundle.getString(ContentResolver.QUERY_ARG_SQL_SELECTION)
        if (selection != null && selection.contains("android_id")) return true
        val args = bundle.getStringArray(ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS)
        if (args != null && args.any { it == "android_id" }) return true
        return false
    }

    private fun callRefsAndroidId(method: String?, arg: String?, extras: Bundle?): Boolean {
        if (method != null && method.contains("android_id")) return true
        if (arg == "android_id") return true
        if (extras != null && extras.containsKey("android_id")) return true
        return false
    }

    // ------------------------------------------------------------------
    // query hooks
    // ------------------------------------------------------------------

    private fun hookQuery(module: XposedModule) {
        hookSafe(module, "ContentResolver.query(gsf)") {
            val method = ContentResolver::class.java.getMethod(
                "query",
                Uri::class.java,
                Array<String>::class.java,
                String::class.java,
                Array<String>::class.java,
                String::class.java
            )
            module.hook(method).intercept { chain ->
                val uri = chain.getArg(0) as? Uri
                val selection = chain.getArg(2) as? String
                val args = chain.getArg(3) as? Array<*>
                val matched = isGsfAuthority(uri) && refsAndroidId(uri, selection, args)
                val cursor = if (matched) gsfCursor() else null
                if (cursor != null) {
                    module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed")
                    cursor
                } else {
                    if (isGsfAuthority(uri)) {
                        logUnmatchedGsf(module, "query uri=$uri sel=$selection args=${args?.joinToString()}")
                    }
                    chain.proceed()
                }
            }
        }
    }

    private fun hookQueryBundle(module: XposedModule) {
        hookSafe(module, "ContentResolver.query(gsf,bundle)") {
            val method = ContentResolver::class.java.getMethod(
                "query",
                Uri::class.java,
                Array<String>::class.java,
                Bundle::class.java,
                CancellationSignal::class.java
            )
            module.hook(method).intercept { chain ->
                val uri = chain.getArg(0) as? Uri
                val bundle = chain.getArg(2) as? Bundle
                val matched = isGsfAuthority(uri) &&
                    (refsAndroidIdInBundle(bundle) || refsAndroidId(uri, null, null))
                val cursor = if (matched) gsfCursor() else null
                if (cursor != null) {
                    module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (bundle)")
                    cursor
                } else {
                    if (isGsfAuthority(uri)) {
                        logUnmatchedGsf(module, "query-bundle uri=$uri keys=${bundle?.keySet()?.joinToString()}")
                    }
                    chain.proceed()
                }
            }
        }
    }

    /** Extra coverage: query(Uri, String[], String, String[], String, CancellationSignal). */
    private fun hookQueryCancellation(module: XposedModule) {
        hookSafe(module, "ContentResolver.query(gsf,cancellation)") {
            val method = ContentResolver::class.java.getMethod(
                "query",
                Uri::class.java,
                Array<String>::class.java,
                String::class.java,
                Array<String>::class.java,
                String::class.java,
                CancellationSignal::class.java
            )
            module.hook(method).intercept { chain ->
                val uri = chain.getArg(0) as? Uri
                val selection = chain.getArg(2) as? String
                val args = chain.getArg(3) as? Array<*>
                val matched = isGsfAuthority(uri) && refsAndroidId(uri, selection, args)
                val cursor = if (matched) gsfCursor() else null
                if (cursor != null) {
                    module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (cancellation)")
                    cursor
                } else {
                    if (isGsfAuthority(uri)) {
                        logUnmatchedGsf(module, "query-cancel uri=$uri sel=$selection args=${args?.joinToString()}")
                    }
                    chain.proceed()
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // call hooks ("getValue"-style reads)
    // ------------------------------------------------------------------

    private fun spoofedCallResult(result: Bundle?, explicit: Boolean): Bundle {
        val out = Bundle(result ?: Bundle())
        val spoof = SpoofState.gsfId.toLongOrNull()
        if (spoof == null) return result ?: out
        if (out.containsKey("android_id")) {
            // Preserve the value type the reader expects.
            when {
                out.get("android_id") is String ->
                    out.putString("android_id", SpoofState.gsfId)
                else -> out.putLong("android_id", spoof)
            }
        } else if (explicit) {
            out.putLong("android_id", spoof)
        }
        return out
    }

    private fun hookCallUri(module: XposedModule) {
        hookSafe(module, "ContentResolver.call(gsf,uri)") {
            val method = ContentResolver::class.java.getMethod(
                "call",
                Uri::class.java,
                String::class.java,
                String::class.java,
                Bundle::class.java
            )
            module.hook(method).intercept { chain ->
                val uri = chain.getArg(0) as? Uri
                val callMethod = chain.getArg(1) as? String
                val arg = chain.getArg(2) as? String
                val extras = chain.getArg(3) as? Bundle
                val matched = isGsfAuthority(uri) &&
                    callRefsAndroidId(callMethod, arg, extras)
                val result = chain.proceed() as? Bundle
                if (matched) {
                    val spoofed = spoofedCallResult(result, explicit = true)
                    module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (call)")
                    spoofed
                } else {
                    if (isGsfAuthority(uri)) {
                        logUnmatchedGsf(module, "call uri=$uri method=$callMethod arg=$arg")
                    }
                    result
                }
            }
        }
    }

    private fun hookCallAuthority(module: XposedModule) {
        hookSafe(module, "ContentResolver.call(gsf,authority)") {
            val method = ContentResolver::class.java.getMethod(
                "call",
                String::class.java,
                String::class.java,
                String::class.java,
                Bundle::class.java
            )
            module.hook(method).intercept { chain ->
                val authority = chain.getArg(0) as? String
                val callMethod = chain.getArg(1) as? String
                val arg = chain.getArg(2) as? String
                val extras = chain.getArg(3) as? Bundle
                val matched = isGsfAuthorityName(authority) &&
                    callRefsAndroidId(callMethod, arg, extras)
                val result = chain.proceed() as? Bundle
                if (matched) {
                    val spoofed = spoofedCallResult(result, explicit = true)
                    module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (call)")
                    spoofed
                } else {
                    if (isGsfAuthorityName(authority)) {
                        logUnmatchedGsf(module, "call-auth method=$callMethod arg=$arg")
                    }
                    result
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // spoofed cursor
    // ------------------------------------------------------------------

    private fun gsfCursor(): MatrixCursor? {
        val value = SpoofState.gsfId.toLongOrNull() ?: return null
        val cursor = MatrixCursor(arrayOf("_id", "value"))
        cursor.addRow(arrayOf<Any?>(0L, value))
        return cursor
    }
}
