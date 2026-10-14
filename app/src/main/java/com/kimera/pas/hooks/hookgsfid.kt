package com.kimera.pas.hooks

import android.content.ContentProviderClient
import android.content.ContentResolver
import android.database.Cursor
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
import java.util.Collections
import java.util.WeakHashMap

private const val GSF_AUTHORITY = "com.google.android.gsf.gservices"

/**
 * GSF ID (Google Services Framework android_id) spoof.
 *
 * Covered read paths (all in the scoped app's process):
 *  1. ContentResolver.query(...) on the gservices authority:
 *     4-arg, Bundle and CancellationSignal overloads.
 *  2. Path-style URI (key in the URI path).
 *  3. ContentResolver.call() "getValue"-style, Uri and authority overloads.
 *  4. ContentProviderClient.query(...) - apps that acquire a provider
 *     client bypass every ContentResolver hook. The query Uri carries the
 *     authority, so no receiver access is needed.
 *  5. ContentProviderClient.call(...) - receiver-free: gservices is the
 *     only provider whose call() surface uses android_id as a key, so the
 *     method/arg/extras shape identifies the read. acquire[Unstable]
 *     ContentProviderClient calls are tagged (WeakHashMap + one-shot diag)
 *     as an additional gate for future refinement.
 *
 * One-shot diagnostics (all INFO, tag PerAppSpoofer):
 *  - "gsf read while spoof inert"      -> read raced the config thread
 *  - "real cursor cols/types/count"    -> exact shape to mimic (peek+discard)
 *  - "real call() android_id type"     -> value type the call path delivers
 *  - "ContentProviderClient acquired"  -> reader uses the client path
 *  - "gsfId unparseable"               -> config format problem (leak cause)
 *
 * Not reachable from an in-process hook: reads performed by GMS inside its
 * own process, and reads issued over the raw IContentProvider binder
 * interface without passing through any Java entry point above.
 */
class HookGsfId : XHook {

    override val targetKlass: String
        get() = "android.content.ContentResolver"

    private var unmatchedLogged = 0
    private var inertLogged = false
    private var formatLogged = false
    private var cursorPeeked = false
    private var callPeeked = false
    private var cpcAcquireLogged = false
    private var diagModule: XposedModule? = null

    /** CPC instances handed out for the gservices authority. */
    private val gsfClients = Collections.synchronizedMap(WeakHashMap<Any, Boolean>())

    override fun injectHook(module: XposedModule) {
        diagModule = module
        hookQuery(module)
        hookQueryBundle(module)
        hookQueryCancellation(module)
        hookCallUri(module)
        hookCallAuthority(module)
        // Client-path coverage + observation
        hookCpcQueryClassic(module)
        hookCpcQueryBundle(module)
        hookCpcCall(module)
        hookAcquireVariant(module, "acquireContentProviderClient", String::class.java)
        hookAcquireVariant(module, "acquireContentProviderClient", Uri::class.java)
        hookAcquireVariant(module, "acquireUnstableContentProviderClient", String::class.java)
        hookAcquireVariant(module, "acquireUnstableContentProviderClient", Uri::class.java)
    }

    // ------------------------------------------------------------------
    // matching helpers
    // ------------------------------------------------------------------

    private fun gsfReadyOrDiag(): Boolean {
        if (SpoofState.gsfOn && SpoofState.gsfId.isNotEmpty()) return true
        if (!inertLogged) {
            inertLogged = true
            diagModule?.log(Log.INFO, TAG,
                "[PAS] GSF diag: gsf read while spoof inert " +
                    "(gsfOn=${SpoofState.gsfOn} idEmpty=${SpoofState.gsfId.isEmpty()}) - passed through")
        }
        return false
    }

    private fun isGsfAuthority(uri: Uri?): Boolean =
        uri != null && uri.authority == GSF_AUTHORITY && gsfReadyOrDiag()

    private fun isGsfAuthorityName(authority: String?): Boolean =
        authority == GSF_AUTHORITY && gsfReadyOrDiag()

    /** Does this query reference the android_id key (selection, args, path)? */
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
    // value helpers
    // ------------------------------------------------------------------

    /**
     * Accept the configured GSF ID as decimal or 16-char hex (with/without
     * 0x). Delivered value is always a Long: readers doing getString(1) +
     * Long.parseLong and readers doing getLong(1) both work, and
     * Long.toHexString(...) then produces the expected hex form.
     */
    private fun gsfIdValue(): Long? {
        val raw = SpoofState.gsfId.trim()
        if (raw.isEmpty()) return null
        raw.toLongOrNull()?.let { return it }
        val hex = raw.removePrefix("0x").removePrefix("0X")
        if (hex.length == 16) hex.toLongOrNull(16)?.let { return it }
        return null
    }

    private fun gsfCursor(module: XposedModule): MatrixCursor? {
        val value = gsfIdValue()
        if (value == null) {
            if (!formatLogged && SpoofState.gsfId.isNotEmpty()) {
                formatLogged = true
                module.log(Log.INFO, TAG,
                    "[PAS] GSF diag: configured gsfId unparseable " +
                        "(len=${SpoofState.gsfId.length} prefix='${SpoofState.gsfId.take(4)}') " +
                        "- expected decimal or 16-char hex; reads passed through")
            }
            return null
        }
        val cursor = MatrixCursor(arrayOf("_id", "value"))
        cursor.addRow(arrayOf<Any?>(0L, value))
        return cursor
    }

    /**
     * One-shot: proceed the real query, log the real provider's cursor shape,
     * discard it. The spoofed cursor is returned by the caller regardless.
     */
    private fun peekRealCursorShape(module: XposedModule, proceed: () -> Any?) {
        if (cursorPeeked) return
        cursorPeeked = true
        try {
            val real = proceed() as? Cursor
            if (real == null) {
                module.log(Log.INFO, TAG, "[PAS] GSF diag: real query returned null cursor")
                return
            }
            val names = real.columnNames?.joinToString(",") ?: "?"
            val types = (0 until real.columnCount).joinToString(",") { i ->
                when (real.getType(i)) {
                    Cursor.FIELD_TYPE_INTEGER -> "int"
                    Cursor.FIELD_TYPE_FLOAT -> "float"
                    Cursor.FIELD_TYPE_STRING -> "string"
                    Cursor.FIELD_TYPE_BLOB -> "blob"
                    else -> "null"
                }
            }
            val count = if (real.moveToFirst()) real.count else 0
            module.log(Log.INFO, TAG,
                "[PAS] GSF diag: real cursor cols=[$names] types=[$types] count=$count " +
                    "- spoofed cursor delivers [_id,value]")
            real.close()
        } catch (t: Throwable) {
            module.log(Log.INFO, TAG,
                "[PAS] GSF diag: real cursor peek failed: ${t.javaClass.simpleName}")
        }
    }

    // ------------------------------------------------------------------
    // ContentResolver query hooks
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
                val cursor = if (matched) gsfCursor(module) else null
                if (cursor != null) {
                    peekRealCursorShape(module) { chain.proceed() }
                    module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed")
                    cursor
                } else {
                    if (isGsfAuthority(uri) && !matched) {
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
                val cursor = if (matched) gsfCursor(module) else null
                if (cursor != null) {
                    peekRealCursorShape(module) { chain.proceed() }
                    module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (bundle)")
                    cursor
                } else {
                    if (isGsfAuthority(uri) && !matched) {
                        logUnmatchedGsf(module, "query-bundle uri=$uri keys=${bundle?.keySet()?.joinToString()}")
                    }
                    chain.proceed()
                }
            }
        }
    }

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
                val cursor = if (matched) gsfCursor(module) else null
                if (cursor != null) {
                    peekRealCursorShape(module) { chain.proceed() }
                    module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (cancellation)")
                    cursor
                } else {
                    if (isGsfAuthority(uri) && !matched) {
                        logUnmatchedGsf(module, "query-cancel uri=$uri sel=$selection args=${args?.joinToString()}")
                    }
                    chain.proceed()
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // ContentResolver call hooks ("getValue"-style reads)
    // ------------------------------------------------------------------

    private fun spoofedCallResult(module: XposedModule, result: Bundle?, explicit: Boolean): Bundle {
        val out = Bundle(result ?: Bundle())
        if (!callPeeked && result != null && result.containsKey("android_id")) {
            callPeeked = true
            val v: Any? = result.get("android_id")
            val desc = when (v) {
                null -> "null"
                is Long -> "Long(${v.toString().length} digits)"
                is String -> "String(len=${v.length} prefix='${v.take(4)}')"
                else -> v.javaClass.simpleName
            }
            module.log(Log.INFO, TAG, "[PAS] GSF diag: real call() android_id value type=$desc")
        }
        val spoof = gsfIdValue() ?: return result ?: out
        if (out.containsKey("android_id")) {
            when (out.get("android_id")) {
                is String -> out.putString("android_id", spoof.toString()) // decimal, same as the provider
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
                val matched = isGsfAuthority(uri) && callRefsAndroidId(callMethod, arg, extras)
                val result = chain.proceed() as? Bundle
                if (matched) {
                    val spoofed = spoofedCallResult(module, result, explicit = true)
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
                val matched = isGsfAuthorityName(authority) && callRefsAndroidId(callMethod, arg, extras)
                val result = chain.proceed() as? Bundle
                if (matched) {
                    val spoofed = spoofedCallResult(module, result, explicit = true)
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
    // ContentProviderClient paths (client-based readers)
    // ------------------------------------------------------------------

    private fun hookCpcQueryClassic(module: XposedModule) {
        hookSafe(module, "ContentProviderClient.query(gsf)") {
            val method = ContentProviderClient::class.java.getMethod(
                "query",
                Uri::class.java,
                Array<String>::class.java,
                String::class.java,
                Array<String>::class.java,
                String::class.java
            )
            module.hook(method).intercept { chain ->
                // The client carries no authority; the query Uri does.
                val uri = chain.getArg(0) as? Uri
                val selection = chain.getArg(2) as? String
                val args = chain.getArg(3) as? Array<*>
                val matched = isGsfAuthority(uri) && refsAndroidId(uri, selection, args)
                val cursor = if (matched) gsfCursor(module) else null
                if (cursor != null) {
                    peekRealCursorShape(module) { chain.proceed() }
                    module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (providerclient)")
                    cursor
                } else {
                    if (isGsfAuthority(uri) && !matched) {
                        logUnmatchedGsf(module, "providerclient-query uri=$uri sel=$selection args=${args?.joinToString()}")
                    }
                    chain.proceed()
                }
            }
        }
    }

    private fun hookCpcQueryBundle(module: XposedModule) {
        hookSafe(module, "ContentProviderClient.query(gsf,bundle)") {
            val method = ContentProviderClient::class.java.getMethod(
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
                val cursor = if (matched) gsfCursor(module) else null
                if (cursor != null) {
                    module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (providerclient,bundle)")
                    cursor
                } else {
                    chain.proceed()
                }
            }
        }
    }

    /**
     * Client call() path. Receiver-free: gservices is the only provider
     * whose call() surface uses android_id as a key, so the method/arg/
     * extras shape identifies the read. Result rewriting is type-preserving
     * and touches only the android_id entry.
     */
    private fun hookCpcCall(module: XposedModule) {
        hookSafe(module, "ContentProviderClient.call(gsf)") {
            val method = ContentProviderClient::class.java.getMethod(
                "call", String::class.java, String::class.java, Bundle::class.java
            )
            module.hook(method).intercept { chain ->
                val callMethod = chain.getArg(0) as? String
                val arg = chain.getArg(1) as? String
                val extras = chain.getArg(2) as? Bundle
                val matched = callRefsAndroidId(callMethod, arg, extras) && gsfReadyOrDiag()
                val result = chain.proceed() as? Bundle
                if (matched) {
                    val spoofed = spoofedCallResult(module, result, explicit = true)
                    module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (providerclient,call)")
                    spoofed
                } else {
                    result
                }
            }
        }
    }

    /** Tag CPC instances handed out for gservices (both stable/unstable, String/Uri). */
    private fun hookAcquireVariant(module: XposedModule, methodName: String, argType: Class<*>) {
        hookSafe(module, "ContentResolver.$methodName(gsf,tag)") {
            val method = ContentResolver::class.java.getMethod(methodName, argType)
            module.hook(method).intercept { chain ->
                val a0 = chain.getArg(0)
                val authority = if (a0 is String) a0 else if (a0 is Uri) a0.authority else null
                val client = chain.proceed()
                if (authority == GSF_AUTHORITY && client != null) {
                    gsfClients[client] = true
                    if (!cpcAcquireLogged) {
                        cpcAcquireLogged = true
                        module.log(Log.INFO, TAG,
                            "[PAS] GSF diag: ContentProviderClient acquired for gservices via $methodName")
                    }
                }
                client
            }
        }
    }

    // ------------------------------------------------------------------
    // diag helper
    // ------------------------------------------------------------------

    private fun logUnmatchedGsf(module: XposedModule, shape: String) {
        if (unmatchedLogged >= 3) return
        unmatchedLogged++
        module.log(Log.INFO, TAG, "[PAS] GSF diag: gsf query NOT spoofed: $shape")
    }
}