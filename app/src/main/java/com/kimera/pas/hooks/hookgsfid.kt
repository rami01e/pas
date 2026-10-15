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

/** 16-char value containing at least one hex letter => hex16 format. */
private fun looksHex16(s: String?): Boolean =
    s != null && s.length == 16 &&
        s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } &&
        s.any { it in 'a'..'f' || it in 'A'..'F' }

/**
 * GSF ID (Google Services Framework android_id) spoof - general layer stack.
 *
 * Layer 1 - ContentResolver.query(...) on the gservices authority: 4-arg,
 *           Bundle and CancellationSignal overloads; path-style URIs.
 * Layer 2 - ContentResolver.call(...) "getValue"-style, Uri and authority
 *           overloads.
 * Layer 3 - ContentProviderClient.query(...) and .call(...);
 *           acquire[Unstable]ContentProviderClient tagging (observation).
 * Layer 4 - ContentProviderProxy.query(...): the binder-side choke point.
 *           Every Java-side provider read - wrapper-based OR raw-interface
 *           (an app holding the IContentProvider from the hidden
 *           acquireProvider) - executes this method in the reading process,
 *           so it catches readers that bypass every wrapper. JNI-invoked
 *           queries are covered as well (ART-level hook entry). Unfiltered
 *           full-table dumps are intercepted: the response mirrors ALL rows
 *           and rewrites only the android_id row; queries filtered for
 *           OTHER gservices keys pass raw.
 *
 * RESPONSE MIRRORING (v2.7.4): every matched query proceeds the REAL
 * provider read, then returns a copy with identical column names,
 * per-cell types and rows - only the android_id value cell is replaced,
 * formatted with the same type and radix as the real cell.
 *
 * Double-coverage suppression (v2.7.5): modern ContentResolver implements
 * the classic query overloads by delegating to the Bundle variant, and
 * every wrapper read eventually executes ContentProviderProxy.query - so a
 * mirror's proceed re-enters lower hook layers. While the thread-local
 * flag is set, every query-layer hook passes through: exactly one mirror,
 * one binder read, one log line per app-level call. Attribution:
 * "(mirrored...)" = wrapper path; "(proxy...)" = raw-interface reader.
 *
 * One-shot diagnostics (INFO, tag PerAppSpoofer): "mirror shape ...",
 * "real call() result ...", "gsf query NOT spoofed: <shape>",
 * "gsf read while spoof inert", "gsfId unparseable",
 * "ContentProviderClient acquired ...",
 * "ContentProviderProxy not resolvable ...".
 *
 * Documented structural limits: call() at the proxy level (signature
 * carries no authority - cannot be attributed without receiver access),
 * raw Parcel transacts, and reads performed inside GMS's own process.
 */
class HookGsfId : XHook {

    override val targetKlass: String
        get() = "android.content.ContentResolver"

    private var unmatchedLogged = 0
    private var inertLogged = false
    private var formatLogged = false
    private var shapeLogged = false
    private var callPeeked = false
    private var cpcAcquireLogged = false
    private var diagModule: XposedModule? = null

    /** CPC instances handed out for the gservices authority. */
    private val gsfClients = Collections.synchronizedMap(WeakHashMap<Any, Boolean>())

    /**
     * True while a query-layer hook is proceeding a gservices read on this
     * thread (see class doc: double-coverage suppression).
     */
    private val inWrapperGsf = ThreadLocal.withInitial { false }

    override fun injectHook(module: XposedModule) {
        diagModule = module
        hookQuery(module)
        hookQueryBundle(module)
        hookQueryCancellation(module)
        hookCallUri(module)
        hookCallAuthority(module)
        hookCpcQueryClassic(module)
        hookCpcQueryBundle(module)
        hookCpcCall(module)
        hookProviderProxy(module)
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

    /** Configured GSF ID as decimal or 16-char hex (with/without 0x). */
    private fun gsfIdValue(): Long? {
        val raw = SpoofState.gsfId.trim()
        if (raw.isEmpty()) return null
        raw.toLongOrNull()?.let { return it }
        val hex = raw.removePrefix("0x").removePrefix("0X")
        if (hex.length == 16) hex.toLongOrNull(16)?.let { return it }
        return null
    }

    private fun logUnparseableOnce(module: XposedModule) {
        if (formatLogged || SpoofState.gsfId.isEmpty()) return
        formatLogged = true
        module.log(Log.INFO, TAG,
            "[PAS] GSF diag: configured gsfId unparseable " +
                "(len=${SpoofState.gsfId.length} prefix='${SpoofState.gsfId.take(4)}') " +
                "- expected decimal or 16-char hex; matched reads passed through")
    }

    /** Legacy static shape: last-resort when the real read fails or is empty. */
    private fun staticGsfCursor(spoof: Long): Cursor {
        val cursor = MatrixCursor(arrayOf("_id", "value"))
        cursor.addRow(arrayOf<Any?>(0L, spoof))
        return cursor
    }

    private fun cellAt(c: Cursor, i: Int): Any? = when (c.getType(i)) {
        Cursor.FIELD_TYPE_INTEGER -> c.getLong(i)
        Cursor.FIELD_TYPE_FLOAT -> c.getDouble(i)
        Cursor.FIELD_TYPE_STRING -> c.getString(i)
        Cursor.FIELD_TYPE_BLOB -> c.getBlob(i)
        else -> null
    }

    private fun typeName(t: Int): String = when (t) {
        Cursor.FIELD_TYPE_INTEGER -> "int"
        Cursor.FIELD_TYPE_FLOAT -> "float"
        Cursor.FIELD_TYPE_STRING -> "string"
        Cursor.FIELD_TYPE_BLOB -> "blob"
        else -> "null"
    }

    private fun logShapeOnce(module: XposedModule, detail: String) {
        if (shapeLogged) return
        shapeLogged = true
        module.log(Log.INFO, TAG, "[PAS] GSF diag: $detail")
    }

    /**
     * Build the spoofed response by MIRRORING the real provider's cursor:
     * identical columns, per-cell types and rows; only the android_id value
     * cell is replaced, with the same type and radix as the real cell.
     * When fullDump is true (no selection filter: the reader extracts
     * android_id from the whole table) ALL rows are copied, uncapped up to
     * 4096, and only the android_id row is rewritten. The proceed runs with
     * the suppression flag set so lower hook layers pass through. Returns
     * null only when the configured gsfId is unparseable (caller then
     * passes the real query through).
     */
    private fun spoofedQueryCursor(
        module: XposedModule,
        proceed: () -> Any?,
        fullDump: Boolean = false
    ): Cursor? {
        val spoof = gsfIdValue()
        if (spoof == null) {
            logUnparseableOnce(module)
            return null
        }
        val real: Cursor? = try {
            val prev = inWrapperGsf.get()
            inWrapperGsf.set(true)
            try {
                proceed() as? Cursor
            } finally {
                inWrapperGsf.set(prev)
            }
        } catch (t: Throwable) {
            null
        }
        if (real == null) {
            logShapeOnce(module, "mirror: real query returned null - static shape used")
            return staticGsfCursor(spoof)
        }
        try {
            val cols = real.columnNames?.toList()
            if (cols.isNullOrEmpty()) {
                real.close()
                logShapeOnce(module, "mirror: real query returned no columns - static shape used")
                return staticGsfCursor(spoof)
            }
            val valueCol = cols.indexOf("value").let { if (it >= 0) it else if (cols.size >= 2) 1 else -1 }
            val nameCol = cols.indexOf("name")
            val out = MatrixCursor(cols.toTypedArray())
            val maxRows = if (fullDump) 4096 else 8
            var rowCount = 0
            var hex = false
            if (real.moveToFirst()) {
                var first = true
                do {
                    val row = arrayOfNulls<Any?>(cols.size)
                    for (i in cols.indices) row[i] = cellAt(real, i)
                    if (first) {
                        first = false
                        val types = (0 until real.columnCount).joinToString(",") { typeName(real.getType(it)) }
                        val nameMatches = nameCol < 0 || (row[nameCol] as? String) == "android_id"
                        if (nameMatches && valueCol >= 0) hex = looksHex16(row[valueCol] as? String)
                        logShapeOnce(module, "mirror shape cols=[${cols.joinToString(",")}] " +
                            "types=[$types] count=${real.count} valueCol=$valueCol nameCol=$nameCol " +
                            "radix=${if (hex) "hex16" else "decimal"}${if (fullDump) " fulldump" else ""}")
                    }
                    val isTargetRow = nameCol < 0 || (row[nameCol] as? String) == "android_id"
                    if (isTargetRow && valueCol >= 0) {
                        val orig = row[valueCol]
                        row[valueCol] = if (orig is Long) spoof
                            else if (hex) spoof.toString(16).padStart(16, '0')
                            else spoof.toString()
                    }
                    out.addRow(row)
                    rowCount++
                } while (real.moveToNext() && rowCount < maxRows)
            } else {
                logShapeOnce(module, "mirror shape cols=[${cols.joinToString(",")}] count=0 " +
                    "(real result empty - mirrored)")
            }
            real.close()
            return out
        } catch (t: Throwable) {
            try { real.close() } catch (_: Throwable) {}
            logShapeOnce(module, "mirror failed (${t.javaClass.simpleName}) - static shape used")
            return staticGsfCursor(spoof)
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
                if (inWrapperGsf.get()) return@intercept chain.proceed()
                val uri = chain.getArg(0) as? Uri
                val projection = chain.getArg(1) as? Array<*>
                val selection = chain.getArg(2) as? String
                val args = chain.getArg(3) as? Array<*>
                if (isGsfAuthority(uri) && refsAndroidId(uri, selection, args)) {
                    val cursor = spoofedQueryCursor(module) { chain.proceed() }
                    if (cursor != null) {
                        module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (mirrored)")
                        cursor
                    } else {
                        chain.proceed()
                    }
                } else {
                    if (isGsfAuthority(uri)) {
                        logUnmatchedGsf(module, "query uri=$uri proj=${projection?.joinToString()} " +
                            "sel=$selection args=${args?.joinToString()}")
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
                if (inWrapperGsf.get()) return@intercept chain.proceed()
                val uri = chain.getArg(0) as? Uri
                val bundle = chain.getArg(2) as? Bundle
                if (isGsfAuthority(uri) &&
                    (refsAndroidIdInBundle(bundle) || refsAndroidId(uri, null, null))
                ) {
                    val cursor = spoofedQueryCursor(module) { chain.proceed() }
                    if (cursor != null) {
                        module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (mirrored,bundle)")
                        cursor
                    } else {
                        chain.proceed()
                    }
                } else {
                    if (isGsfAuthority(uri)) {
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
                if (inWrapperGsf.get()) return@intercept chain.proceed()
                val uri = chain.getArg(0) as? Uri
                val projection = chain.getArg(1) as? Array<*>
                val selection = chain.getArg(2) as? String
                val args = chain.getArg(3) as? Array<*>
                if (isGsfAuthority(uri) && refsAndroidId(uri, selection, args)) {
                    val cursor = spoofedQueryCursor(module) { chain.proceed() }
                    if (cursor != null) {
                        module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (mirrored,cancellation)")
                        cursor
                    } else {
                        chain.proceed()
                    }
                } else {
                    if (isGsfAuthority(uri)) {
                        logUnmatchedGsf(module, "query-cancel uri=$uri proj=${projection?.joinToString()} " +
                            "sel=$selection args=${args?.joinToString()}")
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
        if (!callPeeked && result != null) {
            callPeeked = true
            val v: Any? = result.get("android_id")
            val desc = when (v) {
                null -> "absent"
                is Long -> "Long(${v.toString().length} digits)"
                is String -> "String(len=${v.length} prefix='${v.take(4)}')"
                else -> v.javaClass.simpleName
            }
            val keys = result.keySet().joinToString(",").take(120)
            module.log(Log.INFO, TAG,
                "[PAS] GSF diag: real call() result android_id=$desc keys=[$keys]")
        }
        val spoof = gsfIdValue()
        if (spoof == null) {
            logUnparseableOnce(module)
            return result ?: out
        }
        if (out.containsKey("android_id")) {
            when (val v = out.get("android_id")) {
                is String -> out.putString("android_id",
                    if (looksHex16(v)) spoof.toString(16).padStart(16, '0') else spoof.toString())
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
                if (inWrapperGsf.get()) return@intercept chain.proceed()
                val uri = chain.getArg(0) as? Uri
                val selection = chain.getArg(2) as? String
                val args = chain.getArg(3) as? Array<*>
                if (isGsfAuthority(uri) && refsAndroidId(uri, selection, args)) {
                    val cursor = spoofedQueryCursor(module) { chain.proceed() }
                    if (cursor != null) {
                        module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (mirrored,providerclient)")
                        cursor
                    } else {
                        chain.proceed()
                    }
                } else {
                    if (isGsfAuthority(uri)) {
                        logUnmatchedGsf(module, "providerclient-query uri=$uri sel=$selection " +
                            "args=${args?.joinToString()}")
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
                if (inWrapperGsf.get()) return@intercept chain.proceed()
                val uri = chain.getArg(0) as? Uri
                val bundle = chain.getArg(2) as? Bundle
                if (isGsfAuthority(uri) &&
                    (refsAndroidIdInBundle(bundle) || refsAndroidId(uri, null, null))
                ) {
                    val cursor = spoofedQueryCursor(module) { chain.proceed() }
                    if (cursor != null) {
                        module.log(Log.INFO, TAG, "[PAS] GSF android_id -> spoofed (mirrored,providerclient,bundle)")
                        cursor
                    } else {
                        chain.proceed()
                    }
                } else {
                    if (isGsfAuthority(uri)) {
                        logUnmatchedGsf(module, "providerclient-query-bundle uri=$uri " +
                            "keys=${bundle?.keySet()?.joinToString()}")
                    }
                    chain.proceed()
                }
            }
        }
    }

    /**
     * Client call() path. Receiver-free: gservices is the only provider
     * whose call() surface uses android_id as a key, so the method/arg/
     * extras shape identifies the read. Result rewriting is type- and
     * radix-preserving and touches only the android_id entry.
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

    // ------------------------------------------------------------------
    // Layer 4: binder-proxy choke point (raw-interface readers)
    // ------------------------------------------------------------------

    /**
     * Resolve the hidden ContentProviderProxy class: top-level since
     * Android 12, inner class of ContentResolver before that, with a
     * declaredClasses scan as the last resort.
     */
    private fun resolveProviderProxyClass(): Class<*>? {
        for (name in listOf(
            "android.content.ContentProviderProxy",
            "android.content.ContentResolver\$ContentProviderProxy"
        )) {
            try {
                return Class.forName(name)
            } catch (_: Throwable) {
            }
        }
        try {
            for (c in ContentResolver::class.java.declaredClasses) {
                if (c.simpleName == "ContentProviderProxy") return c
            }
        } catch (_: Throwable) {
        }
        return null
    }

    /**
     * Hook every ContentProviderProxy.query overload. Known signature
     * shapes (across versions):
     *   legacy: (callingPkg, url, projection[], selection, selectionArgs[], sortOrder)
     *   modern: (callingPkg | AttributionSource, url, projection[], queryArgs Bundle, cancellation)
     * The Uri argument carries the authority, so gservices matching is
     * exact. Keyed android_id reads and unfiltered full-table dumps are
     * mirrored; queries filtered for OTHER gservices keys pass raw. A
     * wrapper-layer proceed sets the suppression flag, and this layer then
     * passes through (single mirror, single log line).
     */
    private fun hookProviderProxy(module: XposedModule) {
        hookSafe(module, "ContentProviderProxy(gsf)") {
            val clazz = resolveProviderProxyClass()
            if (clazz == null) {
                module.log(Log.INFO, TAG,
                    "[PAS] GSF diag: ContentProviderProxy not resolvable " +
                        "(tried android.content.ContentProviderProxy, " +
                        "android.content.ContentResolver\$ContentProviderProxy, declaredClasses) " +
                        "- raw-interface reads not covered")
                return@hookSafe
            }
            var hooked = 0
            for (m in clazz.declaredMethods) {
                if (m.name != "query") continue
                val sig = m.parameterTypes.joinToString(",") { it.simpleName }
                hookSafe(module, "ContentProviderProxy.query($sig)") {
                    module.hook(m).intercept { chain ->
                        if (inWrapperGsf.get()) return@intercept chain.proceed()
                        val n = m.parameterTypes.size
                        var uriIdx = -1
                        for (i in 0 until n) {
                            if (chain.getArg(i) is Uri) {
                                uriIdx = i
                                break
                            }
                        }
                        if (uriIdx < 0) return@intercept chain.proceed()
                        val uri = chain.getArg(uriIdx) as Uri
                        if (uri.authority != GSF_AUTHORITY || !gsfReadyOrDiag()) {
                            return@intercept chain.proceed()
                        }
                        var refs = false
                        for (i in 0 until n) {
                            when (val a = chain.getArg(i)) {
                                is String -> if (a.contains("android_id")) refs = true
                                is Array<*> -> if (a.any { it == "android_id" }) refs = true
                                is Bundle -> if (refsAndroidIdInBundle(a)) refs = true
                            }
                        }
                        if (!refs) {
                            // Unkeyed query: is there a selection filter for another key?
                            val pt = m.parameterTypes
                            var filtered = false
                            if (uriIdx + 2 < n && pt[uriIdx + 2] == String::class.java) {
                                val sel = chain.getArg(uriIdx + 2) as? String
                                val argsA =
                                    if (uriIdx + 3 < n) chain.getArg(uriIdx + 3) as? Array<*> else null
                                filtered = (sel != null && sel.isNotBlank()) ||
                                    (argsA != null && argsA.size > 0)
                            } else if (uriIdx + 2 < n && pt[uriIdx + 2] == Bundle::class.java) {
                                val b = chain.getArg(uriIdx + 2) as? Bundle
                                if (b != null) {
                                    val selArgs =
                                        b.getStringArray(ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS)
                                    filtered =
                                        b.getString(ContentResolver.QUERY_ARG_SQL_SELECTION) != null ||
                                            (selArgs != null && selArgs.size > 0)
                                }
                            }
                            if (filtered) return@intercept chain.proceed()
                        }
                        val fullDump = !refs
                        val cursor = spoofedQueryCursor(module, { chain.proceed() }, fullDump)
                        if (cursor != null) {
                            module.log(Log.INFO, TAG,
                                "[PAS] GSF android_id -> spoofed (proxy${if (fullDump) ",fulldump" else ""})")
                            cursor
                        } else {
                            chain.proceed()
                        }
                    }
                }
                hooked++
            }
            module.log(Log.INFO, TAG,
                "[PAS] GSF provider-proxy query hooks installed=$hooked (${clazz.name})")
            if (hooked == 0) {
                module.log(Log.INFO, TAG,
                    "[PAS] GSF diag: ContentProviderProxy exposes no query methods - nothing hooked")
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
        if (unmatchedLogged >= 10) return
        unmatchedLogged++
        module.log(Log.INFO, TAG, "[PAS] GSF diag: gsf query NOT spoofed: $shape")
    }
}