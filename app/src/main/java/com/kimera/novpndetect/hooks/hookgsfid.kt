package com.kimera.novpndetect.hooks

import android.content.CancellationSignal
import android.content.ContentResolver
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.novpndetect.TAG
import com.kimera.novpndetect.XHook
import com.kimera.novpndetect.hookSafe
import com.kimera.novpndetect.spoof.SpoofState

/**
 * GSF ID (Google Services Framework android_id) spoof.
 *
 * Apps read it with a gservices ContentResolver query:
 *   query(content://com.google.android.gsf.gservices, null, null,
 *         new String[]{"android_id"}, null)
 * returning a two-column cursor (_id, value) where column 1 is the id.
 * Both the classic string-arg overload and the modern Bundle /
 * CancellationSignal overload are intercepted, so any reader style
 * (getLong(1), getColumnIndex("value"), [key]=value bundle queries)
 * receives the spoofed value.
 */
class HookGsfId : XHook {

    override val targetKlass: String
        get() = "android.content.ContentResolver"

    override fun injectHook(module: XposedModule) {
        hookQuery(module)
        hookQueryBundle(module)
    }

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
                val matched = isGsfQuery(uri) &&
                    (
                        (args != null && args.any { it == "android_id" }) ||
                            (selection != null && selection.contains("android_id"))
                        )
                val cursor = if (matched) gsfCursor() else null
                if (cursor != null) {
                    module.log(Log.INFO, TAG, "[NVD] GSF android_id -> spoofed")
                    cursor
                } else {
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
                val args = bundle?.getStringArray(ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS)
                val selection = bundle?.getString(ContentResolver.QUERY_ARG_SQL_SELECTION)
                val matched = isGsfQuery(uri) &&
                    (
                        (args != null && args.any { it == "android_id" }) ||
                            (selection != null && selection.contains("android_id"))
                        )
                val cursor = if (matched) gsfCursor() else null
                if (cursor != null) {
                    module.log(Log.INFO, TAG, "[NVD] GSF android_id -> spoofed (bundle)")
                    cursor
                } else {
                    chain.proceed()
                }
            }
        }
    }

    private fun isGsfQuery(uri: Uri?): Boolean =
        SpoofState.gsfOn &&
            uri != null &&
            uri.authority == "com.google.android.gsf.gservices" &&
            SpoofState.gsfId.isNotEmpty()

    private fun gsfCursor(): MatrixCursor? {
        val value = SpoofState.gsfId.toLongOrNull() ?: return null
        val cursor = MatrixCursor(arrayOf("_id", "value"))
        cursor.addRow(arrayOf<Any?>(0L, value))
        return cursor
    }
}
