package com.kimera.novpndetect.hooks

import android.content.ContentResolver
import android.database.MatrixCursor
import android.net.Uri
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
 * returning a cursor where column 1 is the id as a long. We build that cursor
 * with the spoofed value.
 */
class HookGsfId : XHook {

    override val targetKlass: String
        get() = "android.content.ContentResolver"

    override fun injectHook(module: XposedModule) {
        hookQuery(module)
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
                val gsf = SpoofState.gsfId
                val matched = SpoofState.gsfOn &&
                    uri != null &&
                    uri.authority == "com.google.android.gsf.gservices" &&
                    gsf.isNotEmpty() &&
                    (
                        (args != null && args.any { it == "android_id" }) ||
                            (selection != null && selection.contains("android_id"))
                        )
                if (matched) {
                    val value = gsf.toLongOrNull()
                    if (value != null) {
                        module.log(Log.INFO, TAG, "[NVD] GSF android_id -> spoofed")
                        val cursor = MatrixCursor(arrayOf("_id", "value"))
                        cursor.addRow(arrayOf<Any?>(0L, value))
                        cursor
                    } else {
                        chain.proceed()
                    }
                } else {
                    chain.proceed()
                }
            }
        }
    }
}
