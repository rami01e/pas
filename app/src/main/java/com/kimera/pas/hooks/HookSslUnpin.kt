package com.kimera.pas.hooks

import android.net.http.SslError
import android.util.Log
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState

/**
 * SSL unpinning (per-app): neutralizes the common Java-layer certificate
 * pinning vectors so mitmproxy-style inspection works on scoped apps.
 *
 * Two independent surfaces are covered:
 *
 *  1. OkHttp pinning - CertificatePinner.check(...) made a no-op. This is
 *     the vector used by apps whose HTTP layer is OkHttp (most modern SDKs).
 *
 *  2. WebView SSL errors - SslErrorHandler.cancel() is turned into
 *     SslErrorHandler.proceed(). This is the EULA / in-game-browser path:
 *     WebView reports a cert failure to the app's WebViewClient, the app
 *     decides proceed() (accept) or cancel() (reject), and apps that reject
 *     unknown chains silently kill every page load under mitmproxy. That
 *     was almost certainly what was stalling Big Farm's EULA webview.
 *
 *     Also hooking the framework's WebViewClient.onReceivedSslError default
 *     so any fallback path (app delegates to super) is auto-proceeded too.
 *
 * Compatible with TrustMe-style modules: this only removes enforcement, it
 * does not alter trust evaluation or replace any trust manager.
 */
class HookSslUnpin : XHook {

    override val targetKlass: String
        get() = "okhttp3.CertificatePinner"

    override fun injectHook(module: XposedModule) {
        var installed = 0
        if (unpinOkHttp(module)) installed++
        if (bypassWebViewSslErrors(module)) installed++
        module.log(
            Log.INFO, TAG,
            "[PAS] ssl unpin: java hooks installed ($installed/2 surfaces active)"
        )
    }

    // ------------------------------------------------------------------
    // Surface 1: OkHttp CertificatePinner
    // ------------------------------------------------------------------
    private fun unpinOkHttp(module: XposedModule): Boolean {
        var any = false
        hookSafe(module, "ssl-unpin okhttp3.CertificatePinner") {
            val clazz = Class.forName("okhttp3.CertificatePinner")
            for (name in arrayOf("check", "check\$okhttp")) {
                for (m in clazz.declaredMethods) {
                    if (m.name != name) continue
                    if (m.parameterTypes.isEmpty()) continue
                    m.isAccessible = true
                    module.hook(m).intercept { chain ->
                        if (SpoofState.reconOn) {
                            module.log(
                                Log.INFO, TAG,
                                "[PAS] ssl unpin: CertificatePinner.${m.name} bypassed"
                            )
                        }
                        null
                    }
                    any = true
                }
            }
        }
        return any
    }

    // ------------------------------------------------------------------
    // Surface 2: WebView SslErrorHandler.cancel() -> proceed()
    // ------------------------------------------------------------------
    //
    // SslErrorHandler is a framework class with a stable signature
    // (android.webkit.SslErrorHandler#proceed / #cancel). Apps must call
    // one of the two on the handler instance the framework hands them in
    // onReceivedSslError. Whatever their WebViewClient override does, the
    // last call lands on this handler - so flipping cancel() into proceed()
    // accepts every chain the app was going to reject.
    private fun bypassWebViewSslErrors(module: XposedModule): Boolean {
        var ok = false

        hookSafe(module, "ssl-unpin SslErrorHandler.cancel->proceed") {
            val cls = Class.forName("android.webkit.SslErrorHandler")
            val cancel = cls.getDeclaredMethod("cancel")
            val proceed = cls.getDeclaredMethod("proceed")
            cancel.isAccessible = true
            proceed.isAccessible = true
            module.hook(cancel).intercept { chain ->
                val self = chain.getThisObject()
                if (SpoofState.reconOn) {
                    module.log(
                        Log.INFO, TAG,
                        "[PAS] ssl unpin: SslErrorHandler.cancel() -> proceed()"
                    )
                }
                // Force the accept path. If proceed() throws (already-handled
                // or detached state), swallow - the load stays alive either
                // way, and returning normally avoids the app's own cancel.
                runCatching { proceed.invoke(self) }
                null
            }
            ok = true
        }

        // Defensive: also cover the framework's default onReceivedSslError
        // implementation. Apps that override without calling super never
        // reach this (their override calls the handler directly, which the
        // cancel hook above already covers). Apps that delegate to super
        // hit this and get an auto-proceed without their default cancel.
        hookSafe(module, "ssl-unpin WebViewClient.onReceivedSslError") {
            val cls = WebViewClient::class.java
            val m = cls.getDeclaredMethod(
                "onReceivedSslError",
                WebView::class.java,
                SslErrorHandler::class.java,
                SslError::class.java
            )
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                val handler = chain.getArg(1) as? SslErrorHandler
                if (handler != null) {
                    if (SpoofState.reconOn) {
                        module.log(
                            Log.INFO, TAG,
                            "[PAS] ssl unpin: WebViewClient.onReceivedSslError -> proceed()"
                        )
                    }
                    runCatching { handler.proceed() }
                    null
                } else {
                    chain.proceed()
                }
            }
            ok = true
        }

        return ok
    }
}