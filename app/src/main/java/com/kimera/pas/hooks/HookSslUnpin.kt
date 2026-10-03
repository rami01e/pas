package com.kimera.pas.hooks

import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState

/**
 * SSL unpinning (per-app). Gate: SpoofState.sslUnpinMode
 *   0 = OFF, 1 = JAVA only, 2 = NATIVE only, 3 = BOTH
 *
 * The Java surfaces installed here cover the certificate-pinning vectors
 * used by OkHttp, Conscrypt (Android's default TLS provider), the
 * NetworkSecurityConfig layer, and WebView's SSL error handler. Every
 * interception is logged as "ssl-pin: ..." so Diagnose captures show which
 * surfaces a scoped app actually touches.
 *
 * Surfaces (mirrors the well-known TrustMe set):
 *   - okhttp3.CertificatePinner.check        (+ check$okhttp)
 *   - okhttp3.internal.tls.OkHostnameVerifier.verify
 *   - com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive
 *   - com.android.org.conscrypt.TrustManagerImpl.verifyChain
 *   - android.security.net.config.NetworkSecurityTrustManager.checkServerTrusted
 *   - android.security.net.config.NetworkSecurityTrustManager.isSubdomain
 *   - javax.net.ssl.HttpsURLConnection default HostnameVerifier
 *   - android.webkit.SslErrorHandler.cancel  -> proceed
 *
 * NOT hooked: android.webkit.WebViewClient.onReceivedSslError. Resolving
 * its parameter types forces the WebView provider to initialize at module
 * time, which crashes the app (NoSuchMethodError AconfigPackage.load on
 * modern Chromium). SslErrorHandler alone covers the same surface without
 * touching WebView.
 *
 * Native-side unpinning (SSL_set_verify / X509_verify_cert) is installed
 * by hide_ssl.cpp when mode is 2 or 3.
 */
class HookSslUnpin : XHook {

    override val targetKlass: String
        get() = "okhttp3.CertificatePinner"

    override fun injectHook(module: XposedModule) {
        val mode = SpoofState.sslUnpinMode
        if (mode == 0 || mode == 2) {
            module.log(Log.INFO, TAG, "[PAS] ssl unpin: java surfaces skipped (mode=$mode)")
            return
        }

        var count = 0
        if (hookOkHttpPinner(module)) count++
        if (hookOkHostnameVerifier(module)) count++
        if (hookConscryptTrustManager(module)) count++
        if (hookNetworkSecurityTrustManager(module)) count++
        if (hookHttpsHostnameVerifier(module)) count++
        if (hookWebViewSslHandler(module)) count++

        module.log(
            Log.INFO, TAG,
            "[PAS] ssl unpin: java surfaces installed ($count/6) mode=$mode"
        )
    }

    // ------------------------------------------------------------------
    // 1. OkHttp CertificatePinner.check(...)
    // ------------------------------------------------------------------
    private fun hookOkHttpPinner(module: XposedModule): Boolean {
        var any = false
        hookSafe(module, "ssl-pin okhttp CertificatePinner") {
            val cls = Class.forName("okhttp3.CertificatePinner")
            for (name in arrayOf("check", "check\$okhttp")) {
                for (m in cls.declaredMethods) {
                    if (m.name != name) continue
                    if (m.parameterTypes.isEmpty()) continue
                    m.isAccessible = true
                    module.hook(m).intercept { chain ->
                        val host = chain.args.firstOrNull { it is String } as? String
                        module.log(
                            Log.INFO, TAG,
                            "[PAS] ssl-pin: okhttp CertificatePinner.${m.name}" +
                                (host?.let { " host=$it" } ?: "")
                        )
                        null
                    }
                    any = true
                }
            }
        }
        return any
    }

    // ------------------------------------------------------------------
    // 2. OkHostnameVerifier.verify(String, SSLSession)
    // ------------------------------------------------------------------
    private fun hookOkHostnameVerifier(module: XposedModule): Boolean {
        var any = false
        hookSafe(module, "ssl-pin OkHostnameVerifier") {
            val cls = Class.forName("okhttp3.internal.tls.OkHostnameVerifier")
            for (m in cls.declaredMethods) {
                if (m.name != "verify") continue
                if (m.parameterTypes.size != 2) continue
                m.isAccessible = true
                module.hook(m).intercept { chain ->
                    val host = chain.args.firstOrNull { it is String } as? String
                    module.log(
                        Log.INFO, TAG,
                        "[PAS] ssl-pin: OkHostnameVerifier.verify" +
                            (host?.let { " host=$it" } ?: "") + " -> true"
                    )
                    true
                }
                any = true
            }
        }
        return any
    }

    // ------------------------------------------------------------------
    // 3. Conscrypt TrustManagerImpl (Android's default TLS verifier)
    //    checkTrustedRecursive and verifyChain both return a List<X509Certificate>
    //    on success and throw on failure. Turning either into a no-op
    //    accepts every chain the default trust manager would reject.
    // ------------------------------------------------------------------
    private fun hookConscryptTrustManager(module: XposedModule): Boolean {
        var any = false
        hookSafe(module, "ssl-pin Conscrypt TrustManagerImpl") {
            val cls = Class.forName("com.android.org.conscrypt.TrustManagerImpl")
            for (m in cls.declaredMethods) {
                if (m.name != "checkTrustedRecursive" && m.name != "verifyChain") continue
                m.isAccessible = true
                module.hook(m).intercept { chain ->
                    if (SpoofState.reconOn) {
                        module.log(
                            Log.INFO, TAG,
                            "[PAS] ssl-pin: Conscrypt TrustManagerImpl.${m.name} bypassed"
                        )
                    }
                    // Returning the input chain (last List<X509Certificate> arg)
                    // makes the caller see "verified". If we can't find one,
                    // fall through to the original and hope it succeeded.
                    chain.args.lastOrNull { it is List<*> } ?: chain.proceed()
                }
                any = true
            }
        }
        return any
    }

    // ------------------------------------------------------------------
    // 4. NetworkSecurityConfig layer
    // ------------------------------------------------------------------
    private fun hookNetworkSecurityTrustManager(module: XposedModule): Boolean {
        var any = false
        hookSafe(module, "ssl-pin NetworkSecurityTrustManager") {
            val cls = Class.forName("android.security.net.config.NetworkSecurityTrustManager")
            for (m in cls.declaredMethods) {
                when (m.name) {
                    "checkServerTrusted" -> {
                        m.isAccessible = true
                        module.hook(m).intercept { chain ->
                            if (SpoofState.reconOn) {
                                module.log(
                                    Log.INFO, TAG,
                                    "[PAS] ssl-pin: NetworkSecurityTrustManager.checkServerTrusted bypassed"
                                )
                            }
                            val chainArg = chain.args.firstOrNull { it is Array<*> }
                            @Suppress("UNCHECKED_CAST")
                            val certs = (chainArg as? Array<*>)?.filterIsInstance<java.security.cert.X509Certificate>()
                            if (!certs.isNullOrEmpty()) certs else chain.proceed()
                        }
                        any = true
                    }
                    "isSubdomain" -> {
                        m.isAccessible = true
                        module.hook(m).intercept { chain ->
                            val host = chain.args.firstOrNull { it is String } as? String
                            module.log(
                                Log.INFO, TAG,
                                "[PAS] ssl-pin: NetworkSecurityTrustManager.isSubdomain" +
                                    (host?.let { " host=$it" } ?: "") + " -> true"
                            )
                            true
                        }
                        any = true
                    }
                }
            }
        }
        return any
    }

    // ------------------------------------------------------------------
    // 5. Default HttpsURLConnection hostname verifier
    // ------------------------------------------------------------------
    private fun hookHttpsHostnameVerifier(module: XposedModule): Boolean {
        var any = false
        hookSafe(module, "ssl-pin default HostnameVerifier") {
            val cls = Class.forName("javax.net.ssl.HttpsURLConnection")
            val setDefault = cls.getMethod(
                "setDefaultHostnameVerifier",
                Class.forName("javax.net.ssl.HostnameVerifier")
            )
            setDefault.isAccessible = true
            module.hook(setDefault).intercept { chain ->
                module.log(Log.INFO, TAG, "[PAS] ssl-pin: setDefaultHostnameVerifier (accepted)")
                null
            }
            any = true
        }
        return any
    }

    // ------------------------------------------------------------------
    // 6. WebView SSL error handler
    // ------------------------------------------------------------------
    private fun hookWebViewSslHandler(module: XposedModule): Boolean {
        var any = false
        hookSafe(module, "ssl-pin SslErrorHandler.cancel->proceed") {
            val cls = Class.forName("android.webkit.SslErrorHandler")
            val cancel = cls.getDeclaredMethod("cancel")
            val proceed = cls.getDeclaredMethod("proceed")
            cancel.isAccessible = true
            proceed.isAccessible = true
            module.hook(cancel).intercept { chain ->
                module.log(Log.INFO, TAG, "[PAS] ssl-pin: WebView SslErrorHandler.cancel -> proceed")
                runCatching { proceed.invoke(chain.thisObject) }
                null
            }
            any = true
        }
        return any
    }
}