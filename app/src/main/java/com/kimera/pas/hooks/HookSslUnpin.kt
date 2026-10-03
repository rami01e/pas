package com.kimera.pas.hooks

import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState
import java.security.cert.X509Certificate

/**
 * SSL unpinning + TLS verdict trace (per-app), replacing the earlier
 * frida-inject plan: the module is already injected into scoped apps from
 * process spawn, so the verdict logging runs in-process with no external
 * daemon. While Recon (DEBUG master) is on, every Java-layer TLS decision is
 * mirrored into the module log:
 *  - TrustManagerImpl (checkTrusted family and verifyChain): hostname + verdict
 *  - platform X509TrustManagerImpl.checkServerTrusted: chain errors
 *  - OkHostnameVerifier.verify: hostname verdict
 *  - okhttp3.CertificatePinner.check / check$okhttp: BYPASSED (unpin)
 *  - HttpsURLConnection SSLSocketFactory/HostnameVerifier: accepted
 *  - WebViewClient.onReceivedSslError: proceed + primaryError
 * All hooks pass calls through unmodified except CertificatePinner (no-op)
 * and onReceivedSslError (proceed). A game that rejects the mitmproxy chain
 * then shows exactly which stage rejected it, with the failing host.
 */
class HookSslUnpin : XHook {

    override val targetKlass: String
        get() = "okhttp3.CertificatePinner"

    override fun injectHook(module: XposedModule) {
        unpinOkHttp(module)
        traceHostnameVerifier(module)
        traceTrustManagerImpl(module)
        tracePlatformTrustManager(module)
        traceHttpsUrlConnection(module)
        traceWebViewSslError(module)
    }

    private fun logTls(module: XposedModule, tag: String, msg: String) {
        if (SpoofState.reconOn) {
            module.log(Log.INFO, TAG, "[PAS] tls/$tag: $msg")
        }
    }

    /** okhttp pinning: bypass (existing behavior) + per-host trace. */
    private fun unpinOkHttp(module: XposedModule) {
        hookSafe(module, "ssl-unpin okhttp3.CertificatePinner") {
            val clazz = Class.forName("okhttp3.CertificatePinner")
            for (name in arrayOf("check", "check\$okhttp")) {
                for (m in clazz.declaredMethods) {
                    if (m.name != name) continue
                    if (m.parameterTypes.isEmpty()) continue
                    m.isAccessible = true
                    module.hook(m).intercept { chain ->
                        val host = (chain.getArg(0) as? String) ?: "?"
                        logTls(module, "okhttp-pins", "host=$host -> BYPASSED")
                        null
                    }
                }
            }
        }
    }

    /** Conscrypt TrustManagerImpl: the real trust verdict for most stacks. */
    private fun traceTrustManagerImpl(module: XposedModule) {
        hookSafe(module, "tls trace TrustManagerImpl") {
            val clazz = Class.forName("com.android.org.conscrypt.TrustManagerImpl")
            for (m in clazz.declaredMethods) {
                if (m.name != "checkTrusted" && m.name != "verifyChain") continue
                m.isAccessible = true
                val kind = m.name
                module.hook(m).intercept { chain ->
                    val host = chain.args.firstOrNull { it is String } as? String ?: "?"
                    return@intercept try {
                        val r = chain.proceed()
                        logTls(module, "tmimpl", "$kind host=$host -> TRUSTED")
                        r
                    } catch (t: Throwable) {
                        logTls(module, "tmimpl", "$kind host=$host -> REJECTED: ${t.javaClass.simpleName}: ${t.message}")
                        throw t
                    }
                }
            }
        }
    }

    /** Platform default TM: surfaces raw chain validation errors. */
    private fun tracePlatformTrustManager(module: XposedModule) {
        hookSafe(module, "tls trace X509TrustManagerImpl") {
            val clazz = Class.forName("com.android.org.bouncycastle.jsse.provider.X509TrustManagerImpl")
            for (m in clazz.declaredMethods) {
                if (m.name != "checkServerTrusted") continue
                m.isAccessible = true
                module.hook(m).intercept { chain ->
                    val certs = (chain.getArg(0) as? Array<X509Certificate>)
                    val subj = certs?.firstOrNull()?.subjectDN?.toString() ?: "?"
                    return@intercept try {
                        val r = chain.proceed()
                        logTls(module, "platform-tm", "checkServerTrusted leaf=$subj -> TRUSTED")
                        r
                    } catch (t: Throwable) {
                        logTls(module, "platform-tm", "checkServerTrusted leaf=$subj -> REJECTED: ${t.javaClass.simpleName}: ${t.message}")
                        throw t
                    }
                }
            }
        }
    }

    /** OkHttp hostname verification (also used by conscrypt callers). */
    private fun traceHostnameVerifier(module: XposedModule) {
        hookSafe(module, "tls trace OkHostnameVerifier") {
            val clazz = Class.forName("com.android.okhttp.internal.tls.OkHostnameVerifier")
            for (m in clazz.declaredMethods) {
                if (m.name != "verify") continue
                m.isAccessible = true
                module.hook(m).intercept { chain ->
                    val host = (chain.getArg(0) as? String) ?: "?"
                    val r = chain.proceed()
                    logTls(module, "hostname", "verify host=$host -> $r")
                    r
                }
            }
        }
    }

    /** HttpsURLConnection defaults: accept whatever the app sets. */
    private fun traceHttpsUrlConnection(module: XposedModule) {
        hookSafe(module, "ssl-unpin HttpsURLConnection") {
            val clazz = HttpsURLConnection::class.java
            for (name in arrayOf("setSSLSocketFactory", "setHostnameVerifier", "setDefaultSSLSocketFactory", "setDefaultHostnameVerifier")) {
                for (m in clazz.declaredMethods) {
                    if (m.name != name) continue
                    m.isAccessible = true
                    module.hook(m).intercept { chain ->
                        logTls(module, "hc", "$name called")
                        chain.proceed()
                    }
                }
            }
        }
    }

    /** WebView TLS errors: proceed (unpin) + record the primary error code. */
    private fun traceWebViewSslError(module: XposedModule) {
        hookSafe(module, "ssl-unpin WebViewClient.onReceivedSslError") {
            val clazz = Class.forName("android.webkit.WebViewClient")
            for (m in clazz.declaredMethods) {
                if (m.name != "onReceivedSslError") continue
                m.isAccessible = true
                module.hook(m).intercept { chain ->
                    val err = chain.args.getOrNull(2)
                    val primary = try {
                        err?.javaClass?.getMethod("getPrimaryError")?.invoke(err)
                    } catch (_: Throwable) {
                        null
                    }
                    logTls(module, "webview-ssl", "onReceivedSslError primaryError=$primary -> proceed")
                    try {
                        val handler = chain.args.getOrNull(1)
                        handler?.javaClass?.getMethod("proceed")?.invoke(handler)
                    } catch (_: Throwable) {
                    }
                    null
                }
            }
        }
    }
}
