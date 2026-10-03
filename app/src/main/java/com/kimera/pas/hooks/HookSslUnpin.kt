package com.kimera.pas.hooks

import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * SSL unpinning (per-app). Gate: SpoofState.sslUnpinMode
 *   0 = OFF, 1 = JAVA only, 2 = NATIVE only, 3 = BOTH
 *
 * v2.3.5 adds the SSLContext.init hook - apps that install their own
 * X509TrustManager (common in games with cert pinning) bypass every other
 * Java surface, because they never call the framework's default trust
 * manager. Swapping the TM array for a permissive one covers that vector.
 *
 * Surfaces installed (mode 1 or 3):
 *   1. okhttp3.CertificatePinner.check                 (+ check$okhttp)
 *   2. okhttp3.internal.tls.OkHostnameVerifier.verify
 *   3. com.android.org.conscrypt.TrustManagerImpl      (checkTrustedRecursive, verifyChain)
 *   4. android.security.net.config.NetworkSecurityTrustManager
 *   5. javax.net.ssl.HttpsURLConnection setDefaultHostnameVerifier
 *   6. android.webkit.SslErrorHandler.cancel -> proceed
 *   7. javax.net.ssl.SSLContext.init(KeyManager[], TrustManager[], SecureRandom)  [NEW]
 *   8. javax.net.ssl.SSLContext.init(KeyManager[], TrustManager[])                [NEW]
 *
 * Every interception logs "ssl-pin: ..." (visible in Diagnose).
 */
class HookSslUnpin : XHook {

    override val targetKlass: String
        get() = "okhttp3.CertificatePinner"

    /** Permissive trust manager: accepts every chain. Installed into every
     *  app SSLContext via the init hook below. */
    private val permissiveTm: X509TrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

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
        if (hookSslContextInit(module)) count++

        module.log(
            Log.INFO, TAG,
            "[PAS] ssl unpin: java surfaces installed ($count/7) mode=$mode"
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
    // 3. Conscrypt TrustManagerImpl
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
                            val certs = (chainArg as? Array<*>)?.filterIsInstance<X509Certificate>()
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

    // ------------------------------------------------------------------
    // 7+8. SSLContext.init - swap the trust manager array for a permissive one
    //
    // Apps with their own pinning often build an SSLContext with a custom
    // X509TrustManager so the framework's default trust manager (hooked by
    // #3 / #4) never sees the check. This hook replaces the trust manager
    // array argument on every SSLContext.init call the app makes, which
    // catches that class of pinning at the source.
    // ------------------------------------------------------------------
    private fun hookSslContextInit(module: XposedModule): Boolean {
        var any = false

        hookSafe(module, "ssl-pin SSLContext.init(3arg)") {
            val cls = SSLContext::class.java
            val init3 = cls.getDeclaredMethod(
                "init",
                Array<KeyManager>::class.java,
                Array<TrustManager>::class.java,
                SecureRandom::class.java
            )
            init3.isAccessible = true
            module.hook(init3).intercept { chain ->
                module.log(
                    Log.INFO, TAG,
                    "[PAS] ssl-pin: SSLContext.init(3arg) -> permissive TrustManager"
                )
                val km = chain.args.getOrNull(0)
                val sr = chain.args.getOrNull(2) as? SecureRandom ?: SecureRandom()
                try {
                    chain.proceed(arrayOf(km, arrayOf<TrustManager>(permissiveTm), sr))
                } catch (t: Throwable) {
                    module.log(Log.INFO, TAG, "[PAS] ssl-pin: init(3arg) proceed failed: $t")
                    chain.proceed()
                }
            }
            any = true
        }

        hookSafe(module, "ssl-pin SSLContext.init(2arg)") {
            val cls = SSLContext::class.java
            val init2 = runCatching {
                cls.getDeclaredMethod(
                    "init",
                    Array<KeyManager>::class.java,
                    Array<TrustManager>::class.java
                )
            }.getOrNull()
            if (init2 != null) {
                init2.isAccessible = true
                module.hook(init2).intercept { chain ->
                    module.log(
                        Log.INFO, TAG,
                        "[PAS] ssl-pin: SSLContext.init(2arg) -> permissive TrustManager"
                    )
                    val km = chain.args.getOrNull(0)
                    try {
                        chain.proceed(arrayOf(km, arrayOf<TrustManager>(permissiveTm)))
                    } catch (t: Throwable) {
                        module.log(Log.INFO, TAG, "[PAS] ssl-pin: init(2arg) proceed failed: $t")
                        chain.proceed()
                    }
                }
                any = true
            }
        }

        return any
    }
}