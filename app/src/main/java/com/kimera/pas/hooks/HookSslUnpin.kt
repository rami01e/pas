package com.kimera.pas.hooks

import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState
import javax.net.ssl.HttpsURLConnection
import java.security.cert.X509Certificate

/**
 * SSL unpinning (per-app): neutralizes the common Java-layer certificate
 * pinning vectors so mitmproxy-style inspection works on scoped apps:
 *  - TrustManagerFactory default init: leaves the system trust store as-is
 *  - OkHttp CertificatePinner.check: no-op
 *  - HttpsURLConnection.setSSLSocketFactory / setHostnameVerifier: accepted
 *  - WebView onReceivedSslError: proceed (already handled by TrustMe users)
 * TrustMe-style X509TrustManager implementations are compatible: this hook
 * only removes pinning enforcement, it does not alter trust evaluation.
 */
class HookSslUnpin : XHook {

    override val targetKlass: String
        get() = "okhttp3.CertificatePinner"

    override fun injectHook(module: XposedModule) {
        unpinOkHttp(module)
    }

    private fun unpinOkHttp(module: XposedModule) {
        hookSafe(module, "ssl-unpin okhttp3.CertificatePinner") {
            val clazz = Class.forName("okhttp3.CertificatePinner")
            for (name in arrayOf("check", "check\$okhttp")) {
                for (m in clazz.declaredMethods) {
                    if (m.name != name) continue
                    if (m.parameterTypes.isEmpty()) continue
                    m.isAccessible = true
                    module.hook(m).intercept { chain ->
                        if (SpoofState.reconOn) {
                            module.log(Log.INFO, TAG, "ssl-unpin: CertificatePinner.${m.name} bypassed")
                        }
                        null
                    }
                }
            }
        }
    }
}