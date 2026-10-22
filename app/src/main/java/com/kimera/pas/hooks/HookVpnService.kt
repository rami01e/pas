package com.kimera.pas.hooks

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe

/**
 * v2.12.17 VPN DETECTION - VpnService.prepare(Context).
 *
 * prepare() returns null exactly when a VPN is already active. That is the
 * cheapest "is a VPN up?" probe on Android: it needs no permission, it is one
 * call, and it bypasses every ConnectivityManager / NetworkInterface / proc
 * spoof in this module. A null result is replaced with an empty non-null
 * Intent, i.e. "no VPN is running, consent would be needed".
 *
 * Caveat: a scoped VPN client that calls prepare() to reconnect would get the
 * dummy Intent instead of null. Do not scope the VPN app itself.
 */
class HookVpnService : XHook {

    override val targetKlass: String
        get() = "android.net.VpnService"

    override fun injectHook(module: XposedModule) {
        hookSafe(module, "VpnService.prepare") {
            val m = VpnService::class.java.getMethod("prepare", Context::class.java)
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                val result = chain.proceed()
                if (result == null) {
                    module.log(Log.INFO, TAG, "[PAS] VpnService.prepare null -> dummy Intent (VPN hidden)")
                    Intent()
                } else {
                    result
                }
            }
        }
    }
}
