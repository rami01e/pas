package com.kimera.novpndetect.hooks

import android.net.ConnectivityManager
import android.net.NetworkInfo
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.novpndetect.TAG
import com.kimera.novpndetect.XHook
import com.kimera.novpndetect.hookSafe

class HookNetworkInfo : XHook {

    override val targetKlass: String
        get() = "android.net.NetworkInfo"

    override fun injectHook(module: XposedModule) {
        hookGetType(module)
        hookGetTypeName(module)
        // hookIsConnected(module) // TODO: find a better way to patch https://stackoverflow.com/a/43967558/16676567
    }

    private fun hookGetType(module: XposedModule) {
        hookSafe(module, "NetworkInfo.getType") {
            val method = NetworkInfo::class.java.getMethod("getType")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                module.log(Log.INFO, TAG, "NetworkInfo.getType() -> $result")
                if (result == ConnectivityManager.TYPE_VPN) ConnectivityManager.TYPE_WIFI else result
            }
        }

        hookSafe(module, "NetworkInfo.getSubtype") {
            val method = NetworkInfo::class.java.getMethod("getSubtype")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                module.log(Log.INFO, TAG, "NetworkInfo.getSubtype() -> $result")
                if (result == ConnectivityManager.TYPE_VPN) ConnectivityManager.TYPE_WIFI else result
            }
        }
    }

    private fun hookGetTypeName(module: XposedModule) {
        hookSafe(module, "NetworkInfo.getTypeName") {
            val method = NetworkInfo::class.java.getMethod("getTypeName")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                module.log(Log.INFO, TAG, "NetworkInfo.getTypeName() -> $result")
                if (result is String && result.contains("VPN", ignoreCase = true)) "WIFI" else result
            }
        }

        hookSafe(module, "NetworkInfo.getSubtypeName") {
            val method = NetworkInfo::class.java.getMethod("getSubtypeName")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                module.log(Log.INFO, TAG, "NetworkInfo.getSubtypeName() -> $result")
                if (result is String && result.contains("VPN", ignoreCase = true)) "WIFI" else result
            }
        }
    }
}
