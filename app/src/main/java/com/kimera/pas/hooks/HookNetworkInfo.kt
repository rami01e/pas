package com.kimera.pas.hooks

import android.net.ConnectivityManager
import android.net.NetworkInfo
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState

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
                if (SpoofState.netCellular &&
                    (result == ConnectivityManager.TYPE_WIFI || result == ConnectivityManager.TYPE_VPN)
                ) {
                    if (SpoofState.reconOn) {
                        module.log(Log.INFO, TAG, "NetworkInfo.getType() $result -> TYPE_MOBILE (cellular spoof)")
                    }
                    return@intercept ConnectivityManager.TYPE_MOBILE
                }
                module.log(Log.INFO, TAG, "NetworkInfo.getType() -> $result")
                if (result == ConnectivityManager.TYPE_VPN) ConnectivityManager.TYPE_WIFI else result
            }
        }

        hookSafe(module, "NetworkInfo.getSubtype") {
            val method = NetworkInfo::class.java.getMethod("getSubtype")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                if (SpoofState.netCellular &&
                    (result == ConnectivityManager.TYPE_WIFI || result == ConnectivityManager.TYPE_VPN || result <= 0)
                ) {
                    if (SpoofState.reconOn) {
                        module.log(Log.INFO, TAG, "NetworkInfo.getSubtype() $result -> LTE (cellular spoof)")
                    }
                    return@intercept android.telephony.TelephonyManager.NETWORK_TYPE_LTE
                }
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
                if (SpoofState.netCellular && result is String &&
                    (result.contains("WIFI", true) || result.contains("VPN", true))
                ) {
                    if (SpoofState.reconOn) {
                        module.log(Log.INFO, TAG, "NetworkInfo.getTypeName() $result -> LTE (cellular spoof)")
                    }
                    return@intercept "LTE"
                }
                module.log(Log.INFO, TAG, "NetworkInfo.getTypeName() -> $result")
                if (result is String && result.contains("VPN", ignoreCase = true)) "WIFI" else result
            }
        }

        hookSafe(module, "NetworkInfo.getSubtypeName") {
            val method = NetworkInfo::class.java.getMethod("getSubtypeName")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                if (SpoofState.netCellular && result is String &&
                    (result.isBlank() || result.contains("WIFI", true) || result.contains("VPN", true))
                ) {
                    if (SpoofState.reconOn) {
                        module.log(Log.INFO, TAG, "NetworkInfo.getSubtypeName() '$result' -> LTE (cellular spoof)")
                    }
                    return@intercept "LTE"
                }
                module.log(Log.INFO, TAG, "NetworkInfo.getSubtypeName() -> $result")
                if (result is String && result.contains("VPN", ignoreCase = true)) "WIFI" else result
            }
        }
    }
}
