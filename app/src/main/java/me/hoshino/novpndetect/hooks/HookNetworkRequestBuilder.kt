package me.hoshino.novpndetect.hooks

import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedHelpers
import me.hoshino.novpndetect.TAG
import me.hoshino.novpndetect.XHook

class HookNetworkRequestBuilder : XHook {

    override val targetKlass: String
        get() = "android.net.NetworkRequest.Builder"

    override fun injectHook() {
        hookAddCapability()
        hookAddTransportType()
    }

    private fun hookAddCapability() {
        XposedHelpers.findAndHookMethod(NetworkRequest.Builder::class.java, "addCapability", Int::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "NetworkRequest.Builder.addCapability(${param.args[0]})")
                if (param.args[0] == NetworkCapabilities.NET_CAPABILITY_NOT_VPN) {
                    param.result = param.thisObject
                }
            }
        })
    }

    private fun hookAddTransportType() {
        XposedHelpers.findAndHookMethod(NetworkRequest.Builder::class.java, "addTransportType", Int::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "NetworkRequest.Builder.addTransportType(${param.args[0]})")
                if (param.args[0] != NetworkCapabilities.TRANSPORT_VPN) {
                    (param.thisObject as NetworkRequest.Builder).addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                }
            }
        })
    }
}