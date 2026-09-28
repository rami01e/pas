package me.hoshino.novpndetect.hooks

import android.net.ConnectivityManager
import android.net.NetworkInfo
import android.util.Log
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedHelpers
import me.hoshino.novpndetect.TAG
import me.hoshino.novpndetect.XHook

class HookNetworkInfo : XHook {

    override val targetKlass: String
        get() = "android.net.NetworkInfo"

    override fun injectHook() {
        hookGetType()
        hookGetTypeName()
//        hookIsConnected()
    }

    private fun hookGetType() {
        XposedHelpers.findAndHookMethod(NetworkInfo::class.java, "getType", object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "NetworkInfo.getType() -> ${param.result}")
                if (param.result == ConnectivityManager.TYPE_VPN) {
                    param.result = ConnectivityManager.TYPE_WIFI
                }
            }
        })
        XposedHelpers.findAndHookMethod(NetworkInfo::class.java, "getSubtype", object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "NetworkInfo.getSubtype() -> ${param.result}")
                if (param.result == ConnectivityManager.TYPE_VPN) {
                    param.result = ConnectivityManager.TYPE_WIFI
                }
            }
        })
    }

    private fun hookGetTypeName() {
        XposedHelpers.findAndHookMethod(NetworkInfo::class.java, "getTypeName", object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "NetworkInfo.getTypeName() -> ${param.result}")
                val res = param.result
                if (res is String && res.contains("VPN", ignoreCase = true)) {
                    param.result = "WIFI"
                }
            }
        })
        XposedHelpers.findAndHookMethod(NetworkInfo::class.java, "getSubtypeName", object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "NetworkInfo.getSubtypeName() -> ${param.result}")
                val res = param.result
                if (res is String && res.contains("VPN", ignoreCase = true)) {
                    param.result = "WIFI"
                }
            }
        })
    }

    private fun hookIsConnected() {
        // TODO: find a better way to patch https://stackoverflow.com/a/43967558/16676567
        XposedHelpers.findAndHookMethod(NetworkInfo::class.java, "isConnected", object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "NetworkInfo.isConnected (${param.result})")
                param.result = false
            }
        })
        XposedHelpers.findAndHookMethod(NetworkInfo::class.java, "isConnectedOrConnecting", object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "NetworkInfo.isConnectedOrConnecting (${param.result})")
                param.result = false
            }
        })
    }
}