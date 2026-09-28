package me.hoshino.novpndetect.hooks

import android.app.PendingIntent
import android.net.ConnectivityManager
import android.net.NetworkRequest
import android.os.Handler
import android.util.Log
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedHelpers
import me.hoshino.novpndetect.TAG
import me.hoshino.novpndetect.XHook

class HookConnectivityManager : XHook {

    override val targetKlass: String
        get() = "android.net.ConnectivityManager"

    override fun injectHook() {
        hookNetworkInfo()
        hookRequestNetwork()
        // TODO: will apps detect VPN from isVpnLockdownEnabled?
    }

    private fun hookNetworkInfo() {
        XposedHelpers.findAndHookMethod(ConnectivityManager::class.java, "getNetworkInfo", Int::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "ConnectivityManager.getNetworkInfo (${param.args[0]})")
                if (param.args[0] == ConnectivityManager.TYPE_VPN) {
                    param.result = null
                }
            }
        })
    }

    private fun hookRequestNetwork() {
        // For debug purposes only

        XposedHelpers.findAndHookMethod(ConnectivityManager::class.java, "requestNetwork", NetworkRequest::class.java, ConnectivityManager.NetworkCallback::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "ConnectivityManager.requestNetwork (${param.args[0]}, ${param.args[1]})")
            }
        })

        XposedHelpers.findAndHookMethod(ConnectivityManager::class.java, "requestNetwork", NetworkRequest::class.java, ConnectivityManager.NetworkCallback::class.java, Int::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "ConnectivityManager.requestNetwork (${param.args[0]}, ${param.args[1]}, ${param.args[2]})")
            }
        })

        XposedHelpers.findAndHookMethod(ConnectivityManager::class.java, "requestNetwork", NetworkRequest::class.java, ConnectivityManager.NetworkCallback::class.java, Handler::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "ConnectivityManager.requestNetwork (${param.args[0]}, ${param.args[1]}, ${param.args[2]})")
            }
        })

        XposedHelpers.findAndHookMethod(ConnectivityManager::class.java, "requestNetwork", NetworkRequest::class.java, PendingIntent::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "ConnectivityManager.requestNetwork (${param.args[0]}, ${param.args[1]})")
            }
        })

        XposedHelpers.findAndHookMethod(ConnectivityManager::class.java, "requestNetwork", NetworkRequest::class.java, ConnectivityManager.NetworkCallback::class.java, Handler::class.java, Int::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "ConnectivityManager.requestNetwork (${param.args[0]}, ${param.args[1]}, ${param.args[2]}, ${param.args[3]})")
            }
        })
    }
}