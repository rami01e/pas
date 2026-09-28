package me.hoshino.novpndetect.hooks

import android.app.PendingIntent
import android.net.ConnectivityManager
import android.net.NetworkRequest
import android.os.Handler
import android.util.Log
import io.github.libxposed.api.XposedModule
import me.hoshino.novpndetect.TAG
import me.hoshino.novpndetect.XHook
import me.hoshino.novpndetect.hookSafe

class HookConnectivityManager : XHook {

    override val targetKlass: String
        get() = "android.net.ConnectivityManager"

    override fun injectHook(module: XposedModule) {
        hookNetworkInfo(module)
        hookRequestNetwork(module)
        // TODO: will apps detect VPN from isVpnLockdownEnabled?
    }

    private fun hookNetworkInfo(module: XposedModule) {
        hookSafe(module, "ConnectivityManager.getNetworkInfo") {
            val method = ConnectivityManager::class.java.getMethod("getNetworkInfo", java.lang.Integer.TYPE)
            module.hook(method).intercept { chain ->
                val type = chain.getArg(0)
                module.log(Log.INFO, TAG, "ConnectivityManager.getNetworkInfo ($type)")
                if (type == ConnectivityManager.TYPE_VPN) null else chain.proceed()
            }
        }
    }

    private fun hookRequestNetwork(module: XposedModule) {
        // For debug purposes only
        val cm = ConnectivityManager::class.java
        val request = NetworkRequest::class.java
        val callback = ConnectivityManager.NetworkCallback::class.java

        hookSafe(module, "ConnectivityManager.requestNetwork(NetworkRequest, NetworkCallback)") {
            val method = cm.getMethod("requestNetwork", request, callback)
            module.hook(method).intercept { chain ->
                module.log(Log.INFO, TAG, "ConnectivityManager.requestNetwork (${chain.getArg(0)}, ${chain.getArg(1)})")
                chain.proceed()
            }
        }

        hookSafe(module, "ConnectivityManager.requestNetwork(NetworkRequest, NetworkCallback, int)") {
            val method = cm.getMethod("requestNetwork", request, callback, java.lang.Integer.TYPE)
            module.hook(method).intercept { chain ->
                module.log(Log.INFO, TAG, "ConnectivityManager.requestNetwork (${chain.getArg(0)}, ${chain.getArg(1)}, ${chain.getArg(2)})")
                chain.proceed()
            }
        }

        hookSafe(module, "ConnectivityManager.requestNetwork(NetworkRequest, NetworkCallback, Handler)") {
            val method = cm.getMethod("requestNetwork", request, callback, Handler::class.java)
            module.hook(method).intercept { chain ->
                module.log(Log.INFO, TAG, "ConnectivityManager.requestNetwork (${chain.getArg(0)}, ${chain.getArg(1)}, ${chain.getArg(2)})")
                chain.proceed()
            }
        }

        hookSafe(module, "ConnectivityManager.requestNetwork(NetworkRequest, PendingIntent)") {
            val method = cm.getMethod("requestNetwork", request, PendingIntent::class.java)
            module.hook(method).intercept { chain ->
                module.log(Log.INFO, TAG, "ConnectivityManager.requestNetwork (${chain.getArg(0)}, ${chain.getArg(1)})")
                chain.proceed()
            }
        }

        hookSafe(module, "ConnectivityManager.requestNetwork(NetworkRequest, NetworkCallback, Handler, int)") {
            val method = cm.getMethod("requestNetwork", request, callback, Handler::class.java, java.lang.Integer.TYPE)
            module.hook(method).intercept { chain ->
                module.log(Log.INFO, TAG, "ConnectivityManager.requestNetwork (${chain.getArg(0)}, ${chain.getArg(1)}, ${chain.getArg(2)}, ${chain.getArg(3)})")
                chain.proceed()
            }
        }
    }
}
