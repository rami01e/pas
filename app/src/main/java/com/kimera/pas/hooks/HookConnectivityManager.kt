package com.kimera.pas.hooks

import android.app.PendingIntent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import android.os.Handler
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState

class HookConnectivityManager : XHook {

    override val targetKlass: String
        get() = "android.net.ConnectivityManager"

    override fun injectHook(module: XposedModule) {
        hookNetworkInfo(module)
        hookRequestNetwork(module)
        hookEnumeration(module)
        // TODO: will apps detect VPN from isVpnLockdownEnabled?
    }

    /** Recon: log-only pass-throughs around the network enumeration paths. */
    private fun hookEnumeration(module: XposedModule) {
        hookSafe(module, "ConnectivityManager.getActiveNetwork") {
            val method = ConnectivityManager::class.java.getMethod("getActiveNetwork")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                if (SpoofState.reconOn) {
                    module.log(Log.INFO, TAG, "ConnectivityManager.getActiveNetwork -> $result")
                }
                result
            }
        }
        hookSafe(module, "ConnectivityManager.getAllNetworks") {
            val method = ConnectivityManager::class.java.getMethod("getAllNetworks")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                if (SpoofState.reconOn) {
                    val arr = result as? Array<*>
                    val names = arr?.take(8)?.joinToString { it.toString() } ?: "?"
                    module.log(Log.INFO, TAG, "ConnectivityManager.getAllNetworks -> ${arr?.size ?: 0}: $names")
                }
                result
            }
        }
        hookSafe(module, "ConnectivityManager.getNetworkCapabilities") {
            val method = ConnectivityManager::class.java.getMethod(
                "getNetworkCapabilities", Network::class.java
            )
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                if (SpoofState.reconOn) {
                    module.log(Log.INFO, TAG, "ConnectivityManager.getNetworkCapabilities -> $result")
                }
                result
            }
        }
        hookSafe(module, "ConnectivityManager.getLinkProperties") {
            runCatching {
                ConnectivityManager::class.java.getMethod("getLinkProperties", Network::class.java)
            }.getOrNull()?.let { m ->
                module.hook(m).intercept { chain ->
                    val r = chain.proceed()
                    if (SpoofState.reconOn) {
                        module.log(Log.INFO, TAG, "ConnectivityManager.getLinkProperties(${chain.getArg(0)}) -> $r")
                    }
                    r
                }
            }
        }
        hookSafe(module, "ConnectivityManager.getNetworkInfo(Network)") {
            val m = ConnectivityManager::class.java.getMethod("getNetworkInfo", Network::class.java)
            module.hook(m).intercept { chain ->
                val r = chain.proceed()
                if (SpoofState.reconOn) {
                    module.log(Log.INFO, TAG, "ConnectivityManager.getNetworkInfo(${chain.getArg(0)}) -> $r")
                }
                r
            }
        }
        hookSafe(module, "ConnectivityManager.getActiveNetworkInfo") {
            val m = ConnectivityManager::class.java.getMethod("getActiveNetworkInfo")
            module.hook(m).intercept { chain ->
                val r = chain.proceed()
                if (SpoofState.reconOn) {
                    module.log(Log.INFO, TAG, "ConnectivityManager.getActiveNetworkInfo -> $r")
                }
                r
            }
        }
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
