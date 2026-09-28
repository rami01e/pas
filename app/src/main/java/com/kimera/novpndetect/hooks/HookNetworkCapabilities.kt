package com.kimera.novpndetect.hooks

import android.net.NetworkCapabilities
import android.util.Log
import io.github.libxposed.api.XposedModule
import java.net.NetworkInterface
import kotlin.collections.iterator
import com.kimera.novpndetect.TAG
import com.kimera.novpndetect.XHook
import com.kimera.novpndetect.hookSafe

class HookNetworkCapabilities : XHook {

    override val targetKlass: String
        get() = "android.os.NetworkCapabilities"

    override fun injectHook(module: XposedModule) {
        hookHasTransport(module)
        hookGetCapabilities(module)
        hookHasCapability(module)
    }

    private fun hookHasTransport(module: XposedModule) {
        hookSafe(module, "NetworkCapabilities.hasTransport") {
            val method = NetworkCapabilities::class.java.getMethod("hasTransport", java.lang.Integer.TYPE)
            module.hook(method).intercept { chain ->
                val transport = chain.getArg(0)
                module.log(Log.INFO, TAG, "NetworkCapabilities.hasTransport($transport)")

                var probablyTransport = NetworkCapabilities.TRANSPORT_WIFI
                val interfaces = NetworkInterface.getNetworkInterfaces()
                if (interfaces != null) {
                    for (iface in interfaces) {
                        if (!iface.isUp || iface.isLoopback)
                            continue

                        if (iface.name.contains("wlan")) {
                            probablyTransport = NetworkCapabilities.TRANSPORT_WIFI
                            break
                        } else if (iface.name.contains("rmnet_data")) {
                            probablyTransport = NetworkCapabilities.TRANSPORT_CELLULAR
                            break
                        } else if (iface.name.contains("eth")) {
                            probablyTransport = NetworkCapabilities.TRANSPORT_ETHERNET
                            break
                        }
                    }
                }

                val forced: Boolean? =
                    when {
                        transport == NetworkCapabilities.TRANSPORT_VPN -> false
                        transport == probablyTransport -> true
                        else -> null
                    }
                val result = forced ?: chain.proceed()
                module.log(Log.INFO, TAG, "NetworkCapabilities.hasTransport($transport) -> $result")
                result
            }
        }
    }

    private fun hookGetCapabilities(module: XposedModule) {
        hookSafe(module, "NetworkCapabilities.getCapabilities") {
            val method = NetworkCapabilities::class.java.getMethod("getCapabilities")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                module.log(Log.INFO, TAG, "NetworkCapabilities.getCapabilities() -> $result")
                if (result !is IntArray || result.contains(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                    result
                } else {
                    val newResult = IntArray(result.size + 1)
                    result.forEachIndexed { index, i -> newResult[index] = i }
                    newResult[newResult.size - 1] = NetworkCapabilities.NET_CAPABILITY_NOT_VPN
                    newResult
                }
            }
        }
    }

    private fun hookHasCapability(module: XposedModule) {
        hookSafe(module, "NetworkCapabilities.hasCapability") {
            val method = NetworkCapabilities::class.java.getMethod("hasCapability", java.lang.Integer.TYPE)
            module.hook(method).intercept { chain ->
                val capability = chain.getArg(0)
                module.log(Log.INFO, TAG, "NetworkCapabilities.hasCapability($capability)")
                val forced: Boolean? =
                    when {
                        capability == NetworkCapabilities.NET_CAPABILITY_NOT_VPN -> true
                        capability == NetworkCapabilities.NET_CAPABILITY_INTERNET -> true
                        capability == NetworkCapabilities.NET_CAPABILITY_VALIDATED -> true
                        else -> null
                    }
                val result = forced ?: chain.proceed()
                module.log(Log.INFO, TAG, "NetworkCapabilities.hasCapability($capability) -> $result")
                result
            }
        }
    }
}
