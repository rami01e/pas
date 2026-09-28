package me.hoshino.novpndetect.hooks

import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import io.github.libxposed.api.XposedModule
import me.hoshino.novpndetect.TAG
import me.hoshino.novpndetect.XHook
import me.hoshino.novpndetect.hookSafe

class HookNetworkRequestBuilder : XHook {

    override val targetKlass: String
        get() = "android.net.NetworkRequest.Builder"

    override fun injectHook(module: XposedModule) {
        hookAddCapability(module)
        hookAddTransportType(module)
    }

    private fun hookAddCapability(module: XposedModule) {
        hookSafe(module, "NetworkRequest.Builder.addCapability") {
            val method = NetworkRequest.Builder::class.java.getMethod("addCapability", java.lang.Integer.TYPE)
            module.hook(method).intercept { chain ->
                val capability = chain.getArg(0)
                module.log(Log.INFO, TAG, "NetworkRequest.Builder.addCapability($capability)")
                if (capability == NetworkCapabilities.NET_CAPABILITY_NOT_VPN) chain.getThisObject() else chain.proceed()
            }
        }
    }

    private fun hookAddTransportType(module: XposedModule) {
        hookSafe(module, "NetworkRequest.Builder.addTransportType") {
            val method = NetworkRequest.Builder::class.java.getMethod("addTransportType", java.lang.Integer.TYPE)
            module.hook(method).intercept { chain ->
                val transportType = chain.getArg(0)
                module.log(Log.INFO, TAG, "NetworkRequest.Builder.addTransportType($transportType)")
                if (transportType != NetworkCapabilities.TRANSPORT_VPN) {
                    (chain.getThisObject() as NetworkRequest.Builder).addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                }
                chain.proceed()
            }
        }
    }
}
