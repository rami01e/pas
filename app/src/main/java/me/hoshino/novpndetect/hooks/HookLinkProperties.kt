package me.hoshino.novpndetect.hooks

import android.net.LinkProperties
import android.util.Log
import io.github.libxposed.api.XposedModule
import java.net.NetworkInterface
import kotlin.collections.iterator
import me.hoshino.novpndetect.TAG
import me.hoshino.novpndetect.XHook
import me.hoshino.novpndetect.hookSafe

class HookLinkProperties : XHook {

    override val targetKlass: String
        get() = "android.net.LinkProperties"

    override fun injectHook(module: XposedModule) {
        hookGetInterfaceName(module)
    }

    private fun hookGetInterfaceName(module: XposedModule) {
        hookSafe(module, "LinkProperties.getInterfaceName") {
            val method = LinkProperties::class.java.getMethod("getInterfaceName")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                module.log(Log.INFO, TAG, "$targetKlass.getInterfaceName () -> $result")
                if (result is String && result.startsWith("tun")) {
                    var replacement: String? = null
                    val interfaces = NetworkInterface.getNetworkInterfaces()
                    if (interfaces != null) {
                        for (iface in interfaces) {
                            if (!iface.isUp || iface.isLoopback)
                                continue

                            if (
                                iface.name.contains("wlan")
                                || iface.name.contains("rmnet_data")
                                || iface.name.contains("eth")
                            ) {
                                replacement = iface.name
                                break
                            }
                        }
                    }
                    replacement ?: "wlan0"
                } else {
                    result
                }
            }
        }
    }
}
