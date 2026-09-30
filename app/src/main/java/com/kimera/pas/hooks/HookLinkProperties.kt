package com.kimera.pas.hooks

import android.net.LinkProperties
import android.util.Log
import io.github.libxposed.api.XposedModule
import java.net.InetAddress
import java.net.NetworkInterface
import kotlin.collections.iterator
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState

class HookLinkProperties : XHook {

    private val vpnInterfacePattern = Regex(
        "^(tun\\d+|tap\\d+|wg\\d+|ppp\\d+|pptp.*|utun\\d*|zt.*|tailscale\\d*|svpn\\d*|gre\\d+|l2tp\\d+|he-ipv6.*|ipsec.*|xfrm.*)$"
    )

    private val routeInterfaceMethod by lazy {
        runCatching { Class.forName("android.net.RouteInfo").getMethod("getInterface") }.getOrNull()
    }

    override val targetKlass: String
        get() = "android.net.LinkProperties"

    override fun injectHook(module: XposedModule) {
        hookGetInterfaceName(module)
        hookGetRoutes(module)
        hookGetDnsServers(module)
        hookGetLinkAddresses(module)
    }

    private fun hookGetInterfaceName(module: XposedModule) {
        hookSafe(module, "LinkProperties.getInterfaceName") {
            val method = LinkProperties::class.java.getMethod("getInterfaceName")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                module.log(Log.INFO, TAG, "$targetKlass.getInterfaceName () -> $result")
                if (result is String && vpnInterfacePattern.matches(result)) {
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

    /** Recon: log-only pass-through so captures show which addresses apps read. */
    private fun hookGetLinkAddresses(module: XposedModule) {
        hookSafe(module, "LinkProperties.getLinkAddresses") {
            val method = LinkProperties::class.java.getMethod("getLinkAddresses")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                if (SpoofState.reconOn) {
                    val list = (result as? List<*>)?.joinToString { it.toString() } ?: "?"
                    module.log(Log.INFO, TAG, "LinkProperties.getLinkAddresses -> [$list]")
                }
                result
            }
        }
    }

    private fun hookGetRoutes(module: XposedModule) {
        hookSafe(module, "LinkProperties.getRoutes") {
            val method = LinkProperties::class.java.getMethod("getRoutes")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                val routes = result as? List<*>
                if (routes == null) {
                    result
                } else {
                    routes.filter { route ->
                        val iface = routeInterfaceMethod?.let { m ->
                            runCatching { m.invoke(route) as? String }.getOrNull()
                        }
                        iface == null || !vpnInterfacePattern.matches(iface)
                    }
                }
            }
        }
    }

    private fun hookGetDnsServers(module: XposedModule) {
        hookSafe(module, "LinkProperties.getDnsServers") {
            val method = LinkProperties::class.java.getMethod("getDnsServers")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                val servers = result as? List<*>
                if (servers == null) {
                    result
                } else {
                    servers.map { address ->
                        val inet = address as? InetAddress
                        if (inet != null && isPrivateDnsAddress(inet)) PUBLIC_DNS else address
                    }
                }
            }
        }
    }

    private fun isPrivateDnsAddress(address: InetAddress): Boolean {
        if (address.isLoopbackAddress || address.isSiteLocalAddress || address.isLinkLocalAddress || address.isAnyLocalAddress) {
            return true
        }
        val bytes = address.address
        return when (bytes.size) {
            4 -> bytes[0].toInt() == 100 && (bytes[1].toInt() and 0xFF) in 64..127
            16 -> (bytes[0].toInt() and 0xFE) == 0xFC
            else -> false
        }
    }

    companion object {
        private val PUBLIC_DNS: InetAddress = InetAddress.getByName("8.8.8.8")
    }
}
