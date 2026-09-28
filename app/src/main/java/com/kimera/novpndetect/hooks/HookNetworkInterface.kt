package com.kimera.novpndetect.hooks

import android.util.Log
import io.github.libxposed.api.XposedModule
import java.net.NetworkInterface
import com.kimera.novpndetect.TAG
import com.kimera.novpndetect.XHook
import com.kimera.novpndetect.hookSafe
import com.kimera.novpndetect.util.getRandomString

class HookNetworkInterface : XHook {

    private val renamedInterfaces = HashMap<String, String>()

    override val targetKlass: String
        get() = "android.net.NetworkInterface"

    override fun injectHook(module: XposedModule) {
        hookGetName(module)
        hookIsVirtual(module)
        hookGetByName(module)
        hookIsUp(module)
    }

    private fun hookIsVirtual(module: XposedModule) {
        hookSafe(module, "NetworkInterface.isVirtual") {
            val method = NetworkInterface::class.java.getMethod("isVirtual")
            module.hook(method).intercept { chain ->
                module.log(Log.INFO, TAG, "NetworkInterface.isVirtual")
                // VPNs are always virtual
                false
            }
        }
    }

    private fun hookGetName(module: XposedModule) {
        hookSafe(module, "NetworkInterface.getName") {
            val method = NetworkInterface::class.java.getMethod("getName")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                module.log(Log.INFO, TAG, "NetworkInterface.getName ($result)")
                // breaks VPN name detection
                if (result is String) {
                    if (result.startsWith("tun") || result.startsWith("ppp") || result.startsWith("pptp")) {
                        if (!renamedInterfaces.contains(result))
                            renamedInterfaces[result] = getRandomString(result.length)
                        renamedInterfaces[result]
                    } else {
                        result
                    }
                } else {
                    module.log(Log.ERROR, TAG, "NetworkInterface.getName: result is not String")
                    result
                }
            }
        }
    }

    private fun hookGetByName(module: XposedModule) {
        hookSafe(module, "NetworkInterface.getByName") {
            val method = NetworkInterface::class.java.getMethod("getByName", String::class.java)
            module.hook(method).intercept { chain ->
                val name = chain.getArg(0) as String
                module.log(Log.INFO, TAG, "NetworkInterface.getByName ($name)")
                // Note: the inverted contains check below is preserved verbatim from upstream.
                if (!renamedInterfaces.contains(name)) {
                    chain.proceed(arrayOf<Any?>(renamedInterfaces[name]))
                } else if (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("pptp")) {
                    null
                } else {
                    chain.proceed()
                }
            }
        }
    }

    private fun hookIsUp(module: XposedModule) {
        hookSafe(module, "NetworkInterface.isUp") {
            val method = NetworkInterface::class.java.getMethod("isUp")
            module.hook(method).intercept { chain ->
                val name = (chain.getThisObject() as NetworkInterface).name
                module.log(Log.INFO, TAG, "NetworkInterface.isUp() on interface $name")
                if (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("pptp")) false else chain.proceed()
            }
        }
    }
}
