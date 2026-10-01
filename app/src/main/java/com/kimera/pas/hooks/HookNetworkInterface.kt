package com.kimera.pas.hooks

import android.util.Log
import io.github.libxposed.api.XposedModule
import java.net.NetworkInterface
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState
import com.kimera.pas.util.getRandomString

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
                if (SpoofState.reconOn) module.log(Log.INFO, TAG, "NetworkInterface.isVirtual")
                if (SpoofState.relaxNet) {
                    chain.proceed()
                } else {
                    // VPNs are always virtual
                    false
                }
            }
        }
    }

    private fun hookGetName(module: XposedModule) {
        hookSafe(module, "NetworkInterface.getName") {
            val method = NetworkInterface::class.java.getMethod("getName")
            module.hook(method).intercept { chain ->
                val result = chain.proceed()
                if (SpoofState.reconOn) module.log(Log.INFO, TAG, "NetworkInterface.getName ($result)")
                // breaks VPN name detection
                if (SpoofState.relaxNet) {
                    result
                } else if (result is String) {
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
                val name = chain.getArg(0) as? String
                module.log(
                    Log.INFO, TAG,
                    "NetworkInterface.getByName ($name) webrtcMode=${SpoofState.webrtcMode}"
                )
                if (name == null) {
                    // Non-string lookup: leave the call untouched.
                    return@intercept chain.proceed()
                }
                when {
                    // Relaxed view: everything resolves truthfully.
                    SpoofState.relaxNet -> chain.proceed()
                    // VPN-style interfaces never resolve.
                    name.startsWith("tun") || name.startsWith("ppp") ||
                        name.startsWith("pptp") || name.startsWith("wg") -> null
                    // RKN mode: suppress non-VPN resolution too so browsers
                    // cannot gather local (host) candidates.
                    SpoofState.webrtcMode == 2 -> null
                    // Everything else resolves normally. (The previous
                    // upstream code passed a wrapped array here, which made
                    // every non-tun lookup fail - breaking local-candidate
                    // enumeration in browsers.)
                    else -> chain.proceed()
                }
            }
        }
    }

    private fun hookIsUp(module: XposedModule) {
        hookSafe(module, "NetworkInterface.isUp") {
            val method = NetworkInterface::class.java.getMethod("isUp")
            module.hook(method).intercept { chain ->
                val name = (chain.getThisObject() as NetworkInterface).name
                if (SpoofState.reconOn) module.log(Log.INFO, TAG, "NetworkInterface.isUp() on interface $name")
                if (!SpoofState.relaxNet &&
                    (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("pptp"))
                ) false else chain.proceed()
            }
        }
    }
}
