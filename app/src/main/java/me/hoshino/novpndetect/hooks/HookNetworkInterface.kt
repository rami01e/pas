package me.hoshino.novpndetect.hooks

import android.util.Log
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedHelpers
import me.hoshino.novpndetect.TAG
import me.hoshino.novpndetect.XHook
import me.hoshino.novpndetect.util.getRandomString
import java.net.NetworkInterface

class HookNetworkInterface : XHook {

    private val renamedInterfaces = HashMap<String, String>()

    override val targetKlass: String
        get() = "android.net.NetworkInterface"

    override fun injectHook() {
        hookGetName()
        hookIsVirtual()
        hookGetByName()
        hookIsUp()
    }

    private fun hookIsVirtual() {
        XposedHelpers.findAndHookMethod(NetworkInterface::class.java, "isVirtual", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "NetworkInterface.isVirtual")
                // VPNs are always virtual
                param.result = false
            }
        })
    }

    private fun hookGetName() {
        XposedHelpers.findAndHookMethod(NetworkInterface::class.java, "getName", object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "NetworkInterface.getName (${param.result})")
                // breaks VPN name detection
                if (param.result is String) {
                    val name = param.result as String
                    if (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("pptp")) {
                        if(!renamedInterfaces.contains(name))
                            renamedInterfaces[name] = getRandomString(name.length)
                        param.result = renamedInterfaces[name]
                    }
                } else {
                    Log.e(TAG, "NetworkInterface.getName: result is not String")
                }
            }
        })
    }

    private fun hookGetByName() {
        XposedHelpers.findAndHookMethod(NetworkInterface::class.java, "getByName", String::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.i(TAG, "NetworkInterface.getByName (${param.args[0]})")
                val name = param.args[0] as String
                if(!renamedInterfaces.contains(name))
                    param.args[0] = renamedInterfaces[name]
                else if (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("pptp"))
                    param.result = null
            }
        })
    }

    private fun hookIsUp() {
        XposedHelpers.findAndHookMethod(NetworkInterface::class.java, "isUp", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val name = (param.thisObject as NetworkInterface).name
                Log.i(TAG, "NetworkInterface.isUp() on interface $name")
                if (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("pptp"))
                    param.result = false
            }
        })
    }
}