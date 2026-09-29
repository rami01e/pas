package com.kimera.novpndetect.hooks

import android.media.MediaDrm
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.novpndetect.TAG
import com.kimera.novpndetect.XHook
import com.kimera.novpndetect.hookSafe
import com.kimera.novpndetect.spoof.SpoofState

/**
 * Widevine property spoof: reports security level L1 and a generated
 * deviceUniqueId. This covers the properties that fingerprinting code reads
 * through MediaDrm; it does not create hardware-backed L1 playback (that
 * needs a real L1 CDM), which is not what app/web fingerprinting checks.
 */
class HookMediaDrm : XHook {

    override val targetKlass: String
        get() = "android.media.MediaDrm"

    override fun injectHook(module: XposedModule) {
        hookPropertyString(module)
        hookPropertyByteArray(module)
        hookSecurityLevel(module)
    }

    private fun hookPropertyString(module: XposedModule) {
        hookSafe(module, "MediaDrm.getPropertyString") {
            val method = MediaDrm::class.java.getMethod("getPropertyString", String::class.java)
            module.hook(method).intercept { chain ->
                val key = chain.getArg(0) as? String
                if (SpoofState.widevineOn && key == "securityLevel") {
                    module.log(Log.INFO, TAG, "[NVD] MediaDrm securityLevel -> L1")
                    "L1"
                } else {
                    chain.proceed()
                }
            }
        }
    }

    private fun hookPropertyByteArray(module: XposedModule) {
        hookSafe(module, "MediaDrm.getPropertyByteArray") {
            val method = MediaDrm::class.java.getMethod("getPropertyByteArray", String::class.java)
            module.hook(method).intercept { chain ->
                val key = chain.getArg(0) as? String
                val hex = SpoofState.widevineId
                if (SpoofState.widevineOn && key == "deviceUniqueId" && isSpoofableHex(hex)) {
                    module.log(Log.INFO, TAG, "[NVD] MediaDrm deviceUniqueId -> spoofed")
                    hexToBytes(hex)
                } else {
                    chain.proceed()
                }
            }
        }
    }

    private fun hookSecurityLevel(module: XposedModule) {
        hookSafe(module, "MediaDrm.getSecurityLevel") {
            val method = MediaDrm::class.java.getMethod("getSecurityLevel")
            module.hook(method).intercept { chain ->
                if (SpoofState.widevineOn) {
                    // MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL
                    5
                } else {
                    chain.proceed()
                }
            }
        }
    }

    private fun isSpoofableHex(s: String): Boolean {
        if (s.isEmpty() || s.length % 2 != 0 || s.length > 128) return false
        for (c in s) {
            if (c !in "0123456789abcdefABCDEF") return false
        }
        return true
    }

    private fun hexToBytes(hex: String): ByteArray {
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(hex[i * 2], 16) shl 4) or
                Character.digit(hex[i * 2 + 1], 16)).toByte()
        }
        return out
    }
}
