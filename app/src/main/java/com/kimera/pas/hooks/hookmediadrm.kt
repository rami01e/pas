package com.kimera.pas.hooks

import android.media.MediaDrm
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState
import java.util.UUID

/**
 * Widevine property spoof: reports security level L1, a generated
 * deviceUniqueId and reference-device version / max HDCP strings. This covers
 * the properties that fingerprinting code reads through MediaDrm; it does not
 * create hardware-backed L1 playback (that needs a real L1 CDM), which is not
 * what app/web fingerprinting checks.
 */
class HookMediaDrm : XHook {

    override val targetKlass: String
        get() = "android.media.MediaDrm"

    override fun injectHook(module: XposedModule) {
        hookPropertyString(module)
        hookPropertyByteArray(module)
        hookIsCryptoSchemeSupported(module)
        hookMaxSecurityLevel(module)
        hookOpenSession(module)
        hookChromiumBridge(module)
        val has3 = runCatching {
            MediaDrm::class.java.getMethod(
                "isCryptoSchemeSupported", UUID::class.java, String::class.java, Integer.TYPE
            )
        }.isSuccess
        val hasOs = runCatching {
            MediaDrm::class.java.getMethod("openSession", Integer.TYPE)
        }.isSuccess
        val hasMax = runCatching {
            MediaDrm::class.java.getMethod("getMaxSecurityLevel")
        }.isSuccess
        module.log(
            Log.INFO, TAG,
            "[PAS] MediaDrm hooks avail: 3arg=$has3 sessionInt=$hasOs maxLevel=$hasMax"
        )
    }

    private fun hookPropertyString(module: XposedModule) {
        hookSafe(module, "MediaDrm.getPropertyString") {
            val method = MediaDrm::class.java.getMethod("getPropertyString", String::class.java)
            module.hook(method).intercept { chain ->
                val key = chain.getArg(0) as? String
                if (!SpoofState.widevineOn) {
                    chain.proceed()
                } else if (key == "securityLevel") {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm securityLevel -> L1")
                    "L1"
                } else if (key == "maxHdcpLevel") {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm maxHdcpLevel -> $MAX_HDCP_LEVEL")
                    MAX_HDCP_LEVEL
                } else if (key == "version") {
                    // Cosmetic alignment: only rewrite values shaped like a
                    // Widevine version (x.y.z...). ClearKey reports "1.2" and
                    // stays untouched.
                    val orig = chain.proceed() as? String
                    if (orig != null && WIDEVINE_VERSION_LIKE.containsMatchIn(orig)) {
                        module.log(Log.INFO, TAG, "[PAS] MediaDrm version -> $WIDEVINE_VERSION")
                        WIDEVINE_VERSION
                    } else {
                        orig
                    }
                } else {
                    val orig = chain.proceed()
                    if (SpoofState.widevineOn) {
                        module.log(
                            Log.INFO, TAG,
                            "[PAS] MediaDrm.getPropertyString($key) -> ${orig?.toString()?.take(80)}"
                        )
                    }
                    orig
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
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm deviceUniqueId -> spoofed")
                    hexToBytes(hex)
                } else {
                    val orig = chain.proceed()
                    if (SpoofState.widevineOn) {
                        val n = (orig as? ByteArray)?.size ?: -1
                        module.log(Log.INFO, TAG, "[PAS] MediaDrm.getPropertyByteArray($key) -> $n bytes")
                    }
                    orig
                }
            }
        }
    }

    /**
     * EME capability negotiation surfaces: browsers gate "HW_SECURE_ALL"
     * (L1) support on these calls, not only on the property strings. Real
     * hardware-backed L1 playback still needs a secure decoder - only the
     * capability surfaces are covered here.
     */
    private fun hookIsCryptoSchemeSupported(module: XposedModule) {
        val uuidCls = UUID::class.java
        hookSafe(module, "MediaDrm.isCryptoSchemeSupported(UUID)") {
            val method = MediaDrm::class.java.getMethod("isCryptoSchemeSupported", uuidCls)
            module.hook(method).intercept { chain ->
                val uuid = chain.getArg(0) as? UUID
                if (SpoofState.widevineOn && uuid == WIDEVINE_UUID) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm.isCryptoSchemeSupported(uuid) -> true")
                    true
                } else {
                    chain.proceed()
                }
            }
        }
        hookSafe(module, "MediaDrm.isCryptoSchemeSupported(UUID, String)") {
            val method = MediaDrm::class.java.getMethod(
                "isCryptoSchemeSupported", uuidCls, String::class.java
            )
            module.hook(method).intercept { chain ->
                val uuid = chain.getArg(0) as? UUID
                if (SpoofState.widevineOn && uuid == WIDEVINE_UUID) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm.isCryptoSchemeSupported(uuid, mime) -> true")
                    true
                } else {
                    chain.proceed()
                }
            }
        }
        // 3-arg overload exists on API 28+; skip silently elsewhere (minSdk 26).
        runCatching {
            MediaDrm::class.java.getMethod(
                "isCryptoSchemeSupported", uuidCls, String::class.java, Integer.TYPE
            )
        }.getOrNull()?.let { method ->
            module.hook(method).intercept { chain ->
                val uuid = chain.getArg(0) as? UUID
                val level = (chain.getArg(2) as? Int) ?: -1
                if (SpoofState.widevineOn && uuid == WIDEVINE_UUID && level in 0..5) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm.isCryptoSchemeSupported(uuid, mime, $level) -> true")
                    true
                } else {
                    chain.proceed()
                }
            }
        }
    }

    /**
     * The browser EME "HW_SECURE_*" path opens sessions at the requested
     * security level; a software CDM rejects levels above its native one,
     * which made browser capability checks fail even when the support query
     * answered yes. Fall back to a default session for levels >= 2.
     */
    private fun hookOpenSession(module: XposedModule) {
        // openSession(int) exists on API 28+; skip silently elsewhere.
        runCatching { MediaDrm::class.java.getMethod("openSession", Integer.TYPE) }.getOrNull()?.let { method ->
            module.hook(method).intercept { chain ->
                val level = (chain.getArg(0) as? Int) ?: 0
                if (SpoofState.widevineOn && level in 2..5) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm.openSession($level) -> default session")
                    val drm = chain.getThisObject() as? MediaDrm
                    if (drm != null) {
                        try {
                            drm.openSession()
                        } catch (t: Throwable) {
                            module.log(Log.INFO, TAG, "[PAS] default openSession failed: $t")
                            null
                        }
                    } else {
                        chain.proceed()
                    }
                } else {
                    chain.proceed()
                }
            }
        }
    }

    private fun hookMaxSecurityLevel(module: XposedModule) {
        // getMaxSecurityLevel() exists on API 28+; skip silently elsewhere.
        runCatching { MediaDrm::class.java.getMethod("getMaxSecurityLevel") }.getOrNull()?.let { method ->
            module.hook(method).intercept { chain ->
                if (SpoofState.widevineOn) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm.getMaxSecurityLevel -> 5")
                    5
                } else {
                    chain.proceed()
                }
            }
        }
    }

    /**
     * Chromium's own EME layer (Chrome and WebView share
     * org.chromium.media.MediaDrmBridge). The browser decides which
     * robustness levels a container supports through this class, and the
     * check can run in a process where the platform-side hooks see nothing -
     * mirroring the substitutions here covers both browsers directly.
     */
    private fun hookChromiumBridge(module: XposedModule) {
        val cls = try {
            Class.forName("org.chromium.media.MediaDrmBridge")
        } catch (t: Throwable) {
            null
        }
        if (cls == null) {
            module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge: class not present")
            return
        }
        val m1 = runCatching {
            cls.getDeclaredMethod("isCryptoSchemeSupported", ByteArray::class.java)
        }.getOrNull()
        if (m1 != null) {
            m1.isAccessible = true
            module.hook(m1).intercept { chain ->
                val arg = chain.getArg(0) as? ByteArray
                val orig = chain.proceed()
                if (SpoofState.widevineOn && isWidevineBytes(arg)) {
                    module.log(
                        Log.INFO, TAG,
                        "[PAS] MediaDrmBridge.isCryptoSchemeSupported -> true (orig=$orig)"
                    )
                    true
                } else {
                    orig
                }
            }
            module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.isCryptoSchemeSupported: hooked")
        } else {
            module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.isCryptoSchemeSupported: absent")
        }
        val m2 = runCatching {
            cls.getDeclaredMethod("getSupportedContainers", ByteArray::class.java, Integer.TYPE)
        }.getOrNull()
        if (m2 != null) {
            m2.isAccessible = true
            module.hook(m2).intercept { chain ->
                val arg = chain.getArg(0) as? ByteArray
                val level = (chain.getArg(1) as? Int) ?: -1
                val orig = chain.proceed()
                if (SpoofState.widevineOn && isWidevineBytes(arg) && level >= 2) {
                    val list = (orig as? Array<*>)?.map { it?.toString() ?: "" } ?: emptyList()
                    val missing = mutableListOf<String>()
                    if (!list.contains("video/mp4")) missing.add("video/mp4")
                    if (!list.contains("video/webm")) missing.add("video/webm")
                    if (missing.isNotEmpty()) {
                        module.log(
                            Log.INFO, TAG,
                            "[PAS] MediaDrmBridge.getSupportedContainers(level=$level) +$missing (orig=$list)"
                        )
                        (list + missing).toTypedArray()
                    } else {
                        orig
                    }
                } else {
                    orig
                }
            }
            module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.getSupportedContainers: hooked")
        } else {
            module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.getSupportedContainers: absent")
        }
    }

    private fun isWidevineBytes(b: ByteArray?): Boolean =
        b != null && b.size == 16 && b.contentEquals(WIDEVINE_BYTES)

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

    private companion object {
        /** Mirrors what the reference device (Galaxy A13 class) reports. */
        const val WIDEVINE_VERSION = "16.1.1@015"
        const val MAX_HDCP_LEVEL = "HDCP-2.2"
        val WIDEVINE_VERSION_LIKE = Regex("""^\d+\.\d+\.\d+""")
        val WIDEVINE_UUID: UUID = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")
        val WIDEVINE_BYTES: ByteArray = byteArrayOf(
            0xed.toByte(), 0xef.toByte(), 0x8b.toByte(), 0xa9.toByte(),
            0x79.toByte(), 0xd6.toByte(), 0x4a.toByte(), 0xce.toByte(),
            0xa3.toByte(), 0xc8.toByte(), 0x27.toByte(), 0xdc.toByte(),
            0xd5.toByte(), 0x1d.toByte(), 0x21.toByte(), 0xed.toByte()
        )
    }
}
