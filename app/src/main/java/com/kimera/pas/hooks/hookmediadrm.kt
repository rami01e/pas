package com.kimera.pas.hooks

import android.media.MediaDrm
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState
import java.security.SecureRandom
import java.util.UUID

/**
 * Widevine spoof (v3.1.0, option B complete): "report L1, never L3" on BOTH
 * the property surfaces and the session lifecycle.
 *
 * Property surfaces (unchanged): securityLevel -> L1, maxHdcpLevel ->
 * HDCP-2.2, deviceUniqueId -> spoofed id, version / oemCrypto aligned.
 *
 * Session lifecycle (v3.1.0 - the "Session inconclusive / maximum session:
 * FAILURE / SESSION_OPEN(RUNTIME)" half of the Duck credential card): the
 * MuMu CDM cannot actually open the session an L1 story advertises, so
 * detectors that probe the credential graded the whole card inconclusive.
 * The session surfaces are now completed to match the property story:
 *   - openSession() / openSession(level) answer a non-empty session id when
 *     the real CDM fails (the card requires sessionStatus = SUCCESS),
 *   - getSecurityLevel(session) answers HW_SECURE_ALL when the real read
 *     fails or reports anything lower (actualSessionSecurityLevel must not
 *     be "known below HW_SECURE_ALL" while HW_SECURE_ALL capability is
 *     advertised),
 *   - getKeyRequest(...) answers a synthetic request on failure (the card
 *     requires keyRequestStatus = SUCCESS once a session exists),
 *   - closeSession(...) swallows failures (a fake session id cannot be
 *     closed by the CDM and that error is pure noise).
 * Every hook still tries the REAL call first and only substitutes on
 * failure/empty, so a device with a working CDM keeps its real behaviour.
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
        hookOpenSessionNoArg(module)
        hookSessionSecurityLevel(module)
        hookGetKeyRequest(module)
        hookCloseSession(module)
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
                } else if (key == "oemCryptoBuildInformation" && SpoofState.widevineOn) {
                    val orig = chain.proceed() as? String
                    val spoofed = orig?.replace("Level3", "Level1") ?: "OEMCrypto Level1"
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm oemCryptoBuildInformation -> $spoofed")
                    spoofed
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
                            newFakeSessionId()
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

    /**
     * v3.1.0: the no-arg openSession() is what credential/session probes
     * actually call (Duck's openMaximumSecuritySession -> openSession()).
     * The real call fails on an emulator CDM that cannot honor the L1
     * story; answer a non-empty synthetic session so the caller's session
     * pipeline continues instead of grading SESSION_OPEN(FAILURE).
     */
    private fun hookOpenSessionNoArg(module: XposedModule) {
        hookSafe(module, "MediaDrm.openSession()") {
            val method = MediaDrm::class.java.getMethod("openSession")
            module.hook(method).intercept { chain ->
                if (!SpoofState.widevineOn) return@intercept chain.proceed()
                val orig = try {
                    chain.proceed() as? ByteArray
                } catch (t: Throwable) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm.openSession failed -> synthetic session ($t)")
                    null
                }
                if (orig != null && orig.isNotEmpty()) {
                    orig
                } else {
                    newFakeSessionId()
                }
            }
        }
    }

    /**
     * v3.1.0: session-level reads must never report below HW_SECURE_ALL
     * while the property story advertises L1 + HW_SECURE_ALL capability.
     * The real read wins when it already answers 5; anything else (throw,
     * L3/L1 software answers) becomes HW_SECURE_ALL.
     */
    private fun hookSessionSecurityLevel(module: XposedModule) {
        // getSecurityLevel(byte[]) exists on API 28+; skip silently elsewhere.
        runCatching {
            MediaDrm::class.java.getMethod("getSecurityLevel", ByteArray::class.java)
        }.getOrNull()?.let { method ->
            module.hook(method).intercept { chain ->
                if (!SpoofState.widevineOn) return@intercept chain.proceed()
                val orig = try {
                    chain.proceed() as? Int
                } catch (t: Throwable) {
                    null
                }
                if (orig == MEDIA_SECURITY_LEVEL_HW_SECURE_ALL) {
                    orig
                } else {
                    module.log(
                        Log.INFO, TAG,
                        "[PAS] MediaDrm.getSecurityLevel(orig=$orig) -> HW_SECURE_ALL"
                    )
                    MEDIA_SECURITY_LEVEL_HW_SECURE_ALL
                }
            }
        }
    }

    /**
     * v3.1.0: a synthetic session cannot produce a real key request; the
     * real getKeyRequest on a fake id throws, which a probe would grade as
     * KEY_REQUEST(FAILURE). Answer a synthetic request on failure so the
     * local key-request step completes like on a working CDM.
     */
    private fun hookGetKeyRequest(module: XposedModule) {
        hookSafe(module, "MediaDrm.getKeyRequest") {
            val method = MediaDrm::class.java.getMethod(
                "getKeyRequest", ByteArray::class.java, ByteArray::class.java,
                String::class.java, Integer.TYPE, java.util.HashMap::class.java
            )
            module.hook(method).intercept { chain ->
                if (!SpoofState.widevineOn) return@intercept chain.proceed()
                try {
                    chain.proceed()
                } catch (t: Throwable) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm.getKeyRequest failed -> synthetic ($t)")
                    // Fall back to the original failure when the runtime
                    // refuses to hand us a synthetic request instance.
                    newFakeKeyRequest() ?: throw t
                }
            }
        }
    }

    /**
     * v3.1.0: closing a synthetic session id throws in the CDM; that error
     * is never actionable (and probes record it as SESSION_CLOSE noise).
     * Swallow it when the widevine story is on.
     */
    private fun hookCloseSession(module: XposedModule) {
        hookSafe(module, "MediaDrm.closeSession") {
            val method = MediaDrm::class.java.getMethod("closeSession", ByteArray::class.java)
            module.hook(method).intercept { chain ->
                if (!SpoofState.widevineOn) return@intercept chain.proceed()
                try {
                    chain.proceed()
                } catch (t: Throwable) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm.closeSession swallowed: $t")
                    null
                }
            }
        }
    }

    /**
     * Builds an empty MediaDrm.KeyRequest for the failure path of
     * getKeyRequest. KeyRequest's constructor is package-private and its
     * data setter is not part of the public SDK, so the instance is created
     * and its data field is filled in reflectively (neither member is on the
     * hidden-API blocklist; both are plain framework-internal visibility).
     * Returns null when the runtime refuses anything, so the caller can
     * rethrow the original error and keep the pre-hook behaviour.
     */
    private fun newFakeKeyRequest(): MediaDrm.KeyRequest? = runCatching {
        val ctor = MediaDrm.KeyRequest::class.java.getDeclaredConstructor()
        ctor.isAccessible = true
        val request = ctor.newInstance() as MediaDrm.KeyRequest
        val dataField = MediaDrm.KeyRequest::class.java.getDeclaredField("mData")
        dataField.isAccessible = true
        dataField.set(request, ByteArray(32))
        request
    }.getOrNull()

    /** Non-empty, never-all-zero session id for the synthetic session. */
    private fun newFakeSessionId(): ByteArray {
        val id = ByteArray(16)
        SECURE_RANDOM.nextBytes(id)
        if (id[0] == 0.toByte() && id.none { it != 0.toByte() }) id[0] = 1
        return id
    }

    private fun hookMaxSecurityLevel(module: XposedModule) {
        // getMaxSecurityLevel() exists on API 28+; skip silently elsewhere.
        runCatching { MediaDrm::class.java.getMethod("getMaxSecurityLevel") }.getOrNull()?.let { method ->
            module.hook(method).intercept { chain ->
                if (SpoofState.widevineOn) {
                    val orig = chain.proceed()
                    module.log(Log.INFO, TAG, "[PAS] MediaDrm.getMaxSecurityLevel (orig=$orig) -> 5")
                    5
                } else {
                    chain.proceed()
                }
            }
        }
    }

    /** Locate Chromium's MediaDrmBridge across the process classloaders. */
    private fun findMediaDrmBridgeClass(module: XposedModule): Class<*>? {
        val name = "org.chromium.media.MediaDrmBridge"
        val loaders = ArrayList<Pair<String, ClassLoader?>>()
        loaders.add("app" to com.kimera.pas.pasClassLoader)
        loaders.add("context" to Thread.currentThread().contextClassLoader)
        loaders.add(
            "activity" to try {
                val at = Class.forName("android.app.ActivityThread")
                val app = at.getMethod("currentApplication").invoke(null)
                (app as? android.content.Context)?.classLoader
            } catch (t: Throwable) {
                null
            }
        )
        loaders.add(
            "webview" to try {
                val wvf = Class.forName("android.webkit.WebViewFactory")
                val provider = wvf.getMethod("getProvider").invoke(null)
                provider?.javaClass?.classLoader
            } catch (t: Throwable) {
                null
            }
        )
        for ((tag, loader) in loaders) {
            if (loader == null) {
                module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge loader=$tag: null")
                continue
            }
            var l: ClassLoader? = loader
            var depth = 0
            while (l != null && depth < 4) {
                try {
                    val c = Class.forName(name, false, l)
                    module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge loader=$tag depth=$depth: found")
                    return c
                } catch (t: Throwable) {
                    // climb the parent chain
                }
                l = l.parent
                depth++
            }
            module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge loader=$tag: not found")
        }
        return null
    }

    /**
     * Chromium's own EME layer (Chrome and WebView share
     * org.chromium.media.MediaDrmBridge). The browser decides which
     * robustness levels a container supports through this class, and the
     * check can run in a process where the platform-side hooks see nothing -
     * mirroring the substitutions here covers both browsers directly.
     */
    private fun hookChromiumBridge(module: XposedModule) {
        val cls = findMediaDrmBridgeClass(module)
        if (cls == null) {
            module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge: class not present")
            return
        }
        // The exact methods present in release Chrome builds (confirmed via
        // the method inventory): isCryptoSchemeSupported(byte[], String) and
        // getSupportedContainers(byte[]).
        runCatching {
            cls.getDeclaredMethod("isCryptoSchemeSupported", ByteArray::class.java, String::class.java)
        }.getOrNull()?.let { m ->
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                val arg = chain.getArg(0) as? ByteArray
                val orig = chain.proceed()
                if (SpoofState.widevineOn && isWidevineBytes(arg)) {
                    module.log(
                        Log.INFO, TAG,
                        "[PAS] MediaDrmBridge.isCryptoSchemeSupported(bytes, mime) -> true (orig=$orig)"
                    )
                    true
                } else {
                    orig
                }
            }
            module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.isCryptoSchemeSupported(bytes,String): hooked")
        }
        runCatching {
            cls.getDeclaredMethod("getSupportedContainers", ByteArray::class.java)
        }.getOrNull()?.let { m ->
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                val arg = chain.getArg(0) as? ByteArray
                val orig = chain.proceed()
                if (SpoofState.widevineOn && isWidevineBytes(arg)) {
                    val list = (orig as? Array<*>)?.map { it?.toString() ?: "" } ?: emptyList()
                    val missing = mutableListOf<String>()
                    if (!list.contains("video/mp4")) missing.add("video/mp4")
                    if (!list.contains("video/webm")) missing.add("video/webm")
                    if (missing.isNotEmpty()) {
                        module.log(
                            Log.INFO, TAG,
                            "[PAS] MediaDrmBridge.getSupportedContainers(bytes) +$missing (orig=$list)"
                        )
                        (list + missing).toTypedArray()
                    } else {
                        orig
                    }
                } else {
                    orig
                }
            }
            module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.getSupportedContainers(bytes): hooked")
        }
        // CDM creation attempts (diagnostic + resilience): if the requested
        // hardware level fails or yields nothing, retry once at level 3 so
        // the capability negotiation can still complete.
        runCatching {
            cls.getDeclaredMethod(
                "create", ByteArray::class.java, String::class.java, Integer.TYPE,
                String::class.java, java.lang.Boolean.TYPE, java.lang.Long.TYPE, java.lang.Long.TYPE
            )
        }.getOrNull()?.let { m ->
            m.isAccessible = true
            val isStatic = java.lang.reflect.Modifier.isStatic(m.modifiers)
            module.hook(m).intercept { chain ->
                val recv: Any? = if (isStatic) null else chain.getThisObject()
                val a0 = chain.getArg(0)
                val a1 = chain.getArg(1)
                val lvl = (chain.getArg(2) as? Int) ?: -1
                val a3 = chain.getArg(3)
                val a4 = chain.getArg(4)
                val a5 = chain.getArg(5)
                val a6 = chain.getArg(6)
                module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.create(level=$lvl info=$a3)")
                fun retry(): Any? = runCatching {
                    m.invoke(recv, a0, a1, 3, a3, a4, a5, a6)
                }.onFailure {
                    module.log(Log.INFO, TAG, "[PAS] create retry(level=3) threw: $it")
                }.getOrNull()
                try {
                    val r = chain.proceed()
                    if (r == null && SpoofState.widevineOn && lvl != 3) {
                        module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.create(level=$lvl) returned null - retrying level=3")
                        retry() ?: r
                    } else {
                        r
                    }
                } catch (t: Throwable) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.create(level=$lvl) threw: $t")
                    if (SpoofState.widevineOn && lvl != 3) {
                        retry() ?: throw t
                    } else {
                        throw t
                    }
                }
            }
        }
        // Log-only surfaces: version / HDCP level / session plumbing.
        runCatching { cls.getDeclaredMethod("getVersion") }.getOrNull()?.let { m ->
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                val orig = chain.proceed()
                if (SpoofState.widevineOn) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.getVersion -> $orig")
                }
                orig
            }
        }
        runCatching { cls.getDeclaredMethod("getCurrentHdcpLevel") }.getOrNull()?.let { m ->
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                val orig = chain.proceed()
                if (SpoofState.widevineOn) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.getCurrentHdcpLevel -> $orig")
                }
                orig
            }
        }
        runCatching {
            cls.getDeclaredMethod(
                "createSessionFromNative", ByteArray::class.java, String::class.java,
                Integer.TYPE, Array<String>::class.java, java.lang.Long.TYPE
            )
        }.getOrNull()?.let { m ->
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                if (SpoofState.widevineOn) {
                    module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge.createSessionFromNative called")
                }
                chain.proceed()
            }
        }
        val methods = cls.declaredMethods
        var scan1: java.lang.reflect.Method? = null
        var scan2: java.lang.reflect.Method? = null
        for (m in methods) {
            if (!java.lang.reflect.Modifier.isStatic(m.modifiers)) continue
            val pt = m.parameterTypes
            if (pt.size == 1 && pt[0] == ByteArray::class.java &&
                (m.returnType == java.lang.Boolean.TYPE || m.returnType == java.lang.Boolean::class.java)
            ) {
                if (scan1 == null) scan1 = m
            } else if (pt.size == 2 && pt[0] == ByteArray::class.java && pt[1] == Integer.TYPE &&
                m.returnType == Array<String>::class.java
            ) {
                if (scan2 == null) scan2 = m
            }
        }
        module.log(
            Log.INFO, TAG,
            "[PAS] MediaDrmBridge scan: crypto=${scan1?.name ?: "?"} containers=${scan2?.name ?: "?"}"
        )
        if (SpoofState.reconOn) {
            val inv = StringBuilder()
            var n = 0
            val kw = listOf(
                "security", "level", "secure", "robust", "hdcp", "version",
                "session", "crypto", "decrypt", "codec"
            )
            for (m in methods) {
                if (n >= 60) break
                val mn = m.name.lowercase()
                if (kw.none { mn.contains(it) }) continue
                val kind = if (java.lang.reflect.Modifier.isStatic(m.modifiers)) "S" else "I"
                inv.append(m.name).append('(')
                    .append(m.parameterTypes.joinToString(",") { it.simpleName })
                    .append("):").append(m.returnType.simpleName).append(':').append(kind).append(' ')
                n++
            }
            module.log(Log.INFO, TAG, "[PAS] MediaDrmBridge key methods: $inv")
        }
        val m1 = scan1
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
        val m2 = scan2
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

        /** MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL (API 28 constant value). */
        const val MEDIA_SECURITY_LEVEL_HW_SECURE_ALL = 5

        val SECURE_RANDOM = SecureRandom()
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