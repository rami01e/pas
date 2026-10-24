package com.kimera.pas.hooks

import android.os.Build
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe
import com.kimera.pas.spoof.SpoofState

/**
 * v2.12.8 EXEC SHIELD - closes the child-process bypass of every in-process
 * mask.
 *
 * Evidence (Vector-logs-release-20261020-111217): the v2.12.7 build runs
 * clean - sweep shield hides 9 packages, the lookup shield answers the
 * manager probes ("lookup 'eu.chainfire.supersu' hidden", and no
 * "Hooker ... crashed" line exists for the 11:06 session; every crash line
 * in the capture constructs the NameNotFoundException INSIDE the old
 * v2.9.4 throw-based hooker) - and the app STILL flags the device. The
 * remaining RootBeer checks all share one property no in-process mask can
 * touch: they exec a helper binary and read the CHILD's stdout. The exec'd
 * child is a clean process without libpas (execve replaces the forked
 * image, so every PLT/GOT hook and every patched Build field vanish), so:
 *
 *   checkForDangerousProps() -> Runtime.exec("getprop"): MuMu ships a
 *       userdebug build, so the bare property dump contains
 *       "[ro.debuggable]: [1]" plus ro.secure / ro.build.selinux.
 *   checkForRWPaths()        -> Runtime.exec("mount"): the real mount table
 *       still lists writable system partitions. (The v2.12.7 native
 *       RewriteMountsLine only filters IN-PROCESS /proc/mounts reads - the
 *       child's output never passes through it.)
 *   checkSuExists()          -> Runtime.exec("/system/xbin/which", "su").
 *   isSelinuxFlagInEnabled() -> Runtime.exec("getenforce"): this device runs
 *       SELinux permissive (the capture is full of audit "permissive=1"
 *       lines), so the child prints "Permissive".
 *
 * What this hook does: sits on the two Java spawn chokepoints that every
 * Runtime.exec / ProcessBuilder path funnels through -
 *   - java.lang.ProcessBuilder.start()
 *   - java.lang.Runtime.exec(String[], String[], File)  (the funnel overload)
 * inspects the argv, and for root-evidence commands rewrites the command IN
 * PLACE to a harmless stand-in before the original spawn runs:
 *   getprop (bare dump)          -> /system/bin/true         (empty output)
 *   getprop <dangerous key>      -> /system/bin/echo <clean value>
 *   mount / umount               -> /system/bin/true         (empty output)
 *   getenforce                   -> /system/bin/echo Enforcing
 *   setenforce                   -> /system/bin/false        (exit 1 = denied)
 *   su / which <root binary>     -> /system/bin/false        (exit 1, no output =
 *                                    exactly what "not found" looks like)
 *   cat /proc/<mount files>      -> /system/bin/true
 *   sh -c "<root vocabulary>"    -> true/false depending on the probe kind
 *
 * v3.0.0 (P5): Duck Detector's "Android/data Ignorable CodePoint Bypass"
 * probes run ProcessBuilder("ls", <path with an invisible codepoint>) -
 * "/sdcard/Android/data\u200B/", "/sdcard\u00AD/Android/data", ...
 * The inserted ignorable Unicode codepoints make exact-byte path matching
 * miss while the kernel still resolves the same directory (MuMu's FUSE is
 * only partially patched against CVE-2024-43093), so the listing leaks the
 * hidden packages' storage dirs. The `ls` argv path is normalized (ignorable
 * codepoints stripped) before matching, and `ls` (direct or as a
 * toybox/busybox applet) targeting Android/data|obb is answered with
 * /system/bin/false - exit 1, no output - which is exactly what the FUSE
 * denial on a patched device looks like (the kernelcheck probe grades that
 * "blocked" = patch present, the dangerousapps probe gets an empty list).
 * Identity-critical getprop keys (ro.build.fingerprint, ro.product.*,
 * ro.build.tags, ...) are answered with the SAME values the in-process
 * Build patch already shows the app, so the child process agrees with the
 * spoofed identity instead of leaking the emulator's real one.
 *
 * Failure philosophy: analysis bugs and immutable command lists fail OPEN
 * (the original command runs untouched) - this shield must never break a
 * legitimate exec and never throws from an interceptor body (Vector's
 * PROTECTIVE mode would swallow the exception, log "Hooker ... crashed"
 * and disable the hook). Only the exact command shapes above are
 * rewritten; everything else passes through, so benign execs (pm / am /
 * dumpsys, analytics, getprop of harmless keys) are untouched.
 *
 * Gating: SpoofState.antiEmuOn, checked per call - toggling ANTI-EMU takes
 * effect without a process restart (same ownership as the sweep and
 * settings shields).
 *
 * Residual (accepted): a caller that spawns through the hidden
 * ProcessImpl.start directly, bypassing both chokepoints, is not covered;
 * RootBeer and every SDK observed so far go through the hooked surfaces.
 */
class HookExec : XHook {

    override val targetKlass: String
        get() = "java.lang.ProcessBuilder"

    private var execLog = 0

    override fun injectHook(module: XposedModule) {
        hookProcessBuilderStart(module)
        hookRuntimeFunnel(module)
    }

    // ------------------------------------------------------------------
    // java.lang.ProcessBuilder.start() - covers direct ProcessBuilder use
    // and (on Android) the Runtime.exec delegation path.
    // ------------------------------------------------------------------
    private fun hookProcessBuilderStart(module: XposedModule) {
        hookSafe(module, "exec ProcessBuilder.start") {
            val clazz = Class.forName("java.lang.ProcessBuilder")
            var installed = 0
            for (m in clazz.declaredMethods) {
                if (m.name != "start" || m.parameterTypes.isNotEmpty()) continue
                try {
                    m.isAccessible = true
                    module.hook(m).intercept { chain ->
                        if (!SpoofState.antiEmuOn) return@intercept chain.proceed()
                        val pb = chain.thisObject as? ProcessBuilder
                            ?: return@intercept chain.proceed()
                        val cmd = try {
                            pb.command()
                        } catch (t: Throwable) {
                            return@intercept chain.proceed()
                        }
                        val replacement = try {
                            analyze(cmd)
                        } catch (t: Throwable) {
                            null
                        } ?: return@intercept chain.proceed()
                        val original = cmd.joinToString(" ")
                        try {
                            // ProcessBuilder.command() returns the live list the
                            // original start() spawns from - mutate it in place.
                            cmd.clear()
                            cmd.addAll(replacement)
                        } catch (t: Throwable) {
                            // immutable command list on some ROMs - fail open
                            return@intercept chain.proceed()
                        }
                        logHit(module, "'$original' -> ${replacement.joinToString(" ")}")
                        chain.proceed()
                    }
                    installed++
                } catch (t: Throwable) {
                    // one unsupported signature must not sink the rest
                }
            }
            module.log(Log.INFO, TAG, "[PAS] exec shield: ProcessBuilder.start x$installed")
        }
    }

    // ------------------------------------------------------------------
    // java.lang.Runtime.exec(String[], String[], File) - the funnel every
    // Runtime.exec overload ends in. Belt-and-braces for ROMs where
    // Runtime.exec spawns without going through ProcessBuilder.start():
    // the String[] argv is rewritten IN PLACE (same array object the
    // original body reads), so no proceed()-semantics are involved and no
    // exception is ever raised here. When both hooks fire on one exec
    // (delegating ROMs), the second analysis sees the already-rewritten
    // benign command and passes it through.
    // ------------------------------------------------------------------
    private fun hookRuntimeFunnel(module: XposedModule) {
        hookSafe(module, "exec Runtime.exec funnel") {
            val clazz = Class.forName("java.lang.Runtime")
            var installed = 0
            for (m in clazz.declaredMethods) {
                if (m.name != "exec") continue
                val types = m.parameterTypes
                if (types.size != 3 || types[0] != Array<String>::class.java) continue
                try {
                    m.isAccessible = true
                    module.hook(m).intercept { chain ->
                        if (!SpoofState.antiEmuOn) return@intercept chain.proceed()
                        val args = chain.getArgs().toTypedArray()
                        @Suppress("UNCHECKED_CAST")
                        val argv = args.getOrNull(0) as? Array<String>
                            ?: return@intercept chain.proceed()
                        if (argv.isEmpty()) return@intercept chain.proceed()
                        val replacement = try {
                            analyze(argv.toList())
                        } catch (t: Throwable) {
                            null
                        } ?: return@intercept chain.proceed()
                        // the in-place rewrite must fit the fixed-size array;
                        // a too-long stand-in degrades to a silent empty-output
                        // command (still exactly what "not found" looks like)
                        val fitted =
                            if (replacement.size <= argv.size) replacement
                            else listOf(TRUE_BIN)
                        val original = argv.joinToString(" ")
                        for (i in argv.indices) {
                            argv[i] = fitted.getOrElse(i) { "" }
                        }
                        logHit(module, "'$original' -> ${fitted.joinToString(" ")}")
                        chain.proceed()
                    }
                    installed++
                } catch (t: Throwable) {
                    // one unsupported signature must not sink the rest
                }
            }
            module.log(Log.INFO, TAG, "[PAS] exec shield: Runtime.exec funnel x$installed")
        }
    }

    // ------------------------------------------------------------------
    // argv analysis. Returns the replacement command, or null to let the
    // original command run untouched.
    // ------------------------------------------------------------------
    private fun analyze(cmd: List<String>): List<String>? {
        if (cmd.isEmpty() || cmd[0].isEmpty()) return null
        val base = cmd[0].substringAfterLast('/')
        val rest = cmd.drop(1)

        // toybox / busybox / toolbox: "<toolbox> <applet> [args...]"
        if ((base == "toybox" || base == "busybox" || base == "toolbox") &&
            rest.isNotEmpty()
        ) {
            val sub = rest[0].substringAfterLast('/')
            return decide(sub, listOf(sub) + rest.drop(1))
        }

        // sh / mksh / bash -c "<payload>"
        if (base == "sh" || base == "mksh" || base == "bash") {
            val idx = rest.indexOf("-c")
            if (idx >= 0 && idx + 1 < rest.size) {
                val payload = rest.subList(idx + 1, rest.size).joinToString(" ")
                return when (payloadVerdict(payload)) {
                    PROBE_OUTPUT -> listOf(TRUE_BIN)
                    PROBE_BINARY -> listOf(FALSE_BIN)
                    else -> null
                }
            }
            return null
        }

        return decide(base, cmd)
    }

    /** base = program basename, cmd = full argv with the program at [0]. */
    private fun decide(base: String, cmd: List<String>): List<String>? {
        val rest = cmd.drop(1)
        return when (base) {
            "getprop" -> when {
                rest.isEmpty() -> listOf(TRUE_BIN)
                else -> PROP_SPOOF[rest[0]]?.let { listOf(ECHO_BIN, it) }
            }
            "ls" -> {
                // v3.0.0 (P5): a listing of Android/data|obb is answered by
                // FUSE on a patched device; MuMu's partially patched FUSE
                // can be talked into listing it (CVE-2024-43093 class),
                // which leaks hidden packages. Answer with exit 1 / no
                // output - the exact "denied" signature of a patched FUSE.
                // The path is normalized first so codepoint-mangled variants
                // ("/sdcard/Android/data\u200B/") match the same rule.
                val target = rest.firstOrNull { it.startsWith("/") } ?: return null
                val n = normalizeIgnorable(target).trimEnd('/')
                if (FUSE_DATA_DIRS.any { n == it || n.startsWith("$it/") }) {
                    listOf(FALSE_BIN)
                } else {
                    null
                }
            }
            "mount", "umount" -> listOf(TRUE_BIN)
            "getenforce" -> listOf(ECHO_BIN, "Enforcing")
            "setenforce" -> listOf(FALSE_BIN)
            "su" -> listOf(FALSE_BIN)
            "which" ->
                if (rest.any { it.substringAfterLast('/') in ROOT_BINARIES }) listOf(FALSE_BIN)
                else null
            "cat" ->
                if (rest.any { it.startsWith("/proc/") && it.contains("mount") }) listOf(TRUE_BIN)
                else null
            else -> null
        }
    }

    /**
     * 0 = pass through, PROBE_OUTPUT = command whose value is its stdout
     * (getprop / mount / getenforce) - silenced to empty output,
     * PROBE_BINARY = command whose value is its exit code or mere existence
     * (su, which, setenforce) - silenced to exit 1.
     */
    private fun payloadVerdict(payload: String): Int {
        val parts = payload.split(Regex("[^A-Za-z0-9_./-]+")).filter { it.isNotEmpty() }
        val hit = parts.any { it in SHELL_TOKENS } || SHELL_PATHS.any { payload.contains(it) }
        if (!hit) return 0
        val outputProbe = parts.any {
            it == "getprop" || it == "mount" || it == "getenforce"
        } || SHELL_PATHS.any { it.startsWith("/proc/") && payload.contains(it) }
        return if (outputProbe) PROBE_OUTPUT else PROBE_BINARY
    }

    private fun logHit(module: XposedModule, what: String) {
        if (execLog >= 16) return
        execLog++
        module.log(Log.INFO, TAG, "[PAS] exec shield: $what")
    }

    companion object {
        private const val PROBE_OUTPUT = 1
        private const val PROBE_BINARY = 2

        private const val TRUE_BIN = "/system/bin/true"
        private const val FALSE_BIN = "/system/bin/false"
        private const val ECHO_BIN = "/system/bin/echo"

        /**
         * v3.0.0 (P5): ignorable Unicode codepoints Duck's Android/data
         * bypass inserts into probe paths. Superset of the detector's lists
         * (soft hyphen, combining grapheme joiner, hangul fillers, Mongolian
         * vowel separator, ZW* family, directional marks/isolates, word
         * joiners, variation selectors, BOM, interlinear annotations).
         */
        private val IGNORABLE_CP = Regex(
            "[\\u00AD\\u034F\\u061C\\u115F\\u1160\\u17B4\\u17B5\\u180E" +
                "\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u2066-\\u206F" +
                "\\u3164\\uFE00-\\uFE0F\\uFEFF\\uFFA0\\uFFF9-\\uFFFB]"
        )

        private fun normalizeIgnorable(s: String): String = IGNORABLE_CP.replace(s, "")

        /** External-storage app-data roots whose listing is FUSE-gated. */
        private val FUSE_DATA_DIRS = listOf(
            "/sdcard/Android/data",
            "/sdcard/Android/obb",
            "/storage/emulated/0/Android/data",
            "/storage/emulated/0/Android/obb",
        )

        /** Root binaries a `which` / `ls` probe may look for. */
        private val ROOT_BINARIES = setOf(
            "su", "daemonsu", "magisk", "magiskhide", "magiskpolicy", "supolicy",
            "busybox", "ksud", "apd", "superuser", "supersu"
        )

        /** Whole-word shell tokens that mark a payload as a root probe. */
        private val SHELL_TOKENS = setOf(
            "su", "daemonsu", "magisk", "magiskhide", "magiskpolicy", "supolicy",
            "busybox", "ksud", "apd", "supersu", "superuser", "kernelsu", "rootcloak",
            "getprop", "mount", "getenforce", "setenforce", "which", "resetprop",
            "setprop", "ps"
        )

        /** Path fragments that mark a payload as a root probe. */
        private val SHELL_PATHS = arrayOf(
            "/system/xbin", "/system/bin/su", "/system/bin/.ext", "/data/adb",
            "/sbin/.magisk", "/proc/mounts", "/proc/self/mounts", "/proc/self/mountinfo",
            "/system/app/Superuser.apk", "/su/bin"
        )

        /**
         * getprop keys answered with a clean value. Fixed strings are what a
         * stock, locked, non-developer user build reports; the Build.* entries
         * echo the IN-PROCESS (already patched) fields, so the child process
         * always agrees with the identity the app sees directly. Read lazily
         * on the first intercepted exec - i.e. after HookAntiEmu patched Build.
         */
        private val PROP_SPOOF: Map<String, String> = mapOf(
            "ro.debuggable" to "0",
            "ro.secure" to "1",
            "ro.adb.secure" to "1",
            "ro.build.selinux" to "1",
            "service.adb.root" to "0",
            "ro.allow.mock.location" to "0",
            "ro.boot.vbmeta.device_state" to "locked",
            "ro.boot.verifiedbootstate" to "green",
            "ro.boot.flash.locked" to "1",
            "ro.boot.veritymode" to "enforcing",
            "ro.boot.warranty_bit" to "0",
            "ro.warranty_bit" to "0",
            "ro.kernel.qemu" to "0",
            "ro.boot.qemu" to "0",
            "sys.oem_unlock_allowed" to "0",
            "ro.build.type" to Build.TYPE,
            "ro.build.tags" to Build.TAGS,
            "ro.build.fingerprint" to Build.FINGERPRINT,
            "ro.build.host" to Build.HOST,
            "ro.build.id" to Build.ID,
            "ro.build.display.id" to Build.DISPLAY,
            "ro.build.version.incremental" to Build.VERSION.INCREMENTAL,
            "ro.build.characteristics" to "default",
            "ro.product.model" to Build.MODEL,
            "ro.product.brand" to Build.BRAND,
            "ro.product.device" to Build.DEVICE,
            "ro.product.name" to Build.PRODUCT,
            "ro.product.manufacturer" to Build.MANUFACTURER,
            "ro.hardware" to Build.HARDWARE
        )
    }
}