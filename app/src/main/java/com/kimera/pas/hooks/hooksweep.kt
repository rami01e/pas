package com.kimera.pas.hooks

import android.content.pm.PackageManager
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe

/**
 * v2.12.7 SWEEP SHIELD - hides configured packages from the scoped app's
 * PackageManager view.
 *
 * Evidence (com.playnearn capture, 10-19): the target runs RootBeer-style
 * detection - its dex carries the classic su paths, Superuser.apk, daemonsu,
 * test-keys, rootcloak and development_settings_enabled vocabulary, and the
 * recon log showed it querying managers through PackageManager. Root manager
 * apps that MUST stay installed on the device (KernelSU manager =
 * me.weishu.kernelsu, installed by MuMu itself and required by the LSPosed
 * stack; org.lsposed.corepatch = this device's actual framework manager)
 * become invisible to the scoped app while this hook is armed.
 *
 * Scope and gating:
 *  - Active only when the ANTI-EMU toggle is on (same ownership as the
 *    native anti-emu layer; off = zero interference).
 *  - Hidden list: pref "hidden_packages" (comma separated, group
 *    "pas_spoof"); default covers the common managers so it works with no
 *    configuration. Matching is exact OR token-based: a package whose name
 *    carries a hook-framework / root-manager token is hidden too, which is
 *    how org.lsposed.corepatch (never in any fixed list before v2.9.4)
 *    stays covered.
 *  - Surfaces covered: getInstalledPackages / getInstalledApplications /
 *    getInstalledModules (every declared overload, incl. the API 33
 *    flag-object variants), and single lookups getPackageInfo /
 *    getPackageInfoAsUser / getApplicationInfo / getApplicationInfoAsUser.
 *
 * v2.12.7 LOOKUP FIX - why the lookup hooks no longer throw:
 *
 *  The v2.9.4 lookup interceptor threw PackageManager.NameNotFoundException
 *  for hidden names. Vector installs module hookers in PROTECTIVE exception
 *  mode: "any exception thrown by the hooker will be caught and logged, and
 *  the call will proceed as if no hook exists" - the framework log line for
 *  exactly that is "Hooker [com.kimera.pas.hooks.n] crashed before proceed.
 *  Skipping." from the 10-19 capture (getPackageInfo("eu.chainfire.
 *  supersu")). So the NNFE NEVER reached the app: Vector swallowed it,
 *  continued the chain without the hook, and the original getPackageInfo
 *  answered with the REAL PackageInfo of every installed-but-hidden manager
 *  (org.lsposed.corepatch) - root still detected despite the sweep.
 *
 *  The fix re-runs the ORIGINAL lookup through chain.proceed(args) with a
 *  never-installed shadow name instead of throwing. The framework then
 *  produces the NameNotFoundException itself, and the API contract is
 *  explicit that "exceptions thrown by proceed will always be propagated" -
 *  for names that are genuinely not installed the original call throws on
 *  its own and we simply let that exception pass through untouched. Either
 *  way the app sees the exact not-installed verdict a clean device reports,
 *  and no hooker exception is ever raised for Vector to swallow.
 */
class HookSweep : XHook {

    override val targetKlass: String
        get() = "android.app.ApplicationPackageManager"

    private var hidden: Set<String> = emptySet()
    private var sweepLog = 0

    override fun injectHook(module: XposedModule) {
        val antiEmu = try {
            module.getRemotePreferences(PREF_GROUP).getBoolean("anti_emu_enabled", false)
        } catch (t: Throwable) {
            false
        }
        if (!antiEmu) {
            module.log(Log.INFO, TAG, "[PAS] sweep shield: anti-emu off - inert")
            return
        }
        hidden = try {
            val raw = module.getRemotePreferences(PREF_GROUP)
                .getString("hidden_packages", DEFAULT_HIDDEN) ?: DEFAULT_HIDDEN
            raw.split(",").map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        } catch (t: Throwable) {
            DEFAULT_HIDDEN.split(",").map { it.trim() }.toSet()
        }
        module.log(Log.INFO, TAG, "[PAS] sweep shield on: hiding ${hidden.size} package(s)")

        val pmClass = runCatching { Class.forName(targetKlass) }.getOrNull() ?: return
        val baseClass = runCatching { Class.forName("android.content.pm.PackageManager") }.getOrNull()

        listOf("getInstalledPackages", "getInstalledApplications", "getInstalledModules")
            .forEach { hookListNamed(module, pmClass, baseClass, it) }
        listOf(
            "getPackageInfo", "getApplicationInfo",
            "getPackageInfoAsUser", "getApplicationInfoAsUser"
        ).forEach { hookLookupNamed(module, pmClass, baseClass, it) }
    }

    // ------------------------------------------------------------------
    // hook every declared overload of `name` in ApplicationPackageManager,
    // falling back to PackageManager for anything only declared there.
    // ------------------------------------------------------------------
    private fun methodsFor(pmClass: Class<*>, baseClass: Class<*>?, name: String):
        List<java.lang.reflect.Method> {
        val out = ArrayList<java.lang.reflect.Method>()
        for (c in listOfNotNull(pmClass, baseClass)) {
            for (m in c.declaredMethods) {
                if (m.name == name && out.none { it == m }) out.add(m)
            }
        }
        return out
    }

    private fun hookListNamed(
        module: XposedModule,
        pmClass: Class<*>,
        baseClass: Class<*>?,
        name: String
    ) {
        hookSafe(module, "sweep $name") {
            var installed = 0
            for (m in methodsFor(pmClass, baseClass, name)) {
                try {
                    m.isAccessible = true
                    module.hook(m).intercept { chain ->
                        val result = chain.proceed() ?: return@intercept null
                        if (hidden.isEmpty()) return@intercept result
                        val list = result as? List<*> ?: return@intercept result
                        val out = ArrayList<Any?>(list.size)
                        var removed = 0
                        for (item in list) {
                            val pkg = packageNameOf(item)
                            if (pkg != null && isHidden(pkg)) {
                                removed++
                                logHit(module, "list", pkg)
                                continue
                            }
                            out.add(item)
                        }
                        if (removed > 0) out else result
                    }
                    installed++
                } catch (t: Throwable) {
                    // one unsupported overload must not sink the rest
                }
            }
            module.log(Log.INFO, TAG, "[PAS] sweep shield: $name x$installed")
        }
    }

    private fun hookLookupNamed(
        module: XposedModule,
        pmClass: Class<*>,
        baseClass: Class<*>?,
        name: String
    ) {
        hookSafe(module, "sweep $name") {
            var installed = 0
            for (m in methodsFor(pmClass, baseClass, name)) {
                val types = m.parameterTypes
                if (types.isEmpty() || types[0] != String::class.java) continue
                try {
                    m.isAccessible = true
                    module.hook(m).intercept { chain ->
                        val pkg = chain.getArg(0) as? String ?: return@intercept chain.proceed()
                        if (!isHidden(pkg)) return@intercept chain.proceed()
                        if (pkg.endsWith(SHADOW_SUFFIX)) return@intercept chain.proceed()
                        logHit(module, "lookup", pkg)
                        // Let the original answer first: for names that are
                        // genuinely not installed it throws NameNotFoundException
                        // on its own, and exceptions raised by proceed() are
                        // always propagated - no hooker exception involved.
                        chain.proceed()
                        // proceed() returned normally = the framework says the
                        // hidden package IS installed. Re-run the original
                        // lookup against a name that cannot be installed, so
                        // the FRAMEWORK throws the NameNotFoundException the
                        // app must see. Throwing it from this interceptor
                        // would hit Vector's PROTECTIVE mode ("crashed before
                        // proceed. Skipping.") and leak the package instead.
                        val args = chain.getArgs().toTypedArray()
                        args[0] = pkg + SHADOW_SUFFIX
                        chain.proceed(args)
                    }
                    installed++
                } catch (t: Throwable) {
                    // one unsupported overload must not sink the rest
                }
            }
            module.log(Log.INFO, TAG, "[PAS] sweep shield: $name x$installed")
        }
    }

    // ------------------------------------------------------------------
    /**
     * Hidden when the exact package is listed OR its name carries a
     * hook-framework / root-manager token. The token rule matters because
     * managers get repackaged under new names: this device ships
     * "org.lsposed.corepatch", which the fixed list never contained.
     */
    private fun isHidden(pkg: String): Boolean {
        if (pkg in hidden) return true
        for (t in MANAGER_TOKENS) {
            if (pkg.contains(t, ignoreCase = true)) return true
        }
        return false
    }

    private fun packageNameOf(item: Any?): String? {
        return when (item) {
            is android.content.pm.PackageInfo -> item.packageName
            is android.content.pm.ApplicationInfo -> item.packageName
            else -> runCatching {
                item?.javaClass?.getMethod("getPackageName")?.invoke(item) as? String
            }.getOrNull()
        }
    }

    private fun logHit(module: XposedModule, kind: String, name: String) {
        if (sweepLog >= 16) return
        sweepLog++
        module.log(Log.INFO, TAG, "[PAS] sweep shield: $kind '$name' hidden")
    }

    companion object {
        private const val PREF_GROUP = "pas_spoof"

        /**
         * v2.12.7: appended to a hidden package name to build the shadow
         * name the re-run lookup queries. No real package carries this
         * suffix, so the original implementation answers with
         * NameNotFoundException and the app sees "not installed". The
         * endsWith() guard in the lookup keeps the shadow name itself
         * outside the hidden-set logic.
         */
        private const val SHADOW_SUFFIX = ".nonexistent"

        private val MANAGER_TOKENS = arrayOf("lsposed", "xposed", "magisk", "kernelsu", "apatch")
        private const val DEFAULT_HIDDEN =
            "me.weishu.kernelsu,hk.kirk.trustme,com.kimera.pas," +
            "org.lsposed.corepatch,de.robv.android.xposed.installer,org.lsposed.manager," +
            "io.github.lsposed.manager,com.topjohnwu.magisk,eu.chainfire.supersu"
    }
}