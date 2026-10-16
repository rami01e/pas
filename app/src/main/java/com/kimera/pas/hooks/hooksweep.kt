package com.kimera.pas.hooks

import android.content.pm.PackageManager
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe

/**
 * v2.9.4 SWEEP SHIELD - hides configured packages from the scoped app's
 * PackageManager view.
 *
 * Evidence (June's Journey / AppDome, JJ capture 19:24): the target ran its
 * root/tool sweep through PackageManager queries. Root manager apps that
 * MUST stay installed on the device (KernelSU manager = me.weishu.kernelsu,
 * installed by MuMu itself and required by the LSPosed stack) become
 * invisible to the scoped app while this hook is armed.
 *
 * Scope and gating:
 *  - Active only when the ANTI-EMU toggle is on (same ownership as the
 *    native anti-emu layer; off = zero interference).
 *  - Hidden list: pref "hidden_packages" (comma separated, group
 *    "pas_spoof"); default covers the common managers so it works with no
 *    configuration:
 *      me.weishu.kernelsu, hk.kirk.trustme, de.robv.android.xposed.installer,
 *      org.lsposed.manager, io.github.lsposed.manager, com.topjohnwu.magisk,
 *      eu.chainfire.supersu
 *  - Surfaces covered: getInstalledPackages / getInstalledApplications /
 *    getInstalledModules (every declared overload, incl. the API 33
 *    flag-object variants), and single lookups getPackageInfo /
 *    getApplicationInfo, which throw NameNotFoundException for hidden names
 *    exactly like the framework does for a package that is not installed.
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
        listOf("getPackageInfo", "getApplicationInfo")
            .forEach { hookLookupNamed(module, pmClass, baseClass, it) }
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
                            if (pkg != null && pkg in hidden) {
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
                        if (pkg !in hidden) return@intercept chain.proceed()
                        logHit(module, "lookup", pkg)
                        throw PackageManager.NameNotFoundException(pkg)
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
        private const val DEFAULT_HIDDEN =
            "me.weishu.kernelsu,hk.kirk.trustme,de.robv.android.xposed.installer," +
            "org.lsposed.manager,io.github.lsposed.manager,com.topjohnwu.magisk," +
            "eu.chainfire.supersu"
    }
}